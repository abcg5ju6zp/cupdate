package vulndb

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// recover reconciles the on-disk state at process start. Based on the durable
// publish record it either:
//
//   - keeps serving the complete previously published generation,
//   - completes the switch of an already validated candidate, or
//   - cleans up abandoned staging files, orphan generations and generations
//     retired by the previous process (all their file descriptors are gone
//     with the process).
//
// A legacy regular file at the active path (written by older versions) is
// adopted as generation 1 after validation.
func (m *Manager) recover() error {
	l := m.layout

	if err := os.MkdirAll(l.stateDir, 0755); err != nil {
		return err
	}

	// Startup recovery must run even if the caller's context is canceled.
	lock, err := acquireFileLock(context.Background(), l.lockPath)
	if err != nil {
		return err
	}
	defer lock.release()

	if err := l.ensure(); err != nil {
		return err
	}

	// Interrupted downloads never produce candidates: staging content is
	// always partial/unverified, remove it.
	if err := clearDirectory(l.stagingDir); err != nil {
		return err
	}

	info, err := os.Lstat(l.path)
	switch {
	case err == nil && info.Mode().Type().IsRegular():
		if err := m.recoverLegacyFile(info); err != nil {
			return err
		}
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		if err := m.recoverSymlink(); err != nil {
			return err
		}
	default:
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := m.recoverMissing(); err != nil {
			return err
		}
	}

	return nil
}

// recoverLegacyFile adopts a regular file written by older versions.
func (m *Manager) recoverLegacyFile(info os.FileInfo) error {
	l := m.layout

	digest, err := digestFile(l.path)
	if err != nil {
		return err
	}

	if err := validateDatabase(context.Background(), l.path); err != nil {
		// The only local database is unusable. Quarantine it and start without
		// an active generation - the first refresh performs a fresh install.
		l.quarantine(l.path)
		record := newPublishRecord()
		if err := l.saveRecord(record); err != nil {
			return err
		}
		m.setRecord(record)
		return m.cleanupGenerations(record)
	}

	generationPath := l.generationPath(digest)
	if err := os.Rename(l.path, generationPath); err != nil {
		return err
	}
	if err := syncDir(l.generationsDir); err != nil {
		return err
	}

	if err := l.switchActive(digest); err != nil {
		return err
	}

	record := &publishRecord{
		Version:      1,
		ActiveDigest: digest,
		Generation:   1,
		PublishedAt:  info.ModTime(),
	}
	if err := l.saveRecord(record); err != nil {
		return err
	}
	m.setRecord(record)
	return m.cleanupGenerations(record)
}

// recoverSymlink reconciles an existing active symlink with the publish
// record, including completing an interrupted candidate switch.
func (m *Manager) recoverSymlink() error {
	l := m.layout

	record, err := l.loadRecord()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		record = newPublishRecord()
	}

	target, targetErr := filepath.EvalSymlinks(l.path)
	targetDigest := ""
	if targetErr == nil {
		targetDigest, _ = digestFromGenerationPath(filepath.Base(target))
	}

	// Complete or roll back an interrupted candidate switch.
	if record.Candidate != nil {
		candidate := record.Candidate
		candidatePath := l.generationPath(candidate.Digest)

		if !candidate.ValidatedAt.IsZero() && m.generationUsable(candidatePath, candidate.Digest) {
			oldDigest := record.ActiveDigest
			if targetDigest != candidate.Digest {
				if err := l.switchActive(candidate.Digest); err != nil {
					return err
				}
			}

			record.ActiveDigest = candidate.Digest
			record.Generation = candidate.Generation
			record.Candidate = nil
			if oldDigest != "" && oldDigest != candidate.Digest {
				record.Retired = append(record.Retired, retiredGeneration{
					Digest:    oldDigest,
					RetiredAt: candidate.ValidatedAt,
				})
			}
			slog.Info("Completed interrupted vulnerability database generation switch",
				slog.String("digest", candidate.Digest))
		} else {
			// Candidate did not survive intact. Discard it and fall through to
			// reconciliation against the previous active generation.
			_ = removeGeneration(candidatePath)
			record.Candidate = nil
			if err := l.saveRecord(record); err != nil {
				return err
			}
		}
	}

	// Re-read the physical target; switchActive above may have changed it.
	target, targetErr = filepath.EvalSymlinks(l.path)
	if targetErr == nil {
		targetDigest, _ = digestFromGenerationPath(filepath.Base(target))
	}

	switch {
	case record.ActiveDigest != "" && targetDigest == record.ActiveDigest:
		// The pointer and the record agree - this is the complete previous
		// version.
	case record.ActiveDigest != "" && generationFileExists(l, record.ActiveDigest):
		// Pointer is stale or dangling, but the recorded generation is intact.
		// Restore it.
		if err := l.switchActive(record.ActiveDigest); err != nil {
			return err
		}
		slog.Info("Restored active pointer to the last complete vulnerability database generation",
			slog.String("digest", record.ActiveDigest))
	case targetDigest != "" && m.generationUsable(target, targetDigest):
		// Record missing or unusable, but the pointer resolves to an intact
		// generation. Adopt it.
		record.ActiveDigest = targetDigest
		if record.Generation == 0 {
			record.Generation = 1
		}
		if record.PublishedAt.IsZero() {
			record.PublishedAt = modTimeOrNow(target)
		}
	default:
		// Nothing usable. Drop the dangling pointer and start as a first
		// install.
		_ = os.Remove(l.path)
		record = newPublishRecord()
	}

	if err := l.saveRecord(record); err != nil {
		return err
	}
	m.setRecord(record)
	return m.cleanupGenerations(record)
}

// recoverMissing handles the case where the active path does not exist.
func (m *Manager) recoverMissing() error {
	l := m.layout

	record, err := l.loadRecord()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		record = newPublishRecord()
	}

	// An interrupted candidate switch never reached the symlink; the recorded
	// active generation (if any and intact) is the one to serve.
	if record.Candidate != nil {
		_ = removeGeneration(l.generationPath(record.Candidate.Digest))
		record.Candidate = nil
	}

	if record.ActiveDigest != "" && generationFileExists(l, record.ActiveDigest) {
		if err := l.switchActive(record.ActiveDigest); err != nil {
			return err
		}
		slog.Info("Recovered active pointer to the last complete vulnerability database generation",
			slog.String("digest", record.ActiveDigest))
	} else {
		record = newPublishRecord()
	}

	if err := l.saveRecord(record); err != nil {
		return err
	}
	m.setRecord(record)
	return m.cleanupGenerations(record)
}

// generationUsable reports that path exists, has the expected digest and
// passes the same integrity and schema checks a fresh candidate gets.
func (m *Manager) generationUsable(path, digest string) bool {
	if !generationFileExists(m.layout, digest) {
		return false
	}
	actualDigest, err := digestFile(path)
	if err != nil || actualDigest != digest {
		return false
	}
	if err := validateDatabase(context.Background(), path); err != nil {
		return false
	}
	return true
}

// cleanupGenerations removes files no generation may use anymore: generations
// retired before the previous process exited (their file descriptors died
// with it) and any orphan generation files not referenced by the record.
func (m *Manager) cleanupGenerations(record *publishRecord) error {
	l := m.layout

	// Retired generations are safe to remove on process start.
	for _, retired := range record.Retired {
		if retired.Digest == record.ActiveDigest {
			continue
		}
		if err := removeGeneration(l.generationPath(retired.Digest)); err != nil {
			slog.Warn("Failed to clean up retired vulnerability database generation", slog.Any("error", err))
		}
	}
	record.Retired = nil

	entries, err := os.ReadDir(l.generationsDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			name = strings.TrimSuffix(name, suffix)
		}
		digest, ok := digestFromGenerationPath(name)
		if !ok || digest == record.ActiveDigest {
			continue
		}
		// Drop orphan or retired generations and their SQLite sidecars.
		_ = removeGeneration(filepath.Join(l.generationsDir, entry.Name()))
	}

	if err := l.saveRecord(record); err != nil {
		return err
	}
	m.setRecord(record)
	return nil
}

func (m *Manager) setRecord(record *publishRecord) {
	m.stateMu.Lock()
	m.record = record.clone()
	m.stateMu.Unlock()
}

// generationFileExists reports that the generation's main database file is
// present.
func generationFileExists(l *layout, digest string) bool {
	if digest == "" {
		return false
	}
	info, err := os.Stat(l.generationPath(digest))
	return err == nil && !info.IsDir()
}

func modTimeOrNow(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Now()
	}
	return info.ModTime()
}

// clearDirectory removes all entries of a directory but keeps the directory.
func clearDirectory(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(path, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
