package vulndb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

// On-disk layout (path is the configured cache location, e.g.
// /tmp/vulndb.sqlite):
//
//	path                         symlink to <state>/generations/<digest>.sqlite
//	<state>/lock                 flock serializing generation commits
//	<state>/publish.json         durable publish record
//	<state>/generations/<d>.sqlite  immutable, verified generation files
//	<state>/staging/<d>.sqlite   isolated, in-progress candidate downloads
//
// Because path is a symlink, switching the active generation is a single
// atomic rename of a symlink. Readers that resolved the symlink before the
// switch keep using the old inode; new readers resolve the new generation.
// Old generation files are only removed once all readers have released them.
const (
	generationsDirName = "generations"
	stagingDirName     = "staging"
	lockName           = "lock"
	recordName         = "publish.json"
)

// candidateState describes a validated candidate whose switch was possibly
// interrupted. On startup the switch can either be completed or rolled back.
type candidateState struct {
	// Digest is the candidate blob's digest.
	Digest string `json:"digest"`
	// Generation is the generation id the candidate would become.
	Generation int `json:"generation"`
	// BaseGeneration is the active generation id at refresh start. It is the
	// compare-and-swap fence: a candidate is only committed if no other
	// generation was committed in between.
	BaseGeneration int `json:"baseGeneration"`
	// ValidatedAt is set once the candidate passed all checks on disk.
	ValidatedAt time.Time `json:"validatedAt"`
}

// retiredGeneration describes a previous generation whose files can only be
// removed once every reader (in this process) has released its connection.
// Persisting it lets a restarted process safely finish the cleanup, since all
// former file descriptors are gone.
type retiredGeneration struct {
	Digest    string    `json:"digest"`
	RetiredAt time.Time `json:"retiredAt"`
}

// publishRecord is the durable record of the local publication state.
type publishRecord struct {
	// Version of the record format.
	Version int `json:"version"`
	// ActiveDigest is the digest of the currently published generation.
	ActiveDigest string `json:"activeDigest"`
	// Generation is a monotonically increasing commit counter. It acts as the
	// fencing token when multiple workers or processes race to commit.
	Generation int `json:"generation"`
	// PublishedAt is when the active generation was published (or adopted, for
	// legacy files). Cache age is derived from it.
	PublishedAt time.Time `json:"publishedAt"`
	// Candidate is a validated candidate awaiting the symlink switch, if any.
	Candidate *candidateState `json:"candidate,omitempty"`
	// Retired lists generations kept on disk because readers still hold them.
	Retired []retiredGeneration `json:"retired,omitempty"`
}

func newPublishRecord() *publishRecord {
	return &publishRecord{Version: 1}
}

func (r *publishRecord) clone() *publishRecord {
	clone := *r
	if r.Candidate != nil {
		candidate := *r.Candidate
		clone.Candidate = &candidate
	}
	clone.Retired = append([]retiredGeneration(nil), r.Retired...)
	return &clone
}

// layout resolves all on-disk locations for a cache path.
type layout struct {
	// path is the user-facing active database location (a symlink).
	path string
	// dir is the directory containing path.
	dir string
	// stateDir holds all generation bookkeeping.
	stateDir string
	// generationsDir holds immutable published generation files.
	generationsDir string
	// stagingDir holds isolated in-progress downloads.
	stagingDir string
	// lockPath is the cross-process commit lock.
	lockPath string
	// recordPath is the publish record.
	recordPath string
}

func newLayout(path string) (*layout, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(absolute)
	stateDir := absolute + ".state"

	return &layout{
		path:           absolute,
		dir:            dir,
		stateDir:       stateDir,
		generationsDir: filepath.Join(stateDir, generationsDirName),
		stagingDir:     filepath.Join(stateDir, stagingDirName),
		lockPath:       filepath.Join(stateDir, lockName),
		recordPath:     filepath.Join(stateDir, recordName),
	}, nil
}

func (l *layout) ensure() error {
	if err := os.MkdirAll(l.generationsDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(l.stagingDir, 0755); err != nil {
		return err
	}
	return nil
}

// generationPath returns the immutable file location of a generation.
func (l *layout) generationPath(digest string) string {
	return filepath.Join(l.generationsDir, generationFileName(digest))
}

// stagingPath returns the isolated candidate location for a digest.
func (l *layout) stagingPath(digest string) string {
	return filepath.Join(l.stagingDir, generationFileName(digest))
}

// generationFileName turns a "sha256:<hex>" digest into a safe file name.
func generationFileName(digest string) string {
	return strings.ReplaceAll(digest, ":", "-") + ".sqlite"
}

// digestFromGenerationPath is the inverse of generationFileName.
func digestFromGenerationPath(name string) (string, bool) {
	if !strings.HasSuffix(name, ".sqlite") {
		return "", false
	}
	stem := strings.TrimSuffix(name, ".sqlite")
	parts := strings.SplitN(stem, "-", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	return parts[0] + ":" + parts[1], true
}

// activeLinkTarget is the relative symlink target used for the active pointer.
func (l *layout) activeLinkTarget(digest string) string {
	relative, err := filepath.Rel(l.dir, l.generationPath(digest))
	if err != nil {
		return l.generationPath(digest)
	}
	return relative
}

// fileLock is an advisory, cross-process lock backed by flock.
type fileLock struct {
	file *os.File
}

// acquireFileLock takes an exclusive lock, waiting until it is available or
// ctx is canceled. flock itself is uninterruptible, so a non-blocking attempt
// is polled.
func acquireFileLock(ctx context.Context, path string) (*fileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &fileLock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			file.Close()
			return nil, err
		}

		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (l *fileLock) release() error {
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	return errors.Join(unlockErr, closeErr)
}

// saveRecord atomically writes the publish record.
func (l *layout) saveRecord(record *publishRecord) error {
	contents, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(l.stateDir, "."+recordName+".*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, l.recordPath); err != nil {
		return err
	}
	return syncDir(l.stateDir)
}

func (l *layout) loadRecord() (*publishRecord, error) {
	contents, err := os.ReadFile(l.recordPath)
	if err != nil {
		return nil, err
	}
	var record publishRecord
	if err := json.Unmarshal(contents, &record); err != nil {
		return nil, err
	}
	if record.Version != 1 {
		return nil, fmt.Errorf("unsupported publish record version %d", record.Version)
	}
	return &record, nil
}

// switchActive atomically points path at the given generation.
func (l *layout) switchActive(digest string) error {
	// os.CreateTemp creates a regular file - remove it and use the unique name
	// for a symlink instead.
	tmpFile, err := os.CreateTemp(l.dir, "."+filepath.Base(l.path)+".link-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	if err := os.Remove(tmpPath); err != nil {
		return err
	}

	target := l.activeLinkTarget(digest)
	if err := os.Symlink(target, tmpPath); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, l.path); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return syncDir(l.dir)
}

// validateDatabase opens a candidate read-only and verifies both SQLite
// integrity and that the schema required by queries is present.
func validateDatabase(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", fileURL(path, "mode=ro&immutable=1"))
	if err != nil {
		return err
	}
	defer db.Close()

	row := db.QueryRowContext(ctx, "PRAGMA integrity_check;")
	var result string
	if err := row.Scan(&result); err != nil {
		return fmt.Errorf("%w: integrity check failed: %w", ErrContentCorrupt, err)
	}
	if result != "ok" {
		return fmt.Errorf("%w: integrity check reported %q", ErrContentCorrupt, result)
	}

	// Ensure the schema required by GetGitHubAdvisoriesForRepository exists.
	rows, err := db.QueryContext(ctx, "SELECT id, published, severity, introduced_version, fixed_version FROM github_advisories LIMIT 0;")
	if err != nil {
		return fmt.Errorf("%w: required schema missing: %w", ErrContentCorrupt, err)
	}
	rows.Close()

	return nil
}

// digestFile computes the sha256 digest of a file.
func digestFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

// removeGeneration removes a generation file and all of its SQLite sidecars.
func removeGeneration(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		// Best effort - sidecars are optional.
		_ = os.Remove(path + suffix)
	}
	return nil
}

// syncDir fsyncs a directory, ensuring entries created, renamed or removed in
// it are persisted.
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// quarantine moves an unusable file next to the state directory instead of
// deleting it outright, preserving forensic evidence while keeping it out of
// any active path.
func (l *layout) quarantine(path string) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	destination := filepath.Join(l.stateDir, "quarantine-"+filepath.Base(path)+"-"+time.Now().Format("20060102T150405.000000000"))
	if err := os.MkdirAll(l.stateDir, 0755); err == nil {
		if err := os.Rename(path, destination); err != nil {
			slog.Warn("Failed to quarantine invalid legacy vulnerability database", slog.Any("error", err))
			return
		}
		slog.Warn("Quarantined invalid legacy vulnerability database", slog.String("path", destination))
	}
}
