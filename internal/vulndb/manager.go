package vulndb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/httputil"
)

// defaultOldConnectionTimeout is how long a generation switch waits for
// existing readers to close their connections before the old generation files
// are removed. On timeout the files are retained and cleaned up once the
// connections close or the process restarts.
const defaultOldConnectionTimeout = 10 * time.Second

// Manager owns the local vulnerability database generations for one cache
// path. It serializes refreshes across workers within the process and across
// processes sharing the cache path, and keeps old generations alive until
// their last reader is gone.
type Manager struct {
	layout *layout
	// client is used for downloads. nil disables automatic downloads.
	client httputil.Requester
	maxAge time.Duration
	// oldConnectionTimeout bounds how long a switch waits for old readers.
	oldConnectionTimeout time.Duration

	// refreshMu serializes refreshes within the process, providing singleflight
	// for concurrent workers.
	refreshMu sync.Mutex

	stateMu sync.Mutex
	record  *publishRecord
	// leases counts open connections per physical generation path.
	leases map[string]int
	// retained marks old generations kept on disk past a switch.
	retained map[string]bool
	// waiters are notified when a retained generation's last lease is released.
	waiters map[string][]chan struct{}
}

func newManager(path string, client httputil.Requester, maxAge time.Duration) (*Manager, error) {
	layout, err := newLayout(path)
	if err != nil {
		return nil, err
	}

	manager := &Manager{
		layout:               layout,
		client:               client,
		maxAge:               maxAge,
		oldConnectionTimeout: defaultOldConnectionTimeout,
		record:               newPublishRecord(),
		leases:               make(map[string]int),
		retained:             make(map[string]bool),
		waiters:              make(map[string][]chan struct{}),
	}

	if err := manager.recover(); err != nil {
		return nil, err
	}

	return manager, nil
}

// Get returns a connection to the published database generation, refreshing it
// first if missing or older than max age. The returned connection stays on
// the generation that was published at acquisition time - later refreshes do
// not affect it. New calls enter the newest published generation.
func (m *Manager) Get(ctx context.Context) (*Conn, error) {
	if m.client == nil {
		// Automatic downloads disabled. Use whatever is locally available.
		return m.openActive()
	}

	if m.needsRefresh() {
		if err := m.refresh(ctx); err != nil {
			if m.activeDigest() != "" {
				// A complete previous generation exists. Keep serving it rather
				// than failing queries on a refresh problem.
				slog.WarnContext(ctx, "Failed to refresh vulnerability database, continuing on the previous generation", slog.Any("error", err))
			} else {
				return nil, err
			}
		}
	}

	return m.openActive()
}

func (m *Manager) activeDigest() string {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return m.record.ActiveDigest
}

// needsRefresh reports whether a refresh should be attempted: no active
// generation exists, or the published one is older than max age.
func (m *Manager) needsRefresh() bool {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.record.ActiveDigest == "" {
		return true
	}
	return time.Since(m.record.PublishedAt) > m.maxAge
}

// openActive opens the physical file backing the currently published
// generation and registers a reader lease on it. The symlink is resolved at
// open time, so the connection is pinned to that generation even if the active
// pointer later switches.
func (m *Manager) openActive() (*Conn, error) {
	m.stateMu.Lock()
	digest := m.record.ActiveDigest
	m.stateMu.Unlock()

	if digest == "" {
		if m.client == nil {
			return nil, errors.New("vulndb: no local database and automatic download is disabled")
		}
		return nil, errors.New("vulndb: no published database generation")
	}

	physical := m.layout.generationPath(digest)
	if _, err := os.Stat(physical); err != nil {
		return nil, fmt.Errorf("vulndb: published generation is missing on disk: %w", err)
	}

	conn, err := Open(physical)
	if err != nil {
		return nil, err
	}

	m.stateMu.Lock()
	m.leases[physical]++
	m.stateMu.Unlock()

	path := physical
	conn.onClose = func() {
		m.release(path)
	}
	return conn, nil
}

// release drops a reader lease. If the generation was retained pending
// closure of the last reader, its files are removed now.
func (m *Manager) release(path string) {
	m.stateMu.Lock()

	m.leases[path]--
	if m.leases[path] <= 0 {
		delete(m.leases, path)
	}
	waiters := m.waiters[path]
	delete(m.waiters, path)

	retained := m.retained[path]
	if retained {
		delete(m.retained, path)
	}

	// Prepare the retired-entry removal under the lock; the actual file IO is
	// done without holding it.
	var record *publishRecord
	var digest string
	if retained {
		if d, ok := digestFromGenerationPath(filepath.Base(path)); ok {
			digest = d
			record = m.record.clone()
			record.Retired = removeRetired(record.Retired, digest)
			m.record = record
		} else {
			retained = false
		}
	}

	m.stateMu.Unlock()

	// Waiters (if any) are unblocked once cleanup below has finished.
	defer func() {
		for _, waiter := range waiters {
			close(waiter)
		}
	}()

	if !retained {
		return
	}

	if err := m.layout.saveRecord(record); err != nil {
		slog.Warn("Failed to update publish record after releasing old generation", slog.Any("error", err))
	}
	if err := removeGeneration(path); err != nil {
		slog.Warn("Failed to remove old generation files", slog.Any("error", err))
	}
}

// refresh performs a single generation refresh. Serialized within the process
// by refreshMu and across processes by the on-disk flock.
func (m *Manager) refresh(ctx context.Context) error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	// Another worker in this process may have refreshed while waiting.
	if !m.needsRefresh() {
		return nil
	}

	if err := m.layout.ensure(); err != nil {
		return err
	}

	lock, err := acquireFileLock(ctx, m.layout.lockPath)
	if err != nil {
		return err
	}
	defer lock.release()

	// Another process sharing the cache may have committed meanwhile.
	if err := m.reloadRecord(); err != nil {
		return err
	}
	if !m.needsRefresh() {
		return nil
	}

	// 1. Pin the remote artifact's digests and the local generation at start.
	art, err := resolveArtifact(ctx, m.client, artifactReference)
	if err != nil {
		return err
	}

	m.stateMu.Lock()
	record := m.record.clone()
	m.stateMu.Unlock()

	// The tag points at the same content the active generation already has.
	// Renew the age without downloading anything.
	if art.layerDigest == record.ActiveDigest {
		record.PublishedAt = time.Now()
		if err := m.layout.saveRecord(record); err != nil {
			return err
		}
		m.stateMu.Lock()
		m.record = record
		m.stateMu.Unlock()
		return nil
	}

	// 2. Download into the isolated staging location.
	staging := m.layout.stagingPath(art.layerDigest)
	file, err := os.OpenFile(staging, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("%w: cannot create staging file: %w", ErrDownloadFailed, err)
	}

	downloadErr := art.downloadTo(ctx, m.client, file)
	if downloadErr == nil {
		if err := file.Sync(); downloadErr == nil && err != nil {
			downloadErr = fmt.Errorf("%w: %w", ErrDownloadFailed, err)
		}
	}
	if err := file.Close(); downloadErr == nil && err != nil {
		downloadErr = fmt.Errorf("%w: %w", ErrDownloadFailed, err)
	}
	if downloadErr != nil {
		// Both interrupted downloads and corrupt content leave only an
		// unusable partial candidate: discard it. Recovery actions differ in
		// that corruption additionally marks the content rejected - the error
		// type tells callers apart network vs. content problems.
		_ = os.Remove(staging)
		return downloadErr
	}

	// 3. Verify SQLite integrity and the required schema before publishing.
	if err := validateDatabase(ctx, staging); err != nil {
		_ = os.Remove(staging)
		return err
	}

	// 4. Commit under the generation fence.
	return m.commit(art.layerDigest, staging, record)
}

// commit publishes a verified candidate using a compare-and-swap on the
// generation counter. A stale refresh (another generation was committed after
// this one pinned its base) never overwrites the newer artifact.
func (m *Manager) commit(digest, staging string, pinned *publishRecord) error {
	// Re-read the durable record while holding the flock. The flock excludes
	// other processes; the in-process refreshMu excludes other goroutines.
	onDisk, err := m.layout.loadRecord()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if onDisk == nil {
		onDisk = newPublishRecord()
	}

	// Fence check: the local generation must be the one pinned at refresh
	// start, unless the new content was committed concurrently (idempotent).
	if onDisk.Generation != pinned.Generation || onDisk.ActiveDigest != pinned.ActiveDigest {
		_ = os.Remove(staging)
		if onDisk.ActiveDigest == digest {
			// The same candidate won the race. Nothing to do.
			m.stateMu.Lock()
			m.record = onDisk
			m.stateMu.Unlock()
			return nil
		}
		// A different, newer generation won. Discard the stale candidate and
		// keep serving the committed generation.
		slog.Info("Skipping stale vulnerability database generation commit",
			slog.String("candidate", digest),
			slog.String("active", onDisk.ActiveDigest))
		m.stateMu.Lock()
		m.record = onDisk
		m.stateMu.Unlock()
		return nil
	}

	generationPath := m.layout.generationPath(digest)

	// Move the verified candidate into the immutable generations directory.
	if err := os.Rename(staging, generationPath); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("%w: cannot install candidate: %w", ErrPublishFailed, err)
	}
	if err := syncDir(m.layout.generationsDir); err != nil {
		_ = removeGeneration(generationPath)
		return fmt.Errorf("%w: %w", ErrPublishFailed, err)
	}

	// Persist the validated candidate so a crash before the symlink switch can
	// be completed on restart.
	candidate := &candidateState{
		Digest:         digest,
		Generation:     onDisk.Generation + 1,
		BaseGeneration: onDisk.Generation,
		ValidatedAt:    time.Now(),
	}
	onDisk.Candidate = candidate
	if err := m.layout.saveRecord(onDisk); err != nil {
		_ = removeGeneration(generationPath)
		return fmt.Errorf("%w: cannot persist candidate: %w", ErrPublishFailed, err)
	}

	// Atomically switch the active pointer.
	oldDigest := onDisk.ActiveDigest
	if err := m.layout.switchActive(digest); err != nil {
		// Roll back: restore the previous pointer if there was one and discard
		// the unpublished candidate.
		if oldDigest != "" {
			_ = m.layout.switchActive(oldDigest)
		} else {
			_ = os.Remove(m.layout.path)
		}
		onDisk.Candidate = nil
		_ = m.layout.saveRecord(onDisk)
		_ = removeGeneration(generationPath)
		return fmt.Errorf("%w: cannot switch active generation: %w", ErrPublishFailed, err)
	}

	// Finalize the publication. The old generation is retired only after this
	// durable point; readers still on it keep working.
	now := time.Now()
	onDisk.ActiveDigest = digest
	onDisk.Generation = candidate.Generation
	onDisk.Candidate = nil
	onDisk.PublishedAt = now

	if oldDigest != "" {
		onDisk.Retired = append(onDisk.Retired, retiredGeneration{
			Digest:    oldDigest,
			RetiredAt: now,
		})
	}
	if err := m.layout.saveRecord(onDisk); err != nil {
		// The switch itself happened; report but keep the new generation. A
		// restart reconciles the record from the symlink.
		slog.Error("Failed to finalize publish record after generation switch", slog.Any("error", err))
	}

	m.stateMu.Lock()
	m.record = onDisk.clone()
	m.stateMu.Unlock()

	if oldDigest != "" {
		m.retire(oldDigest)
	}

	return nil
}

// retire removes an old generation's files once all in-process readers have
// released them, waiting up to oldConnectionTimeout. On timeout the files are
// retained: they are removed when the last connection closes, or on the next
// process start (when all former file descriptors are gone).
func (m *Manager) retire(digest string) {
	path := m.layout.generationPath(digest)

	released := make(chan struct{})

	m.stateMu.Lock()
	if m.leases[path] == 0 {
		// No readers in this process. Remove immediately and clear the retired
		// entry that the finalize step persisted.
		m.stateMu.Unlock()
		if err := removeGeneration(path); err != nil {
			slog.Warn("Failed to remove retired vulnerability database generation", slog.Any("error", err))
		}
		m.clearRetiredRecord(digest)
		return
	}
	m.retained[path] = true
	m.waiters[path] = append(m.waiters[path], released)
	m.stateMu.Unlock()

	timer := time.NewTimer(m.oldConnectionTimeout)
	defer timer.Stop()

	select {
	case <-released:
		// release() removed the files and cleared the retired record entry.
	case <-timer.C:
		slog.Warn("Timed out waiting for old vulnerability database connections to close; retaining old generation files",
			slog.String("digest", digest),
			slog.Duration("timeout", m.oldConnectionTimeout))
	}
}

func (m *Manager) clearRetiredRecord(digest string) {
	m.stateMu.Lock()
	record := m.record.clone()
	record.Retired = removeRetired(record.Retired, digest)
	m.record = record
	m.stateMu.Unlock()
	if err := m.layout.saveRecord(record); err != nil {
		slog.Warn("Failed to update publish record while clearing retired generation", slog.Any("error", err))
	}
}

func removeRetired(retired []retiredGeneration, digest string) []retiredGeneration {
	filtered := retired[:0]
	for _, entry := range retired {
		if entry.Digest != digest {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// reloadRecord reloads the publish record from disk after taking the lock.
func (m *Manager) reloadRecord() error {
	record, err := m.layout.loadRecord()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			record = newPublishRecord()
		} else {
			return err
		}
	}
	m.stateMu.Lock()
	m.record = record
	m.stateMu.Unlock()
	return nil
}
