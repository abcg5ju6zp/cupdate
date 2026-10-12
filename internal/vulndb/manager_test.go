package vulndb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/cachetest"
	"github.com/AlexGustafsson/cupdate/internal/httputil"
	"github.com/AlexGustafsson/cupdate/internal/semver"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

const testRepository = "https://github.com/acme/app"

// buildVulnDatabase creates a valid vulnerability SQLite database containing a
// single advisory with the given ID and returns its bytes.
func buildVulnDatabase(t *testing.T, advisoryID string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulndb.sqlite")

	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)

	_, err = db.Exec(`CREATE TABLE github_advisories (
		id TEXT PRIMARY KEY NOT NULL,
		repository NOT NULL,
		published DATETIME NOT NULL,
		severity TEXT NOT NULL,
		introduced_version TEXT NOT NULL,
		fixed_version TEXT
	);`)
	require.NoError(t, err)

	_, err = db.Exec(`INSERT INTO github_advisories (id, repository, published, severity, introduced_version, fixed_version) VALUES (?, ?, ?, ?, ?, ?);`,
		advisoryID, testRepository, "2024-01-01 00:00:00", "high", "1.0.0", "")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	return contents
}

func digestBytes(contents []byte) string {
	sum := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// registryMode controls how the fake OCI registry delivers the blob.
type registryMode string

const (
	registryModeOK            registryMode = "ok"
	registryModeTruncated     registryMode = "truncated"
	registryModeMismatch      registryMode = "mismatch"
	registryModeInvalidSQLite registryMode = "invalid-sqlite"
)

// fakeRegistry is a minimal OCI distribution endpoint serving the vulndb
// artifact.
type fakeRegistry struct {
	*httptest.Server

	mu sync.Mutex

	// blob is what the blob endpoint actually serves.
	blob []byte
	// declaredDigest and declaredSize are what the manifest advertises.
	declaredDigest string
	declaredSize   int64
	mode           registryMode

	manifestHits atomic.Int64
	blobHits     atomic.Int64
}

func newFakeRegistry(t *testing.T, blob []byte) *fakeRegistry {
	r := &fakeRegistry{mode: registryModeOK}
	r.setDatabase(blob)
	r.Server = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.Server.Close)
	return r
}

func (r *fakeRegistry) setDatabase(blob []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode = registryModeOK
	r.blob = blob
	r.declaredDigest = digestBytes(blob)
	r.declaredSize = int64(len(blob))
}

// setTruncated advertises a valid database but cuts the response in half.
func (r *fakeRegistry) setTruncated(blob []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode = registryModeTruncated
	r.blob = blob
	r.declaredDigest = digestBytes(blob)
	r.declaredSize = int64(len(blob))
}

// setDigestMismatch serves garbage while advertising a valid database digest.
func (r *fakeRegistry) setDigestMismatch(validBlob []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode = registryModeMismatch
	r.blob = []byte("this is definitely not the database you are looking for")
	r.declaredDigest = digestBytes(validBlob)
	r.declaredSize = int64(len(validBlob))
}

// setInvalidSQLite serves non-database content with its own correct digest.
func (r *fakeRegistry) setInvalidSQLite() {
	garbage := []byte("not a sqlite database at all, but digest will match the manifest")
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode = registryModeInvalidSQLite
	r.blob = garbage
	r.declaredDigest = digestBytes(garbage)
	r.declaredSize = int64(len(garbage))
}

func (r *fakeRegistry) snapshot() (blob []byte, digest string, size int64, mode registryMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.blob...), r.declaredDigest, r.declaredSize, r.mode
}

func (r *fakeRegistry) serve(w http.ResponseWriter, req *http.Request) {
	switch {
	case strings.HasSuffix(req.URL.Path, "/manifests/latest"):
		r.manifestHits.Add(1)
		_, digest, size, _ := r.snapshot()
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		manifest := fmt.Sprintf(`{
			"schemaVersion": 2,
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"artifactType": "application/vnd.cupdate.vulndb.v1+json",
			"config": {"mediaType": "application/vnd.oci.empty.v1+json", "size": 2, "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
			"layers": [{"mediaType": "application/x-sqlite3", "digest": %q, "size": %d}]
		}`, digest, size)
		io.WriteString(w, manifest)
	case strings.Contains(req.URL.Path, "/blobs/"):
		r.blobHits.Add(1)
		blob, _, _, mode := r.snapshot()
		if mode == registryModeTruncated {
			// Declare the full length but abort halfway, mimicking a network
			// interruption during the file write.
			w.Header().Set("Content-Length", strconv.Itoa(len(blob)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(blob[:len(blob)/2])
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return
		}
		_, _ = w.Write(blob)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type rewriteTransport struct {
	target *url.URL
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rewritten := req.Clone(req.Context())
	rewritten.URL.Scheme = t.target.Scheme
	rewritten.URL.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(rewritten)
}

func newTestHTTPClient(t *testing.T, registry *fakeRegistry) *httputil.Client {
	t.Helper()
	target, err := url.Parse(registry.URL)
	require.NoError(t, err)
	// Cache entries are always considered expired so tests observe the current
	// state of the (possibly moving) registry tag.
	client := httputil.NewClient(cachetest.NewCache(t), -time.Hour)
	client.Transport = &rewriteTransport{target: target}
	return client
}

func newTestManager(t *testing.T, registry *fakeRegistry, maxAge time.Duration) *Manager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulndb.sqlite")
	manager, err := newManager(path, newTestHTTPClient(t, registry), maxAge)
	require.NoError(t, err)
	return manager
}

// advisoryID queries the connection for the test repository's advisory ID, or
// "" when no advisory matches.
func advisoryID(t *testing.T, conn *Conn) string {
	t.Helper()
	version, err := semver.ParseVersion("2.0.0")
	require.NoError(t, err)
	vulnerabilities, err := conn.GetGitHubAdvisoriesForRepository(context.Background(), testRepository, version)
	require.NoError(t, err)
	if len(vulnerabilities) == 0 {
		return ""
	}
	return vulnerabilities[0].ID
}

func TestAutoFetchAndOpenFirstInstall(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	manager := newTestManager(t, registry, time.Hour)

	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()

	require.Equal(t, "GHSA-v1", advisoryID(t, conn))
	require.Equal(t, int64(1), registry.manifestHits.Load())
	require.Equal(t, int64(1), registry.blobHits.Load())

	// Active path is a symlink into the generations directory.
	resolved, err := filepath.EvalSymlinks(manager.layout.path)
	require.NoError(t, err)
	resolvedGenerationsDir, err := filepath.EvalSymlinks(manager.layout.generationsDir)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(resolved, resolvedGenerationsDir+string(filepath.Separator)))
}

func TestAutoFetchAndOpenUnexpiredSkipsDownload(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	manager := newTestManager(t, registry, time.Hour)

	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	conn.Close()

	registry.manifestHits.Store(0)
	registry.blobHits.Store(0)

	// Fresh cache: no network at all.
	conn, err = manager.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()

	require.Equal(t, int64(0), registry.manifestHits.Load())
	require.Equal(t, int64(0), registry.blobHits.Load())
	require.Equal(t, "GHSA-v1", advisoryID(t, conn))
}

func TestRefreshSameDigestRenewsAgeWithoutDownload(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	manager := newTestManager(t, registry, 0)

	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	conn.Close()

	registry.blobHits.Store(0)

	// Cache always considered expired, but the tag still points at the same
	// content: only the manifest is resolved, no blob download.
	conn, err = manager.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()

	require.Equal(t, int64(0), registry.blobHits.Load())
	require.Equal(t, "GHSA-v1", advisoryID(t, conn))
}

func TestRefreshSwitchesGenerationAtomicallyAndPinsReaders(t *testing.T) {
	v1 := buildVulnDatabase(t, "GHSA-v1")
	registry := newFakeRegistry(t, v1)
	manager := newTestManager(t, registry, 0)
	// Keep the test fast while old readers are held.
	manager.oldConnectionTimeout = 50 * time.Millisecond

	connV1, err := manager.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "GHSA-v1", advisoryID(t, connV1))
	v1Digest := registry.declaredDigest
	v1Path := manager.layout.generationPath(v1Digest)

	// Publish a new generation under the moving tag.
	registry.setDatabase(buildVulnDatabase(t, "GHSA-v2"))

	connV2, err := manager.Get(context.Background())
	require.NoError(t, err)
	defer connV2.Close()

	// New queries enter the new generation.
	require.Equal(t, "GHSA-v2", advisoryID(t, connV2))
	// Existing readers keep querying the old generation through the switch.
	require.Equal(t, "GHSA-v1", advisoryID(t, connV1))

	// Old files retained while the old connection is open (retire timed out).
	_, err = os.Stat(v1Path)
	require.NoError(t, err)

	require.NoError(t, connV1.Close())

	// Once the old reader closes, the old generation is removed.
	require.Eventually(t, func() bool {
		_, err := os.Stat(v1Path)
		return errors.Is(err, os.ErrNotExist)
	}, time.Second, 10*time.Millisecond)

	// Only the v2 generation remains.
	entries, err := os.ReadDir(manager.layout.generationsDir)
	require.NoError(t, err)
	var sqliteFiles []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sqlite") {
			sqliteFiles = append(sqliteFiles, entry.Name())
		}
	}
	require.Len(t, sqliteFiles, 1)
	require.Equal(t, generationFileName(registry.declaredDigest), sqliteFiles[0])
}

func TestDownloadInterruptionKeepsPreviousGeneration(t *testing.T) {
	v1 := buildVulnDatabase(t, "GHSA-v1")
	registry := newFakeRegistry(t, v1)
	manager := newTestManager(t, registry, 0)

	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	conn.Close()

	registry.setTruncated(buildVulnDatabase(t, "GHSA-v2"))

	err = manager.refresh(context.Background())
	require.ErrorIs(t, err, ErrDownloadFailed)

	// No staging files survive the failed download.
	entries, err := os.ReadDir(manager.layout.stagingDir)
	require.NoError(t, err)
	require.Empty(t, entries)

	// The complete previous generation is still served.
	conn, err = manager.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, "GHSA-v1", advisoryID(t, conn))
}

func TestDigestMismatchRejectsCandidate(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	manager := newTestManager(t, registry, 0)

	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	conn.Close()

	registry.setDigestMismatch(buildVulnDatabase(t, "GHSA-v2"))

	err = manager.refresh(context.Background())
	require.ErrorIs(t, err, ErrContentCorrupt)

	entries, err := os.ReadDir(manager.layout.stagingDir)
	require.NoError(t, err)
	require.Empty(t, entries)

	conn, err = manager.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, "GHSA-v1", advisoryID(t, conn))
}

func TestInvalidSQLiteRejectsCandidate(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	manager := newTestManager(t, registry, 0)

	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	conn.Close()

	registry.setInvalidSQLite()

	err = manager.refresh(context.Background())
	require.ErrorIs(t, err, ErrContentCorrupt)

	conn, err = manager.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, "GHSA-v1", advisoryID(t, conn))
}

func TestConcurrentFirstInstallCommitsOnce(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	manager := newTestManager(t, registry, time.Hour)

	const workers = 20
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	conns := make(chan *Conn, workers)

	start := make(chan struct{})
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			conn, err := manager.Get(context.Background())
			if err != nil {
				errs <- err
				return
			}
			conns <- conn
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	close(conns)

	for err := range errs {
		require.NoError(t, err)
	}

	for conn := range conns {
		require.Equal(t, "GHSA-v1", advisoryID(t, conn))
		require.NoError(t, conn.Close())
	}

	require.Equal(t, int64(1), registry.manifestHits.Load())
	require.Equal(t, int64(1), registry.blobHits.Load())
}

func TestStaleCommitDoesNotOverwriteNewerGeneration(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	manager := newTestManager(t, registry, time.Hour)

	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	conn.Close()

	// Simulate a refresh that pinned generation 0 before generation 1 was
	// committed. Its candidate must not overwrite the newer generation.
	v2 := buildVulnDatabase(t, "GHSA-v2")
	v2Digest := digestBytes(v2)
	staging := manager.layout.stagingPath(v2Digest)
	require.NoError(t, os.MkdirAll(manager.layout.stagingDir, 0755))
	require.NoError(t, os.WriteFile(staging, v2, 0644))

	stale := newPublishRecord() // Generation 0, no active digest
	err = manager.commit(v2Digest, staging, stale)
	require.NoError(t, err)

	_, err = os.Stat(manager.layout.generationPath(v2Digest))
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(staging)
	require.ErrorIs(t, err, os.ErrNotExist)

	conn, err = manager.openActive()
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, "GHSA-v1", advisoryID(t, conn))
}

func TestRestartCompletesValidatedCandidateSwitch(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	path := filepath.Join(t.TempDir(), "vulndb.sqlite")
	client := newTestHTTPClient(t, registry)

	manager, err := newManager(path, client, time.Hour)
	require.NoError(t, err)
	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	v1Digest := manager.activeDigest()
	conn.Close()

	// Simulate a crash after candidate validation but before the symlink
	// switch: candidate file is in place, record advertises it.
	v2 := buildVulnDatabase(t, "GHSA-v2")
	v2Digest := digestBytes(v2)
	require.NoError(t, os.WriteFile(manager.layout.generationPath(v2Digest), v2, 0644))

	record, err := manager.layout.loadRecord()
	require.NoError(t, err)
	record.Candidate = &candidateState{
		Digest:         v2Digest,
		Generation:     record.Generation + 1,
		BaseGeneration: record.Generation,
		ValidatedAt:    time.Now(),
	}
	require.NoError(t, manager.layout.saveRecord(record))

	// New process, new manager. The client points at v1 still - recovery must
	// not need the network to finish the local switch.
	registry.manifestHits.Store(0)
	restarted, err := newManager(path, client, time.Hour)
	require.NoError(t, err)
	require.Equal(t, int64(0), registry.manifestHits.Load())

	require.Equal(t, v2Digest, restarted.activeDigest())
	_, err = os.Stat(restarted.layout.generationPath(v1Digest))
	require.ErrorIs(t, err, os.ErrNotExist)

	conn, err = restarted.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, "GHSA-v2", advisoryID(t, conn))
}

func TestRestartFinalizesSwitchAfterSymlinkButBeforeRecord(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	path := filepath.Join(t.TempDir(), "vulndb.sqlite")
	client := newTestHTTPClient(t, registry)

	manager, err := newManager(path, client, time.Hour)
	require.NoError(t, err)
	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	conn.Close()

	v2 := buildVulnDatabase(t, "GHSA-v2")
	v2Digest := digestBytes(v2)
	require.NoError(t, os.WriteFile(manager.layout.generationPath(v2Digest), v2, 0644))

	// Symlink already switched, candidate recorded, but the record's active
	// digest was never finalized.
	require.NoError(t, manager.layout.switchActive(v2Digest))
	record, err := manager.layout.loadRecord()
	require.NoError(t, err)
	v1Digest := record.ActiveDigest
	record.Candidate = &candidateState{
		Digest:         v2Digest,
		Generation:     record.Generation + 1,
		BaseGeneration: record.Generation,
		ValidatedAt:    time.Now(),
	}
	require.NoError(t, manager.layout.saveRecord(record))

	restarted, err := newManager(path, client, time.Hour)
	require.NoError(t, err)

	require.Equal(t, v2Digest, restarted.activeDigest())
	_, err = os.Stat(restarted.layout.generationPath(v1Digest))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRestartCleansAbandonedFiles(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	path := filepath.Join(t.TempDir(), "vulndb.sqlite")
	client := newTestHTTPClient(t, registry)

	manager, err := newManager(path, client, time.Hour)
	require.NoError(t, err)
	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	conn.Close()

	// Abandoned partial download.
	require.NoError(t, os.WriteFile(filepath.Join(manager.layout.stagingDir, "partial.sqlite"), []byte("partial"), 0644))

	// Orphan generation (not referenced by the record).
	orphan := buildVulnDatabase(t, "GHSA-orphan")
	orphanDigest := digestBytes(orphan)
	require.NoError(t, os.WriteFile(manager.layout.generationPath(orphanDigest), orphan, 0644))

	// Retired generation from the previous process (old fds are dead).
	retired := buildVulnDatabase(t, "GHSA-old")
	retiredDigest := digestBytes(retired)
	require.NoError(t, os.WriteFile(manager.layout.generationPath(retiredDigest), retired, 0644))
	record, err := manager.layout.loadRecord()
	require.NoError(t, err)
	record.Retired = []retiredGeneration{{Digest: retiredDigest, RetiredAt: time.Now()}}
	require.NoError(t, manager.layout.saveRecord(record))

	restarted, err := newManager(path, client, time.Hour)
	require.NoError(t, err)

	_, err = os.Stat(manager.layout.generationPath(orphanDigest))
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(manager.layout.generationPath(retiredDigest))
	require.ErrorIs(t, err, os.ErrNotExist)

	stagingEntries, err := os.ReadDir(manager.layout.stagingDir)
	require.NoError(t, err)
	require.Empty(t, stagingEntries)

	restartedRecord, err := restarted.layout.loadRecord()
	require.NoError(t, err)
	require.Empty(t, restartedRecord.Retired)

	conn, err = restarted.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, "GHSA-v1", advisoryID(t, conn))
}

func TestRestartRestoresMissingPointer(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	path := filepath.Join(t.TempDir(), "vulndb.sqlite")
	client := newTestHTTPClient(t, registry)

	manager, err := newManager(path, client, time.Hour)
	require.NoError(t, err)
	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	conn.Close()

	// Active pointer removed, record and generations intact.
	require.NoError(t, os.Remove(manager.layout.path))

	restarted, err := newManager(path, client, time.Hour)
	require.NoError(t, err)

	conn, err = restarted.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, "GHSA-v1", advisoryID(t, conn))
}

func TestAutoDownloadDisabledKeepsExistingGeneration(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	path := filepath.Join(t.TempDir(), "vulndb.sqlite")
	client := newTestHTTPClient(t, registry)

	manager, err := newManager(path, client, time.Hour)
	require.NoError(t, err)
	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	conn.Close()

	// Even with an always-expired age, a nil client never triggers downloads.
	disabled, err := newManager(path, nil, 0)
	require.NoError(t, err)
	conn, err = disabled.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, "GHSA-v1", advisoryID(t, conn))
	require.Equal(t, int64(1), registry.manifestHits.Load())
}

func TestAutoDownloadDisabledWithoutDatabaseErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulndb.sqlite")
	manager, err := newManager(path, nil, 0)
	require.NoError(t, err)

	_, err = manager.Get(context.Background())
	require.Error(t, err)
}

func TestFirstInstallFailureIsReturned(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	registry.setTruncated(buildVulnDatabase(t, "GHSA-v1"))
	manager := newTestManager(t, registry, time.Hour)

	_, err := manager.Get(context.Background())
	require.ErrorIs(t, err, ErrDownloadFailed)
}

func TestQueryWithoutMatchReturnsEmpty(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-v1"))
	manager := newTestManager(t, registry, time.Hour)

	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()

	version, err := semver.ParseVersion("2.0.0")
	require.NoError(t, err)
	vulnerabilities, err := conn.GetGitHubAdvisoriesForRepository(context.Background(), "https://github.com/other/repo", version)
	require.NoError(t, err)
	require.Empty(t, vulnerabilities)
}

func TestLegacyRegularFileIsAdopted(t *testing.T) {
	registry := newFakeRegistry(t, buildVulnDatabase(t, "GHSA-legacy"))
	path := filepath.Join(t.TempDir(), "vulndb.sqlite")
	client := newTestHTTPClient(t, registry)

	// Older versions left a plain file at the cache path.
	require.NoError(t, os.WriteFile(path, buildVulnDatabase(t, "GHSA-legacy"), 0644))

	manager, err := newManager(path, client, time.Hour)
	require.NoError(t, err)
	conn, err := manager.Get(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, "GHSA-legacy", advisoryID(t, conn))

	info, err := os.Lstat(path)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink)
	require.Equal(t, int64(0), registry.manifestHits.Load())
}

func TestLegacyInvalidFileIsQuarantined(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulndb.sqlite")
	require.NoError(t, os.WriteFile(path, []byte("broken database"), 0644))

	manager, err := newManager(path, nil, 0)
	require.NoError(t, err)
	require.Equal(t, "", manager.activeDigest())

	_, err = os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)

	entries, err := os.ReadDir(manager.layout.stateDir)
	require.NoError(t, err)
	var quarantined bool
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "quarantine-") {
			quarantined = true
		}
	}
	require.True(t, quarantined)
}

func TestRetiredGenerationRemovedOnLeaseRelease(t *testing.T) {
	v1 := buildVulnDatabase(t, "GHSA-v1")
	registry := newFakeRegistry(t, v1)
	manager := newTestManager(t, registry, 0)
	manager.oldConnectionTimeout = 30 * time.Millisecond

	connV1, err := manager.Get(context.Background())
	require.NoError(t, err)
	v1Digest := registry.declaredDigest
	v1Path := manager.layout.generationPath(v1Digest)

	registry.setDatabase(buildVulnDatabase(t, "GHSA-v2"))
	connV2, err := manager.Get(context.Background())
	require.NoError(t, err)
	defer connV2.Close()

	// Timeout path: old generation is retained and recorded as retired.
	require.Eventually(t, func() bool {
		record, err := manager.layout.loadRecord()
		if err != nil {
			return false
		}
		for _, retired := range record.Retired {
			if retired.Digest == v1Digest {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)

	_, err = os.Stat(v1Path)
	require.NoError(t, err)

	require.NoError(t, connV1.Close())

	require.Eventually(t, func() bool {
		_, err := os.Stat(v1Path)
		return errors.Is(err, os.ErrNotExist)
	}, time.Second, 10*time.Millisecond)

	record, err := manager.layout.loadRecord()
	require.NoError(t, err)
	require.Empty(t, record.Retired)
}
