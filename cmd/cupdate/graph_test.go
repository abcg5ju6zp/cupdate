package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/events"
	"github.com/AlexGustafsson/cupdate/internal/models"
	"github.com/AlexGustafsson/cupdate/internal/oci"
	"github.com/AlexGustafsson/cupdate/internal/platform"
	"github.com/AlexGustafsson/cupdate/internal/platform/docker"
	"github.com/AlexGustafsson/cupdate/internal/store"
	"github.com/AlexGustafsson/cupdate/internal/worker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeContinuousGrapher publishes snapshots handed to it.
type fakeContinuousGrapher struct {
	snapshots chan platform.Snapshot
}

func (f *fakeContinuousGrapher) Graph(context.Context) error { return nil }

func (f *fakeContinuousGrapher) Graphs() <-chan platform.Snapshot { return f.snapshots }

func (f *fakeContinuousGrapher) Close() error { return nil }

func newTestStores(t *testing.T, readOnly bool) (*store.Store, string) {
	t.Helper()
	uri := "file://" + t.TempDir() + "/sqlite.db"
	require.NoError(t, store.Initialize(t.Context(), uri))
	s, err := store.New(t.Context(), uri, readOnly)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s, uri
}

func openTestStore(t *testing.T, uri string, readOnly bool) *store.Store {
	t.Helper()
	s, err := store.New(t.Context(), uri, readOnly)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func imageGraph(t *testing.T, references ...string) platform.Graph {
	t.Helper()
	g := platform.NewGraph()
	for _, reference := range references {
		ref, err := oci.ParseReference(reference)
		require.NoError(t, err)
		g.InsertTree(platform.ImageNode{Reference: ref})
	}
	return g
}

func sendSnapshot(t *testing.T, ch chan<- platform.Snapshot, generation uint64, graph platform.Graph) {
	t.Helper()
	go func() {
		ch <- platform.Snapshot{
			Platform:   "static",
			Generation: generation,
			CapturedAt: time.Now(),
			Graph:      graph,
		}
	}()
}

func startCoordinator(t *testing.T, s *store.Store, q *worker.Queue[oci.Reference], hub *events.Hub[models.PlatformEvent]) (context.CancelFunc, chan platform.Snapshot, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	ch := make(chan platform.Snapshot)
	done := make(chan struct{})

	go func() {
		defer close(done)
		HandleGraphs(ctx, &fakeContinuousGrapher{snapshots: ch}, hub, s, q)
	}()

	return cancel, ch, done
}

func stopCoordinator(cancel context.CancelFunc, done <-chan struct{}) {
	cancel()
	<-done
}

func rawReferences(t *testing.T, ctx context.Context, s *store.Store) []string {
	t.Helper()
	rawImages, err := s.ListRawImages(ctx, nil)
	require.NoError(t, err)
	references := make([]string, 0, len(rawImages))
	for _, image := range rawImages {
		references = append(references, image.Reference)
	}
	return references
}

// TestHandleGraphsGenerationArbitration verifies that complete snapshots are
// published, that new images are enqueued and that a late, older scan cannot
// overwrite a newer snapshot.
func TestHandleGraphsGenerationArbitration(t *testing.T) {
	_, uri := newTestStores(t, false)
	writeStore := openTestStore(t, uri, false)
	readStore := openTestStore(t, uri, true)
	queue := worker.NewQueue[oci.Reference](10, 0)
	t.Cleanup(queue.Close)
	hub := events.NewReplayHub[models.PlatformEvent]()

	cancel, ch, done := startCoordinator(t, writeStore, queue, hub)
	defer stopCoordinator(cancel, done)
	ctx := t.Context()

	mongo, err := oci.ParseReference("mongo:4")
	require.NoError(t, err)
	redis, err := oci.ParseReference("redis:7")
	require.NoError(t, err)

	sendSnapshot(t, ch, 1, imageGraph(t, "mongo:4"))

	require.Eventually(t, func() bool {
		_, generation, ok, err := readStore.GetConfirmedSnapshot(ctx)
		return err == nil && ok && generation == 1
	}, time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return queue.Len() == 1 }, time.Second, 10*time.Millisecond)

	// A newer snapshot adds redis
	sendSnapshot(t, ch, 3, imageGraph(t, "mongo:4", "redis:7"))
	require.Eventually(t, func() bool {
		_, generation, _, err := readStore.GetConfirmedSnapshot(ctx)
		return err == nil && generation == 3
	}, time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return queue.Len() == 2 }, time.Second, 10*time.Millisecond)

	// A late, older snapshot carrying nginx must be dropped
	sendSnapshot(t, ch, 2, imageGraph(t, "nginx:1"))

	assert.Never(t, func() bool {
		_, generation, _, err := readStore.GetConfirmedSnapshot(ctx)
		return err == nil && generation == 2
	}, 200*time.Millisecond, 20*time.Millisecond)

	references := rawReferences(t, ctx, readStore)
	assert.Len(t, references, 2)
	assert.Contains(t, references, mongo.String())
	assert.Contains(t, references, redis.String())

	pending, err := readStore.ListPendingReferences(ctx)
	require.NoError(t, err)
	assert.Empty(t, pending)

	backlog := queue.Len()
	assert.Equal(t, 2, backlog)
}

// TestHandleGraphsQueueClosedKeepsOutbox verifies that references committed by
// a snapshot stay recorded when the processing queue is closed and are only
// re-enqueued, deduplicated, on recovery.
func TestHandleGraphsQueueClosedKeepsOutbox(t *testing.T) {
	writeStore1, uri := newTestStores(t, false)
	closedQueue := worker.NewQueue[oci.Reference](10, 0)
	closedQueue.Close()
	hub := events.NewReplayHub[models.PlatformEvent]()

	cancel1, ch1, done1 := startCoordinator(t, writeStore1, closedQueue, hub)

	sendSnapshot(t, ch1, 1, imageGraph(t, "mongo:4"))

	require.Eventually(t, func() bool {
		_, generation, ok, err := writeStore1.GetConfirmedSnapshot(t.Context())
		return err == nil && ok && generation == 1
	}, time.Second, 10*time.Millisecond)

	// The snapshot was confirmed but the reference could not be enqueued. It
	// remains in the outbox.
	require.Eventually(t, func() bool {
		pending, err := writeStore1.ListPendingReferences(t.Context())
		return err == nil && len(pending) == 1 && pending[0] != ""
	}, time.Second, 10*time.Millisecond)

	stopCoordinator(cancel1, done1)

	// A restarted process recovers the outbox into a fresh queue
	require.NoError(t, writeStore1.Close())
	writeStore2, err := store.New(t.Context(), uri, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = writeStore2.Close() })

	freshQueue := worker.NewQueue[oci.Reference](10, 0)
	t.Cleanup(freshQueue.Close)

	cancel2, _, done2 := startCoordinator(t, writeStore2, freshQueue, events.NewReplayHub[models.PlatformEvent]())
	defer stopCoordinator(cancel2, done2)

	require.Eventually(t, func() bool { return freshQueue.Len() == 1 }, time.Second, 10*time.Millisecond)

	require.Eventually(t, func() bool {
		pending, err := writeStore2.ListPendingReferences(t.Context())
		return err == nil && len(pending) == 0
	}, time.Second, 10*time.Millisecond)
}

// TestHandleGraphsDatabaseFailureKeepsPreviousSnapshot verifies that a snapshot
// that cannot be written does not replace the last confirmed snapshot and that
// the candidate is retained and retried.
func TestHandleGraphsDatabaseFailureKeepsPreviousSnapshot(t *testing.T) {
	writeStore, uri := newTestStores(t, false)
	queue := worker.NewQueue[oci.Reference](10, 0)
	t.Cleanup(queue.Close)

	cancel1, ch1, done1 := startCoordinator(t, writeStore, queue, events.NewReplayHub[models.PlatformEvent]())

	sendSnapshot(t, ch1, 1, imageGraph(t, "mongo:4"))

	require.Eventually(t, func() bool {
		_, generation, ok, err := writeStore.GetConfirmedSnapshot(t.Context())
		return err == nil && ok && generation == 1
	}, time.Second, 10*time.Millisecond)
	stopCoordinator(cancel1, done1)
	require.NoError(t, writeStore.Close())

	// A new process against a read-only database cannot publish anything. The
	// last confirmed snapshot must remain current while the candidate is
	// retained for retry.
	readOnlyStore, err := store.New(t.Context(), uri, true)
	require.NoError(t, err)
	t.Cleanup(func() { _ = readOnlyStore.Close() })

	closedQueue := worker.NewQueue[oci.Reference](10, 0)
	t.Cleanup(closedQueue.Close)

	cancel2, ch2, done2 := startCoordinator(t, readOnlyStore, closedQueue, events.NewReplayHub[models.PlatformEvent]())

	sendSnapshot(t, ch2, 1, imageGraph(t, "mongo:4", "redis:7"))

	// Let the immediate publish attempt fail while the candidate stays retained
	time.Sleep(300 * time.Millisecond)

	_, generation, ok, err := readOnlyStore.GetConfirmedSnapshot(t.Context())
	require.NoError(t, err)
	require.True(t, ok)
	assert.EqualValues(t, 1, generation)

	references := rawReferences(t, t.Context(), readOnlyStore)
	mongo, err := oci.ParseReference("mongo:4")
	require.NoError(t, err)
	assert.Len(t, references, 1)
	assert.Contains(t, references, mongo.String())

	stopCoordinator(cancel2, done2)
}

// labeledTestNode is a docker resource carrying cupdate policy labels.
type labeledTestNode struct {
	id     string
	labels platform.Labels
}

func (n *labeledTestNode) ID() string   { return n.id }
func (n *labeledTestNode) Type() string { return "docker/" + string(docker.ResourceKindContainer) }
func (n *labeledTestNode) Kind() docker.ResourceKind {
	return docker.ResourceKindContainer
}
func (n *labeledTestNode) Name() string                            { return n.id }
func (n *labeledTestNode) String() string                          { return n.id }
func (n *labeledTestNode) Labels() platform.Labels                 { return n.labels }
func (n *labeledTestNode) InternalLabels() platform.InternalLabels { return nil }

func TestBuildSnapshotImagesLabelPoliciesAndEmptyGraph(t *testing.T) {
	// Empty graph stays compatible
	assert.Empty(t, buildSnapshotImages(platform.NewGraph()))

	// Ignore policy removes the whole image tree
	ignored := platform.NewGraph()
	ignoredRef, err := oci.ParseReference("ignored:1")
	require.NoError(t, err)
	ignored.InsertTree(
		platform.ImageNode{Reference: ignoredRef},
		&labeledTestNode{id: "ignored/resource", labels: platform.Labels{"config.cupdate/ignore": "true"}},
	)
	assert.Empty(t, buildSnapshotImages(ignored))

	// Pin policy is resolved onto the image's labels
	pinned := platform.NewGraph()
	pinnedRef, err := oci.ParseReference("pinned:1")
	require.NoError(t, err)
	pinned.InsertTree(
		platform.ImageNode{Reference: pinnedRef},
		&labeledTestNode{id: "pinned/resource", labels: platform.Labels{"config.cupdate/pin": "true"}},
	)
	images := buildSnapshotImages(pinned)
	require.Len(t, images, 1)
	assert.Equal(t, pinnedRef.String(), images[0].Reference)
	pinnedNodeID := fmt.Sprintf("oci/image/%s", pinnedRef.String())
	assert.Equal(t, "true", images[0].Graph.Nodes[pinnedNodeID].Labels["config.cupdate/pin"])

	// A normal single discovery produces a single raw image
	normal := imageGraph(t, "mongo:4")
	single := buildSnapshotImages(normal)
	require.Len(t, single, 1)
	mongo, err := oci.ParseReference("mongo:4")
	require.NoError(t, err)
	assert.Equal(t, mongo.String(), single[0].Reference)
}
