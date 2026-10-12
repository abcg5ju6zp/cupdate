package store

import (
	"context"
	"testing"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func emptyGraph() models.Graph {
	return models.Graph{
		Edges: map[string]map[string]bool{},
		Nodes: map[string]models.GraphNode{},
	}
}

func rawImage(reference string) *models.RawImage {
	return &models.RawImage{
		Reference: reference,
		Tags:      []string{"kubernetes"},
		Graph:     emptyGraph(),
	}
}

func TestStorePublishSnapshotAtomic(t *testing.T) {
	store := newStore(t, false)
	defer store.Close()
	ctx := t.Context()

	result, err := store.PublishSnapshot(ctx, "static", 1, []*models.RawImage{
		rawImage("mongo:4"),
		rawImage("redis:7"),
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"mongo:4", "redis:7"}, result.Unprocessed)
	assert.Zero(t, result.Removed)

	// The full candidate is visible
	rawImages, err := store.ListRawImages(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, rawImages, 2)

	// Unprocessed stubs were created
	image, err := store.GetImage(ctx, "mongo:4")
	require.NoError(t, err)
	assert.Contains(t, image.Tags, "unprocessed")
	assert.Contains(t, image.Tags, "kubernetes")

	// Unprocessed references are tracked in the outbox until enqueued
	pending, err := store.ListPendingReferences(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"mongo:4", "redis:7"}, pending)

	// The generation was confirmed
	platform, generation, ok, err := store.GetConfirmedSnapshot(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "static", platform)
	assert.EqualValues(t, 1, generation)
}

func TestStorePublishSnapshotCleanupOnlyAfterConfirmation(t *testing.T) {
	store := newStore(t, false)
	defer store.Close()
	ctx := t.Context()

	_, err := store.PublishSnapshot(ctx, "static", 1, []*models.RawImage{
		rawImage("mongo:4"),
		rawImage("redis:7"),
	})
	require.NoError(t, err)

	// Mark mongo as processed - it must no longer be re-enqueued
	processed := rawImage("mongo:4")
	processed.LastProcessed = time.Now()
	_, err = store.InsertRawImage(ctx, processed)
	require.NoError(t, err)
	require.NoError(t, store.DeletePendingReference(ctx, "mongo:4"))

	// A new snapshot drops redis and adds nginx
	result, err := store.PublishSnapshot(ctx, "static", 2, []*models.RawImage{
		rawImage("mongo:4"),
		rawImage("nginx:1"),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"nginx:1"}, result.Unprocessed)
	assert.EqualValues(t, 1, result.Removed)

	rawImages, err := store.ListRawImages(ctx, nil)
	require.NoError(t, err)
	references := make([]string, len(rawImages))
	for i, image := range rawImages {
		references[i] = image.Reference
	}
	assert.ElementsMatch(t, []string{"mongo:4", "nginx:1"}, references)

	// The pending row for redis cascaded away with the raw image
	pending, err := store.ListPendingReferences(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"nginx:1"}, pending)

	_, generation, _, err := store.GetConfirmedSnapshot(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 2, generation)
}

func TestStorePublishSnapshotEmptyGraph(t *testing.T) {
	store := newStore(t, false)
	defer store.Close()
	ctx := t.Context()

	_, err := store.PublishSnapshot(ctx, "static", 1, []*models.RawImage{rawImage("mongo:4")})
	require.NoError(t, err)

	// An empty discovery confirms an empty snapshot and removes all images
	result, err := store.PublishSnapshot(ctx, "static", 2, []*models.RawImage{})
	require.NoError(t, err)
	assert.Empty(t, result.Unprocessed)
	assert.EqualValues(t, 1, result.Removed)

	rawImages, err := store.ListRawImages(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, rawImages)
}

func TestStorePublishSnapshotStaleGeneration(t *testing.T) {
	store := newStore(t, false)
	defer store.Close()
	ctx := t.Context()

	_, err := store.PublishSnapshot(ctx, "static", 5, []*models.RawImage{rawImage("mongo:4")})
	require.NoError(t, err)

	// A late, older scan cannot overwrite the confirmed snapshot
	_, err = store.PublishSnapshot(ctx, "static", 5, []*models.RawImage{rawImage("evil:1")})
	assert.ErrorIs(t, err, ErrStaleSnapshot)

	_, err = store.PublishSnapshot(ctx, "static", 4, []*models.RawImage{rawImage("evil:1")})
	assert.ErrorIs(t, err, ErrStaleSnapshot)

	rawImages, err := store.ListRawImages(ctx, nil)
	require.NoError(t, err)
	require.Len(t, rawImages, 1)
	assert.Equal(t, "mongo:4", rawImages[0].Reference)

	_, generation, _, err := store.GetConfirmedSnapshot(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 5, generation)
}

func TestStorePublishSnapshotFailureKeepsPreviousSnapshot(t *testing.T) {
	store := newStore(t, false)
	defer store.Close()
	ctx := t.Context()

	_, err := store.PublishSnapshot(ctx, "static", 1, []*models.RawImage{rawImage("mongo:4")})
	require.NoError(t, err)

	// A failed publish rolls the complete candidate back. It can safely be
	// retried afterwards
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = store.PublishSnapshot(canceledCtx, "static", 2, []*models.RawImage{
		rawImage("mongo:4"),
		rawImage("redis:7"),
	})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrStaleSnapshot)

	rawImages, err := store.ListRawImages(ctx, nil)
	require.NoError(t, err)
	require.Len(t, rawImages, 1)
	assert.Equal(t, "mongo:4", rawImages[0].Reference)

	_, generation, _, err := store.GetConfirmedSnapshot(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 1, generation)

	// Retrying the retained candidate succeeds and confirms the new generation
	_, err = store.PublishSnapshot(ctx, "static", 2, []*models.RawImage{
		rawImage("mongo:4"),
		rawImage("redis:7"),
	})
	require.NoError(t, err)

	_, generation, _, err = store.GetConfirmedSnapshot(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 2, generation)
}

func TestStorePendingReferencesOutbox(t *testing.T) {
	store := newStore(t, false)
	defer store.Close()
	ctx := t.Context()

	_, err := store.PublishSnapshot(ctx, "static", 1, []*models.RawImage{rawImage("mongo:4")})
	require.NoError(t, err)

	pending, err := store.ListPendingReferences(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"mongo:4"}, pending)

	require.NoError(t, store.DeletePendingReference(ctx, "mongo:4"))

	pending, err = store.ListPendingReferences(ctx)
	require.NoError(t, err)
	assert.Empty(t, pending)
}
