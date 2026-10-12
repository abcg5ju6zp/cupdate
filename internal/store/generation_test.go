package store

import (
	"testing"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newGenerationPublication(reference string, generation *models.ImageGeneration) *ImageGenerationPublication {
	return &ImageGenerationPublication{
		Generation: generation,
		Image: &models.Image{
			Reference:    reference,
			Description:  "an image",
			Tags:         []string{"status:complete"},
			Links:        []models.ImageLink{},
			LastModified: time.Now(),
		},
		HasDescription: true,
		Description: &models.ImageDescription{
			Markdown: "full description",
		},
		Vulnerabilities: make([]models.ImageVulnerability, 0),
		Graph: &models.Graph{
			Edges: map[string]map[string]bool{},
			Nodes: map[string]models.GraphNode{},
		},
		WorkflowRun: models.WorkflowRun{
			Started: time.Now(),
			Result:  models.WorkflowRunResultSucceeded,
			Jobs:    []models.JobRun{},
		},
	}
}

func TestGenerationResumeAndPublish(t *testing.T) {
	store := newStore(t, false)
	defer store.Close()

	ctx := t.Context()

	// A raw image must exist for FK cascades
	_, err := store.InsertRawImage(ctx, &models.RawImage{
		Reference: "mongo:4",
		Tags:      []string{},
		Graph:     models.Graph{Edges: map[string]map[string]bool{}, Nodes: map[string]models.GraphNode{}},
	})
	require.NoError(t, err)

	generation, err := store.BeginGeneration(ctx, "mongo:4", "mongo:4", "sha256:abc", "linux/amd64")
	require.NoError(t, err)
	assert.Equal(t, models.ImageGenerationStatusPartial, generation.Status)

	// Beginning again reuses the same generation and its receipts
	generation.Stages = []models.ImageGenerationStage{
		{
			Name:      "manifest",
			Status:    models.ImageGenerationStageStatusSucceeded,
			Source:    "docker.io",
			Blob:      []byte(`{}`),
			UpdatedAt: time.Now(),
		},
		{
			Name:      "description",
			Status:    models.ImageGenerationStageStatusFailed,
			Error:     "service unavailable",
			UpdatedAt: time.Now(),
		},
	}
	completed := time.Now()
	generation.Completed = &completed
	generation.Status = models.ImageGenerationStatusPartial

	publication := newGenerationPublication("mongo:4", generation)
	require.NoError(t, store.PublishGeneration(ctx, publication))

	resumed, err := store.BeginGeneration(ctx, "mongo:4", "mongo:4", "sha256:abc", "linux/amd64")
	require.NoError(t, err)
	assert.Equal(t, generation.ID, resumed.ID)

	receipts := map[string]models.ImageGenerationStage{}
	for _, stage := range resumed.Stages {
		receipts[stage.Name] = stage
	}
	assert.Contains(t, receipts, "manifest")
	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, receipts["manifest"].Status)
	assert.Equal(t, "docker.io", receipts["manifest"].Source)
	assert.Contains(t, receipts, "description")
	assert.Equal(t, models.ImageGenerationStageStatusFailed, receipts["description"].Status)

	// The current generation is queryable
	current, err := store.GetCurrentGeneration(ctx, "mongo:4")
	require.NoError(t, err)
	assert.Equal(t, generation.ID, current.ID)
	assert.Equal(t, "sha256:abc", current.Digest)
	assert.Equal(t, "linux/amd64", current.Platform)

	// Published data of the generation is visible
	description, err := store.GetImageDescription(ctx, "mongo:4")
	require.NoError(t, err)
	assert.Equal(t, "full description", description.Markdown)
}

func TestGenerationMovedTagRejectsStaleWrite(t *testing.T) {
	store := newStore(t, false)
	defer store.Close()

	ctx := t.Context()

	_, err := store.InsertRawImage(ctx, &models.RawImage{
		Reference: "mongo:4",
		Tags:      []string{},
		Graph:     models.Graph{Edges: map[string]map[string]bool{}, Nodes: map[string]models.GraphNode{}},
	})
	require.NoError(t, err)

	oldGeneration, err := store.BeginGeneration(ctx, "mongo:4", "mongo:4", "sha256:old", "linux/amd64")
	require.NoError(t, err)

	require.NoError(t, store.PublishGeneration(ctx, newGenerationPublication("mongo:4", oldGeneration)))

	// The tag moves to a new digest - a new generation starts
	newGeneration, err := store.BeginGeneration(ctx, "mongo:4", "mongo:4", "sha256:new", "linux/amd64")
	require.NoError(t, err)
	assert.Greater(t, newGeneration.ID, oldGeneration.ID)

	require.NoError(t, store.PublishGeneration(ctx, newGenerationPublication("mongo:4", newGeneration)))

	// A late write from the old worker must not overwrite the new generation
	err = store.PublishGeneration(ctx, newGenerationPublication("mongo:4", oldGeneration))
	assert.ErrorIs(t, err, ErrStaleGeneration)

	current, err := store.GetCurrentGeneration(ctx, "mongo:4")
	require.NoError(t, err)
	assert.Equal(t, newGeneration.ID, current.ID)
	assert.Equal(t, "sha256:new", current.Digest)
}

func TestGenerationPartialPublishing(t *testing.T) {
	store := newStore(t, false)
	defer store.Close()

	ctx := t.Context()

	_, err := store.InsertRawImage(ctx, &models.RawImage{
		Reference: "mongo:4",
		Tags:      []string{},
		Graph:     models.Graph{Edges: map[string]map[string]bool{}, Nodes: map[string]models.GraphNode{}},
	})
	require.NoError(t, err)

	generation, err := store.BeginGeneration(ctx, "mongo:4", "mongo:4", "sha256:abc", "linux/amd64")
	require.NoError(t, err)

	// Only the description stage is present - other stage tables must not have
	// rows for the generation
	publication := newGenerationPublication("mongo:4", generation)
	publication.HasDescription = false
	require.NoError(t, store.PublishGeneration(ctx, publication))

	scorecard, err := store.GetImageScorecard(ctx, "mongo:4")
	require.NoError(t, err)
	assert.Nil(t, scorecard)
	sbom, err := store.GetImageSBOM(ctx, "mongo:4")
	require.NoError(t, err)
	assert.Nil(t, sbom)

	// The image itself is visible even for a partial generation
	image, err := store.GetImage(ctx, "mongo:4")
	require.NoError(t, err)
	assert.Equal(t, "an image", image.Description)

	// Publishing again with the scorecard present makes it visible
	generation.Stages = []models.ImageGenerationStage{
		{Name: "scorecard", Status: models.ImageGenerationStageStatusSucceeded, UpdatedAt: time.Now()},
	}
	publication.HasScorecard = true
	publication.Scorecard = &models.ImageScorecard{
		Score: 5.0,
		Risk:  models.ImageScorecardRiskLow,
	}
	require.NoError(t, store.PublishGeneration(ctx, publication))

	scorecard, err = store.GetImageScorecard(ctx, "mongo:4")
	require.NoError(t, err)
	assert.Equal(t, float32(5.0), scorecard.Score)
}

func TestGenerationFailedPinDoesNotTakeOver(t *testing.T) {
	store := newStore(t, false)
	defer store.Close()

	ctx := t.Context()

	_, err := store.InsertRawImage(ctx, &models.RawImage{
		Reference: "mongo:4",
		Tags:      []string{},
		Graph:     models.Graph{Edges: map[string]map[string]bool{}, Nodes: map[string]models.GraphNode{}},
	})
	require.NoError(t, err)

	// A good generation establishes visible data
	good, err := store.BeginGeneration(ctx, "mongo:4", "mongo:4", "sha256:good", "linux/amd64")
	require.NoError(t, err)
	require.NoError(t, store.PublishGeneration(ctx, newGenerationPublication("mongo:4", good)))

	// A later run cannot pin the digest (transient registry failure)
	bad, err := store.BeginGeneration(ctx, "mongo:4", "mongo:4", "", "linux/amd64")
	require.NoError(t, err)
	assert.NotEqual(t, good.ID, bad.ID)

	// The good generation stays current
	current, err := store.GetCurrentGeneration(ctx, "mongo:4")
	require.NoError(t, err)
	assert.Equal(t, good.ID, current.ID)

	// Publishing the failed generation is rejected as stale - no clobbering
	err = store.PublishGeneration(ctx, newGenerationPublication("mongo:4", bad))
	assert.ErrorIs(t, err, ErrStaleGeneration)

	// Once the registry recovers, a pinned generation takes over
	recovered, err := store.BeginGeneration(ctx, "mongo:4", "mongo:4", "sha256:good", "linux/amd64")
	require.NoError(t, err)
	assert.Equal(t, good.ID, recovered.ID)
}

func TestGenerationPlatformsAreIndependent(t *testing.T) {
	store := newStore(t, false)
	defer store.Close()

	ctx := t.Context()

	_, err := store.InsertRawImage(ctx, &models.RawImage{
		Reference: "mongo:4",
		Tags:      []string{},
		Graph:     models.Graph{Edges: map[string]map[string]bool{}, Nodes: map[string]models.GraphNode{}},
	})
	require.NoError(t, err)

	amd64, err := store.BeginGeneration(ctx, "mongo:4", "mongo:4", "sha256:abc", "linux/amd64")
	require.NoError(t, err)
	arm64, err := store.BeginGeneration(ctx, "mongo:4", "mongo:4", "sha256:abc", "linux/arm64")
	require.NoError(t, err)

	assert.NotEqual(t, amd64.ID, arm64.ID)
}
