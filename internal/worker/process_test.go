package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/AlexGustafsson/cupdate/internal/httptest"
	"github.com/AlexGustafsson/cupdate/internal/httputil"
	"github.com/AlexGustafsson/cupdate/internal/models"
	"github.com/AlexGustafsson/cupdate/internal/oci"
	"github.com/AlexGustafsson/cupdate/internal/store"
	"github.com/AlexGustafsson/cupdate/internal/workflow/imageworkflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()

	uri := "file://" + t.TempDir() + "/sqlite.db"
	require.NoError(t, store.Initialize(t.Context(), uri))

	store, err := store.New(t.Context(), uri, false)
	require.NoError(t, err)

	t.Cleanup(func() { store.Close() })
	return store
}

// TestProcessRawImageGenerationLifecycle pins a digest reference, collects it,
// publishes a complete generation and then reuses the receipts without making
// any new requests.
func TestProcessRawImageGenerationLifecycle(t *testing.T) {
	state := newTestStore(t)
	ctx := t.Context()

	digest := "sha256:" + repeat("a", 64)
	reference := "example.com/app@" + digest

	_, err := state.InsertRawImage(ctx, &models.RawImage{
		Reference: reference,
		Tags:      []string{},
		Graph:     models.Graph{Edges: map[string]map[string]bool{}, Nodes: map[string]models.GraphNode{}},
	})
	require.NoError(t, err)

	manifestBody := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:cfg","size":2},"layers":[]}`
	manifestSum := sha256.Sum256([]byte(manifestBody))
	manifestDigest := "sha256:" + hex.EncodeToString(manifestSum[:])

	manifestResponse := func() httptest.Response {
		return httptest.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/vnd.oci.image.manifest.v1+json"}},
			Body:       manifestBody,
		}
	}

	client := &httptest.Client{
		T: t,
		Requests: []httptest.Request{
			// oci job: get manifest
			{Expectations: httptest.RequestExpectations{URL: "https://example.com/v2/app/manifests/" + digest}, Response: manifestResponse()},
			// oci job: get annotations -> manifest blob (rewritten to the body's digest)
			{Expectations: httptest.RequestExpectations{URL: "https://example.com/v2/app/manifests/" + manifestDigest}, Response: manifestResponse()},
			// oci job: config blob
			{
				Expectations: httptest.RequestExpectations{URL: "https://example.com/v2/app/blobs/sha256:cfg"},
				Response: httptest.Response{
					StatusCode: http.StatusOK,
					Body:       `{"config":{"Labels":{"org.opencontainers.image.description":"An app"}}}`,
				},
			},
			// attestations job: get manifest
			{Expectations: httptest.RequestExpectations{URL: "https://example.com/v2/app/manifests/" + digest}, Response: manifestResponse()},
			// attestations job: referrers (none)
			{
				Expectations: httptest.RequestExpectations{URL: "https://example.com/v2/app/referrers/" + manifestDigest},
				Response:     httptest.Response{StatusCode: http.StatusNotFound},
			},
		},
	}

	w := New(client, state, httputil.NewAuthMux(), nil)
	ref, err := oci.ParseReference(reference)
	require.NoError(t, err)

	require.NoError(t, w.ProcessRawImage(ctx, ref))

	generation, err := state.GetCurrentGeneration(ctx, reference)
	require.NoError(t, err)
	assert.Equal(t, digest, generation.Digest)
	assert.Contains(t, generation.Platform, "/")
	assert.Equal(t, models.ImageGenerationStatusComplete, generation.Status)

	stages := map[string]models.ImageGenerationStage{}
	for _, stage := range generation.Stages {
		stages[stage.Name] = stage
		assert.Equal(t, models.ImageGenerationStageStatusSucceeded, stage.Status, "stage %s failed: %s", stage.Name, stage.Error)
	}
	assert.Contains(t, stages, imageworkflow.StageManifest)
	assert.Contains(t, stages, imageworkflow.StageVersions)
	assert.Contains(t, stages, imageworkflow.StageProvenance)
	assert.Contains(t, stages, imageworkflow.StageSBOM)
	assert.Contains(t, stages, imageworkflow.StageDescription)
	assert.Contains(t, stages, imageworkflow.StageWorkflow)

	image, err := state.GetImage(ctx, reference)
	require.NoError(t, err)
	assert.Contains(t, image.Tags, "status:complete")

	// Re-processing must make zero network requests - all receipts are reused
	reuseClient := &httptest.Client{T: t, Requests: nil}
	reuseWorker := New(reuseClient, state, httputil.NewAuthMux(), nil)
	require.NoError(t, reuseWorker.ProcessRawImage(context.Background(), ref))

	reused, err := state.GetCurrentGeneration(ctx, reference)
	require.NoError(t, err)
	assert.Equal(t, generation.ID, reused.ID)
	assert.Equal(t, models.ImageGenerationStatusComplete, reused.Status)
}

// TestProcessRawImageFailedManifestPublishesFailedGeneration ensures an
// unreachable registry results in a failed (but published) generation.
func TestProcessRawImageFailedManifestPublishesFailedGeneration(t *testing.T) {
	state := newTestStore(t)
	ctx := t.Context()

	reference := "example.com/app:1.0.0"

	_, err := state.InsertRawImage(ctx, &models.RawImage{
		Reference: reference,
		Tags:      []string{},
		Graph:     models.Graph{Edges: map[string]map[string]bool{}, Nodes: map[string]models.GraphNode{}},
	})
	require.NoError(t, err)

	// Every request fails. The pinned digest resolution, and later the workflow
	// oci job, both fail.
	client := &httptest.Client{T: t}
	for i := 0; i < 10; i++ {
		client.Requests = append(client.Requests, httptest.Request{
			Response: httptest.Response{StatusCode: http.StatusBadGateway},
		})
	}

	w := New(client, state, httputil.NewAuthMux(), nil)
	ref, err := oci.ParseReference(reference)
	require.NoError(t, err)

	require.NoError(t, w.ProcessRawImage(ctx, ref))

	generation, err := state.GetCurrentGeneration(ctx, reference)
	require.NoError(t, err)
	assert.Equal(t, models.ImageGenerationStatusFailed, generation.Status)

	image, err := state.GetImage(ctx, reference)
	require.NoError(t, err)
	assert.Contains(t, image.Tags, "status:failed")
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n)
	for range n {
		out = append(out, s[0])
	}
	return string(out)
}
