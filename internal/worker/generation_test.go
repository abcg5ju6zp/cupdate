package worker

import (
	"testing"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/models"
	"github.com/AlexGustafsson/cupdate/internal/workflow/imageworkflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func jobRun(id string, result models.JobRunResult, stepResults ...models.StepRunResult) models.JobRun {
	steps := make([]models.StepRun, len(stepResults))
	for i, result := range stepResults {
		steps[i] = models.StepRun{Result: result}
		if result == models.StepRunResultFailed {
			steps[i].Error = "step failed"
		}
	}
	return models.JobRun{
		JobID:  id,
		Result: result,
		Steps:  steps,
	}
}

func allSucceeded(id string, steps int) models.JobRun {
	results := make([]models.StepRunResult, steps)
	for i := range results {
		results[i] = models.StepRunResultSucceeded
	}
	return jobRun(id, models.JobRunResultSucceeded, results...)
}

func skipped(id string, steps int) models.JobRun {
	results := make([]models.StepRunResult, steps)
	for i := range results {
		results[i] = models.StepRunResultSkipped
	}
	return jobRun(id, models.JobRunResultSkipped, results...)
}

func findOutcome(outcomes []evaluatedStage, name string) evaluatedStage {
	for _, outcome := range outcomes {
		if outcome.name == name {
			return outcome
		}
	}
	return evaluatedStage{name: name, status: "missing"}
}

func TestEvaluateStagesAllSucceeded(t *testing.T) {
	data := &imageworkflow.Data{
		FullDescription: imageworkflow.Result[*models.ImageDescription]{OK: true, Value: &models.ImageDescription{Markdown: "desc"}},
		ReleaseNotes:    imageworkflow.Result[*models.ImageReleaseNotes]{OK: true},
		Scorecard:       imageworkflow.Result[*models.ImageScorecard]{OK: true},
		Provenance:      imageworkflow.Result[*models.ImageProvenance]{OK: true},
		SBOM:            imageworkflow.Result[*models.ImageSBOM]{OK: true},
	}

	run := &models.WorkflowRun{
		Jobs: []models.JobRun{
			allSucceeded("oci", 4),
			allSucceeded("versions", 4),
			allSucceeded("attestations", 4),
			allSucceeded("docker", 6),
			skipped("ghcr", 4),
			skipped("quay", 2),
			skipped("gitlab", 3),
			skipped("github", 7),
			skipped("openssf", 2),
			skipped("sbom", 2),
		},
	}

	outcomes := evaluateStages(data, run, "docker.io")

	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, findOutcome(outcomes, imageworkflow.StageManifest).status)
	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, findOutcome(outcomes, imageworkflow.StageVersions).status)
	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, findOutcome(outcomes, imageworkflow.StageProvenance).status)
	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, findOutcome(outcomes, imageworkflow.StageSBOM).status)

	description := findOutcome(outcomes, imageworkflow.StageDescription)
	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, description.status)
	assert.Equal(t, "docker.io", description.source)

	vulnerabilities := findOutcome(outcomes, imageworkflow.StageVulnerabilities)
	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, vulnerabilities.status)
	assert.Equal(t, "docker.io", vulnerabilities.source)

	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, findOutcome(outcomes, imageworkflow.StageScorecard).status)
	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, findOutcome(outcomes, imageworkflow.StageReleaseNotes).status)
}

func TestEvaluateStagesVulnerabilityFailureKeepsOtherStages(t *testing.T) {
	data := &imageworkflow.Data{
		FullDescription: imageworkflow.Result[*models.ImageDescription]{OK: true, Value: &models.ImageDescription{Markdown: "desc"}},
	}

	run := &models.WorkflowRun{
		Jobs: []models.JobRun{
			allSucceeded("oci", 4),
			allSucceeded("versions", 4),
			allSucceeded("attestations", 4),
			// GitHub advisories (step 5) fail, all other steps succeed
			jobRun("github", models.JobRunResultFailed,
				models.StepRunResultSucceeded, // init
				models.StepRunResultSucceeded, // repository
				models.StepRunResultSucceeded, // links
				models.StepRunResultSucceeded, // release
				models.StepRunResultSucceeded, // release notes
				models.StepRunResultFailed,    // advisories
				models.StepRunResultSkipped,   // finalize
			),
			skipped("docker", 6),
			skipped("quay", 2),
			skipped("ghcr", 4),
			skipped("gitlab", 3),
			skipped("openssf", 2),
			skipped("sbom", 2),
		},
	}

	data.ReleaseNotes.OK = true

	outcomes := evaluateStages(data, run, "ghcr.io")

	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, findOutcome(outcomes, imageworkflow.StageManifest).status)
	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, findOutcome(outcomes, imageworkflow.StageReleaseNotes).status)
	vulnerabilities := findOutcome(outcomes, imageworkflow.StageVulnerabilities)
	assert.Equal(t, models.ImageGenerationStageStatusFailed, vulnerabilities.status)
	assert.Equal(t, "github.com", vulnerabilities.source)
}

func TestEvaluateStagesManifestFailure(t *testing.T) {
	data := &imageworkflow.Data{}

	run := &models.WorkflowRun{
		Jobs: []models.JobRun{
			// Registry setup failed
			jobRun("oci", models.JobRunResultFailed, models.StepRunResultFailed),
			skipped("versions", 4),
			skipped("attestations", 4),
			skipped("docker", 6),
			skipped("quay", 2),
			skipped("ghcr", 4),
			skipped("gitlab", 3),
			skipped("github", 7),
			skipped("openssf", 2),
			skipped("sbom", 2),
		},
	}

	outcomes := evaluateStages(data, run, "registry.example")
	assert.Equal(t, models.ImageGenerationStageStatusFailed, findOutcome(outcomes, imageworkflow.StageManifest).status)
}

func TestEvaluateStagesTruncatedAttestationBlob(t *testing.T) {
	data := &imageworkflow.Data{}
	data.AddStageError(imageworkflow.StageProvenance, "sha256:dead: unexpected EOF")

	run := &models.WorkflowRun{
		Jobs: []models.JobRun{
			allSucceeded("oci", 4),
			allSucceeded("versions", 4),
			allSucceeded("attestations", 4),
			skipped("docker", 6),
			skipped("quay", 2),
			skipped("ghcr", 4),
			skipped("gitlab", 3),
			skipped("github", 7),
			skipped("openssf", 2),
			skipped("sbom", 2),
		},
	}

	outcomes := evaluateStages(data, run, "docker.io")
	assert.Equal(t, models.ImageGenerationStageStatusFailed, findOutcome(outcomes, imageworkflow.StageProvenance).status)
	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, findOutcome(outcomes, imageworkflow.StageSBOM).status)
	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, findOutcome(outcomes, imageworkflow.StageManifest).status)
}

func TestMergeStagesReusesSucceededReceipt(t *testing.T) {
	prior := map[string]models.ImageGenerationStage{
		imageworkflow.StageDescription: {
			Name:      imageworkflow.StageDescription,
			Status:    models.ImageGenerationStageStatusSucceeded,
			Source:    "docker.io",
			Blob:      []byte(`{"markdown":"desc"}`),
			UpdatedAt: time.Now().Add(-time.Hour),
		},
	}

	outcomes := []evaluatedStage{
		{name: imageworkflow.StageDescription, status: models.ImageGenerationStageStatusFailed, source: "docker.io", err: "service unavailable"},
		{name: imageworkflow.StageVulnerabilities, status: models.ImageGenerationStageStatusSucceeded, source: "docker.io"},
	}

	merged := mergeStages(prior, outcomes, time.Now())

	stages := map[string]models.ImageGenerationStage{}
	for _, stage := range merged {
		stages[stage.Name] = stage
	}

	// The confirmed payload is retained, but the stage is marked failed so the
	// generation is reported as partial and the stage is retried
	require.Contains(t, stages, imageworkflow.StageDescription)
	assert.Equal(t, models.ImageGenerationStageStatusFailed, stages[imageworkflow.StageDescription].Status)
	assert.Equal(t, []byte(`{"markdown":"desc"}`), stages[imageworkflow.StageDescription].Blob)

	// New stages are added
	assert.Equal(t, models.ImageGenerationStageStatusSucceeded, stages[imageworkflow.StageVulnerabilities].Status)

	// Once the stage succeeds on a retry, it is complete again
	merged = mergeStages(map[string]models.ImageGenerationStage{
		"description": stages[imageworkflow.StageDescription],
	}, []evaluatedStage{
		{name: imageworkflow.StageDescription, status: models.ImageGenerationStageStatusSucceeded, source: "docker.io"},
	}, time.Now())

	for _, stage := range merged {
		if stage.Name == imageworkflow.StageDescription {
			assert.Equal(t, models.ImageGenerationStageStatusSucceeded, stage.Status)
		}
	}
}

func TestCanSkipWorkflow(t *testing.T) {
	generation := &models.ImageGeneration{
		Stages: []models.ImageGenerationStage{
			{Name: imageworkflow.StageManifest, Status: models.ImageGenerationStageStatusSucceeded, Blob: []byte(`{}`)},
			{Name: imageworkflow.StageWorkflow, Status: models.ImageGenerationStageStatusSucceeded, Blob: []byte(`{}`)},
		},
	}
	assert.True(t, canSkipWorkflow(generation))

	// A failed manifest means the workflow must rerun
	generation.Stages[0].Status = models.ImageGenerationStageStatusFailed
	assert.False(t, canSkipWorkflow(generation))
}
