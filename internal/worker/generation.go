package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/httputil"
	"github.com/AlexGustafsson/cupdate/internal/models"
	"github.com/AlexGustafsson/cupdate/internal/oci"
	"github.com/AlexGustafsson/cupdate/internal/workflow/imageworkflow"
)

// targetPlatform returns the platform pinned for the generation.
func targetPlatform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// pinManifestDigest resolves the manifest digest the generation is pinned to.
// Digest-pinned references are used as-is. Tagged references are resolved so
// that a tag moving during processing cannot mix another digest's data into
// the generation.
func pinManifestDigest(ctx context.Context, httpClient httputil.Requester, registryAuth *httputil.AuthMux, ref oci.Reference) (string, error) {
	if ref.HasDigest {
		return ref.Digest, nil
	}

	client := &oci.Client{
		Client:   httpClient,
		AuthFunc: registryAuth.HandleAuth,
	}

	manifest, err := client.GetManifest(ctx, ref)
	if err != nil {
		return "", err
	}

	switch m := manifest.(type) {
	case *oci.ImageManifest:
		return m.Digest, nil
	case *oci.ImageIndex:
		return m.Digest, nil
	default:
		return "", fmt.Errorf("worker: unexpected manifest type %T", manifest)
	}
}

// stageReceipts returns prior stage receipts keyed by stage name.
func stageReceipts(generation *models.ImageGeneration) map[string]models.ImageGenerationStage {
	receipts := make(map[string]models.ImageGenerationStage)
	for _, stage := range generation.Stages {
		receipts[stage.Name] = stage
	}
	return receipts
}

// hydrateData restores data from verifiable stage receipts so that only
// missing/failed stages need to be recollected. All receipts belong to the
// generation's pinned digest, so hydrating can never mix in another digest's
// data.
func hydrateData(data *imageworkflow.Data, generation *models.ImageGeneration) {
	for _, stage := range generation.Stages {
		if stage.Status != models.ImageGenerationStageStatusSucceeded {
			continue
		}

		switch stage.Name {
		case imageworkflow.StageManifest:
			if len(stage.Blob) > 0 {
				if receipt, err := imageworkflow.DecodeManifestReceipt(stage.Blob); err == nil {
					receipt.ApplyTo(data)
				}
			}
		case imageworkflow.StageDescription:
			data.FullDescription.OK = true
			data.FullDescription.Value = decodeStageBlob[models.ImageDescription](stage.Blob)
		case imageworkflow.StageReleaseNotes:
			data.ReleaseNotes.OK = true
			data.ReleaseNotes.Value = decodeStageBlob[models.ImageReleaseNotes](stage.Blob)
		case imageworkflow.StageScorecard:
			data.Scorecard.OK = true
			data.Scorecard.Value = decodeStageBlob[models.ImageScorecard](stage.Blob)
		case imageworkflow.StageProvenance:
			data.Provenance.OK = true
			data.Provenance.Value = decodeStageBlob[models.ImageProvenance](stage.Blob)
		case imageworkflow.StageSBOM:
			data.SBOM.OK = true
			data.SBOM.Value = decodeStageBlob[models.ImageSBOM](stage.Blob)
		case imageworkflow.StageVulnerabilities:
			if len(stage.Blob) > 0 {
				var vulnerabilities []models.ImageVulnerability
				if err := json.Unmarshal(stage.Blob, &vulnerabilities); err == nil {
					data.InsertVulnerabilities(vulnerabilities)
				}
			}
		}
	}
}

func decodeStageBlob[T any](blob []byte) *T {
	if len(blob) == 0 {
		return nil
	}

	var value T
	if err := json.Unmarshal(blob, &value); err != nil {
		return nil
	}
	return &value
}

// canSkipWorkflow reports whether all stages are covered by verifiable
// receipts. Concurrent queue items, service restarts and cache hits then reuse
// the receipts without recollecting any data. Any failed stage forces a rerun
// so that only the missing parts are retried.
func canSkipWorkflow(generation *models.ImageGeneration) bool {
	receipts := stageReceipts(generation)
	manifest, manifestOK := receipts[imageworkflow.StageManifest]
	if !manifestOK || manifest.Status != models.ImageGenerationStageStatusSucceeded {
		return false
	}
	if _, workflowOK := receipts[imageworkflow.StageWorkflow]; !workflowOK {
		return false
	}

	for _, stage := range generation.Stages {
		if stage.Status == models.ImageGenerationStageStatusFailed {
			return false
		}
	}
	return true
}

// hydrateWorkflowRun restores the persisted workflow run.
func hydrateWorkflowRun(generation *models.ImageGeneration) (models.WorkflowRun, bool) {
	for _, stage := range generation.Stages {
		if stage.Name == imageworkflow.StageWorkflow && len(stage.Blob) > 0 {
			var run models.WorkflowRun
			if err := json.Unmarshal(stage.Blob, &run); err == nil {
				return run, true
			}
		}
	}
	return models.WorkflowRun{}, false
}

// stepResult finds a job's step result by job and step index.
func stepResult(run *models.WorkflowRun, jobID string, stepIndex int) models.StepRun {
	for i := range run.Jobs {
		if run.Jobs[i].JobID == jobID {
			if stepIndex < len(run.Jobs[i].Steps) {
				return run.Jobs[i].Steps[stepIndex]
			}
		}
	}
	return models.StepRun{Result: models.StepRunResultSkipped}
}

func jobRan(run *models.WorkflowRun, jobID string) bool {
	for i := range run.Jobs {
		if run.Jobs[i].JobID == jobID {
			return run.Jobs[i].Result != models.JobRunResultSkipped
		}
	}
	return false
}

func jobFailed(run *models.WorkflowRun, jobID string) bool {
	for i := range run.Jobs {
		if run.Jobs[i].JobID == jobID {
			return run.Jobs[i].Result == models.JobRunResultFailed
		}
	}
	return false
}

func failedStepErrors(run *models.WorkflowRun, jobID string, stepIndices ...int) string {
	var errs []string
	for i := range run.Jobs {
		if run.Jobs[i].JobID != jobID {
			continue
		}
		for _, index := range stepIndices {
			if index < len(run.Jobs[i].Steps) && run.Jobs[i].Steps[index].Result == models.StepRunResultFailed {
				if message := run.Jobs[i].Steps[index].Error; message != "" {
					errs = append(errs, message)
				}
			}
		}
	}
	return strings.Join(errs, "; ")
}

// evaluatedStage is the freshly observed outcome of a stage.
type evaluatedStage struct {
	name   string
	status models.ImageGenerationStageStatus
	source string
	err    string
}

// evaluateStages maps workflow job/step results and non-fatal collection errors
// to independent collection stage outcomes.
func evaluateStages(data *imageworkflow.Data, run *models.WorkflowRun, domain string) []evaluatedStage {
	stageErrors := data.StageErrors()

	outcomes := make([]evaluatedStage, 0, 8)

	// Manifest stage - oci job
	{
		errs := failedStepErrors(run, "oci", 0, 1, 2, 3)
		status := models.ImageGenerationStageStatusSucceeded
		if errs != "" {
			status = models.ImageGenerationStageStatusFailed
		}
		outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageManifest, status: status, source: domain, err: errs})
	}

	// Versions stage - versions job (only meaningful if the manifest stage ran)
	if jobRan(run, "versions") {
		errs := failedStepErrors(run, "versions", 0, 1, 2, 3)
		status := models.ImageGenerationStageStatusSucceeded
		if errs != "" {
			status = models.ImageGenerationStageStatusFailed
		}
		outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageVersions, status: status, source: domain, err: errs})
	}

	// Provenance / SBOM stages - attestations job
	if jobRan(run, "attestations") {
		provenanceErr := strings.Join(stageErrors[imageworkflow.StageProvenance], "; ")
		if provenanceErr == "" {
			provenanceErr = failedStepErrors(run, "attestations", 1)
		}
		provenanceStatus := models.ImageGenerationStageStatusSucceeded
		if provenanceErr != "" {
			provenanceStatus = models.ImageGenerationStageStatusFailed
		}
		outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageProvenance, status: provenanceStatus, source: domain, err: provenanceErr})

		sbomErr := strings.Join(stageErrors[imageworkflow.StageSBOM], "; ")
		if sbomErr == "" {
			sbomErr = failedStepErrors(run, "attestations", 2)
		}
		sbomStatus := models.ImageGenerationStageStatusSucceeded
		if sbomErr != "" {
			sbomStatus = models.ImageGenerationStageStatusFailed
		}
		outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageSBOM, status: sbomStatus, source: domain, err: sbomErr})
	}

	// Description stage - docker / ghcr / gitlab jobs
	{
		source := ""
		errs := ""
		switch {
		case jobRan(run, "docker"):
			source = "docker.io"
			if !data.FullDescription.OK {
				errs = failedStepErrors(run, "docker", 0, 3)
			}
		case jobRan(run, "ghcr"):
			source = "ghcr.io"
			if !data.FullDescription.OK {
				errs = failedStepErrors(run, "ghcr", 0, 1, 2, 3)
			}
		case jobRan(run, "gitlab"):
			source = "gitlab.com"
			if !data.FullDescription.OK {
				errs = failedStepErrors(run, "gitlab", 0, 1, 2)
			}
		default:
			// No description source applies - a confirmed absence
			outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageDescription, status: models.ImageGenerationStageStatusSucceeded})
		}
		if source != "" {
			status := models.ImageGenerationStageStatusSucceeded
			if errs != "" {
				status = models.ImageGenerationStageStatusFailed
			}
			outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageDescription, status: status, source: source, err: errs})
		}
	}

	// Release notes stage - GitHub job
	if jobRan(run, "github") {
		errs := ""
		if !data.ReleaseNotes.OK {
			errs = failedStepErrors(run, "github", 1, 3, 4)
		}
		status := models.ImageGenerationStageStatusSucceeded
		if errs != "" {
			status = models.ImageGenerationStageStatusFailed
		}
		outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageReleaseNotes, status: status, source: "github.com", err: errs})
	} else {
		outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageReleaseNotes, status: models.ImageGenerationStageStatusSucceeded})
	}

	// Vulnerabilities stage - docker / quay / github / SBOM scan
	{
		sources := make([]string, 0, 4)
		var errs []string
		if jobRan(run, "docker") {
			sources = append(sources, "docker.io")
			if err := failedStepErrors(run, "docker", 2); err != "" {
				errs = append(errs, err)
			}
		}
		if jobRan(run, "quay") {
			sources = append(sources, "quay.io")
			if err := failedStepErrors(run, "quay", 0); err != "" {
				errs = append(errs, err)
			}
		}
		if jobRan(run, "github") {
			sources = append(sources, "github.com")
			if err := failedStepErrors(run, "github", 5); err != "" {
				errs = append(errs, err)
			}
		}
		if jobRan(run, "sbom") {
			sources = append(sources, "osv.dev")
			if err := failedStepErrors(run, "sbom", 0); err != "" {
				errs = append(errs, err)
			}
		}

		if len(sources) == 0 {
			outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageVulnerabilities, status: models.ImageGenerationStageStatusSucceeded})
		} else {
			status := models.ImageGenerationStageStatusSucceeded
			if len(errs) > 0 {
				status = models.ImageGenerationStageStatusFailed
			}
			outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageVulnerabilities, status: status, source: strings.Join(sources, ","), err: strings.Join(errs, "; ")})
		}
	}

	// Scorecard stage - OpenSSF job
	if jobRan(run, "openssf") {
		errs := failedStepErrors(run, "openssf", 0, 1)
		status := models.ImageGenerationStageStatusSucceeded
		if errs != "" {
			status = models.ImageGenerationStageStatusFailed
		}
		outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageScorecard, status: status, source: "openssf", err: errs})
	} else {
		outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageScorecard, status: models.ImageGenerationStageStatusSucceeded})
	}

	return outcomes
}

// mergeStages combines prior receipts with freshly observed outcomes.
// Successful prior receipts (verifiable for the pinned digest) are reused:
// a transient failure on a later run never discards confirmed data.
func mergeStages(prior map[string]models.ImageGenerationStage, outcomes []evaluatedStage, now time.Time) []models.ImageGenerationStage {
	merged := make(map[string]models.ImageGenerationStage)
	for name, receipt := range prior {
		merged[name] = receipt
	}

	for _, outcome := range outcomes {
		if receipt, exists := merged[outcome.name]; exists && receipt.Status == models.ImageGenerationStageStatusSucceeded && outcome.status == models.ImageGenerationStageStatusFailed {
			// Keep the verifiable payload (confirmed for this digest) but mark
			// the stage failed so the generation is reported as partial and the
			// missing stage is retried on the next run.
			receipt.Status = models.ImageGenerationStageStatusFailed
			receipt.Source = outcome.source
			receipt.Error = outcome.err
			receipt.UpdatedAt = now
			merged[outcome.name] = receipt
			continue
		}
		if outcome.status == models.ImageGenerationStageStatusSucceeded {
			if receipt, exists := merged[outcome.name]; exists && receipt.Status == models.ImageGenerationStageStatusSucceeded && len(receipt.Blob) > 0 {
				// A confirmed absence (no blob) must not replace a confirmed
				// value, even across different sources
				continue
			}
		}

		merged[outcome.name] = models.ImageGenerationStage{
			Name:      outcome.name,
			Status:    outcome.status,
			Source:    outcome.source,
			Error:     outcome.err,
			UpdatedAt: now,
		}
	}

	order := []string{
		imageworkflow.StageManifest,
		imageworkflow.StageVersions,
		imageworkflow.StageDescription,
		imageworkflow.StageReleaseNotes,
		imageworkflow.StageVulnerabilities,
		imageworkflow.StageSBOM,
		imageworkflow.StageProvenance,
		imageworkflow.StageScorecard,
		imageworkflow.StageWorkflow,
	}

	stages := make([]models.ImageGenerationStage, 0, len(merged))
	for _, name := range order {
		if stage, ok := merged[name]; ok {
			stages = append(stages, stage)
		}
	}
	return stages
}

// attachReceiptBlobs serializes the canonical payload of each successful stage
// into its receipt.
func attachReceiptBlobs(stages []models.ImageGenerationStage, data *imageworkflow.Data, run models.WorkflowRun) []models.ImageGenerationStage {
	workflowBlob, err := json.Marshal(run)
	if err != nil {
		workflowBlob = nil
	}

	for i := range stages {
		if stages[i].Status != models.ImageGenerationStageStatusSucceeded {
			continue
		}

		var blob []byte
		switch stages[i].Name {
		case imageworkflow.StageManifest:
			blob, _ = json.Marshal(data.ManifestReceipt())
		case imageworkflow.StageDescription:
			blob = marshalStageValue(data.FullDescription.Value)
		case imageworkflow.StageReleaseNotes:
			blob = marshalStageValue(data.ReleaseNotes.Value)
		case imageworkflow.StageScorecard:
			blob = marshalStageValue(data.Scorecard.Value)
		case imageworkflow.StageProvenance:
			blob = marshalStageValue(data.Provenance.Value)
		case imageworkflow.StageSBOM:
			blob = marshalStageValue(data.SBOM.Value)
		case imageworkflow.StageVulnerabilities:
			vulnerabilities := data.Vulnerabilities
			if vulnerabilities == nil {
				vulnerabilities = make([]models.ImageVulnerability, 0)
			}
			blob, _ = json.Marshal(vulnerabilities)
		case imageworkflow.StageWorkflow:
			blob = workflowBlob
		}
		stages[i].Blob = blob
	}
	return stages
}

func marshalStageValue[T any](value *T) []byte {
	if value == nil {
		return nil
	}
	blob, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return blob
}

// stageSucceeded reports whether a stage has a successful receipt.
func stageSucceeded(stages []models.ImageGenerationStage, name string) bool {
	for _, stage := range stages {
		if stage.Name == name {
			return stage.Status == models.ImageGenerationStageStatusSucceeded
		}
	}
	return false
}

// stageAvailable reports whether a stage has data that may be published. A
// stage is available when it succeeded, or when a failed rerun retained a
// previously confirmed payload - allowing partial generations to keep
// confirmed data visible.
func stageAvailable(stages []models.ImageGenerationStage, name string) bool {
	for _, stage := range stages {
		if stage.Name == name {
			return stage.Status == models.ImageGenerationStageStatusSucceeded || len(stage.Blob) > 0
		}
	}
	return false
}
