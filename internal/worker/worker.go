package worker

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/events"
	"github.com/AlexGustafsson/cupdate/internal/httputil"
	"github.com/AlexGustafsson/cupdate/internal/models"
	"github.com/AlexGustafsson/cupdate/internal/oci"
	"github.com/AlexGustafsson/cupdate/internal/osv"
	"github.com/AlexGustafsson/cupdate/internal/platform/docker"
	"github.com/AlexGustafsson/cupdate/internal/platform/kubernetes"
	"github.com/AlexGustafsson/cupdate/internal/semver"
	"github.com/AlexGustafsson/cupdate/internal/store"
	"github.com/AlexGustafsson/cupdate/internal/workflow/imageworkflow"
	"github.com/prometheus/client_golang/prometheus"
)

var _ prometheus.Collector = (*Worker)(nil)

// EventType is the type of an event.
type EventType string

const (
	// EventTypeUpdated is emitted whenever data of an image is updated.
	EventTypeUpdated EventType = "updated"
	// EventTypeProcessed is emitted whenever an image was processed.
	EventTypeProcessed EventType = "processed"
	// EventTypeNewVersionAvailable is emitted whenever the latest available
	// version of an image changes.
	EventTypeNewVersionAvailable EventType = "newVersionAvailable"
)

// Event describes a Worker event.
type Event struct {
	Reference string
	Type      EventType
}

// inflightCall coalesces concurrent processing of the same reference so that
// concurrent queue items reuse the same generation receipts.
type inflightCall struct {
	done chan struct{}
	err  error
}

// Worker processes raw container image entries, running the image workflow and
// storing the result to the state store.
// The worker produces events of the type [Event].
type Worker struct {
	*events.Hub[Event]

	httpClient      httputil.Requester
	store           *store.Store
	registryAuth    *httputil.AuthMux
	registryMirrors map[string]string

	inflightMu sync.Mutex
	inflight   map[string]*inflightCall

	processedCounter   prometheus.Counter
	processingDuration prometheus.Counter
	processingGauge    prometheus.Gauge
}

func New(httpClient httputil.Requester, store *store.Store, registryAuth *httputil.AuthMux, registryMirrors map[string]string) *Worker {
	return &Worker{
		Hub: events.NewHub[Event](),

		httpClient:      httpClient,
		store:           store,
		registryAuth:    registryAuth,
		registryMirrors: registryMirrors,

		inflight: make(map[string]*inflightCall),

		processedCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "cupdate",
			Subsystem: "worker",
			Name:      "processed_images_total",
		}),
		processingDuration: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "cupdate",
			Subsystem: "worker",
			Name:      "processed_images_duration_seconds",
		}),
		processingGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "cupdate",
			Subsystem: "worker",
			Name:      "processing_images",
		}),
	}
}

// ProcessRawImage processes a raw image by the specified reference. Concurrent
// processing of the same reference coalesces onto the same in-flight call.
func (w *Worker) ProcessRawImage(ctx context.Context, reference oci.Reference) error {
	key := reference.String()

	w.inflightMu.Lock()
	if call, ok := w.inflight[key]; ok {
		w.inflightMu.Unlock()
		log := slog.With(slog.String("reference", key))
		log.DebugContext(ctx, "Reusing in-flight processing")
		select {
		case <-call.done:
			return call.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	call := &inflightCall{done: make(chan struct{})}
	w.inflight[key] = call
	w.inflightMu.Unlock()

	call.err = w.processRawImage(ctx, reference)
	close(call.done)

	w.inflightMu.Lock()
	delete(w.inflight, key)
	w.inflightMu.Unlock()

	return call.err
}

func (w *Worker) processRawImage(ctx context.Context, reference oci.Reference) error {
	start := time.Now()
	w.processingGauge.Inc()
	defer w.processingGauge.Dec()

	image, err := w.store.GetRawImage(ctx, reference.String())
	if err != nil {
		return err
	}

	log := slog.With(slog.String("reference", reference.String()))
	log.DebugContext(ctx, "Processing reference")

	// Try to update the image's process time
	// NOTE: Always update immediately as a failure to process or update the image
	// could be a reoccuring issue, so try to process other images before retrying
	// the failing image.
	image.LastProcessed = time.Now()
	if _, err := w.store.InsertRawImage(ctx, image); err != nil {
		return err
	}

	// Map any mirrored references to their underlying image reference
	underlyingReference := reference
	if underlyingDomain, ok := w.registryMirrors[reference.Domain]; ok {
		underlyingReference = reference.WithDomain(underlyingDomain)
	}

	// Pin the generation's manifest digest before collecting anything. A moving
	// tag can no longer mix another digest's data into this processing run.
	digest, err := pinManifestDigest(ctx, w.httpClient, w.registryAuth, underlyingReference)
	if err != nil {
		log.WarnContext(ctx, "Failed to pin manifest digest", slog.Any("error", err))
	}

	platform := targetPlatform()

	// Begin (or resume) the generation for the pinned tuple. This immediately
	// becomes the current generation, so late writes from an older generation
	// cannot overwrite data of a newer one.
	generation, err := w.store.BeginGeneration(ctx, reference.String(), underlyingReference.String(), digest, platform)
	if err != nil {
		return err
	}

	log = log.With(slog.String("digest", digest), slog.String("platform", platform), slog.Int64("generation", generation.ID))

	data := &imageworkflow.Data{
		ImageReference:           reference,
		UnderlyingImageReference: underlyingReference,
		Digest:                   digest,
		PlatformOS:               runtime.GOOS,
		PlatformArch:             runtime.GOARCH,
		Image:                    "",
		Annotations:              nil,
		LatestReference:          nil,
		LatestAnnotations:        nil,
		Tags:                     make([]string, 0),
		Description:              "",
		Links:                    make([]models.ImageLink, 0),
		Vulnerabilities:          make([]models.ImageVulnerability, 0),
		Graph:                    image.Graph,
		RegistryAuth:             w.registryAuth,
	}

	for _, tag := range image.Tags {
		data.InsertTag(tag)
	}

	// Reuse verifiable stage receipts from prior runs
	hydrateData(data, generation)

	// If all stages are covered by receipts, recollect nothing. This covers
	// concurrent queue items, service restarts and cache hits.
	var workflowRun models.WorkflowRun
	reusedReceipts := canSkipWorkflow(generation)
	if reusedReceipts {
		log.DebugContext(ctx, "Reusing collection receipts, skipping workflow")
		if run, ok := hydrateWorkflowRun(generation); ok {
			workflowRun = run
		} else {
			reusedReceipts = false
		}
	}

	if !reusedReceipts {
		log.DebugContext(ctx, "Running workflow")
		flow := imageworkflow.New(w.httpClient, data)
		workflowRun, err = flow.Run(ctx)
		if err != nil {
			if jobFailed(&workflowRun, "oci") {
				log.ErrorContext(ctx, "Failed to run image workflow", slog.Any("error", err))
			} else {
				log.WarnContext(ctx, "Failed to run a subset of image workflow", slog.Any("error", err))
			}
			// Fallthrough - record stage failures and publish what we have
		}
	}

	// Re-derive tags that are normally inserted by workflow jobs, so that
	// reused receipts produce the same tags.
	rederiveTags(data)

	versionDiffSortable := semver.PackInt64(nil)

	// Add some basic tags
	if data.LatestReference != nil {
		if data.ImageReference.String() == data.LatestReference.String() {
			data.InsertTag("up-to-date")
		} else {
			data.InsertTag("outdated")
			// We know that the image is outdated, default to assuming the update is a
			// patch to handle cases like where digests diff but not the tag itself
			versionDiffSortable = semver.PackedSingleDigitPatchDiff
		}

		currentVersion, currentVersionErr := semver.ParseVersion(data.ImageReference.Version())
		newVersion, newVersionErr := semver.ParseVersion(data.LatestReference.Version())
		if currentVersion != nil && currentVersionErr == nil && newVersion != nil && newVersionErr == nil {
			diff := currentVersion.Diff(newVersion)
			if diff != "" {
				data.InsertTag("bump:" + diff)
				versionDiffSortable = semver.PackInt64(newVersion) - semver.PackInt64(currentVersion)
			}
		}
	}

	// Add Kubernetes namespace and Docker stack tags
	for _, node := range image.Graph.Nodes {
		switch node.Domain {
		case "kubernetes":
			if node.Type == kubernetes.ResourceKindCoreV1Namespace {
				data.InsertTag("namespace:" + node.Name)
			}
		case "docker":
			if node.Type == docker.ResourceKindSwarmNamespace {
				data.InsertTag("namespace:" + node.Name)
			} else if node.Type == docker.ResourceKindComposeProject {
				data.InsertTag("project:" + node.Name)
			}
		}
	}

	// Add risk task based on OpenSSF score
	if data.Scorecard.OK && data.Scorecard.Value != nil {
		// Don't add a label for low risk components
		if data.Scorecard.Value.Risk != models.ImageScorecardRiskLow {
			data.InsertTag("risk:" + string(data.Scorecard.Value.Risk))
		}
	}

	// Add vulnerable label if there are specified severities
	var maxSeverity osv.NormalizedSeverity
	for _, vulnerability := range data.Vulnerabilities {
		severity := vulnerability.NormalizedSeverity()
		if severity.Compare(maxSeverity) < 0 {
			maxSeverity = severity
		}
	}

	if maxSeverity != "" {
		switch maxSeverity {
		case osv.NormalizedSeverityCritical:
			data.InsertTag("vulnerability:critical")
		case osv.NormalizedSeverityHigh:
			data.InsertTag("vulnerability:high")
		case osv.NormalizedSeverityMedium:
			data.InsertTag("vulnerability:medium")
		case osv.NormalizedSeverityLow:
			data.InsertTag("vulnerability:low")
		default:
			data.InsertTag("vulnerability:unspecified")
		}
	}

	// Evaluate independent stage outcomes and merge them with prior receipts
	outcomes := evaluateStages(data, &workflowRun, underlyingReference.Domain)
	if !reusedReceipts {
		outcomes = append(outcomes, evaluatedStage{name: imageworkflow.StageWorkflow, status: models.ImageGenerationStageStatusSucceeded})
	}

	now := time.Now()
	stages := mergeStages(stageReceipts(generation), outcomes, now)
	stages = attachReceiptBlobs(stages, data, workflowRun)

	// Determine the generation's overall state
	generation.Stages = stages
	switch {
	case !stageSucceeded(stages, imageworkflow.StageManifest):
		generation.Status = models.ImageGenerationStatusFailed
		data.InsertTag("status:failed")
	case hasFailedStage(stages):
		generation.Status = models.ImageGenerationStatusPartial
		data.InsertTag("status:incomplete")
	default:
		generation.Status = models.ImageGenerationStatusComplete
		data.InsertTag("status:complete")
	}
	generation.Completed = &now

	result := models.Image{
		Reference:           data.ImageReference.String(),
		Created:             data.Created,
		Annotations:         data.Annotations,
		LatestReference:     "",
		LatestCreated:       data.LatestCreated,
		LatestAnnotations:   data.LatestAnnotations,
		VersionDiffSortable: versionDiffSortable,
		Description:         data.Description,
		Tags:                data.Tags,
		Image:               data.Image,
		Links:               data.Links,
		Vulnerabilities:     len(data.Vulnerabilities),
		LastModified:        time.Now(),
	}
	if data.LatestReference != nil {
		result.LatestReference = data.LatestReference.String()
	}

	vulnerabilities := data.Vulnerabilities
	if vulnerabilities == nil {
		vulnerabilities = make([]models.ImageVulnerability, 0)
	}

	// Publish all data of the generation as one atomic unit. Stages confirmed
	// absent delete their visible rows; stages not yet confirmed carry no data.
	timeBeforeInsert := time.Now()
	publication := &store.ImageGenerationPublication{
		Generation:       generation,
		Image:            &result,
		HasDescription:   stageAvailable(stages, imageworkflow.StageDescription),
		Description:      data.FullDescription.Value,
		HasReleaseNotes:  stageAvailable(stages, imageworkflow.StageReleaseNotes),
		ReleaseNotes:     data.ReleaseNotes.Value,
		HasScorecard:     stageAvailable(stages, imageworkflow.StageScorecard),
		Scorecard:        data.Scorecard.Value,
		HasProvenance:    stageAvailable(stages, imageworkflow.StageProvenance),
		Provenance:       data.Provenance.Value,
		HasSBOM:          stageAvailable(stages, imageworkflow.StageSBOM),
		SBOM:             data.SBOM.Value,
		Vulnerabilities: vulnerabilities,
		Graph:           &data.Graph,
		WorkflowRun:     workflowRun,
	}

	if err := w.store.PublishGeneration(ctx, publication); err != nil {
		if errors.Is(err, store.ErrStaleGeneration) {
			log.InfoContext(ctx, "Discarding late write from stale generation")
			return nil
		}
		log.ErrorContext(ctx, "Failed to publish generation", slog.Any("error", err))
		return err
	}
	timeAfterInsert := time.Now()

	log.DebugContext(ctx, "Processed image", slog.String("status", string(generation.Status)))
	w.processedCounter.Inc()
	w.processingDuration.Add(time.Since(start).Seconds())

	// Try to identify what changed
	changes, err := w.store.GetChanges(ctx, &store.GetChangesOptions{
		Reference: reference.String(),
		After:     timeBeforeInsert,
		Before:    timeAfterInsert,
	})
	if err != nil {
		log.ErrorContext(ctx, "Failed to identify changes", slog.Any("error", err))
	} else if len(changes) > 0 {
		log.DebugContext(ctx, "Updated image date", slog.Int("changes", len(changes)))
		w.Broadcast(ctx, Event{
			Reference: reference.String(),
			Type:      EventTypeUpdated,
		})
	}

	if result.LatestReference != "" && result.LatestReference != result.Reference {
		w.Broadcast(ctx, Event{
			Reference: reference.String(),
			Type:      EventTypeNewVersionAvailable,
		})
	}

	w.Broadcast(ctx, Event{
		Reference: reference.String(),
		Type:      EventTypeProcessed,
	})

	return nil
}

// rederiveTags re-adds semantic tags from hydrated data when the workflow was
// not run (or when the data came from receipts).
func rederiveTags(data *imageworkflow.Data) {
	if data.SBOM.OK && data.SBOM.Value != nil && len(data.SBOM.Value.SBOM) > 0 {
		data.InsertTag("sbom")
	}

	for _, link := range data.Links {
		switch link.Type {
		case "github", "github-releases":
			data.InsertTag("github")
		case "gitlab":
			data.InsertTag("gitlab")
		}
	}
}

func hasFailedStage(stages []models.ImageGenerationStage) bool {
	for _, stage := range stages {
		if stage.Status == models.ImageGenerationStageStatusFailed {
			return true
		}
	}
	return false
}

// Collect implements prometheus.Collector.
func (w *Worker) Collect(ch chan<- prometheus.Metric) {
	w.processedCounter.Collect(ch)
	w.processingDuration.Collect(ch)
	w.processingGauge.Collect(ch)
}

// Describe implements prometheus.Collector.
func (w *Worker) Describe(descs chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(w, descs)
}
