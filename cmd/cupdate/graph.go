package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/events"
	"github.com/AlexGustafsson/cupdate/internal/models"
	"github.com/AlexGustafsson/cupdate/internal/oci"
	"github.com/AlexGustafsson/cupdate/internal/platform"
	"github.com/AlexGustafsson/cupdate/internal/platform/docker"
	"github.com/AlexGustafsson/cupdate/internal/platform/kubernetes"
	"github.com/AlexGustafsson/cupdate/internal/store"
	"github.com/AlexGustafsson/cupdate/internal/worker"
)

// retryInterval is how often a candidate that could not be confirmed and an
// event that could not be broadcast are retried.
const retryInterval = 10 * time.Second

// broadcastTimeout bounds a single synchronous broadcast attempt so that a
// slow subscriber cannot stall graph processing indefinitely.
const broadcastTimeout = 10 * time.Second

// pendingCandidate is a complete snapshot candidate that has not yet been
// confirmed. It is retained so that it can be safely retried while the
// previously confirmed snapshot remains the current fact.
type pendingCandidate struct {
	platform   string
	generation uint64
	images     []*models.RawImage
}

func HandleGraphs(ctx context.Context, targetPlatform platform.ContinuousGrapher, platformEvents *events.Hub[models.PlatformEvent], writeStore *store.Store, processQueue *worker.Queue[oci.Reference]) {
	defer slog.Debug("Closed graphing")

	// Recover the generation high-water mark across restarts so that generations
	// keep moving forward and a late, older scan cannot be confirmed after
	// restart
	_, confirmedGeneration, hasConfirmed, err := writeStore.GetConfirmedSnapshot(ctx)
	if err != nil {
		slog.Error("Failed to read confirmed platform snapshot, starting without a generation baseline", slog.Any("error", err))
	}

	// Producer generations reset on restart. Offset them by the generation that
	// was confirmed before this process started.
	generationBaseline := confirmedGeneration
	lastObservedGeneration := confirmedGeneration

	if hasConfirmed {
		// Prime event replay with the generation confirmed before this process
		// started, letting subscribers reconnecting after a restart catch up on
		// the current generation without another graph being produced
		platformEvents.Seed(models.PlatformEvent{Type: models.EventTypeGraphUpdated})
	}

	// Recover references that were committed but never safely enqueued
	recoverPendingReferences(ctx, writeStore, processQueue)

	var candidate *pendingCandidate
	notificationPending := false
	retryTicker := time.NewTicker(retryInterval)
	defer retryTicker.Stop()

	for {
		var retryCh <-chan time.Time
		if candidate != nil || notificationPending {
			retryCh = retryTicker.C
		}

		select {
		case <-ctx.Done():
			return
		case snapshot, ok := <-targetPlatform.Graphs():
			if !ok {
				return
			}

			slog.Debug("Got updated platform graph", slog.Uint64("generation", snapshot.Generation))

			// Arbitrate by generation. Generations are pinned before the
			// platform is read, so a late, older scan - from a slow poll,
			// consecutive informer events interleaved with the initial list or a
			// restart - can never overwrite a newer snapshot
			generation := generationBaseline + snapshot.Generation
			if generation <= lastObservedGeneration {
				slog.Debug("Ignoring stale platform snapshot", slog.Uint64("generation", generation), slog.Uint64("latest", lastObservedGeneration))
				continue
			}
			lastObservedGeneration = generation

			// Build the complete candidate in memory before anything is written.
			// Partial candidates never reach the database.
			candidate = &pendingCandidate{
				platform:   snapshot.Platform,
				generation: generation,
				images:     buildSnapshotImages(snapshot.Graph),
			}
		case <-retryCh:
			// Retry the retained candidate and/or unconfirmed notification
		}

		if candidate != nil {
			resolved, changed := publishCandidate(ctx, candidate, writeStore, processQueue)
			if resolved {
				candidate = nil
				if changed {
					// Replay the same generation's notification until it is
					// confirmed - no new graph is produced to do so
					notificationPending = true
				}
			}
		}

		if candidate == nil && notificationPending {
			notificationPending = !broadcastGraphUpdated(ctx, platformEvents)
		}
	}
}

// publishCandidate attempts to confirm a complete snapshot candidate.
// resolved is true when the candidate is confirmed or dropped as stale.
// changed is true when the confirmed snapshot differs from the previous one.
func publishCandidate(ctx context.Context, candidate *pendingCandidate, writeStore *store.Store, processQueue *worker.Queue[oci.Reference]) (resolved bool, changed bool) {
	log := slog.With(slog.Uint64("generation", candidate.generation))

	result, err := writeStore.PublishSnapshot(ctx, candidate.platform, candidate.generation, candidate.images)
	if errors.Is(err, store.ErrStaleSnapshot) {
		log.Debug("Dropping stale platform snapshot")
		return true, false
	}
	if err != nil {
		// The transaction was rolled back. The previous snapshot stays current
		// and the complete candidate is retained for a safe retry
		log.Error("Failed to publish platform snapshot, retaining last confirmed snapshot and candidate for retry", slog.Any("error", err))
		return false, false
	}

	log.Debug("Published platform snapshot", slog.Int("unprocessed", len(result.Unprocessed)), slog.Int64("removed", result.Removed))

	// Offer unprocessed references to the processing queue. The outbox rows are
	// removed only after the references were safely enqueued. If the queue is
	// closed, the references stay recorded and are re-enqueued on recovery.
	enqueueReferences(ctx, result.Unprocessed, writeStore, processQueue)

	return true, len(result.Unprocessed) > 0 || result.Removed > 0
}

// enqueueReferences offers references to the processing queue and removes them
// from the persistent outbox only once they were safely enqueued.
func enqueueReferences(ctx context.Context, references []string, writeStore *store.Store, processQueue *worker.Queue[oci.Reference]) {
	if len(references) == 0 {
		return
	}

	parsedReferences := make([]oci.Reference, 0, len(references))
	for _, reference := range references {
		parsed, err := oci.ParseReference(reference)
		if err != nil {
			slog.Error("Unexpectedly failed to parse reference from processing outbox", slog.Any("error", err), slog.String("reference", reference))
			continue
		}
		parsedReferences = append(parsedReferences, parsed)
	}

	if len(parsedReferences) == 0 {
		return
	}

	if !processQueue.TryPushBack(parsedReferences...) {
		// The queue is shutting down. The outbox rows remain in the database and
		// are re-enqueued on the next start - only unconfirmed references are
		slog.Warn("Processing queue is closed, pending references will be re-enqueued on recovery", slog.Int("references", len(parsedReferences)))
		return
	}

	for _, reference := range references {
		if err := writeStore.DeletePendingReference(ctx, reference); err != nil {
			// The reference was enqueued but could not be marked as such. It
			// will simply be deduplicated by the queue if recovered later.
			slog.Error("Failed to remove enqueued reference from processing outbox", slog.Any("error", err), slog.String("reference", reference))
		}
	}
}

// recoverPendingReferences re-enqueues references that were confirmed by
// earlier snapshots but never safely offered to the processing queue, e.g.
// because the queue was closed during shutdown.
func recoverPendingReferences(ctx context.Context, writeStore *store.Store, processQueue *worker.Queue[oci.Reference]) {
	references, err := writeStore.ListPendingReferences(ctx)
	if err != nil {
		slog.Error("Failed to list references pending processing", slog.Any("error", err))
		return
	}

	if len(references) > 0 {
		slog.Info("Recovering references pending processing", slog.Int("references", len(references)))
		enqueueReferences(ctx, references, writeStore, processQueue)
	}
}

// broadcastGraphUpdated broadcasts a graph-updated notification for the
// confirmed generation. It returns true when the notification was delivered to
// all current subscribers and remembered for late subscribers.
func broadcastGraphUpdated(ctx context.Context, platformEvents *events.Hub[models.PlatformEvent]) bool {
	broadcastCtx, cancel := context.WithTimeout(ctx, broadcastTimeout)
	defer cancel()

	err := platformEvents.Broadcast(broadcastCtx, models.PlatformEvent{Type: models.EventTypeGraphUpdated})
	if err != nil {
		slog.Warn("Failed to broadcast platform snapshot event, will replay the same generation", slog.Any("error", err))
		return false
	}

	return true
}

// buildSnapshotImages converts a platform graph into a complete set of raw
// images, applying the ignore label policy and resolving each image's
// dependency edges, resource nodes and tags.
func buildSnapshotImages(graph platform.Graph) []*models.RawImage {
	// Delete ignored images / trees
	graph.DeleteFunc(func(n platform.Node) bool {
		return n.Labels().Ignore()
	})

	roots := graph.Roots()

	images := make([]*models.RawImage, 0, len(roots))
	for _, root := range roots {
		imageNode := root.(platform.ImageNode)

		subgraph := graph.Subgraph(root.ID())

		edges := subgraph.Edges()
		nodes := subgraph.Nodes()

		var namespaceNode *platform.Node

		mappedNodes := make(map[string]models.GraphNode)
		for _, node := range nodes {
			switch n := node.(type) {
			case kubernetes.Resource:
				mappedNodes[node.ID()] = models.GraphNode{
					Domain:         "kubernetes",
					Type:           string(n.Kind()),
					Name:           n.Name(),
					Labels:         n.Labels().RemoveUnsupported(),
					InternalLabels: n.InternalLabels(),
				}
				if node.Type() == "kubernetes/"+kubernetes.ResourceKindCoreV1Namespace {
					namespaceNode = &node
				}
			case docker.Resource:
				mappedNodes[node.ID()] = models.GraphNode{
					Domain:         "docker",
					Type:           string(n.Kind()),
					Name:           n.Name(),
					Labels:         n.Labels().RemoveUnsupported(),
					InternalLabels: n.InternalLabels(),
				}
				if node.Type() == "docker/"+docker.ResourceKindSwarmNamespace || node.Type() == "docker/"+docker.ResourceKindComposeProject {
					namespaceNode = &node
				}
			case platform.ImageNode:
				// This node is added later on
			default:
				panic(fmt.Sprintf("mapping unimplemented node type: %s", node.Type()))
			}
		}

		// Resolve labels for the image node. The nearest label takes precedence
		resolvedLabels := make(map[string]string)
		queue := []string{root.ID()}
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]

			for k, v := range mappedNodes[id].Labels {
				_, ok := resolvedLabels[k]
				if !ok {
					resolvedLabels[k] = v
				}
			}

			for adjacent, isChild := range edges[id] {
				if isChild {
					queue = append(queue, adjacent)
				}
			}
		}
		mappedNodes[root.ID()] = models.GraphNode{
			Domain:         "oci",
			Type:           "image",
			Name:           imageNode.Reference.String(),
			Labels:         resolvedLabels,
			InternalLabels: nil,
		}

		tags := []string{}

		// Set tags for resources
		if namespaceNode != nil {
			children := edges[(*namespaceNode).ID()]
			for childID, isParent := range children {
				if isParent {
					continue
				}

				var childNode *platform.Node
				for _, node := range nodes {
					var n = node
					if node.ID() == childID {
						childNode = &n
						break
					}
				}

				if childNode != nil {
					switch resource := (*childNode).(type) {
					case kubernetes.Resource:
						kind := resource.Kind()
						if kind.IsSupported() {
							tags = append(tags, kubernetes.TagName(resource.Kind()))
						}
					case docker.Resource:
						tags = append(tags, docker.TagName(resource.Kind()))
					}
				}
			}
		}

		mappedGraph := models.Graph{
			Edges: edges,
			Nodes: mappedNodes,
		}

		rawImage := &models.RawImage{
			Reference: imageNode.Reference.String(),
			Tags:      slices.Clone(tags),
			Graph:     mappedGraph,
		}

		images = append(images, rawImage)
	}

	return images
}
