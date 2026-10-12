package imageworkflow

import (
	"errors"
	"runtime"

	"github.com/AlexGustafsson/cupdate/internal/oci"
	"github.com/AlexGustafsson/cupdate/internal/workflow"
)

func GetAttestationManifests() workflow.Step {
	return workflow.Step{
		Name: "Get attestation manifests",

		Main: func(ctx workflow.Context) (workflow.Command, error) {
			registryClient, err := workflow.GetInput[*oci.Client](ctx, "registryClient", true)
			if err != nil {
				return nil, err
			}

			image, err := workflow.GetInput[oci.Reference](ctx, "reference", true)
			if errors.Is(err, workflow.ErrInvalidType) {
				imageRef, err := workflow.GetInput[*oci.Reference](ctx, "reference", true)
				if err != nil {
					return nil, err
				} else if imageRef != nil {
					image = *imageRef
				}
			} else if err != nil {
				return nil, err
			}

			architecture, err := workflow.GetInput[string](ctx, "architecture", false)
			if err != nil || architecture == "" {
				architecture = runtime.GOARCH
			}

			os, err := workflow.GetInput[string](ctx, "os", false)
			if err != nil {
				os = runtime.GOOS
			}

			// Collect attestations for the pinned platform. Per-manifest errors
			// (interrupted pagination, failed referrer lookups) are reported without
			// discarding attestations collected for other manifests.
			attestationManifests, err := registryClient.GetAttestationManifests(ctx, image, &oci.GetAttestationsOptions{
				Architecture: architecture,
				OS:           os,
			})

			errs := make([]string, 0)
			if err != nil {
				errs = append(errs, err.Error())
			}

			return workflow.Batch(
				workflow.SetOutput("manifests", attestationManifests),
				workflow.SetOutput("errors", errs),
			), nil
		},
	}
}
