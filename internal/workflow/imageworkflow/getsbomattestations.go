package imageworkflow

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/AlexGustafsson/cupdate/internal/oci"
	"github.com/AlexGustafsson/cupdate/internal/workflow"
)

func GetSBOMAttestations() workflow.Step {
	return workflow.Step{
		Name: "Get SBOM attestations",

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

			manifests, err := workflow.GetInput[map[string]*oci.ImageManifest](ctx, "manifests", true)
			if err != nil {
				return nil, err
			}

			// Read attestations one digest at a time. A failed or short blob read
			// only fails the digest's read; other attestations are kept. The stage
			// is retried for the missing digests on the next processing run.
			attestations := make(map[string]oci.SBOMAttestation)
			errs := make([]string, 0)
			for manifestDigest, attestationManifest := range manifests {
				_, sbomBlobDigest, ok := attestationManifest.SBOMLayerDigest()
				if !ok {
					continue
				}

				blob, err := registryClient.GetBlob(ctx, image, sbomBlobDigest, true)
				if err != nil {
					errs = append(errs, fmt.Sprintf("%s: %v", manifestDigest, err))
					continue
				}

				var attestation oci.SBOMAttestation
				if decodeErr := json.NewDecoder(blob).Decode(&attestation); decodeErr != nil {
					blob.Close()
					errs = append(errs, fmt.Sprintf("%s: %v", manifestDigest, decodeErr))
					continue
				}
				blob.Close()

				// NOTE: Docker Hardened Images reports CyclonedX, but its predicate is
				// just null, ignore them
				if attestation.SBOM == "null" {
					continue
				}

				attestations[manifestDigest] = attestation
			}

			return workflow.Batch(
				workflow.SetOutput("attestations", attestations),
				workflow.SetOutput("errors", errs),
			), nil
		},
	}
}
