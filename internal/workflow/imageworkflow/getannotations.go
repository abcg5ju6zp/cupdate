package imageworkflow

import (
	"errors"
	"runtime"

	"github.com/AlexGustafsson/cupdate/internal/oci"
	"github.com/AlexGustafsson/cupdate/internal/workflow"
)

func GetAnnotations() workflow.Step {
	return workflow.Step{
		Name: "Get annotations",

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

			manifest, err := workflow.GetInput[any](ctx, "manifest", true)
			if err != nil {
				return nil, err
			}

			var manifests []oci.ImageManifest
			switch m := manifest.(type) {
			case *oci.ImageIndex:
				manifests = m.Manifests
			case *oci.ImageManifest:
				manifests = []oci.ImageManifest{*m}
			}

			// Default to the host platform. The worker pins the platform for the
			// generation, but the defaults keep direct uses of the step compatible.
			architecture, err := workflow.GetInput[string](ctx, "architecture", false)
			if err != nil || architecture == "" {
				architecture = runtime.GOARCH
			}

			os, err := workflow.GetInput[string](ctx, "os", false)
			if err != nil {
				os = runtime.GOOS
			}

			annotations, err := registryClient.GetAnnotations(ctx, image, &oci.GetAnnotationsOptions{
				Manifests:    manifests,
				Architecture: architecture,
				OS:           os,
			})
			if err != nil {
				return nil, err
			}

			return workflow.SetOutput("annotations", annotations), nil
		},
	}
}
