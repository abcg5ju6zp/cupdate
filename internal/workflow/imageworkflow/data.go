package imageworkflow

import (
	"slices"
	"sync"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/httputil"
	"github.com/AlexGustafsson/cupdate/internal/models"
	"github.com/AlexGustafsson/cupdate/internal/oci"
)

// Result is a simple type useful to note values that may be empty both when
// successful and unsuccessful. The zero value of a result is an unsuccessful
// result.
type Result[T any] struct {
	OK    bool
	Value T
}

// Collection stage names. Each identifies an independently verifiable
// collection result of a generation.
const (
	StageManifest        = "manifest"
	StageVersions        = "versions"
	StageDescription     = "description"
	StageReleaseNotes    = "releaseNotes"
	StageVulnerabilities = "vulnerabilities"
	StageSBOM            = "sbom"
	StageProvenance      = "provenance"
	StageScorecard       = "scorecard"
	StageWorkflow        = "workflow"
)

type Data struct {
	sync.Mutex
	ImageReference           oci.Reference
	UnderlyingImageReference oci.Reference
	// Digest is the manifest digest the generation is pinned to. All collection
	// steps target this digest, even if the tag moves while processing.
	Digest string
	// PlatformOS and PlatformArch identify the pinned target platform.
	PlatformOS   string
	PlatformArch string
	Created      *time.Time
	Image        string
	Annotations  oci.Annotations
	LatestReference          *oci.Reference
	LatestCreated            *time.Time
	LatestAnnotations        oci.Annotations
	Tags                     []string
	Description              string
	FullDescription          Result[*models.ImageDescription]
	ReleaseNotes             Result[*models.ImageReleaseNotes]
	Links                    []models.ImageLink
	Vulnerabilities          []models.ImageVulnerability
	Graph                    models.Graph
	Scorecard                Result[*models.ImageScorecard]
	Provenance               Result[*models.ImageProvenance]
	SBOM                     Result[*models.ImageSBOM]
	RegistryAuth             *httputil.AuthMux

	// HasAttestationManifest denotes that the pinned index carries an
	// attestation manifest.
	HasAttestationManifest bool

	// stageErrors holds non-fatal per-stage collection errors (for example a
	// truncated attestation blob while other attestations were read). The stage
	// is marked failed but the data collected for other stages is kept.
	stageErrors map[string][]string
}

// PinnedReference returns the underlying reference pinned to the generation's
// manifest digest. If no digest was pinned (resolution failed), the underlying
// reference is returned as-is.
func (d *Data) PinnedReference() oci.Reference {
	ref := d.UnderlyingImageReference
	if d.Digest != "" {
		ref.HasTag = false
		ref.Tag = ""
		ref.HasDigest = true
		ref.Digest = d.Digest
	}
	return ref
}

// AddStageError records a non-fatal collection error for a stage.
func (d *Data) AddStageError(stage string, err string) {
	d.Lock()
	defer d.Unlock()

	if d.stageErrors == nil {
		d.stageErrors = make(map[string][]string)
	}
	d.stageErrors[stage] = append(d.stageErrors[stage], err)
}

// StageErrors returns all recorded non-fatal errors keyed by stage.
func (d *Data) StageErrors() map[string][]string {
	d.Lock()
	defer d.Unlock()

	if d.stageErrors == nil {
		return map[string][]string{}
	}

	result := make(map[string][]string, len(d.stageErrors))
	for stage, errs := range d.stageErrors {
		result[stage] = append([]string{}, errs...)
	}
	return result
}

func (d *Data) InsertTag(tag string) {
	d.Lock()
	defer d.Unlock()

	if !slices.Contains(d.Tags, tag) {
		d.Tags = append(d.Tags, tag)
	}
}

func (d *Data) InsertLinks(links []models.ImageLink) {
	d.Lock()
	defer d.Unlock()

	for _, link := range links {
		exists := false
		for _, other := range d.Links {
			if link.Type == other.Type && link.URL == other.URL {
				exists = true
				break
			}
		}

		if !exists {
			d.Links = append(d.Links, link)
		}
	}
}

func (d *Data) InsertLink(link models.ImageLink) {
	d.InsertLinks([]models.ImageLink{link})
}

func (d *Data) InsertVulnerabilities(vulnerabilities []models.ImageVulnerability) {
	d.Lock()
	defer d.Unlock()

	for _, vulnerability := range vulnerabilities {
		exists := false
		for _, other := range d.Vulnerabilities {
			if vulnerability.ID == other.ID {
				exists = true
				break
			}
		}

		if !exists {
			d.Vulnerabilities = append(d.Vulnerabilities, vulnerability)
		}
	}
}

func (d *Data) InsertVulnerability(vulnerability models.ImageVulnerability) {
	d.InsertVulnerabilities([]models.ImageVulnerability{vulnerability})
}
