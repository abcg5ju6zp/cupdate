package imageworkflow

import (
	"encoding/json"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/models"
	"github.com/AlexGustafsson/cupdate/internal/oci"
)

// manifestReceipt is the canonical, verifiable payload of the manifest and
// version stages. It is persisted as a stage receipt so that concurrent queue
// items, cache hits and service restarts can reuse the result without
// recollecting it.
type manifestReceipt struct {
	Digest            string             `json:"digest"`
	Image             string             `json:"image,omitempty"`
	Description       string             `json:"description,omitempty"`
	Annotations       oci.Annotations    `json:"annotations,omitempty"`
	Created           *time.Time         `json:"created,omitempty"`
	LatestReference   *oci.Reference     `json:"latestReference,omitempty"`
	LatestAnnotations oci.Annotations    `json:"latestAnnotations,omitempty"`
	LatestCreated     *time.Time         `json:"latestCreated,omitempty"`
	Links             []models.ImageLink `json:"links"`
	HasAttestation    bool               `json:"hasAttestation,omitempty"`
}

// DecodeManifestReceipt decodes a persisted manifest stage receipt.
func DecodeManifestReceipt(blob []byte) (*manifestReceipt, error) {
	var receipt manifestReceipt
	if err := json.Unmarshal(blob, &receipt); err != nil {
		return nil, err
	}
	return &receipt, nil
}

// ApplyTo hydrates data from the receipt. Only digest-pinned data is restored,
// so reusing a receipt can never mix data from another digest.
func (r *manifestReceipt) ApplyTo(data *Data) {
	data.Image = r.Image
	data.Description = r.Description
	data.Annotations = r.Annotations
	data.Created = r.Created
	data.LatestReference = r.LatestReference
	data.LatestAnnotations = r.LatestAnnotations
	data.LatestCreated = r.LatestCreated
	data.InsertLinks(r.Links)
	data.HasAttestationManifest = r.HasAttestation
	if r.HasAttestation {
		data.InsertTag("attestation")
	}
}

// ManifestReceipt returns the canonical manifest stage payload for the data.
func (d *Data) ManifestReceipt() *manifestReceipt {
	return &manifestReceipt{
		Digest:            d.Digest,
		Image:             d.Image,
		Description:       d.Description,
		Annotations:       d.Annotations,
		Created:           d.Created,
		LatestReference:   d.LatestReference,
		LatestAnnotations: d.LatestAnnotations,
		LatestCreated:     d.LatestCreated,
		Links:             d.Links,
		HasAttestation:    d.HasAttestationManifest,
	}
}
