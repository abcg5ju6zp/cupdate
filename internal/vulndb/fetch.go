package vulndb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/AlexGustafsson/cupdate/internal/httputil"
	"github.com/AlexGustafsson/cupdate/internal/oci"
)

const (
	// artifactReference is the OCI artifact the vulnerability database is
	// published as.
	artifactReference = "ghcr.io/alexgustafsson/cupdate/vulndb:latest"
	// artifactType identifies OCI artifacts carrying a cupdate vulnerability
	// database.
	artifactType = "application/vnd.cupdate.vulndb.v1+json"
	// databaseLayerMediaType is the media type of the SQLite database layer.
	databaseLayerMediaType = "application/x-sqlite3"
)

var (
	// ErrDownloadFailed is returned when the vulnerability database artifact
	// could not be fully retrieved (network failure, bad status, interrupted
	// write). Any partially downloaded content is discarded. The previously
	// published generation, if any, stays in use.
	ErrDownloadFailed = errors.New("vulndb: failed to download database")
	// ErrContentCorrupt is returned when downloaded content failed verification
	// (digest or size mismatch, SQLite integrity check or required schema
	// missing). The candidate is discarded and the previously published
	// generation stays in use.
	ErrContentCorrupt = errors.New("vulndb: downloaded database is corrupt or unsupported")
	// ErrPublishFailed is returned when a verified candidate could not be
	// atomically published on disk. The active generation is rolled back to
	// (or kept as) the previous complete version.
	ErrPublishFailed = errors.New("vulndb: failed to publish database generation")
)

// artifact describes the exact remote artifact a refresh pinned at its start.
type artifact struct {
	// reference is the parsed OCI reference (tag) the artifact was resolved
	// from.
	reference oci.Reference
	// manifestDigest is the digest of the manifest as observed while resolving
	// the tag. It pins the tag's state at refresh start, so a moving tag cannot
	// silently swap the content underneath the refresh.
	manifestDigest string
	// layerDigest is the digest of the SQLite database blob.
	layerDigest string
	// layerSize is the database blob's advertised size in bytes, if known.
	layerSize int64
}

// resolveArtifact resolves the remote manifest and pins both the manifest
// digest (the tag's current state) and the database blob digest.
func resolveArtifact(ctx context.Context, httpClient httputil.Requester, reference string) (artifact, error) {
	client := oci.Client{
		Client: httpClient,
	}

	ref, err := oci.ParseReference(reference)
	if err != nil {
		return artifact{}, err
	}

	manifestBlob, err := client.GetManifestBlob(ctx, ref)
	if err != nil {
		return artifact{}, fmt.Errorf("%w: %w", ErrDownloadFailed, err)
	}

	manifestBlobContents, err := io.ReadAll(manifestBlob)
	manifestBlob.Close()
	if err != nil {
		return artifact{}, fmt.Errorf("%w: %w", ErrDownloadFailed, err)
	}

	var baseManifest struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		ArtifactType  string `json:"artifactType"`
	}
	if err := json.Unmarshal(manifestBlobContents, &baseManifest); err != nil {
		return artifact{}, fmt.Errorf("%w: invalid manifest: %w", ErrContentCorrupt, err)
	}

	if baseManifest.SchemaVersion != 2 ||
		baseManifest.MediaType != "application/vnd.oci.image.manifest.v1+json" ||
		baseManifest.ArtifactType != artifactType {
		return artifact{}, fmt.Errorf("%w: unsupported manifest", ErrContentCorrupt)
	}

	var manifest struct {
		Layers []struct {
			MediaType   string            `json:"mediaType"`
			Digest      string            `json:"digest"`
			Size        int64             `json:"size"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBlobContents, &manifest); err != nil {
		return artifact{}, fmt.Errorf("%w: invalid manifest: %w", ErrContentCorrupt, err)
	}

	var layerDigest string
	var layerSize int64
	for _, layer := range manifest.Layers {
		if layer.MediaType == databaseLayerMediaType {
			layerDigest = layer.Digest
			layerSize = layer.Size
			break
		}
	}

	if layerDigest == "" {
		return artifact{}, fmt.Errorf("%w: artifact contains no database blob", ErrContentCorrupt)
	}

	return artifact{
		reference:      ref,
		manifestDigest: manifestBlob.Digest(),
		layerDigest:    layerDigest,
		layerSize:      layerSize,
	}, nil
}

// downloadTo streams the database blob to w, verifying its digest and, when
// advertised, its size. Returns ErrDownloadFailed on transport errors and
// ErrContentCorrupt on digest/size mismatches.
func (a artifact) downloadTo(ctx context.Context, httpClient httputil.Requester, w io.Writer) error {
	client := oci.Client{
		Client: httpClient,
	}

	blob, err := client.GetBlob(ctx, a.reference, a.layerDigest, false)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDownloadFailed, err)
	}
	defer blob.Close()

	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, hasher), blob)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDownloadFailed, err)
	}

	actualDigest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if actualDigest != a.layerDigest {
		return fmt.Errorf("%w: expected digest %s, got %s", ErrContentCorrupt, a.layerDigest, actualDigest)
	}

	if a.layerSize > 0 && n != a.layerSize {
		return fmt.Errorf("%w: expected size %d, got %d", ErrContentCorrupt, a.layerSize, n)
	}

	return nil
}

// Fetch downloads the vulnerability database published as an OCI artifact and
// writes it atomically to destination. The content is downloaded to a
// temporary file in destination's directory, verified against the manifest's
// digest and only then renamed into place, so destination is never observed
// half-written.
func Fetch(ctx context.Context, httpClient httputil.Requester, destination string) error {
	art, err := resolveArtifact(ctx, httpClient, artifactReference)
	if err != nil {
		return err
	}

	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("%w: %w", ErrDownloadFailed, err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(destination)+".download-*")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDownloadFailed, err)
	}
	tmpPath := tmp.Name()
	// On success the temp path no longer exists - removal is a no-op then.
	defer os.Remove(tmpPath)

	if err := art.downloadTo(ctx, httpClient, tmp); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: %w", ErrDownloadFailed, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: %w", ErrDownloadFailed, err)
	}

	if err := os.Rename(tmpPath, destination); err != nil {
		return fmt.Errorf("%w: cannot rename candidate into place: %w", ErrPublishFailed, err)
	}

	if err := syncDir(dir); err != nil {
		return fmt.Errorf("%w: %w", ErrPublishFailed, err)
	}

	return nil
}

// fileURL returns a file: URL for path with the given raw query parameters.
func fileURL(path string, rawQuery string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	u := url.URL{
		Scheme: "file",
		Path:   absolute,
	}
	if rawQuery != "" {
		u.RawQuery = rawQuery
	}
	return u.String()
}
