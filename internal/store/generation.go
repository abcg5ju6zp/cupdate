package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/models"
)

// ErrStaleGeneration is returned when a worker for an old generation attempts
// to publish data after a newer generation (a moved tag's digest) has taken
// over the reference.
var ErrStaleGeneration = errors.New("store: generation is no longer current")

// BeginGeneration pins a collection generation to the specified canonical
// reference, target platform and manifest digest. If a generation already
// exists for the tuple, it - along with its stage receipts - is reused. The
// returned generation immediately becomes the current one for the reference,
// ensuring that late writes from older generations cannot overwrite newer data.
func (s *Store) BeginGeneration(ctx context.Context, reference string, underlyingReference string, digest string, platform string) (*models.ImageGeneration, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	started := time.Now()

	// Insert a new generation or reuse the existing one for the tuple
	if _, err := tx.ExecContext(ctx, `INSERT INTO image_generations
		(reference, underlyingReference, digest, platform, status, startedAt)
		VALUES
		(?, ?, ?, ?, ?, ?)
		ON CONFLICT(reference, digest, platform) DO NOTHING;`,
		reference, underlyingReference, digest, platform, string(models.ImageGenerationStatusPartial), started); err != nil {
		return nil, err
	}

	generation, err := getGeneration(ctx, tx, `SELECT id, reference, underlyingReference, digest, platform, status, startedAt, completedAt
		FROM image_generations
		WHERE reference = ? AND digest = ? AND platform = ?;`,
		reference, digest, platform)
	if err != nil {
		return nil, err
	}

	// Point the reference at the generation. A generation whose digest could not
	// be pinned must not take over from an already established generation - a
	// transient registry failure must not wipe confirmed data. Any (newer,
	// digest-pinned) generation can take over.
	var existingID int64
	switch err := tx.QueryRowContext(ctx, `SELECT generation FROM image_generation_current WHERE reference = ?;`, reference).Scan(&existingID); err {
	case nil:
		if digest != "" || existingID == generation.ID {
			if _, err := tx.ExecContext(ctx, `UPDATE image_generation_current SET generation = MAX(generation, ?) WHERE reference = ?;`,
				generation.ID, reference); err != nil {
				return nil, err
			}
		}
	case sql.ErrNoRows:
		if _, err := tx.ExecContext(ctx, `INSERT INTO image_generation_current (reference, generation) VALUES (?, ?);`,
			reference, generation.ID); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	stages, err := listGenerationStages(ctx, tx, generation.ID)
	if err != nil {
		return nil, err
	}
	generation.Stages = stages

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return generation, nil
}

// GetCurrentGeneration returns the generation currently allowed to publish for
// the reference, along with its stage receipts.
func (s *Store) GetCurrentGeneration(ctx context.Context, reference string) (*models.ImageGeneration, error) {
	generation, err := getGeneration(ctx, s.db, `SELECT image_generations.id, image_generations.reference, image_generations.underlyingReference, image_generations.digest, image_generations.platform, image_generations.status, image_generations.startedAt, image_generations.completedAt
		FROM image_generations
		INNER JOIN image_generation_current ON image_generation_current.generation = image_generations.id
		WHERE image_generations.reference = ?;`,
		reference)
	if err != nil {
		return nil, err
	}

	stages, err := listGenerationStages(ctx, s.db, generation.ID)
	if err != nil {
		return nil, err
	}
	generation.Stages = stages

	return generation, nil
}

type rowQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func getGeneration(ctx context.Context, q rowQueryer, query string, args ...any) (*models.ImageGeneration, error) {
	res, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	if !res.Next() {
		return nil, sql.ErrNoRows
	}

	var generation models.ImageGeneration
	if err := res.Scan(
		&generation.ID,
		&generation.Reference,
		&generation.UnderlyingReference,
		&generation.Digest,
		&generation.Platform,
		&generation.Status,
		&generation.Started,
		&generation.Completed,
	); err != nil {
		return nil, err
	}

	return &generation, nil
}

func listGenerationStages(ctx context.Context, q rowQueryer, generationID int64) ([]models.ImageGenerationStage, error) {
	res, err := q.QueryContext(ctx, `SELECT stage, status, source, error, blob, updatedAt
		FROM image_generation_stages
		WHERE generation = ?
		ORDER BY stage ASC;`, generationID)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	stages := make([]models.ImageGenerationStage, 0)
	for res.Next() {
		var stage models.ImageGenerationStage
		if err := res.Scan(&stage.Name, &stage.Status, &stage.Source, &stage.Error, &stage.Blob, &stage.UpdatedAt); err != nil {
			return nil, err
		}
		stages = append(stages, stage)
	}
	if err := res.Err(); err != nil {
		return nil, err
	}

	return stages, nil
}

// ImageGenerationPublication holds all data of one generation that is
// published atomically. Optional fields use the paired Has* flag: a present
// stage with a nil value deletes any previously visible row, whereas an absent
// stage leaves no data of its kind visible for the generation.
type ImageGenerationPublication struct {
	Generation *models.ImageGeneration

	Image *models.Image

	HasDescription bool
	Description    *models.ImageDescription

	HasReleaseNotes bool
	ReleaseNotes    *models.ImageReleaseNotes

	HasScorecard bool
	Scorecard    *models.ImageScorecard

	HasProvenance bool
	Provenance    *models.ImageProvenance

	HasSBOM bool
	SBOM    *models.ImageSBOM

	Vulnerabilities []models.ImageVulnerability
	Graph           *models.Graph
	WorkflowRun     models.WorkflowRun
}

// PublishGeneration publishes all data of a generation as one atomic unit.
// Either all tables (main image, version relations, description, release
// notes, graph, scorecard, provenance, SBOM, vulnerabilities, workflow run and
// stage receipts) are updated, or none of them are. Late writes from old
// generations are rejected with [ErrStaleGeneration].
func (s *Store) PublishGeneration(ctx context.Context, publication *ImageGenerationPublication) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	generation := publication.Generation
	if generation == nil {
		return fmt.Errorf("store: cannot publish without a generation")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Guard: only the generation currently pointed at may publish visible data.
	statement, err := tx.PrepareContext(ctx, `SELECT generation FROM image_generation_current WHERE reference = ?;`)
	if err != nil {
		return err
	}

	res, err := statement.QueryContext(ctx, generation.Reference)
	if err != nil {
		statement.Close()
		return err
	}

	var currentGeneration int64
	if res.Next() {
		if err := res.Scan(&currentGeneration); err != nil {
			res.Close()
			statement.Close()
			return err
		}
	}
	res.Close()
	statement.Close()

	if currentGeneration != generation.ID {
		return ErrStaleGeneration
	}

	if err := publishGenerationMetadata(ctx, tx, generation); err != nil {
		return err
	}

	if err := publishImage(ctx, tx, publication.Image); err != nil {
		return err
	}

	if publication.HasDescription {
		if err := replaceDescription(ctx, tx, generation.Reference, publication.Description); err != nil {
			return err
		}
	} else if err := deleteFromTable(ctx, tx, "images_descriptions", generation.Reference); err != nil {
		return err
	}

	if publication.HasReleaseNotes {
		if err := replaceReleaseNotes(ctx, tx, generation.Reference, publication.ReleaseNotes); err != nil {
			return err
		}
	} else if err := deleteFromTable(ctx, tx, "images_release_notes", generation.Reference); err != nil {
		return err
	}

	if err := publishGraph(ctx, tx, generation.Reference, publication.Graph); err != nil {
		return err
	}

	if publication.HasScorecard {
		if err := replaceScorecard(ctx, tx, generation.Reference, publication.Scorecard); err != nil {
			return err
		}
	} else if err := deleteFromTable(ctx, tx, "images_scorecards", generation.Reference); err != nil {
		return err
	}

	if publication.HasProvenance {
		if err := replaceProvenance(ctx, tx, generation.Reference, publication.Provenance); err != nil {
			return err
		}
	} else if err := deleteFromTable(ctx, tx, "images_provenance", generation.Reference); err != nil {
		return err
	}

	if publication.HasSBOM {
		if err := replaceSBOM(ctx, tx, generation.Reference, publication.SBOM); err != nil {
			return err
		}
	} else if err := deleteFromTable(ctx, tx, "images_sbom", generation.Reference); err != nil {
		return err
	}

	if err := publishVulnerabilities(ctx, tx, generation.Reference, publication.Vulnerabilities); err != nil {
		return err
	}

	if err := publishWorkflowRun(ctx, tx, generation.Reference, &publication.WorkflowRun); err != nil {
		return err
	}

	return tx.Commit()
}

func publishGenerationMetadata(ctx context.Context, tx *sql.Tx, generation *models.ImageGeneration) error {
	statement, err := tx.PrepareContext(ctx, `UPDATE image_generations
		SET status = ?, completedAt = ?
		WHERE id = ?;`)
	if err != nil {
		return err
	}

	if _, err := statement.ExecContext(ctx, string(generation.Status), generation.Completed, generation.ID); err != nil {
		statement.Close()
		return err
	}
	statement.Close()

	statement, err = tx.PrepareContext(ctx, `INSERT INTO image_generation_stages
		(generation, stage, status, source, error, blob, updatedAt)
		VALUES
		(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(generation, stage) DO UPDATE SET
			status=excluded.status,
			source=excluded.source,
			error=excluded.error,
			blob=excluded.blob,
			updatedAt=excluded.updatedAt;`)
	if err != nil {
		return err
	}

	for _, stage := range generation.Stages {
		var blob any
		if len(stage.Blob) > 0 {
			blob = stage.Blob
		}
		if _, err := statement.ExecContext(ctx, generation.ID, stage.Name, string(stage.Status), stage.Source, stage.Error, blob, stage.UpdatedAt); err != nil {
			statement.Close()
			return err
		}
	}
	statement.Close()

	return nil
}

func publishImage(ctx context.Context, tx *sql.Tx, image *models.Image) error {
	var annotations *string
	if len(image.Annotations) > 0 {
		encoded, err := json.Marshal(image.Annotations)
		if err != nil {
			return err
		}
		encodedString := string(encoded)
		annotations = &encodedString
	}

	var latestAnnotations *string
	if len(image.LatestAnnotations) > 0 {
		encoded, err := json.Marshal(image.LatestAnnotations)
		if err != nil {
			return err
		}
		encodedString := string(encoded)
		latestAnnotations = &encodedString
	}

	var latestReference *string
	if image.LatestReference != "" {
		latestReference = &image.LatestReference
	}

	statement, err := tx.PrepareContext(ctx, `INSERT INTO images
		(reference, created, annotations, latestReference, latestCreated, latestAnnotations, versionDiffSortable, description, lastModified, imageUrl)
		VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(reference) DO UPDATE SET
			created=excluded.created,
			annotations=excluded.annotations,
			latestReference=excluded.latestReference,
			latestCreated=excluded.latestCreated,
			latestAnnotations=excluded.latestAnnotations,
			versionDiffSortable=excluded.versionDiffSortable,
			description=excluded.description,
			lastModified=excluded.lastModified,
			imageUrl=excluded.imageUrl;`)
	if err != nil {
		return err
	}

	if _, err := statement.ExecContext(ctx, image.Reference, image.Created, annotations, latestReference, image.LatestCreated, latestAnnotations, image.VersionDiffSortable, image.Description, image.LastModified, image.Image); err != nil {
		statement.Close()
		return err
	}
	statement.Close()

	if _, err := tx.ExecContext(ctx, `DELETE FROM images_tags WHERE reference = ?;`, image.Reference); err != nil {
		return err
	}

	statement, err = tx.PrepareContext(ctx, `INSERT INTO images_tags
		(reference, tag)
		VALUES
		(?, ?)
		ON CONFLICT(reference, tag) DO NOTHING;`)
	if err != nil {
		return err
	}

	for _, tag := range image.Tags {
		if _, err := statement.ExecContext(ctx, image.Reference, tag); err != nil {
			statement.Close()
			return err
		}
	}
	statement.Close()

	serializedLinks, err := json.Marshal(image.Links)
	if err != nil {
		return err
	}

	statement, err = tx.PrepareContext(ctx, `INSERT INTO images_linksv2
		(reference, links)
		VALUES
		(?, ?)
		ON CONFLICT(reference) DO UPDATE SET
			links=excluded.links;`)
	if err != nil {
		return err
	}

	if _, err := statement.ExecContext(ctx, image.Reference, serializedLinks); err != nil {
		statement.Close()
		return err
	}
	statement.Close()

	return nil
}

// deleteFromTable deletes the row(s) for the reference from a stage table.
// table must be a hard-coded table name, never user input.
func deleteFromTable(ctx context.Context, tx *sql.Tx, table string, reference string) error {
	_, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE reference = ?;`, table), reference)
	return err
}

func replaceDescription(ctx context.Context, tx *sql.Tx, reference string, description *models.ImageDescription) error {
	if description == nil {
		return deleteFromTable(ctx, tx, "images_descriptions", reference)
	}

	statement, err := tx.PrepareContext(ctx, `INSERT INTO images_descriptions
		(reference, html, markdown)
		VALUES
		(?, ?, ?)
		ON CONFLICT(reference) DO UPDATE SET
			html=excluded.html,
			markdown=excluded.markdown;`)
	if err != nil {
		return err
	}

	_, err = statement.ExecContext(ctx, reference, description.HTML, description.Markdown)
	statement.Close()
	return err
}

func replaceReleaseNotes(ctx context.Context, tx *sql.Tx, reference string, releaseNotes *models.ImageReleaseNotes) error {
	if releaseNotes == nil {
		return deleteFromTable(ctx, tx, "images_release_notes", reference)
	}

	statement, err := tx.PrepareContext(ctx, `INSERT INTO images_release_notes
		(reference, title, html, markdown, released)
		VALUES
		(?, ?, ?, ?, ?)
		ON CONFLICT(reference) DO UPDATE SET
			title=excluded.title,
			html=excluded.html,
			markdown=excluded.markdown,
			released=excluded.released;`)
	if err != nil {
		return err
	}

	_, err = statement.ExecContext(ctx, reference, releaseNotes.Title, releaseNotes.HTML, releaseNotes.Markdown, releaseNotes.Released)
	statement.Close()
	return err
}

func replaceScorecard(ctx context.Context, tx *sql.Tx, reference string, scorecard *models.ImageScorecard) error {
	if scorecard == nil {
		return deleteFromTable(ctx, tx, "images_scorecards", reference)
	}

	blob, err := json.Marshal(scorecard)
	if err != nil {
		return err
	}

	statement, err := tx.PrepareContext(ctx, `INSERT INTO images_scorecards
		(reference, score, scorecard)
		VALUES
		(?, ?, ?)
		ON CONFLICT(reference) DO UPDATE SET
			score=excluded.score,
			scorecard=excluded.scorecard;`)
	if err != nil {
		return err
	}

	_, err = statement.ExecContext(ctx, reference, scorecard.Score, blob)
	statement.Close()
	return err
}

func replaceProvenance(ctx context.Context, tx *sql.Tx, reference string, provenance *models.ImageProvenance) error {
	if provenance == nil {
		return deleteFromTable(ctx, tx, "images_provenance", reference)
	}

	blob, err := json.Marshal(provenance)
	if err != nil {
		return err
	}

	statement, err := tx.PrepareContext(ctx, `INSERT INTO images_provenance
		(reference, provenance)
		VALUES
		(?, ?)
		ON CONFLICT(reference) DO UPDATE SET
			provenance=excluded.provenance;`)
	if err != nil {
		return err
	}

	_, err = statement.ExecContext(ctx, reference, blob)
	statement.Close()
	return err
}

func replaceSBOM(ctx context.Context, tx *sql.Tx, reference string, sbom *models.ImageSBOM) error {
	if sbom == nil {
		return deleteFromTable(ctx, tx, "images_sbom", reference)
	}

	blob, err := json.Marshal(sbom)
	if err != nil {
		return err
	}

	statement, err := tx.PrepareContext(ctx, `INSERT INTO images_sbom
		(reference, sbom)
		VALUES
		(?, ?)
		ON CONFLICT(reference) DO UPDATE SET
			sbom=excluded.sbom;`)
	if err != nil {
		return err
	}

	_, err = statement.ExecContext(ctx, reference, blob)
	statement.Close()
	return err
}

func publishGraph(ctx context.Context, tx *sql.Tx, reference string, graph *models.Graph) error {
	blob, err := json.Marshal(graph)
	if err != nil {
		return err
	}

	statement, err := tx.PrepareContext(ctx, `INSERT INTO images_graphs
		(reference, graph)
		VALUES
		(?, ?)
		ON CONFLICT(reference) DO UPDATE SET
			graph=excluded.graph;`)
	if err != nil {
		return err
	}

	_, err = statement.ExecContext(ctx, reference, blob)
	statement.Close()
	return err
}

func publishVulnerabilities(ctx context.Context, tx *sql.Tx, reference string, vulnerabilities []models.ImageVulnerability) error {
	blob, err := json.Marshal(vulnerabilities)
	if err != nil {
		return err
	}

	statement, err := tx.PrepareContext(ctx, `INSERT INTO images_vulnerabilitiesv3
		(reference, count, vulnerabilities)
		VALUES
		(?, ?, ?)
		ON CONFLICT(reference) DO UPDATE SET
			count=excluded.count,
			vulnerabilities=excluded.vulnerabilities;`)
	if err != nil {
		return err
	}

	_, err = statement.ExecContext(ctx, reference, len(vulnerabilities), blob)
	statement.Close()
	return err
}

func publishWorkflowRun(ctx context.Context, tx *sql.Tx, reference string, workflowRun *models.WorkflowRun) error {
	blob, err := json.Marshal(workflowRun)
	if err != nil {
		return err
	}

	statement, err := tx.PrepareContext(ctx, `INSERT INTO images_workflow_runs
		(reference, started, result, blob)
		VALUES
		(?, ?, ?, ?);`)
	if err != nil {
		return err
	}

	_, err = statement.ExecContext(ctx, reference, workflowRun.Started, workflowRun.Result, blob)
	statement.Close()
	return err
}
