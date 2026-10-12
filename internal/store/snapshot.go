package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/models"
)

// ErrStaleSnapshot is returned when a snapshot cannot be published because its
// generation is not newer than the generation of the snapshot that is already
// confirmed. A late, older scan must never overwrite a newer snapshot.
var ErrStaleSnapshot = errors.New("store: stale snapshot generation")

// PublishSnapshotResult describes what changed as a snapshot was confirmed.
type PublishSnapshotResult struct {
	// Unprocessed holds the references present in the snapshot that have not yet
	// been processed and that must be offered to the processing queue.
	Unprocessed []string
	// Removed is the number of raw images that were removed because they were
	// no longer present in the snapshot.
	Removed int64
}

// PublishSnapshot atomically publishes a complete platform snapshot.
//
// The whole candidate - raw images (including their normalized references,
// resource nodes, dependency edges and label policies), unprocessed image
// stubs, the cleanup of images no longer present, the processing outbox and
// the confirmed generation - is committed in a single transaction. Readers
// therefore never observe a half-written graph, and cleanup only happens once
// the full new snapshot is confirmed.
//
// If the transaction fails, it is rolled back and the previously confirmed
// snapshot remains the current fact. The candidate can safely be retried.
//
// Returns [ErrStaleSnapshot] if the candidate's generation is not newer than
// the generation of the already confirmed snapshot.
func (s *Store) PublishSnapshot(ctx context.Context, platformID string, generation uint64, images []*models.RawImage) (*PublishSnapshotResult, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Arbitrate against the confirmed generation so that late, older scans
	// cannot overwrite a newer snapshot, including across restarts
	var currentGeneration sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT generation FROM platform_snapshots WHERE id = 0;`).Scan(&currentGeneration)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil && uint64(currentGeneration.Int64) >= generation {
		return nil, ErrStaleSnapshot
	}

	result := &PublishSnapshotResult{
		Unprocessed: make([]string, 0),
	}
	now := time.Now()

	upsertRawImage, err := tx.PrepareContext(ctx, `INSERT INTO raw_images
		(reference, tags, graph, lastProcessed)
		VALUES
		(?, ?, ?, NULL)
		ON CONFLICT(reference) DO UPDATE SET
			tags=excluded.tags,
			graph=excluded.graph,
			lastProcessed=lastProcessed
		RETURNING lastProcessed;`)
	if err != nil {
		return nil, err
	}

	insertImage, err := tx.PrepareContext(ctx, `INSERT INTO images
		(reference, created, annotations, latestReference, latestCreated, latestAnnotations, versionDiffSortable, description, lastModified, imageUrl)
		VALUES
		(?, NULL, NULL, '', NULL, NULL, 0, '', ?, '')
		ON CONFLICT(reference) DO NOTHING;`)
	if err != nil {
		upsertRawImage.Close()
		return nil, err
	}

	insertImageTag, err := tx.PrepareContext(ctx, `INSERT INTO images_tags
		(reference, tag)
		VALUES
		(?, ?)
		ON CONFLICT(reference, tag) DO NOTHING;`)
	if err != nil {
		upsertRawImage.Close()
		insertImage.Close()
		return nil, err
	}

	insertImageLinks, err := tx.PrepareContext(ctx, `INSERT INTO images_linksv2
		(reference, links)
		VALUES
		(?, 'null')
		ON CONFLICT(reference) DO NOTHING;`)
	if err != nil {
		upsertRawImage.Close()
		insertImage.Close()
		insertImageTag.Close()
		return nil, err
	}

	insertPending, err := tx.PrepareContext(ctx, `INSERT INTO pending_references
		(reference, generation)
		VALUES
		(?, ?)
		ON CONFLICT(reference) DO NOTHING;`)
	if err != nil {
		upsertRawImage.Close()
		insertImage.Close()
		insertImageTag.Close()
		insertImageLinks.Close()
		return nil, err
	}

	for _, image := range images {
		tags, err := json.Marshal(image.Tags)
		if err != nil {
			return nil, err
		}

		graph, err := json.Marshal(image.Graph)
		if err != nil {
			return nil, err
		}

		var lastProcessed *time.Time
		res, err := upsertRawImage.QueryContext(ctx, image.Reference, tags, graph)
		if err != nil {
			return nil, err
		}
		if !res.Next() {
			res.Close()
			return nil, errors.New("store: no row returned when inserting raw image")
		}
		if err := res.Scan(&lastProcessed); err != nil {
			res.Close()
			return nil, err
		}
		if err := res.Err(); err != nil {
			res.Close()
			return nil, err
		}
		res.Close()

		// Insert an unprocessed stub for the image, mirroring the previous
		// behavior, so that newly discovered images are visible immediately
		// once the snapshot is confirmed
		insertRes, err := insertImage.ExecContext(ctx, image.Reference, now)
		if err != nil {
			return nil, err
		}

		insertedStub, err := insertRes.RowsAffected()
		if err != nil {
			return nil, err
		}

		if insertedStub > 0 {
			for _, tag := range image.Tags {
				if _, err := insertImageTag.ExecContext(ctx, image.Reference, tag); err != nil {
					return nil, err
				}
			}
			if _, err := insertImageTag.ExecContext(ctx, image.Reference, "unprocessed"); err != nil {
				return nil, err
			}

			if _, err := insertImageLinks.ExecContext(ctx, image.Reference); err != nil {
				return nil, err
			}
		}

		// References that have never been processed still need to be offered to
		// the processing queue - track them in the outbox until they are
		if lastProcessed == nil {
			result.Unprocessed = append(result.Unprocessed, image.Reference)
			if _, err := insertPending.ExecContext(ctx, image.Reference, generation); err != nil {
				return nil, err
			}
		}
	}

	upsertRawImage.Close()
	insertImage.Close()
	insertImageTag.Close()
	insertImageLinks.Close()
	insertPending.Close()

	// Cleanup images that are no longer present, in the same transaction as the
	// writes. The old snapshot stays current until the new one commits.
	removed, err := deleteNonPresent(ctx, tx, imageReferences(images))
	if err != nil {
		return nil, err
	}
	result.Removed = removed

	// Confirm the snapshot generation as the last step before commit
	_, err = tx.ExecContext(ctx, `INSERT INTO platform_snapshots
		(id, platform, generation, confirmedAt)
		VALUES
		(0, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			platform=excluded.platform,
			generation=excluded.generation,
			confirmedAt=excluded.confirmedAt;`, platformID, generation, now)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return result, nil
}

func imageReferences(images []*models.RawImage) []string {
	references := make([]string, len(images))
	for i, image := range images {
		references[i] = image.Reference
	}
	return references
}

// deleteNonPresent deletes all raw images whose references are not in the
// specified set, as part of an existing transaction.
func deleteNonPresent(ctx context.Context, tx *sql.Tx, references []string) (int64, error) {
	// Drop any table left behind on a pooled connection by an aborted round
	if _, err := tx.ExecContext(ctx, "DROP TABLE IF EXISTS temp.present_references;"); err != nil {
		return 0, err
	}

	// Create a temporary table that is kept throughout the transaction. This in
	// order to be able to handle any number of references, without limitation
	if _, err := tx.ExecContext(ctx, "CREATE TABLE temp.present_references (reference TEXT);"); err != nil {
		return 0, err
	}

	statement, err := tx.PrepareContext(ctx, "INSERT INTO temp.present_references (reference) VALUES (?);")
	if err != nil {
		return 0, err
	}

	for _, reference := range references {
		if _, err := statement.ExecContext(ctx, reference); err != nil {
			statement.Close()
			return 0, err
		}
	}
	if err := statement.Close(); err != nil {
		return 0, err
	}

	res, err := tx.ExecContext(ctx, "DELETE FROM raw_images WHERE reference NOT IN (SELECT reference FROM temp.present_references);")
	if err != nil {
		return 0, err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	if _, err := tx.ExecContext(ctx, "DROP TABLE temp.present_references;"); err != nil {
		return 0, err
	}

	return rowsAffected, nil
}

// GetConfirmedSnapshot returns the platform and generation of the latest fully
// confirmed snapshot. ok is false if no snapshot has ever been confirmed.
func (s *Store) GetConfirmedSnapshot(ctx context.Context) (platformID string, generation uint64, ok bool, err error) {
	var platform sql.NullString
	var currentGeneration sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT platform, generation FROM platform_snapshots WHERE id = 0;`).Scan(&platform, &currentGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	return platform.String, uint64(currentGeneration.Int64), true, nil
}

// ListPendingReferences returns references that were confirmed in snapshots
// but not yet safely offered to the processing queue.
func (s *Store) ListPendingReferences(ctx context.Context) ([]string, error) {
	statement, err := s.db.PrepareContext(ctx, `SELECT reference FROM pending_references ORDER BY generation ASC, reference ASC;`)
	if err != nil {
		return nil, err
	}

	res, err := statement.QueryContext(ctx)
	statement.Close()
	if err != nil {
		return nil, err
	}

	references := make([]string, 0)
	for res.Next() {
		var reference string
		if err := res.Scan(&reference); err != nil {
			res.Close()
			return nil, err
		}
		references = append(references, reference)
	}
	res.Close()
	if err := res.Err(); err != nil {
		return nil, err
	}

	return references, nil
}

// DeletePendingReference removes a reference from the processing outbox once it
// has been safely offered to the processing queue.
func (s *Store) DeletePendingReference(ctx context.Context, reference string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	statement, err := s.db.PrepareContext(ctx, `DELETE FROM pending_references WHERE reference = ?;`)
	if err != nil {
		return err
	}

	_, err = statement.ExecContext(ctx, reference)
	statement.Close()
	return err
}
