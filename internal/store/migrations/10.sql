-- Source revision: 10
-- Target revision: 11
-- Summary: Atomic platform snapshot generations and processing outbox

-- The latest platform snapshot that was confirmed (committed in full).
-- A single platform is followed per process, so only a single row is kept.
CREATE TABLE IF NOT EXISTS platform_snapshots (
  id INTEGER PRIMARY KEY CHECK (id = 0),
  platform TEXT NOT NULL,
  generation INTEGER NOT NULL,
  confirmedAt DATETIME NOT NULL
);

-- References that were part of a confirmed snapshot but have not yet been
-- enqueued for processing. The outbox makes "database committed, queue not
-- notified" recoverable: rows are removed only once the reference was safely
-- handed to the processing queue. Rows are cascade-removed if the reference
-- stops being present in later snapshots.
CREATE TABLE IF NOT EXISTS pending_references (
  reference TEXT PRIMARY KEY NOT NULL,
  generation INTEGER NOT NULL,
  FOREIGN KEY(reference) REFERENCES raw_images(reference) ON DELETE CASCADE
);

INSERT INTO revision (id, revision) VALUES (0, 11) ON CONFLICT DO UPDATE SET revision=excluded.revision;
