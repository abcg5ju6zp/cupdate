-- Source revision: 10
-- Target revision: 11
-- Summary: Add collection generations and stage receipts

-- A generation is pinned to a canonical reference, target platform and
-- manifest digest. All intelligence of one generation describes the same
-- digest.
CREATE TABLE IF NOT EXISTS image_generations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reference TEXT NOT NULL,
  underlyingReference TEXT NOT NULL,
  digest TEXT NOT NULL,
  platform TEXT NOT NULL,
  status TEXT NOT NULL,
  startedAt DATETIME NOT NULL,
  completedAt DATETIME,
  UNIQUE(reference, digest, platform)
);

-- Verifiable per-stage receipts. Blob holds the canonical payload of the stage
-- so that it can be reused on retries, restarts, concurrent queue items and
-- cache hits without recollecting the data.
CREATE TABLE IF NOT EXISTS image_generation_stages (
  generation INTEGER NOT NULL,
  stage TEXT NOT NULL,
  status TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  blob BLOB,
  updatedAt DATETIME NOT NULL,
  PRIMARY KEY (generation, stage),
  FOREIGN KEY(generation) REFERENCES image_generations(id) ON DELETE CASCADE
);

-- Points to the generation that is currently allowed to publish visible data
-- for a reference. A generation for a moved tag points at a new digest, and
-- late writes from an old generation are rejected.
CREATE TABLE IF NOT EXISTS image_generation_current (
  reference TEXT PRIMARY KEY NOT NULL,
  generation INTEGER NOT NULL
);

INSERT INTO revision (id, revision) VALUES (0, 11) ON CONFLICT DO UPDATE SET revision=excluded.revision;
