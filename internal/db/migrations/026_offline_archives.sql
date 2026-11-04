-- Mode hors ligne (T23, ADR 0059) : une ingestion reçue par l'import d'une archive garde
-- l'empreinte de son manifeste signé. Une archive importée deux fois retrouve la même
-- ingestion (un seul instantané), même si son SBOM ou sa référence ont été rangés entre
-- les deux. Les ingestions purgées par la rétention libèrent leur empreinte.
ALTER TABLE ingestions ADD COLUMN archive_sha256 bytea CHECK (archive_sha256 IS NULL OR length(archive_sha256) = 32);
CREATE UNIQUE INDEX ingestions_archive_idx ON ingestions (org_id, archive_sha256) WHERE archive_sha256 IS NOT NULL;
