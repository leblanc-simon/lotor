-- Point compatible Dependency-Track (T19, ADR 0058).
--
-- Une version de projet au sens de Dependency-Track devient une référence suivie de nature
-- « version » d'un dépôt : sans commit, rangée comme un hôte (un inventaire identique au
-- courant n'avance que la date de dernière analyse).
ALTER TABLE tracked_refs DROP CONSTRAINT tracked_refs_kind_check;
ALTER TABLE tracked_refs ADD CONSTRAINT tracked_refs_kind_check
    CHECK (kind IN ('branch', 'tag', 'version', 'host', 'container'));
ALTER TABLE tracked_refs ADD CONSTRAINT tracked_refs_version_of_repo
    CHECK (kind <> 'version' OR project_kind = 'repo');

-- Création automatique de projets et de versions par un agent dépôt, au point compatible
-- Dependency-Track (autoCreate). Elle n'a d'effet que pour un agent rattaché à une équipe :
-- le projet créé appartient à l'équipe de l'agent. Pas de contrainte sur team_id : la
-- suppression d'une équipe rend ses agents à l'organisation (ON DELETE SET NULL), ce qui
-- suspend la création automatique sans erreur.
ALTER TABLE agents ADD COLUMN dt_auto_create boolean NOT NULL DEFAULT false;
ALTER TABLE agents ADD CONSTRAINT agents_dt_auto_create_repo CHECK (NOT dt_auto_create OR kind = 'repo');

-- Recherche d'un projet confié à un agent par son nom (point compatible).
CREATE INDEX projects_agent_name_idx ON projects (org_id, agent_id, name) WHERE agent_id IS NOT NULL;
