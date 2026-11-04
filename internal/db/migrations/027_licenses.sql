-- Licences (T20, ADR 0060) : politique de licences d'une organisation, constats de licence
-- par référence, expressions de licence rencontrées (recherche « license: »), et sujet
-- « licence » des règles de politique (T15).

-- Politique de licences : une ligne par organisation ; sans ligne, la politique par défaut
-- (toute licence SPDX connue autorisée, décision de l'utilisateur).
CREATE TABLE license_policies (
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    default_status  text NOT NULL CHECK (default_status IN ('allowed', 'review', 'denied')),
    allowed         text[] NOT NULL DEFAULT '{}' CHECK (cardinality(allowed) <= 500),
    review          text[] NOT NULL DEFAULT '{}' CHECK (cardinality(review) <= 500),
    denied          text[] NOT NULL DEFAULT '{}' CHECK (cardinality(denied) <= 500),
    require_license boolean NOT NULL DEFAULT false,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      bigint REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (org_id)
);
CALL lotor_enforce_org_rls('license_policies');

-- Constats de licence : un composant de l'inventaire courant d'une référence dont les
-- licences sont refusées ou à revoir. Même cycle de vie que les constats de vulnérabilité :
-- ouvert tant que le verdict tient, résolu sinon (composant retiré, licence ou politique
-- changée), rouvert s'il revient.
CREATE TABLE license_findings (
    org_id        uuid NOT NULL,
    id            uuid NOT NULL,
    project_id    uuid NOT NULL,
    ref_id        uuid NOT NULL,
    component_id  uuid NOT NULL,
    status        text NOT NULL CHECK (status IN ('open', 'resolved')),
    verdict       text NOT NULL CHECK (verdict IN ('review', 'denied')),
    -- Licences déclarées (expressions telles que reçues) et licences qui décident.
    licenses      text[] NOT NULL DEFAULT '{}',
    license_ids   text[] NOT NULL DEFAULT '{}',
    missing       boolean NOT NULL DEFAULT false,
    snapshot_id   uuid,
    first_seen_at timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    resolved_at   timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, ref_id, component_id),
    FOREIGN KEY (org_id, ref_id, project_id) REFERENCES tracked_refs (org_id, id, project_id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, component_id) REFERENCES components (org_id, id),
    FOREIGN KEY (org_id, snapshot_id) REFERENCES snapshots (org_id, id) ON DELETE SET NULL (snapshot_id),
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL)),
    CHECK (last_seen_at >= first_seen_at)
);
CALL lotor_enforce_org_rls('license_findings');
CREATE INDEX license_findings_project_idx ON license_findings (org_id, project_id, status);
CREATE INDEX license_findings_component_idx ON license_findings (org_id, component_id);
-- La rétention supprime des instantanés : la clé étrangère se vérifie par cet index.
CREATE INDEX license_findings_snapshot_idx ON license_findings (org_id, snapshot_id) WHERE snapshot_id IS NOT NULL;

-- Expressions de licence rencontrées par organisation : la recherche « license: » en lit
-- la liste (courte), retient en Go celles qui citent la licence, puis cherche les éléments
-- d'inventaire qui les portent.
CREATE TABLE license_expressions (
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    expression text NOT NULL,
    PRIMARY KEY (org_id, expression)
);
CALL lotor_enforce_org_rls('license_expressions');
INSERT INTO license_expressions (org_id, expression)
SELECT DISTINCT i.org_id, l FROM component_set_items i CROSS JOIN LATERAL unnest(i.licenses) l
ON CONFLICT DO NOTHING;

-- Sujet « licence » des règles et des violations.
DO $$
DECLARE c record;
BEGIN
    FOR c IN SELECT conrelid::regclass AS t, conname FROM pg_constraint
              WHERE conrelid IN ('policies'::regclass, 'policy_violations'::regclass) AND contype = 'c'
                AND pg_get_constraintdef(oid) LIKE '%subject%'
    LOOP
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', c.t, c.conname);
    END LOOP;
END $$;
ALTER TABLE policies ADD CONSTRAINT policies_subject_check CHECK (subject IN ('finding', 'agent', 'license'));
ALTER TABLE policy_violations ADD COLUMN license_finding_id uuid,
    ADD CONSTRAINT policy_violations_license_fk FOREIGN KEY (org_id, license_finding_id)
        REFERENCES license_findings (org_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT policy_violations_subject_check CHECK (subject IN ('finding', 'agent', 'license')),
    ADD CONSTRAINT policy_violations_finding_subject CHECK (
        (subject = 'finding') = (finding_id IS NOT NULL) AND
        (subject = 'agent') = (agent_id IS NOT NULL) AND
        (subject = 'license') = (license_finding_id IS NOT NULL)),
    ADD CONSTRAINT policy_violations_project_subject CHECK (
        (subject = 'agent') = (project_id IS NULL AND ref_id IS NULL));
CREATE UNIQUE INDEX policy_violations_open_license ON policy_violations (org_id, policy_id, license_finding_id)
    WHERE resolved_at IS NULL AND license_finding_id IS NOT NULL;
