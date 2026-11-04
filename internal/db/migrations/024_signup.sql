-- Inscription des comptes locaux (T28, ADR 0056) : codes d'inscription, vérifications
-- d'adresse et lien secret des invitations d'organisation. Les jetons suivent le format
-- commun (internal/token) : identifiant public, empreinte SHA-256 du secret, jamais le
-- secret lui-même.

-- Codes d'inscription du mode « invitation », créés par un administrateur d'instance. Un
-- code ouvre une seule inscription (used_at), avant son échéance, sauf révocation ; il n'est
-- lié à aucune adresse et l'adresse à laquelle il a été envoyé n'est pas conservée.
CREATE TABLE signup_codes (
    id          uuid PRIMARY KEY,
    public_id   text NOT NULL UNIQUE CHECK (public_id ~ '^[a-z2-7]{26}$'),
    secret_hash bytea NOT NULL CHECK (length(secret_hash) = 32),
    label       text NOT NULL CHECK (length(btrim(label)) BETWEEN 1 AND 100),
    created_by  bigint REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    used_by     bigint REFERENCES users (id) ON DELETE SET NULL,
    revoked_at  timestamptz,
    CHECK (expires_at > created_at),
    CHECK (used_at IS NULL OR revoked_at IS NULL)
);
CREATE INDEX signup_codes_list_idx ON signup_codes (created_at DESC, id DESC);

-- Vérifications d'adresse en attente (mode public, et mode invitation quand le serveur
-- envoie des courriels) : le lien reçu prouve la possession de l'adresse ; il est à usage
-- unique, borné à 24 h, et porte le code d'inscription présenté s'il y en a un (consommé
-- seulement à la création du compte).
CREATE TABLE signup_verifications (
    id          uuid PRIMARY KEY,
    public_id   text NOT NULL UNIQUE CHECK (public_id ~ '^[a-z2-7]{26}$'),
    secret_hash bytea NOT NULL CHECK (length(secret_hash) = 32),
    email       text NOT NULL CHECK (length(email) BETWEEN 3 AND 320 AND email = lower(email)),
    code_id     uuid REFERENCES signup_codes (id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX signup_verifications_expiry_idx ON signup_verifications (expires_at);

-- Lien secret d'une invitation d'organisation : il permet de créer son compte à l'adresse
-- invitée. Les invitations antérieures n'en ont pas ; un compte existant les accepte comme
-- avant, depuis « Mon compte › Invitations ».
ALTER TABLE org_invitations
    ADD COLUMN public_id text UNIQUE CHECK (public_id ~ '^[a-z2-7]{26}$'),
    ADD COLUMN secret_hash bytea CHECK (length(secret_hash) = 32),
    ADD CONSTRAINT org_invitations_token_pair CHECK ((public_id IS NULL) = (secret_hash IS NULL));

-- Invitation désignée par l'identifiant public de son lien (crossorg, ADR 0056) : la
-- seule lecture d'une invitation hors de son organisation, pour qui présente le lien avant
-- d'avoir un compte. Elle renvoie l'empreinte du secret, comparée en temps constant par
-- l'appelant ; rien pour une invitation expirée ou une organisation archivée. La création
-- du compte se fait ensuite dans InOrg, sous la RLS, après une nouvelle vérification.
CREATE FUNCTION lotor_invitation_by_token(p_public_id text)
RETURNS TABLE (org_id uuid, invitation_id uuid, email text, role text, secret_hash bytea,
               expires_at timestamptz, slug text, name text, language text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT i.org_id, i.id, i.email, i.role, i.secret_hash, i.expires_at, o.slug, o.name, o.default_language
      FROM org_invitations i
      JOIN organizations o ON o.id = i.org_id
     WHERE i.public_id = p_public_id AND i.expires_at > now() AND o.archived_at IS NULL
$$;
