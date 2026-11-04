package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// Clés des refus d'un jeton (problèmes de l'API, traduits par <clé>.title et <clé>.text).
// Tant que le secret n'est pas vérifié, le refus est toujours KeyTokenInvalid : il ne
// révèle rien de l'existence d'un jeton.
const (
	KeyTokenInvalid        = "error.token.invalid"
	KeyTokenRevokedErr     = "error.token.revoked"
	KeyTokenExpired        = "error.token.expired"
	KeyAgentDisabledErr    = "error.agent.disabled"
	KeyEnrollmentExhausted = "error.enrollment.exhausted"
	KeyHostTaken           = "error.enrollment.host_taken"
	KeyProjectUnavailable  = "error.enrollment.project_unavailable"
)

// ErrorKeys liste les clés d'erreur du paquet (tests de traduction).
func ErrorKeys() []string {
	return []string{KeyTokenInvalid, KeyTokenRevokedErr, KeyTokenExpired, KeyAgentDisabledErr,
		KeyEnrollmentExhausted, KeyHostTaken, KeyProjectUnavailable, KeyNoHostProject, KeyContainersLimit}
}

// AuthError est le refus d'un jeton présenté à l'API des agents.
type AuthError struct{ Key string }

func (e *AuthError) Error() string { return "agent: jeton refusé : " + e.Key }

// ConflictError est une requête d'agent refusée par l'état de l'organisation (hôte déjà
// suivi par un agent actif, projet archivé).
type ConflictError struct{ Key string }

func (e *ConflictError) Error() string { return "agent: requête refusée : " + e.Key }

func isAuthError(err error) bool {
	var a *AuthError
	var c *ConflictError
	return errors.As(err, &a) || errors.As(err, &c)
}

var errInvalid = &AuthError{Key: KeyTokenInvalid}

// Principal est l'auteur authentifié d'une requête de l'API des agents : un agent (jeton
// d'agent) ou un jeton d'inscription.
type Principal struct {
	Kind     TokenKind
	Org      tenant.OrgID
	TokenID  uuid.UUID
	PublicID string
	// Pour un jeton d'agent :
	AgentID   uuid.UUID
	AgentKind Kind
	AgentName string

	hash SecretHash // empreinte présentée, revérifiée par Enroll sous verrou
}

// RateKey est la clé de limitation de débit du principal : un compteur par jeton.
func (p Principal) RateKey() string { return string(p.Kind) + ":" + p.PublicID }

// touchEvery espace les mises à jour de la date de dernier usage : une requête sur
// plusieurs écrit, pas toutes.
const touchEvery = time.Minute

// Authenticate vérifie un jeton d'agent ou d'inscription présenté à l'API. Un jeton mal
// formé est refusé sans requête ; sinon l'organisation est résolue par crossorg, puis le
// secret est comparé en temps constant et l'état du jeton vérifié dans InOrg.
func (s *Service) Authenticate(ctx context.Context, raw string) (Principal, error) {
	kind, ok := KindOf(raw)
	if !ok {
		return Principal{}, errInvalid
	}
	publicID, hash, err := ParseToken(kind, raw)
	if err != nil {
		return Principal{}, errInvalid
	}
	resolve := crossorg.AgentTokenOrg
	if kind == KindEnrollment {
		resolve = crossorg.EnrollmentTokenOrg
	}
	org, err := resolve(ctx, s.pool.DB(), publicID)
	if errors.Is(err, crossorg.ErrUnknownToken) {
		return Principal{}, errInvalid
	}
	if err != nil {
		return Principal{}, wrap("authentification", err)
	}
	p := Principal{Kind: kind, Org: org, PublicID: publicID}
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if kind == KindEnrollment {
			return s.checkEnrollment(ctx, tx, &p, hash)
		}
		return s.checkAgent(ctx, tx, &p, hash)
	})
	if err != nil {
		return Principal{}, wrap("authentification", err)
	}
	return p, nil
}

func (s *Service) checkAgent(ctx context.Context, tx *db.OrgTx, p *Principal, hash SecretHash) error {
	var stored []byte
	var expires, used, revoked, disabled, seen sql.NullTime
	var kind string
	err := tx.QueryRowContext(ctx, `
		SELECT t.id, t.secret_hash, t.expires_at, t.last_used_at, t.revoked_at,
		       a.id, a.kind, a.name, a.disabled_at, a.last_seen_at
		  FROM agent_tokens t JOIN agents a ON a.org_id = t.org_id AND a.id = t.agent_id
		 WHERE t.public_id = $1`, p.PublicID).
		Scan(&p.TokenID, &stored, &expires, &used, &revoked, &p.AgentID, &kind, &p.AgentName, &disabled, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return errInvalid
	}
	if err != nil {
		return err
	}
	if !hash.Matches(stored) {
		return errInvalid
	}
	now := s.Now()
	switch {
	case revoked.Valid:
		return &AuthError{Key: KeyTokenRevokedErr}
	case disabled.Valid:
		return &AuthError{Key: KeyAgentDisabledErr}
	case expires.Valid && !now.Before(expires.Time):
		return &AuthError{Key: KeyTokenExpired}
	}
	p.AgentKind = Kind(kind)
	if !used.Valid || now.Sub(used.Time) >= touchEvery {
		if _, err := tx.ExecContext(ctx, `UPDATE agent_tokens SET last_used_at = $2 WHERE id = $1`, p.TokenID, now); err != nil {
			return err
		}
	}
	if !seen.Valid || now.Sub(seen.Time) >= touchEvery {
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET last_seen_at = $2 WHERE id = $1`, p.AgentID, now); err != nil {
			return err
		}
	}
	return nil
}

// enrollmentRow est l'état d'un jeton d'inscription, lu (et verrouillé) pour l'inscription.
type enrollmentRow struct {
	name      string
	stored    []byte
	expires   time.Time
	maxUses   int
	uses      int
	labels    project.Labels
	projectID uuid.NullUUID
	teamID    uuid.UUID
	revoked   bool
}

func readEnrollment(ctx context.Context, tx *db.OrgTx, publicID string, lock bool) (uuid.UUID, enrollmentRow, error) {
	query := `SELECT id, name, secret_hash, expires_at, max_uses, uses, labels, project_id, team_id, revoked_at IS NOT NULL
		FROM enrollment_tokens WHERE public_id = $1`
	if lock {
		query += ` FOR UPDATE`
	}
	var id uuid.UUID
	var r enrollmentRow
	var labels []byte
	err := tx.QueryRowContext(ctx, query, publicID).
		Scan(&id, &r.name, &r.stored, &r.expires, &r.maxUses, &r.uses, &labels, &r.projectID, &r.teamID, &r.revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.UUID{}, enrollmentRow{}, errInvalid
	}
	if err != nil {
		return uuid.UUID{}, enrollmentRow{}, err
	}
	return id, r, json.Unmarshal(labels, &r.labels)
}

func (r enrollmentRow) check(hash SecretHash, now time.Time) error {
	switch {
	case !hash.Matches(r.stored):
		return errInvalid
	case r.revoked:
		return &AuthError{Key: KeyTokenRevokedErr}
	case !now.Before(r.expires):
		return &AuthError{Key: KeyTokenExpired}
	case r.uses >= r.maxUses:
		return &AuthError{Key: KeyEnrollmentExhausted}
	}
	return nil
}

// checkEnrollment vérifie un jeton d'inscription ; Enroll le revérifie sous verrou.
func (s *Service) checkEnrollment(ctx context.Context, tx *db.OrgTx, p *Principal, hash SecretHash) error {
	id, r, err := readEnrollment(ctx, tx, p.PublicID, false)
	if err != nil {
		return err
	}
	p.TokenID = id
	p.hash = hash
	return r.check(hash, s.Now())
}

// EnrollRequest est la demande d'inscription d'un agent serveur.
type EnrollRequest struct {
	Hostname string
	Version  string
	// Labels sont les étiquettes de la configuration de l'agent, ajoutées à celles du
	// jeton sur un projet créé par l'inscription.
	Labels map[string]string
}

// Enrollment est le résultat d'une inscription : l'agent, le projet de son hôte, et son
// jeton d'agent, dont le secret n'est renvoyé qu'ici.
type Enrollment struct {
	Agent   Agent
	Project project.Project
	Created bool // projet créé par l'inscription
	Token   IssuedToken
}

// ValidVersion vérifie une version d'agent annoncée (64 caractères imprimables au plus).
func ValidVersion(v string) error {
	if len(v) > 64 || strings.ContainsFunc(v, func(r rune) bool { return !unicode.IsPrint(r) || unicode.IsSpace(r) }) {
		return invalid("version", KeyVersionInvalid)
	}
	return nil
}

// Enroll inscrit un agent serveur avec le jeton d'inscription de p (voir Authenticate).
// Dans une seule transaction : jeton revérifié et consommé sous verrou, agent créé,
// projet de l'hôte créé (étiquettes du jeton) ou rattaché (projet désigné par le jeton, ou
// projet existant de même référence d'hôte, de l'équipe du jeton, s'il n'a pas d'agent
// actif), jeton d'agent tiré, journal.
func (s *Service) Enroll(ctx context.Context, p Principal, req EnrollRequest, ip, requestID string) (Enrollment, error) {
	if p.Kind != KindEnrollment {
		return Enrollment{}, errInvalid
	}
	actor := audit.Actor{Email: DisplayPrefix(KindEnrollment, p.PublicID), IP: ip, RequestID: requestID}
	return s.enroll(ctx, p.Org, p.PublicID, func(r enrollmentRow) error { return r.check(p.hash, s.Now()) }, req, nil, actor)
}

// enroll inscrit un agent serveur avec le jeton d'inscription publicID, vérifié par
// verify sous verrou. proposed, s'il n'est pas nul, est le jeton d'agent que l'agent a tiré
// lui-même (inscription hors ligne, T23) ; sinon un jeton est tiré ici.
func (s *Service) enroll(ctx context.Context, org tenant.OrgID, publicID string, verify func(enrollmentRow) error,
	req EnrollRequest, proposed *ProposedToken, actor audit.Actor) (Enrollment, error) {
	host, err := project.NormalizeHostRef(req.Hostname)
	if err != nil {
		return Enrollment{}, err
	}
	if err := ValidVersion(req.Version); err != nil {
		return Enrollment{}, err
	}
	if _, err := mergeLabels(nil, req.Labels); err != nil {
		return Enrollment{}, err
	}
	var out Enrollment
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		id, r, err := readEnrollment(ctx, tx, publicID, true)
		if err != nil {
			return err
		}
		if err := verify(r); err != nil {
			return err
		}
		if r.labels, err = mergeLabels(r.labels, req.Labels); err != nil {
			return err
		}
		now := s.Now()
		if out.Agent, err = newAgent(ctx, tx, KindHost, host, req.Version, 0, &now, &r.teamID); err != nil {
			if v, ok := account.IsValidation(err); ok && v.Key == KeyNameTaken {
				return &ConflictError{Key: KeyHostTaken}
			}
			return err
		}
		if out.Project, out.Created, err = hostProject(ctx, tx, r, host, out.Agent.ID); err != nil {
			return err
		}
		// L'agent suit l'équipe de son hôte : celle du jeton pour un projet créé, celle du
		// projet rattaché sinon.
		if !out.Created {
			if err := tx.QueryRowContext(ctx, `UPDATE agents a SET team_id = p.team_id FROM projects p
				 WHERE a.id = $1 AND p.id = $2 RETURNING p.team_id`, out.Agent.ID, out.Project.ID).Scan(&out.Project.TeamID); err != nil {
				return err
			}
			out.Agent.TeamID = &out.Project.TeamID
		}
		var t Token
		if proposed != nil {
			t, err = insertProposedToken(ctx, tx, out.Agent.ID, r.name, *proposed)
		} else {
			t, out.Token, err = insertToken(ctx, tx, out.Agent.ID, r.name, nil, 0)
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET uses = uses + 1, last_used_at = $2 WHERE id = $1`, id, now); err != nil {
			return err
		}
		if out.Created {
			if err := audit.RecordOrg(ctx, tx, actor, audit.Event{Action: audit.ProjectCreated, TargetType: "project",
				TargetID: out.Project.ID.String(), TargetLabel: out.Project.Slug,
				Details: map[string]string{"kind": string(project.KindHost), "team": out.Project.TeamName}}); err != nil {
				return err
			}
		}
		if err := audit.RecordOrg(ctx, tx, actor, agentEvent(audit.AgentEnrolled, out.Agent,
			map[string]string{"project": out.Project.Slug, "token": r.name})); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, tokenEvent(audit.AgentTokenCreated, out.Agent, t, nil))
	})
	if err != nil {
		return Enrollment{}, wrap("inscription", err)
	}
	return out, nil
}

// hostProject confie à agentID le projet de son hôte : celui que désigne le jeton,
// sinon celui qui suit déjà cet hôte, sinon un projet créé.
//
// Sans projet désigné, le rattachement par le nom d'hôte déclaré est borné à l'équipe du
// jeton (SEC2-02) : un projet homonyme d'une autre équipe répond comme un hôte déjà suivi
// (KeyHostTaken, la référence d'hôte étant unique dans l'organisation), sans être pris ni
// révéler son équipe, qu'il ait un agent, aucun, ou qu'il soit archivé. Seul
// l'administrateur d'organisation lève le conflit (jeton de la bonne équipe, ou projet
// désigné).
func hostProject(ctx context.Context, tx *db.OrgTx, r enrollmentRow, host string, agentID uuid.UUID) (project.Project, bool, error) {
	var pid, team uuid.UUID
	var slug string
	var archived, assigned bool
	query := `SELECT p.id, p.slug, p.team_id, p.archived_at IS NOT NULL, p.agent_id IS NOT NULL FROM projects p WHERE p.id = $1 FOR UPDATE`
	arg := any(r.projectID)
	if !r.projectID.Valid {
		query = `SELECT p.id, p.slug, p.team_id, p.archived_at IS NOT NULL, p.agent_id IS NOT NULL
			FROM projects p JOIN tracked_refs t ON t.org_id = p.org_id AND t.project_id = p.id
			WHERE t.kind = 'host' AND lower(t.name) = $1 FOR UPDATE OF p`
		arg = host
	}
	err := tx.QueryRowContext(ctx, query, arg).Scan(&pid, &slug, &team, &archived, &assigned)
	switch {
	case errors.Is(err, sql.ErrNoRows) && !r.projectID.Valid:
		p, err := project.CreateHost(ctx, tx, host, r.labels, agentID, r.teamID)
		if v, ok := account.IsValidation(err); ok && v.Key == project.KeyHostRefTaken {
			return project.Project{}, false, &ConflictError{Key: KeyHostTaken}
		}
		return p, true, err
	case errors.Is(err, sql.ErrNoRows):
		return project.Project{}, false, &ConflictError{Key: KeyProjectUnavailable}
	case err != nil:
		return project.Project{}, false, err
	case !r.projectID.Valid && team != r.teamID:
		return project.Project{}, false, &ConflictError{Key: KeyHostTaken}
	case team != r.teamID:
		// Projet désigné passé dans une autre équipe depuis la création du jeton.
		return project.Project{}, false, &ConflictError{Key: KeyProjectUnavailable}
	case archived:
		return project.Project{}, false, &ConflictError{Key: KeyProjectUnavailable}
	case assigned:
		return project.Project{}, false, &ConflictError{Key: KeyHostTaken}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE projects SET agent_id = $2, updated_at = now() WHERE id = $1`, pid, agentID); err != nil {
		return project.Project{}, false, err
	}
	return project.Project{ID: pid, Kind: project.KindHost, Slug: slug}, false, nil
}

// CurrentSnapshots renvoie l'instantané courant de celles des références refIDs qui en
// ont un (commit du dernier instantané, pour le rattrapage de l'agent dépôt). Les
// références viennent d'AssignedProjects ; la RLS borne de toute façon la lecture à
// l'organisation du jeton.
func (s *Service) CurrentSnapshots(ctx context.Context, p Principal, refIDs []uuid.UUID) (map[uuid.UUID]inventory.Current, error) {
	if p.Kind != KindAgent {
		return nil, errInvalid
	}
	var out map[uuid.UUID]inventory.Current
	err := s.pool.InOrg(ctx, p.Org, func(tx *db.OrgTx) error {
		var err error
		out, err = inventory.CurrentByRef(ctx, tx, refIDs)
		return err
	}, db.ReadOnly())
	return out, wrap("instantanés courants", err)
}

// AssignedProjects renvoie une page des projets actifs confiés à l'agent de p.
func (s *Service) AssignedProjects(ctx context.Context, p Principal, cursor string, limit int) (projects []project.Project, next string, err error) {
	if p.Kind != KindAgent {
		return nil, "", errInvalid
	}
	err = s.pool.InOrg(ctx, p.Org, func(tx *db.OrgTx) error {
		page, err := project.ListForAgent(ctx, tx, p.AgentID, cursor, limit)
		projects, next = page.Items, page.NextCursor
		return err
	}, db.ReadOnly())
	return projects, next, err
}

// AIComponents renvoie les composants IA de l'instantané courant de la référence refID,
// si elle appartient à un projet actif confié à l'agent de p ; project.ErrNotFound
// sinon.
func (s *Service) AIComponents(ctx context.Context, p Principal, refID uuid.UUID) ([]inventory.AIComponent, error) {
	if p.Kind != KindAgent {
		return nil, errInvalid
	}
	var out []inventory.AIComponent
	err := s.pool.InOrg(ctx, p.Org, func(tx *db.OrgTx) error {
		if _, err := project.RefOfAgent(ctx, tx, p.AgentID, refID); err != nil {
			return err
		}
		var err error
		out, err = inventory.AIComponents(ctx, tx, refID)
		return err
	}, db.ReadOnly())
	return out, err
}
