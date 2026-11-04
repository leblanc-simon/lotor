package agent

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// Clés des refus du point compatible Dependency-Track (ADR 0057).
const (
	KeyDTAgentKind        = "error.dt.agent_kind"
	KeyDTProjectUnknown   = "error.dt.project_unknown"
	KeyDTAmbiguous        = "error.dt.project_ambiguous"
	KeyDTAutoCreate       = "error.dt.auto_create_forbidden"
	KeyDTVersionsLimit    = "error.dt.versions_limit"
	KeyDTTargetMissing    = "validation.dt.target_missing"
	KeyDTVersionInvalid   = "validation.dt.version_invalid"
	KeyDTNotAutoCreatable = "validation.dt.team_missing"
)

// DTErrorKeys liste les clés d'erreur du point compatible (tests de traduction).
func DTErrorKeys() []string {
	return []string{KeyDTAgentKind, KeyDTProjectUnknown, KeyDTAmbiguous, KeyDTAutoCreate, KeyDTVersionsLimit}
}

// DTValidationKeys liste les clés de saisie du point compatible (tests de traduction).
func DTValidationKeys() []string {
	return []string{KeyDTTargetMissing, KeyDTVersionInvalid, KeyDTNotAutoCreatable}
}

// ForbiddenError est une requête d'agent authentifiée mais hors de ses droits (403).
type ForbiddenError struct{ Key string }

func (e *ForbiddenError) Error() string { return "agent: requête interdite : " + e.Key }

// ErrDTUnknown : projet ou version inconnus de l'agent, sans création automatique
// demandée (404, sans distinguer un projet absent d'un projet confié à un autre agent).
var ErrDTUnknown = errors.New("agent: projet ou version inconnus pour cet agent")

// UploadTarget désigne la cible d'un envoi au point compatible : par la référence
// (identifiant « project » de Dependency-Track, qui désigne un projet et sa version),
// ou par le nom du projet et sa version.
type UploadTarget struct {
	RefID       uuid.UUID
	ProjectName string
	Version     string
	AutoCreate  bool
}

// ResolvedTarget est la référence de nature « version » qui reçoit l'envoi.
type ResolvedTarget struct {
	ProjectID uuid.UUID
	RefID     uuid.UUID
	Version   string
	// ProjectCreated, VersionCreated : créés par cet envoi (autoCreate).
	ProjectCreated bool
	VersionCreated bool
}

// ResolveUpload résout la cible d'un envoi au point compatible Dependency-Track, pour un
// agent dépôt : le projet est un dépôt confié à l'agent, désigné par son nom exact, la
// version une référence de nature « version » (ADR 0057). Avec AutoCreate et si l'agent
// y est autorisé (DTAutoCreate, agent d'équipe), le projet et la version manquants sont
// créés, dans l'équipe de l'agent, et journalisés. La résolution compte comme un contact
// de l'agent. Le reste des contrôles (référence confiée à l'agent, bornes, quotas) est
// celui de l'ingestion native, que l'appelant enchaîne.
func (s *Service) ResolveUpload(ctx context.Context, p Principal, t UploadTarget, ip, requestID string) (ResolvedTarget, error) {
	if p.Kind != KindAgent || p.AgentKind != KindRepo {
		return ResolvedTarget{}, &ForbiddenError{Key: KeyDTAgentKind}
	}
	if t.RefID == uuid.Nil {
		if t.ProjectName == "" || t.Version == "" {
			return ResolvedTarget{}, invalid("project", KeyDTTargetMissing)
		}
		if !project.ValidVersionName(t.Version) {
			return ResolvedTarget{}, invalid("projectVersion", KeyDTVersionInvalid)
		}
	}
	actor := audit.Actor{Email: DisplayPrefix(KindAgent, p.PublicID), IP: ip, RequestID: requestID}
	var out ResolvedTarget
	err := s.pool.InOrg(ctx, p.Org, func(tx *db.OrgTx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET last_seen_at = $2 WHERE id = $1`, p.AgentID, s.Now()); err != nil {
			return err
		}
		if t.RefID != uuid.Nil {
			return refByID(ctx, tx, p.AgentID, t.RefID, &out)
		}
		// Deux envois simultanés du même agent ne créent pas deux fois le même projet.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('lotor:dt:' || $1::text, 0))`,
			p.AgentID); err != nil {
			return err
		}
		var allowed bool
		var team uuid.NullUUID
		if err := tx.QueryRowContext(ctx, `SELECT dt_auto_create, team_id FROM agents WHERE id = $1`, p.AgentID).
			Scan(&allowed, &team); err != nil {
			return err
		}
		create := func() error {
			if !t.AutoCreate {
				return ErrDTUnknown
			}
			if !allowed || !team.Valid {
				return &ForbiddenError{Key: KeyDTAutoCreate}
			}
			return nil
		}
		pr, err := projectByName(ctx, tx, p.AgentID, t.ProjectName)
		switch {
		case errors.Is(err, project.ErrNotFound):
			if err := create(); err != nil {
				return err
			}
			created, err := project.CreateForAgent(ctx, tx, actor, t.ProjectName, p.AgentID, team.UUID)
			if err != nil {
				return err
			}
			pr, out.ProjectCreated = created.ID, true
		case err != nil:
			return err
		}
		out.ProjectID, out.Version = pr, t.Version
		ref, err := project.VersionRef(ctx, tx, pr, t.Version)
		if errors.Is(err, project.ErrNotFound) {
			if err := create(); err != nil {
				return err
			}
			ref, err = project.AddVersion(ctx, tx, actor, pr, t.Version)
			if errors.Is(err, project.ErrVersionsLimit) {
				return &ConflictError{Key: KeyDTVersionsLimit}
			}
			out.VersionCreated = err == nil
		}
		if err != nil {
			return err
		}
		out.RefID = ref
		return nil
	})
	if err != nil {
		return ResolvedTarget{}, wrapDT(err)
	}
	return out, nil
}

func wrapDT(err error) error {
	var f *ForbiddenError
	if errors.Is(err, ErrDTUnknown) || errors.As(err, &f) {
		return err
	}
	return wrap("point compatible Dependency-Track", err)
}

// refByID lit une référence de nature « version » d'un dépôt actif confié à l'agent.
func refByID(ctx context.Context, tx *db.OrgTx, agentID, refID uuid.UUID, out *ResolvedTarget) error {
	err := tx.QueryRowContext(ctx, `
		SELECT r.project_id, r.name FROM tracked_refs r
		  JOIN projects p ON p.org_id = r.org_id AND p.id = r.project_id
		 WHERE r.id = $1 AND r.kind = 'version' AND r.removed_at IS NULL
		   AND p.agent_id = $2 AND p.kind = 'repo' AND p.archived_at IS NULL`, refID, agentID).
		Scan(&out.ProjectID, &out.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDTUnknown
	}
	out.RefID = refID
	return err
}

// projectByName lit le dépôt actif confié à l'agent qui porte exactement ce nom ; deux
// dépôts homonymes de l'agent rendent la cible ambiguë.
func projectByName(ctx context.Context, tx *db.OrgTx, agentID uuid.UUID, name string) (uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id FROM projects WHERE agent_id = $1 AND name = $2 AND kind = 'repo' AND archived_at IS NULL
		 ORDER BY id LIMIT 2 FOR UPDATE`, agentID, name)
	if err != nil {
		return uuid.Nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return uuid.Nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, err
	}
	switch len(ids) {
	case 0:
		return uuid.Nil, project.ErrNotFound
	case 1:
		return ids[0], nil
	}
	return uuid.Nil, &ConflictError{Key: KeyDTAmbiguous}
}

// SetDTAutoCreate autorise ou non un agent dépôt à créer projets et versions par le point
// compatible Dependency-Track. L'autorisation exige un agent d'équipe : le projet créé
// appartient à l'équipe de l'agent.
func (s *Service) SetDTAutoCreate(ctx context.Context, actor audit.Actor, org tenant.OrgID, agentID uuid.UUID, allowed bool) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		a, err := loadAgent(ctx, tx, agentID, s.Now(), true, false)
		if err != nil {
			return err
		}
		if a.Kind != KindRepo || a.DisabledAt != nil {
			return ErrNotFound
		}
		if allowed && a.TeamID == nil {
			return invalid("dt_auto_create", KeyDTNotAutoCreatable)
		}
		if a.DTAutoCreate == allowed {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET dt_auto_create = $2 WHERE id = $1`, agentID, allowed); err != nil {
			return err
		}
		action := audit.AgentDTAutoCreateOff
		if allowed {
			action = audit.AgentDTAutoCreateOn
		}
		return audit.RecordOrg(ctx, tx, actor, agentEvent(action, a, nil))
	})
	return wrap("création automatique Dependency-Track", err)
}
