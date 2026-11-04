package project

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
)

// ErrVersionsLimit : le dépôt suit déjà MaxVersions versions actives.
var ErrVersionsLimit = errors.New("project: trop de versions suivies")

// CreateForAgent crée, dans la transaction de l'appelant, le dépôt d'un envoi au point
// compatible Dependency-Track (autoCreate, ADR 0057) : nom de l'envoi, slug dérivé et
// rendu unique, confié à l'agent, dans son équipe, sans adresse de forge ni référence.
// La création est journalisée au nom du jeton de l'agent.
func CreateForAgent(ctx context.Context, tx *db.OrgTx, actor audit.Actor, name string, agentID, teamID uuid.UUID) (Project, error) {
	n, err := validName(name)
	if err != nil {
		return Project{}, err
	}
	p, err := insert(ctx, tx, Input{Kind: KindRepo, Name: n, Labels: Labels{}, TeamID: teamID}, &agentID)
	if err != nil {
		return Project{}, err
	}
	return p, audit.RecordOrg(ctx, tx, actor, event(audit.ProjectCreated, p,
		map[string]string{"kind": string(p.Kind), "team": p.TeamName, "source": "dependency-track"}))
}

// VersionRef renvoie la référence active de nature « version » d'un dépôt.
func VersionRef(ctx context.Context, tx *db.OrgTx, projectID uuid.UUID, version string) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM tracked_refs
		WHERE project_id = $1 AND kind = 'version' AND name = $2 AND removed_at IS NULL`, projectID, version).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return id, err
}

// AddVersion ajoute (ou réactive) la version d'un dépôt, dans la transaction de
// l'appelant, sous verrou du projet, et la journalise. Au-delà de MaxVersions versions
// actives, ErrVersionsLimit.
func AddVersion(ctx context.Context, tx *db.OrgTx, actor audit.Actor, projectID uuid.UUID, version string) (uuid.UUID, error) {
	if !ValidVersionName(version) {
		return uuid.Nil, invalid("versions", KeyRefInvalid)
	}
	var slug string
	var active int
	err := tx.QueryRowContext(ctx, `SELECT p.slug,
		       (SELECT count(*) FROM tracked_refs r WHERE r.org_id = p.org_id AND r.project_id = p.id
		           AND r.kind = 'version' AND r.removed_at IS NULL)
		  FROM projects p WHERE p.id = $1 AND p.kind = 'repo' FOR UPDATE OF p`, projectID).Scan(&slug, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	if active >= MaxVersions {
		return uuid.Nil, ErrVersionsLimit
	}
	var id uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name)
		VALUES ($1, $2, $3, 'repo', 'version', $4)
		ON CONFLICT (org_id, project_id, kind, name) DO UPDATE SET removed_at = NULL
		RETURNING id`, tx.OrgID(), uuid.Must(uuid.NewV7()), projectID, version).Scan(&id); err != nil {
		return uuid.Nil, err
	}
	return id, audit.RecordOrg(ctx, tx, actor, audit.Event{Action: audit.ProjectVersionAdded, TargetType: "project",
		TargetID: projectID.String(), TargetLabel: slug, Details: map[string]string{"version": version}})
}
