package crossorg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// ErrNoAccess : organisation inconnue, archivée, ou dont le compte n'est pas membre. Les
// trois cas sont volontairement confondus (la garde répond 404).
var ErrNoAccess = errors.New("crossorg: organisation inaccessible")

// ErrNotFound : aucune organisation ne porte ce slug.
var ErrNotFound = errors.New("crossorg: organisation inconnue")

// MaxPage borne une page de ListOrganizations.
const MaxPage = 200

// Access résout le slug d'une organisation active dont userID est membre, pour la garde
// d'organisation (fonction lotor_org_access).
func Access(ctx context.Context, q db.Querier, slug string, userID int64) (tenant.Access, error) {
	var a tenant.Access
	var role string
	err := q.QueryRowContext(ctx,
		`SELECT org_id, slug, name, default_language, role FROM lotor_org_access($1, $2)`, slug, userID,
	).Scan(&a.Org, &a.Slug, &a.Name, &a.Language, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return tenant.Access{}, ErrNoAccess
	}
	if err != nil {
		return tenant.Access{}, fmt.Errorf("crossorg: accès à %q : %w", slug, err)
	}
	if a.Role, err = tenant.ParseRole(role); err != nil {
		return tenant.Access{}, err
	}
	return a, nil
}

// OrgRef est une organisation du sélecteur.
type OrgRef struct {
	Org  tenant.OrgID
	Slug string
	Name string
	Role tenant.Role
}

// UserOrgs renvoie les organisations actives de userID, par nom (200 au plus ; fonction
// lotor_user_orgs).
func UserOrgs(ctx context.Context, q db.Querier, userID int64) ([]OrgRef, error) {
	rows, err := q.QueryContext(ctx, `SELECT org_id, slug, name, role FROM lotor_user_orgs($1)`, userID)
	if err != nil {
		return nil, fmt.Errorf("crossorg: organisations du compte : %w", err)
	}
	defer rows.Close()
	var out []OrgRef
	for rows.Next() {
		var o OrgRef
		var role string
		if err := rows.Scan(&o.Org, &o.Slug, &o.Name, &role); err != nil {
			return nil, fmt.Errorf("crossorg: organisations du compte : %w", err)
		}
		if o.Role, err = tenant.ParseRole(role); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("crossorg: organisations du compte : %w", err)
	}
	return out, nil
}

// OrgSummary décrit une organisation pour l'administration de l'instance.
type OrgSummary struct {
	Org             tenant.OrgID
	Slug            string
	Name            string
	DefaultLanguage string
	ArchivedAt      *time.Time
	CreatedAt       time.Time
	Members         int64
}

// ListOrganizations renvoie au plus limit organisations (archivées comprises) de slug
// supérieur à after, par slug (fonction lotor_list_organizations). Réservé à
// l'administration de l'instance : l'appelant vérifie le rôle du compte.
func ListOrganizations(ctx context.Context, q db.Querier, after string, limit int) ([]OrgSummary, error) {
	if limit < 1 || limit > MaxPage {
		return nil, fmt.Errorf("crossorg: taille de page %d hors de [1, %d]", limit, MaxPage)
	}
	rows, err := q.QueryContext(ctx,
		`SELECT org_id, slug, name, default_language, archived_at, created_at, member_count
		   FROM lotor_list_organizations($1, $2)`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("crossorg: liste des organisations : %w", err)
	}
	defer rows.Close()
	var out []OrgSummary
	for rows.Next() {
		var o OrgSummary
		var archived sql.NullTime
		if err := rows.Scan(&o.Org, &o.Slug, &o.Name, &o.DefaultLanguage, &archived, &o.CreatedAt, &o.Members); err != nil {
			return nil, fmt.Errorf("crossorg: liste des organisations : %w", err)
		}
		if archived.Valid {
			t := archived.Time
			o.ArchivedAt = &t
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("crossorg: liste des organisations : %w", err)
	}
	return out, nil
}

// OrgIDBySlug résout un slug, organisations archivées comprises, pour l'administration de
// l'instance (fonction lotor_org_id_by_slug).
func OrgIDBySlug(ctx context.Context, q db.Querier, slug string) (tenant.OrgID, error) {
	var id sql.Null[tenant.OrgID]
	if err := q.QueryRowContext(ctx, `SELECT lotor_org_id_by_slug($1)`, slug).Scan(&id); err != nil {
		return tenant.OrgID{}, fmt.Errorf("crossorg: slug %q : %w", slug, err)
	}
	if !id.Valid {
		return tenant.OrgID{}, ErrNotFound
	}
	return id.V, nil
}

// ErrUnknownToken : aucun jeton actif d'une organisation active ne porte cet identifiant
// public.
var ErrUnknownToken = errors.New("crossorg: jeton inconnu")

// AgentTokenOrg renvoie l'organisation (active) d'un jeton d'agent désigné par son
// identifiant public (fonction lotor_agent_token_org). Le secret, la révocation et
// l'expiration se vérifient ensuite dans InOrg.
func AgentTokenOrg(ctx context.Context, q db.Querier, publicID string) (tenant.OrgID, error) {
	return tokenOrg(ctx, q, `SELECT lotor_agent_token_org($1)`, publicID)
}

// EnrollmentTokenOrg fait de même pour un jeton d'inscription (fonction
// lotor_enrollment_token_org).
func EnrollmentTokenOrg(ctx context.Context, q db.Querier, publicID string) (tenant.OrgID, error) {
	return tokenOrg(ctx, q, `SELECT lotor_enrollment_token_org($1)`, publicID)
}

func tokenOrg(ctx context.Context, q db.Querier, query, publicID string) (tenant.OrgID, error) {
	var id sql.Null[tenant.OrgID]
	if err := q.QueryRowContext(ctx, query, publicID).Scan(&id); err != nil {
		return tenant.OrgID{}, fmt.Errorf("crossorg: organisation d'un jeton : %w", err)
	}
	if !id.Valid {
		return tenant.OrgID{}, ErrUnknownToken
	}
	return id.V, nil
}

// Invitation est une invitation en attente d'un compte.
type Invitation struct {
	Org       tenant.OrgID
	ID        uuid.UUID
	Slug      string
	Name      string
	Role      tenant.Role
	CreatedAt time.Time
	ExpiresAt time.Time
}

// UserInvitations renvoie les invitations en attente adressées à l'e-mail de userID
// (50 au plus, des organisations actives dont il n'est pas membre ; fonction
// lotor_user_invitations, ADR 0034).
func UserInvitations(ctx context.Context, q db.Querier, userID int64) ([]Invitation, error) {
	rows, err := q.QueryContext(ctx, `SELECT org_id, invitation_id, slug, name, role, created_at, expires_at
		  FROM lotor_user_invitations($1)`, userID)
	if err != nil {
		return nil, fmt.Errorf("crossorg: invitations du compte : %w", err)
	}
	defer rows.Close()
	var out []Invitation
	for rows.Next() {
		var i Invitation
		var role string
		if err := rows.Scan(&i.Org, &i.ID, &i.Slug, &i.Name, &role, &i.CreatedAt, &i.ExpiresAt); err != nil {
			return nil, fmt.Errorf("crossorg: invitations du compte : %w", err)
		}
		if i.Role, err = tenant.ParseRole(role); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("crossorg: invitations du compte : %w", err)
	}
	return out, nil
}

// TokenInvitation est une invitation d'organisation désignée par l'identifiant public de son
// lien (T28) : SecretHash est l'empreinte attendue du secret, à comparer en temps constant.
type TokenInvitation struct {
	Org        tenant.OrgID
	ID         uuid.UUID
	Email      string
	Role       tenant.Role
	SecretHash []byte
	ExpiresAt  time.Time
	Slug       string
	Name       string
	Language   string
}

// InvitationByToken renvoie l'invitation non expirée, d'une organisation active, dont le
// lien porte publicID (fonction lotor_invitation_by_token, ADR 0056) ; ErrNotFound sinon.
func InvitationByToken(ctx context.Context, q db.Querier, publicID string) (TokenInvitation, error) {
	var i TokenInvitation
	var role string
	err := q.QueryRowContext(ctx, `SELECT org_id, invitation_id, email, role, secret_hash, expires_at, slug, name, language
		  FROM lotor_invitation_by_token($1)`, publicID).
		Scan(&i.Org, &i.ID, &i.Email, &role, &i.SecretHash, &i.ExpiresAt, &i.Slug, &i.Name, &i.Language)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenInvitation{}, ErrNotFound
	}
	if err != nil {
		return TokenInvitation{}, fmt.Errorf("crossorg: invitation par son lien : %w", err)
	}
	if i.Role, err = tenant.ParseRole(role); err != nil {
		return TokenInvitation{}, err
	}
	return i, nil
}
