package org

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/tenant"
)

// ErrNotFound : organisation ou membre inconnu (dans l'organisation déclarée).
var ErrNotFound = errors.New("org: introuvable")

// Clés de validation.
const (
	KeySlugInvalid    = "validation.slug_invalid"
	KeySlugTaken      = "validation.slug_taken"
	KeyNameInvalid    = "validation.name_invalid"
	KeyLanguage       = "validation.language_invalid"
	KeyRoleInvalid    = "validation.role_invalid"
	KeyMemberExists   = "validation.member_exists"
	KeyUnknownAccount = "validation.member_unknown_account"
	KeyLastOrgAdmin   = "validation.last_org_admin"
)

func invalid(field, key string) error { return &account.ValidationError{Field: field, Key: key} }

// slugPattern reprend la contrainte de la table organizations.
var slugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)

// Organization est une organisation.
type Organization struct {
	ID              tenant.OrgID
	Slug            string
	Name            string
	DefaultLanguage string
	ArchivedAt      *time.Time
	CreatedAt       time.Time
}

// Member est l'appartenance d'un compte à une organisation.
type Member struct {
	UserID   int64
	Email    string
	Active   bool
	Role     tenant.Role
	JoinedAt time.Time
}

// Service gère les organisations et leurs membres. Toute lecture ou écriture passe par
// InOrg ; chaque modification est journalisée dans la même transaction.
type Service struct {
	pool *db.Pool
}

// NewService construit le service.
func NewService(pool *db.Pool) *Service { return &Service{pool: pool} }

func validName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" || utf8.RuneCountInString(n) > 100 {
		return "", invalid("name", KeyNameInvalid)
	}
	return n, nil
}

func validLanguage(lang string) error {
	if !slices.Contains(account.Languages, lang) {
		return invalid("language", KeyLanguage)
	}
	return nil
}

func orgEvent(action audit.Action, o Organization, details map[string]string) audit.Event {
	return audit.Event{Action: action, TargetType: "org", TargetID: o.ID.String(), TargetLabel: o.Slug, Details: details}
}

// DefaultTeamName est le nom de l'équipe créée avec chaque organisation, selon sa langue
// (même nom que l'équipe de la migration 016).
func DefaultTeamName(lang string) string {
	if lang == "en" {
		return "General"
	}
	return "Général"
}

// Create crée une organisation, en fait de adminUserID son premier administrateur et lui
// donne une première équipe (DefaultTeamName), pour que ses premiers projets en aient une.
func (s *Service) Create(ctx context.Context, actor audit.Actor, slug, name, lang string, adminUserID int64) (Organization, error) {
	id, err := tenant.NewOrgID()
	if err != nil {
		return Organization{}, err
	}
	var o Organization
	err = s.pool.InOrg(ctx, id, func(tx *db.OrgTx) error {
		var err error
		o, err = CreateIn(ctx, tx, actor, []string{strings.TrimSpace(slug)}, name, lang, adminUserID)
		return err
	})
	if err != nil {
		return Organization{}, wrap("création de l'organisation "+slug, err)
	}
	return o, nil
}

// CreateIn crée, dans tx déclarée pour l'organisation à créer (tx.OrgID()), l'organisation
// name avec le premier des identifiants d'URL slugs qui est libre, fait de adminUserID son
// premier administrateur et crée son équipe « Général ». Un identifiant pris n'interrompt
// pas la transaction (ON CONFLICT) : l'inscription (T28) propose ainsi plusieurs candidats
// dérivés du nom dans la transaction qui crée aussi le compte. Tous pris : KeySlugTaken.
func CreateIn(ctx context.Context, tx *db.OrgTx, actor audit.Actor, slugs []string, name, lang string, adminUserID int64) (Organization, error) {
	for _, slug := range slugs {
		if !slugPattern.MatchString(slug) {
			return Organization{}, invalid("slug", KeySlugInvalid)
		}
	}
	if len(slugs) == 0 {
		return Organization{}, invalid("slug", KeySlugInvalid)
	}
	name, err := validName(name)
	if err != nil {
		return Organization{}, err
	}
	if err := validLanguage(lang); err != nil {
		return Organization{}, err
	}
	var o Organization
	created := false
	for _, slug := range slugs {
		err := tx.QueryRowContext(ctx, `
			INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, $3, $4)
			ON CONFLICT (slug) DO NOTHING
			RETURNING id, slug, name, default_language, archived_at, created_at`,
			tx.OrgID(), slug, name, lang).Scan(&o.ID, &o.Slug, &o.Name, &o.DefaultLanguage, new(sql.NullTime), &o.CreatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return Organization{}, err
		}
		created = true
		break
	}
	if !created {
		return Organization{}, invalid("slug", KeySlugTaken)
	}
	ev := orgEvent(audit.OrgCreated, o, map[string]string{"name": name, "language": lang})
	if err := audit.RecordOrg(ctx, tx, actor, ev); err != nil {
		return Organization{}, err
	}
	if err := audit.RecordInstance(ctx, tx, actor, ev); err != nil {
		return Organization{}, err
	}
	if err := addMember(ctx, tx, actor, adminUserID, tenant.RoleAdmin); err != nil {
		return Organization{}, err
	}
	if _, err := insertTeam(ctx, tx, actor, DefaultTeamName(lang)); err != nil {
		return Organization{}, err
	}
	return o, nil
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := account.IsValidation(err); ok || errors.Is(err, ErrNotFound) {
		return err
	}
	return fmt.Errorf("org: %s : %w", what, err)
}

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

func getOrg(ctx context.Context, tx *db.OrgTx, lock bool) (Organization, error) {
	query := `SELECT id, slug, name, default_language, archived_at, created_at FROM organizations`
	if lock {
		query += ` FOR UPDATE`
	}
	var o Organization
	var archived sql.NullTime
	// La RLS ne laisse voir que l'organisation déclarée : pas de filtre ici.
	err := tx.QueryRowContext(ctx, query).Scan(&o.ID, &o.Slug, &o.Name, &o.DefaultLanguage, &archived, &o.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	if err != nil {
		return Organization{}, err
	}
	if archived.Valid {
		t := archived.Time
		o.ArchivedAt = &t
	}
	return o, nil
}

// Get renvoie une organisation.
func (s *Service) Get(ctx context.Context, org tenant.OrgID) (Organization, error) {
	var o Organization
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		o, err = getOrg(ctx, tx, false)
		return err
	}, db.ReadOnly())
	return o, wrap("lecture de l'organisation", err)
}

// Update change le nom et la langue par défaut d'une organisation.
func (s *Service) Update(ctx context.Context, actor audit.Actor, org tenant.OrgID, name, lang string) error {
	name, err := validName(name)
	if err != nil {
		return err
	}
	if err := validLanguage(lang); err != nil {
		return err
	}
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		o, err := getOrg(ctx, tx, true)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE organizations SET name = $1, default_language = $2`, name, lang); err != nil {
			return err
		}
		var events []audit.Event
		if name != o.Name {
			events = append(events, orgEvent(audit.OrgRenamed, o, map[string]string{"from": o.Name, "to": name}))
		}
		if lang != o.DefaultLanguage {
			events = append(events, orgEvent(audit.OrgLanguageChanged, o, map[string]string{"from": o.DefaultLanguage, "to": lang}))
		}
		for _, ev := range events {
			if err := audit.RecordOrg(ctx, tx, actor, ev); err != nil {
				return err
			}
			if err := audit.RecordInstance(ctx, tx, actor, ev); err != nil {
				return err
			}
		}
		return nil
	})
	return wrap("modification de l'organisation", err)
}

// SetArchived archive une organisation (elle disparaît pour ses membres : 404) ou la
// réactive.
func (s *Service) SetArchived(ctx context.Context, actor audit.Actor, org tenant.OrgID, archived bool) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		o, err := getOrg(ctx, tx, true)
		if err != nil {
			return err
		}
		if (o.ArchivedAt != nil) == archived {
			return nil
		}
		query, action := `UPDATE organizations SET archived_at = now()`, audit.OrgArchived
		if !archived {
			query, action = `UPDATE organizations SET archived_at = NULL`, audit.OrgUnarchived
		}
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
		ev := orgEvent(action, o, nil)
		if err := audit.RecordOrg(ctx, tx, actor, ev); err != nil {
			return err
		}
		return audit.RecordInstance(ctx, tx, actor, ev)
	})
	return wrap("archivage de l'organisation", err)
}

// DefaultPage et MaxPage bornent une page de membres.
const (
	DefaultPage = 50
	MaxPage     = 200
)

const memberColumns = `m.user_id, u.email, u.is_active, m.role, m.created_at`

func scanMember(row interface{ Scan(...any) error }) (Member, error) {
	var m Member
	var active int
	var role string
	if err := row.Scan(&m.UserID, &m.Email, &active, &role, &m.JoinedAt); err != nil {
		return Member{}, err
	}
	m.Active = active == 1
	var err error
	m.Role, err = tenant.ParseRole(role)
	return m, err
}

// Members renvoie une page des membres de l'organisation, par e-mail.
func (s *Service) Members(ctx context.Context, org tenant.OrgID, cursor string, limit int) (pagination.Page[Member], error) {
	if limit < 1 || limit > MaxPage {
		return pagination.Page[Member]{}, &pagination.LimitError{Max: MaxPage}
	}
	var after string
	if cursor != "" {
		if err := pagination.Decode(cursor, &after); err != nil {
			return pagination.Page[Member]{}, err
		}
	}
	var page pagination.Page[Member]
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT `+memberColumns+`
			  FROM org_memberships m JOIN users u ON u.id = m.user_id
			 WHERE m.org_id = $1 AND u.email > $2
			 ORDER BY u.email LIMIT $3`, tx.OrgID(), after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		var out []Member
		for rows.Next() {
			m, err := scanMember(rows)
			if err != nil {
				return err
			}
			out = append(out, m)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		page, err = pagination.Build(out, limit, func(m Member) any { return m.Email })
		return err
	}, db.ReadOnly())
	return page, wrap("liste des membres", err)
}

// Member renvoie le membre userID de l'organisation ; ErrNotFound s'il n'en est pas
// membre.
func (s *Service) Member(ctx context.Context, org tenant.OrgID, userID int64) (Member, error) {
	var m Member
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		m, err = scanMember(tx.QueryRowContext(ctx, `
			SELECT `+memberColumns+`
			  FROM org_memberships m JOIN users u ON u.id = m.user_id
			 WHERE m.org_id = $1 AND m.user_id = $2`, tx.OrgID(), userID))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}, db.ReadOnly())
	return m, wrap("lecture d'un membre", err)
}

// Admins renvoie les administrateurs de l'organisation (50 au plus).
func (s *Service) Admins(ctx context.Context, org tenant.OrgID) ([]Member, error) {
	var out []Member
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT `+memberColumns+`
			  FROM org_memberships m JOIN users u ON u.id = m.user_id
			 WHERE m.org_id = $1 AND m.role = 'admin'
			 ORDER BY u.email LIMIT 50`, tx.OrgID())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			m, err := scanMember(rows)
			if err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	}, db.ReadOnly())
	return out, wrap("administrateurs de l'organisation", err)
}

func memberEvent(action audit.Action, userID int64, email string, details map[string]string) audit.Event {
	return audit.Event{Action: action, TargetType: "member", TargetID: strconv.FormatInt(userID, 10), TargetLabel: email, Details: details}
}

func addMember(ctx context.Context, tx *db.OrgTx, actor audit.Actor, userID int64, role tenant.Role) error {
	var email string
	err := tx.QueryRowContext(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return invalid("email", KeyUnknownAccount)
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1, $2, $3)`,
		tx.OrgID(), userID, string(role))
	if isUnique(err) {
		return invalid("email", KeyMemberExists)
	}
	if err != nil {
		return err
	}
	return audit.RecordOrg(ctx, tx, actor, memberEvent(audit.MemberAdded, userID, email, map[string]string{"role": string(role)}))
}

// AddMember ajoute directement un compte existant (désigné par son e-mail) à
// l'organisation. Réservé à l'administration de l'instance, qui connaît déjà les comptes :
// dans l'organisation, un membre s'ajoute par invitation (Invite, SEC-09).
func (s *Service) AddMember(ctx context.Context, actor audit.Actor, org tenant.OrgID, email string, role tenant.Role) error {
	if _, err := tenant.ParseRole(string(role)); err != nil {
		return invalid("role", KeyRoleInvalid)
	}
	e, err := account.NormalizeEmail(email)
	if err != nil {
		return err
	}
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var id int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE email = $1`, e).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return invalid("email", KeyUnknownAccount)
		}
		if err != nil {
			return err
		}
		return addMember(ctx, tx, actor, id, role)
	})
	return wrap("ajout d'un membre", err)
}

// lockMember charge un membre sous verrou ; l'organisation entière est verrouillée pour
// que deux retraits simultanés ne laissent pas l'organisation sans administrateur.
func lockMember(ctx context.Context, tx *db.OrgTx, userID int64) (Member, error) {
	if _, err := getOrg(ctx, tx, true); err != nil {
		return Member{}, err
	}
	m, err := scanMember(tx.QueryRowContext(ctx, `
		SELECT `+memberColumns+`
		  FROM org_memberships m JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1 AND m.user_id = $2`, tx.OrgID(), userID))
	if errors.Is(err, sql.ErrNoRows) {
		return Member{}, ErrNotFound
	}
	return m, err
}

func keepOneAdmin(ctx context.Context, tx *db.OrgTx, m Member) error {
	if m.Role != tenant.RoleAdmin {
		return nil
	}
	var others int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM org_memberships WHERE org_id = $1 AND role = 'admin' AND user_id <> $2`,
		tx.OrgID(), m.UserID).Scan(&others); err != nil {
		return err
	}
	if others == 0 {
		return invalid("role", KeyLastOrgAdmin)
	}
	return nil
}

// SetMemberRole change le rôle d'un membre ; le dernier administrateur le reste.
func (s *Service) SetMemberRole(ctx context.Context, actor audit.Actor, org tenant.OrgID, userID int64, role tenant.Role) error {
	if _, err := tenant.ParseRole(string(role)); err != nil {
		return invalid("role", KeyRoleInvalid)
	}
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		m, err := lockMember(ctx, tx, userID)
		if err != nil {
			return err
		}
		if m.Role == role {
			return nil
		}
		if role != tenant.RoleAdmin {
			if err := keepOneAdmin(ctx, tx, m); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE org_memberships SET role = $1 WHERE org_id = $2 AND user_id = $3`,
			string(role), tx.OrgID(), userID); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, memberEvent(audit.MemberRoleChanged, userID, m.Email,
			map[string]string{"from": string(m.Role), "to": string(role)}))
	})
	return wrap("changement de rôle", err)
}

// RemoveMember retire un membre ; le dernier administrateur ne peut pas être retiré.
func (s *Service) RemoveMember(ctx context.Context, actor audit.Actor, org tenant.OrgID, userID int64) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		m, err := lockMember(ctx, tx, userID)
		if err != nil {
			return err
		}
		if err := keepOneAdmin(ctx, tx, m); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM org_memberships WHERE org_id = $1 AND user_id = $2`,
			tx.OrgID(), userID); err != nil {
			return err
		}
		// Une organisation par défaut qui n'est plus la sienne n'est plus proposée.
		if _, err := tx.ExecContext(ctx,
			`UPDATE account_settings SET default_org_id = NULL WHERE user_id = $1 AND default_org_id = $2`,
			userID, tx.OrgID()); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, memberEvent(audit.MemberRemoved, userID, m.Email,
			map[string]string{"role": string(m.Role)}))
	})
	return wrap("retrait d'un membre", err)
}
