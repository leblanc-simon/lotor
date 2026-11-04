package org

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/mailer"
	"leblanc.io/lotor/internal/secret"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/token"
)

// Bornes des invitations : durée de validité, invitations en attente par organisation.
const (
	InvitationLifetime = 30 * 24 * time.Hour
	MaxInvitations     = 200
)

// Invitation est une invitation d'une organisation, vue de ses administrateurs.
type Invitation struct {
	ID        uuid.UUID
	Email     string
	Role      tenant.Role
	InvitedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Expired indique si l'invitation a expiré à l'instant now.
func (i Invitation) Expired(now time.Time) bool { return !now.Before(i.ExpiresAt) }

func invitationEvent(action audit.Action, email string, id uuid.UUID, details map[string]string) audit.Event {
	return audit.Event{Action: action, TargetType: "invitation", TargetID: id.String(), TargetLabel: email, Details: details}
}

// Invite invite l'adresse email à rejoindre l'organisation avec le rôle role, sans lien
// à transmettre (voir InviteWithLink).
func (s *Service) Invite(ctx context.Context, actor audit.Actor, org tenant.OrgID, email string, role tenant.Role) error {
	_, err := s.InviteWithLink(ctx, actor, org, email, role, InviteMail{})
	return err
}

// InviteMail règle l'envoi du lien d'une invitation par courriel (T28). Sans Secrets, le
// lien n'est pas envoyé : l'administrateur le transmet à la main.
type InviteMail struct {
	Secrets *secret.Box
	// Language est la langue du courriel, celle de l'invitant ; RoleLabel le rôle traduit
	// dans cette langue.
	Language  string
	RoleLabel string
}

// Link est le lien d'une invitation : Token, à montrer une seule fois s'il n'est pas
// envoyé, est vide quand l'adresse est déjà membre (rien n'est créé).
type Link struct {
	Token     string
	Mailed    bool
	ExpiresAt time.Time
}

// InvitationPath est le chemin du lien d'une invitation d'organisation.
func InvitationPath(raw string) string { return "/invitation/" + raw }

// InviteWithLink invite l'adresse email à rejoindre l'organisation avec le rôle role
// (SEC-09) et lui attache un lien secret neuf (T28), qui remplace le précédent : avec lui,
// la personne invitée crée son compte à cette adresse, ou se connecte pour accepter. La
// réponse ne dit rien du compte : l'invitation est enregistrée qu'un compte porte cette
// adresse ou non, et une nouvelle invitation remplace la précédente (rôle, échéance,
// lien). Seule exception, sans rien révéler de plus que la liste des membres : une adresse
// déjà membre n'est pas invitée. Avec mail.Secrets, le lien part par courriel, mis en file
// dans la transaction.
func (s *Service) InviteWithLink(ctx context.Context, actor audit.Actor, org tenant.OrgID, email string, role tenant.Role,
	mail InviteMail) (Link, error) {
	if _, err := tenant.ParseRole(string(role)); err != nil {
		return Link{}, invalid("role", KeyRoleInvalid)
	}
	e, err := account.NormalizeEmail(email)
	if err != nil {
		return Link{}, err
	}
	issued, err := token.New(token.Invitation)
	if err != nil {
		return Link{}, err
	}
	var link Link
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		o, err := getOrg(ctx, tx, true)
		if err != nil {
			return err
		}
		var member bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM org_memberships m JOIN users u ON u.id = m.user_id
			 WHERE m.org_id = $1 AND u.email = $2)`, tx.OrgID(), e).Scan(&member); err != nil {
			return err
		}
		if member {
			return nil
		}
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM org_invitations WHERE email <> $1`, e).Scan(&pending); err != nil {
			return err
		}
		if pending >= MaxInvitations {
			return invalid("email", KeyInvitationLimit)
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		var invitedBy *int64
		if actor.UserID != 0 {
			invitedBy = &actor.UserID
		}
		var expires time.Time
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO org_invitations (org_id, id, email, role, invited_by, expires_at, public_id, secret_hash)
			VALUES ($1, $2, $3, $4, $5, now() + $6 * interval '1 second', $7, $8)
			ON CONFLICT (org_id, email) DO UPDATE
			   SET role = excluded.role, invited_by = excluded.invited_by, created_at = now(), expires_at = excluded.expires_at,
			       public_id = excluded.public_id, secret_hash = excluded.secret_hash
			RETURNING id, expires_at`, tx.OrgID(), id, e, string(role), invitedBy, int64(InvitationLifetime/time.Second),
			issued.PublicID, issued.Hash[:]).Scan(&id, &expires); err != nil {
			return err
		}
		link = Link{Token: issued.Plaintext, ExpiresAt: expires}
		if mail.Secrets != nil {
			inviter := actor.Email
			if inviter == "" {
				inviter = o.Name
			}
			if err := mailer.Enqueue(ctx, tx, mail.Secrets, mailer.Message{To: e, Language: mail.Language,
				Template: mailer.OrgInvitation, Path: InvitationPath(issued.Plaintext),
				Params: map[string]string{"Org": o.Name, "Inviter": inviter, "Role": mail.RoleLabel,
					"Expires": expires.UTC().Format(time.DateOnly)}}); err != nil {
				return err
			}
			link.Mailed = true
		}
		return audit.RecordOrg(ctx, tx, actor, invitationEvent(audit.MemberInvited, e, id,
			map[string]string{"role": string(role), "mailed": strconv.FormatBool(link.Mailed)}))
	})
	return link, wrap("invitation", err)
}

// Invitations renvoie les invitations de l'organisation (expirées comprises, jusqu'à leur
// remplacement ou leur révocation), de la plus récente à la plus ancienne.
func (s *Service) Invitations(ctx context.Context, org tenant.OrgID) ([]Invitation, error) {
	var out []Invitation
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT i.id, i.email, i.role, coalesce(u.email, ''), i.created_at, i.expires_at
			  FROM org_invitations i LEFT JOIN users u ON u.id = i.invited_by
			 ORDER BY i.created_at DESC, i.id LIMIT $1`, MaxInvitations)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i Invitation
			var role string
			if err := rows.Scan(&i.ID, &i.Email, &role, &i.InvitedBy, &i.CreatedAt, &i.ExpiresAt); err != nil {
				return err
			}
			if i.Role, err = tenant.ParseRole(role); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	}, db.ReadOnly())
	return out, wrap("liste des invitations", err)
}

// Invitation renvoie une invitation de l'organisation ; ErrNotFound sinon.
func (s *Service) Invitation(ctx context.Context, org tenant.OrgID, id uuid.UUID) (Invitation, error) {
	var i Invitation
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var role string
		err := tx.QueryRowContext(ctx, `
			SELECT i.id, i.email, i.role, coalesce(u.email, ''), i.created_at, i.expires_at
			  FROM org_invitations i LEFT JOIN users u ON u.id = i.invited_by WHERE i.id = $1`, id).
			Scan(&i.ID, &i.Email, &role, &i.InvitedBy, &i.CreatedAt, &i.ExpiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		i.Role, err = tenant.ParseRole(role)
		return err
	}, db.ReadOnly())
	return i, wrap("lecture d'une invitation", err)
}

// RevokeInvitation révoque une invitation.
func (s *Service) RevokeInvitation(ctx context.Context, actor audit.Actor, org tenant.OrgID, id uuid.UUID) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var email string
		err := tx.QueryRowContext(ctx, `DELETE FROM org_invitations WHERE id = $1 RETURNING email`, id).Scan(&email)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, invitationEvent(audit.InvitationRevoked, email, id, nil))
	})
	return wrap("révocation d'une invitation", err)
}

// PendingInvitations renvoie les invitations en attente du compte userID.
func (s *Service) PendingInvitations(ctx context.Context, userID int64) ([]crossorg.Invitation, error) {
	out, err := crossorg.UserInvitations(ctx, s.pool.DB(), userID)
	return out, wrap("invitations en attente", err)
}

// respond accepte ou décline l'invitation id adressée à userID. L'invitation est d'abord
// retrouvée parmi celles du compte (crossorg), puis vérifiée de nouveau dans InOrg sous
// verrou : adresse du compte, échéance. Toute autre invitation répond KeyInvitationUnknown.
func (s *Service) respond(ctx context.Context, actor audit.Actor, userID int64, id uuid.UUID, accept bool) (tenant.OrgID, error) {
	pending, err := crossorg.UserInvitations(ctx, s.pool.DB(), userID)
	if err != nil {
		return tenant.OrgID{}, err
	}
	var org tenant.OrgID
	for _, p := range pending {
		if p.ID == id {
			org = p.Org
		}
	}
	if org.IsZero() {
		return tenant.OrgID{}, invalid("invitation", KeyInvitationUnknown)
	}
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error { return respondIn(ctx, tx, actor, userID, id, accept) })
	return org, err
}

// AcceptIn accepte, dans tx déclarée pour l'organisation de l'invitation, l'invitation id
// adressée à userID : adresse du compte, échéance vérifiées sous verrou. L'inscription par
// le lien d'une invitation (T28) crée le compte et l'accepte dans la même transaction.
func AcceptIn(ctx context.Context, tx *db.OrgTx, actor audit.Actor, userID int64, id uuid.UUID) error {
	return respondIn(ctx, tx, actor, userID, id, true)
}

func respondIn(ctx context.Context, tx *db.OrgTx, actor audit.Actor, userID int64, id uuid.UUID, accept bool) error {
	var email, role string
	err := tx.QueryRowContext(ctx, `
		SELECT i.email, i.role FROM org_invitations i JOIN users u ON lower(u.email) = i.email
		 WHERE i.id = $1 AND u.id = $2 AND u.is_active = 1 AND i.expires_at > now() FOR UPDATE OF i`, id, userID).Scan(&email, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return invalid("invitation", KeyInvitationUnknown)
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM org_invitations WHERE id = $1`, id); err != nil {
		return err
	}
	if !accept {
		return audit.RecordOrg(ctx, tx, actor, invitationEvent(audit.InvitationDeclined, email, id, nil))
	}
	r, err := tenant.ParseRole(role)
	if err != nil {
		return err
	}
	if err := audit.RecordOrg(ctx, tx, actor, invitationEvent(audit.InvitationAccepted, email, id, map[string]string{"role": role})); err != nil {
		return err
	}
	return addMember(ctx, tx, actor, userID, r)
}

// AcceptInvitation fait de userID un membre de l'organisation qui l'a invité, avec le rôle
// de l'invitation, et renvoie cette organisation.
func (s *Service) AcceptInvitation(ctx context.Context, actor audit.Actor, userID int64, id uuid.UUID) (tenant.OrgID, error) {
	org, err := s.respond(ctx, actor, userID, id, true)
	return org, wrap("acceptation d'une invitation", err)
}

// DeclineInvitation décline (supprime) une invitation adressée à userID.
func (s *Service) DeclineInvitation(ctx context.Context, actor audit.Actor, userID int64, id uuid.UUID) error {
	_, err := s.respond(ctx, actor, userID, id, false)
	return wrap("refus d'une invitation", err)
}
