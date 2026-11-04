package signup

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/token"
)

// CodeStatus est l'état d'un code d'inscription.
type CodeStatus string

// États d'un code.
const (
	CodeActive  CodeStatus = "active"
	CodeUsed    CodeStatus = "used"
	CodeExpired CodeStatus = "expired"
	CodeRevoked CodeStatus = "revoked"
)

// CodeStatuses renvoie les états, pour les tests de traductions.
func CodeStatuses() []CodeStatus { return []CodeStatus{CodeActive, CodeUsed, CodeExpired, CodeRevoked} }

// Code est un code d'inscription, vu des administrateurs d'instance : jamais son secret.
type Code struct {
	ID        uuid.UUID
	Label     string
	Prefix    string // début reconnaissable (lotor_sgn_k7q2xa)
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
	UsedBy    string
	RevokedAt *time.Time
}

// Status renvoie l'état du code à l'instant now.
func (c Code) Status(now time.Time) CodeStatus {
	switch {
	case c.RevokedAt != nil:
		return CodeRevoked
	case c.UsedAt != nil:
		return CodeUsed
	case !now.Before(c.ExpiresAt):
		return CodeExpired
	}
	return CodeActive
}

// SignupPath est le chemin de la page d'inscription.
const SignupPath = "/signup"

func codeEvent(action audit.Action, c Code, details map[string]string) audit.Event {
	return audit.Event{Action: action, TargetType: "signup_code", TargetID: c.ID.String(), TargetLabel: c.Label, Details: details}
}

// CreateCode crée un code d'inscription de libellé label, valable days jours (1 à
// MaxCodeDays), et renvoie son texte, à montrer ou envoyer une seule fois. Réservé au mode
// invitation.
func (s *Service) CreateCode(ctx context.Context, actor audit.Actor, label string, days int) (Code, token.Issued, error) {
	if s.o.Mode != Invitation {
		return Code{}, token.Issued{}, invalid("label", KeyClosed)
	}
	label = strings.TrimSpace(label)
	if label == "" || utf8.RuneCountInString(label) > MaxCodeLabel {
		return Code{}, token.Issued{}, invalid("label", KeyCodeLabel)
	}
	if days < 1 || days > MaxCodeDays {
		return Code{}, token.Issued{}, invalid("days", KeyCodeDays)
	}
	issued, err := token.New(token.SignupCode)
	if err != nil {
		return Code{}, token.Issued{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Code{}, token.Issued{}, err
	}
	var by *int64
	if actor.UserID != 0 {
		by = &actor.UserID
	}
	c := Code{ID: id, Label: label, Prefix: token.DisplayPrefix(token.SignupCode, issued.PublicID), CreatedBy: actor.Email}
	err = s.o.Pool.InTx(ctx, func(tx *db.Tx) error {
		if err := tx.QueryRowContext(ctx, `INSERT INTO signup_codes (id, public_id, secret_hash, label, created_by, expires_at)
			VALUES ($1, $2, $3, $4, $5, now() + $6 * interval '1 day') RETURNING created_at, expires_at`,
			id, issued.PublicID, issued.Hash[:], label, by, days).Scan(&c.CreatedAt, &c.ExpiresAt); err != nil {
			return err
		}
		return audit.RecordInstance(ctx, tx, actor, codeEvent(audit.SignupCodeCreated, c, map[string]string{
			"expires_at": c.ExpiresAt.UTC().Format(time.RFC3339)}))
	})
	if err != nil {
		return Code{}, token.Issued{}, wrap("création d'un code", err)
	}
	return c, issued, nil
}

const codeColumns = `c.id, c.label, c.public_id, coalesce(cb.email, ''), c.created_at, c.expires_at, c.used_at,
	coalesce(ub.email, ''), c.revoked_at`

func scanCode(row interface{ Scan(...any) error }) (Code, error) {
	var c Code
	var publicID string
	var used, revoked sql.NullTime
	if err := row.Scan(&c.ID, &c.Label, &publicID, &c.CreatedBy, &c.CreatedAt, &c.ExpiresAt, &used, &c.UsedBy, &revoked); err != nil {
		return Code{}, err
	}
	c.Prefix = token.DisplayPrefix(token.SignupCode, publicID)
	if used.Valid {
		c.UsedAt = &used.Time
	}
	if revoked.Valid {
		c.RevokedAt = &revoked.Time
	}
	return c, nil
}

// Codes renvoie les codes d'inscription, du plus récent au plus ancien (500 au plus).
func (s *Service) Codes(ctx context.Context) ([]Code, error) {
	var out []Code
	err := s.o.Pool.InTx(ctx, func(tx *db.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+codeColumns+` FROM signup_codes c
			LEFT JOIN users cb ON cb.id = c.created_by LEFT JOIN users ub ON ub.id = c.used_by
			ORDER BY c.created_at DESC, c.id DESC LIMIT $1`, codeList)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanCode(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	}, db.ReadOnly())
	return out, wrap("liste des codes", err)
}

// ErrCodeNotFound : aucun code ne porte cet identifiant.
var ErrCodeNotFound = errors.New("signup: code inconnu")

// CodeByID renvoie le code id ; ErrCodeNotFound sinon.
func (s *Service) CodeByID(ctx context.Context, id uuid.UUID) (Code, error) {
	var c Code
	err := s.o.Pool.InTx(ctx, func(tx *db.Tx) error {
		var err error
		c, err = scanCode(tx.QueryRowContext(ctx, `SELECT `+codeColumns+` FROM signup_codes c
			LEFT JOIN users cb ON cb.id = c.created_by LEFT JOIN users ub ON ub.id = c.used_by WHERE c.id = $1`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCodeNotFound
		}
		return err
	}, db.ReadOnly())
	if errors.Is(err, ErrCodeNotFound) {
		return Code{}, err
	}
	return c, wrap("code", err)
}

// RevokeCode révoque un code encore utilisable ; un code utilisé, expiré ou déjà révoqué
// donne KeyCodeNotRevoked.
func (s *Service) RevokeCode(ctx context.Context, actor audit.Actor, id uuid.UUID) error {
	err := s.o.Pool.InTx(ctx, func(tx *db.Tx) error {
		c, err := scanCode(tx.QueryRowContext(ctx, `SELECT `+codeColumns+` FROM signup_codes c
			LEFT JOIN users cb ON cb.id = c.created_by LEFT JOIN users ub ON ub.id = c.used_by WHERE c.id = $1 FOR UPDATE OF c`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCodeNotFound
		}
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE signup_codes SET revoked_at = now()
			 WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return invalid("code", KeyCodeNotRevoked)
		}
		return audit.RecordInstance(ctx, tx, actor, codeEvent(audit.SignupCodeRevoked, c, nil))
	})
	if errors.Is(err, ErrCodeNotFound) {
		return err
	}
	return wrap("révocation d'un code", err)
}
