package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"leblanc.io/open-go-base/authx"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/pagination"
)

// RoleAdmin est le rôle d'instance (colonne role d'authx) de l'administrateur d'instance.
// Un compte ordinaire a un rôle vide.
const RoleAdmin authx.Role = "admin"

var (
	// ErrNotFound : compte inconnu.
	ErrNotFound = errors.New("account: compte inconnu")
)

// User est un compte tel que l'administration le présente.
type User struct {
	ID            int64
	Email         string
	Admin         bool
	Active        bool
	MustChangePwd bool
	TOTPEnabled   bool
	CreatedAt     time.Time
	LastLogin     *time.Time
}

// Service crée et modifie les comptes. C'est le seul écrivain de la table users d'authx ;
// chaque modification est journalisée dans la même transaction.
type Service struct {
	pool       *db.Pool
	bcryptCost int
}

// NewService construit le service. bcryptCost est celui d'appconf.Auth.
func NewService(pool *db.Pool, bcryptCost int) *Service {
	return &Service{pool: pool, bcryptCost: bcryptCost}
}

const userColumns = `u.id, u.email, u.role, u.is_active, u.must_change_pwd, u.created_at, u.last_login,
	coalesce(t.enabled, 0)`

const userFrom = ` FROM users u LEFT JOIN mfa_totp t ON t.user_id = u.id`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var role string
	var active, mustChange, totp int
	var last sql.NullTime
	if err := row.Scan(&u.ID, &u.Email, &role, &active, &mustChange, &u.CreatedAt, &last, &totp); err != nil {
		return User{}, err
	}
	u.Admin = authx.Role(role) == RoleAdmin
	u.Active, u.MustChangePwd, u.TOTPEnabled = active == 1, mustChange == 1, totp == 1
	if last.Valid {
		t := last.Time
		u.LastLogin = &t
	}
	return u, nil
}

func getUser(ctx context.Context, q db.Querier, id int64, lock bool) (User, error) {
	query := `SELECT ` + userColumns + userFrom + ` WHERE u.id = $1`
	if lock {
		query += ` FOR UPDATE OF u`
	}
	u, err := scanUser(q.QueryRowContext(ctx, query, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("account: lecture du compte %d : %w", id, err)
	}
	return u, nil
}

// Get renvoie un compte.
func (s *Service) Get(ctx context.Context, id int64) (User, error) {
	var u User
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		var err error
		u, err = getUser(ctx, tx, id, false)
		return err
	}, db.ReadOnly())
	return u, err
}

// GetByEmail renvoie le compte d'un e-mail (forme normalisée).
func (s *Service) GetByEmail(ctx context.Context, email string) (User, error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return User{}, ErrNotFound
	}
	var u User
	err = s.pool.InTx(ctx, func(tx *db.Tx) error {
		var err error
		u, err = scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+userFrom+` WHERE u.email = $1`, e))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}, db.ReadOnly())
	return u, err
}

// DefaultPage et MaxPage bornent une page de comptes.
const (
	DefaultPage = 50
	MaxPage     = 200
)

// List renvoie une page de comptes par e-mail croissant.
func (s *Service) List(ctx context.Context, cursor string, limit int) (pagination.Page[User], error) {
	if limit < 1 || limit > MaxPage {
		return pagination.Page[User]{}, &pagination.LimitError{Max: MaxPage}
	}
	var after string
	if cursor != "" {
		if err := pagination.Decode(cursor, &after); err != nil {
			return pagination.Page[User]{}, err
		}
	}
	var page pagination.Page[User]
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT `+userColumns+userFrom+` WHERE u.email > $1 ORDER BY u.email LIMIT $2`, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		var out []User
		for rows.Next() {
			u, err := scanUser(rows)
			if err != nil {
				return err
			}
			out = append(out, u)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		page, err = pagination.Build(out, limit, func(u User) any { return u.Email })
		return err
	}, db.ReadOnly())
	if err != nil {
		return pagination.Page[User]{}, fmt.Errorf("account: liste des comptes : %w", err)
	}
	return page, nil
}

// ActiveAdmins compte les administrateurs d'instance actifs.
func (s *Service) ActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT count(*) FROM users WHERE role = $1 AND is_active = 1`, string(RoleAdmin)).Scan(&n)
	}, db.ReadOnly())
	if err != nil {
		return 0, fmt.Errorf("account: décompte des administrateurs : %w", err)
	}
	return n, nil
}

func target(u User) audit.Event {
	return audit.Event{TargetType: "account", TargetID: strconv.FormatInt(u.ID, 10), TargetLabel: u.Email}
}

func event(action audit.Action, u User, details map[string]string) audit.Event {
	e := target(u)
	e.Action = action
	e.Details = details
	return e
}

// Create crée un compte avec un mot de passe temporaire, à changer à la première connexion
// (must_change_pwd), et renvoie ce mot de passe, à transmettre une fois au titulaire.
func (s *Service) Create(ctx context.Context, actor audit.Actor, email string, admin bool) (User, string, error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return User{}, "", err
	}
	password := GeneratePassword()
	u, err := s.create(ctx, actor, e, password, admin, audit.AccountCreated)
	return u, password, err
}

func (s *Service) create(ctx context.Context, actor audit.Actor, email, password string, admin bool, action audit.Action) (User, error) {
	if err := ValidatePassword(password, email); err != nil {
		return User{}, err
	}
	hash, err := authx.HashPassword(password, s.bcryptCost)
	if err != nil {
		return User{}, fmt.Errorf("account: hachage : %w", err)
	}
	var u User
	err = s.pool.InTx(ctx, func(tx *db.Tx) error {
		var err error
		u, err = insertUser(ctx, tx, actor, email, hash, admin, true, action, map[string]string{"admin": strconv.FormatBool(admin)})
		return err
	})
	if err != nil {
		if _, ok := IsValidation(err); ok {
			return User{}, err
		}
		return User{}, fmt.Errorf("account: création de %s : %w", email, err)
	}
	return u, nil
}

// insertUser crée le compte dans tx et journalise action ; une adresse déjà prise donne
// KeyEmailTaken. mustChange impose le changement de mot de passe à la première connexion
// (mot de passe temporaire).
func insertUser(ctx context.Context, tx *db.Tx, actor audit.Actor, email, hash string, admin, mustChange bool,
	action audit.Action, details map[string]string) (User, error) {
	role := ""
	if admin {
		role = string(RoleAdmin)
	}
	change := 0
	if mustChange {
		change = 1
	}
	var id int64
	err := tx.QueryRowContext(ctx,
		`INSERT INTO users (email, password_hash, role, must_change_pwd) VALUES ($1, $2, $3, $4) RETURNING id`,
		email, hash, role, change).Scan(&id)
	if isUniqueViolation(err) {
		return User{}, &ValidationError{Field: "email", Key: KeyEmailTaken}
	}
	if err != nil {
		return User{}, err
	}
	u, err := getUser(ctx, tx, id, false)
	if err != nil {
		return User{}, err
	}
	return u, audit.RecordInstance(ctx, tx, actor, event(action, u, details))
}

// Registration est un compte à créer par son titulaire (inscription, T28) : adresse
// normalisée, mot de passe choisi et déjà haché.
type Registration struct {
	Email string
	hash  string
}

// PrepareRegistration vérifie l'adresse et le mot de passe choisi (politique, confirmation)
// et hache ce dernier, hors de toute transaction : le hachage bcrypt est lent.
func (s *Service) PrepareRegistration(email, password, confirm string) (Registration, error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return Registration{}, err
	}
	if password != confirm {
		return Registration{}, &ValidationError{Field: "confirm", Key: KeyPasswordMismatch}
	}
	if err := ValidatePassword(password, e); err != nil {
		return Registration{}, err
	}
	hash, err := authx.HashPassword(password, s.bcryptCost)
	if err != nil {
		return Registration{}, fmt.Errorf("account: hachage : %w", err)
	}
	return Registration{Email: e, hash: hash}, nil
}

// Register crée dans tx le compte r, sans mot de passe temporaire (le titulaire l'a
// choisi) et sans rôle d'instance, et journalise AccountSignedUp avec details. L'appelant
// fait de la même transaction la création de l'organisation ou l'adhésion (T28).
func Register(ctx context.Context, tx *db.Tx, actor audit.Actor, r Registration, details map[string]string) (User, error) {
	if r.Email == "" || len(r.hash) == 0 {
		return User{}, errors.New("account: inscription non préparée")
	}
	return insertUser(ctx, tx, actor, r.Email, r.hash, false, false, audit.AccountSignedUp, details)
}

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// update charge le compte id sous verrou, applique change dans la transaction puis
// journalise l'événement qu'il renvoie.
func (s *Service) update(ctx context.Context, actor audit.Actor, id int64, change func(*db.Tx, User) (audit.Event, error)) error {
	return s.pool.InTx(ctx, func(tx *db.Tx) error {
		u, err := getUser(ctx, tx, id, true)
		if err != nil {
			return err
		}
		ev, err := change(tx, u)
		if err != nil {
			return err
		}
		return audit.RecordInstance(ctx, tx, actor, ev)
	})
}

// lastAdminGuard refuse de retirer le dernier administrateur d'instance actif.
func lastAdminGuard(ctx context.Context, tx *db.Tx, u User) error {
	if !u.Admin || !u.Active {
		return nil
	}
	var others int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM users WHERE role = $1 AND is_active = 1 AND id <> $2`, string(RoleAdmin), u.ID,
	).Scan(&others); err != nil {
		return err
	}
	if others == 0 {
		return &ValidationError{Field: "account", Key: KeyLastAdmin}
	}
	return nil
}

func deleteSessions(ctx context.Context, tx *db.Tx, userID int64, keepToken string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token <> $2`, userID, keepToken)
	return err
}

// SetActive active ou désactive un compte ; la désactivation ferme ses sessions. Le
// dernier administrateur d'instance actif ne peut pas être désactivé.
func (s *Service) SetActive(ctx context.Context, actor audit.Actor, id int64, active bool) error {
	return s.update(ctx, actor, id, func(tx *db.Tx, u User) (audit.Event, error) {
		if !active {
			if actor.UserID == u.ID {
				return audit.Event{}, &ValidationError{Field: "account", Key: KeyCannotTargetSelf}
			}
			if err := lastAdminGuard(ctx, tx, u); err != nil {
				return audit.Event{}, err
			}
			if err := deleteSessions(ctx, tx, u.ID, ""); err != nil {
				return audit.Event{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET is_active = $1 WHERE id = $2`, boolInt(active), u.ID); err != nil {
			return audit.Event{}, err
		}
		action := audit.AccountActivated
		if !active {
			action = audit.AccountDeactivated
		}
		return event(action, u, nil), nil
	})
}

// SetAdmin promeut un compte administrateur d'instance ou lui retire ce rôle ; le dernier
// administrateur actif le garde.
func (s *Service) SetAdmin(ctx context.Context, actor audit.Actor, id int64, admin bool) error {
	return s.update(ctx, actor, id, func(tx *db.Tx, u User) (audit.Event, error) {
		if !admin {
			if err := lastAdminGuard(ctx, tx, u); err != nil {
				return audit.Event{}, err
			}
		}
		role := ""
		if admin {
			role = string(RoleAdmin)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET role = $1 WHERE id = $2`, role, u.ID); err != nil {
			return audit.Event{}, err
		}
		return event(audit.AccountRoleChanged, u, map[string]string{"admin": strconv.FormatBool(admin)}), nil
	})
}

// Raisons de révocation d'office des jetons personnels, notées au journal d'audit.
const (
	revokedPasswordReset   = "password_reset"
	revokedTOTPReset       = "totp_reset"
	revokedPasswordChanged = "password_changed"
)

// ResetPassword remplace le mot de passe d'un compte par un mot de passe temporaire (à
// changer à la connexion suivante), ferme ses sessions, révoque ses jetons personnels et
// renvoie le mot de passe. La réinitialisation est un geste de remédiation : rien de ce
// qu'une session volée a pu obtenir ne doit lui survivre.
func (s *Service) ResetPassword(ctx context.Context, actor audit.Actor, id int64) (string, error) {
	return s.resetCredentials(ctx, actor, id, false)
}

// ResetTOTP retire le second facteur d'un compte et, comme ResetPassword, lui impose un
// mot de passe temporaire, ferme ses sessions et révoque ses jetons personnels ; il
// renvoie le mot de passe. Sans nouveau mot de passe, quiconque connaît l'ancien
// enrôlerait son propre TOTP avant le titulaire (ADR 0029).
func (s *Service) ResetTOTP(ctx context.Context, actor audit.Actor, id int64) (string, error) {
	return s.resetCredentials(ctx, actor, id, true)
}

func (s *Service) resetCredentials(ctx context.Context, actor audit.Actor, id int64, totp bool) (string, error) {
	password := GeneratePassword()
	hash, err := authx.HashPassword(password, s.bcryptCost)
	if err != nil {
		return "", fmt.Errorf("account: hachage : %w", err)
	}
	err = s.update(ctx, actor, id, func(tx *db.Tx, u User) (audit.Event, error) {
		if err := setTemporaryPassword(ctx, tx, u.ID, hash); err != nil {
			return audit.Event{}, err
		}
		if totp {
			if err := resetTOTP(ctx, tx, actor, u.ID); err != nil {
				return audit.Event{}, err
			}
			return event(audit.AccountTOTPReset, u, nil), nil
		}
		if err := deleteSessions(ctx, tx, u.ID, ""); err != nil {
			return audit.Event{}, err
		}
		if err := revokePersonalTokens(ctx, tx, actor, u.ID, revokedPasswordReset); err != nil {
			return audit.Event{}, err
		}
		return event(audit.AccountPasswordReset, u, nil), nil
	})
	if err != nil {
		return "", err
	}
	return password, nil
}

func setTemporaryPassword(ctx context.Context, tx *db.Tx, userID int64, hash string) error {
	_, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = $1, must_change_pwd = 1 WHERE id = $2`, hash, userID)
	return err
}

// resetTOTP retire le second facteur de userID (secret, défis, verrouillage, codes de secours), ferme ses
// sessions et révoque ses jetons personnels. L'appelant impose aussi un nouveau mot de
// passe.
func resetTOTP(ctx context.Context, tx *db.Tx, actor audit.Actor, userID int64) error {
	for _, q := range []string{
		`DELETE FROM mfa_totp WHERE user_id = $1`,
		`DELETE FROM mfa_challenges WHERE user_id = $1`,
		`DELETE FROM mfa_lockouts WHERE user_id = $1`,
		`DELETE FROM mfa_recovery_codes WHERE user_id = $1`,
	} {
		if _, err := tx.ExecContext(ctx, q, userID); err != nil {
			return err
		}
	}
	if err := deleteSessions(ctx, tx, userID, ""); err != nil {
		return err
	}
	return revokePersonalTokens(ctx, tx, actor, userID, revokedTOTPReset)
}

// ChangePassword change le mot de passe d'un compte après vérification de l'actuel, lève
// must_change_pwd et ferme ses autres sessions (keepToken est le jeton de la session
// courante, conservée). revokeTokens révoque aussi ses jetons personnels (choix proposé
// coché : changer de mot de passe après une compromission doit tout couper).
func (s *Service) ChangePassword(ctx context.Context, actor audit.Actor, id int64, current, next, confirm, keepToken string, revokeTokens bool) error {
	if next != confirm {
		return &ValidationError{Field: "confirm", Key: KeyPasswordMismatch}
	}
	var hash, email string
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT password_hash, email FROM users WHERE id = $1`, id).Scan(&hash, &email)
	}, db.ReadOnly())
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("account: lecture du compte %d : %w", id, err)
	}
	if err := authx.CheckPassword(hash, current); err != nil {
		if errors.Is(err, authx.ErrInvalidCredentials) {
			return &ValidationError{Field: "current", Key: KeyPasswordWrong}
		}
		return fmt.Errorf("account: vérification du mot de passe : %w", err)
	}
	if err := ValidatePassword(next, email); err != nil {
		return err
	}
	if next == current {
		return &ValidationError{Field: "password", Key: KeyPasswordUnchanged}
	}
	newHash, err := authx.HashPassword(next, s.bcryptCost)
	if err != nil {
		return fmt.Errorf("account: hachage : %w", err)
	}
	return s.update(ctx, actor, id, func(tx *db.Tx, u User) (audit.Event, error) {
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET password_hash = $1, must_change_pwd = 0 WHERE id = $2`, newHash, u.ID); err != nil {
			return audit.Event{}, err
		}
		if err := deleteSessions(ctx, tx, u.ID, keepToken); err != nil {
			return audit.Event{}, err
		}
		if revokeTokens {
			if err := revokePersonalTokens(ctx, tx, actor, u.ID, revokedPasswordChanged); err != nil {
				return audit.Event{}, err
			}
		}
		return event(audit.AccountPasswordChanged, u, nil), nil
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
