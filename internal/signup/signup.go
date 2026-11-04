// Package signup porte l'inscription des comptes locaux (T28, ADR 0056) : codes
// d'inscription du mode « invitation », vérification d'une adresse par un lien, création
// atomique du compte et de son organisation, et création d'un compte depuis le lien d'une
// invitation d'organisation.
//
// Trois modes (Mode), réglés par l'exploitant :
//   - Private : aucune inscription libre ; seul le lien d'une invitation d'organisation
//     crée un compte (JoinByLink), rattaché à l'organisation qui invite ;
//   - Invitation : un code d'inscription (CreateCode), à usage unique, crée un compte et
//     une organisation dont il est administrateur. Avec l'envoi de courriels, l'adresse
//     est vérifiée par un lien (Start puis Complete) ; sans lui, tout se fait en une étape
//     (Direct) et l'adresse n'est pas vérifiée ;
//   - Public : inscription libre, dans les domaines autorisés s'il y en a, adresse
//     vérifiée (Start puis Complete), une organisation par compte.
//
// Les réponses ne disent pas si une adresse a déjà un compte : avec l'envoi, Start répond
// toujours de la même façon et le courriel dit « vous avez déjà un compte » ; sans lui,
// Direct répond comme pour un code refusé, sans consommer le code. Un compte, son
// organisation et la consommation du code ou du lien se font dans une seule transaction,
// déclarée pour la nouvelle organisation : tout ou rien.
package signup

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/mailer"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/secret"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/token"
)

// Mode est le mode d'inscription de l'instance.
type Mode string

// Modes d'inscription (signup.mode).
const (
	Private    Mode = "private"
	Invitation Mode = "invitation"
	Public     Mode = "public"
)

// Bornes de l'inscription.
const (
	// VerificationLifetime est la validité d'un lien de vérification.
	VerificationLifetime = 24 * time.Hour
	// MaxVerificationsPerEmail borne les liens envoyés à une même adresse sur
	// VerificationLifetime : au-delà, Start répond pareil sans rien envoyer (un tiers ne
	// peut pas faire inonder une boîte de courriels).
	MaxVerificationsPerEmail = 3
	// DefaultCodeDays et MaxCodeDays bornent la validité d'un code d'inscription, en jours.
	DefaultCodeDays = 30
	MaxCodeDays     = 365
	// MaxCodeLabel borne le libellé d'un code.
	MaxCodeLabel = 100
	// codeList borne la liste des codes affichée.
	codeList = 500
)

// Clés d'erreur traduisibles (validation.* et signup.error.*).
const (
	KeyClosed         = "signup.error.closed"
	KeyCodeInvalid    = "signup.error.code_invalid"
	KeyDomain         = "signup.error.domain"
	KeyLinkInvalid    = "signup.error.link_invalid"
	KeyAccountExists  = "signup.error.account_exists"
	KeyOtherAccount   = "signup.error.other_account"
	KeyCodeLabel      = "validation.signup_code_label"
	KeyCodeDays       = "validation.signup_code_days"
	KeyCodeNotRevoked = "signup.error.code_not_revocable"
)

// ValidationKeys renvoie les clés d'erreur, pour les tests de traductions.
func ValidationKeys() []string {
	return []string{KeyClosed, KeyCodeInvalid, KeyDomain, KeyLinkInvalid, KeyAccountExists, KeyOtherAccount,
		KeyCodeLabel, KeyCodeDays, KeyCodeNotRevoked}
}

func invalid(field, key string) error { return &account.ValidationError{Field: field, Key: key} }

// Options règle le service.
type Options struct {
	Pool     *db.Pool
	Accounts *account.Service
	// Secrets chiffre les liens dans la file des courriels.
	Secrets *secret.Box
	Mode    Mode
	// AllowedDomains restreint le mode public à ces domaines (vide : tous).
	AllowedDomains []string
	// Mail : le serveur envoie des courriels porteurs d'un lien (SMTP et URL publique).
	Mail bool
	// Now remplace l'horloge (tests).
	Now func() time.Time
}

// Service porte l'inscription.
type Service struct {
	o       Options
	domains []string
}

// NewService prépare le service.
func NewService(o Options) (*Service, error) {
	if o.Pool == nil || o.Accounts == nil || o.Secrets == nil {
		return nil, errors.New("signup: base, comptes et clés obligatoires")
	}
	switch o.Mode {
	case Private, Invitation:
	case Public:
		if !o.Mail {
			return nil, errors.New("signup: l'inscription publique exige l'envoi de courriels")
		}
	default:
		return nil, fmt.Errorf("signup: mode %q inconnu", o.Mode)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &Service{o: o}
	for _, d := range o.AllowedDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			s.domains = append(s.domains, d)
		}
	}
	return s, nil
}

// Mode renvoie le mode d'inscription.
func (s *Service) Mode() Mode { return s.o.Mode }

// Mail indique si le serveur envoie les courriels de l'inscription.
func (s *Service) Mail() bool { return s.o.Mail }

// Domains renvoie les domaines autorisés du mode public (vide : tous).
func (s *Service) Domains() []string { return slices.Clone(s.domains) }

// Open indique si l'inscription libre (avec ou sans code) est ouverte.
func (s *Service) Open() bool { return s.o.Mode != Private }

// VerifyPath est le chemin du lien de vérification d'une adresse.
func VerifyPath(raw string) string { return "/signup/verify/" + raw }

func (s *Service) domainAllowed(email string) bool {
	if len(s.domains) == 0 {
		return true
	}
	_, d, _ := strings.Cut(email, "@")
	return slices.Contains(s.domains, d)
}

// StartRequest est la première étape d'une inscription avec vérification de l'adresse.
type StartRequest struct {
	Email string
	Code  string // mode invitation
	// Language est la langue des courriels et de l'organisation à créer.
	Language string
}

// Start vérifie la demande et envoie, si elle est recevable, un lien de vérification à
// l'adresse (ou, si elle a déjà un compte, un courriel qui le dit). La réponse ne dépend
// pas de l'existence d'un compte. Erreurs : KeyClosed (mode privé, ou pas d'envoi),
// adresse invalide, KeyDomain (mode public), KeyCodeInvalid (mode invitation).
func (s *Service) Start(ctx context.Context, actor audit.Actor, r StartRequest) error {
	if !s.Open() || !s.o.Mail {
		return invalid("email", KeyClosed)
	}
	email, err := account.NormalizeEmail(r.Email)
	if err != nil {
		return err
	}
	var codeHash token.SecretHash
	var codePublic string
	if s.o.Mode == Invitation {
		if codePublic, codeHash, err = token.Parse(token.SignupCode, strings.TrimSpace(r.Code)); err != nil {
			return invalid("code", KeyCodeInvalid)
		}
	} else if !s.domainAllowed(email) {
		return invalid("email", KeyDomain)
	}
	issued, err := token.New(token.Verification)
	if err != nil {
		return err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	err = s.o.Pool.InTx(ctx, func(tx *db.Tx) error {
		var codeID *uuid.UUID
		if s.o.Mode == Invitation {
			c, err := activeCode(ctx, tx, codePublic, codeHash, false)
			if err != nil {
				return err
			}
			codeID = &c
		}
		var recent int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM signup_verifications WHERE email = $1 AND created_at > now() - $2 * interval '1 second'`,
			email, int64(VerificationLifetime/time.Second)).Scan(&recent); err != nil {
			return err
		}
		if recent >= MaxVerificationsPerEmail {
			return nil // même réponse, rien de plus n'est envoyé
		}
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = $1)`, email).Scan(&exists); err != nil {
			return err
		}
		// La vérification est enregistrée dans les deux cas : elle compte pour la borne par
		// adresse, et le lien d'une adresse déjà inscrite n'est jamais envoyé.
		if _, err := tx.ExecContext(ctx, `INSERT INTO signup_verifications (id, public_id, secret_hash, email, code_id, expires_at)
			VALUES ($1, $2, $3, $4, $5, now() + $6 * interval '1 second')`, id, issued.PublicID, issued.Hash[:], email, codeID,
			int64(VerificationLifetime/time.Second)); err != nil {
			return err
		}
		msg := mailer.Message{To: email, Language: r.Language, Template: mailer.SignupVerify, Path: VerifyPath(issued.Plaintext)}
		if exists {
			msg = mailer.Message{To: email, Language: r.Language, Template: mailer.SignupExisting, Path: "/login"}
		}
		if err := mailer.Enqueue(ctx, tx, s.o.Secrets, msg); err != nil {
			return err
		}
		return audit.RecordInstance(ctx, tx, actor, audit.Event{Action: audit.SignupRequested, TargetType: "account",
			TargetLabel: email, Details: map[string]string{"mode": string(s.o.Mode)}})
	})
	return wrap("demande d'inscription", err)
}

// activeCode retrouve un code d'inscription utilisable (ni utilisé, ni révoqué, ni
// expiré) et compare son secret ; consume le marque utilisé (sous verrou de la ligne).
// Tout refus donne KeyCodeInvalid, sans dire pourquoi.
func activeCode(ctx context.Context, q db.Querier, publicID string, hash token.SecretHash, lock bool) (uuid.UUID, error) {
	lockClause := " FOR SHARE"
	if lock {
		lockClause = " FOR UPDATE"
	}
	var id uuid.UUID
	var stored []byte
	err := q.QueryRowContext(ctx, `SELECT id, secret_hash FROM signup_codes
		 WHERE public_id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()`+lockClause, publicID).Scan(&id, &stored)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !hash.Matches(stored)) {
		return uuid.Nil, invalid("code", KeyCodeInvalid)
	}
	return id, err
}

func consumeCode(ctx context.Context, q db.Querier, id uuid.UUID, userID int64) error {
	res, err := q.ExecContext(ctx, `UPDATE signup_codes SET used_at = now(), used_by = $2
		 WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return invalid("code", KeyCodeInvalid)
	}
	return nil
}

// Pending est une vérification d'adresse en attente, vue par qui présente son lien.
type Pending struct {
	Email string
	Code  bool // inscription sur code (mode invitation)
}

type verification struct {
	id     uuid.UUID
	email  string
	codeID *uuid.UUID
}

// findVerification retrouve la vérification non expirée du lien raw ; KeyLinkInvalid sinon.
func findVerification(ctx context.Context, q db.Querier, raw string, lock bool) (verification, error) {
	publicID, hash, err := token.Parse(token.Verification, raw)
	if err != nil {
		return verification{}, invalid("link", KeyLinkInvalid)
	}
	lockClause := ""
	if lock {
		lockClause = " FOR UPDATE"
	}
	var v verification
	var stored []byte
	err = q.QueryRowContext(ctx, `SELECT id, email, code_id, secret_hash FROM signup_verifications
		 WHERE public_id = $1 AND expires_at > now()`+lockClause, publicID).Scan(&v.id, &v.email, &v.codeID, &stored)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !hash.Matches(stored)) {
		return verification{}, invalid("link", KeyLinkInvalid)
	}
	return v, err
}

// Verification renvoie la vérification en attente du lien raw ; KeyLinkInvalid si le lien
// est inconnu, expiré ou déjà utilisé.
func (s *Service) Verification(ctx context.Context, raw string) (Pending, error) {
	if !s.Open() {
		return Pending{}, invalid("link", KeyLinkInvalid)
	}
	var v verification
	err := s.o.Pool.InTx(ctx, func(tx *db.Tx) error {
		var err error
		v, err = findVerification(ctx, tx, raw, false)
		return err
	}, db.ReadOnly())
	if err != nil {
		return Pending{}, wrap("lien de vérification", err)
	}
	return Pending{Email: v.email, Code: v.codeID != nil}, nil
}

// Account est le compte et l'organisation créés par une inscription.
type Account struct {
	User account.User
	Org  org.Organization
}

// AccountRequest complète une inscription : organisation et mot de passe choisis.
type AccountRequest struct {
	OrgName  string
	Password string
	Confirm  string
	Language string
}

// Complete termine l'inscription du lien de vérification raw : dans une seule transaction,
// le lien est consommé (avec les autres liens de la même adresse), le code éventuel aussi,
// puis le compte et son organisation sont créés, le compte en est administrateur. Une
// adresse inscrite entre-temps donne KeyAccountExists (le titulaire du lien prouve qu'il
// possède l'adresse).
func (s *Service) Complete(ctx context.Context, actor audit.Actor, raw string, r AccountRequest) (Account, error) {
	pending, err := s.Verification(ctx, raw)
	if err != nil {
		return Account{}, err
	}
	reg, err := s.prepare(pending.Email, r)
	if err != nil {
		return Account{}, err
	}
	out, err := s.createWithOrg(ctx, actor, reg, r, func(tx *db.OrgTx, userID int64) error {
		v, err := findVerification(ctx, tx, raw, true)
		if err != nil {
			return err
		}
		if v.email != reg.Email {
			return invalid("link", KeyLinkInvalid)
		}
		if v.codeID != nil {
			if err := consumeCode(ctx, tx, *v.codeID, userID); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM signup_verifications WHERE email = $1`, v.email)
		return err
	}, KeyAccountExists, "verified")
	return out, wrap("inscription", err)
}

// DirectRequest est une inscription sur code sans vérification de l'adresse (mode
// invitation, sans envoi de courriels).
type DirectRequest struct {
	Code  string
	Email string
	AccountRequest
}

// Direct inscrit en une étape, sur code, sans vérifier l'adresse (mode invitation sans
// envoi). Une adresse déjà inscrite répond comme un code refusé (KeyCodeInvalid), et le
// code n'est pas consommé : seul le porteur d'un code valide apprend qu'une adresse a un
// compte.
func (s *Service) Direct(ctx context.Context, actor audit.Actor, r DirectRequest) (Account, error) {
	if s.o.Mode != Invitation || s.o.Mail {
		return Account{}, invalid("code", KeyClosed)
	}
	publicID, hash, err := token.Parse(token.SignupCode, strings.TrimSpace(r.Code))
	if err != nil {
		return Account{}, invalid("code", KeyCodeInvalid)
	}
	reg, err := s.prepare(r.Email, r.AccountRequest)
	if err != nil {
		return Account{}, err
	}
	out, err := s.createWithOrg(ctx, actor, reg, r.AccountRequest, func(tx *db.OrgTx, userID int64) error {
		id, err := activeCode(ctx, tx, publicID, hash, true)
		if err != nil {
			return err
		}
		return consumeCode(ctx, tx, id, userID)
	}, KeyCodeInvalid, "code")
	return out, wrap("inscription", err)
}

// prepare vérifie l'adresse, le mot de passe et le nom de l'organisation, hors
// transaction.
func (s *Service) prepare(email string, r AccountRequest) (account.Registration, error) {
	if name := strings.TrimSpace(r.OrgName); name == "" || utf8.RuneCountInString(name) > 100 {
		return account.Registration{}, invalid("org_name", org.KeyNameInvalid)
	}
	return s.o.Accounts.PrepareRegistration(email, r.Password, r.Confirm)
}

// createWithOrg crée, dans une transaction déclarée pour une nouvelle organisation, le
// compte reg, puis appelle consume (consommation du lien ou du code, qui peut refuser),
// puis l'organisation. Une adresse déjà prise devient takenKey.
func (s *Service) createWithOrg(ctx context.Context, actor audit.Actor, reg account.Registration, r AccountRequest,
	consume func(*db.OrgTx, int64) error, takenKey, via string) (Account, error) {
	orgID, err := tenant.NewOrgID()
	if err != nil {
		return Account{}, err
	}
	slugs := slugCandidates(r.OrgName)
	var out Account
	err = s.o.Pool.InOrg(ctx, orgID, func(tx *db.OrgTx) error {
		u, err := account.Register(ctx, &tx.Tx, actor, reg, map[string]string{"mode": string(s.o.Mode), "via": via})
		if v, ok := account.IsValidation(err); ok && v.Key == account.KeyEmailTaken {
			return invalid("email", takenKey)
		}
		if err != nil {
			return err
		}
		if err := consume(tx, u.ID); err != nil {
			return err
		}
		self := actor
		self.UserID, self.Email = u.ID, u.Email
		o, err := org.CreateIn(ctx, tx, self, slugs, r.OrgName, orgLanguage(r.Language), u.ID)
		if err != nil {
			return err
		}
		out = Account{User: u, Org: o}
		return nil
	})
	return out, err
}

// orgLanguage ramène la langue de la page à une langue d'organisation.
func orgLanguage(lang string) string {
	if slices.Contains(account.Languages, lang) {
		return lang
	}
	return account.Languages[0]
}

var slugSuffix = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// slugCandidates dérive du nom les identifiants d'URL essayés dans l'ordre : le nom, puis
// numéroté, puis suivi d'un suffixe tiré au hasard.
func slugCandidates(name string) []string {
	base := project.Slugify(name)
	if base == "project" && !strings.Contains(strings.ToLower(name), "project") {
		base = "org"
	}
	if len(base) > 40 {
		base = strings.TrimRight(base[:40], "-")
	}
	out := []string{base}
	for i := 2; i <= 9; i++ {
		out = append(out, base+"-"+strconv.Itoa(i))
	}
	buf := make([]byte, 5)
	if _, err := rand.Read(buf); err == nil {
		out = append(out, base+"-"+slugSuffix.EncodeToString(buf))
	}
	return out
}

// LinkInvitation est l'invitation d'organisation vue par qui présente son lien.
type LinkInvitation struct {
	Org       tenant.OrgID
	ID        uuid.UUID
	OrgName   string
	OrgSlug   string
	Language  string
	Email     string
	Role      tenant.Role
	ExpiresAt time.Time
}

// InvitationByLink renvoie l'invitation du lien raw ; KeyLinkInvalid si le lien est
// inconnu, expiré, remplacé ou déjà utilisé. Ouvert dans tous les modes.
func (s *Service) InvitationByLink(ctx context.Context, raw string) (LinkInvitation, error) {
	publicID, hash, err := token.Parse(token.Invitation, raw)
	if err != nil {
		return LinkInvitation{}, invalid("link", KeyLinkInvalid)
	}
	i, err := crossorg.InvitationByToken(ctx, s.o.Pool.DB(), publicID)
	if errors.Is(err, crossorg.ErrNotFound) || (err == nil && !hash.Matches(i.SecretHash)) {
		return LinkInvitation{}, invalid("link", KeyLinkInvalid)
	}
	if err != nil {
		return LinkInvitation{}, err
	}
	return LinkInvitation{Org: i.Org, ID: i.ID, OrgName: i.Name, OrgSlug: i.Slug, Language: i.Language, Email: i.Email,
		Role: i.Role, ExpiresAt: i.ExpiresAt}, nil
}

// lockInvitation vérifie de nouveau, sous verrou et dans l'organisation, que le lien raw
// désigne toujours l'invitation inv.
func lockInvitation(ctx context.Context, tx *db.OrgTx, raw string, inv LinkInvitation) error {
	publicID, hash, err := token.Parse(token.Invitation, raw)
	if err != nil {
		return invalid("link", KeyLinkInvalid)
	}
	var stored []byte
	err = tx.QueryRowContext(ctx, `SELECT secret_hash FROM org_invitations
		 WHERE id = $1 AND public_id = $2 AND expires_at > now() FOR UPDATE`, inv.ID, publicID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !hash.Matches(stored)) {
		return invalid("link", KeyLinkInvalid)
	}
	return err
}

// JoinByLink crée, depuis le lien raw d'une invitation d'organisation, le compte de
// l'adresse invitée avec le mot de passe choisi et l'ajoute à l'organisation avec le rôle
// de l'invitation, dans une seule transaction de l'organisation qui invite. Une adresse
// qui a déjà un compte donne KeyAccountExists : la personne se connecte puis accepte.
func (s *Service) JoinByLink(ctx context.Context, actor audit.Actor, raw, password, confirm string) (account.User, LinkInvitation, error) {
	inv, err := s.InvitationByLink(ctx, raw)
	if err != nil {
		return account.User{}, LinkInvitation{}, err
	}
	reg, err := s.o.Accounts.PrepareRegistration(inv.Email, password, confirm)
	if err != nil {
		return account.User{}, LinkInvitation{}, err
	}
	var u account.User
	err = s.o.Pool.InOrg(ctx, inv.Org, func(tx *db.OrgTx) error {
		if err := lockInvitation(ctx, tx, raw, inv); err != nil {
			return err
		}
		var err error
		u, err = account.Register(ctx, &tx.Tx, actor, reg, map[string]string{"mode": string(s.o.Mode), "via": "invitation"})
		if v, ok := account.IsValidation(err); ok && v.Key == account.KeyEmailTaken {
			return invalid("email", KeyAccountExists)
		}
		if err != nil {
			return err
		}
		self := actor
		self.UserID, self.Email = u.ID, u.Email
		return org.AcceptIn(ctx, tx, self, u.ID, inv.ID)
	})
	return u, inv, wrap("inscription par invitation", err)
}

// AcceptByLink fait accepter au compte connecté userID, d'adresse email, l'invitation du
// lien raw ; une invitation adressée à une autre adresse donne KeyOtherAccount.
func (s *Service) AcceptByLink(ctx context.Context, actor audit.Actor, raw string, userID int64, email string) (LinkInvitation, error) {
	inv, err := s.InvitationByLink(ctx, raw)
	if err != nil {
		return LinkInvitation{}, err
	}
	if !strings.EqualFold(inv.Email, email) {
		return LinkInvitation{}, invalid("link", KeyOtherAccount)
	}
	err = s.o.Pool.InOrg(ctx, inv.Org, func(tx *db.OrgTx) error {
		if err := lockInvitation(ctx, tx, raw, inv); err != nil {
			return err
		}
		return org.AcceptIn(ctx, tx, actor, userID, inv.ID)
	})
	return inv, wrap("acceptation par le lien", err)
}

// PurgeKind est le job qui supprime les vérifications d'adresse expirées.
const PurgeKind = "signup.purge"

// PurgeSchedule passe toutes les heures.
func PurgeSchedule() jobs.Schedule {
	return jobs.Schedule{Name: PurgeKind, Every: time.Hour, Job: jobs.Job{Kind: PurgeKind}}
}

// PurgeHandler supprime les vérifications expirées ; idempotent.
func (s *Service) PurgeHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, _ jobs.Execution) error {
		return wrap("purge des vérifications", s.o.Pool.InTx(ctx, func(tx *db.Tx) error {
			_, err := tx.ExecContext(ctx, `DELETE FROM signup_verifications WHERE expires_at < now()`)
			return err
		}))
	})
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := account.IsValidation(err); ok {
		return err
	}
	return fmt.Errorf("signup: %s : %w", what, err)
}
