//go:build integration

package signup_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/mailer"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/secret"
	"leblanc.io/lotor/internal/signup"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/locales"
)

type fixture struct {
	tdb      *dbtest.DB
	accounts *account.Service
	orgs     *org.Service
	box      *secret.Box
	mail     *mailer.Mailer
	sent     *[]notify.Mail
	sentMu   *sync.Mutex
	handled  map[uuid.UUID]bool
}

type recorder struct {
	mu   *sync.Mutex
	sent *[]notify.Mail
}

func (r recorder) Mail(_ context.Context, m notify.Mail) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	*r.sent = append(*r.sent, m)
	return nil
}

func setup(t *testing.T) *fixture {
	t.Helper()
	tdb := dbtest.New(t)
	box, err := secret.Parse(map[string]string{"k": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}, "k")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := locale.New(locales.FS, ".", "fr")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{tdb: tdb, accounts: account.NewService(tdb.App, 4), orgs: org.NewService(tdb.App), box: box,
		sent: &[]notify.Mail{}, sentMu: &sync.Mutex{}, handled: map[uuid.UUID]bool{}}
	f.mail, err = mailer.New(mailer.Options{Sender: recorder{mu: f.sentMu, sent: f.sent}, Secrets: box, Catalog: cat,
		PublicURL: "https://sbom.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) service(t *testing.T, mode signup.Mode, mail bool, domains ...string) *signup.Service {
	t.Helper()
	s, err := signup.NewService(signup.Options{Pool: f.tdb.App, Accounts: f.accounts, Secrets: f.box, Mode: mode, Mail: mail,
		AllowedDomains: domains})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// deliver envoie les courriels mis en file depuis le dernier appel (job mail.send) et les
// renvoie.
func (f *fixture) deliver(t *testing.T) []notify.Mail {
	t.Helper()
	ctx := context.Background()
	rows, err := f.tdb.Owner(t).QueryContext(ctx, `SELECT id, payload FROM jobs WHERE kind = $1 ORDER BY created_at, id`, mailer.Kind)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	start := len(*f.sent)
	for rows.Next() {
		var id uuid.UUID
		var payload json.RawMessage
		if err := rows.Scan(&id, &payload); err != nil {
			t.Fatal(err)
		}
		if f.handled[id] {
			continue
		}
		f.handled[id] = true
		if err := f.mail.Handler().Handle(ctx, jobs.Execution{ID: id, Kind: mailer.Kind, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	return append([]notify.Mail(nil), (*f.sent)[start:]...)
}

// link extrait le jeton du lien d'un courriel (dernier segment du chemin).
func link(t *testing.T, m notify.Mail) string {
	t.Helper()
	if m.HTML == nil || m.HTML.URL == "" {
		t.Fatalf("courriel sans lien : %+v", m)
	}
	return m.HTML.URL[strings.LastIndex(m.HTML.URL, "/")+1:]
}

func isKey(err error, key string) bool {
	v, ok := account.IsValidation(err)
	return ok && v.Key == key
}

func (f *fixture) userByEmail(t *testing.T, email string) (account.User, bool) {
	t.Helper()
	u, err := f.accounts.GetByEmail(context.Background(), email)
	if err != nil {
		return account.User{}, false
	}
	return u, true
}

func (f *fixture) role(t *testing.T, o tenant.OrgID, userID int64) tenant.Role {
	t.Helper()
	m, err := f.orgs.Member(context.Background(), o, userID)
	if err != nil {
		t.Fatal(err)
	}
	return m.Role
}

var anon = audit.Actor{IP: "192.0.2.1"}

func req(name string) signup.AccountRequest {
	return signup.AccountRequest{OrgName: name, Password: "une phrase de passe solide", Confirm: "une phrase de passe solide",
		Language: "fr"}
}

// TestPublicSignup : l'adresse est vérifiée par un lien à usage unique ; le compte choisit
// son mot de passe et administre l'organisation créée ; la réponse ne dit pas si
// l'adresse a déjà un compte ; un domaine hors liste est refusé.
func TestPublicSignup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	s := f.service(t, signup.Public, true)

	if err := s.Start(ctx, anon, signup.StartRequest{Email: " Alice@Example.org ", Language: "en"}); err != nil {
		t.Fatal(err)
	}
	mails := f.deliver(t)
	if len(mails) != 1 || mails[0].To[0] != "alice@example.org" || mails[0].HTML.Lang != "en" ||
		!strings.HasPrefix(mails[0].HTML.URL, "https://sbom.example.org/signup/verify/lotor_vrf_") {
		t.Fatalf("courriel de vérification %+v", mails)
	}
	if _, ok := f.userByEmail(t, "alice@example.org"); ok {
		t.Fatal("compte créé avant la vérification")
	}
	raw := link(t, mails[0])
	if p, err := s.Verification(ctx, raw); err != nil || p.Email != "alice@example.org" || p.Code {
		t.Fatalf("vérification %+v, %v", p, err)
	}
	i := len(raw) - 20
	alt := byte('a')
	if raw[i] == 'a' {
		alt = 'b'
	}
	if _, err := s.Verification(ctx, raw[:i]+string(alt)+raw[i+1:]); !isKey(err, signup.KeyLinkInvalid) {
		t.Errorf("lien altéré : %v", err)
	}
	if _, err := s.Complete(ctx, anon, raw, signup.AccountRequest{OrgName: "Atelier", Password: "court", Confirm: "court"}); !isKey(err, account.KeyPasswordTooShort) {
		t.Errorf("mot de passe court : %v", err)
	}
	acct, err := s.Complete(ctx, anon, raw, req("Atelier Nord"))
	if err != nil {
		t.Fatal(err)
	}
	if acct.User.Email != "alice@example.org" || acct.User.MustChangePwd || acct.User.Admin || acct.Org.Slug != "atelier-nord" ||
		acct.Org.Name != "Atelier Nord" {
		t.Fatalf("compte %+v", acct)
	}
	if r := f.role(t, acct.Org.ID, acct.User.ID); r != tenant.RoleAdmin {
		t.Errorf("rôle %s, attendu admin", r)
	}
	if teams, err := f.orgs.Teams(ctx, acct.Org.ID, tenant.AllTeams()); err != nil || len(teams) != 1 {
		t.Errorf("équipe par défaut : %+v, %v", teams, err)
	}
	if _, err := s.Complete(ctx, anon, raw, req("Encore")); !isKey(err, signup.KeyLinkInvalid) {
		t.Errorf("lien réutilisé : %v", err)
	}

	// Adresse déjà inscrite : même réponse, courriel « vous avez déjà un compte » ; même
	// nom d'organisation : identifiant suivant.
	if err := s.Start(ctx, anon, signup.StartRequest{Email: "alice@example.org", Language: "fr"}); err != nil {
		t.Fatalf("adresse inscrite : %v", err)
	}
	mails = f.deliver(t)
	if len(mails) != 1 || mails[0].HTML.URL != "https://sbom.example.org/login" || !strings.Contains(mails[0].Subject, "compte") {
		t.Fatalf("courriel « compte existant » %+v", mails)
	}
	if err := s.Start(ctx, anon, signup.StartRequest{Email: "bob@example.org"}); err != nil {
		t.Fatal(err)
	}
	bob, err := s.Complete(ctx, anon, link(t, f.deliver(t)[0]), req("Atelier Nord"))
	if err != nil || bob.Org.Slug != "atelier-nord-2" {
		t.Fatalf("même nom : %+v, %v", bob.Org, err)
	}

	// Une adresse ne reçoit pas plus de MaxVerificationsPerEmail liens par jour.
	for i := 0; i < signup.MaxVerificationsPerEmail+2; i++ {
		if err := s.Start(ctx, anon, signup.StartRequest{Email: "flood@example.org"}); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.deliver(t)); n != signup.MaxVerificationsPerEmail {
		t.Errorf("%d courriels envoyés à la même adresse, %d attendus", n, signup.MaxVerificationsPerEmail)
	}

	// Domaines autorisés.
	restricted := f.service(t, signup.Public, true, "Acme.fr")
	if err := restricted.Start(ctx, anon, signup.StartRequest{Email: "x@example.org"}); !isKey(err, signup.KeyDomain) {
		t.Errorf("domaine hors liste : %v", err)
	}
	if err := restricted.Start(ctx, anon, signup.StartRequest{Email: "x@acme.fr"}); err != nil {
		t.Errorf("domaine autorisé : %v", err)
	}
	if err := restricted.Start(ctx, anon, signup.StartRequest{Email: "x@sub.acme.fr"}); !isKey(err, signup.KeyDomain) {
		t.Errorf("sous-domaine non listé : %v", err)
	}
}

// TestInvitationCodesWithoutMail : sans envoi, l'inscription se fait en une étape ; un code
// ne sert qu'une fois ; une adresse déjà inscrite répond comme un code refusé et ne
// consomme pas le code ; deux inscriptions simultanées n'en créent qu'une.
func TestInvitationCodesWithoutMail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	s := f.service(t, signup.Invitation, false)
	admin := audit.Actor{UserID: 0, Email: "root@example.org"}

	if _, _, err := s.CreateCode(ctx, admin, " ", 30); !isKey(err, signup.KeyCodeLabel) {
		t.Errorf("libellé vide : %v", err)
	}
	if _, _, err := s.CreateCode(ctx, admin, "x", signup.MaxCodeDays+1); !isKey(err, signup.KeyCodeDays) {
		t.Errorf("durée : %v", err)
	}
	code, issued, err := s.CreateCode(ctx, admin, "Équipe Paiement", signup.DefaultCodeDays)
	if err != nil || !strings.HasPrefix(issued.Plaintext, "lotor_sgn_") || code.Status(code.CreatedAt) != signup.CodeActive {
		t.Fatalf("code %+v, %v", code, err)
	}
	if err := s.Start(ctx, anon, signup.StartRequest{Email: "a@example.org", Code: issued.Plaintext}); !isKey(err, signup.KeyClosed) {
		t.Errorf("Start sans envoi : %v", err)
	}
	direct := func(code, email string) error {
		_, err := s.Direct(ctx, anon, signup.DirectRequest{Code: code, Email: email, AccountRequest: req("Paiement")})
		return err
	}
	if err := direct("lotor_sgn_faux", "a@example.org"); !isKey(err, signup.KeyCodeInvalid) {
		t.Errorf("code mal formé : %v", err)
	}
	if err := direct(issued.Plaintext, "a@example.org"); err != nil {
		t.Fatal(err)
	}
	a, ok := f.userByEmail(t, "a@example.org")
	if !ok {
		t.Fatal("compte absent")
	}
	if err := direct(issued.Plaintext, "b@example.org"); !isKey(err, signup.KeyCodeInvalid) {
		t.Errorf("code réutilisé : %v", err)
	}
	if c, err := s.CodeByID(ctx, code.ID); err != nil || c.Status(c.CreatedAt) != signup.CodeUsed || c.UsedBy != a.Email {
		t.Errorf("code utilisé : %+v, %v", c, err)
	}

	// Adresse déjà inscrite : même refus qu'un code invalide, code intact.
	_, fresh, err := s.CreateCode(ctx, admin, "frais", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := direct(fresh.Plaintext, "A@example.org"); !isKey(err, signup.KeyCodeInvalid) {
		t.Errorf("adresse inscrite : %v", err)
	}
	if err := direct(fresh.Plaintext, "c@example.org"); err != nil {
		t.Errorf("code non consommé par le refus : %v", err)
	}

	// Révocation.
	revoked, rawRevoked, err := s.CreateCode(ctx, admin, "révoqué", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeCode(ctx, admin, revoked.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeCode(ctx, admin, revoked.ID); !isKey(err, signup.KeyCodeNotRevoked) {
		t.Errorf("double révocation : %v", err)
	}
	if err := direct(rawRevoked.Plaintext, "d@example.org"); !isKey(err, signup.KeyCodeInvalid) {
		t.Errorf("code révoqué : %v", err)
	}

	// Concurrence : un seul compte pour un code.
	_, race, err := s.CreateCode(ctx, admin, "course", 1)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = direct(race.Plaintext, "race"+string(rune('a'+i))+"@example.org")
		}(i)
	}
	wg.Wait()
	ok1 := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok1++
		case !isKey(err, signup.KeyCodeInvalid):
			t.Errorf("course : %v", err)
		}
	}
	if ok1 != 1 {
		t.Errorf("%d inscriptions avec un même code, 1 attendue", ok1)
	}
	codes, err := s.Codes(ctx)
	if err != nil || len(codes) != 4 {
		t.Errorf("codes %d, %v", len(codes), err)
	}
}

// TestInvitationCodesWithMail : avec envoi, le code est vérifié avant l'envoi du lien et
// consommé à la création du compte ; un échec à la création (code révoqué entre-temps)
// ne laisse ni compte ni organisation, et le lien reste utilisable pour un nouveau code.
func TestInvitationCodesWithMail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	s := f.service(t, signup.Invitation, true)
	admin := audit.Actor{Email: "root@example.org"}
	code, issued, err := s.CreateCode(ctx, admin, "Équipe", 30)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx, anon, signup.StartRequest{Email: "e@example.org", Code: "lotor_sgn_x"}); !isKey(err, signup.KeyCodeInvalid) {
		t.Errorf("code faux : %v", err)
	}
	if err := s.Start(ctx, anon, signup.StartRequest{Email: "e@example.org", Code: issued.Plaintext}); err != nil {
		t.Fatal(err)
	}
	raw := link(t, f.deliver(t)[0])
	if p, err := s.Verification(ctx, raw); err != nil || !p.Code {
		t.Fatalf("vérification sur code : %+v, %v", p, err)
	}
	if _, err := s.Direct(ctx, anon, signup.DirectRequest{Code: issued.Plaintext, Email: "e@example.org", AccountRequest: req("X")}); !isKey(err, signup.KeyClosed) {
		t.Errorf("Direct avec envoi : %v", err)
	}
	// Atomicité : le code révoqué fait échouer la création après l'insertion du compte.
	if err := s.RevokeCode(ctx, admin, code.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Complete(ctx, anon, raw, req("Équipe E")); !isKey(err, signup.KeyCodeInvalid) {
		t.Fatalf("code révoqué avant la fin : %v", err)
	}
	if _, ok := f.userByEmail(t, "e@example.org"); ok {
		t.Fatal("compte créé malgré l'échec")
	}
	var orgs int
	if err := f.tdb.Owner(t).QueryRowContext(ctx, `SELECT count(*) FROM organizations WHERE name = 'Équipe E'`).Scan(&orgs); err != nil || orgs != 0 {
		t.Fatalf("organisation créée malgré l'échec : %d, %v", orgs, err)
	}
	if _, err := s.Verification(ctx, raw); err != nil {
		t.Errorf("lien consommé malgré l'échec : %v", err)
	}
	// Avec un code valide, le parcours complet.
	_, second, err := s.CreateCode(ctx, admin, "second", 30)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx, anon, signup.StartRequest{Email: "e@example.org", Code: second.Plaintext}); err != nil {
		t.Fatal(err)
	}
	acct, err := s.Complete(ctx, anon, link(t, f.deliver(t)[0]), req("Équipe E"))
	if err != nil || acct.Org.Slug != "equipe-e" {
		t.Fatalf("inscription : %+v, %v", acct, err)
	}
	// Les autres liens de l'adresse sont consommés avec celui-ci.
	if _, err := s.Verification(ctx, raw); !isKey(err, signup.KeyLinkInvalid) {
		t.Errorf("ancien lien de la même adresse : %v", err)
	}
}

// TestJoinByLinkInEveryMode : le lien d'une invitation d'organisation crée le compte de
// l'adresse invitée, membre avec le rôle de l'invitation, même en mode privé ; un compte
// existant se connecte puis accepte ; une nouvelle invitation remplace le lien.
func TestJoinByLinkInEveryMode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	s := f.service(t, signup.Private, false)
	owner, _, err := f.accounts.Create(ctx, audit.System, "owner@example.org", false)
	if err != nil {
		t.Fatal(err)
	}
	o, err := f.orgs.Create(ctx, audit.System, "atelier", "Atelier", "fr", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx, anon, signup.StartRequest{Email: "x@example.org"}); !isKey(err, signup.KeyClosed) {
		t.Errorf("mode privé : %v", err)
	}
	ownerActor := audit.Actor{UserID: owner.ID, Email: owner.Email}
	l1, err := f.orgs.InviteWithLink(ctx, ownerActor, o.ID, "New@Example.org", tenant.RoleAdmin, org.InviteMail{})
	if err != nil || !strings.HasPrefix(l1.Token, "lotor_inv_") || l1.Mailed {
		t.Fatalf("invitation %+v, %v", l1, err)
	}
	// Une nouvelle invitation remplace le lien.
	l2, err := f.orgs.InviteWithLink(ctx, ownerActor, o.ID, "new@example.org", tenant.RoleMember, org.InviteMail{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InvitationByLink(ctx, l1.Token); !isKey(err, signup.KeyLinkInvalid) {
		t.Errorf("lien remplacé : %v", err)
	}
	inv, err := s.InvitationByLink(ctx, l2.Token)
	if err != nil || inv.Email != "new@example.org" || inv.OrgName != "Atelier" || inv.Role != tenant.RoleMember {
		t.Fatalf("invitation par le lien : %+v, %v", inv, err)
	}
	if _, _, err := s.JoinByLink(ctx, anon, l2.Token, "une phrase de passe", "autre phrase"); !isKey(err, account.KeyPasswordMismatch) {
		t.Errorf("confirmation : %v", err)
	}
	u, _, err := s.JoinByLink(ctx, anon, l2.Token, "une phrase de passe solide", "une phrase de passe solide")
	if err != nil || u.Email != "new@example.org" || u.MustChangePwd {
		t.Fatalf("compte par le lien : %+v, %v", u, err)
	}
	if r := f.role(t, o.ID, u.ID); r != tenant.RoleMember {
		t.Errorf("rôle %s", r)
	}
	if _, _, err := s.JoinByLink(ctx, anon, l2.Token, "une phrase de passe solide", "une phrase de passe solide"); !isKey(err, signup.KeyLinkInvalid) {
		t.Errorf("lien réutilisé : %v", err)
	}

	// Compte existant : création refusée (il se connecte), puis acceptation par le lien.
	bob, _, err := f.accounts.Create(ctx, audit.System, "bob@example.org", false)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := f.orgs.InviteWithLink(ctx, ownerActor, o.ID, "bob@example.org", tenant.RoleAdmin, org.InviteMail{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.JoinByLink(ctx, anon, lb.Token, "une phrase de passe solide", "une phrase de passe solide"); !isKey(err, signup.KeyAccountExists) {
		t.Errorf("compte existant : %v", err)
	}
	if _, err := s.AcceptByLink(ctx, audit.Actor{UserID: u.ID}, lb.Token, u.ID, u.Email); !isKey(err, signup.KeyOtherAccount) {
		t.Errorf("autre compte : %v", err)
	}
	if _, err := s.AcceptByLink(ctx, audit.Actor{UserID: bob.ID}, lb.Token, bob.ID, bob.Email); err != nil {
		t.Fatal(err)
	}
	if r := f.role(t, o.ID, bob.ID); r != tenant.RoleAdmin {
		t.Errorf("rôle de bob %s", r)
	}

	// Lien expiré : refusé.
	le, err := f.orgs.InviteWithLink(ctx, ownerActor, o.ID, "late@example.org", tenant.RoleMember, org.InviteMail{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.tdb.Owner(t).ExecContext(ctx, `UPDATE org_invitations SET expires_at = now() - interval '1 minute' WHERE email = 'late@example.org'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InvitationByLink(ctx, le.Token); !isKey(err, signup.KeyLinkInvalid) {
		t.Errorf("lien expiré : %v", err)
	}

	// Avec envoi : le lien part par courriel, dans la langue de l'invitant.
	lm, err := f.orgs.InviteWithLink(ctx, ownerActor, o.ID, "mailed@example.org", tenant.RoleMember,
		org.InviteMail{Secrets: f.box, Language: "en", RoleLabel: "member"})
	if err != nil || !lm.Mailed {
		t.Fatalf("invitation envoyée : %+v, %v", lm, err)
	}
	mails := f.deliver(t)
	if len(mails) != 1 || mails[0].HTML.Lang != "en" || mails[0].HTML.Org != "Atelier" ||
		mails[0].HTML.URL != "https://sbom.example.org/invitation/"+lm.Token || !strings.Contains(mails[0].HTML.Intro, "owner@example.org") {
		t.Fatalf("courriel d'invitation %+v", mails)
	}
}

// TestPurgeRemovesExpiredVerifications : la purge horaire supprime les liens expirés.
func TestPurgeRemovesExpiredVerifications(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	s := f.service(t, signup.Public, true)
	for _, e := range []string{"a@example.org", "b@example.org"} {
		if err := s.Start(ctx, anon, signup.StartRequest{Email: e}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.tdb.Owner(t).ExecContext(ctx, `UPDATE signup_verifications SET created_at = now() - interval '2 days',
		expires_at = now() - interval '1 day' WHERE email = 'a@example.org'`); err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeHandler().Handle(ctx, jobs.Execution{}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.tdb.App.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM signup_verifications`).Scan(&n)
	}); err != nil || n != 1 {
		t.Errorf("vérifications restantes %d, %v", n, err)
	}
}
