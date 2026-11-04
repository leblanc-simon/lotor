//go:build integration

package web

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/mailer"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/signup"
	"leblanc.io/lotor/internal/tenant"
)

const testPublicURL = "https://sbom.example.org"

// mailbox reçoit les courriels de l'inscription : ceux de la file (deliver) et ceux
// envoyés sur-le-champ (codes d'inscription).
type mailbox struct {
	rec     notifyRecorder
	ml      *mailer.Mailer
	handled map[uuid.UUID]bool
}

// withSignup règle le mode d'inscription ; mb non nil branche l'envoi de courriels.
func withSignup(mode signup.Mode, mb *mailbox, domains ...string) appOption {
	return func(o *RouterOptions) {
		id := o.Identity
		s, err := signup.NewService(signup.Options{Pool: id.Pool, Accounts: id.Accounts, Secrets: id.Secrets, Mode: mode,
			AllowedDomains: domains, Mail: mb != nil})
		if err != nil {
			panic(err)
		}
		id.Signup = s
		if mb != nil {
			mb.handled = map[uuid.UUID]bool{}
			if mb.ml, err = mailer.New(mailer.Options{Sender: &mb.rec, Secrets: id.Secrets, Catalog: o.Catalog,
				PublicURL: testPublicURL}); err != nil {
				panic(err)
			}
			id.Mailer, id.PublicURL = mb.ml, testPublicURL
		}
	}
}

// deliver envoie les courriels mis en file depuis le dernier appel et renvoie tous ceux
// reçus depuis.
func (mb *mailbox) deliver(t *testing.T, a *app) []notify.Mail {
	t.Helper()
	ctx := context.Background()
	start := len(mb.sentMails())
	rows, err := a.tdb.Owner(t).QueryContext(ctx, `SELECT id, payload FROM jobs WHERE kind = $1 ORDER BY created_at, id`, mailer.Kind)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var payload json.RawMessage
		if err := rows.Scan(&id, &payload); err != nil {
			t.Fatal(err)
		}
		if mb.handled[id] {
			continue
		}
		mb.handled[id] = true
		if err := mb.ml.Handler().Handle(ctx, jobs.Execution{ID: id, Kind: mailer.Kind, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	return mb.sentMails()[start:]
}

func (mb *mailbox) sentMails() []notify.Mail {
	mb.rec.mu.Lock()
	defer mb.rec.mu.Unlock()
	return append([]notify.Mail(nil), mb.rec.mails...)
}

// mailPath renvoie le chemin du lien d'un courriel.
func mailPath(t *testing.T, m notify.Mail) string {
	t.Helper()
	if m.HTML == nil || !strings.HasPrefix(m.HTML.URL, testPublicURL+"/") {
		t.Fatalf("courriel sans lien : %+v", m)
	}
	return strings.TrimPrefix(m.HTML.URL, testPublicURL)
}

var totpSecret = regexp.MustCompile(`<code class="auth__secret">([A-Z2-7 ]+)</code>`)

// enrollTOTP termine, depuis la session de configuration ouverte par une inscription, le
// parcours obligatoire : enrôlement du TOTP, puis codes de secours.
func (a *app) enrollTOTP(b *browser, email string) user {
	a.t.Helper()
	p := b.get(pathTOTPSetup)
	m := totpSecret.FindStringSubmatch(p.body)
	if p.status != http.StatusOK || m == nil {
		a.t.Fatalf("enrôlement du TOTP : %d\n%s", p.status, p.body)
	}
	u, ok := a.account(email)
	if !ok {
		a.t.Fatalf("compte %s absent", email)
	}
	secret := strings.ReplaceAll(m[1], " ", "")
	p = b.post(pathTOTPOn, url.Values{"code": {a.code(u.ID, secret)}})
	if p.status != http.StatusOK || !strings.Contains(p.body, "recovery") {
		a.t.Fatalf("activation du TOTP : %d\n%s", p.status, p.body)
	}
	return user{ID: u.ID, Email: email, Secret: secret}
}

func (a *app) account(email string) (account.User, bool) {
	a.t.Helper()
	var id int64
	err := a.tdb.Owner(a.t).QueryRowContext(context.Background(), `SELECT id FROM users WHERE email = $1`, email).Scan(&id)
	if err != nil {
		return account.User{}, false
	}
	u, err := a.accounts.Get(context.Background(), id)
	if err != nil {
		a.t.Fatal(err)
	}
	return u, true
}

// orgRole renvoie le rôle de userID dans l'organisation slug ("" s'il n'en est pas membre).
func (a *app) orgRole(slug string, userID int64) string {
	a.t.Helper()
	var role string
	_ = a.tdb.Owner(a.t).QueryRowContext(context.Background(), `SELECT m.role FROM org_memberships m
		JOIN organizations o ON o.id = m.org_id WHERE o.slug = $1 AND m.user_id = $2`, slug, userID).Scan(&role)
	return role
}

func wantStatus(t *testing.T, p page, status int, what string) {
	t.Helper()
	if p.status != status {
		t.Fatalf("%s : %d, attendu %d\n%s", what, p.status, status, p.body)
	}
	if strings.HasPrefix(p.header.Get("Content-Type"), "text/html") {
		assertScreen(t, what, p)
	}
}

func wantBody(t *testing.T, p page, what string, parts ...string) {
	t.Helper()
	for _, s := range parts {
		if !strings.Contains(p.body, s) && !strings.Contains(p.body, html.EscapeString(s)) {
			t.Errorf("%s : %q absent", what, s)
		}
	}
}

const signupPassword = "une phrase de passe solide"

func TestSignupPrivateMode(t *testing.T) {
	a := newApp(t)
	b := a.browser()
	wantStatus(t, b.get("/signup"), http.StatusNotFound, "inscription d'une instance privée")
	wantStatus(t, b.post("/signup", url.Values{"email": {"x@example.org"}}), http.StatusNotFound, "POST d'une instance privée")
	if p := b.get("/login"); strings.Contains(p.body, `href="/signup"`) {
		t.Error("lien d'inscription sur la connexion d'une instance privée")
	}
	if p := b.get("/"); strings.Contains(p.body, `href="/signup"`) {
		t.Error("lien d'inscription sur la présentation d'une instance privée")
	}
	p := b.get("/invitation/lotor_inv_aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	wantStatus(t, p, http.StatusNotFound, "lien d'invitation inconnu")
	wantBody(t, p, "lien inconnu", "Ce lien n'est plus valable")
	if p.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", p.header.Get("Cache-Control"))
	}
	admin := a.user("admin@example.org", true)
	ab := a.signIn(admin)
	p = ab.get("/admin/signup")
	wantStatus(t, p, http.StatusOK, "page Inscription de l'administration")
	wantBody(t, p, "mode", "Privée : pas d'inscription")
	if strings.Contains(p.body, `action="/admin/signup/codes"`) {
		t.Error("création de codes proposée hors mode invitation")
	}
	wantStatus(t, ab.post("/admin/signup/codes", url.Values{"label": {"x"}, "days": {"30"}}), http.StatusUnprocessableEntity,
		"création d'un code hors mode invitation")
}

func TestPublicSignupWithVerification(t *testing.T) {
	mb := &mailbox{}
	a := newApp(t, withSignup(signup.Public, mb, "example.org"))
	existing := a.user("deja@example.org", false)
	b := a.browser()
	if p := b.get("/login"); !strings.Contains(p.body, `href="/signup"`) {
		t.Error("pas de lien d'inscription sur la connexion")
	}
	p := b.get("/signup")
	wantStatus(t, p, http.StatusOK, "formulaire d'inscription")
	wantBody(t, p, "formulaire", "Adresses acceptées : example.org.", `name="email"`)
	if strings.Contains(p.body, `name="code"`) || strings.Contains(p.body, `name="password"`) {
		t.Error("code ou mot de passe demandés à la première étape du mode public")
	}

	p = b.post("/signup", url.Values{"email": {"nouveau@ailleurs.test"}})
	wantStatus(t, p, http.StatusUnprocessableEntity, "domaine refusé")
	wantBody(t, p, "domaine refusé", "domaine accepté", `value="nouveau@ailleurs.test"`, `aria-invalid="true"`)

	// Réponse identique pour une adresse inscrite ou non.
	fresh := b.post("/signup", url.Values{"email": {"Nouveau@Example.org"}})
	wantStatus(t, fresh, http.StatusOK, "demande d'inscription")
	taken := b.post("/signup", url.Values{"email": {existing.Email}})
	wantStatus(t, taken, http.StatusOK, "demande pour une adresse inscrite")
	wantBody(t, fresh, "demande d'inscription", "Si l'inscription est possible")
	if fresh.body != taken.body {
		t.Error("réponse neutre attendue : pages différentes")
	}
	mails := mb.deliver(t, a)
	if len(mails) != 2 || mails[0].To[0] != "nouveau@example.org" || mails[1].To[0] != existing.Email {
		t.Fatalf("courriels : %+v", mails)
	}
	if got := mailPath(t, mails[1]); got != "/login" {
		t.Errorf("courriel d'un compte existant vers %q", got)
	}
	verify := mailPath(t, mails[0])
	if !strings.HasPrefix(verify, "/signup/verify/lotor_vrf_") {
		t.Fatalf("lien de vérification %q", verify)
	}

	v := a.browser()
	for _, path := range []string{"/signup?lang=en", verify + "?lang=en"} {
		wantStatus(t, v.get(path), http.StatusOK, path+" en anglais")
	}
	p = v.get(verify)
	wantStatus(t, p, http.StatusOK, "page de fin d'inscription")
	wantBody(t, p, "fin d'inscription", "nouveau@example.org", `name="org_name"`, `autocomplete="new-password"`)
	if p.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", p.header.Get("Cache-Control"))
	}
	p = v.post(verify, url.Values{"org_name": {"Nouvelle Org"}, "password": {signupPassword}, "confirm": {"autre chose encore"}})
	wantStatus(t, p, http.StatusUnprocessableEntity, "confirmation différente")
	wantBody(t, p, "confirmation différente", `value="Nouvelle Org"`)
	p = v.post(verify, url.Values{"org_name": {"Nouvelle Org"}, "password": {signupPassword}, "confirm": {signupPassword}})
	if p.status != http.StatusSeeOther || p.location != pathTOTPSetup {
		t.Fatalf("fin d'inscription : %d %q\n%s", p.status, p.location, p.body)
	}
	// La session de configuration ne mène qu'à l'enrôlement du TOTP.
	if p := v.get("/account"); p.status != http.StatusSeeOther || p.location != pathTOTPSetup {
		t.Errorf("session de configuration : %d %q", p.status, p.location)
	}
	u := a.enrollTOTP(v, "nouveau@example.org")
	if role := a.orgRole("nouvelle-org", u.ID); role != string(tenant.RoleAdmin) {
		t.Errorf("rôle dans la nouvelle organisation : %q", role)
	}
	if p := v.get("/o/nouvelle-org/"); p.status != http.StatusOK {
		t.Errorf("tableau de bord de la nouvelle organisation : %d", p.status)
	}
	// Le lien est consommé ; un visiteur connecté est renvoyé vers l'accueil.
	wantStatus(t, a.browser().get(verify), http.StatusNotFound, "lien réutilisé")
	if p := v.get("/signup"); p.status != http.StatusSeeOther || p.location != "/" {
		t.Errorf("inscription d'un visiteur connecté : %d %q", p.status, p.location)
	}
}

var signupCodeRE = regexp.MustCompile(`<code class="secret-once">(lotor_sgn_[A-Za-z0-9_]+)</code>`)

// createCode crée un code depuis l'administration et renvoie son texte.
func createCode(t *testing.T, b *browser, label string, extra url.Values) (string, page) {
	t.Helper()
	form := url.Values{"label": {label}, "days": {"30"}}
	for k, v := range extra {
		form[k] = v
	}
	p := b.post("/admin/signup/codes", form)
	m := signupCodeRE.FindStringSubmatch(p.body)
	if p.status != http.StatusOK || m == nil {
		t.Fatalf("création d'un code : %d\n%s", p.status, p.body)
	}
	assertScreen(t, "code créé", p)
	return m[1], p
}

func TestInvitationCodesWithoutMail(t *testing.T) {
	a := newApp(t, withSignup(signup.Invitation, nil))
	admin := a.user("admin@example.org", true)
	ab := a.signIn(admin)
	p := ab.get("/admin/signup")
	wantStatus(t, p, http.StatusOK, "page Inscription")
	wantBody(t, p, "page Inscription", "Sur code d'inscription", `action="/admin/signup/codes"`, `value="30"`)
	if strings.Contains(p.body, `name="recipient"`) {
		t.Error("destinataire proposé sans envoi de courriels")
	}
	wantStatus(t, ab.post("/admin/signup/codes", url.Values{"label": {"x"}, "days": {"366"}}), http.StatusUnprocessableEntity,
		"validité trop longue")
	code, p := createCode(t, ab, "Équipe pilote", nil)
	if p.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", p.header.Get("Cache-Control"))
	}
	if p := ab.get("/admin/signup"); strings.Contains(p.body, code) || !strings.Contains(p.body, "Équipe pilote") {
		t.Error("liste des codes : libellé attendu, jamais le code")
	}

	v := a.browser()
	p = v.get("/signup")
	wantBody(t, p, "inscription en une étape", `name="code"`, `name="email"`, `name="org_name"`, `name="password"`)
	form := url.Values{"code": {code}, "email": {admin.Email}, "org_name": {"Pilote"}, "password": {signupPassword},
		"confirm": {signupPassword}}
	// Adresse déjà inscrite : même refus qu'un code faux, code non consommé.
	p = v.post("/signup", form)
	wantStatus(t, p, http.StatusUnprocessableEntity, "adresse déjà inscrite")
	wantBody(t, p, "adresse déjà inscrite", "Code d'inscription refusé")
	if strings.Contains(p.body, code) {
		t.Error("code renvoyé dans la page")
	}
	form.Set("email", "pilote@example.org")
	p = v.post("/signup", form)
	if p.status != http.StatusSeeOther || p.location != pathTOTPSetup {
		t.Fatalf("inscription sur code : %d %q\n%s", p.status, p.location, p.body)
	}
	u := a.enrollTOTP(v, "pilote@example.org")
	if role := a.orgRole("pilote", u.ID); role != string(tenant.RoleAdmin) {
		t.Errorf("rôle : %q", role)
	}
	// Un code ne sert qu'une fois.
	form.Set("email", "second@example.org")
	wantStatus(t, a.browser().post("/signup", form), http.StatusUnprocessableEntity, "code réutilisé")
	if p := ab.get("/admin/signup"); !strings.Contains(p.body, "Utilisé") || !strings.Contains(p.body, "pilote@example.org") {
		t.Error("code utilisé : état et compte attendus dans la liste")
	}

	// Révocation : page de confirmation, puis le code est refusé.
	other, _ := createCode(t, ab, "À révoquer", nil)
	var codeID string
	if err := a.tdb.Owner(t).QueryRowContext(context.Background(), `SELECT id FROM signup_codes WHERE label = $1`, "À révoquer").Scan(&codeID); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, ab.get("/admin/signup/codes/"+codeID+"/revoke"), http.StatusOK, "confirmation de révocation")
	p = ab.post("/admin/signup/codes/"+codeID+"/revoke", nil)
	if p.status != http.StatusSeeOther || p.location != "/admin/signup?done=signup_code_revoked" {
		t.Fatalf("révocation : %d %q", p.status, p.location)
	}
	wantStatus(t, ab.post("/admin/signup/codes/"+codeID+"/revoke", nil), http.StatusUnprocessableEntity, "double révocation")
	form.Set("code", other)
	wantStatus(t, a.browser().post("/signup", form), http.StatusUnprocessableEntity, "code révoqué")
	wantStatus(t, ab.get("/admin/signup/codes/"+uuid.NewString()+"/revoke"), http.StatusNotFound, "code inconnu")

	// Réservé aux administrateurs d'instance.
	plain := a.signIn(a.user("plain@example.org", false))
	wantStatus(t, plain.get("/admin/signup"), http.StatusNotFound, "page Inscription d'un compte ordinaire")
}

func TestInvitationCodeMailedByAdmin(t *testing.T) {
	mb := &mailbox{}
	a := newApp(t, withSignup(signup.Invitation, mb))
	admin := a.user("admin@example.org", true)
	ab := a.signIn(admin)
	wantStatus(t, ab.post("/admin/signup/codes", url.Values{"label": {"x"}, "days": {"30"}, "recipient": {"pas une adresse"}}),
		http.StatusUnprocessableEntity, "destinataire invalide")
	code, p := createCode(t, ab, "Partenaire", url.Values{"recipient": {"contact@partenaire.test"}})
	wantBody(t, p, "code envoyé", "contact@partenaire.test")
	sent := mb.sentMails()
	if len(sent) != 1 || sent[0].To[0] != "contact@partenaire.test" || !strings.Contains(sent[0].Text, code) {
		t.Fatalf("courriel du code : %+v", sent)
	}
	// L'adresse du destinataire n'est conservée nulle part.
	var n int
	if err := a.tdb.Owner(t).QueryRowContext(context.Background(), `SELECT
		(SELECT count(*) FROM signup_codes WHERE row_to_json(signup_codes)::text LIKE '%partenaire.test%') +
		(SELECT count(*) FROM audit_events WHERE row_to_json(audit_events)::text LIKE '%partenaire.test%') +
		(SELECT count(*) FROM jobs WHERE row_to_json(jobs)::text LIKE '%partenaire.test%')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("adresse du destinataire conservée (%d lignes)", n)
	}
	if strings.Contains(a.logs.String(), "partenaire.test") || strings.Contains(a.logs.String(), code) {
		t.Error("adresse ou code dans les journaux")
	}

	// Inscription à une autre adresse que celle qui a reçu le code, avec vérification.
	v := a.browser()
	p = v.get("/signup")
	if strings.Contains(p.body, `name="password"`) {
		t.Error("mot de passe demandé avant la vérification de l'adresse")
	}
	wantStatus(t, v.post("/signup", url.Values{"code": {code}, "email": {"autre@example.org"}}), http.StatusOK, "demande sur code")
	mails := mb.deliver(t, a)
	if len(mails) != 1 || mails[0].To[0] != "autre@example.org" {
		t.Fatalf("courriels : %+v", mails)
	}
	verify := mailPath(t, mails[0])
	p = v.post(verify, url.Values{"org_name": {"Partenaire"}, "password": {signupPassword}, "confirm": {signupPassword}})
	if p.status != http.StatusSeeOther || p.location != pathTOTPSetup {
		t.Fatalf("fin d'inscription : %d %q\n%s", p.status, p.location, p.body)
	}
	a.enrollTOTP(v, "autre@example.org")
	wantStatus(t, a.browser().post("/signup", url.Values{"code": {code}, "email": {"troisieme@example.org"}}),
		http.StatusUnprocessableEntity, "code consommé")
}

var inviteLinkRE = regexp.MustCompile(`<code class="secret-once">https?://[^/]+(/invitation/lotor_inv_[A-Za-z0-9_]+)</code>`)

func TestInvitationLinkWithoutMail(t *testing.T) {
	a := newApp(t) // instance privée : le lien d'une invitation d'organisation sert quand même
	owner := a.user("owner@example.org", false)
	a.org("acme", owner)
	ob := a.signIn(owner)
	p := ob.post("/o/acme/members", url.Values{"email": {"Invite@Example.org"}, "role": {string(tenant.RoleMember)}})
	wantStatus(t, p, http.StatusOK, "invitation sans envoi")
	m := inviteLinkRE.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("lien d'invitation absent\n%s", p.body)
	}
	link := m[1]
	if p.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", p.header.Get("Cache-Control"))
	}
	if p := ob.get("/o/acme/members"); strings.Contains(p.body, link) {
		t.Error("lien affiché de nouveau")
	}

	v := a.browser()
	p = v.get(link)
	wantStatus(t, p, http.StatusOK, "page du lien")
	wantBody(t, p, "page du lien", "Rejoindre Org acme", "invite@example.org", `name="password"`, "/login?next=")
	p = v.post(link, url.Values{"password": {signupPassword}, "confirm": {signupPassword}})
	if p.status != http.StatusSeeOther || p.location != pathTOTPSetup {
		t.Fatalf("création par le lien : %d %q\n%s", p.status, p.location, p.body)
	}
	u := a.enrollTOTP(v, "invite@example.org")
	if role := a.orgRole("acme", u.ID); role != string(tenant.RoleMember) {
		t.Errorf("rôle : %q", role)
	}
	if _, ok := a.account("invite@example.org"); !ok {
		t.Fatal("compte non créé")
	}
	wantStatus(t, a.browser().get(link), http.StatusNotFound, "lien consommé")

	// Compte existant : un autre compte connecté est arrêté, le bon accepte.
	known := a.user("known@example.org", false)
	p = ob.post("/o/acme/members", url.Values{"email": {known.Email}, "role": {string(tenant.RoleAdmin)}})
	m = inviteLinkRE.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("lien d'invitation absent\n%s", p.body)
	}
	link = m[1]
	p = ob.get(link)
	wantStatus(t, p, http.StatusOK, "autre compte connecté")
	wantBody(t, p, "autre compte connecté", "Autre compte connecté")
	wantStatus(t, ob.post(link, nil), http.StatusUnprocessableEntity, "acceptation par un autre compte")
	kb := a.signIn(known)
	p = kb.get(link)
	wantStatus(t, p, http.StatusOK, "compte invité connecté")
	wantBody(t, p, "compte invité connecté", "Accepter l'invitation")
	p = kb.post(link, nil)
	if p.status != http.StatusSeeOther || p.location != "/account/invitations?done=invitation_accepted" {
		t.Fatalf("acceptation : %d %q", p.status, p.location)
	}
	if role := a.orgRole("acme", known.ID); role != string(tenant.RoleAdmin) {
		t.Errorf("rôle après acceptation : %q", role)
	}
	// Création par le lien d'une adresse qui a déjà un compte : refusée.
	p = ob.post("/o/acme/members", url.Values{"email": {"third@example.org"}, "role": {string(tenant.RoleMember)}})
	link = inviteLinkRE.FindStringSubmatch(p.body)[1]
	a.user("third@example.org", false)
	p = a.browser().post(link, url.Values{"password": {signupPassword}, "confirm": {signupPassword}})
	wantStatus(t, p, http.StatusUnprocessableEntity, "lien d'une adresse inscrite")
	wantBody(t, p, "lien d'une adresse inscrite", "Un compte existe déjà")
}

func TestInvitationMailedInInviterLanguage(t *testing.T) {
	mb := &mailbox{}
	a := newApp(t, withSignup(signup.Private, mb))
	owner := a.user("owner@example.org", false)
	a.org("acme", owner)
	if err := a.accounts.SaveSettings(context.Background(), audit.System, owner.ID, account.Settings{Language: "en"}); err != nil {
		t.Fatal(err)
	}
	ob := a.signIn(owner)
	p := ob.post("/o/acme/members", url.Values{"email": {"invite@example.org"}, "role": {string(tenant.RoleAdmin)}})
	if p.status != http.StatusSeeOther || !strings.HasSuffix(p.location, "done=invitation_mailed") {
		t.Fatalf("invitation envoyée : %d %q\n%s", p.status, p.location, p.body)
	}
	if p := ob.get(p.location); inviteLinkRE.MatchString(p.body) {
		t.Error("lien affiché alors qu'il est envoyé")
	}
	mails := mb.deliver(t, a)
	if len(mails) != 1 || mails[0].To[0] != "invite@example.org" || mails[0].HTML.Lang != "en" ||
		!strings.Contains(mails[0].Text, owner.Email) || !strings.Contains(mails[0].Text, "Administrator") {
		t.Fatalf("courriel d'invitation : %+v", mails)
	}
	v := a.browser()
	link := mailPath(t, mails[0])
	p = v.post(link, url.Values{"password": {signupPassword}, "confirm": {signupPassword}})
	if p.status != http.StatusSeeOther || p.location != pathTOTPSetup {
		t.Fatalf("création par le lien : %d %q\n%s", p.status, p.location, p.body)
	}
	u := a.enrollTOTP(v, "invite@example.org")
	if role := a.orgRole("acme", u.ID); role != string(tenant.RoleAdmin) {
		t.Errorf("rôle : %q", role)
	}
}
