//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/web/webtest"
)

func (a *app) instanceActions() []audit.Action {
	a.t.Helper()
	page, err := audit.ListInstance(context.Background(), a.tdb.App.DB(), "", audit.MaxPage)
	if err != nil {
		a.t.Fatal(err)
	}
	var out []audit.Action
	for _, e := range page.Items {
		out = append(out, e.Action)
	}
	return out
}

func hasAction(actions []audit.Action, want audit.Action) bool {
	for _, a := range actions {
		if a == want {
			return true
		}
	}
	return false
}

// TestFirstLoginOfBootstrappedAdmin suit le premier administrateur : mot de passe
// temporaire, enrôlement obligatoire du TOTP, changement de mot de passe imposé, puis
// reconnexion avec code TOTP, code faux et rejeu refusés.
// assertAutofocus vérifie que la page donne le focus à ce champ, et à lui seul.
func assertAutofocus(t *testing.T, body, id string) {
	t.Helper()
	if n := strings.Count(body, " autofocus"); n != 1 {
		t.Errorf("%d champs avec autofocus, attendu 1", n)
	}
	if !regexp.MustCompile(`<input[^>]* id="` + id + `"[^>]* autofocus[ >]`).MatchString(body) {
		t.Errorf("autofocus absent de %s", id)
	}
}

func TestFirstLoginOfBootstrappedAdmin(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	ctx := context.Background()
	const email, temp = "admin@example.org", "mot de passe temporaire"
	created, err := a.accounts.Bootstrap(ctx, email, temp)
	if err != nil || !created {
		t.Fatalf("bootstrap : %v, %v", created, err)
	}
	b := a.browser()
	assertAutofocus(t, b.get("/login").body, "login-email")

	// Mot de passe valide, aucun TOTP : session de configuration seulement.
	p := b.post("/login", url.Values{"email": {email}, "password": {temp}})
	if p.status != http.StatusSeeOther || p.location != pathTOTPSetup {
		t.Fatalf("connexion : %d %q", p.status, p.location)
	}
	for _, path := range []string{"/", "/account", "/admin/users", "/account/password"} {
		if p := b.get(path); p.status != http.StatusSeeOther || p.location != pathTOTPSetup {
			t.Errorf("%s en session de configuration : %d %q", path, p.status, p.location)
		}
	}

	// Enrôlement : un code faux régénère la clé, le bon active le TOTP.
	setup := b.get(pathTOTPSetup)
	if setup.status != http.StatusOK {
		t.Fatalf("page d'enrôlement : %d", setup.status)
	}
	webtest.AssertAccessible(t, []byte(setup.body))
	webtest.AssertNoInlineCode(t, []byte(setup.body))
	assertAutofocus(t, setup.body, "totp-code")
	if !strings.Contains(setup.body, `src="data:image/png;base64,`) {
		t.Error("code QR absent")
	}
	p = b.post(pathTOTPOn, url.Values{"code": {"000000"}})
	if p.status != http.StatusSeeOther || !strings.Contains(p.location, "error=invalid_code") {
		t.Fatalf("code faux à l'enrôlement : %d %q", p.status, p.location)
	}
	setup = b.get(p.location)
	if !strings.Contains(setup.body, "scannez à nouveau") {
		t.Error("message d'erreur d'enrôlement absent")
	}
	secretKey := setupSecret(t, setup.body)
	code, _ := totp.GenerateCode(secretKey, time.Now())
	// Activation : les codes de secours sont montrés dans la réponse, une seule fois.
	if p = b.post(pathTOTPOn, url.Values{"code": {code}}); p.status != http.StatusOK || len(recoveryCodesIn(p.body)) != 10 {
		t.Fatalf("activation : %d %q", p.status, p.location)
	}

	// Mot de passe temporaire : aucune page avant de l'avoir changé.
	for _, path := range []string{"/", "/account", "/admin/users", "/o/nimporte"} {
		if p := b.get(path); p.status != http.StatusSeeOther || p.location != pathPassword {
			t.Errorf("%s avant changement : %d %q", path, p.status, p.location)
		}
	}
	pw := b.get(pathPassword)
	if pw.status != http.StatusOK || !strings.Contains(pw.body, "temporaire") {
		t.Fatalf("page de changement : %d", pw.status)
	}
	webtest.AssertAccessible(t, []byte(pw.body))
	if p = b.post(pathPassword, url.Values{"current": {temp}, "password": {"court"}, "confirm": {"court"}}); p.status != http.StatusUnprocessableEntity ||
		!strings.Contains(unescape(p.body), "au moins 12 caractères") {
		t.Fatalf("mot de passe trop court : %d", p.status)
	}
	if p = b.post(pathPassword, url.Values{"current": {temp}, "password": {email}, "confirm": {email}}); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("mot de passe égal à l'e-mail : %d", p.status)
	}
	const final = "une phrase de passe solide"
	if p = b.post(pathPassword, url.Values{"current": {temp}, "password": {final}, "confirm": {final}}); p.status != http.StatusSeeOther {
		t.Fatalf("changement : %d\n%s", p.status, p.body)
	}
	if p = b.get("/"); p.status != http.StatusOK || !strings.Contains(unescape(p.body), "Aucune organisation") {
		t.Fatalf("accueil sans organisation : %d", p.status)
	}

	// Déconnexion, puis connexion complète : code faux (401), bon code, rejeu refusé.
	if p = b.post(pathLogout, nil); p.status != http.StatusSeeOther {
		t.Fatalf("déconnexion : %d", p.status)
	}
	if p = b.get("/account"); p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, "/login") {
		t.Fatalf("après déconnexion : %d %q", p.status, p.location)
	}
	var userID int64
	if err := a.tdb.App.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&userID)
	}); err != nil {
		t.Fatal(err)
	}
	a.steps[userID] = 2 // le pas courant a servi à l'enrôlement
	b = a.browser()
	if p = b.post("/login", url.Values{"email": {email}, "password": {final}}); p.location != pathVerify {
		t.Fatalf("mot de passe : %d %q", p.status, p.location)
	}
	verify := b.get(pathVerify)
	webtest.AssertAccessible(t, []byte(verify.body))
	assertAutofocus(t, verify.body, "verify-code")
	if p = b.post(pathVerify, url.Values{"code": {"000000"}}); p.status != http.StatusUnauthorized ||
		!strings.Contains(unescape(p.body), "incorrect, expiré ou déjà utilisé") ||
		p.header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("code faux : %d %q", p.status, p.header.Get("Content-Type"))
	}
	good := a.code(userID, secretKey)
	if p = b.post(pathVerify, url.Values{"code": {good}}); p.status != http.StatusSeeOther {
		t.Fatalf("bon code : %d\n%s", p.status, p.body)
	}
	other := a.browser()
	other.post("/login", url.Values{"email": {email}, "password": {final}})
	if p = other.post(pathVerify, url.Values{"code": {good}}); p.status != http.StatusUnauthorized {
		t.Fatalf("rejeu du code : %d", p.status)
	}

	actions := a.instanceActions()
	for _, want := range []audit.Action{audit.AccountBootstrapped, audit.TOTPEnrolled, audit.LoginSucceeded,
		audit.AccountPasswordChanged, audit.Logout, audit.TOTPFailed} {
		if !hasAction(actions, want) {
			t.Errorf("événement %s absent du journal : %v", want, actions)
		}
	}
	if strings.Contains(a.logs.String(), final) || strings.Contains(a.logs.String(), temp) {
		t.Error("un mot de passe apparaît dans les journaux")
	}
}

// TestLoginErrorsAreGenericTranslatedAndTimed : e-mail inconnu, mot de passe faux et
// compte désactivé donnent la même réponse, traduite, en un temps comparable.
func TestLoginErrorsAreGenericTranslatedAndTimed(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	u := a.user("alice@example.org", false)
	off := a.user("off@example.org", false)
	if err := a.accounts.SetActive(context.Background(), audit.System, off.ID, false); err != nil {
		t.Fatal(err)
	}
	b := a.browser()
	attempt := func(lang, email, password string) (page, time.Duration) {
		start := time.Now()
		p := b.post("/login?lang="+lang, url.Values{"email": {email}, "password": {password}})
		return p, time.Since(start)
	}
	for lang, want := range map[string]string{"fr": "Adresse e-mail ou mot de passe incorrect.", "en": "Incorrect e-mail address or password."} {
		for _, c := range [][2]string{{"inconnu@example.org", "x"}, {u.Email, "mauvais mot de passe"}, {off.Email, off.Password}} {
			p, _ := attempt(lang, c[0], c[1])
			if p.status != http.StatusUnauthorized || !strings.Contains(unescape(p.body), want) {
				t.Errorf("%s %s : %d", lang, c[0], p.status)
			}
			webtest.AssertAccessible(t, []byte(p.body))
		}
	}
	// Temps égalisé : authx compare toujours un hash bcrypt (factice si le compte manque).
	var unknown, wrong time.Duration
	for range 5 {
		_, d := attempt("fr", "inconnu@example.org", "x")
		unknown += d
		_, d = attempt("fr", u.Email, "mauvais mot de passe")
		wrong += d
	}
	if ratio := float64(unknown) / float64(wrong); ratio < 0.5 || ratio > 2 {
		t.Errorf("temps de réponse : inconnu %v, mot de passe faux %v", unknown/5, wrong/5)
	}
	if n := countAction(a.instanceActions(), audit.LoginFailed); n < 16 {
		t.Errorf("%d échecs journalisés, attendu 16", n)
	}
}

func countAction(actions []audit.Action, want audit.Action) int {
	n := 0
	for _, a := range actions {
		if a == want {
			n++
		}
	}
	return n
}

// TestNoApplicationSessionWithoutTOTP : sans TOTP actif ni méthode enregistrée, aucune
// session applicative ; une réinitialisation du TOTP ferme les sessions ouvertes.
func TestNoApplicationSessionWithoutTOTP(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	ctx := context.Background()
	admin := a.user("admin@example.org", true)
	u := a.user("bob@example.org", false)
	b := a.signIn(u)
	if p := b.get("/account"); p.status != http.StatusOK {
		t.Fatalf("session ouverte : %d", p.status)
	}
	temp, err := a.accounts.ResetTOTP(ctx, audit.Actor{UserID: admin.ID, Email: admin.Email}, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p := b.get("/account"); p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, "/login") {
		t.Fatalf("après réinitialisation du TOTP : %d %q", p.status, p.location)
	}
	// Après réinitialisation, le mot de passe temporaire ne donne qu'une session de
	// configuration.
	p := b.post("/login", url.Values{"email": {u.Email}, "password": {temp}})
	if p.location != pathTOTPSetup {
		t.Fatalf("connexion sans TOTP : %q", p.location)
	}
	if p := b.get("/account"); p.location != pathTOTPSetup {
		t.Fatalf("page applicative en session de configuration : %d %q", p.status, p.location)
	}

	// Une session authentifiée sans ligne dans session_auth (créée hors du parcours) est
	// refusée.
	c := a.signIn(admin)
	if _, err := a.tdb.App.DB().ExecContext(ctx, `DELETE FROM session_auth WHERE user_id = $1`, admin.ID); err != nil {
		t.Fatal(err)
	}
	if p := c.get("/account"); p.status != http.StatusSeeOther || p.location != pathLogin {
		t.Fatalf("session sans méthode : %d %q", p.status, p.location)
	}
	// La déconnexion efface aussi la ligne de session_auth (déclencheur).
	d := a.signIn(admin)
	d.post(pathLogout, nil)
	var n int
	if err := a.tdb.App.DB().QueryRowContext(ctx, `SELECT count(*) FROM session_auth`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("session_auth après déconnexion : %d, %v", n, err)
	}
}

// TestLoginRateLimit : au-delà du seuil par minute et par IP, /login répond 429.
func TestLoginRateLimit(t *testing.T) {
	t.Parallel()
	a := newApp(t, func(o *RouterOptions) { o.Identity.LoginRateLimit = 3 })
	b := a.browser()
	var last page
	for range 4 {
		last = b.post("/login", url.Values{"email": {"x@example.org"}, "password": {"y"}})
	}
	if last.status != http.StatusTooManyRequests || !strings.Contains(unescape(last.body), "Trop de requêtes") {
		t.Fatalf("4e tentative : %d", last.status)
	}
	if p := b.get("/login"); p.status != http.StatusOK {
		t.Fatalf("GET /login limité : %d", p.status)
	}
}

// TestCSRFFailureIsTranslated : un POST sans jeton reçoit la page 403 traduite.
func TestCSRFFailureIsTranslated(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	b := a.browser()
	req, _ := http.NewRequest(http.MethodPost, a.srv.URL+"/login?lang=en", strings.NewReader("email=a&password=b"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p := b.do(req)
	if p.status != http.StatusForbidden || !strings.Contains(p.body, "Form expired") {
		t.Fatalf("CSRF : %d\n%s", p.status, p.body)
	}
	webtest.AssertAccessible(t, []byte(p.body))
}
