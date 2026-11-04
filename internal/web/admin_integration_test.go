//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/webtest"
)

var tempPassword = regexp.MustCompile(`<code class="secret-once">([^<]+)</code>`)

// TestInstanceAdministration : chaque action d'administration aboutit et produit un
// événement lisible dans le journal de l'instance ; l'avertissement « un seul
// administrateur » disparaît avec le second.
func TestInstanceAdministration(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", true)
	b := a.signIn(admin)

	if p := b.get("/admin/users"); p.status != http.StatusOK || !strings.Contains(unescape(p.body), "Un seul administrateur") {
		t.Fatalf("liste des comptes : %d", p.status)
	}
	p := b.post("/admin/users", url.Values{"email": {"Carole@Example.org "}})
	m := tempPassword.FindStringSubmatch(p.body)
	if p.status != http.StatusOK || m == nil || len(m[1]) != account.TempPasswordLength {
		t.Fatalf("création : %d\n%s", p.status, p.body)
	}
	if strings.Contains(a.logs.String(), m[1]) {
		t.Error("mot de passe temporaire journalisé")
	}
	carole, err := a.accounts.GetByEmail(context.Background(), "carole@example.org")
	if err != nil || !carole.MustChangePwd || carole.Admin {
		t.Fatalf("compte créé : %+v, %v", carole, err)
	}
	if p := b.post("/admin/users", url.Values{"email": {"carole@example.org"}}); p.status != http.StatusUnprocessableEntity {
		t.Errorf("doublon : %d", p.status)
	}
	base := "/admin/users/" + itoa(carole.ID)
	for _, action := range []string{"promote", "demote", "deactivate", "activate"} {
		if p := b.post(base+"/"+action, nil); p.status != http.StatusSeeOther {
			t.Errorf("%s : %d\n%s", action, p.status, p.body)
		}
	}
	if p := b.post(base+"/reset-password", nil); p.status != http.StatusOK || tempPassword.FindStringSubmatch(p.body) == nil {
		t.Errorf("réinitialisation du mot de passe : %d", p.status)
	}
	// La réinitialisation du TOTP impose aussi un mot de passe temporaire (SEC-03).
	if p := b.post(base+"/reset-totp", nil); p.status != http.StatusOK || tempPassword.FindStringSubmatch(p.body) == nil ||
		!strings.Contains(p.body, "TOTP et mot de passe réinitialisés") {
		t.Errorf("réinitialisation du TOTP : %d", p.status)
	}
	if p := b.post(base+"/inconnue", nil); p.status != http.StatusNotFound {
		t.Errorf("action inconnue : %d", p.status)
	}
	// Garde-fous : pas de désactivation de soi, pas de retrait du dernier administrateur.
	if p := b.post("/admin/users/"+itoa(admin.ID)+"/deactivate", nil); p.status != http.StatusUnprocessableEntity {
		t.Errorf("auto-désactivation : %d", p.status)
	}
	if p := b.post("/admin/users/"+itoa(admin.ID)+"/demote", nil); p.status != http.StatusUnprocessableEntity {
		t.Errorf("retrait du dernier administrateur : %d", p.status)
	}

	// Organisations : création, renommage, langue, administrateur, archivage.
	if p := b.post("/admin/orgs", url.Values{"slug": {"Mauvais Slug"}, "name": {"X"}, "language": {"fr"}, "admin_email": {admin.Email}}); p.status != http.StatusUnprocessableEntity {
		t.Errorf("slug invalide : %d", p.status)
	}
	if p := b.post("/admin/orgs", url.Values{"slug": {"atelier"}, "name": {"Atelier"}, "language": {"fr"}, "admin_email": {"carole@example.org"}}); p.status != http.StatusSeeOther {
		t.Fatalf("création d'organisation : %d\n%s", p.status, p.body)
	}
	if p := b.post("/admin/orgs", url.Values{"slug": {"atelier"}, "name": {"Bis"}, "language": {"fr"}, "admin_email": {admin.Email}}); p.status != http.StatusUnprocessableEntity {
		t.Errorf("slug pris : %d", p.status)
	}
	for _, s := range []struct {
		action string
		form   url.Values
	}{
		{"update", url.Values{"name": {"Atelier Nord"}, "language": {"en"}}},
		{"admins", url.Values{"email": {admin.Email}}},
		{"admins", url.Values{"email": {admin.Email}}}, // déjà administrateur : sans effet
		{"archive", nil},
		{"unarchive", nil},
	} {
		if p := b.post("/admin/orgs/atelier/"+s.action, s.form); p.status != http.StatusSeeOther {
			t.Errorf("%s : %d\n%s", s.action, p.status, p.body)
		}
	}
	if p := b.get("/admin/orgs/inconnue"); p.status != http.StatusNotFound {
		t.Errorf("organisation inconnue : %d", p.status)
	}
	// L'administrateur nommé voit désormais l'organisation (il en est membre).
	if p := b.get("/o/atelier"); p.status != http.StatusOK {
		t.Errorf("organisation de l'administrateur : %d", p.status)
	}

	// Second administrateur : plus d'avertissement.
	b.post(base+"/promote", nil)
	if p := b.get("/admin/users"); strings.Contains(unescape(p.body), "Un seul administrateur") {
		t.Error("avertissement maintenu avec deux administrateurs")
	}

	journal := unescape(b.get("/admin/audit").body)
	for _, want := range []string{
		"Compte carole@example.org créé", "Rôle d'instance de carole@example.org modifié",
		"Compte carole@example.org désactivé", "Compte carole@example.org réactivé",
		"TOTP de carole@example.org réinitialisé", "Mot de passe de carole@example.org réinitialisé",
		"Organisation atelier créée", "Organisation renommée de « Atelier » en « Atelier Nord »",
		"Organisation atelier archivée", "Organisation atelier réactivée", "Connexion de admin@example.org",
	} {
		if !strings.Contains(journal, want) {
			t.Errorf("journal de l'instance sans « %s »", want)
		}
	}
}

// TestRescueProcedure : la procédure de secours retire le TOTP de l'administrateur une
// fois par ticket, lui impose le mot de passe temporaire de l'exploitant, ferme ses
// sessions et le journalise ; il enrôle un nouveau TOTP. L'ancien mot de passe ne suffit
// plus (SEC-03).
func TestRescueProcedure(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	ctx := context.Background()
	admin := a.user("admin@example.org", true)
	plain := a.user("plain@example.org", false)
	b := a.signIn(admin)

	const rescue = "mot de passe de secours"
	if _, err := a.accounts.RescueTOTP(ctx, plain.Email, "INC-2026-0042", rescue); err == nil {
		t.Fatal("secours accepté pour un compte ordinaire")
	}
	if _, err := a.accounts.RescueTOTP(ctx, admin.Email, "court", rescue); err == nil {
		t.Fatal("ticket trop court accepté")
	}
	if _, err := a.accounts.RescueTOTP(ctx, admin.Email, "INC-2026-0042", "court"); err == nil {
		t.Fatal("mot de passe de secours trop court accepté")
	}
	applied, err := a.accounts.RescueTOTP(ctx, admin.Email, "INC-2026-0042", rescue)
	if err != nil || !applied {
		t.Fatalf("secours : %v, %v", applied, err)
	}
	if p := b.get("/account"); p.status != http.StatusSeeOther {
		t.Fatalf("session après secours : %d", p.status)
	}
	again, err := a.accounts.RescueTOTP(ctx, admin.Email, "INC-2026-0042", "un autre mot de passe")
	if err != nil || again {
		t.Fatalf("second démarrage avec le même ticket : %v, %v", again, err)
	}
	c := a.browser()
	if p := c.post("/login", url.Values{"email": {admin.Email}, "password": {admin.Password}}); p.status != http.StatusUnauthorized {
		t.Fatalf("ancien mot de passe après secours : %d %q", p.status, p.location)
	}
	if p := c.post("/login", url.Values{"email": {admin.Email}, "password": {rescue}}); p.location != pathTOTPSetup {
		t.Fatalf("connexion après secours : %q", p.location)
	}
	if !hasAction(a.instanceActions(), audit.AccountRescueTOTPReset) {
		t.Error("procédure de secours absente du journal")
	}
	page, _ := audit.ListInstance(ctx, a.tdb.App.DB(), "", 50)
	for _, e := range page.Items {
		if e.Action == audit.AccountRescueTOTPReset && e.Details["ticket"] != "INC-2026-0042" {
			t.Errorf("ticket non journalisé : %v", e.Details)
		}
	}
}

// TestProfileSettings : langue et thème du compte, organisation par défaut.
func TestProfileSettings(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	u := a.user("u@example.org", false)
	other := a.user("other@example.org", false)
	a.org("alpha", u)
	beta := a.org("beta", u)
	foreign := a.org("gamma", other)
	b := a.signIn(u)
	if p := b.get("/"); p.location != "/o/alpha" {
		t.Fatalf("organisation par défaut implicite : %q", p.location)
	}
	if p := b.post("/account", url.Values{"language": {"en"}, "theme": {"dark"}, "default_org": {foreign.ID.String()}}); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("organisation étrangère acceptée : %d", p.status)
	}
	if p := b.post("/account", url.Values{"language": {"xx"}}); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("langue inconnue acceptée : %d", p.status)
	}
	if p := b.post("/account", url.Values{"language": {"en"}, "theme": {"dark"}, "default_org": {beta.ID.String()}}); p.status != http.StatusSeeOther {
		t.Fatalf("préférences : %d\n%s", p.status, p.body)
	}
	if b.cookie(render.ThemeCookie) != "dark" {
		t.Error("cookie de thème non posé")
	}
	if p := b.get("/"); p.location != "/o/beta" {
		t.Fatalf("organisation par défaut : %q", p.location)
	}
	// La préférence du compte l'emporte sur Accept-Language et sur la langue de l'organisation.
	req, _ := http.NewRequest(http.MethodGet, a.srv.URL+"/o/beta", nil)
	req.Header.Set("Accept-Language", "fr")
	if p := b.do(req); p.header.Get("Content-Language") != "en" || !strings.Contains(p.body, `data-theme="dark"`) {
		t.Fatalf("langue %q, thème", p.header.Get("Content-Language"))
	}
	// Un membre retiré perd son organisation par défaut.
	if err := a.orgs.AddMember(context.Background(), audit.System, beta.ID, other.Email, tenant.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := a.orgs.RemoveMember(context.Background(), audit.System, beta.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if p := b.get("/"); p.location != "/o/alpha" {
		t.Fatalf("après retrait : %q", p.location)
	}
}

// TestEveryScreenIsAccessible rend chaque écran en français et en anglais, en thème
// clair et sombre, et le passe à l'assistant d'accessibilité.
func TestEveryScreenIsAccessible(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", true)
	viewer := a.user("viewer@example.org", false)
	o := a.org("atelier", admin)
	a.addTeamMember(o, viewer, tenant.TeamReader)
	b := a.signIn(admin)
	anon := a.browser()
	screens := map[string]*browser{
		"/login": anon, "/account": b, "/account/password": b, pathSecurity: b,
		"/o/atelier": b, "/o/atelier/members": b, "/o/atelier/settings": b, "/o/atelier/audit": b,
		"/admin/users": b, "/admin/users/" + itoa(viewer.ID): b, "/admin/orgs": b, "/admin/orgs/atelier": b, "/admin/audit": b,
		"/admin/jobs": b, "/admin/vulndb": b, "/admin/signup": b,
	}
	for path, br := range screens {
		for _, lang := range []string{"fr", "en"} {
			for _, theme := range []string{"light", "dark"} {
				req, _ := http.NewRequest(http.MethodGet, a.srv.URL+path+"?lang="+lang, nil)
				req.AddCookie(&http.Cookie{Name: render.ThemeCookie, Value: theme})
				p := br.do(req)
				if p.status != http.StatusOK {
					t.Errorf("%s (%s) : %d", path, lang, p.status)
					continue
				}
				if !strings.Contains(p.body, `lang="`+lang+`"`) || !strings.Contains(p.body, `data-theme="`+theme+`"`) {
					t.Errorf("%s : langue ou thème absent", path)
				}
				if strings.Contains(p.body, "<no value>") {
					t.Errorf("%s (%s) : paramètre de traduction manquant", path, lang)
				}
				for _, problem := range webtest.CheckAccessibility([]byte(p.body)) {
					t.Errorf("%s (%s) : %s", path, lang, problem)
				}
				for _, problem := range webtest.CheckNoInlineCode([]byte(p.body)) {
					t.Errorf("%s (%s) : %s", path, lang, problem)
				}
			}
		}
	}
	// Pages rendues sur une action : second facteur, mot de passe temporaire.
	v := a.browser()
	v.post("/login", url.Values{"email": {viewer.Email}, "password": {viewer.Password}})
	verify := v.get("/login/2fa?lang=en")
	if verify.status != http.StatusOK {
		t.Fatalf("second facteur : %d", verify.status)
	}
	webtest.AssertAccessible(t, []byte(verify.body))
	webtest.AssertNoInlineCode(t, []byte(verify.body))
	p := b.post("/admin/users/"+itoa(viewer.ID)+"/reset-password", nil)
	webtest.AssertAccessible(t, []byte(p.body))
	webtest.AssertNoInlineCode(t, []byte(p.body))
	// Accueil sans organisation.
	lone := a.signIn(a.user("lone@example.org", false))
	home := lone.get("/")
	if home.status != http.StatusOK {
		t.Fatalf("accueil : %d", home.status)
	}
	webtest.AssertAccessible(t, []byte(home.body))
}
