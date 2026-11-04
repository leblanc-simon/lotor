//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/license"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/webtest"
)

// TestLicenseScreens : page Licences de l'organisation (politique par défaut qui accepte
// tout, saisie refusée avec message situé, enregistrement journalisé), constats après
// réévaluation, filtre de verdict, onglet Licences du projet, recherche « license: »,
// droits (lecteur : lecture seule, 403 à l'enregistrement), deux langues, accessibilité.
func TestLicenseScreens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := newApp(t)
	admin, reader := a.user("admin@example.org", false), a.user("reader@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	a.addTeamMember(f.org, reader, tenant.TeamReader)
	a.pushLog4shell(f, 1, sbomFile(t, "portail-client.cdx16.json"))
	ref := a.mainRef(f.org.ID, f.p.ID)
	evaluate := func() {
		t.Helper()
		if err := a.tdb.App.InOrg(ctx, f.org.ID, func(tx *db.OrgTx) error {
			return a.licenses.EvaluateRef(ctx, tx, ref, f.p.ID)
		}); err != nil {
			t.Fatal(err)
		}
	}
	evaluate()

	ab := a.signIn(admin)
	project := "/o/org-a/projects/" + f.p.Slug + "/licenses"
	for _, lang := range []string{"fr", "en"} {
		for _, path := range []string{"/o/org-a/licenses", project} {
			pg := ab.get(path + "?lang=" + lang)
			if pg.status != http.StatusOK {
				t.Fatalf("%s (%s) : %d", path, lang, pg.status)
			}
			webtest.AssertAccessible(t, []byte(pg.body))
			webtest.AssertNoInlineCode(t, []byte(pg.body))
		}
	}
	// Politique par défaut : tout est accepté, aucun constat.
	if pg := ab.get("/o/org-a/licenses"); !strings.Contains(unescape(pg.body), "Aucun constat de licence") ||
		!strings.Contains(pg.body, `name="denied"`) {
		t.Fatal("page des licences sous la politique par défaut")
	}
	if pg := ab.get(project); !strings.Contains(pg.body, ">MIT<") || !strings.Contains(unescape(pg.body), "Acceptée") {
		t.Fatal("onglet Licences : MIT acceptée attendue")
	}

	bad := ab.post("/o/org-a/licenses", url.Values{"default": {"allowed"}, "denied": {"MIT AND GPL-2.0-only"}})
	if bad.status != http.StatusUnprocessableEntity || !strings.Contains(bad.body, `id="license-denied" name="denied" rows="4" spellcheck="false" aria-describedby="license-list-hint" aria-invalid="true"`) ||
		!strings.Contains(bad.body, "MIT AND GPL-2.0-only") {
		t.Fatalf("saisie refusée : %d", bad.status)
	}
	ok := ab.post("/o/org-a/licenses", url.Values{"default": {"allowed"}, "denied": {"MIT\nAGPL-3.0-only"}, "require_license": {"1"}})
	if ok.status != http.StatusSeeOther || ok.location != "/o/org-a/licenses?done=license_policy_saved" {
		t.Fatalf("enregistrement : %d %s", ok.status, ok.body)
	}
	p, err := a.licenses.Policy(ctx, f.org.ID)
	if err != nil || !p.RequireLicense || len(p.Denied) != 2 {
		t.Fatalf("politique enregistrée %+v : %v", p, err)
	}
	if n := countAudit(t, a, f, "license_policy.updated"); n != 1 {
		t.Fatalf("journal d'audit : %d", n)
	}
	evaluate()
	org := ab.get("/o/org-a/licenses")
	for _, want := range []string{"lodash", "express", "django", "Refusée", "À revoir", "Sans licence"} {
		if !strings.Contains(unescape(org.body), want) {
			t.Fatalf("constats de l'organisation : %q absent", want)
		}
	}
	denied := ab.get("/o/org-a/licenses?verdict=denied")
	if denied.status != http.StatusOK || strings.Contains(denied.body, "django") || !strings.Contains(denied.body, "lodash") {
		t.Fatalf("filtre refusées : %d", denied.status)
	}
	if pg := ab.get("/o/org-a/licenses?verdict=allowed"); pg.status != http.StatusNotFound {
		t.Fatalf("verdict inconnu : %d", pg.status)
	}

	// Recherche par licence.
	for _, lang := range []string{"fr", "en"} {
		pg := ab.get("/o/org-a/search?q=license%3Amit&lang=" + lang)
		if pg.status != http.StatusOK || !strings.Contains(pg.body, "lodash") || strings.Contains(pg.body, "django") {
			t.Fatalf("recherche license:mit (%s) : %d", lang, pg.status)
		}
		webtest.AssertAccessible(t, []byte(pg.body))
	}
	if pg := ab.get("/o/org-a/search?q=license%3AMIT+OR+X"); pg.status != http.StatusBadRequest {
		t.Fatalf("recherche par expression : %d", pg.status)
	}

	// Lecteur : constats visibles, politique en lecture seule.
	rb := a.signIn(reader)
	rp := rb.get("/o/org-a/licenses")
	if rp.status != http.StatusOK || strings.Contains(rp.body, `name="denied"`) || !strings.Contains(rp.body, "AGPL-3.0-only") {
		t.Fatalf("lecteur : %d", rp.status)
	}
	if pg := rb.post("/o/org-a/licenses", url.Values{"default": {"denied"}}); pg.status != http.StatusForbidden {
		t.Fatalf("lecteur qui enregistre : %d", pg.status)
	}
	if p, _ := a.licenses.Policy(ctx, f.org.ID); p.Default != license.StatusAllowed {
		t.Fatal("politique modifiée par un lecteur")
	}
}

func countAudit(t *testing.T, a *app, f repoFixture, action string) int {
	t.Helper()
	var n int
	if err := a.tdb.App.InOrg(context.Background(), f.org.ID, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_events WHERE action = $1`, action).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}
