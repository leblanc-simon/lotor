//go:build integration

package web

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/api/gen/userapi"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/search"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/webtest"
)

// apiGet appelle l'API utilisateur avec un jeton personnel.
func (a *app) apiGet(token, path string) page {
	a.t.Helper()
	req, err := http.NewRequest(http.MethodGet, a.srv.URL+path, nil)
	if err != nil {
		a.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return a.browser().do(req)
}

var patPattern = regexp.MustCompile(`lotor_pat_[a-z2-7]{26}_[a-z2-7]{52}`)

// TestSearchScreenAndAPI : écran (deux langues, accessibilité, filtres reflétés dans
// l'URL), export, API identique à l'écran, jeton personnel, isolement.
func TestSearchScreenAndAPI(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin, viewer := a.user("admin@example.org", false), a.user("viewer@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	a.addTeamMember(f.org, viewer, tenant.TeamReader)
	s := a.analysis()
	s.publish(t, time.Now().Add(-48*time.Hour), log4shellRules()...)
	a.pushLog4shell(f, 1, sbomFile(t, "log4shell.cdx16.json"))
	if _, err := s.analyzer.Analyze(context.Background(), f.org.ID, a.mainRef(f.org.ID, f.p.ID)); err != nil {
		t.Fatal(err)
	}

	b := a.signIn(viewer)
	general := a.defaultTeam(f.org.ID).String()
	queries := []string{"", "q=log4j-core", "q=CVE-2021-44228", "q=CVE-2021-44228&resolved=1&kev=1&severity=critical",
		"q=pkg%3Amaven%2Forg.apache.logging.log4j%2Flog4j-core+vers%3Amaven%2F%3C2.15.0", "q=log4j&type=repo&origin=syft&sort=name",
		"q=absent-zzz", "q=lodash+vers%3Anpm%2F%3C1", "q=license%3AMIT", "q=CVE-2021-44228&triage=in_triage&team=" + general,
		"q=log4j-core&triage=affected", "q=log4j-core&at=" + time.Now().UTC().Format(time.DateOnly), "q=log4j-core&at=2026-01-01",
		"q=log4j-core&at=2099-01-01", "q=CVE-2021-44228&at=2026-01-01"}
	for _, lang := range []string{"fr", "en"} {
		for _, q := range queries {
			pg := b.get("/o/org-a/search?" + q + "&lang=" + lang)
			want := http.StatusOK
			if strings.Contains(q, "vers%3Anpm") || strings.Contains(q, "license") || strings.Contains(q, "log4j-core&triage") ||
				strings.Contains(q, "at=2099") || strings.Contains(q, "CVE-2021-44228&at") {
				want = http.StatusBadRequest
			}
			if pg.status != want {
				t.Fatalf("%s (%s) : %d", q, lang, pg.status)
			}
			webtest.AssertAccessible(t, []byte(pg.body))
			webtest.AssertNoInlineCode(t, []byte(pg.body))
		}
	}
	// À la date du jour : l'instantané courant, daté, sans vulnérabilités ; avant lui, rien.
	at := unescape(b.get("/o/org-a/search?q=log4j-core&at=" + time.Now().UTC().Format(time.DateOnly)).body)
	for _, want := range []string{"État des inventaires au", "Instantané retenu", "2.14.1", "dans 1 projet"} {
		if !strings.Contains(at, want) {
			t.Errorf("écran à une date sans %q", want)
		}
	}
	if strings.Contains(at, "Corrigée en") {
		t.Error("vulnérabilités montrées à une date passée")
	}
	if before := unescape(b.get("/o/org-a/search?q=log4j-core&at=2026-01-01").body); !strings.Contains(before, "Aucun") {
		t.Error("résultat avant le premier instantané")
	}
	body := unescape(b.get("/o/org-a/search?q=pkg%3Amaven%2Forg.apache.logging.log4j%2Flog4j-core+vers%3Amaven%2F%3C2.15.0").body)
	for _, want := range []string{"Interprété comme", "vers:maven/<2.15.0", "Portail client", "log4j-core", "2.14.1", "Critique",
		"KEV", "2.15.0", "1 occurrence", "dans 1 projet", "format=csv"} {
		if !strings.Contains(body, want) {
			t.Errorf("écran sans %q", want)
		}
	}
	// Recherche par vulnérabilité : statut de triage de chaque constat (lien vers sa fiche),
	// filtre de triage proposé ; filtre « équipe » et équipe de chaque projet.
	vulnBody := unescape(b.get("/o/org-a/search?q=CVE-2021-44228").body)
	for _, want := range []string{`name="triage"`, "Statut de triage", "À analyser", "/findings/", `name="team"`, "Équipe Général"} {
		if !strings.Contains(vulnBody, want) {
			t.Errorf("recherche par CVE sans %q", want)
		}
	}
	if strings.Contains(unescape(b.get("/o/org-a/search?q=log4j-core").body), `name="triage"`) {
		t.Error("filtre de triage proposé pour une recherche par composant")
	}
	if !strings.Contains(unescape(b.get("/o/org-a/search?q=log4j-core&triage=affected").body), "Filtre de triage sans objet") {
		t.Error("triage sur un composant : message absent")
	}
	if !strings.Contains(unescape(b.get("/o/org-a/search?q=lodash+vers%3Anpm%2F%3C1").body), "Plage sans purl") {
		t.Error("plage sur un nom : message absent")
	}
	// Le tableau de bord mène des composants répandus à leur recherche.
	if dash := b.get("/o/org-a").body; !strings.Contains(dash, "/o/org-a/search?q=pkg%3Amaven%2Forg.apache.logging.log4j%2Flog4j-core") {
		t.Error("composant répandu sans lien vers la recherche")
	}
	// Les filtres sont dans l'URL : la même URL redonne la même page, filtres cochés et
	// retirables.
	filtered := "/o/org-a/search?q=log4j-core&kev=1&type=repo"
	first, second := b.get(filtered), b.get(filtered)
	strip := regexp.MustCompile(`csrf_token" value="[^"]*"|nonce="[^"]*"`)
	if strip.ReplaceAllString(first.body, "") != strip.ReplaceAllString(second.body, "") {
		t.Error("une même URL donne deux pages différentes")
	}
	if !strings.Contains(first.body, `value="1" checked`) || !strings.Contains(unescape(first.body), "Retirer le filtre KEV uniquement") {
		t.Error("filtre KEV non reflété")
	}

	// Export : CSV et JSON, même contenu que l'écran.
	csvPage := b.get("/o/org-a/search/export?q=log4j-core&format=csv")
	if csvPage.status != http.StatusOK || !strings.HasPrefix(csvPage.header.Get("Content-Type"), "text/csv") ||
		!strings.Contains(csvPage.header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("export CSV : %d %v", csvPage.status, csvPage.header)
	}
	rows, err := csv.NewReader(strings.NewReader(csvPage.body)).ReadAll()
	if err != nil || len(rows) != 2 || rows[1][7] != "log4j-core" {
		t.Fatalf("CSV : %v, %v", rows, err)
	}
	// Un export à la fois par compte (SEC-07).
	if release, ok := a.exports.Acquire("user:" + itoa(viewer.ID)); !ok {
		t.Fatal("place d'export")
	} else {
		if pg := b.get("/o/org-a/search/export?q=log4j-core&format=csv"); pg.status != http.StatusTooManyRequests {
			t.Errorf("second export simultané du compte : %d", pg.status)
		}
		release()
	}
	if pg := b.get("/o/org-a/search/export?q=log4j-core&format=xml"); pg.status != http.StatusBadRequest {
		t.Errorf("format inconnu : %d", pg.status)
	}
	if pg := b.get("/o/org-a/search/export?q=log4j-core&format=json"); pg.status != http.StatusOK || !json.Valid([]byte(pg.body)) {
		t.Errorf("export JSON : %d", pg.status)
	}

	// Jeton personnel : créé depuis le profil, montré une fois, jamais journalisé.
	if pg := b.get("/account/tokens?lang=en"); pg.status != http.StatusOK {
		t.Fatalf("page des jetons : %d", pg.status)
	} else {
		webtest.AssertAccessible(t, []byte(pg.body))
		webtest.AssertNoInlineCode(t, []byte(pg.body))
	}
	// Sa création exige un code TOTP (réauthentification, SEC-02).
	if pg := b.post("/account/tokens", url.Values{"name": {"Script"}, "expires_in": {"30"}}); pg.status != http.StatusUnprocessableEntity ||
		patPattern.MatchString(pg.body) || !strings.Contains(pg.body, `id="tk-code"`) {
		t.Fatalf("création sans code TOTP : %d", pg.status)
	}
	created := b.post("/account/tokens", url.Values{"name": {"Script"}, "expires_in": {"30"}, "code": {a.code(viewer.ID, viewer.Secret)}})
	token := patPattern.FindString(created.body)
	if created.status != http.StatusOK || token == "" {
		t.Fatalf("création du jeton : %d", created.status)
	}
	webtest.AssertAccessible(t, []byte(created.body))
	if again := b.get("/account/tokens"); strings.Contains(again.body, token) || !strings.Contains(again.body, "Script") {
		t.Fatal("jeton réaffiché ou absent de la liste")
	}
	if bad := b.post("/account/tokens", url.Values{"name": {""}, "expires_in": {"30"}, "code": {a.code(viewer.ID, viewer.Secret)}}); bad.status != http.StatusUnprocessableEntity {
		t.Errorf("nom vide : %d", bad.status)
	}

	// L'API renvoie exactement les mêmes résultats que l'écran.
	for _, q := range []string{"q=log4j-core", "q=CVE-2021-44228&resolved=1", "q=GHSA-jfh8-c2jp-5v3q", "q=log4j-core&team=" + general,
		"q=CVE-2021-44228&triage=in_triage",
		"q=pkg%3Amaven%2Forg.apache.logging.log4j%2Flog4j-core+vers%3Amaven%2F%3C2.15.0", "q=log4j&type=host",
		"q=log4j-core&at=" + time.Now().UTC().Format(time.DateOnly)} {
		pg := a.apiGet(token, "/api/v1/orgs/org-a/search?"+q)
		if pg.status != http.StatusOK {
			t.Fatalf("API %s : %d %s", q, pg.status, pg.body)
		}
		var res userapi.SearchResult
		if err := json.Unmarshal([]byte(pg.body), &res); err != nil {
			t.Fatal(err)
		}
		req, _ := url.ParseQuery(q)
		screen, err := a.search.Search(context.Background(), f.org.ID, tenant.AllTeams(), mustRequest(t, req))
		if err != nil {
			t.Fatal(err)
		}
		if res.Occurrences != screen.Hits || res.Projects != screen.Projects || len(res.Groups) != len(screen.Groups) {
			t.Fatalf("%s : API %d/%d, écran %d/%d", q, res.Occurrences, res.Projects, screen.Hits, screen.Projects)
		}
		for i, g := range res.Groups {
			if g.Project.Slug != screen.Groups[i].Project.Slug || len(g.Hits) != len(screen.Groups[i].Hits) {
				t.Fatalf("%s : groupe %d différent", q, i)
			}
		}
		screenBody := unescape(b.get("/o/org-a/search?" + q).body)
		for _, g := range res.Groups {
			for _, h := range g.Hits {
				if !strings.Contains(screenBody, h.Component.Purl) {
					t.Errorf("%s : %s dans l'API, pas à l'écran", q, h.Component.Purl)
				}
			}
		}
	}
	if pg := a.apiGet(token, "/api/v1/orgs/org-a/search?q=CVE-2021-44228"); !strings.Contains(pg.body, `"status":"open"`) ||
		!strings.Contains(pg.body, `"fixed_versions":["2.15.0"]`) || !strings.Contains(pg.body, `"triage_status":"in_triage"`) ||
		!strings.Contains(pg.body, `"team":{"id":"`+general+`","name":"Général"}`) {
		t.Errorf("API CVE : %s", pg.body)
	}
	exp := a.apiGet(token, "/api/v1/orgs/org-a/search/export?q=log4j-core&format=csv")
	if exp.status != http.StatusOK || exp.body != csvPage.body {
		t.Errorf("export par l'API : %d", exp.status)
	}
	for q, key := range map[string]string{"q=": "error.search.empty", "q=lodash+vers%3Anpm%2F%3C1": "error.search.range_needs_purl",
		"q=x&type=container": "error.search.filter_invalid", "q=x&team=moi": "error.invalid_request",
		"q=log4j&triage=affected": "error.search.triage_vulnerability_only", "q=log4j&at=hier": "error.search.at_invalid",
		"q=CVE-2021-44228&at=2026-01-01": "error.search.at_components_only", "q=x&cursor=illisible": "error.invalid_cursor", "q=x&limit=500": "error.invalid_limit"} {
		if pg := a.apiGet(token, "/api/v1/orgs/org-a/search?"+q); pg.status != http.StatusBadRequest || !strings.Contains(pg.body, key) {
			t.Errorf("API %s : %d %s", q, pg.status, pg.body)
		}
	}

	// Un jeton ne donne jamais plus que son propriétaire : organisation dont il n'est pas
	// membre (ou inconnue) 404 ; sans jeton ou jeton faux 401 ; révoqué 401.
	stranger := a.user("stranger@example.org", false)
	a.org("org-b", stranger)
	for _, path := range []string{"/api/v1/orgs/org-b/search?q=log4j", "/api/v1/orgs/inconnue/search?q=log4j",
		"/api/v1/orgs/org-b/search/export?q=log4j&format=csv"} {
		if pg := a.apiGet(token, path); pg.status != http.StatusNotFound {
			t.Errorf("%s : %d", path, pg.status)
		}
	}
	for name, tok := range map[string]string{"sans": "", "faux": token[:len(token)-3] + "aaa", "agent": f.token} {
		if pg := a.apiGet(tok, "/api/v1/orgs/org-a/search?q=log4j"); pg.status != http.StatusUnauthorized ||
			!strings.Contains(pg.body, "error.token.invalid") {
			t.Errorf("jeton %s : %d %s", name, pg.status, pg.body)
		}
	}
	// Retiré de l'organisation : refusé à la requête suivante, sans attendre le jeton.
	if err := a.orgs.RemoveMember(context.Background(), audit.System, f.org.ID, viewer.ID); err != nil {
		t.Fatal(err)
	}
	if pg := a.apiGet(token, "/api/v1/orgs/org-a/search?q=log4j"); pg.status != http.StatusNotFound {
		t.Errorf("membre retiré : %d", pg.status)
	}
	a.addTeamMember(f.org, viewer, tenant.TeamReader)
	tokens, err := a.accounts.PersonalTokens(context.Background(), viewer.ID)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("jetons : %v, %v", tokens, err)
	}
	// Un autre compte ne révoque pas ce jeton.
	if pg := a.signIn(stranger).post("/account/tokens/"+tokens[0].ID.String()+"/revoke", nil); pg.status != http.StatusNotFound {
		t.Errorf("révocation par un autre compte : %d", pg.status)
	}
	if pg := b.post("/account/tokens/"+tokens[0].ID.String()+"/revoke", nil); pg.status != http.StatusSeeOther {
		t.Fatalf("révocation : %d", pg.status)
	}
	if pg := a.apiGet(token, "/api/v1/orgs/org-a/search?q=log4j"); pg.status != http.StatusUnauthorized ||
		!strings.Contains(pg.body, "error.token.revoked") {
		t.Errorf("jeton révoqué : %d %s", pg.status, pg.body)
	}
	if strings.Contains(a.logs.String(), token) || strings.Contains(a.logs.String(), token[len(token)-52:]) {
		t.Fatal("jeton personnel dans les journaux")
	}

	// Écran : un compte d'une autre organisation n'y voit rien (404, harnais complet dans
	// TestEveryOrgRouteAnswers404ToAnotherOrganization).
	sb := a.signIn(stranger)
	for _, path := range []string{"/o/org-a/search?q=log4j", "/o/org-a/search/export?q=log4j&format=csv"} {
		if pg := sb.get(path); pg.status != http.StatusNotFound {
			t.Errorf("%s : %d", path, pg.status)
		}
	}
	if body := sb.get("/o/org-b/search?q=log4j-core").body; strings.Contains(body, "Portail client") {
		t.Error("projet de A dans la recherche de B")
	}
}

func mustRequest(t *testing.T, v url.Values) search.Request {
	t.Helper()
	r, err := search.ParseRequest(v)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
