//go:build integration

package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/license"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// TestTeamFilterOnEverySurface est le test unique des surfaces de lecture : deux projets
// touchés par la même vulnérabilité, l'un dans l'équipe « Général », l'autre dans
// « Sécurité ». Chaque surface (liste et fiche des projets, recherche, exports de
// l'écran et de l'API, tableau de bord, fiches vulnérabilité et composant, licences, agents,
// équipes) ne montre à un membre que le projet de son équipe, rien à un membre sans
// équipe, et les deux à l'administrateur d'organisation.
func TestTeamFilterOnEverySurface(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	secu, err := a.orgs.CreateTeam(ctx, audit.System, f.org.ID, "Sécurité")
	if err != nil {
		t.Fatal(err)
	}
	back, err := a.projects.Create(ctx, audit.System, f.org.ID, project.Input{Kind: project.KindRepo, Name: "Back-office",
		Branches: []string{"main"}, TeamID: secu.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.projects.AssignAgent(ctx, audit.System, f.org.ID, back.Slug, &f.agentID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.agents.CreateRepoAgent(ctx, audit.System, f.org.ID, &secu.ID, "ci-secu", "initial", 90); err != nil {
		t.Fatal(err)
	}
	s := a.analysis()
	s.publish(t, time.Now().Add(-48*time.Hour), log4shellRules()...)
	fb := repoFixture{token: f.token, p: back, org: f.org, agentID: f.agentID}
	for _, fx := range []repoFixture{f, fb} {
		a.pushLog4shell(fx, 1, sbomFile(t, "log4shell.cdx16.json"))
		if _, err := s.analyzer.Analyze(ctx, f.org.ID, a.mainRef(f.org.ID, fx.p.ID)); err != nil {
			t.Fatal(err)
		}
	}
	component := a.componentID(f.org.ID, log4jCore)
	// Licences (T20) : les composants sans licence sont à revoir, pour qu'une surface en
	// montre les constats.
	if err := a.licenses.SetPolicy(ctx, audit.System, f.org.ID, license.Policy{Default: license.StatusAllowed, RequireLicense: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.licenses.EvaluateOrg(ctx, f.org.ID); err != nil {
		t.Fatal(err)
	}

	general, security, none := a.user("general@example.org", false), a.user("secu@example.org", false), a.user("none@example.org", false)
	a.addTeamMember(f.org, general, tenant.TeamReader)
	a.addMember(f.org, security, tenant.RoleMember)
	if err := a.orgs.AddTeamMember(ctx, audit.System, f.org.ID, secu.ID, security.Email, tenant.TeamReader); err != nil {
		t.Fatal(err)
	}
	a.addMember(f.org, none, tenant.RoleMember)

	type sees struct{ portail, back bool }
	cases := []struct {
		who  user
		want sees
	}{
		{admin, sees{true, true}},
		{general, sees{true, false}},
		{security, sees{false, true}},
		{none, sees{false, false}},
	}
	for _, c := range cases {
		b := a.signIn(c.who)
		_, pat, err := a.accounts.CreatePersonalToken(ctx, audit.System, c.who.ID, "script", 30)
		if err != nil {
			t.Fatal(err)
		}
		surfaces := map[string]page{
			"liste des projets":    b.get("/o/org-a/projects"),
			"recherche":            b.get("/o/org-a/search?q=log4j-core"),
			"recherche par CVE":    b.get("/o/org-a/search?q=CVE-2021-44228"),
			"export CSV":           b.get("/o/org-a/search/export?q=log4j-core&format=csv"),
			"tableau de bord":      b.get("/o/org-a"),
			"fiche vulnérabilité":  b.get("/o/org-a/vulnerabilities/CVE-2021-44228"),
			"licences":             b.get("/o/org-a/licenses"),
			"API de recherche":     a.apiGet(pat.Plaintext, "/api/v1/orgs/org-a/search?q=log4j-core"),
			"export JSON de l'API": a.apiGet(pat.Plaintext, "/api/v1/orgs/org-a/search/export?q=CVE-2021-44228&format=json"),
		}
		if c.want.portail || c.want.back {
			surfaces["fiche composant"] = b.get("/o/org-a/components/" + component)
		} else if p := b.get("/o/org-a/components/" + component); p.status != http.StatusNotFound {
			t.Errorf("%s : fiche composant %d, attendu 404", c.who.Email, p.status)
		}
		for name, p := range surfaces {
			if p.status != http.StatusOK {
				t.Errorf("%s : %s %d", c.who.Email, name, p.status)
				continue
			}
			body := unescape(p.body)
			if got := strings.Contains(body, "Portail client"); got != c.want.portail {
				t.Errorf("%s : %s montre « Portail client » : %v", c.who.Email, name, got)
			}
			if got := strings.Contains(body, "Back-office"); got != c.want.back {
				t.Errorf("%s : %s montre « Back-office » : %v", c.who.Email, name, got)
			}
		}
		// Fiches des projets : 404 hors de ses équipes.
		for slug, visible := range map[string]bool{f.p.Slug: c.want.portail, back.Slug: c.want.back} {
			want := http.StatusNotFound
			if visible {
				want = http.StatusOK
			}
			for _, path := range []string{"", "/findings", "/snapshots", "/licenses"} {
				if p := b.get("/o/org-a/projects/" + slug + path); p.status != want {
					t.Errorf("%s : /projects/%s%s %d, attendu %d", c.who.Email, slug, path, p.status, want)
				}
			}
		}
		// Agents et équipes : l'agent d'organisation n'est visible que de l'administrateur.
		agents := unescape(b.get("/o/org-a/agents").body)
		if got := strings.Contains(agents, "ci-secu"); got != c.want.back {
			t.Errorf("%s : agent de Sécurité visible : %v", c.who.Email, got)
		}
		if got := strings.Contains(agents, ">ci<"); got != (c.who.ID == admin.ID) {
			t.Errorf("%s : agent d'organisation visible : %v", c.who.Email, got)
		}
		teams := unescape(b.get("/o/org-a/teams").body)
		if got := strings.Contains(teams, "Sécurité"); got != c.want.back {
			t.Errorf("%s : équipe Sécurité visible : %v", c.who.Email, got)
		}
	}
}
