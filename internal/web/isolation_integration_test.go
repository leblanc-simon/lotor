//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

type route struct{ method, pattern string }

// routes renvoie toutes les routes de l'interface montées par le routeur.
func (a *app) routes() []route {
	a.t.Helper()
	var out []route
	err := chi.Walk(a.handler.(chi.Routes), func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, route{method, strings.TrimSuffix(pattern, "/")})
		return nil
	})
	if err != nil {
		a.t.Fatal(err)
	}
	return out
}

// fill remplace les paramètres d'un motif de route.
func fill(pattern string, params map[string]string) string {
	for k, v := range params {
		pattern = strings.ReplaceAll(pattern, "{"+k+"}", v)
	}
	if pattern == "" {
		return "/"
	}
	return pattern
}

// globalRoutes sont les seules routes de l'interface hors /o/{slug} : aucune ne sert de
// données d'organisation. Une nouvelle route ailleurs fait échouer le test, pour qu'elle
// soit placée sous /o/{slug} (et donc derrière la garde) ou ajoutée ici en connaissance de
// cause.
var globalRoutes = []string{
	"", "/login", "/login/2fa", "/logout", "/account", "/account/password", "/account/tokens",
	"/account/tokens/{tokenID}/revoke", "/account/invitations", "/account/invitations/{invitationID}/accept",
	"/account/invitations/{invitationID}/decline", "/account/security", "/account/security/recovery-codes",
	"/account/security/reconfigure",
	"/account/totp/setup", "/account/totp/enable", "/static/*", "/api/*", "/sitemap",
	"/signup", "/signup/verify/{token}", "/invitation/{token}",
}

func isGlobal(pattern string) bool {
	// /dt/ : point compatible Dependency-Track, authentifié par jeton d'agent comme /api/,
	// l'organisation venant du jeton ; son isolement est vérifié par TestDTUploadRefusals.
	if strings.HasPrefix(pattern, "/admin") || strings.HasPrefix(pattern, "/api/") || strings.HasPrefix(pattern, "/dt/") {
		return true
	}
	for _, g := range globalRoutes {
		if pattern == g {
			return true
		}
	}
	return false
}

// TestEveryOrgRouteAnswers404ToAnotherOrganization est le harnais d'isolement par route :
// chaque route de /o/{slug} (toutes méthodes), demandée par un administrateur de A avec le
// slug de B, d'une organisation inconnue ou d'une organisation archivée dont il est
// membre, répond 404 — jamais 403, jamais 200.
func TestEveryOrgRouteAnswers404ToAnotherOrganization(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	alice, bob := a.user("alice@example.org", false), a.user("bob@example.org", false)
	a.org("org-a", alice)
	orgB := a.org("org-b", bob)
	archived := a.org("org-archivee", alice)
	if err := a.orgs.SetArchived(context.Background(), audit.System, archived.ID, true); err != nil {
		t.Fatal(err)
	}
	b := a.signIn(alice)

	orgRoutes := 0
	for _, r := range a.routes() {
		if !strings.HasPrefix(r.pattern, "/o/{slug}") {
			if !isGlobal(r.pattern) {
				t.Errorf("route %s %s hors de /o/{slug} et de la liste des routes globales", r.method, r.pattern)
			}
			continue
		}
		orgRoutes++
		for _, slug := range []string{orgB.Slug, "inconnue", archived.Slug} {
			path := fill(r.pattern, map[string]string{"slug": slug, "userID": itoa(bob.ID), "project": "projet",
				"agentID": "0192d6a4-0000-7000-8000-000000000001", "tokenID": "0192d6a4-0000-7000-8000-000000000002",
				"snapshotID": "0192d6a4-0000-7000-8000-000000000003", "componentID": "0192d6a4-0000-7000-8000-000000000004",
				"vulnID": "CVE-2021-44228", "findingID": "0192d6a4-0000-7000-8000-000000000005",
				"decisionID": "0192d6a4-0000-7000-8000-000000000006"})
			var p page
			switch r.method {
			case http.MethodGet:
				p = b.get(path)
			case http.MethodPost:
				p = b.post(path, url.Values{"email": {alice.Email}, "role": {"admin"}, "name": {"x"}, "language": {"en"}})
			default:
				t.Fatalf("méthode %s non couverte par le harnais", r.method)
			}
			if p.status != http.StatusNotFound {
				t.Errorf("%s %s : %d, attendu 404", r.method, path, p.status)
			}
		}
	}
	if orgRoutes < 29 {
		t.Fatalf("%d routes d'organisation parcourues : le parcours du routeur est cassé", orgRoutes)
	}
	// Rien n'a été modifié chez B.
	members, err := a.orgs.Members(context.Background(), orgB.ID, "", 10)
	if err != nil || len(members.Items) != 1 || members.Items[0].UserID != bob.ID {
		t.Fatalf("membres de B : %+v, %v", members.Items, err)
	}
	if o, err := a.orgs.Get(context.Background(), orgB.ID); err != nil || o.Name != "Org org-b" || o.DefaultLanguage != "fr" {
		t.Fatalf("B modifiée : %+v, %v", o, err)
	}
}

// TestAdminRoutesAnswer404ToNonAdmins : l'administration de l'instance n'existe pas pour
// un compte ordinaire.
func TestAdminRoutesAnswer404ToNonAdmins(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", true)
	u := a.user("user@example.org", false)
	a.org("org-a", admin)
	b := a.signIn(u)
	n := 0
	for _, r := range a.routes() {
		if !strings.HasPrefix(r.pattern, "/admin") {
			continue
		}
		n++
		path := fill(r.pattern, map[string]string{"userID": itoa(admin.ID), "slug": "org-a", "action": "deactivate",
			"jobID": "0192d6a4-0000-7000-8000-000000000005"})
		var p page
		if r.method == http.MethodGet {
			p = b.get(path)
		} else {
			p = b.post(path, url.Values{"email": {u.Email}, "slug": {"x"}, "name": {"x"}, "admin_email": {u.Email}})
		}
		if p.status != http.StatusNotFound {
			t.Errorf("%s %s : %d, attendu 404", r.method, path, p.status)
		}
	}
	if n < 8 {
		t.Fatalf("%d routes d'administration parcourues", n)
	}
	if got, err := a.accounts.Get(context.Background(), admin.ID); err != nil || !got.Active {
		t.Fatalf("administrateur modifié : %+v, %v", got, err)
	}
}

// TestRolesInOrganization : un lecteur consulte mais ne modifie ni membres ni paramètres
// (403) ; un administrateur de l'organisation le peut, et ses actions sont journalisées.
func TestRolesInOrganization(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin, viewer, newcomer := a.user("admin@example.org", false), a.user("viewer@example.org", false), a.user("new@example.org", false)
	o := a.org("org-a", admin)
	a.addTeamMember(o, viewer, tenant.TeamReader)

	v := a.signIn(viewer)
	if p := v.get("/o/org-a/members"); p.status != http.StatusOK || !strings.Contains(p.body, admin.Email) {
		t.Fatalf("liste des membres pour un lecteur : %d", p.status)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/o/org-a/members"},
		{http.MethodPost, "/o/org-a/members/" + itoa(admin.ID) + "/role"},
		{http.MethodPost, "/o/org-a/members/" + itoa(admin.ID) + "/remove"},
		{http.MethodGet, "/o/org-a/settings"},
		{http.MethodPost, "/o/org-a/settings"},
		{http.MethodGet, "/o/org-a/audit"},
	} {
		var p page
		if c.method == http.MethodGet {
			p = v.get(c.path)
		} else {
			p = v.post(c.path, url.Values{"email": {newcomer.Email}, "role": {"admin"}, "name": {"Pris"}, "language": {"en"}})
		}
		if p.status != http.StatusForbidden || !strings.Contains(unescape(p.body), "Accès refusé") {
			t.Errorf("lecteur %s %s : %d", c.method, c.path, p.status)
		}
	}

	ad := a.signIn(admin)
	// SEC-09 : l'invitation répond de même, que l'adresse ait un compte ou non (sans envoi
	// de courriels, la page montre le lien à transmettre, T28).
	known := ad.post("/o/org-a/members", url.Values{"email": {newcomer.Email}, "role": {"member"}})
	unknown := ad.post("/o/org-a/members", url.Values{"email": {"absent@example.org"}, "role": {"member"}})
	if known.status != http.StatusOK || known.status != unknown.status || !inviteLinkRE.MatchString(known.body) ||
		!inviteLinkRE.MatchString(unknown.body) {
		t.Fatalf("invitations : %d, %d", known.status, unknown.status)
	}
	if p := ad.get("/o/org-a/members"); !strings.Contains(p.body, "absent@example.org") || !strings.Contains(p.body, newcomer.Email) {
		t.Errorf("invitations en attente absentes de la page des membres")
	}
	// Le compte invité n'est pas membre tant qu'il n'a pas accepté.
	nb := a.signIn(newcomer)
	if p := nb.get("/o/org-a"); p.status != http.StatusNotFound {
		t.Fatalf("invité avant acceptation : %d", p.status)
	}
	inv := nb.get("/account/invitations")
	m := regexp.MustCompile(`/account/invitations/([0-9a-f-]{36})/accept`).FindStringSubmatch(inv.body)
	if m == nil || !strings.Contains(inv.body, "Org org-a") {
		t.Fatalf("invitation absente de la page du compte :\n%s", inv.body)
	}
	if p := nb.post("/account/invitations/"+m[1]+"/accept", nil); p.status != http.StatusSeeOther || !strings.Contains(p.location, "invitation_accepted") {
		t.Fatalf("acceptation : %d %q", p.status, p.location)
	}
	if p := nb.get("/o/org-a"); p.status != http.StatusOK {
		t.Fatalf("membre après acceptation : %d", p.status)
	}
	if p := nb.post("/account/invitations/"+m[1]+"/accept", nil); p.status != http.StatusNotFound {
		t.Errorf("seconde acceptation : %d", p.status)
	}
	steps := []struct {
		path string
		form url.Values
		done string
	}{
		{"/o/org-a/members/" + itoa(newcomer.ID) + "/role", url.Values{"role": {"admin"}}, "member_updated"},
		{"/o/org-a/members/" + itoa(newcomer.ID) + "/remove", nil, "member_removed"},
		{"/o/org-a/settings", url.Values{"name": {"Atelier Nord"}, "language": {"en"}}, "org_saved"},
	}
	for _, s := range steps {
		if p := ad.post(s.path, s.form); p.status != http.StatusSeeOther || !strings.Contains(p.location, s.done) {
			t.Fatalf("%s : %d %q\n%s", s.path, p.status, p.location, p.body)
		}
	}
	// Le dernier administrateur ne peut pas se retirer ni se rétrograder.
	if p := ad.post("/o/org-a/members/"+itoa(admin.ID)+"/remove", nil); p.status != http.StatusUnprocessableEntity {
		t.Errorf("retrait du dernier administrateur : %d", p.status)
	}
	if p := ad.post("/o/org-a/members", url.Values{"email": {"pas une adresse"}, "role": {"member"}}); p.status != http.StatusUnprocessableEntity {
		t.Errorf("adresse invalide : %d", p.status)
	}
	// La langue de l'organisation s'applique à un membre sans préférence ni Accept-Language.
	if p := ad.get("/o/org-a"); p.header.Get("Content-Language") != "en" || !strings.Contains(p.body, "Open findings") {
		t.Errorf("langue de l'organisation : %q", p.header.Get("Content-Language"))
	}
	auditPage := ad.get("/o/org-a/audit")
	body := unescape(auditPage.body)
	for _, want := range []string{"new@example.org invited with the role member", "absent@example.org invited with the role member",
		"Invitation accepted by new@example.org (role member)", "Role of new@example.org: member → admin",
		"new@example.org removed from the organization", "Organization renamed from “Org org-a” to “Atelier Nord”"} {
		if !strings.Contains(body, want) {
			t.Errorf("journal de l'organisation sans « %s »", want)
		}
	}
}

// TestOrgResourcesOfAnotherOrganizationAnswer404 : dans sa propre organisation, un
// administrateur de A qui désigne un projet, un agent ou un jeton de B reçoit 404 sur
// chaque route qui en prend un, et rien ne change chez B.
func TestOrgResourcesOfAnotherOrganizationAnswer404(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := newApp(t)
	alice, bob := a.user("alice@example.org", false), a.user("bob@example.org", false)
	a.org("org-a", alice)
	orgB := a.org("org-b", bob)
	if _, err := a.projects.Create(ctx, audit.System, orgB.ID, a.inTeam(orgB.ID, project.Input{Kind: project.KindRepo, Name: "projet-b", Branches: []string{"main"}})); err != nil {
		t.Fatal(err)
	}
	agB, _, err := a.agents.CreateRepoAgent(ctx, audit.System, orgB.ID, nil, "ci-b", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.projects.AssignAgent(ctx, audit.System, orgB.ID, "projet-b", &agB.ID); err != nil {
		t.Fatal(err)
	}
	agB, err = a.agents.Get(ctx, orgB.ID, tenant.AllTeams(), agB.ID)
	if err != nil {
		t.Fatal(err)
	}
	enrB, _, err := a.agents.CreateEnrollment(ctx, audit.System, orgB.ID, a.enrollTeam(orgB.ID, agent.EnrollmentInput{Name: "parc", LifetimeHours: 24, MaxUses: 1}))
	if err != nil {
		t.Fatal(err)
	}
	b := a.signIn(alice)

	n := 0
	for _, r := range a.routes() {
		if !strings.HasPrefix(r.pattern, "/o/{slug}") ||
			!strings.Contains(r.pattern, "{project}") && !strings.Contains(r.pattern, "{agentID}") && !strings.Contains(r.pattern, "{tokenID}") {
			continue
		}
		n++
		token := agB.Tokens[0].ID.String()
		if strings.HasPrefix(r.pattern, "/o/{slug}/enrollment-tokens") {
			token = enrB.ID.String()
		}
		path := fill(r.pattern, map[string]string{"slug": "org-a", "project": "projet-b", "agentID": agB.ID.String(), "tokenID": token})
		var p page
		if r.method == http.MethodGet {
			p = b.get(path)
		} else {
			p = b.post(path, url.Values{"name": {"x"}, "branches": {"main"}, "agent": {agB.ID.String()}, "expires_in": {"30"}})
		}
		if p.status != http.StatusNotFound {
			t.Errorf("%s %s : %d, attendu 404", r.method, path, p.status)
		}
	}
	if n < 11 {
		t.Fatalf("%d routes de ressources parcourues", n)
	}
	got, err := a.agents.Get(ctx, orgB.ID, tenant.AllTeams(), agB.ID)
	if err != nil || got.DisabledAt != nil || len(got.Tokens) != 1 || got.Tokens[0].RevokedAt != nil {
		t.Fatalf("agent de B modifié : %+v %v", got, err)
	}
	pb, err := a.projects.Get(ctx, orgB.ID, tenant.AllTeams(), "projet-b")
	if err != nil || pb.ArchivedAt != nil || pb.Name != "projet-b" || pb.Agent == nil {
		t.Fatalf("projet de B modifié : %+v %v", pb, err)
	}
	list, err := a.agents.Enrollments(ctx, orgB.ID, tenant.AllTeams())
	if err != nil || len(list) != 1 || list[0].RevokedAt != nil {
		t.Fatalf("jeton d'inscription de B modifié : %+v %v", list, err)
	}
}
