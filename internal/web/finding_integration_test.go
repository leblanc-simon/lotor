//go:build integration

package web

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/vuln"
	"leblanc.io/lotor/internal/vuln/vulntest"
	"leblanc.io/lotor/internal/web/webtest"
)

const log4jCore = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

// analysisSetup : une base de vulnérabilités factice cible, un analyseur sur la base de
// l'application.
type analysisSetup struct {
	checker  *vuln.Checker
	source   *vulntest.Source
	analyzer *finding.Analyzer
}

func (a *app) analysis() analysisSetup {
	a.t.Helper()
	dir := a.t.TempDir()
	engine := &vulntest.Engine{}
	s := analysisSetup{source: &vulntest.Source{}}
	s.checker = vuln.NewChecker(vuln.CheckerOptions{Pool: a.tdb.App, Source: s.source, Engine: engine, Dir: dir, MaxArchive: 1 << 20})
	manager := vuln.NewManager(vuln.ManagerOptions{Pool: a.tdb.App, Engine: engine, Dir: dir})
	s.analyzer = finding.NewAnalyzer(finding.Options{Pool: a.tdb.App, Engine: manager, Blobs: a.ingest})
	return s
}

func (s analysisSetup) publish(t *testing.T, built time.Time, rules ...vulntest.Rule) {
	t.Helper()
	s.source.Publish(vulntest.Archive(t, vulntest.Content{Built: built, Rules: rules}), built, "")
	if _, err := s.checker.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func log4shellRules() []vulntest.Rule {
	added := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)
	return []vulntest.Rule{
		{PURL: log4jCore, Vuln: vuln.Vulnerability{ID: "CVE-2021-44228", Namespace: "nvd:cpe", Severity: vuln.SeverityCritical,
			Description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.",
			Aliases:     []string{"GHSA-jfh8-c2jp-5v3q"}, CWEs: []string{"CWE-502"}, DataSource: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
			URLs: []string{"https://logging.apache.org/security.html", "javascript:alert(1)"},
			CVSS: []vuln.CVSS{{Source: "nvd@nist.gov", Type: "Primary", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", BaseScore: 10},
				{Version: "2.0", Vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C", BaseScore: 9.3}},
			EPSS: &vuln.EPSS{Score: 0.944, Percentile: 0.9999, Date: added}, KEV: &vuln.KEV{DateAdded: &added, Ransomware: true}, Risk: 99},
			Match: vuln.Match{FixedVersions: []string{"2.15.0"}, FixState: vuln.FixFixed, Risk: 99}},
		{PURL: "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1", Vuln: vuln.Vulnerability{ID: "CVE-2099-0002",
			Severity: vuln.SeverityLow, Risk: 2}, Match: vuln.Match{FixState: vuln.FixWontFix}},
	}
}

func (a *app) pushLog4shell(f repoFixture, commit int, body []byte) {
	a.t.Helper()
	r := a.upload(f.token, []part{contextPart(a.t, repoContext(f.p, commit)), {name: "sbom", contentType: "application/json", body: body}})
	if r.status != http.StatusAccepted {
		a.t.Fatalf("envoi : %d %s", r.status, r.body)
	}
	if err := a.ingest.Decode(context.Background(), f.org.ID, uuid.MustParse(decodeIngestion(a.t, r).ID)); err != nil {
		a.t.Fatal(err)
	}
}

func (a *app) mainRef(org tenant.OrgID, projectID uuid.UUID) uuid.UUID {
	a.t.Helper()
	var ref uuid.UUID
	if err := a.tdb.App.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT id FROM tracked_refs WHERE project_id = $1`, projectID).Scan(&ref)
	}); err != nil {
		a.t.Fatal(err)
	}
	return ref
}

func (a *app) componentID(org tenant.OrgID, purl string) string {
	a.t.Helper()
	var id string
	err := a.tdb.App.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT id FROM components WHERE purl = $1`, purl).Scan(&id)
	})
	if err != nil && err != sql.ErrNoRows {
		a.t.Fatal(err)
	}
	return id
}

// Écrans : onglet des constats (tri par risque, filtres sévérité et KEV, résolus), fiche
// vulnérabilité, fiche composant ; accessibilité, deux langues, isolement.
func TestFindingScreens(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin, viewer := a.user("admin@example.org", false), a.user("viewer@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	a.addTeamMember(f.org, viewer, tenant.TeamReader)
	s := a.analysis()
	s.publish(t, time.Now().Add(-48*time.Hour), log4shellRules()...)
	ctx := context.Background()
	ref := a.mainRef(f.org.ID, f.p.ID)
	a.pushLog4shell(f, 1, sbomFile(t, "log4shell.cdx16.json"))
	if out, err := s.analyzer.Analyze(ctx, f.org.ID, ref); err != nil || out != finding.OutcomeAnalyzed {
		t.Fatalf("analyse : %s, %v", out, err)
	}
	// Un second commit résout le constat de log4j-api (composant retiré).
	a.pushLog4shell(f, 2, []byte(strings.Replace(string(sbomFile(t, "log4shell.cdx16.json")),
		`"pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1"`, `"pkg:maven/org.apache.logging.log4j/log4j-api@2.17.1"`, -1)))
	if _, err := s.analyzer.Analyze(ctx, f.org.ID, ref); err != nil {
		t.Fatal(err)
	}
	comp := a.componentID(f.org.ID, log4jCore)
	base := "/o/org-a/projects/" + f.p.Slug
	vulnPage := "/o/org-a/vulnerabilities/CVE-2021-44228"
	pages := []string{base + "/findings", base + "/findings?status=resolved", base + "/findings?severity=critical&kev=1",
		base + "/findings?severity=low", vulnPage, vulnPage + "?state=resolved", "/o/org-a/components/" + comp,
		"/o/org-a/vulnerabilities/GHSA-jfh8-c2jp-5v3q"}
	for _, u := range []user{admin, viewer} {
		b := a.signIn(u)
		for _, lang := range []string{"fr", "en"} {
			for _, path := range pages {
				sep := "?"
				if strings.Contains(path, "?") {
					sep = "&"
				}
				pg := b.get(path + sep + "lang=" + lang)
				if pg.status != http.StatusOK {
					t.Fatalf("%s (%s) : %d %s", path, lang, pg.status, pg.body)
				}
				webtest.AssertAccessible(t, []byte(pg.body))
				webtest.AssertNoInlineCode(t, []byte(pg.body))
			}
		}
	}
	b := a.signIn(admin)
	tab := unescape(b.get(base + "/findings").body)
	for _, want := range []string{"Constats de main", "CVE-2021-44228", "KEV", "Critique", "10,0", "94,4", "log4j-core", "2.15.0", "99", "base du"} {
		if !strings.Contains(tab, want) {
			t.Errorf("onglet des constats sans %q", want)
		}
	}
	if strings.Contains(tab, "CVE-2099-0002") {
		t.Error("constat résolu parmi les ouverts")
	}
	// RGAA 3.1 et 10.9 : sévérité écrite dans les pastilles, référence affichée écrite.
	for _, want := range []string{`title="Critique" aria-hidden="true">Crit.</abbr>`, `<span class="visually-hidden">Critique </span><span>1</span>`,
		`<span class="chip">Affichée</span>`} {
		if !strings.Contains(tab, want) {
			t.Errorf("onglet des constats sans %q", want)
		}
	}
	// Liste des projets : constats ouverts à traiter du projet, même règle que la fiche.
	for _, lang := range []string{"fr", "en"} {
		pg := b.get("/o/org-a/projects?lang=" + lang)
		webtest.AssertAccessible(t, []byte(pg.body))
		webtest.AssertNoInlineCode(t, []byte(pg.body))
	}
	list := unescape(b.get("/o/org-a/projects").body)
	for _, want := range []string{"Constats ouverts", `<span class="visually-hidden">Critique </span><span>1</span>`,
		`<span class="visually-hidden">Faible </span><span>0</span>`, `<span class="kev"><span>KEV</span>`} {
		if !strings.Contains(list, want) {
			t.Errorf("liste des projets sans %q", want)
		}
	}
	if filtered := unescape(b.get(base + "/findings?severity=low").body); strings.Contains(filtered, "CVE-2021-44228") ||
		!strings.Contains(filtered, "Aucun constat ne correspond aux filtres") {
		t.Error("filtre de sévérité")
	}
	if resolved := unescape(b.get(base + "/findings?status=resolved").body); !strings.Contains(resolved, "CVE-2099-0002") ||
		!strings.Contains(resolved, "Composant retiré ou mis à jour") || !strings.Contains(resolved, "Ne sera pas corrigée") {
		t.Error("constats résolus")
	}
	vp := unescape(b.get(vulnPage + "?lang=en").body)
	for _, want := range []string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "Network", "Changed", "CWE-502", "logging.apache.org/security.html",
		"nvd.nist.gov/vuln/detail/CVE-2021-44228", "Known use", "94.4%", "Portail client", "1 open finding · 1 project", "1 other score"} {
		if !strings.Contains(vp, want) {
			t.Errorf("fiche vulnérabilité sans %q", want)
		}
	}
	if strings.Contains(vp, "javascript:") {
		t.Error("référence non http(s) affichée")
	}
	cp := unescape(b.get("/o/org-a/components/" + comp).body)
	for _, want := range []string{"log4j-core", "pkg:maven/org.apache.logging.log4j/log4j-core", "Vulnérable", "CVE-2021-44228", "Portail client",
		"1 constat", "1 projet", `<span class="status status--danger">Version vulnérable</span>`, `<span class="chip">Version de cette fiche</span>`} {
		if !strings.Contains(cp, want) {
			t.Errorf("fiche composant sans %q", want)
		}
	}
	for _, path := range []string{"/o/org-a/vulnerabilities/CVE-0000-0000", "/o/org-a/components/pas-un-uuid", "/o/org-a/components/" + uuid.NewString(),
		"/o/org-a/projects/absent/findings"} {
		if pg := b.get(path); pg.status != http.StatusNotFound {
			t.Errorf("%s : %d", path, pg.status)
		}
	}
	if pg := b.get(base + "/findings?cursor=illisible"); pg.status != http.StatusBadRequest {
		t.Errorf("curseur illisible : %d", pg.status)
	}

	// Une autre organisation : 404 sur les routes de A, rien de A dans la fiche publique
	// de la vulnérabilité, composant de A introuvable sous son propre slug.
	stranger := a.user("stranger@example.org", false)
	a.org("org-b", stranger)
	sb := a.signIn(stranger)
	for _, path := range []string{base + "/findings", vulnPage, "/o/org-a/components/" + comp, "/o/org-b/components/" + comp,
		"/o/org-b/projects/" + f.p.Slug + "/findings"} {
		if pg := sb.get(path); pg.status != http.StatusNotFound {
			t.Errorf("%s par une autre organisation : %d", path, pg.status)
		}
	}
	other := unescape(sb.get("/o/org-b/vulnerabilities/CVE-2021-44228").body)
	if !strings.Contains(other, "CVE-2021-44228") || strings.Contains(other, "Portail client") || strings.Contains(other, "log4j-core") {
		t.Error("constats de A visibles depuis B")
	}
}

// TestPaginationOfFindings : plus d'une page de constats, par risque décroissant.
func TestPaginationOfFindings(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	s := a.analysis()
	var rules []vulntest.Rule
	for i := range findingPageSize + 5 {
		rules = append(rules, vulntest.Rule{PURL: log4jCore, Vuln: vuln.Vulnerability{ID: "CVE-2030-" + itoa(int64(1000+i)),
			Severity: vuln.SeverityMedium}, Match: vuln.Match{Risk: float64(i % 100)}})
	}
	s.publish(t, time.Now().Add(-time.Hour), rules...)
	a.pushLog4shell(f, 1, sbomFile(t, "log4shell.cdx16.json"))
	if _, err := s.analyzer.Analyze(context.Background(), f.org.ID, a.mainRef(f.org.ID, f.p.ID)); err != nil {
		t.Fatal(err)
	}
	b := a.signIn(admin)
	first := b.get("/o/org-a/projects/" + f.p.Slug + "/findings")
	i := strings.Index(first.body, "cursor=")
	if first.status != http.StatusOK || i < 0 || strings.Count(first.body, "/vulnerabilities/CVE-2030-") != findingPageSize {
		t.Fatalf("première page : %d", first.status)
	}
	cursor := first.body[i+len("cursor="):]
	cursor = cursor[:strings.IndexAny(cursor, `"&`)]
	cursor, _ = url.QueryUnescape(unescape(cursor))
	second := b.get("/o/org-a/projects/" + f.p.Slug + "/findings?ref=" + a.mainRef(f.org.ID, f.p.ID).String() + "&cursor=" + url.QueryEscape(cursor))
	if second.status != http.StatusOK || strings.Count(second.body, "/vulnerabilities/CVE-2030-") != 5 {
		t.Fatalf("seconde page : %d, %d constats", second.status, strings.Count(second.body, "/vulnerabilities/CVE-2030-"))
	}
	if !strings.Contains(first.body, "CVE-2030-1054") || strings.Contains(first.body, "CVE-2030-1000\"") || !strings.Contains(second.body, "CVE-2030-1000\"") {
		t.Error("tri par risque décroissant")
	}
}

// TestVulnDBAdminScreen : état de la base et alerte d'âge sur les pages d'administration.
func TestVulnDBAdminScreen(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", true)
	a.org("org-a", admin)
	b := a.signIn(admin)
	for _, path := range []string{"/admin/vulndb", "/admin/users"} {
		pg := b.get(path)
		if pg.status != http.StatusOK || !strings.Contains(unescape(pg.body), "Aucune base de vulnérabilités") {
			t.Fatalf("%s sans base : %d", path, pg.status)
		}
		webtest.AssertAccessible(t, []byte(pg.body))
		webtest.AssertNoInlineCode(t, []byte(pg.body))
	}
	s := a.analysis()
	s.publish(t, time.Now().Add(-10*24*time.Hour-time.Hour))
	for _, lang := range []string{"fr", "en"} {
		pg := b.get("/admin/vulndb?lang=" + lang)
		if pg.status != http.StatusOK {
			t.Fatalf("%s : %d", lang, pg.status)
		}
		webtest.AssertAccessible(t, []byte(pg.body))
		webtest.AssertNoInlineCode(t, []byte(pg.body))
	}
	stale := unescape(b.get("/admin/orgs").body)
	if !strings.Contains(stale, "Base de vulnérabilités vieille de 10 jours") {
		t.Error("alerte d'âge absente")
	}
	s.publish(t, time.Now().Add(-time.Hour))
	fresh := unescape(b.get("/admin/vulndb").body)
	if strings.Contains(fresh, "vieille de") || !strings.Contains(fresh, "Cible") || !strings.Contains(fresh, "Précédente") ||
		!strings.Contains(fresh, "Téléchargée") || !strings.Contains(fresh, "v6.1.10") {
		t.Error("état de la base")
	}
}
