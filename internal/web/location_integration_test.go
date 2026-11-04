//go:build integration

package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/web/webtest"
)

// log4shellWithLocations : le SBOM log4shell, log4j-core trouvé à deux endroits.
func log4shellWithLocations(t *testing.T) []byte {
	return []byte(strings.Replace(string(sbomFile(t, "log4shell.cdx16.json")),
		`"purl": "`+log4jCore+`"`,
		`"purl": "`+log4jCore+`",
      "properties": [
        {"name": "syft:location:0:path", "value": "/app/lib/log4j-core-2.14.1.jar"},
        {"name": "syft:location:0:layerID", "value": "sha256:0123456789abcdef"},
        {"name": "syft:location:1:path", "value": "/opt/legacy/log4j-core-2.14.1.jar"}
      ]`, 1))
}

// TestLocationScreens : les emplacements d'un composant dans la liste des constats, la
// fiche d'un constat, la fiche composant et les composants d'un instantané ; accessibles,
// en deux langues.
func TestLocationScreens(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	s := a.analysis()
	s.publish(t, time.Now().Add(-48*time.Hour), log4shellRules()...)
	ctx := context.Background()
	ref := a.mainRef(f.org.ID, f.p.ID)
	a.pushLog4shell(f, 1, log4shellWithLocations(t))
	if out, err := s.analyzer.Analyze(ctx, f.org.ID, ref); err != nil || out != finding.OutcomeAnalyzed {
		t.Fatalf("analyse : %s, %v", out, err)
	}
	var snapshot string
	if err := a.tdb.App.InOrg(ctx, f.org.ID, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT snapshot_id FROM ref_current WHERE ref_id = $1`, ref).Scan(&snapshot)
	}); err != nil {
		t.Fatal(err)
	}
	base := "/o/org-a/projects/" + f.p.Slug
	findingPage := base + "/findings/" + a.findingID(f.org.ID, f.p.ID, "CVE-2021-44228").String()
	pages := map[string]string{
		"liste des constats":  base + "/findings",
		"fiche du constat":    findingPage,
		"fiche composant":     "/o/org-a/components/" + a.componentID(f.org.ID, log4jCore),
		"instantané":          base + "/snapshots/" + snapshot,
		"fiche vulnérabilité": "/o/org-a/vulnerabilities/CVE-2021-44228",
		"recherche":           "/o/org-a/search?q=log4j-core",
	}
	b := a.signIn(admin)
	for name, path := range pages {
		for _, lang := range []string{"fr", "en"} {
			sep := "?"
			if strings.Contains(path, "?") {
				sep = "&"
			}
			pg := b.get(path + sep + "lang=" + lang)
			if pg.status != http.StatusOK {
				t.Fatalf("%s (%s) : %d", name, lang, pg.status)
			}
			webtest.AssertAccessible(t, []byte(pg.body))
			webtest.AssertNoInlineCode(t, []byte(pg.body))
			body := unescape(pg.body)
			for _, want := range []string{"/app/lib/log4j-core-2.14.1.jar", "/opt/legacy/log4j-core-2.14.1.jar"} {
				if !strings.Contains(body, want) {
					t.Errorf("%s (%s) sans %q", name, lang, want)
				}
			}
		}
	}
	detail := unescape(b.get(findingPage).body)
	for _, want := range []string{"<dt>Emplacements</dt>", "couche sha256:0123456789abcdef"} {
		if !strings.Contains(detail, want) {
			t.Errorf("fiche du constat sans %q", want)
		}
	}
	// Un composant sans emplacement : rien sous son nom dans la liste, « Non renseigné »
	// dans la colonne de l'instantané.
	snap := unescape(b.get(pages["instantané"]).body)
	if !strings.Contains(snap, "<th scope=\"col\">Emplacement</th>") || !strings.Contains(snap, "Non renseigné") {
		t.Error("instantané : colonne des emplacements")
	}
}
