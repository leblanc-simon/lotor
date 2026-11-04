//go:build integration

package policy

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/license"
	"leblanc.io/lotor/internal/sbom/schema"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/vuln"
)

// licensedSBOM est un inventaire aux licences variées : MIT, un choix MIT OR GPL, une
// AGPL, un composant sans licence et une licence en texte libre.
const licensedSBOM = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "metadata": {"timestamp": "2026-10-31T08:00:00Z", "component": {"bom-ref": "app", "type": "application", "name": "app", "version": "1.0.0"}},
  "components": [
    {"bom-ref": "a", "type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0",
     "licenses": [{"license": {"id": "MIT"}}]},
    {"bom-ref": "b", "type": "library", "name": "dual", "version": "2.0.0", "purl": "pkg:npm/dual@2.0.0",
     "licenses": [{"expression": "MIT OR GPL-3.0-only"}]},
    {"bom-ref": "c", "type": "library", "name": "ghostscript-js", "version": "9.0.0", "purl": "pkg:npm/ghostscript-js@9.0.0",
     "licenses": [{"license": {"id": "AGPL-3.0-only"}}]},
    {"bom-ref": "d", "type": "library", "name": "bare", "version": "0.1.0", "purl": "pkg:npm/bare@0.1.0"},
    {"bom-ref": "e", "type": "library", "name": "custom", "version": "1.0.0", "purl": "pkg:npm/custom@1.0.0",
     "licenses": [{"license": {"name": "Acme Proprietary"}}]}
  ]
}`

// withoutAGPL est le même inventaire après le retrait de la dépendance AGPL.
const withoutAGPL = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "metadata": {"timestamp": "2026-10-31T09:00:00Z", "component": {"bom-ref": "app", "type": "application", "name": "app", "version": "1.0.1"}},
  "components": [
    {"bom-ref": "a", "type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0",
     "licenses": [{"license": {"id": "MIT"}}]}
  ]
}`

// licenseEnv ajoute à env le service des licences, branché comme dans lotor-server : après
// chaque analyse, licences de la référence puis évaluation des politiques.
func licenseEnv(t *testing.T) (*env, *license.Service) {
	t.Helper()
	e := newEnv(t)
	v, err := schema.New()
	if err != nil {
		t.Fatal(err)
	}
	ls, err := license.NewService(license.Options{Pool: e.pool, Known: license.KnownFrom(v.CycloneDXLicenseIDs("1.6")),
		OnChange: OnLicenseChange})
	if err != nil {
		t.Fatal(err)
	}
	manager := vuln.NewManager(vuln.ManagerOptions{Pool: e.pool, Engine: e.engine, Dir: e.dir})
	e.analyzer = finding.NewAnalyzer(finding.Options{Pool: e.pool, Engine: manager, Blobs: e.ingest,
		OnAnalyzed: func(ctx context.Context, tx *db.OrgTx, refID, projectID uuid.UUID) error {
			if err := ls.OnAnalyzed(ctx, tx, refID, projectID); err != nil {
				return err
			}
			return OnAnalyzed(ctx, tx, refID, projectID)
		}})
	return e, ls
}

func licenseFindings(t *testing.T, ls *license.Service, org tenant.OrgID, project uuid.UUID) map[string]license.Finding {
	t.Helper()
	fs, err := ls.Findings(context.Background(), org, tenant.AllTeams(), project, "")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]license.Finding{}
	for _, f := range fs {
		out[f.Name] = f
	}
	return out
}

// TestLicenseDefaultPolicyAcceptsKnownLicenses : sans politique, toute licence SPDX connue
// est acceptée (décision de l'utilisateur) ; seule la licence en texte libre est à revoir,
// et un composant sans licence ne donne pas de constat.
func TestLicenseDefaultPolicyAcceptsKnownLicenses(t *testing.T) {
	e, ls := licenseEnv(t)
	e.publish(vuln.FixFixed)
	e.push(e.org, e.agent, e.repo, []byte(licensedSBOM))
	e.analyze(e.org, e.main)
	got := licenseFindings(t, ls, e.org, e.repo)
	if len(got) != 1 || got["custom"].Verdict != license.StatusReview || !slices.Equal(got["custom"].IDs, []string{"Acme Proprietary"}) {
		t.Fatalf("constats sous la politique par défaut : %+v", got)
	}
	usage, err := ls.ProjectLicenses(context.Background(), e.org, tenant.AllTeams(), e.repo)
	if err != nil || len(usage) != 5 || usage[0].Status != license.StatusReview || !usage[0].Unknown {
		t.Fatalf("licences du projet %+v : %v", usage, err)
	}
}

// TestLicensePolicyLifecycle : une politique qui refuse l'AGPL et revoit la GPL produit les
// constats attendus (le choix MIT OR GPL reste accepté), la règle de modèle « AGPL dans un
// produit distribué » ouvre une violation bloquante, et le retrait du composant résout
// constat et violation.
func TestLicensePolicyLifecycle(t *testing.T) {
	e, ls := licenseEnv(t)
	ctx := context.Background()
	e.exec(e.org, `UPDATE projects SET labels = '{"distribution": "public"}' WHERE id = $1`, e.repo)
	e.publish(vuln.FixFixed)
	snap := e.push(e.org, e.agent, e.repo, []byte(licensedSBOM))
	e.analyze(e.org, e.main)

	// Saisie refusée : une expression n'est pas un identifiant.
	err := ls.SetPolicy(ctx, actor, e.org, license.Policy{Default: license.StatusAllowed, Denied: []string{"MIT AND GPL-2.0-only"}})
	if fe, ok := account.IsValidation(err); !ok || fe.Field != "denied" {
		t.Fatalf("expression acceptée comme identifiant : %v", err)
	}
	p := license.Policy{Default: license.StatusAllowed, Denied: []string{"AGPL-3.0-only"}, Review: []string{"GPL-3.0-only"},
		RequireLicense: true}
	if err := ls.SetPolicy(ctx, actor, e.org, p); err != nil {
		t.Fatal(err)
	}
	if n := e.jobs(license.EvaluateOrgKind); n != 1 {
		t.Fatalf("réévaluation en file : %d", n)
	}
	if n := e.count(e.org, `SELECT count(*) FROM audit_events WHERE action = 'license_policy.updated'`); n != 1 {
		t.Fatalf("journal d'audit : %d", n)
	}
	if err := ls.EvaluateOrg(ctx, e.org); err != nil {
		t.Fatal(err)
	}
	got := licenseFindings(t, ls, e.org, e.repo)
	if len(got) != 3 || got["ghostscript-js"].Verdict != license.StatusDenied || got["bare"].Verdict != license.StatusReview ||
		!got["bare"].Missing || got["custom"].Verdict != license.StatusReview {
		t.Fatalf("constats : %+v", got)
	}
	if _, ok := got["dual"]; ok {
		t.Fatal("MIT OR GPL-3.0-only doit rester acceptée (OR retient le plus favorable)")
	}
	counts, err := ls.Counts(ctx, e.org, tenant.AllTeams(), uuid.Nil)
	if err != nil || counts[license.StatusDenied] != 1 || counts[license.StatusReview] != 2 {
		t.Fatalf("comptes %v : %v", counts, err)
	}
	// Une réévaluation sans changement n'écrit rien et ne remet pas l'évaluation en file.
	e.exec(e.org, `DELETE FROM jobs WHERE kind = $1`, ProjectKind)
	if err := ls.EvaluateOrg(ctx, e.org); err != nil {
		t.Fatal(err)
	}
	if n := e.jobs(ProjectKind); n != 0 {
		t.Fatalf("évaluation de politique remise en file sans changement : %d", n)
	}

	pol := e.fromTemplate(e.org, TemplateLicenseAGPL)
	e.evaluate(e.org, e.repo)
	if e.open(e.org, pol.ID) != 1 {
		t.Fatalf("violations ouvertes : %d", e.open(e.org, pol.ID))
	}
	page, err := e.policies.Violations(ctx, e.org, tenant.AllTeams(), Filter{}, "", 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].Subject != SubjectLicense || page.Items[0].VulnID != "AGPL-3.0-only" ||
		page.Items[0].Severity != string(license.StatusDenied) {
		t.Fatalf("violation %+v : %v", page.Items, err)
	}
	verdict, err := e.policies.Verdict(ctx, e.org, e.agent, snap)
	if err != nil || verdict.State != VerdictFail {
		t.Fatalf("verdict bloquant attendu : %+v %v", verdict, err)
	}

	// Le composant AGPL disparaît : constat et violation résolus.
	e.push(e.org, e.agent, e.repo, []byte(withoutAGPL))
	e.analyze(e.org, e.main)
	if got := licenseFindings(t, ls, e.org, e.repo); len(got) != 0 {
		t.Fatalf("constats après retrait : %+v", got)
	}
	e.evaluate(e.org, e.repo)
	if e.open(e.org, pol.ID) != 0 {
		t.Fatalf("violation non résolue : %d", e.open(e.org, pol.ID))
	}
	if n := e.count(e.org, `SELECT count(*) FROM license_findings WHERE status = 'resolved'`); n != 3 {
		t.Fatalf("constats résolus : %d", n)
	}
}

// TestLicenseIsolation : la politique et les constats d'une organisation ne se lisent pas
// depuis une autre, et une équipe invisible masque ses constats.
func TestLicenseIsolation(t *testing.T) {
	e, ls := licenseEnv(t)
	ctx := context.Background()
	e.publish(vuln.FixFixed)
	e.push(e.org, e.agent, e.repo, []byte(licensedSBOM))
	e.analyze(e.org, e.main)
	other, _, _, _ := e.newOrg("autre", `{}`)
	if p, err := ls.Policy(ctx, other); err != nil || p.Default != license.StatusAllowed || len(p.Denied) != 0 {
		t.Fatalf("politique d'une organisation vide : %+v %v", p, err)
	}
	if err := ls.SetPolicy(ctx, actor, e.org, license.Policy{Default: license.StatusDenied}); err != nil {
		t.Fatal(err)
	}
	if p, err := ls.Policy(ctx, other); err != nil || p.Default != license.StatusAllowed {
		t.Fatalf("politique lue d'une autre organisation : %+v %v", p, err)
	}
	if err := ls.EvaluateOrg(ctx, e.org); err != nil {
		t.Fatal(err)
	}
	if got := licenseFindings(t, ls, other, uuid.Nil); len(got) != 0 {
		t.Fatalf("constats d'une autre organisation : %+v", got)
	}
	if got := licenseFindings(t, ls, other, e.repo); len(got) != 0 {
		t.Fatalf("constats d'un projet d'une autre organisation : %+v", got)
	}
	if fs, err := ls.Findings(ctx, e.org, tenant.AllTeams(), uuid.Nil, ""); err != nil || len(fs) != 4 {
		t.Fatalf("constats sous « tout refuser » (sans licence : aucun constat) : %d %v", len(fs), err)
	}
	fs, err := ls.Findings(ctx, e.org, tenant.OnlyTeams(), uuid.Nil, "")
	if err != nil || len(fs) != 0 {
		t.Fatalf("constats sans équipe visible : %+v %v", fs, err)
	}
	if u, err := ls.ProjectLicenses(ctx, e.org, tenant.OnlyTeams(), e.repo); err != nil || len(u) != 0 {
		t.Fatalf("licences d'un projet invisible : %+v %v", u, err)
	}
}
