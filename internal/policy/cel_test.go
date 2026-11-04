package policy

import (
	"context"
	"strings"
	"testing"
	"time"
)

func compiler(t *testing.T) *Compiler {
	t.Helper()
	c, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// kevProd est un constat qui viole le modèle « KEV sur un projet de production ».
func kevProd() FindingInput {
	return FindingInput{
		Project:   Project{Name: "api", Slug: "api", Kind: "repo", Labels: map[string]string{"env": "production"}},
		Component: Component{PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", Name: "log4j-core", Version: "2.14.1"},
		Finding: Finding{VulnID: "CVE-2021-44228", Severity: "critical", CVSS: 10, KEV: true, Actionable: true,
			FixAvailable: true, FixedVersions: []string{"2.15.0"}, FixAgeDays: 400, AgeDays: 400, FirstSeen: now.AddDate(-1, 0, 0)},
		Triage: Triage{Status: "in_triage"},
		Ref:    Ref{Kind: "branch", Name: "main"},
	}
}

func TestEveryTemplateCompiles(t *testing.T) {
	c := compiler(t)
	for _, tpl := range Templates() {
		if !tpl.Available {
			if _, ok := TemplateByKey(tpl.Key); ok {
				t.Errorf("modèle indisponible %s servi", tpl.Key)
			}
			continue
		}
		if _, err := c.Compile(tpl.Subject, tpl.Expression); err != nil {
			t.Errorf("%s : %v", tpl.Key, err)
		}
	}
}

// Modèle AGPL (T20) : une licence AGPL décisive dans un projet étiqueté « distribution ».
func TestLicenseTemplate(t *testing.T) {
	c := compiler(t)
	tpl, ok := TemplateByKey(TemplateLicenseAGPL)
	if !ok || tpl.Subject != SubjectLicense || !tpl.Blocking {
		t.Fatalf("modèle AGPL %+v", tpl)
	}
	p, err := c.Compile(tpl.Subject, tpl.Expression)
	if err != nil {
		t.Fatal(err)
	}
	in := LicenseInput{Project: Project{Name: "Portail", Labels: map[string]string{"distribution": ""}},
		Component: Component{Name: "ghostscript"}, License: License{Verdict: "denied", IDs: []string{"AGPL-3.0-only"}}}
	for name, c := range map[string]struct {
		mutate func(*LicenseInput)
		want   bool
	}{
		"AGPL distribuée":    {func(*LicenseInput) {}, true},
		"AGPL ou ultérieure": {func(in *LicenseInput) { in.License.IDs = []string{"AGPL-3.0-or-later"} }, true},
		"non distribuée":     {func(in *LicenseInput) { in.Project.Labels = nil }, false},
		"GPL":                {func(in *LicenseInput) { in.License.IDs = []string{"GPL-3.0-only"} }, false},
		"sans licence":       {func(in *LicenseInput) { in.License.IDs = nil; in.License.Missing = true }, false},
	} {
		x := in
		x.Project.Labels = map[string]string{"distribution": ""}
		c.mutate(&x)
		got, err := p.MatchLicense(context.Background(), x, now)
		if err != nil || got != c.want {
			t.Errorf("%s : %v %v", name, got, err)
		}
	}
	// Un champ de constat de vulnérabilité n'existe pas pour une licence.
	if _, err := c.Compile(SubjectLicense, `finding.kev`); err == nil {
		t.Error("finding accepté dans une règle de licence")
	}
	if _, err := p.MatchFinding(context.Background(), FindingInput{}, now); err == nil {
		t.Error("règle de licence évaluée sur un constat")
	}
}

func match(t *testing.T, c *Compiler, key string, in FindingInput) bool {
	t.Helper()
	tpl, _ := TemplateByKey(key)
	p, err := c.Compile(tpl.Subject, tpl.Expression)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := p.MatchFinding(context.Background(), in, now)
	if err != nil {
		t.Fatalf("%s : %v", key, err)
	}
	return ok
}

// TestTemplateKEVProduction : le modèle déclenche sur un jeu construit à la main, et pas
// en dehors.
func TestTemplateKEVProduction(t *testing.T) {
	c := compiler(t)
	if !match(t, c, TemplateKEVProduction, kevProd()) {
		t.Fatal("KEV en production non détecté")
	}
	for name, mutate := range map[string]func(*FindingInput){
		"staging":        func(in *FindingInput) { in.Project.Labels["env"] = "staging" },
		"sans étiquette": func(in *FindingInput) { in.Project.Labels = nil },
		"pas KEV":        func(in *FindingInput) { in.Finding.KEV = false },
		"non affecté":    func(in *FindingInput) { in.Finding.Actionable, in.Triage.Status = false, "not_affected" },
	} {
		in := kevProd()
		mutate(&in)
		if match(t, c, TemplateKEVProduction, in) {
			t.Errorf("%s : déclenché à tort", name)
		}
	}
}

func TestTemplateCriticalFix(t *testing.T) {
	c := compiler(t)
	in := kevProd()
	in.Finding.FixAgeDays = 31
	if !match(t, c, TemplateCriticalFix, in) {
		t.Fatal("critique avec correctif depuis 31 jours non détecté")
	}
	for name, mutate := range map[string]func(*FindingInput){
		"30 jours":       func(in *FindingInput) { in.Finding.FixAgeDays = 30 },
		"haute":          func(in *FindingInput) { in.Finding.Severity = "high" },
		"sans correctif": func(in *FindingInput) { in.Finding.FixAvailable, in.Finding.FixAgeDays = false, 0 },
		"risque accepté": func(in *FindingInput) { in.Finding.Actionable, in.Triage.Status = false, "risk_accepted" },
	} {
		in := kevProd()
		in.Finding.FixAgeDays = 31
		mutate(&in)
		if match(t, c, TemplateCriticalFix, in) {
			t.Errorf("%s : déclenché à tort", name)
		}
	}
}

func TestTemplateAgentSilent(t *testing.T) {
	c := compiler(t)
	tpl, _ := TemplateByKey(TemplateAgentSilent)
	p, err := c.Compile(tpl.Subject, tpl.Expression)
	if err != nil {
		t.Fatal(err)
	}
	for days, want := range map[int64]bool{0: false, 6: false, 7: true, 30: true} {
		got, err := p.MatchAgent(context.Background(), Agent{Name: "srv", SilentDays: days}, now)
		if err != nil || got != want {
			t.Errorf("%d jours : %v, %v", days, got, err)
		}
	}
	if _, err := p.MatchFinding(context.Background(), kevProd(), now); err == nil {
		t.Error("règle d'agent évaluée sur un constat")
	}
}

// TestInvalidRulesAreLocated : une règle invalide est refusée avec une clé traduisible et
// sa position.
func TestInvalidRulesAreLocated(t *testing.T) {
	c := compiler(t)
	for _, tc := range []struct {
		subject      Subject
		expr         string
		key          string
		line, column int
		name         string
	}{
		{SubjectFinding, "", KeyExprRequired, 0, 0, ""},
		{SubjectFinding, strings.Repeat("a", MaxExpression+1), KeyExprTooLong, 0, 0, ""},
		{SubjectFinding, "finding.kev &&", KeyExprSyntax, 1, 15, ""},
		{SubjectFinding, "finding.sevrity == \"critical\"", KeyExprUnknownField, 1, 8, "sevrity"},
		{SubjectFinding, "finding.kev &&\n  agent.silent_days > 3", KeyExprUnknownName, 2, 3, "agent"},
		{SubjectFinding, "finding.severity > 3", KeyExprType, 1, 18, ""},
		{SubjectFinding, "finding.severity", KeyExprNotBool, 0, 0, ""},
		{SubjectAgent, "project.name == \"x\"", KeyExprUnknownName, 1, 1, "project"},
		{SubjectFinding, "finding.fixed_versions.all(a, finding.fixed_versions.all(b, finding.fixed_versions.all(c, a == b && b == c)))",
			KeyExprTooCostly, 0, 0, ""},
	} {
		_, err := c.Compile(tc.subject, tc.expr)
		e, ok := IsExprError(err)
		if !ok {
			t.Errorf("%q : %v", tc.expr, err)
			continue
		}
		if e.Key != tc.key || e.Line != tc.line || e.Column != tc.column || e.Name != tc.name {
			t.Errorf("%q : %+v", tc.expr, e)
		}
	}
}

func TestRuntimeErrorsAndCache(t *testing.T) {
	c := compiler(t)
	p, err := c.Compile(SubjectFinding, `project.labels["env"] == "production"`)
	if err != nil {
		t.Fatal(err)
	}
	in := kevProd()
	in.Project.Labels = nil
	if _, err := p.MatchFinding(context.Background(), in, now); err == nil {
		t.Error("clé absente : erreur d'évaluation attendue")
	}
	again, _ := c.Compile(SubjectFinding, `project.labels["env"] == "production"`)
	if again != p {
		t.Error("programme recompilé au lieu d'être repris du cache")
	}
	vars := Variables(SubjectFinding)
	if len(vars) != 6 || !strings.Contains(strings.Join(vars[2].Fields, ","), "fix_age_days") {
		t.Errorf("variables %v", vars)
	}
}
