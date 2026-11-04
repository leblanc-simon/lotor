package license

import (
	"strings"
	"testing"
)

func known(id string) bool {
	switch strings.ToLower(id) {
	case "mit", "apache-2.0", "gpl-3.0-only", "gpl-2.0-only", "gpl-2.0-or-later", "agpl-3.0-only", "bsd-3-clause",
		"lgpl-2.1-only", "gpl-2.0", "classpath-exception-2.0":
		return true
	}
	return false
}

func TestParse(t *testing.T) {
	cases := map[string]string{
		"MIT":                                        "MIT",
		"mit or gpl-3.0-only":                        "mit OR gpl-3.0-only",
		"(MIT AND BSD-3-Clause) OR Apache-2.0":       "MIT AND BSD-3-Clause OR Apache-2.0",
		"MIT AND (BSD-3-Clause OR Apache-2.0)":       "MIT AND (BSD-3-Clause OR Apache-2.0)",
		"GPL-2.0+ WITH Classpath-exception-2.0":      "GPL-2.0+ WITH Classpath-exception-2.0",
		"LicenseRef-Proprietary":                     "LicenseRef-Proprietary",
		"DocumentRef-spdx-tool:LicenseRef-MIT-Style": "DocumentRef-spdx-tool:LicenseRef-MIT-Style",
	}
	for in, want := range cases {
		n, err := Parse(in)
		if err != nil || n.String() != want {
			t.Errorf("%q : %v %q", in, err, n)
		}
	}
	for _, bad := range []string{"", "MIT OR", "(MIT", "MIT)", "AND MIT", "MIT WITH", "Apache License 2.0", "MIT/X11",
		"LicenseRef-x+", "a:b", "MIT AND AND GPL-3.0-only", "MIT WITH (GPL)", strings.Repeat("MIT AND ", 100) + "MIT"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepté", bad)
		}
	}
	n, _ := Parse("(MIT OR Apache-2.0) AND MIT AND GPL-2.0+ WITH Classpath-exception-2.0")
	if got := strings.Join(n.IDs(), ","); got != "MIT,Apache-2.0,GPL-2.0" {
		t.Errorf("identifiants %s", got)
	}
}

// Tables d'expressions de la fiche : « MIT OR GPL-3.0-only » est conforme si l'une des deux
// est autorisée ; une conjonction vaut sa pire licence ; une licence inconnue n'est jamais
// autorisée.
func TestEvaluate(t *testing.T) {
	deny := Policy{Default: StatusAllowed, Denied: []string{"GPL-3.0-only", "AGPL-3.0-only"}, Review: []string{"LGPL-2.1-only"}}
	strict := Policy{Default: StatusDenied, Allowed: []string{"MIT", "apache-2.0"}}
	cases := []struct {
		p        Policy
		licenses []string
		want     Status
	}{
		{deny, []string{"MIT OR GPL-3.0-only"}, StatusAllowed},
		{deny, []string{"GPL-3.0-only OR MIT"}, StatusAllowed},
		{strict, []string{"MIT OR GPL-3.0-only"}, StatusAllowed},
		{strict, []string{"GPL-3.0-only OR AGPL-3.0-only"}, StatusDenied},
		{deny, []string{"MIT AND GPL-3.0-only"}, StatusDenied},
		{deny, []string{"MIT", "GPL-3.0-only"}, StatusDenied},
		{deny, []string{"MIT AND LGPL-2.1-only"}, StatusReview},
		{deny, []string{"LGPL-2.1-only OR GPL-3.0-only"}, StatusReview},
		{deny, []string{"(MIT AND AGPL-3.0-only) OR (LGPL-2.1-only AND BSD-3-Clause)"}, StatusReview},
		{deny, []string{"Apache License 2.0"}, StatusReview},
		{deny, []string{"LicenseRef-Proprietary"}, StatusReview},
		{deny, []string{"Unknown-License-1.0"}, StatusReview},
		{deny, []string{"Unknown-License-1.0 OR MIT"}, StatusAllowed},
		{strict, []string{"apache-2.0"}, StatusAllowed},
		{strict, []string{"BSD-3-Clause"}, StatusDenied},
		{deny, []string{"GPL-2.0+ WITH Classpath-exception-2.0"}, StatusAllowed},
		{Policy{Default: StatusAllowed, Denied: []string{"GPL-2.0"}}, []string{"GPL-2.0+"}, StatusDenied},
		{DefaultPolicy(), []string{"AGPL-3.0-only"}, StatusAllowed},
		{DefaultPolicy(), []string{"Proprietary"}, StatusReview},
		{DefaultPolicy(), nil, StatusAllowed},
		{Policy{Default: StatusAllowed, RequireLicense: true}, nil, StatusReview},
		{Policy{Default: StatusAllowed, Allowed: []string{"LicenseRef-Interne"}}, []string{"LicenseRef-Interne"}, StatusAllowed},
	}
	for _, c := range cases {
		if got := c.p.Evaluate(c.licenses, known); got.Status != c.want {
			t.Errorf("%v avec %+v : %s, attendu %s (%+v)", c.licenses, c.p, got.Status, c.want, got.Licenses)
		}
	}
	// L'alternative retenue nomme les licences qui décident.
	v := deny.Evaluate([]string{"GPL-3.0-only OR MIT"}, known)
	if ids := v.IDs(); len(ids) != 1 || ids[0] != "MIT" || v.Licenses[0].Reason != ReasonDefault {
		t.Errorf("licences retenues %+v", v.Licenses)
	}
	v = deny.Evaluate([]string{"MIT AND AGPL-3.0-only"}, known)
	if ids := v.IDs(); len(ids) != 2 || v.Licenses[1].Reason != ReasonListed {
		t.Errorf("licences d'une conjonction %+v", v.Licenses)
	}
}

func TestNormalize(t *testing.T) {
	p := Policy{Default: "x", Allowed: []string{" MIT ", "mit", "GPL-3.0-only"}, Denied: []string{"gpl-3.0-only"}}.Normalize()
	if p.Default != StatusAllowed || len(p.Allowed) != 1 || p.Allowed[0] != "MIT" || len(p.Denied) != 1 {
		t.Errorf("%+v", p)
	}
}
