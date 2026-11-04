package search

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/version/grypeversion"
)

var cmp = grypeversion.New()

// TestParseDetectsTheKind : le type de requête est déduit de sa forme (§ 13).
func TestParseDetectsTheKind(t *testing.T) {
	cases := []struct {
		raw  string
		kind Kind
		want string
	}{
		{"log4j-core", KindName, "log4j-core"},
		{"  Visual   C++  ", KindName, "Visual C++"},
		{"pkg:npm/lodash", KindPURL, "pkg:npm/lodash"},
		{"PKG:npm/lodash@4.17.20", KindPURL, "pkg:npm/lodash@4.17.20"},
		{"pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12&arch=amd64", KindPURL,
			"pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12"},
		{"CVE-2021-44228", KindVulnerability, "CVE-2021-44228"},
		{"cve-2021-44228", KindVulnerability, "CVE-2021-44228"},
		{"GHSA-JFH8-C2JP-5V3Q", KindVulnerability, "GHSA-jfh8-c2jp-5v3q"},
		{"sha256:0925E8AD7BD971391A8B1E98BE8E87A6971919EB5B60C196485941C3C1DF089A", KindHash,
			"sha256:0925e8ad7bd971391a8b1e98be8e87a6971919eb5b60c196485941c3c1df089a"},
		{"0925e8ad7bd971391a8b1e98be8e87a6971919eb5b60c196485941c3c1df089a", KindHash,
			"sha256:0925e8ad7bd971391a8b1e98be8e87a6971919eb5b60c196485941c3c1df089a"},
	}
	for _, c := range cases {
		q, err := Parse(c.raw, cmp)
		if err != nil {
			t.Fatalf("%q : %v", c.raw, err)
		}
		var got string
		switch q.Kind {
		case KindName:
			got = q.Name
		case KindPURL:
			got = q.PURL.PURL.String
		case KindVulnerability:
			got = q.VulnID
		case KindHash:
			got = q.Hash
		}
		if q.Kind != c.kind || got != c.want {
			t.Errorf("%q : %s %q, attendu %s %q", c.raw, q.Kind, got, c.kind, c.want)
		}
		if len(q.Tokens()) == 0 {
			t.Errorf("%q : aucun élément interprété", c.raw)
		}
	}
}

func TestParsePURLWithRange(t *testing.T) {
	q, err := Parse("pkg:npm/lodash vers:npm/<4.17.21", cmp)
	if err != nil {
		t.Fatal(err)
	}
	if q.Kind != KindPURL || q.PURL.PURL.Base != "pkg:npm/lodash" || q.Range == nil || q.Range.String() != "vers:npm/<4.17.21" {
		t.Fatalf("%+v", q)
	}
	toks := q.Tokens()
	if len(toks) != 2 || toks[1].KindKey != "search.kind_range" {
		t.Fatalf("éléments %+v", toks)
	}
	// L'ordre des deux éléments ne compte pas.
	if q2, err := Parse("vers:npm/<4.17.21 pkg:npm/lodash", cmp); err != nil || q2.Range == nil {
		t.Fatalf("ordre inversé : %v", err)
	}
	q, err = Parse("pkg:deb/debian/openssl?arch=amd64", cmp)
	if err != nil || q.PURL.Qualifiers["arch"] != "amd64" || q.PURL.PURL.Version != "" {
		t.Fatalf("qualificatifs : %+v %v", q.PURL, err)
	}
}

// TestParseRejects : chaque refus porte une clé traduisible ; une plage ne s'applique
// qu'à un purl sans version, jamais à une recherche par nom.
func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"":                                             KeyEmpty,
		"   ":                                          KeyEmpty,
		strings.Repeat("a", MaxQueryLen+1):             KeyTooLong,
		strings.Repeat("é", MaxNameLen+1):              KeyTooLong,
		"lodash vers:npm/<4.17.21":                     KeyRangeNeedsPURL,
		"vers:npm/<4.17.21":                            KeyRangeNeedsPURL,
		"pkg:npm/a pkg:npm/b vers:npm/<1.0.0":          KeyRangeNeedsPURL,
		"pkg:npm/a vers:npm/<1.0.0 vers:npm/>0":        KeyRangeNeedsPURL,
		"pkg:npm/lodash@4.17.20 vers:npm/<5.0.0":       KeyRangeAndVersion,
		"pkg:npm/lodash vers:npm/<<1":                  KeyVersInvalid,
		"pkg:npm/lodash vers:cobol/<1":                 KeyVersScheme,
		"pkg:npm/lodash vers:npm/<1.0.0|>1.0.0":        KeyVersDuplicate,
		"pkg:npm/lodash vers:npm/<latest":              KeyVersVersion,
		"pkg:npm/lodash vers:maven/<1.0":               KeyVersMismatch,
		"pkg:npm":                                      KeyPURLInvalid,
		"pkg:npm/a pkg:npm/b":                          KeyPURLInvalid,
		"CVE-2021":                                     KeyVulnInvalid,
		"CVE-2021-44228 CVE-2021-45046":                KeyVulnInvalid,
		"GHSA-xxxx-yyyy-zzzz":                          KeyVulnInvalid,
		"sha256:abc":                                   KeyHashInvalid,
		"sha256:" + strings.Repeat("a", 64) + " x":     KeyHashInvalid,
		"license:":                                     KeyLicense,
		"license:MIT OR Apache-2.0":                    KeyLicense,
		"license:GPL-2.0 WITH Classpath-exception-2.0": KeyLicense,
		"\xff": KeyTooLong,
	}
	for raw, key := range cases {
		_, err := Parse(raw, cmp)
		if e, ok := IsError(err); !ok || e.Key != key {
			t.Errorf("%q : %v, attendu %s", raw, err, key)
		}
	}
	for _, k := range ErrorKeys() {
		if !strings.HasPrefix(k, "error.search.") {
			t.Errorf("clé %s hors de error.search", k)
		}
	}
}

// TestRequestRoundTripsThroughTheURL : les filtres sont reflétés dans l'URL ; relire
// l'URL redonne la même recherche (forme stable).
func TestRequestRoundTripsThroughTheURL(t *testing.T) {
	v := url.Values{
		"q": {"pkg:npm/lodash vers:npm/<4.17.21"}, "type": {"host", "repo", "repo"}, "label": {"Env=prod", "exposé-internet"},
		"origin": {"ia"}, "kev": {"1"}, "severity": {"none", "critical"}, "resolved": {"1"}, "sort": {"name"},
		"cursor": {"abc"}, "limit": {"50"},
		"team":   {"0192f5a8-0000-7000-8000-000000000002", "0192f5a8-0000-7000-8000-000000000001", "0192f5a8-0000-7000-8000-000000000002"},
		"triage": {"not_affected", "in_triage"},
	}
	r, err := ParseRequest(v)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Filters.ProjectKinds, []project.Kind{project.KindRepo, project.KindHost}) ||
		!slices.Equal(r.Filters.Labels, []string{"env=prod", "exposé-internet"}) ||
		!slices.Equal(r.Filters.Origins, []sbom.Origin{sbom.OriginIA}) || !r.Filters.KEV || !r.Filters.Resolved ||
		!slices.Equal(r.Filters.Severities, []string{"critical", "none"}) || r.Sort != SortName || r.Cursor != "abc" || r.Limit != 50 ||
		len(r.Filters.Teams) != 2 || r.Filters.Teams[0].String() != "0192f5a8-0000-7000-8000-000000000001" ||
		!slices.Equal(r.Filters.Triage, []triage.Status{triage.StatusInTriage, triage.StatusNotAffected}) {
		t.Fatalf("%+v", r)
	}
	if !r.Filters.Active() {
		t.Fatal("filtres actifs non vus")
	}
	again, err := ParseRequest(r.Values())
	if err != nil {
		t.Fatal(err)
	}
	if again.Values().Encode() != r.Values().Encode() {
		t.Fatalf("aller-retour : %s ≠ %s", again.Values().Encode(), r.Values().Encode())
	}
	if _, ok := r.Values()["cursor"]; ok {
		t.Fatal("curseur dans les paramètres partagés")
	}
	w := r.Without(ParamSeverity, "none")
	if !slices.Equal(w[ParamSeverity], []string{"critical"}) {
		t.Fatalf("retrait : %v", w)
	}
	if w := r.Without(ParamKEV, "1"); w.Get(ParamKEV) != "" {
		t.Fatalf("retrait de kev : %v", w)
	}
	def, _ := ParseRequest(url.Values{"q": {"x"}})
	if def.Sort != SortRisk || def.Values().Encode() != "q=x" || def.Filters.Active() {
		t.Fatalf("défauts : %+v", def)
	}
}

func TestParseRequestRejectsUnknownFilters(t *testing.T) {
	for _, v := range []url.Values{
		{"type": {"container"}}, {"origin": {"manual"}}, {"severity": {"severe"}}, {"kev": {"true"}},
		{"resolved": {"yes"}}, {"sort": {"-risk"}}, {"label": {"a=b,c=d"}}, {"label": {"=x"}}, {"label": {""}},
		{"label": {strings.Repeat("a", 300)}}, {"type": slices.Repeat([]string{"repo"}, 40)}, {"containers": {"oui"}},
		{"team": {"général"}}, {"team": {"00000000-0000-0000-0000-000000000000"}}, {"triage": {"ignored"}},
	} {
		if _, err := ParseRequest(v); err == nil {
			t.Errorf("%v accepté", v)
		} else if e, ok := IsError(err); !ok || e.Key != KeyFilterInvalid {
			t.Errorf("%v : %v", v, err)
		}
	}
	for _, l := range []string{"0", "101", "x"} {
		if _, err := ParseRequest(url.Values{"limit": {l}}); err == nil {
			t.Errorf("taille %s acceptée", l)
		}
	}
}

// TestContainersFilter : les conteneurs ne figurent que s'ils sont inclus, et
// s'ajoutent alors aux types retenus.
func TestContainersFilter(t *testing.T) {
	for _, tc := range []struct {
		v    url.Values
		want []string
	}{
		{url.Values{}, []string{"repo", "host"}},
		{url.Values{"containers": {"1"}}, []string{"repo", "host", "container"}},
		{url.Values{"type": {"host"}}, []string{"host"}},
		{url.Values{"type": {"host"}, "containers": {"1"}}, []string{"host", "container"}},
	} {
		r, err := ParseRequest(tc.v)
		if err != nil {
			t.Fatal(err)
		}
		if got := r.Filters.kinds(); !slices.Equal(got, tc.want) {
			t.Errorf("%v : %v", tc.v, got)
		}
		if r.Filters.Containers != (tc.v.Get("containers") == "1") || r.Values().Get("containers") != tc.v.Get("containers") {
			t.Errorf("%v : filtre relu %+v, %v", tc.v, r.Filters, r.Values())
		}
		if r.Filters.Active() != (len(tc.v) > 0) {
			t.Errorf("%v : actif %v", tc.v, r.Filters.Active())
		}
	}
}

func TestDefuseNeutralizesFormulas(t *testing.T) {
	for in, want := range map[string]string{"=1+1": "'=1+1", "+x": "'+x", "-2": "'-2", "@SUM": "'@SUM", "lodash": "lodash", "": ""} {
		if got := defuse(in); got != want {
			t.Errorf("%q : %q", in, got)
		}
	}
}

// Recherche par licence (T20) : un identifiant SPDX ou une référence LicenseRef-.
func TestParseLicense(t *testing.T) {
	for in, want := range map[string]string{"license:AGPL-3.0-only": "AGPL-3.0-only", "LICENSE:mit": "mit",
		"license:LicenseRef-Interne": "LicenseRef-Interne", "license:GPL-2.0+": "GPL-2.0+"} {
		q, err := Parse(in, nil)
		if err != nil || q.Kind != KindLicense || q.License != want || q.Tokens()[0].Value != want {
			t.Errorf("%q : %+v %v", in, q, err)
		}
	}
}
