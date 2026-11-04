package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func FuzzCanonicalPURL(f *testing.F) {
	for _, s := range []string{
		"pkg:deb/debian/openssl@3.0.14-1~deb12u2?arch=amd64&distro=debian-12",
		"pkg:rpm/redhat/tar@1.30-5.el8?epoch=2&arch=s390x&upstream=tar-1.30-5.el8.src.rpm",
		"pkg:npm/%40babel/runtime@7.24.7", "pkg:pypi/Django_Extensions@3.2.3?A=&b=c#sub/./x",
		"pkg:golang/github.com/BurntSushi/toml@v1.3.2", "PKG:maven/org.a/b@1?type=jar", "pkg:generic/a%20b@1%3A2",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := CanonicalPURL(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalidPURL) {
				t.Fatalf("erreur inattendue %v", err)
			}
			return
		}
		again, err := CanonicalPURL(p.String)
		if err != nil || again != p {
			t.Fatalf("non idempotent : %q → %+v → %+v (%v)", raw, p, again, err)
		}
		if !strings.HasPrefix(p.String, p.Base) || len(p.String) > MaxPURLLen {
			t.Fatalf("base %q hors de %q", p.Base, p.String)
		}
	})
}

// FuzzPrecheck compare Precheck à encoding/json : un objet JSON valide passe (bornes
// larges), un document refusé pour syntaxe n'est pas du JSON valide, et la profondeur
// mesurée est celle du document.
func FuzzPrecheck(f *testing.F) {
	for _, s := range []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","components":[]}]}`,
		`{"spdxVersion":"SPDX-2.3","packages":[]}`, `{"artifacts":[],"schema":{"version":"16"}}`,
		`{"a":[1,-2.5e3,true,null,"é\n"]}`, `{"a":`, `[1]`, `{"a":01}`, "{\"a\":\"\xff\"}",
	} {
		f.Add([]byte(s))
	}
	limits := Limits{MaxBytes: 1 << 20, MaxDepth: 1 << 10, MaxComponents: 1 << 20}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := Precheck(bytes.NewReader(data), limits)
		valid := json.Valid(data)
		if e, ok := AsError(err); ok && e.Key == KeyMalformed && valid {
			t.Fatalf("JSON valide refusé comme mal formé : %q", data)
		}
		if err == nil || (ok(err) && keyOf(err) == KeyUnsupportedFormat && startsWithBrace(data)) {
			if !valid {
				t.Fatalf("JSON invalide accepté : %q", data)
			}
			if d := depthOf(t, data); d != h.Depth {
				t.Fatalf("profondeur %d, attendu %d : %q", h.Depth, d, data)
			}
		}
	})
}

func ok(err error) bool { _, k := AsError(err); return k }

func keyOf(err error) string {
	e, _ := AsError(err)
	return e.Key
}

func startsWithBrace(data []byte) bool {
	t := bytes.TrimLeft(data, " \t\r\n")
	return len(t) > 0 && t[0] == '{'
}

func depthOf(t *testing.T, data []byte) int {
	dec := json.NewDecoder(bytes.NewReader(data))
	depth, maxDepth := 0, 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return maxDepth
		}
		if err != nil {
			t.Fatalf("référence : %v", err)
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			depth++
			maxDepth = max(maxDepth, depth)
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
}

// FuzzNormalize vérifie que la normalisation ne dépend pas de l'ordre des composants et
// que l'empreinte est stable.
func FuzzNormalize(f *testing.F) {
	f.Add("pkg:npm/a@1", "a", "1", "ia", "0.5", "pkg:NPM/a@1", "a", "1", "", "")
	f.Add("", "libfoo", "1.2", "", "", "pkg:generic/libfoo@1.2", "", "", "syft", "1")
	f.Fuzz(func(t *testing.T, p1, n1, v1, o1, c1, p2, n2, v2, o2, c2 string) {
		a := RawComponent{PURL: p1, Name: n1, Version: v1, Origin: o1, Confidence: c1, Licenses: []string{n2},
			Locations: []RawLocation{{Path: n1, AccessPath: v2, Evidence: o2}, {Path: v1, Layer: c2}}}
		b := RawComponent{PURL: p2, Name: n2, Version: v2, Origin: o2, Confidence: c2, Licenses: []string{v1},
			Locations: []RawLocation{{Path: v1, Evidence: o1}, {Path: n2, AccessPath: n1}}}
		x := Normalize(RawDocument{Components: []RawComponent{a, b}})
		y := Normalize(RawDocument{Components: []RawComponent{b, a}})
		if Fingerprint(x.Components) != Fingerprint(y.Components) || x.Skipped != y.Skipped {
			t.Fatalf("dépend de l'ordre :\n%+v\n%+v", x, y)
		}
		for _, c := range x.Components {
			if _, err := CanonicalPURL(c.PURL); err != nil {
				t.Fatalf("purl non canonique %q", c.PURL)
			}
		}
	})
}
