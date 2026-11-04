package web

import "testing"

func TestPackageVersion(t *testing.T) {
	cases := map[string]string{
		"v0.2.0":            "0.2.0",
		"v1.10.3":           "1.10.3",
		"v0.3.0-rc.1":       "0.3.0.rc.1",
		"v0.2.0-dirty":      "",
		"v0.2.0-3-g9c96c4f": "",
		"9c96c4f":           "",
		"develop":           "",
		"":                  "",
		"0.2.0":             "",
	}
	for in, want := range cases {
		if got := packageVersion(in); got != want {
			t.Errorf("packageVersion(%q) = %q, attendu %q", in, got, want)
		}
	}
}
