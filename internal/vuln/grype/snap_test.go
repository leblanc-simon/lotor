package grype

import (
	"context"
	"slices"
	"testing"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestUbuntuOfBase(t *testing.T) {
	for base, want := range map[string]string{
		"core": "16.04", "core18": "18.04", "core22": "22.04", "core24": "24.04",
		"": "", "snapd": "", "core2": "", "corex": "", "bare": "",
	} {
		if got := ubuntuOfBase(base); got != want {
			t.Errorf("%q : %q, attendu %q", base, got, want)
		}
	}
}

func TestReleaseInVersion(t *testing.T) {
	for v, want := range map[string]string{
		"1:2.44-1ubuntu0.22.04.3":  "22.04",
		"12.3.0-1ubuntu1~22.04.3":  "22.04",
		"2.5.3-2ubuntu3~22.04.1":   "22.04",
		"3.10.12-1~22.04.18":       "22.04",
		"1.2-3ubuntu0.24.10.1":     "24.10",
		"3.0.2-0ubuntu1.30":        "",
		"2.35-0ubuntu3.14":         "",
		"2.37.2-4ubuntu3.6":        "",
		"1:1.2.11.dfsg-2ubuntu9.2": "",
		"5.1-6ubuntu1.1":           "",
		"1.0~22.04":                "22.04",
		"1.0-1~22.05":              "",
	} {
		got := ""
		if m := releaseInVersion.FindStringSubmatch(v); m != nil {
			got = m[1]
		}
		if got != want {
			t.Errorf("%s : %q, attendu %q", v, got, want)
		}
	}
}

func TestProvidesBinary(t *testing.T) {
	for _, c := range []struct {
		deb, debVersion, bin, binVersion string
		want                             bool
	}{
		{"openssl", "3.0.2-0ubuntu1.30", "openssl", "3.0.2", true},
		{"bash", "5.1-6ubuntu1.1", "bash", "5.1.16", true},
		{"gzip", "1.10-4ubuntu4.2", "gzip", "1.10", true},
		{"python3.10", "3.10.12-1~22.04.18", "python", "3.10.12", true},
		{"zlib1g", "1:1.2.11.dfsg-2ubuntu9.2", "zlib1g", "1.2.11", false}, // 1.2.11.dfsg ne préfixe pas 1.2.11
		{"libcap2", "1:2.44-1ubuntu0.22.04.3", "libcap2", "2.44", true},
		{"openssl", "3.0.2-0ubuntu1.30", "openssl", "3.0.20", false},
		{"openssl", "3.0.2-0ubuntu1.30", "openssl", "3.1.0", false},
		{"libengine-pkcs11-openssl", "0.4.11-1", "openssl", "0.4.11", false},
		{"python3-minimal", "3.10.6-1~22.04.1", "python", "3.10.6", false},
		{"openssl", "3.0.2-0ubuntu1.30", "openssl", "", false},
		{"openssl", "", "openssl", "3.0.2", false},
	} {
		deb := pkg.Package{Name: c.deb, Version: c.debVersion}
		bin := pkg.Package{Name: c.bin, Version: c.binVersion}
		if got := providesBinary(deb, bin); got != c.want {
			t.Errorf("%s %s / %s %s : %v", c.deb, c.debVersion, c.bin, c.binVersion, got)
		}
	}
}

func TestSnapOf(t *testing.T) {
	for p, want := range map[string]string{
		"/snap/core22/3129/usr/share/snappy/dpkg.yaml":                      "/snap/core22/3129",
		"/snap/snapd/28332/snap/manifest.yaml":                              "/snap/snapd/28332",
		"/snap/core22":                                                      "",
		"/usr/share/doc/linux-modules-7.0.0-43-generic/changelog.Debian.gz": "",
		"/var/lib/snapd/snap/core22/1/x":                                    "",
	} {
		got, ok := snapOf(pkg.Package{Type: syftPkg.DebPkg, Locations: file.NewLocationSet(file.NewLocation(p))})
		if got != want || ok != (want != "") {
			t.Errorf("%s : %q, %v", p, got, ok)
		}
	}
}

// Vulnérabilités fictives propres aux snaps : connues de la seule Ubuntu 26.04 de l'hôte
// (hostOnly), ouverte selon Ubuntu 22.04 pour un paquet de snapd, snap sans base déclarée
// (snapdOpen).
const (
	hostOnlyCVE  = "CVE-2099-0004"
	snapdOpenCVE = "CVE-2099-0005"
)

// TestSnapsFollowTheirUbuntu : sur un hôte Ubuntu 26.04, les paquets des snaps sont
// comparés aux données de leur version d'Ubuntu (core22, base core22, versions en 22.04
// pour snapd) et non à celles de l'hôte ; le binaire openssl de core22 suit le paquet
// openssl du même snap (ADR 0065).
func TestSnapsFollowTheirUbuntu(t *testing.T) {
	d := openTestDB(t, []distroEntry{
		{ubuntu2204, "openssl", fixedCVE, "< 3.0.2-0ubuntu1.5", v6.FixedStatus, "3.0.2-0ubuntu1.5"},
		{ubuntu2204, "openssl", openCVE, "", v6.NotFixedStatus, ""},
		{ubuntu2604, "openssl", hostOnlyCVE, "< 3.5.0-1ubuntu1", v6.FixedStatus, "3.5.0-1ubuntu1"},
		{ubuntu2204, "libcap2", snapdOpenCVE, "", v6.NotFixedStatus, ""},
		{ubuntu2604, "libcap2", hostOnlyCVE, "< 1:2.75-1", v6.FixedStatus, "1:2.75-1"},
	}, []cpeEntry{
		{"a", "openssl", "openssl", fixedCVE, "< 3.0.4", "3.0.4"},
		{"a", "openssl", "openssl", openCVE, "< 3.0.4", "3.0.4"},
		{"a", "openssl", "openssl", nvdOnlyCVE, "< 3.0.4", "3.0.4"},
	})
	ms, _, err := d.Match(context.Background(), readTestSBOM(t, "ubuntu-26.04-snap.syft.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, m := range ms {
		got[m.VulnerabilityID] = append(got[m.VulnerabilityID], m.PURL)
	}
	for id, want := range map[string][]string{
		fixedCVE:     nil,
		hostOnlyCVE:  nil,
		openCVE:      {"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.30?arch=amd64"},
		nvdOnlyCVE:   {"pkg:generic/openssl@3.0.2"},
		snapdOpenCVE: {"pkg:deb/ubuntu/libcap2@1:2.44-1ubuntu0.22.04.3?arch=amd64"},
	} {
		slices.Sort(got[id])
		if !slices.Equal(got[id], want) {
			t.Errorf("%s : %v ; attendu %v", id, got[id], want)
		}
	}
}
