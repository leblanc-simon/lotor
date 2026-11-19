//go:build grypedb

package grype

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"leblanc.io/lotor/internal/vuln"
)

// openReal ouvre la base réelle désignée par LOTOR_TEST_GRYPEDB_DIR (répertoire racine
// d'une base Grype v6 installée, qui contient 6/vulnerability.db).
func openReal(t *testing.T) vuln.Database {
	t.Helper()
	dir := os.Getenv("LOTOR_TEST_GRYPEDB_DIR")
	if dir == "" {
		t.Fatal("LOTOR_TEST_GRYPEDB_DIR : répertoire d'une base Grype v6 installée")
	}
	d, err := NewEngine().Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestRealLog4Shell(t *testing.T) {
	d := openReal(t)
	ms, vulns, err := d.Match(context.Background(), readTestSBOM(t, "log4shell.cdx16.json"))
	if err != nil {
		t.Fatal(err)
	}
	const purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	i := slices.IndexFunc(ms, func(m vuln.Match) bool { return m.VulnerabilityID == "CVE-2021-44228" })
	if i < 0 {
		t.Fatalf("CVE-2021-44228 absent de %d correspondances", len(ms))
	}
	m := ms[i]
	if m.PURL != purl || !slices.Contains(m.FixedVersions, "2.15.0") || m.Severity != vuln.SeverityCritical {
		t.Fatalf("correspondance %+v", m)
	}
	v := vulns["CVE-2021-44228"]
	if v.KEV == nil || v.EPSS == nil || v.EPSS.Score < 0.5 || v.BaseScore() != 10 || !slices.Contains(v.Aliases, "GHSA-jfh8-c2jp-5v3q") {
		t.Fatalf("fiche %+v", v)
	}
	if !strings.HasPrefix(v.Namespace, "nvd") || v.Description == "" || v.Risk < 90 {
		t.Fatalf("fiche NVD attendue : %+v", v)
	}
	// Log4Shell ne touche que log4j-core : log4j-api, de même version, n'est pas concerné.
	for _, m := range ms {
		if m.VulnerabilityID == "CVE-2021-44228" && m.PURL != purl {
			t.Errorf("CVE-2021-44228 rattachée à %s", m.PURL)
		}
	}
}

// TestRealDebian vérifie que distribution et paquets sources arrivent jusqu'à Grype : les
// correspondances viennent de l'espace de noms Debian 12, y compris pour libcurl4 et
// libssl3, rattachées par leur paquet source (curl, openssl).
func TestRealDebian(t *testing.T) {
	d := openReal(t)
	ms, vulns, err := d.Match(context.Background(), readTestSBOM(t, "debian-12.cdx15.json"))
	if err != nil {
		t.Fatal(err)
	}
	byPkg := map[string]int{}
	for _, m := range ms {
		name := strings.SplitN(strings.TrimPrefix(m.PURL, "pkg:deb/debian/"), "@", 2)[0]
		byPkg[name]++
		if !strings.HasPrefix(m.PURL, "pkg:deb/debian/") || !strings.Contains(m.PURL, "distro=debian-12") {
			t.Errorf("purl inattendu %s", m.PURL)
		}
		if m.Type != vuln.MatchExactDirect && m.Type != vuln.MatchExactIndirect {
			t.Errorf("%s : correspondance %s, attendue par l'écosystème deb", m.VulnerabilityID, m.Type)
		}
	}
	for _, p := range []string{"openssl", "libssl3", "curl", "libcurl4", "libc6", "tar"} {
		if byPkg[p] == 0 {
			t.Errorf("aucun constat pour %s (%v)", p, byPkg)
		}
	}
	// CVE-2024-5535 (openssl, corrigée en 3.0.15-1~deb12u1) touche openssl et libssl3,
	// paquet binaire de la source openssl.
	for _, p := range []string{"openssl", "libssl3"} {
		if !slices.ContainsFunc(ms, func(m vuln.Match) bool {
			return m.VulnerabilityID == "CVE-2024-5535" && strings.Contains(m.PURL, "/"+p+"@")
		}) {
			t.Errorf("CVE-2024-5535 attendue sur %s", p)
		}
	}
	if len(vulns) == 0 {
		t.Fatal("catalogue vide")
	}
	t.Logf("%d correspondances, %d vulnérabilités, par paquet : %v", len(ms), len(vulns), byPkg)
}

// TestRealConcurrent : la base ouverte sert plusieurs correspondances à la fois (workers).
func TestRealConcurrent(t *testing.T) {
	d := openReal(t)
	blob := readTestSBOM(t, "debian-12.cdx15.json")
	want, _, err := d.Match(context.Background(), blob)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			got, _, err := d.Match(context.Background(), blob)
			if err != nil || len(got) != len(want) {
				t.Errorf("correspondance concurrente : %d au lieu de %d (%v)", len(got), len(want), err)
			}
		})
	}
	wg.Wait()
}

// TestRealKernel : le noyau d'Ubuntu 26.04 et de Debian 12 suit les données de la
// distribution (ADR 0064). CVE-2026-53266, corrigée par Ubuntu en 7.0.0-31.31, ne touche
// plus 7.0.0-43.43 ; sur Debian 6.1.174-1, elle est encore ouverte (corrigée en
// 6.1.176-1) et signalée une seule fois, sur l'image ; CVE-2026-46300, corrigée par
// Debian en 6.1.174-1, a disparu, y compris du binaire /boot/vmlinuz-*.
func TestRealKernel(t *testing.T) {
	d := openReal(t)
	for _, c := range []struct {
		sbom   string
		absent []string
		// imageOnly : CVE attendue sur l'image seule, avec la version corrigée de la
		// distribution.
		imageOnly, image, fix string
	}{
		{sbom: "ubuntu-26.04-kernel.syft.json", absent: []string{"CVE-2026-53266"}},
		{sbom: "debian-12-kernel.syft.json", absent: []string{"CVE-2026-46300"},
			imageOnly: "CVE-2026-53266", image: "/linux-image-6.1.0-40-amd64@", fix: "6.1.176-1"},
	} {
		t.Run(c.sbom, func(t *testing.T) {
			ms, _, err := d.Match(context.Background(), readTestSBOM(t, c.sbom))
			if err != nil {
				t.Fatal(err)
			}
			byType := map[vuln.MatchType]int{}
			var image []vuln.Match
			for _, m := range ms {
				byType[m.Type]++
				if slices.Contains(c.absent, m.VulnerabilityID) {
					t.Errorf("%s signalée sur %s", m.VulnerabilityID, m.PURL)
				}
				if m.VulnerabilityID == c.imageOnly {
					image = append(image, m)
				}
			}
			if c.imageOnly != "" && (len(image) != 1 || !strings.Contains(image[0].PURL, c.image) ||
				!slices.Equal(image[0].FixedVersions, []string{c.fix})) {
				t.Errorf("%s : %+v ; attendue une fois sur %s, corrigée en %s", c.imageOnly, image, c.image, c.fix)
			}
			t.Logf("%d correspondances, par type : %v", len(ms), byType)
		})
	}
}
