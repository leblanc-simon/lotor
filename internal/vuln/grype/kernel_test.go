package grype

import (
	"context"
	"slices"
	"strings"
	"testing"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"

	"leblanc.io/lotor/internal/vuln"
)

func TestUnsignedKernelSource(t *testing.T) {
	for _, c := range []struct {
		distro distro.Type
		source string
		want   string
	}{
		{distro.Ubuntu, "linux-signed", "linux"},
		{distro.Ubuntu, "linux-signed-hwe-6.8", "linux-hwe-6.8"},
		{distro.Ubuntu, "linux-signed-oem-7.0", "linux-oem-7.0"},
		{distro.Debian, "linux-signed-amd64", "linux"},
		{distro.Debian, "linux-signed-arm64", "linux"},
		{distro.Debian, "linux-signed-6.1-amd64", "linux-6.1"},
		{distro.Debian, "linux-signed", ""},         // pas d'architecture : inconnu de Debian
		{distro.Debian, "linux-signed-riscv64", ""}, // architecture non prévue
		{distro.Ubuntu, "linux", ""},
		{distro.Ubuntu, "linux-signedx", ""},
		{distro.Ubuntu, "openssl", ""},
		{distro.RedHat, "linux-signed", ""},
	} {
		got, ok := unsignedKernelSource(c.distro, c.source)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%s %s : %q, %v ; attendu %q", c.distro, c.source, got, ok, c.want)
		}
	}
}

// Vulnérabilités fictives : corrigée par la distribution (fixed), encore ouverte selon la
// distribution (open), inconnue de la distribution (nvdOnly). La NVD les place toutes
// avant la 7.0.13 amont, donc sur les deux noyaux des jeux d'essai.
const (
	fixedCVE   = "CVE-2099-0001"
	openCVE    = "CVE-2099-0002"
	nvdOnlyCVE = "CVE-2099-0003"
)

var (
	ubuntu2604 = &v6.OperatingSystem{Name: "ubuntu", ReleaseID: "ubuntu", MajorVersion: "26", MinorVersion: "04", Codename: "resolute"}
	ubuntu2204 = &v6.OperatingSystem{Name: "ubuntu", ReleaseID: "ubuntu", MajorVersion: "22", MinorVersion: "04", Codename: "jammy"}
	debian12   = &v6.OperatingSystem{Name: "debian", ReleaseID: "debian", MajorVersion: "12", Codename: "bookworm"}
)

// kernelDB décrit les trois vulnérabilités pour le source linux d'Ubuntu 26.04 et de
// Debian 12, et pour le CPE du noyau dans la NVD.
func kernelDB(t *testing.T) vuln.Database {
	return openTestDB(t, []distroEntry{
		{ubuntu2604, "linux", fixedCVE, "< 7.0.0-31.31", v6.FixedStatus, "7.0.0-31.31"},
		{ubuntu2604, "linux", openCVE, "", v6.NotFixedStatus, ""},
		{debian12, "linux", fixedCVE, "< 6.1.170-3", v6.FixedStatus, "6.1.170-3"},
		{debian12, "linux", openCVE, "< 6.1.176-1", v6.FixedStatus, "6.1.176-1"},
	}, []cpeEntry{
		{"o", "linux", "linux_kernel", fixedCVE, ">= 5.16, < 7.0.13", "7.0.13"},
		{"o", "linux", "linux_kernel", openCVE, ">= 5.16, < 7.0.13", "7.0.13"},
		{"o", "linux", "linux_kernel", nvdOnlyCVE, ">= 5.16, < 7.0.13", "7.0.13"},
	})
}

// TestKernelFollowsDistroData : sur Ubuntu et Debian, le noyau /boot/vmlinuz-* possédé par
// l'image signée n'est plus comparé aux seules plages amont de la NVD. Une CVE corrigée
// par la distribution disparaît, une CVE encore ouverte est signalée une fois, sur le
// paquet de la distribution et avec sa version corrigée, une CVE que la distribution ne
// suit pas reste signalée par CPE (ADR 0064).
func TestKernelFollowsDistroData(t *testing.T) {
	ctx := context.Background()
	d := kernelDB(t)

	for _, c := range []struct {
		sbom, kernel string
		// open : paquets de la distribution signalés pour openCVE, avec leur correctif.
		open    []string
		openFix string
	}{
		{"ubuntu-26.04-kernel.syft.json", "pkg:generic/linux-kernel@7.0.0-43-generic",
			[]string{"linux-image-7.0.0-43-generic", "linux-modules-7.0.0-43-generic"}, ""},
		{"debian-12-kernel.syft.json", "pkg:generic/linux-kernel@6.1.0-40-amd64",
			[]string{"linux-image-6.1.0-40-amd64"}, "6.1.176-1"},
	} {
		t.Run(c.sbom, func(t *testing.T) {
			ms, _, err := d.Match(ctx, readTestSBOM(t, c.sbom))
			if err != nil {
				t.Fatal(err)
			}
			got := map[string][]string{}
			for _, m := range ms {
				got[m.VulnerabilityID] = append(got[m.VulnerabilityID], m.PURL)
				if m.VulnerabilityID == openCVE && (m.Type != vuln.MatchExactIndirect ||
					!slices.Equal(m.FixedVersions, cleanList([]string{c.openFix}, 64))) {
					t.Errorf("%s : %s, correctif %v ; attendu exact-indirect, %q", m.PURL, m.Type, m.FixedVersions, c.openFix)
				}
			}
			if len(got[fixedCVE]) != 0 {
				t.Errorf("%s corrigée par la distribution, signalée sur %v", fixedCVE, got[fixedCVE])
			}
			if len(got[openCVE]) != len(c.open) {
				t.Errorf("%s signalée sur %v ; attendue sur %v seulement", openCVE, got[openCVE], c.open)
			}
			for _, name := range c.open {
				if !slices.ContainsFunc(got[openCVE], func(p string) bool { return strings.Contains(p, "/"+name+"@") }) {
					t.Errorf("%s absente de %s : %v", openCVE, name, got[openCVE])
				}
			}
			if !slices.Equal(got[nvdOnlyCVE], []string{c.kernel}) {
				t.Errorf("%s : %v ; attendue par CPE sur %s", nvdOnlyCVE, got[nvdOnlyCVE], c.kernel)
			}
		})
	}
}
