package grype

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"

	"leblanc.io/lotor/internal/vuln"
	"leblanc.io/lotor/internal/vuln/grype/grypetest"
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

// kernelArchive écrit une base qui décrit les trois vulnérabilités pour le source linux
// d'Ubuntu 26.04 et de Debian 12, et pour le CPE du noyau dans la NVD.
func kernelArchive(t *testing.T) string {
	t.Helper()
	nvd := &v6.Provider{ID: "nvd"}
	// Les fiches sont écrites d'abord : AddAffected* n'écrit pas le contenu d'une fiche.
	var handles []*v6.VulnerabilityHandle
	handle := func(p *v6.Provider, id string) *v6.VulnerabilityHandle {
		h := &v6.VulnerabilityHandle{Name: id, Status: v6.VulnerabilityActive, Provider: p,
			BlobValue: &v6.VulnerabilityBlob{ID: id, Description: "d " + id}}
		handles = append(handles, h)
		return h
	}
	distroRange := func(constraint string, state v6.FixStatus, fix string) []v6.Range {
		return []v6.Range{{Version: v6.Version{Type: "dpkg", Constraint: constraint}, Fix: &v6.Fix{Version: fix, State: state}}}
	}
	type entry struct {
		os     *v6.OperatingSystem
		cve    string
		ranges []v6.Range
	}
	ubuntu := &v6.OperatingSystem{Name: "ubuntu", ReleaseID: "ubuntu", MajorVersion: "26", MinorVersion: "04", Codename: "resolute"}
	debian := &v6.OperatingSystem{Name: "debian", ReleaseID: "debian", MajorVersion: "12", Codename: "bookworm"}
	entries := []entry{
		{ubuntu, fixedCVE, distroRange("< 7.0.0-31.31", v6.FixedStatus, "7.0.0-31.31")},
		{ubuntu, openCVE, distroRange("", v6.NotFixedStatus, "")},
		{debian, fixedCVE, distroRange("< 6.1.170-3", v6.FixedStatus, "6.1.170-3")},
		{debian, openCVE, distroRange("< 6.1.176-1", v6.FixedStatus, "6.1.176-1")},
	}
	var packages []*v6.AffectedPackageHandle
	for _, e := range entries {
		packages = append(packages, &v6.AffectedPackageHandle{
			Vulnerability: handle(&v6.Provider{ID: e.os.Name}, e.cve), OperatingSystem: e.os,
			Package:   &v6.Package{Ecosystem: "deb", Name: "linux"},
			BlobValue: &v6.PackageBlob{CVEs: []string{e.cve}, Ranges: e.ranges},
		})
	}
	var cpes []*v6.AffectedCPEHandle
	for _, id := range []string{fixedCVE, openCVE, nvdOnlyCVE} {
		cpes = append(cpes, &v6.AffectedCPEHandle{
			Vulnerability: handle(nvd, id),
			CPE:           &v6.Cpe{Part: "o", Vendor: "linux", Product: "linux_kernel"},
			BlobValue: &v6.PackageBlob{CVEs: []string{id}, Ranges: []v6.Range{{
				Version: v6.Version{Constraint: ">= 5.16, < 7.0.13"},
				Fix:     &v6.Fix{Version: "7.0.13", State: v6.FixedStatus},
			}}},
		})
	}
	path, err := grypetest.Archive(t.TempDir(), func(w v6.ReadWriter) error {
		if err := w.AddVulnerabilities(handles...); err != nil {
			return err
		}
		if err := w.AddAffectedPackages(packages...); err != nil {
			return err
		}
		return w.AddAffectedCPEs(cpes...)
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// TestKernelFollowsDistroData : sur Ubuntu et Debian, le noyau /boot/vmlinuz-* possédé par
// l'image signée n'est plus comparé aux seules plages amont de la NVD. Une CVE corrigée
// par la distribution disparaît, une CVE encore ouverte est signalée une fois, sur le
// paquet de la distribution et avec sa version corrigée, une CVE que la distribution ne
// suit pas reste signalée par CPE (ADR 0064).
func TestKernelFollowsDistroData(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "db")
	if _, err := NewEngine().Install(ctx, kernelArchive(t), dir); err != nil {
		t.Fatal(err)
	}
	d, err := NewEngine().Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

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

func readTestSBOM(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "sbom", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
