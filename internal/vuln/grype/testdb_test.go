package grype

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v6 "github.com/anchore/grype/grype/db/v6"

	"leblanc.io/lotor/internal/vuln"
	"leblanc.io/lotor/internal/vuln/grype/grypetest"
)

// distroEntry : un paquet source d'une distribution touché par une vulnérabilité.
type distroEntry struct {
	os         *v6.OperatingSystem
	pkg, cve   string
	constraint string
	state      v6.FixStatus
	fix        string
}

// cpeEntry : un CPE de la NVD touché par une vulnérabilité.
type cpeEntry struct {
	part, vendor, product string
	cve, constraint, fix  string
}

// openTestDB écrit, installe et ouvre une vraie base Grype v6 qui ne contient que les
// entrées données.
func openTestDB(t *testing.T, distros []distroEntry, cpes []cpeEntry) vuln.Database {
	t.Helper()
	// Les fiches sont écrites d'abord : AddAffected* n'écrit pas le contenu d'une fiche.
	var handles []*v6.VulnerabilityHandle
	handle := func(provider, id string) *v6.VulnerabilityHandle {
		h := &v6.VulnerabilityHandle{Name: id, Status: v6.VulnerabilityActive, Provider: &v6.Provider{ID: provider},
			BlobValue: &v6.VulnerabilityBlob{ID: id, Description: "d " + id}}
		handles = append(handles, h)
		return h
	}
	// Une copie par base : l'écriture inscrit l'identifiant de l'enregistrement dans la
	// structure, partagée entre les tests.
	oses := map[*v6.OperatingSystem]*v6.OperatingSystem{}
	osOf := func(o *v6.OperatingSystem) *v6.OperatingSystem {
		if c, ok := oses[o]; ok {
			return c
		}
		c := *o
		oses[o] = &c
		return &c
	}
	var packages []*v6.AffectedPackageHandle
	for _, e := range distros {
		packages = append(packages, &v6.AffectedPackageHandle{
			Vulnerability: handle(e.os.Name, e.cve), OperatingSystem: osOf(e.os),
			Package: &v6.Package{Ecosystem: "deb", Name: e.pkg},
			BlobValue: &v6.PackageBlob{CVEs: []string{e.cve}, Ranges: []v6.Range{{
				Version: v6.Version{Type: "dpkg", Constraint: e.constraint},
				Fix:     &v6.Fix{Version: e.fix, State: e.state},
			}}},
		})
	}
	var affectedCPEs []*v6.AffectedCPEHandle
	for _, e := range cpes {
		affectedCPEs = append(affectedCPEs, &v6.AffectedCPEHandle{
			Vulnerability: handle("nvd", e.cve),
			CPE:           &v6.Cpe{Part: e.part, Vendor: e.vendor, Product: e.product},
			BlobValue: &v6.PackageBlob{CVEs: []string{e.cve}, Ranges: []v6.Range{{
				Version: v6.Version{Constraint: e.constraint},
				Fix:     &v6.Fix{Version: e.fix, State: v6.FixedStatus},
			}}},
		})
	}
	archive, err := grypetest.Archive(t.TempDir(), func(w v6.ReadWriter) error {
		if err := w.AddVulnerabilities(handles...); err != nil {
			return err
		}
		if err := w.AddAffectedPackages(packages...); err != nil {
			return err
		}
		return w.AddAffectedCPEs(affectedCPEs...)
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "db")
	if _, err := NewEngine().Install(ctx, archive, dir); err != nil {
		t.Fatal(err)
	}
	d, err := NewEngine().Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func readTestSBOM(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "sbom", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
