package grype

import (
	"path"
	"regexp"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// snapPackages rattache les paquets deb déclarés par les snaps à la version d'Ubuntu du
// snap, et les binaires d'un snap au paquet deb du même snap qui les fournit (ADR 0065).
//
// Le catalogueur des snaps de Syft lit la liste des paquets d'un snap (dpkg.yaml d'un snap
// de base, manifest.yaml d'un snap applicatif) et en fait des paquets deb sans
// distribution : Grype leur donne celle de l'hôte, et les paquets de core22 (Ubuntu 22.04)
// d'un hôte Ubuntu 26.04 étaient comparés aux correctifs de 26.04. Ces listes ne nomment
// aucun fichier : les binaires du snap (/snap/core22/…/usr/bin/openssl) n'étaient liés à
// aucun paquet et restaient comparés par CPE aux versions amont de la NVD.
//
// Version d'Ubuntu : nom du snap de base (core22 → 22.04), sinon base déclarée par le snap
// applicatif, sinon l'unique version d'Ubuntu inscrite dans les versions de ses paquets
// (1ubuntu0.22.04.3, ~22.04.1). Faute de quoi le paquet garde la distribution de l'hôte,
// comme avant.
//
// Binaire : un binaire du snap est lié au paquet deb du même snap de même nom (ou de même
// nom suivi d'une version : python → python3.10) dont la version amont préfixe la sienne
// (bash 5.1.16, paquet 5.1-6ubuntu1.1). Le lien est celui que Syft pose pour un fichier
// possédé : Grype retire alors la correspondance CPE des CVE que la distribution déclare
// corrigées, et dropOwnedCPEDuplicates celles qu'elle déclare ouvertes.
func snapPackages(pkgs []pkg.Package, s *sbom.SBOM) {
	type snapDir = string
	debs := map[snapDir][]int{}
	for i := range pkgs {
		if dir, ok := snapOf(pkgs[i]); ok && pkgs[i].Type == syftPkg.DebPkg {
			debs[dir] = append(debs[dir], i)
		}
	}
	if len(debs) == 0 {
		return
	}
	for dir, idx := range debs {
		d := snapDistro(dir, idx, pkgs, s)
		if d == nil {
			continue
		}
		for _, i := range idx {
			pkgs[i].Distro = d
		}
	}
	for i := range pkgs {
		p := &pkgs[i]
		dir, ok := snapOf(*p)
		if !ok || p.Type != syftPkg.BinaryPkg {
			continue
		}
		for _, j := range debs[dir] {
			if providesBinary(pkgs[j], *p) {
				if p.RelatedPackages == nil {
					p.RelatedPackages = map[artifact.RelationshipType][]*pkg.Package{}
				}
				p.RelatedPackages[artifact.OwnershipByFileOverlapRelationship] = append(
					p.RelatedPackages[artifact.OwnershipByFileOverlapRelationship], &pkgs[j])
			}
		}
	}
}

// snapOf renvoie le répertoire du snap (/snap/<nom>/<révision>) où le paquet a été trouvé.
func snapOf(p pkg.Package) (string, bool) {
	for _, l := range p.Locations.ToSlice() {
		parts := strings.SplitN(strings.TrimPrefix(l.RealPath, "/"), "/", 4)
		if len(parts) >= 3 && parts[0] == "snap" && parts[1] != "" && parts[2] != "" {
			return "/" + path.Join(parts[:3]...), true
		}
	}
	return "", false
}

// coreRelease : core → 16.04, core18 → 18.04, core22 → 22.04…
var coreRelease = regexp.MustCompile(`^core(\d{2})?$`)

func ubuntuOfBase(base string) string {
	m := coreRelease.FindStringSubmatch(base)
	switch {
	case m == nil:
		return ""
	case m[1] == "":
		return "16.04"
	default:
		return m[1] + ".04"
	}
}

// releaseInVersion : version d'Ubuntu inscrite dans une version de paquet
// (2.44-1ubuntu0.22.04.3, 12.3.0-1ubuntu1~22.04.3, 3.10.12-1~22.04.18).
var releaseInVersion = regexp.MustCompile(`(?:~|ubuntu\d+\.)(\d{2}\.(?:04|10))(?:\.\d+)*$`)

func snapDistro(dir string, idx []int, pkgs []pkg.Package, s *sbom.SBOM) *distro.Distro {
	release := ubuntuOfBase(path.Base(path.Dir(dir)))
	if release == "" && s != nil {
		for _, i := range idx {
			if sp := s.Artifacts.Packages.Package(artifact.ID(pkgs[i].ID)); sp != nil {
				if e, ok := sp.Metadata.(syftPkg.SnapEntry); ok {
					if release = ubuntuOfBase(e.Base); release != "" {
						break
					}
				}
			}
		}
	}
	if release == "" {
		seen := map[string]bool{}
		for _, i := range idx {
			if m := releaseInVersion.FindStringSubmatch(pkgs[i].Version); m != nil {
				seen[m[1]] = true
			}
		}
		if len(seen) != 1 {
			return nil
		}
		for r := range seen {
			release = r
		}
	}
	return distro.New(distro.Ubuntu, release, "")
}

// providesBinary : le paquet deb fournit le binaire trouvé par son contenu.
func providesBinary(deb, bin pkg.Package) bool {
	if bin.Version == "" {
		return false
	}
	if deb.Name != bin.Name {
		rest, ok := strings.CutPrefix(deb.Name, bin.Name)
		if !ok || rest == "" || strings.Trim(rest, "0123456789.") != "" {
			return false
		}
	}
	up := deb.Version
	if _, after, ok := strings.Cut(up, ":"); ok {
		up = after
	}
	if i := strings.LastIndex(up, "-"); i > 0 {
		up = up[:i]
	}
	return up != "" && (bin.Version == up || strings.HasPrefix(bin.Version, up+"."))
}
