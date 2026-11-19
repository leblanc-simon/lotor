package grype

import (
	"slices"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// signedKernelUpstreams ajoute aux images de noyau signées de Debian et d'Ubuntu leur
// paquet source non signé (ADR 0064).
//
// linux-image-* vient d'un paquet source linux-signed* qui ne fait qu'emballer l'image
// signée : les suivis de sécurité des deux distributions, donc la base Grype, ne
// connaissent que le source linux*. Sans ce renvoi, l'image n'est rapprochée de rien, et
// le binaire /boot/vmlinuz-* qu'elle possède n'est comparé qu'aux plages amont de la NVD
// (par CPE), que les correctifs reportés par la distribution ne déplacent pas : chaque
// CVE déjà corrigée par la distribution reste signalée. Une fois l'image rapprochée,
// Grype retire lui-même, CVE par CVE, la correspondance CPE du binaire possédé quand la
// distribution déclare la CVE corrigée ou non applicable ; une CVE qu'elle ne suit pas
// reste signalée par CPE.
//
// La version est celle du paquet binaire : c'est celle du source linux* dont l'image est
// construite (7.0.0-43.43 sur Ubuntu, 6.1.128-1 sur Debian), quand la version du source
// signé suit sa propre numérotation sur Debian (6.1.128+1). Le source d'origine est
// gardé.
func signedKernelUpstreams(pkgs []pkg.Package) {
	for i := range pkgs {
		p := &pkgs[i]
		if p.Type != syftPkg.DebPkg || p.Distro == nil || p.Version == "" {
			continue
		}
		for _, u := range p.Upstreams {
			name, ok := unsignedKernelSource(p.Distro.Type, u.Name)
			if !ok || hasUpstream(p.Upstreams, name) {
				continue
			}
			p.Upstreams = append(p.Upstreams, pkg.UpstreamPackage{Name: name, Version: p.Version})
			break
		}
	}
}

// debianArches sont les architectures qui suffixent les sources signés de Debian
// (linux-signed-amd64, linux-signed-6.1-arm64…).
var debianArches = []string{"amd64", "arm64", "i386"}

// unsignedKernelSource renvoie le source non signé d'un source de noyau signé :
// linux-signed → linux, linux-signed-hwe-6.8 → linux-hwe-6.8 (Ubuntu) ;
// linux-signed-amd64 → linux, linux-signed-6.1-amd64 → linux-6.1 (Debian).
func unsignedKernelSource(t distro.Type, source string) (string, bool) {
	rest, ok := strings.CutPrefix(source, "linux-signed")
	if !ok || (rest != "" && !strings.HasPrefix(rest, "-")) {
		return "", false
	}
	switch t {
	case distro.Ubuntu:
		return "linux" + rest, true
	case distro.Debian:
		for _, arch := range debianArches {
			if r, ok := strings.CutSuffix(rest, "-"+arch); ok {
				return "linux" + r, true
			}
		}
	}
	return "", false
}

// dropOwnedCPEDuplicates retire la correspondance par CPE seul d'un paquet dont un
// fichier appartient à un paquet de la distribution, quand ce paquet est lui-même
// rapproché de la même vulnérabilité par les données de la distribution (ADR 0064).
//
// Grype retire déjà la correspondance CPE d'un fichier possédé quand la distribution
// déclare la CVE corrigée ; quand elle la déclare encore ouverte, la CVE restait signalée
// deux fois : sur le paquet de la distribution, avec la version corrigée de la
// distribution, et sur le binaire possédé (/boot/vmlinuz-*), avec les versions amont de
// la NVD. La CVE reste signalée sur le paquet de la distribution : rien n'est perdu.
func dropOwnedCPEDuplicates(ms []match.Match) []match.Match {
	type key struct {
		pkg  pkg.ID
		vuln string
	}
	byDistro := map[key]bool{}
	for _, m := range ms {
		if isOSPackage(m.Package.Type) && !cpeOnly(m.Details) {
			byDistro[key{m.Package.ID, m.Vulnerability.ID}] = true
		}
	}
	if len(byDistro) == 0 {
		return ms
	}
	return slices.DeleteFunc(ms, func(m match.Match) bool {
		if !cpeOnly(m.Details) {
			return false
		}
		for _, owner := range m.Package.RelatedPackages[artifact.OwnershipByFileOverlapRelationship] {
			if owner != nil && byDistro[key{owner.ID, m.Vulnerability.ID}] {
				return true
			}
		}
		return false
	})
}

func isOSPackage(t syftPkg.Type) bool {
	switch t {
	case syftPkg.DebPkg, syftPkg.RpmPkg, syftPkg.ApkPkg, syftPkg.AlpmPkg, syftPkg.PortagePkg:
		return true
	}
	return false
}

// cpeOnly : la correspondance ne repose que sur des CPE.
func cpeOnly(ds match.Details) bool {
	if len(ds) == 0 {
		return false
	}
	for _, d := range ds {
		if d.Type != match.CPEMatch {
			return false
		}
	}
	return true
}

func hasUpstream(us []pkg.UpstreamPackage, name string) bool {
	for _, u := range us {
		if u.Name == name {
			return true
		}
	}
	return false
}
