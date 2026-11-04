package sbom

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"
)

// Bornes des emplacements d'un composant.
const (
	MaxLocations     = 32
	MaxLocationLen   = 4096
	MaxLocationLayer = 128
)

// Location est un emplacement où l'analyse a trouvé un composant : le fichier qui le
// déclare (base de paquets, manifeste, archive, binaire), tel que Syft le note.
type Location struct {
	// Path est le chemin réel du fichier, liens symboliques résolus.
	Path string `json:"path"`
	// AccessPath est le chemin par lequel l'analyse l'a atteint ; vide s'il est égal à
	// Path ou si le format ne le transporte pas (CycloneDX, SPDX).
	AccessPath string `json:"access_path,omitempty"`
	// Layer est la couche de l'image qui contient le fichier ; vide hors image.
	Layer string `json:"layer,omitempty"`
	// Supporting marque un emplacement que Syft annote comme preuve secondaire (fichier
	// de liste ou de sommes d'un paquet). Sans annotation, l'emplacement est principal.
	Supporting bool `json:"supporting,omitempty"`
}

// RawLocation est un emplacement tel que le lit un décodeur.
type RawLocation struct {
	Path       string
	AccessPath string
	Layer      string
	// Evidence est l'annotation « evidence » de Syft : primary, supporting ou vide.
	Evidence string
}

// compareLocations ordonne les emplacements : principaux d'abord, puis par chemin, chemin
// d'accès et couche. Un ordre total : la troncature et la fusion ne dépendent pas de
// l'ordre du document.
func compareLocations(a, b Location) int {
	return cmp.Or(
		compareBool(a.Supporting, b.Supporting),
		strings.Compare(a.Path, b.Path),
		strings.Compare(a.AccessPath, b.AccessPath),
		strings.Compare(a.Layer, b.Layer),
	)
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	}
	return 1
}

// cleanLocations valide, trie, dédoublonne et borne les emplacements bruts.
func cleanLocations(in []RawLocation) []Location {
	out := make([]Location, 0, len(in))
	for _, r := range in {
		p := cleanText(r.Path)
		if p == "" || len(p) > MaxLocationLen {
			continue
		}
		l := Location{Path: p, Supporting: strings.EqualFold(strings.TrimSpace(r.Evidence), "supporting")}
		if a := cleanText(r.AccessPath); a != p && len(a) <= MaxLocationLen {
			l.AccessPath = a
		}
		if ly := cleanText(r.Layer); len(ly) <= MaxLocationLayer {
			l.Layer = ly
		}
		out = append(out, l)
	}
	return compactLocations(out)
}

// unionLocations réunit les emplacements de deux mentions du même purl.
func unionLocations(a, b []Location) []Location {
	return compactLocations(append(slices.Clone(a), b...))
}

// compactLocations trie, fusionne les doublons (un emplacement à la fois principal et
// secondaire reste principal) et borne la liste.
func compactLocations(ls []Location) []Location {
	if len(ls) == 0 {
		return nil
	}
	slices.SortFunc(ls, compareLocations)
	out := ls[:0]
	seen := make(map[Location]bool, len(ls))
	for _, l := range ls {
		key := l
		key.Supporting = false
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, l)
	}
	if len(out) > MaxLocations {
		out = out[:MaxLocations]
	}
	return slices.Clip(out)
}

// MainLocations renvoie les emplacements principaux ; tous, si aucun ne l'est.
func MainLocations(ls []Location) []Location {
	i := slices.IndexFunc(ls, func(l Location) bool { return l.Supporting })
	if i <= 0 {
		return ls
	}
	return ls[:i]
}

// ParseLocations relit les emplacements rangés en base (colonne jsonb) ; nil pour une
// valeur absente ou illisible.
func ParseLocations(b []byte) []Location {
	if len(b) == 0 {
		return nil
	}
	var out []Location
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}
