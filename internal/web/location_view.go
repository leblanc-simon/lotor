package web

import "leblanc.io/lotor/internal/sbom"

// locationsShown borne les emplacements affichés dans une cellule de tableau.
const locationsShown = 3

// locationView est un emplacement d'un composant (sbom.Location) tel que l'affichent les
// gabarits location_short et location_list.
type locationView struct {
	Path       string
	AccessPath string
	Layer      string
	Supporting bool
}

// locationsView est la liste des emplacements d'un composant : Shown, les principaux
// affichés dans un tableau ; More, le nombre des autres ; All, tous (fiche d'un constat).
type locationsView struct {
	Shown []locationView
	More  int
	All   []locationView
}

func locationsOf(ls []sbom.Location) locationsView {
	var v locationsView
	for _, l := range ls {
		v.All = append(v.All, locationView{Path: l.Path, AccessPath: l.AccessPath, Layer: l.Layer,
			Supporting: l.Supporting})
	}
	main := sbom.MainLocations(ls)
	v.Shown = v.All[:min(len(main), locationsShown)]
	v.More = len(v.All) - len(v.Shown)
	return v
}
