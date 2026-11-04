package sbom

import (
	"crypto/sha256"
	"slices"
	"strconv"
	"strings"
)

// fingerprintVersion préfixe la sérialisation : changer les règles de l'empreinte change
// ce préfixe, et donc toutes les empreintes, plutôt que de réutiliser à tort un ensemble.
const fingerprintVersion = "lotor-inventory-v2\n"

// Fingerprint est l'empreinte d'inventaire : SHA-256 de la liste triée des composants et
// de ce qui fait un élément d'ensemble (purl canonique, origine, confiance, modèle,
// portée, identification faible, licences, preuve, emplacements). Les CPE et empreintes de fichier,
// attachés au composant lui-même, n'en font pas partie ; ni les horodatages, ni le numéro
// de série, ni l'outil, ni l'ordre des composants du document.
func Fingerprint(components []Component) [32]byte {
	sorted := slices.IsSortedFunc(components, func(a, b Component) int { return strings.Compare(a.PURL, b.PURL) })
	if !sorted {
		components = slices.Clone(components)
		slices.SortFunc(components, func(a, b Component) int { return strings.Compare(a.PURL, b.PURL) })
	}
	h := sha256.New()
	h.Write([]byte(fingerprintVersion))
	var b strings.Builder
	for _, c := range components {
		b.Reset()
		// Chaque champ est préfixé de sa longueur : aucune valeur ne peut imiter un
		// séparateur.
		field(&b, c.PURL)
		field(&b, string(c.Origin))
		conf := ""
		if c.Confidence != nil {
			conf = strconv.FormatFloat(*c.Confidence, 'f', 4, 64)
		}
		field(&b, conf)
		field(&b, c.Model)
		field(&b, string(c.Scope))
		field(&b, strconv.FormatBool(c.WeakID))
		field(&b, strconv.Itoa(len(c.Licenses)))
		for _, l := range c.Licenses {
			field(&b, l)
		}
		field(&b, string(c.Evidence))
		field(&b, strconv.Itoa(len(c.Locations)))
		for _, l := range c.Locations {
			field(&b, l.Path)
			field(&b, l.AccessPath)
			field(&b, l.Layer)
			field(&b, strconv.FormatBool(l.Supporting))
		}
		b.WriteByte('\n')
		h.Write([]byte(b.String()))
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func field(b *strings.Builder, s string) {
	b.WriteString(strconv.Itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
	b.WriteByte(';')
}
