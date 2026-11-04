package sbom

import (
	"encoding/json"
	"slices"
	"strings"
)

// Format est le format d'un SBOM reçu. Seuls les formats JSON sont acceptés.
type Format string

// Formats acceptés (§ 11 de l'architecture).
const (
	FormatCycloneDX Format = "cyclonedx"
	FormatSPDX      Format = "spdx"
	FormatSyft      Format = "syft"
)

// Origin est l'origine d'un composant : trouvé par Syft, ou ajouté par l'enrichissement IA
// de l'agent dépôt (propriété lotor:origin).
type Origin string

// Origines d'un composant.
const (
	OriginSyft Origin = "syft"
	OriginIA   Origin = "ia"
)

// Origins liste les origines dans l'ordre d'affichage.
func Origins() []Origin { return []Origin{OriginSyft, OriginIA} }

// Scope est la portée CycloneDX d'un composant ; vide si le document ne la donne pas.
type Scope string

// Portées CycloneDX.
const (
	ScopeRequired Scope = "required"
	ScopeOptional Scope = "optional"
	ScopeExcluded Scope = "excluded"
)

// scopeRank ordonne les portées pour la fusion de doublons : la plus contraignante gagne.
func scopeRank(s Scope) int {
	switch s {
	case ScopeRequired:
		return 3
	case ScopeOptional:
		return 2
	case ScopeExcluded:
		return 1
	}
	return 0
}

// Distro est la distribution décrite par un SBOM d'hôte ou d'image.
type Distro struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Name      string `json:"name,omitempty"`
}

// Document est un SBOM décodé et normalisé.
type Document struct {
	Format      Format      `json:"format"`
	SpecVersion string      `json:"spec_version"`
	Distro      *Distro     `json:"distro,omitempty"`
	Components  []Component `json:"components"`
	// Skipped compte les composants écartés : sans nom ni purl, ou hors des bornes de
	// taille d'un champ.
	Skipped int `json:"skipped,omitempty"`
	// Enrichment est le statut de l'enrichissement IA déclaré par le document (propriété
	// lotor:enrichment de ses métadonnées) ; vide sans enrichissement ou valeur inconnue.
	// EnrichmentModel est le modèle déclaré (lotor:enrichment-model).
	Enrichment      Enrichment `json:"enrichment,omitempty"`
	EnrichmentModel string     `json:"enrichment_model,omitempty"`
}

// Enrichment est le statut de l'enrichissement IA d'un SBOM de l'agent dépôt.
type Enrichment string

// Statuts d'enrichissement.
const (
	EnrichmentComplete   Enrichment = "complete"
	EnrichmentIncomplete Enrichment = "incomplete"
	EnrichmentCarried    Enrichment = "carried"
)

// ParseEnrichment lit un statut d'enrichissement ; vide pour une valeur inconnue.
func ParseEnrichment(s string) Enrichment {
	switch e := Enrichment(strings.TrimSpace(s)); e {
	case EnrichmentComplete, EnrichmentIncomplete, EnrichmentCarried:
		return e
	}
	return ""
}

// Component est un composant normalisé (voir Normalize).
type Component struct {
	// PURL est le purl canonique, identité du composant dans l'organisation.
	PURL string `json:"purl"`
	// PURLBase est le purl sans version, qualificatifs ni sous-chemin : pkg:deb/debian/openssl.
	PURLBase string `json:"purl_base"`
	// Type est le type purl (deb, rpm, npm, golang…).
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// CPEs, Licenses et Hashes sont triés et sans doublon. Une empreinte s'écrit
	// « algorithme:valeur » en minuscules (sha256:…).
	CPEs     []string `json:"cpes,omitempty"`
	Licenses []string `json:"licenses,omitempty"`
	Hashes   []string `json:"hashes,omitempty"`
	Origin   Origin   `json:"origin"`
	// Confidence (0 à 1, quatre décimales) vient de lotor:confidence ; nil si absente.
	Confidence *float64 `json:"confidence,omitempty"`
	Model      string   `json:"model,omitempty"`
	// Evidence est le champ evidence de CycloneDX, en JSON canonique (clés triées).
	Evidence json.RawMessage `json:"evidence,omitempty"`
	Scope    Scope           `json:"scope,omitempty"`
	// Locations sont les emplacements où l'analyse l'a trouvé, principaux d'abord (voir
	// Location) ; vide si le document n'en donne pas.
	Locations []Location `json:"locations,omitempty"`
	// WeakID signale un composant sans purl utilisable, identifié par
	// pkg:generic/<nom>@<version>.
	WeakID bool `json:"weak_id,omitempty"`
}

// Counts compte les composants d'un inventaire par origine.
type Counts struct {
	Total int `json:"total"`
	Syft  int `json:"syft"`
	IA    int `json:"ia"`
	Weak  int `json:"weak"`
}

// CountsOf compte les composants par origine et ceux à identification faible.
func CountsOf(cs []Component) Counts {
	c := Counts{Total: len(cs)}
	for _, x := range cs {
		if x.Origin == OriginIA {
			c.IA++
		} else {
			c.Syft++
		}
		if x.WeakID {
			c.Weak++
		}
	}
	return c
}

// clone copie les tranches d'un composant (fusion de doublons sans alias).
func (c Component) clone() Component {
	c.CPEs = slices.Clone(c.CPEs)
	c.Licenses = slices.Clone(c.Licenses)
	c.Hashes = slices.Clone(c.Hashes)
	c.Locations = slices.Clone(c.Locations)
	if c.Confidence != nil {
		v := *c.Confidence
		c.Confidence = &v
	}
	return c
}
