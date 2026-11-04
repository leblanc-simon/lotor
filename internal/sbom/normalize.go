package sbom

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bornes des listes et champs secondaires d'un composant : l'excédent est ignoré (ces
// champs ne font pas l'identité du composant).
const (
	MaxCPEs        = 32
	MaxCPELen      = 512
	MaxLicenses    = 32
	MaxLicenseLen  = 256
	MaxHashes      = 16
	MaxModelLen    = 128
	MaxEvidenceLen = 16 << 10
)

// RawComponent est un composant tel que le lit un décodeur, avant normalisation.
type RawComponent struct {
	PURL     string
	Name     string
	Version  string
	CPEs     []string
	Licenses []string
	// Hashes : algorithme tel qu'écrit par le document (SHA-256, sha256…) et valeur.
	Hashes []RawHash
	// Properties lotor: (origin, confidence, model) ; vides si absentes.
	Origin     string
	Confidence string
	Model      string
	Evidence   json.RawMessage
	Scope      string
	Locations  []RawLocation
}

// RawHash est une empreinte telle que l'écrit le document.
type RawHash struct {
	Algorithm string
	Value     string
}

// RawDocument est un SBOM tel que le lit un décodeur.
type RawDocument struct {
	Format      Format
	SpecVersion string
	Distro      *Distro
	Components  []RawComponent
	// Enrichment et EnrichmentModel : propriétés lotor:enrichment et
	// lotor:enrichment-model des métadonnées (CycloneDX).
	Enrichment      string
	EnrichmentModel string
}

// Normalize canonicalise les composants d'un document décodé : purl canonique (ou générique
// et WeakID), champs bornés, listes triées sans doublon, origine, confiance et portée
// validées, preuve en JSON canonique ; les doublons de purl sont fusionnés et les
// composants triés par purl. Le résultat ne dépend pas de l'ordre du document.
func Normalize(raw RawDocument) Document {
	doc := Document{Format: raw.Format, SpecVersion: raw.SpecVersion, Distro: raw.Distro,
		Enrichment: ParseEnrichment(raw.Enrichment)}
	if m := cleanText(raw.EnrichmentModel); doc.Enrichment != "" && len(m) <= MaxModelLen {
		doc.EnrichmentModel = m
	}
	byPURL := make(map[string]int, len(raw.Components))
	for _, rc := range raw.Components {
		c, ok := normalizeComponent(rc)
		if !ok {
			doc.Skipped++
			continue
		}
		if i, dup := byPURL[c.PURL]; dup {
			doc.Components[i] = merge(doc.Components[i], c)
			continue
		}
		byPURL[c.PURL] = len(doc.Components)
		doc.Components = append(doc.Components, c)
	}
	slices.SortFunc(doc.Components, func(a, b Component) int { return strings.Compare(a.PURL, b.PURL) })
	if doc.Components == nil {
		doc.Components = []Component{}
	}
	return doc
}

func normalizeComponent(rc RawComponent) (Component, bool) {
	name := cleanText(rc.Name)
	version := cleanText(rc.Version)
	if len(name) > MaxNameLen || len(version) > MaxVersionLen {
		return Component{}, false
	}
	p, weak, err := ComponentPURL(strings.TrimSpace(rc.PURL), name, version)
	if err != nil {
		return Component{}, false
	}
	if name == "" {
		name = p.Name
	}
	if version == "" {
		version = p.Version
	}
	c := Component{
		PURL: p.String, PURLBase: p.Base, Type: p.Type, Name: name, Version: version, WeakID: weak,
		CPEs:     cleanList(rc.CPEs, MaxCPEs, MaxCPELen, validCPE),
		Licenses: cleanList(rc.Licenses, MaxLicenses, MaxLicenseLen, nil),
		Hashes:   cleanHashes(rc.Hashes),
		Origin:   OriginSyft,
		Scope:    parseScope(rc.Scope),
	}
	if Origin(strings.TrimSpace(rc.Origin)) == OriginIA {
		c.Origin = OriginIA
	}
	c.Confidence = parseConfidence(rc.Confidence)
	if m := cleanText(rc.Model); len(m) <= MaxModelLen {
		c.Model = m
	}
	c.Evidence = canonicalJSON(rc.Evidence)
	c.Locations = cleanLocations(rc.Locations)
	return c, true
}

// cleanText retire les espaces de bord ; une chaîne qui n'est pas de l'UTF-8 valide ou qui
// contient un caractère de contrôle est vidée (elle ne s'afficherait ni ne se chercherait).
func cleanText(s string) string {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl) {
		return ""
	}
	return s
}

func cleanList(in []string, maxItems, maxLen int, valid func(string) bool) []string {
	var out []string
	for _, s := range in {
		s = cleanText(s)
		if s == "" || len(s) > maxLen || (valid != nil && !valid(s)) {
			continue
		}
		out = append(out, s)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > maxItems {
		out = out[:maxItems]
	}
	return out
}

func validCPE(s string) bool {
	return strings.HasPrefix(s, "cpe:2.3:") || strings.HasPrefix(s, "cpe:/")
}

// hashAlgorithms ramène les noms d'algorithme des formats (SHA-256, SHA256, sha256…) à une
// forme unique, avec la longueur attendue de la valeur en hexadécimal.
var hashAlgorithms = map[string]struct {
	name string
	hex  int
}{
	"md5": {"md5", 32}, "sha1": {"sha1", 40}, "sha224": {"sha224", 56}, "sha256": {"sha256", 64},
	"sha384": {"sha384", 96}, "sha512": {"sha512", 128}, "sha3256": {"sha3-256", 64},
	"sha3384": {"sha3-384", 96}, "sha3512": {"sha3-512", 128}, "blake2b256": {"blake2b-256", 64},
	"blake2b384": {"blake2b-384", 96}, "blake2b512": {"blake2b-512", 128}, "blake3": {"blake3", 64},
}

func cleanHashes(in []RawHash) []string {
	var out []string
	for _, h := range in {
		key := strings.Map(func(r rune) rune {
			if r == '-' || r == '_' {
				return -1
			}
			return unicode.ToLower(r)
		}, strings.TrimSpace(h.Algorithm))
		alg, ok := hashAlgorithms[key]
		v := strings.ToLower(strings.TrimSpace(h.Value))
		if !ok || len(v) != alg.hex {
			continue
		}
		if _, err := hex.DecodeString(v); err != nil {
			continue
		}
		out = append(out, alg.name+":"+v)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > MaxHashes {
		out = out[:MaxHashes]
	}
	return out
}

func parseScope(s string) Scope {
	switch sc := Scope(strings.ToLower(strings.TrimSpace(s))); sc {
	case ScopeRequired, ScopeOptional, ScopeExcluded:
		return sc
	}
	return ""
}

// parseConfidence lit une confiance dans [0, 1], arrondie à quatre décimales pour que
// l'empreinte ne dépende pas de l'écriture du nombre (0.8, 0.80, 8e-1).
func parseConfidence(s string) *float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || f < 0 || f > 1 {
		return nil
	}
	f = math.Round(f*1e4) / 1e4
	return &f
}

// canonicalJSON réécrit une preuve en JSON canonique (clés triées, sans espace) ; une
// preuve illisible, nulle ou trop longue est ignorée.
func canonicalJSON(raw json.RawMessage) json.RawMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > MaxEvidenceLen || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil || dec.More() {
		return nil
	}
	out, err := json.Marshal(v)
	if err != nil || len(out) > MaxEvidenceLen {
		return nil
	}
	return out
}

// merge fusionne deux mentions du même purl : Syft l'emporte sur l'IA (preuve par
// l'analyse), la confiance la plus haute, la portée la plus contraignante, l'union des
// listes (emplacements compris : un même paquet trouvé à deux endroits) ; à égalité, la première valeur non vide dans l'ordre canonique. Le résultat ne
// dépend pas de l'ordre des mentions.
func merge(a, b Component) Component {
	if rank(b) > rank(a) || (rank(b) == rank(a) && tieBreak(b, a) < 0) {
		a, b = b, a
	}
	out := a.clone()
	out.CPEs = union(a.CPEs, b.CPEs, MaxCPEs)
	out.Licenses = union(a.Licenses, b.Licenses, MaxLicenses)
	out.Hashes = union(a.Hashes, b.Hashes, MaxHashes)
	out.Locations = unionLocations(a.Locations, b.Locations)
	if scopeRank(b.Scope) > scopeRank(out.Scope) {
		out.Scope = b.Scope
	}
	out.WeakID = a.WeakID && b.WeakID
	return out
}

// rank classe une mention : origine Syft d'abord, puis confiance.
func rank(c Component) float64 {
	r := 0.0
	if c.Origin == OriginSyft {
		r = 10
	}
	if c.Confidence != nil {
		r += *c.Confidence
	}
	return r
}

// tieBreak départage deux mentions de même rang par un ordre total sur leurs champs.
func tieBreak(a, b Component) int {
	return cmp.Or(
		cmp.Compare(confidenceKey(a), confidenceKey(b)),
		strings.Compare(a.Name, b.Name),
		strings.Compare(a.Version, b.Version),
		strings.Compare(a.Model, b.Model),
		bytes.Compare(a.Evidence, b.Evidence),
		strings.Compare(string(a.Scope), string(b.Scope)),
		strings.Compare(strings.Join(a.Licenses, "\x1f"), strings.Join(b.Licenses, "\x1f")),
	)
}

// confidenceKey ordonne les confiances, une confiance absente avant toute autre.
func confidenceKey(c Component) float64 {
	if c.Confidence == nil {
		return -1
	}
	return *c.Confidence
}

func union(a, b []string, maxItems int) []string {
	out := append(slices.Clone(a), b...)
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > maxItems {
		out = out[:maxItems]
	}
	return out
}
