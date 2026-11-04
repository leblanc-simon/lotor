package search

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/package-url/packageurl-go"

	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/version"
)

// Kind est la nature d'une requête, déduite de sa forme (§ 13 de l'architecture).
type Kind string

// Natures de requête.
const (
	KindName          Kind = "name"          // nom de composant, approché par trigrammes
	KindPURL          Kind = "purl"          // pkg:…, éventuellement suivi d'une plage vers
	KindVulnerability Kind = "vulnerability" // CVE-… ou GHSA-…
	KindHash          Kind = "hash"          // sha256:<hex> ou 64 caractères hexadécimaux
	KindLicense       Kind = "license"       // license:… (T20)
)

// Bornes d'une requête.
const (
	MaxQueryLen = 1024 // octets
	MaxNameLen  = 200  // caractères d'un nom recherché
)

// Clés d'erreur des requêtes et des filtres (problèmes de l'API, messages de l'écran :
// <clé>.title et <clé>.text).
const (
	KeyEmpty           = "error.search.empty"
	KeyTooLong         = "error.search.too_long"
	KeyPURLInvalid     = "error.search.purl_invalid"
	KeyRangeNeedsPURL  = "error.search.range_needs_purl"
	KeyRangeAndVersion = "error.search.range_and_version"
	KeyVersInvalid     = "error.search.vers_invalid"
	KeyVersScheme      = "error.search.vers_scheme"
	KeyVersDuplicate   = "error.search.vers_duplicate"
	KeyVersVersion     = "error.search.vers_version"
	KeyVersMismatch    = "error.search.vers_mismatch"
	KeyVulnInvalid     = "error.search.vulnerability_invalid"
	KeyHashInvalid     = "error.search.hash_invalid"
	KeyLicense         = "error.search.license_unavailable"
	KeyFilterInvalid   = "error.search.filter_invalid"
	// KeyTriageVulnOnly : le filtre de triage ne vaut que pour une recherche par
	// vulnérabilité (un constat a un statut de triage, un composant non).
	KeyTriageVulnOnly = "error.search.triage_vulnerability_only"
	// KeyAtInvalid : date « à la date du » illisible ou dans le futur (T21).
	KeyAtInvalid = "error.search.at_invalid"
	// KeyAtComponentsOnly : à une date passée, la recherche porte sur les composants ; les
	// constats d'alors ne sont pas conservés (T21).
	KeyAtComponentsOnly = "error.search.at_components_only"
)

// ErrorKeys liste les clés d'erreur du paquet (tests de traduction).
func ErrorKeys() []string {
	return []string{KeyEmpty, KeyTooLong, KeyPURLInvalid, KeyRangeNeedsPURL, KeyRangeAndVersion, KeyVersInvalid,
		KeyVersScheme, KeyVersDuplicate, KeyVersVersion, KeyVersMismatch, KeyVulnInvalid, KeyHashInvalid, KeyLicense,
		KeyFilterInvalid, KeyTriageVulnOnly, KeyAtInvalid, KeyAtComponentsOnly}
}

// Error est une requête ou un filtre refusés, avec une clé traduisible.
type Error struct{ Key string }

func (e *Error) Error() string { return "search: requête refusée : " + e.Key }

func refuse(key string) error { return &Error{Key: key} }

// IsError renvoie la requête refusée que porte err.
func IsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// PURLQuery est un purl recherché : sa base (le paquet), et ce qui le précise.
type PURLQuery struct {
	PURL       sbom.PURL // forme canonique ; Base désigne le paquet
	Qualifiers map[string]string
	Subpath    string
	Scheme     version.Scheme // règle de comparaison de ses versions
}

// Query est une requête analysée.
type Query struct {
	Raw  string
	Kind Kind
	// Name : KindName, espaces ramenés à un seul.
	Name string
	// PURL et Range : KindPURL ; Range seulement sans version dans le purl.
	PURL  PURLQuery
	Range *version.Range
	// VulnID : KindVulnerability, forme canonique (CVE-… en majuscules, GHSA-… avec le
	// corps en minuscules).
	VulnID string
	// Hash : KindHash, « sha256:<hex> » en minuscules (forme de components.hashes).
	Hash string
}

var (
	cvePattern  = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	ghsaPattern = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
	hexPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Parse analyse une requête de la barre de recherche. Une chaîne vide (aux espaces près)
// renvoie KeyEmpty ; une plage vers est normalisée avec c.
func Parse(raw string, c version.Comparer) (Query, error) {
	if len(raw) > MaxQueryLen || !utf8.ValidString(raw) {
		return Query{}, refuse(KeyTooLong)
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
	if len(fields) == 0 {
		return Query{}, refuse(KeyEmpty)
	}
	q := Query{Raw: strings.Join(fields, " ")}
	var vers []string
	var rest []string
	for _, f := range fields {
		if strings.HasPrefix(strings.ToLower(f), "vers:") {
			vers = append(vers, f)
		} else {
			rest = append(rest, f)
		}
	}
	first := strings.ToLower(rest0(rest))
	switch {
	case len(vers) > 0:
		if len(vers) > 1 || len(rest) != 1 || !strings.HasPrefix(first, "pkg:") {
			return Query{}, refuse(KeyRangeNeedsPURL)
		}
		return parsePURL(q, rest[0], vers[0], c)
	case strings.HasPrefix(first, "pkg:"):
		if len(rest) != 1 {
			return Query{}, refuse(KeyPURLInvalid)
		}
		return parsePURL(q, rest[0], "", c)
	case strings.HasPrefix(first, "cve-"), strings.HasPrefix(first, "ghsa-"):
		return parseVuln(q, rest)
	case strings.HasPrefix(first, "sha256:"), len(rest) == 1 && hexPattern.MatchString(first):
		return parseHash(q, rest)
	case strings.HasPrefix(first, "license:"):
		return Query{}, refuse(KeyLicense)
	}
	q.Kind, q.Name = KindName, q.Raw
	if utf8.RuneCountInString(q.Name) > MaxNameLen {
		return Query{}, refuse(KeyTooLong)
	}
	return q, nil
}

func rest0(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func parsePURL(q Query, raw, vers string, c version.Comparer) (Query, error) {
	// Le schéma « pkg » ne tient pas compte de la casse ; packageurl-go l'exige minuscule.
	raw = "pkg:" + raw[len("pkg:"):]
	p, err := sbom.CanonicalPURL(raw)
	if err != nil || p.Name == "" {
		return Query{}, refuse(KeyPURLInvalid)
	}
	parsed, err := packageurl.FromString(p.String)
	if err != nil {
		return Query{}, refuse(KeyPURLInvalid)
	}
	q.Kind = KindPURL
	q.PURL = PURLQuery{PURL: p, Qualifiers: parsed.Qualifiers.Map(), Subpath: parsed.Subpath, Scheme: version.ForPURLType(p.Type)}
	if vers == "" {
		return q, nil
	}
	if p.Version != "" {
		return Query{}, refuse(KeyRangeAndVersion)
	}
	r, err := version.ParseVers(vers, c)
	switch {
	case errors.Is(err, version.ErrVersScheme):
		return Query{}, refuse(KeyVersScheme)
	case errors.Is(err, version.ErrVersDuplicate):
		return Query{}, refuse(KeyVersDuplicate)
	case errors.Is(err, version.ErrVersVersion):
		return Query{}, refuse(KeyVersVersion)
	case err != nil:
		return Query{}, refuse(KeyVersInvalid)
	}
	if r.Scheme != q.PURL.Scheme {
		return Query{}, refuse(KeyVersMismatch)
	}
	q.Range = &r
	return q, nil
}

func parseVuln(q Query, rest []string) (Query, error) {
	if len(rest) != 1 {
		return Query{}, refuse(KeyVulnInvalid)
	}
	id := rest[0]
	upper := strings.ToUpper(id)
	switch {
	case cvePattern.MatchString(upper):
		id = upper
	case ghsaPattern.MatchString("GHSA" + strings.ToLower(id[4:])):
		id = "GHSA" + strings.ToLower(id[4:])
	default:
		return Query{}, refuse(KeyVulnInvalid)
	}
	q.Kind, q.VulnID = KindVulnerability, id
	return q, nil
}

func parseHash(q Query, rest []string) (Query, error) {
	if len(rest) != 1 {
		return Query{}, refuse(KeyHashInvalid)
	}
	v := strings.ToLower(rest[0])
	v = strings.TrimPrefix(v, "sha256:")
	if !hexPattern.MatchString(v) {
		return Query{}, refuse(KeyHashInvalid)
	}
	q.Kind, q.Hash = KindHash, "sha256:"+v
	return q, nil
}

// Token est un élément de la requête telle qu'elle a été comprise (« Interprété comme ») :
// la clé de traduction de sa nature et sa valeur.
type Token struct {
	KindKey string
	Value   string
}

// Tokens décrit la requête analysée.
func (q Query) Tokens() []Token {
	switch q.Kind {
	case KindPURL:
		out := []Token{{KindKey: "search.kind_purl", Value: q.PURL.PURL.String}}
		if q.Range != nil {
			out = append(out, Token{KindKey: "search.kind_range", Value: q.Range.String()})
		}
		return out
	case KindVulnerability:
		return []Token{{KindKey: "search.kind_vulnerability", Value: q.VulnID}}
	case KindHash:
		return []Token{{KindKey: "search.kind_hash", Value: q.Hash}}
	case KindName:
		return []Token{{KindKey: "search.kind_name", Value: q.Name}}
	}
	return nil
}
