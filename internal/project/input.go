package project

import (
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"leblanc.io/lotor/internal/account"
)

// Clés de validation.
const (
	KeyKindInvalid     = "validation.project_kind_invalid"
	KeySlugInvalid     = "validation.project_slug_invalid"
	KeySlugTaken       = "validation.project_slug_taken"
	KeyNameInvalid     = "validation.name_invalid"
	KeyDescription     = "validation.description_too_long"
	KeyLabelInvalid    = "validation.label_invalid"
	KeyLabelsTooMany   = "validation.labels_too_many"
	KeyForgeURL        = "validation.forge_url_invalid"
	KeyRefInvalid      = "validation.ref_invalid"
	KeyRefsTooMany     = "validation.refs_too_many"
	KeyRefsMissing     = "validation.refs_missing"
	KeyHostRefInvalid  = "validation.host_ref_invalid"
	KeyHostRefTaken    = "validation.host_ref_taken"
	KeyAgentInvalid    = "validation.agent_invalid"
	KeyProjectArchived = "validation.project_archived"
	KeyTeamInvalid     = "validation.project_team_invalid"
	KeyContainerTeam   = "validation.container_team"
	KeyContainerAbsent = "validation.container_absent"
	KeyAIModeInvalid   = "validation.project_ai_mode_invalid"
	KeyAIExternalOff   = "validation.project_ai_external_forbidden"
)

// ValidationKeys liste les clés de validation du paquet (tests de traduction).
func ValidationKeys() []string {
	return []string{KeyKindInvalid, KeySlugInvalid, KeySlugTaken, KeyNameInvalid, KeyDescription,
		KeyLabelInvalid, KeyLabelsTooMany, KeyForgeURL, KeyRefInvalid, KeyRefsTooMany, KeyRefsMissing,
		KeyHostRefInvalid, KeyHostRefTaken, KeyAgentInvalid, KeyProjectArchived, KeyTeamInvalid, KeyContainerTeam,
		KeyContainerAbsent, KeyContainerInvalid, KeyContainersTooMany}
}

func invalid(field, key string) error { return &account.ValidationError{Field: field, Key: key} }

// Bornes des saisies.
const (
	maxName        = 100
	maxDescription = 2000
	maxLabels      = 20
	maxLabelValue  = 100
	maxRefs        = 50
	maxRefName     = 255
	maxForgeURL    = 500
	maxSlug        = 64
)

// slugPattern reprend la contrainte de la table projects.
var slugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

// labelKeyPattern : une lettre ou un chiffre, puis lettres, chiffres, « . », « _ », « / »
// ou « - » (64 caractères au plus).
var labelKeyPattern = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N}._/-]{0,63}$`)

// hostRefPattern : un nom d'hôte (lettres, chiffres, points, tirets, soulignés), 100
// caractères au plus pour servir aussi de nom au projet et à l'agent.
var hostRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// Labels sont les étiquettes clé=valeur d'un projet ; une valeur vide s'écrit « clé ».
type Labels map[string]string

// ParseLabels lit des étiquettes séparées par des virgules ou des retours à la ligne :
// « env=prod, exposé-internet ». Les clés sont mises en minuscules ; une clé répétée
// garde sa dernière valeur.
func ParseLabels(s string) (Labels, error) {
	out := Labels{}
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key, value, _ := strings.Cut(item, "=")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		if !labelKeyPattern.MatchString(key) || !validText(value, maxLabelValue) {
			return nil, invalid("labels", KeyLabelInvalid)
		}
		out[key] = value
	}
	if len(out) > maxLabels {
		return nil, invalid("labels", KeyLabelsTooMany)
	}
	return out, nil
}

// Validate vérifie des étiquettes venues d'ailleurs que ParseLabels (base, API).
func (l Labels) Validate() error {
	if len(l) > maxLabels {
		return invalid("labels", KeyLabelsTooMany)
	}
	for k, v := range l {
		if k != strings.ToLower(k) || !labelKeyPattern.MatchString(k) || !validText(v, maxLabelValue) ||
			strings.ContainsAny(v, ",=") {
			return invalid("labels", KeyLabelInvalid)
		}
	}
	return nil
}

// Keys renvoie les clés triées.
func (l Labels) Keys() []string { return slices.Sorted(maps.Keys(l)) }

// Pairs renvoie les étiquettes triées, écrites « clé=valeur » ou « clé ».
func (l Labels) Pairs() []string {
	out := make([]string, 0, len(l))
	for _, k := range l.Keys() {
		if v := l[k]; v != "" {
			out = append(out, k+"="+v)
		} else {
			out = append(out, k)
		}
	}
	return out
}

// String est la forme saisissable des étiquettes, relue par ParseLabels.
func (l Labels) String() string { return strings.Join(l.Pairs(), ", ") }

// validText : au plus max caractères, sans caractère de contrôle.
func validText(s string, max int) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

func validName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" || !validText(n, maxName) {
		return "", invalid("name", KeyNameInvalid)
	}
	return n, nil
}

func validDescription(d string) (string, error) {
	d = strings.TrimSpace(d)
	if utf8.RuneCountInString(d) > maxDescription || !utf8.ValidString(d) ||
		strings.ContainsFunc(d, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' }) {
		return "", invalid("description", KeyDescription)
	}
	return d, nil
}

// validForgeURL accepte une URL https (ou http) absolue, sans identifiants.
func validForgeURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	u, err := url.Parse(s)
	if err != nil || len(s) > maxForgeURL || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || !validText(s, maxForgeURL) {
		return "", invalid("forge_url", KeyForgeURL)
	}
	return s, nil
}

// validRefName applique l'essentiel des règles de git check-ref-format à un nom de
// branche ou d'étiquette.
func validRefName(name string) bool {
	if name == "" || len(name) > maxRefName || !utf8.ValidString(name) ||
		strings.HasPrefix(name, "-") || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") ||
		strings.HasSuffix(name, ".") || strings.HasSuffix(name, ".lock") ||
		strings.Contains(name, "..") || strings.Contains(name, "//") || strings.Contains(name, "@{") {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r) || strings.ContainsRune(`~^:?*[\`, r)
	})
}

// ParseRefNames lit une liste de noms de branches ou d'étiquettes (virgules, espaces ou
// retours à la ligne), sans doublon, dans l'ordre de saisie.
func ParseRefNames(s, field string) ([]string, error) {
	var out []string
	for _, name := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		if !validRefName(name) {
			return nil, invalid(field, KeyRefInvalid)
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	if len(out) > maxRefs {
		return nil, invalid(field, KeyRefsTooMany)
	}
	return out, nil
}

// MaxVersions borne les versions suivies d'un dépôt (ADR 0057) : chaque envoi d'une
// nouvelle version par le point compatible Dependency-Track en crée une.
const MaxVersions = 200

// ValidVersionName accepte un nom de version de Dependency-Track : 1 à 255 caractères
// imprimables, sans espace en tête ni en fin, sans caractère de contrôle.
func ValidVersionName(name string) bool {
	return name != "" && name == strings.TrimSpace(name) && validText(name, maxRefName)
}

// ParseVersionNames lit des noms de version, un par ligne (une version peut contenir une
// espace ou une virgule).
func ParseVersionNames(s string) ([]string, error) {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		if !ValidVersionName(name) {
			return nil, invalid("versions", KeyRefInvalid)
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	if len(out) > MaxVersions {
		return nil, invalid("versions", KeyRefsTooMany)
	}
	return out, nil
}

// NormalizeHostRef met une référence d'hôte (son nom) en minuscules et la valide.
func NormalizeHostRef(s string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(s))
	if !hostRefPattern.MatchString(h) {
		return "", invalid("host_ref", KeyHostRefInvalid)
	}
	return h, nil
}

// Slugify dérive un identifiant d'URL d'un nom : minuscules sans accents, tout autre
// caractère devient un tiret.
func Slugify(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range norm.NFD.String(strings.ToLower(name)) {
		switch {
		case unicode.Is(unicode.Mn, r):
			continue
		case r < utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsDigit(r)):
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.TrimRight(b.String(), "-")
	if len(s) > maxSlug {
		s = strings.TrimRight(s[:maxSlug], "-")
	}
	if s == "" {
		return "project"
	}
	return s
}
