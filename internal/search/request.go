package search

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/vuln"
)

// Sort est l'ordre des projets d'un résultat.
type Sort string

// Ordres des projets.
const (
	SortRisk     Sort = "risk"     // risque maximal décroissant (défaut)
	SortName     Sort = "name"     // nom du projet
	SortSnapshot Sort = "snapshot" // instantané le plus récent d'abord
)

// Sorts renvoie les ordres possibles, le défaut en premier.
func Sorts() []Sort { return []Sort{SortRisk, SortName, SortSnapshot} }

// SeverityNone filtre les occurrences sans vulnérabilité ouverte.
const SeverityNone = "none"

// Bornes des filtres.
const (
	maxFilterValues = 32
	maxLabelLen     = 200
)

// Filters restreint un résultat. Dans un même filtre, les valeurs s'additionnent (« ou ») ;
// les filtres se combinent entre eux (« et »).
type Filters struct {
	// ProjectKinds : natures de premier niveau retenues (toutes si vide).
	ProjectKinds []project.Kind
	// Containers ajoute les conteneurs (projets enfants des hôtes), écartés sinon.
	Containers bool
	// Teams : équipes propriétaires retenues (toutes les équipes visibles si vide). Une
	// équipe invisible du compte ne donne rien : la visibilité s'applique d'abord.
	Teams []uuid.UUID
	// Labels : étiquettes « clé=valeur », ou « clé » pour une étiquette sans valeur.
	Labels  []string
	Origins []sbom.Origin
	// KEV : seulement les occurrences d'une vulnérabilité activement exploitée.
	KEV bool
	// Severities : sévérité maximale des vulnérabilités ouvertes de l'occurrence (ou, pour
	// une recherche par vulnérabilité, sa sévérité) ; SeverityNone : aucune.
	Severities []string
	// Resolved : une recherche par vulnérabilité montre aussi les constats résolus.
	Resolved bool
	// Triage : statuts de triage effectifs retenus (recherche par vulnérabilité seulement,
	// KeyTriageVulnOnly sinon) ; tous si vide.
	Triage []triage.Status
	// At : état des inventaires à cette date (T21) ; nil : inventaires courants. Pour
	// chaque référence, l'instantané retenu est le dernier scanné avant At ; les
	// vulnérabilités ne sont pas montrées (les constats d'alors ne sont pas conservés).
	At *time.Time
}

// Active indique si un filtre au moins est posé.
func (f Filters) Active() bool {
	return len(f.ProjectKinds) > 0 || f.Containers || len(f.Teams) > 0 || len(f.Labels) > 0 || len(f.Origins) > 0 || f.KEV ||
		len(f.Severities) > 0 || f.Resolved || len(f.Triage) > 0 || f.At != nil
}

// kinds renvoie les natures de projets retenues : celles demandées, ou toutes celles de
// premier niveau, plus les conteneurs s'ils sont inclus.
func (f Filters) kinds() []string {
	base := f.ProjectKinds
	if len(base) == 0 {
		base = project.Kinds()
	}
	out := make([]string, 0, len(base)+1)
	for _, k := range base {
		out = append(out, string(k))
	}
	if f.Containers {
		out = append(out, string(project.KindContainer))
	}
	return out
}

// Request est une recherche telle que l'écran et l'API la reçoivent : requête, filtres,
// ordre et page. Ses paramètres d'URL sont les mêmes partout, si bien qu'une URL partagée
// redonne le même résultat et que l'API répond comme l'écran.
type Request struct {
	Q       string
	Filters Filters
	Sort    Sort
	Cursor  string
	// Limit : projets par page (DefaultPage si nul).
	Limit int
}

// Pages de projets.
const (
	DefaultPage = 20
	MaxPage     = 100
)

// Paramètres d'URL d'une recherche.
const (
	ParamQuery = "q"
	ParamKind  = "type"
	// ParamContainers vaut « 1 » pour inclure les conteneurs.
	ParamContainers = "containers"
	ParamTeam       = "team"
	ParamLabel      = "label"
	ParamOrigin     = "origin"
	ParamKEV        = "kev"
	ParamSeverity   = "severity"
	ParamResolved   = "resolved"
	ParamTriage     = "triage"
	// ParamAt : « à la date du », AAAA-MM-JJ (fin de la journée UTC) ou RFC 3339.
	ParamAt     = "at"
	ParamSort   = "sort"
	ParamCursor = "cursor"
	ParamLimit  = "limit"
)

func severityValues() []string {
	out := []string{}
	for _, s := range vuln.Severities() {
		out = append(out, string(s))
	}
	return append(out, SeverityNone)
}

// ParseRequest lit une recherche depuis ses paramètres d'URL. Une valeur de filtre
// inconnue est refusée (KeyFilterInvalid) plutôt qu'ignorée : une URL partagée ne change
// pas de sens en silence.
func ParseRequest(v url.Values) (Request, error) {
	r := Request{Q: v.Get(ParamQuery), Sort: SortRisk, Cursor: v.Get(ParamCursor)}
	var err error
	if r.Filters.ProjectKinds, err = closed(v[ParamKind], project.Kinds()); err != nil {
		return Request{}, err
	}
	if r.Filters.Origins, err = closed(v[ParamOrigin], sbom.Origins()); err != nil {
		return Request{}, err
	}
	if r.Filters.Severities, err = closed(v[ParamSeverity], severityValues()); err != nil {
		return Request{}, err
	}
	if r.Filters.Triage, err = closed(v[ParamTriage], triage.Statuses()); err != nil {
		return Request{}, err
	}
	if r.Filters.Teams, err = teamIDs(v[ParamTeam]); err != nil {
		return Request{}, err
	}
	labels := v[ParamLabel]
	if len(labels) > maxFilterValues {
		return Request{}, refuse(KeyFilterInvalid)
	}
	for _, l := range labels {
		l = strings.TrimSpace(l)
		if l == "" || len(l) > maxLabelLen {
			return Request{}, refuse(KeyFilterInvalid)
		}
		parsed, err := labelPair(l)
		if err != nil {
			return Request{}, err
		}
		l = parsed.Pairs()[0]
		if !slices.Contains(r.Filters.Labels, l) {
			r.Filters.Labels = append(r.Filters.Labels, l)
		}
	}
	slices.Sort(r.Filters.Labels)
	if r.Filters.Containers, err = flag(v, ParamContainers); err != nil {
		return Request{}, err
	}
	if r.Filters.KEV, err = flag(v, ParamKEV); err != nil {
		return Request{}, err
	}
	if r.Filters.Resolved, err = flag(v, ParamResolved); err != nil {
		return Request{}, err
	}
	if s := strings.TrimSpace(v.Get(ParamAt)); s != "" {
		at, err := ParseAt(s)
		if err != nil {
			return Request{}, err
		}
		r.Filters.At = &at
	}
	if s := v.Get(ParamSort); s != "" {
		if !slices.Contains(Sorts(), Sort(s)) {
			return Request{}, refuse(KeyFilterInvalid)
		}
		r.Sort = Sort(s)
	}
	if s := v.Get(ParamLimit); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return Request{}, &pagination.LimitError{Max: MaxPage}
		}
		if r.Limit, err = pagination.Limit(&n, DefaultPage, MaxPage); err != nil {
			return Request{}, err
		}
	}
	return r, nil
}

// closed lit les valeurs d'un filtre à valeurs fermées, sans doublon, dans l'ordre de
// allowed.
func closed[T ~string](values []string, allowed []T) ([]T, error) {
	if len(values) > maxFilterValues {
		return nil, refuse(KeyFilterInvalid)
	}
	var out []T
	for _, a := range allowed {
		if slices.Contains(values, string(a)) {
			out = append(out, a)
		}
	}
	for _, v := range values {
		if !slices.Contains(allowed, T(v)) {
			return nil, refuse(KeyFilterInvalid)
		}
	}
	return out, nil
}

// teamIDs lit les équipes d'un filtre : identifiants valides, sans doublon, triés.
func teamIDs(values []string) ([]uuid.UUID, error) {
	if len(values) > maxFilterValues {
		return nil, refuse(KeyFilterInvalid)
	}
	var out []uuid.UUID
	for _, s := range values {
		id, err := uuid.Parse(s)
		if err != nil || id == uuid.Nil {
			return nil, refuse(KeyFilterInvalid)
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	return out, nil
}

func flag(v url.Values, name string) (bool, error) {
	switch v.Get(name) {
	case "":
		return false, nil
	case "1":
		return true, nil
	}
	return false, refuse(KeyFilterInvalid)
}

// labelPair lit une étiquette de filtre : « clé=valeur » ou « clé » (valeur vide), clé en
// minuscules comme dans les projets.
func labelPair(l string) (project.Labels, error) {
	labels, err := project.ParseLabels(l)
	if err != nil || len(labels) != 1 {
		return nil, refuse(KeyFilterInvalid)
	}
	return labels, nil
}

// Values écrit la recherche en paramètres d'URL, sous une forme stable (valeurs triées,
// défauts omis, sans curseur ni taille de page).
func (r Request) Values() url.Values {
	v := url.Values{}
	if q := strings.TrimSpace(r.Q); q != "" {
		v.Set(ParamQuery, q)
	}
	for _, k := range r.Filters.ProjectKinds {
		v.Add(ParamKind, string(k))
	}
	if r.Filters.Containers {
		v.Set(ParamContainers, "1")
	}
	for _, t := range r.Filters.Teams {
		v.Add(ParamTeam, t.String())
	}
	for _, l := range r.Filters.Labels {
		v.Add(ParamLabel, l)
	}
	for _, o := range r.Filters.Origins {
		v.Add(ParamOrigin, string(o))
	}
	if r.Filters.KEV {
		v.Set(ParamKEV, "1")
	}
	for _, s := range r.Filters.Severities {
		v.Add(ParamSeverity, s)
	}
	if r.Filters.Resolved {
		v.Set(ParamResolved, "1")
	}
	for _, s := range r.Filters.Triage {
		v.Add(ParamTriage, string(s))
	}
	if r.Filters.At != nil {
		v.Set(ParamAt, FormatAt(*r.Filters.At))
	}
	if r.Sort != "" && r.Sort != SortRisk {
		v.Set(ParamSort, string(r.Sort))
	}
	return v
}

// ParseAt lit une date « à la date du » : AAAA-MM-JJ désigne la fin de cette journée en
// UTC (les instantanés scannés ce jour-là comptent), une date RFC 3339 l'instant donné.
// L'instant rendu est exclusif : les instantanés retenus sont scannés avant lui.
func ParseAt(s string) (time.Time, error) {
	if d, err := time.Parse(time.DateOnly, s); err == nil {
		return d.AddDate(0, 0, 1), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Year() < 2000 {
		return time.Time{}, refuse(KeyAtInvalid)
	}
	return t.UTC(), nil
}

// FormatAt écrit l'instant de ParseAt sous sa forme la plus courte : une date pour une
// fin de journée UTC, sinon RFC 3339.
func FormatAt(t time.Time) string {
	t = t.UTC()
	if t.Equal(t.Truncate(24 * time.Hour)) {
		return t.AddDate(0, 0, -1).Format(time.DateOnly)
	}
	return t.Format(time.RFC3339)
}

// Without renvoie les paramètres de la recherche sans la valeur value du filtre param
// (lien « retirer le filtre »).
func (r Request) Without(param, value string) url.Values {
	v := r.Values()
	kept := slices.DeleteFunc(v[param], func(s string) bool { return s == value })
	if len(kept) == 0 {
		v.Del(param)
	} else {
		v[param] = kept
	}
	return v
}
