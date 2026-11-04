package web

import (
	"html/template"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	apiv1 "leblanc.io/lotor/internal/api"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/search"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/vuln"
)

// facetOption est une case d'un filtre de l'écran de recherche.
type facetOption struct {
	ID       string
	Value    string
	LabelKey string // clé de traduction, ou vide si Label est déjà lisible
	Label    string
	Class    string // badge de la valeur (sévérité, origine, type de projet)
	Checked  bool
}

// searchChip est un filtre actif, avec le lien qui le retire.
type searchChip struct {
	LabelKey string
	Label    string
	// Date : filtre « à la date du », libellé search.at_chip.
	Date string
	Href template.URL
}

type searchHitRow struct {
	ComponentHref string
	Name          string
	PURL          string
	Version       string
	RefKind       string
	RefName       string
	CommitShort   string
	Origin        string
	Confidence    *int
	Weak          bool
	Open          int
	Sev           *sevBadge
	KEV           bool
	FindingsHref  string
	VulnID        string
	VulnHref      string
	Status        string
	Triage        *statusBadge
	TriageHref    string
	Fixed         []string
	Risk          int
	// Scanned : date de l'instantané retenu, à une date passée.
	Scanned *stamp
}

type searchGroupRow struct {
	ID        string
	Kind      string
	Name      string
	Href      string
	Labels    []string
	Team      string
	Scanned   *stamp
	Count     int
	Truncated bool
	Rows      []searchHitRow
}

type searchView struct {
	render.Page
	Base     string
	Action   string
	Q        string
	ErrorKey string
	Searched bool
	VulnMode bool
	Tokens   []search.Token
	// Résumé.
	Projects     int
	Hits         int
	Truncated    bool
	Approx       bool
	OutOfRange   int
	Unreadable   []search.VersionCount
	WithoutRange template.URL
	Groups       []searchGroupRow
	NextHref     template.URL
	Chips        []searchChip
	ResetHref    template.URL
	ExportCSV    template.URL
	ExportJSON   template.URL
	Kinds        []facetOption
	Teams        []facetOption
	Labels       []facetOption
	Origins      []facetOption
	Severities   []facetOption
	KEV          facetOption
	Containers   facetOption
	Resolved     facetOption
	// Triages : statuts de triage, proposés pour une recherche par vulnérabilité.
	Triages     []facetOption
	TriageFacet bool
	Sorts       []option
	Syntax      []syntaxExample
	// À la date du (T21) : At est la valeur du champ (AAAA-MM-JJ), Today sa borne ;
	// AtMode, une recherche à une date passée ; Horizon, la coupure de la rétention quand
	// la date la précède (résultat partiel).
	At      string
	Today   string
	AtMode  bool
	Horizon *stamp
}

// syntaxExample est une ligne de l'aide de syntaxe : un exemple, sa description.
type syntaxExample struct {
	Example string
	TextKey string
}

var syntaxExamples = []syntaxExample{
	{"log4j-core", "search.syntax_name"},
	{"pkg:npm/lodash vers:npm/<4.17.21", "search.syntax_purl"},
	{"CVE-2021-44228", "search.syntax_vulnerability"},
	{"sha256:0925e8ad7bd971391a8b1e98be8e87a6971919eb5b60c196485941c3c1df089a", "search.syntax_hash"},
	{"license:AGPL-3.0-only", "search.syntax_license"},
}

// href écrit des paramètres de recherche en lien relatif ; url.Values les encode, le
// résultat est sûr comme URL.
func href(path string, v url.Values) template.URL {
	if len(v) == 0 {
		return template.URL(path)
	}
	return template.URL(path + "?" + v.Encode())
}

// search est l'écran de recherche transverse : une barre, des filtres en formulaire GET,
// les résultats groupés par projet. Mêmes paramètres et mêmes résultats que l'API.
func (id *identity) search(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	base := orgBase(acc)
	view := &searchView{Page: render.Page{TitleKey: "search.title", Nav: orgNav(acc, "search")}, Base: base,
		Action: base + "/search", Syntax: syntaxExamples}
	req, err := search.ParseRequest(r.URL.Query())
	status := http.StatusOK
	if err != nil {
		e, ok := search.IsError(err)
		if !ok {
			id.serverError(w, r, err)
			return
		}
		view.ErrorKey, status = e.Key, http.StatusBadRequest
		req = search.Request{Q: r.URL.Query().Get(search.ParamQuery), Sort: search.SortRisk}
	}
	view.Q = req.Q
	if req.Q != "" {
		view.TitleKey, view.TitleArgs = "search.title_query", map[string]any{"Query": req.Q}
	}
	labels, err := id.Search.Labels(r.Context(), acc.Org, acc.Visibility())
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	teams, err := id.Orgs.Teams(r.Context(), acc.Org, acc.Visibility())
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	var teamNames []facetOption
	for _, t := range teams {
		teamNames = append(teamNames, facetOption{Value: t.ID.String(), Label: t.Name})
	}
	// Le filtre de triage n'a de sens que pour une recherche par vulnérabilité : il n'est
	// proposé que pour elle, ou s'il est déjà posé (l'erreur dit alors pourquoi).
	if q, err := search.Parse(req.Q, id.Search.Comparer()); (err == nil && q.Kind == search.KindVulnerability) || len(req.Filters.Triage) > 0 {
		view.TriageFacet = true
	}
	id.searchFacets(view, req, labels, teamNames)
	if view.ErrorKey == "" && req.Q != "" {
		res, err := id.Search.Search(r.Context(), acc.Org, acc.Visibility(), req)
		switch {
		case err == nil:
			id.searchResults(view, req, res)
		case isPaginationError(err):
			id.rd.Error(w, r, http.StatusBadRequest)
			return
		default:
			e, ok := search.IsError(err)
			if !ok {
				id.serverError(w, r, err)
				return
			}
			view.ErrorKey, status = e.Key, http.StatusBadRequest
		}
	}
	id.rd.Render(w, r, status, "search/index", view)
}

// searchFacets prépare les filtres, l'ordre, les filtres actifs et les liens d'export.
func (id *identity) searchFacets(view *searchView, req search.Request, labels []string, teams []facetOption) {
	f := req.Filters
	path := view.Action
	chip := func(param, value, key, label string) {
		view.Chips = append(view.Chips, searchChip{LabelKey: key, Label: label, Href: href(path, req.Without(param, value))})
	}
	for _, k := range project.Kinds() {
		on := slices.Contains(f.ProjectKinds, k)
		cls := "ptype"
		if k == project.KindHost {
			cls += " ptype--server"
		}
		view.Kinds = append(view.Kinds, facetOption{ID: "f-type-" + string(k), Value: string(k), LabelKey: "project_type." + string(k),
			Class: cls, Checked: on})
		if on {
			chip(search.ParamKind, string(k), "project_type."+string(k), "")
		}
	}
	for i, t := range teams {
		on := slices.ContainsFunc(f.Teams, func(u uuid.UUID) bool { return u.String() == t.Value })
		view.Teams = append(view.Teams, facetOption{ID: "f-team-" + strconv.Itoa(i), Value: t.Value, Label: t.Label, Checked: on})
		if on {
			chip(search.ParamTeam, t.Value, "", t.Label)
		}
	}
	for _, u := range f.Teams {
		if !slices.ContainsFunc(teams, func(t facetOption) bool { return t.Value == u.String() }) {
			// Équipe d'une URL partagée invisible du compte (ou supprimée) : elle ne donne
			// aucun résultat ; la case reste visible et cochée, sans en révéler le nom.
			view.Teams = append(view.Teams, facetOption{ID: "f-team-" + strconv.Itoa(len(view.Teams)), Value: u.String(),
				LabelKey: "search.team_unknown", Checked: true})
			chip(search.ParamTeam, u.String(), "search.team_unknown", "")
		}
	}
	for i, l := range labels {
		on := slices.Contains(f.Labels, l)
		view.Labels = append(view.Labels, facetOption{ID: "f-label-" + strconv.Itoa(i), Value: l, Label: l, Class: "chip chip--tag", Checked: on})
	}
	for _, l := range f.Labels {
		chip(search.ParamLabel, l, "", l)
		if !slices.Contains(labels, l) {
			// Étiquette d'une URL partagée sans projet actif : la case reste visible et cochée.
			view.Labels = append(view.Labels, facetOption{ID: "f-label-" + strconv.Itoa(len(view.Labels)), Value: l, Label: l,
				Class: "chip chip--tag", Checked: true})
		}
	}
	for _, o := range sbom.Origins() {
		on := slices.Contains(f.Origins, o)
		view.Origins = append(view.Origins, facetOption{ID: "f-origin-" + string(o), Value: string(o), LabelKey: "origin." + string(o),
			Class: "origin origin--" + string(o), Checked: on})
		if on {
			chip(search.ParamOrigin, string(o), "origin."+string(o), "")
		}
	}
	for _, s := range append(vuln.Severities(), search.SeverityNone) {
		on := slices.Contains(f.Severities, string(s))
		opt := facetOption{ID: "f-sev-" + string(s), Value: string(s), LabelKey: "severity." + string(s), Checked: on}
		if c, ok := sevClasses[s]; ok {
			opt.Class = c
		} else {
			opt.LabelKey = "search.severity_none"
		}
		view.Severities = append(view.Severities, opt)
		if on {
			chip(search.ParamSeverity, string(s), opt.LabelKey, "")
		}
	}
	view.Today = id.Agents.Now().Format(time.DateOnly)
	if f.At != nil {
		view.At = search.FormatAt(*f.At)
		view.AtMode = true
		view.Chips = append(view.Chips, searchChip{Date: view.At, Href: href(path, req.Without(search.ParamAt, view.At))})
	}
	view.Containers = facetOption{ID: "f-containers", Value: "1", Checked: f.Containers}
	if f.Containers {
		chip(search.ParamContainers, "1", "search.filter_containers", "")
	}
	view.KEV = facetOption{ID: "f-kev", Value: "1", Checked: f.KEV}
	if f.KEV {
		chip(search.ParamKEV, "1", "search.filter_kev", "")
	}
	view.Resolved = facetOption{ID: "f-resolved", Value: "1", Checked: f.Resolved}
	if f.Resolved {
		chip(search.ParamResolved, "1", "search.filter_resolved", "")
	}
	for _, s := range triage.Statuses() {
		on := slices.Contains(f.Triage, s)
		b := triageBadge(s)
		view.Triages = append(view.Triages, facetOption{ID: "f-triage-" + string(s), Value: string(s), LabelKey: b.LabelKey,
			Class: b.Class, Checked: on})
		if on {
			chip(search.ParamTriage, string(s), b.LabelKey, "")
		}
	}
	for _, s := range search.Sorts() {
		view.Sorts = append(view.Sorts, option{Value: string(s), LabelKey: "search.sort_" + string(s), Selected: req.Sort == s})
	}
	view.ResetHref = href(path, url.Values{search.ParamQuery: {req.Q}})
	exp := req.Values()
	exp.Set("format", string(search.FormatCSV))
	view.ExportCSV = href(path+"/export", exp)
	exp.Set("format", string(search.FormatJSON))
	view.ExportJSON = href(path+"/export", exp)
}

// searchResults met en forme une page de résultats.
func (id *identity) searchResults(view *searchView, req search.Request, res search.Result) {
	base := view.Base
	view.Searched = true
	view.VulnMode = res.Query.Kind == search.KindVulnerability
	view.Tokens = res.Query.Tokens()
	view.Projects, view.Hits, view.Truncated, view.Approx = res.Projects, res.Hits, res.Truncated, res.Approx
	view.OutOfRange, view.Unreadable = res.OutOfRange, res.Unreadable
	if res.Partial {
		view.Horizon = stampOf(res.Horizon)
	}
	if res.Query.Range != nil {
		v := req.Values()
		v.Set(search.ParamQuery, res.Query.PURL.PURL.String)
		view.WithoutRange = href(view.Action, v)
	}
	for _, g := range res.Groups {
		gr := searchGroupRow{ID: "g-" + g.Project.ID.String(), Kind: string(g.Project.Kind), Name: g.Project.Name,
			Href: base + "/projects/" + g.Project.Slug, Labels: g.Project.Labels.Pairs(), Team: g.Project.Team.Name,
			Scanned: stampOf(g.Scanned),
			Count:   g.HitCount, Truncated: g.Truncated}
		for _, h := range g.Hits {
			row := searchHitRow{ComponentHref: base + "/components/" + h.ComponentID.String(), Name: h.Name, PURL: h.PURL,
				Version: h.Version, RefKind: h.RefKind, RefName: h.RefName, CommitShort: shortCommit(h.Commit),
				Origin: string(h.Origin), Weak: h.Weak, Open: h.Open, KEV: h.KEV, Fixed: h.Fixed, Risk: riskOf(h.Risk),
				Status: string(h.Status), FindingsHref: base + "/projects/" + g.Project.Slug + "/findings?ref=" + h.RefID.String()}
			if view.AtMode && !h.ScannedAt.IsZero() {
				row.Scanned = stampAt(h.ScannedAt)
			}
			if h.Confidence != nil {
				pct := int(math.Round(*h.Confidence * 100))
				row.Confidence = &pct
			}
			if h.Severity != "" {
				s := sevOf(h.Severity, nil)
				row.Sev = &s
			}
			if h.VulnID != "" {
				row.VulnID, row.VulnHref = h.VulnID, base+"/vulnerabilities/"+url.PathEscape(h.VulnID)
			}
			if h.Triage != "" {
				b := triageBadge(h.Triage)
				row.Triage = &b
				row.TriageHref = base + "/projects/" + g.Project.Slug + "/findings/" + h.FindingID.String()
			}
			gr.Rows = append(gr.Rows, row)
		}
		view.Groups = append(view.Groups, gr)
	}
	if res.NextCursor != "" {
		v := req.Values()
		v.Set(search.ParamCursor, res.NextCursor)
		view.NextHref = href(view.Action, v)
	}
}

// searchExport sert l'export CSV ou JSON d'une recherche (mêmes paramètres que l'écran).
func (id *identity) searchExport(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	apiv1.ServeExport(w, r, apiv1.ExportOptions{Search: id.Search, Exports: id.Exports, Catalog: id.cat, Logger: id.logger,
		Org: acc.Org, Visibility: acc.Visibility(), Slug: acc.Slug, Format: r.URL.Query().Get("format"), UserID: viewerFrom(r).user.ID})
}
