package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/license"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
)

// licenseFindingRow est une ligne de la liste des constats de licence.
type licenseFindingRow struct {
	license.Finding
	ComponentHref string
	ProjectHref   string
	VerdictKey    string
	Denied        bool
	RefKindKey    string
	Since         *stamp
}

// verdictTab est un filtre de verdict des constats de licence.
type verdictTab struct {
	LabelKey string
	Href     string
	Current  bool
	Count    int
}

// licensePolicyForm est la saisie de la politique : une licence par ligne.
type licensePolicyForm struct {
	Default        string
	Allowed        string
	Review         string
	Denied         string
	RequireLicense bool
}

func licenseForm(p license.Policy) licensePolicyForm {
	return licensePolicyForm{Default: string(p.Default), Allowed: strings.Join(p.Allowed, "\n"),
		Review: strings.Join(p.Review, "\n"), Denied: strings.Join(p.Denied, "\n"), RequireLicense: p.RequireLicense}
}

// splitIDs découpe une liste saisie : une licence par ligne, virgules et espaces admis.
func splitIDs(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' })
}

func (f licensePolicyForm) policy() license.Policy {
	return license.Policy{Default: license.Status(f.Default), Allowed: splitIDs(f.Allowed), Review: splitIDs(f.Review),
		Denied: splitIDs(f.Denied), RequireLicense: f.RequireLicense}
}

// licenseFindingsView est la liste des constats de licence (partiel license_findings).
type licenseFindingsView struct {
	Tabs      []verdictTab
	Rows      []licenseFindingRow
	Truncated bool
	InProject bool // dans l'onglet d'un projet : colonne du projet omise
}

type licensesView struct {
	render.Page
	Base      string
	CanManage bool
	Policy    license.Policy
	Form      licensePolicyForm
	Defaults  []option
	MaxListed int
	Findings  licenseFindingsView
	FlashKey  string
	Error     formError
}

func verdictKey(s license.Status) string { return "license_verdict." + string(s) }

func licenseRows(base string, fs []license.Finding) []licenseFindingRow {
	out := make([]licenseFindingRow, 0, len(fs))
	for _, f := range fs {
		out = append(out, licenseFindingRow{Finding: f, ComponentHref: base + "/components/" + f.ComponentID.String(),
			ProjectHref: base + "/projects/" + url.PathEscape(f.ProjectSlug), VerdictKey: verdictKey(f.Verdict),
			Denied: f.Verdict == license.StatusDenied, RefKindKey: "ref_kind." + f.RefKind, Since: stampOf(&f.FirstSeen)})
	}
	return out
}

// verdictFilter lit le filtre ?verdict= : vide, « review » ou « denied ».
func verdictFilter(r *http.Request) (license.Status, bool) {
	switch v := license.Status(r.URL.Query().Get("verdict")); v {
	case "", license.StatusReview, license.StatusDenied:
		return v, true
	default:
		return "", false
	}
}

func verdictTabs(href string, current license.Status, counts map[license.Status]int) []verdictTab {
	tabs := []verdictTab{{LabelKey: "licenses.filter_all", Href: href, Current: current == "",
		Count: counts[license.StatusReview] + counts[license.StatusDenied]}}
	for _, s := range []license.Status{license.StatusDenied, license.StatusReview} {
		tabs = append(tabs, verdictTab{LabelKey: verdictKey(s), Href: href + "?verdict=" + string(s), Current: current == s,
			Count: counts[s]})
	}
	return tabs
}

// licenses est la page des licences de l'organisation : sa politique (modifiable avec la
// permission de gérer les politiques) et les constats ouverts des projets visibles.
func (id *identity) licenses(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	p, err := id.Licenses.Policy(r.Context(), acc.Org)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	id.renderLicenses(w, r, http.StatusOK, p, licenseForm(p), formError{})
}

func (id *identity) renderLicenses(w http.ResponseWriter, r *http.Request, status int, p license.Policy, form licensePolicyForm, fe formError) {
	acc := access(r)
	verdict, ok := verdictFilter(r)
	if !ok {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	fs, err := id.Licenses.Findings(r.Context(), acc.Org, acc.Visibility(), uuid.Nil, verdict)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	counts, err := id.Licenses.Counts(r.Context(), acc.Org, acc.Visibility(), uuid.Nil)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base := orgBase(acc)
	view := &licensesView{Page: render.Page{TitleKey: "licenses.title", Nav: orgNav(acc, "licenses")}, Base: base,
		CanManage: acc.Can(tenant.PermPolicyManage, uuid.Nil), Policy: p, Form: form, MaxListed: license.MaxListed,
		Findings: licenseFindingsView{Tabs: verdictTabs(base+"/licenses", verdict, counts), Rows: licenseRows(base, fs),
			Truncated: len(fs) >= license.MaxFindings}, FlashKey: flashKey(r), Error: fe}
	for _, s := range license.Statuses() {
		view.Defaults = append(view.Defaults, option{Value: string(s), LabelKey: verdictKey(s), Selected: form.Default == string(s)})
	}
	id.rd.Render(w, r, status, "org/licenses", view)
}

// saveLicensePolicy enregistre la politique de licences ; la réévaluation des références
// suit dans un job (license.EvaluateOrgKind).
func (id *identity) saveLicensePolicy(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	acc := access(r)
	form := licensePolicyForm{Default: r.PostForm.Get("default"), Allowed: r.PostForm.Get("allowed"),
		Review: r.PostForm.Get("review"), Denied: r.PostForm.Get("denied"), RequireLicense: r.PostForm.Get("require_license") == "1"}
	if err := id.Licenses.SetPolicy(r.Context(), id.actor(r), acc.Org, form.policy()); err != nil {
		if fe, ok := validationOf(err); ok {
			p, perr := id.Licenses.Policy(r.Context(), acc.Org)
			if perr != nil {
				id.serverError(w, r, perr)
				return
			}
			id.renderLicenses(w, r, http.StatusUnprocessableEntity, p, form, fe)
			return
		}
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, orgBase(acc)+"/licenses", "license_policy_saved")
}

// licenseUsageRow est une licence de l'inventaire courant d'un projet.
type licenseUsageRow struct {
	license.Usage
	StatusKey string
	Denied    bool
	Review    bool
}

type projectLicensesView struct {
	render.Page
	Base     string
	Project  projectRow
	Tabs     []projectTab
	Usages   []licenseUsageRow
	Findings licenseFindingsView
}

// projectLicenses est l'onglet Licences d'un projet : les licences de son inventaire
// courant avec leur verdict, puis ses constats ouverts.
func (id *identity) projectLicenses(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	acc := access(r)
	verdict, ok := verdictFilter(r)
	if !ok {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	usages, err := id.Licenses.ProjectLicenses(r.Context(), acc.Org, acc.Visibility(), p.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	fs, err := id.Licenses.Findings(r.Context(), acc.Org, acc.Visibility(), p.ID, verdict)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	counts, err := id.Licenses.Counts(r.Context(), acc.Org, acc.Visibility(), p.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base := orgBase(acc)
	view := &projectLicensesView{
		Page: render.Page{TitleKey: "licenses.project_title", TitleArgs: map[string]any{"Name": p.Name}, Nav: orgNav(acc, "projects")},
		Base: base, Project: id.projectRow(p, id.Agents.Now()), Tabs: projectTabs(acc, p, "licenses"),
		Findings: licenseFindingsView{Tabs: verdictTabs(base+"/projects/"+url.PathEscape(p.Slug)+"/licenses", verdict, counts),
			Rows: licenseRows(base, fs), Truncated: len(fs) >= license.MaxFindings, InProject: true},
	}
	for _, u := range usages {
		view.Usages = append(view.Usages, licenseUsageRow{Usage: u, StatusKey: verdictKey(u.Status),
			Denied: u.Status == license.StatusDenied, Review: u.Status == license.StatusReview})
	}
	id.rd.Render(w, r, http.StatusOK, "projects/licenses", view)
}
