package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/open-go-base/i18n"

	"leblanc.io/lotor/internal/license"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/policy"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/vuln"
)

// Politiques, violations et alertes (T15, ADR 0045 à 0047) : liste et édition des
// règles (validation et aperçu du nombre de violations avant enregistrement), modèles
// fournis, liste des violations.

// exprError est une erreur de règle prête à afficher : clé, position et détail technique.
type exprError struct {
	Key    string
	Args   map[string]any
	Detail string
}

type policyRow struct {
	policy.Policy
	Href          string
	ViolationsURL string
	DeleteHref    string
	SubjectKey    string
	DeliveryKey   string
}

type templateRow struct {
	Key       string
	Subject   string
	Href      string
	Available bool
	Blocking  bool
}

type policiesView struct {
	render.Page
	Base      string
	Rows      []policyRow
	Templates []templateRow
	NewHref   string
	FlashKey  string
	Max       int
}

func (id *identity) policyRow(base string, p policy.Policy) policyRow {
	h := base + "/policies/" + p.ID.String()
	return policyRow{Policy: p, Href: h, DeleteHref: h + "/delete",
		ViolationsURL: base + "/violations?policy=" + p.ID.String(), SubjectKey: "policy_subject." + string(p.Subject),
		DeliveryKey: "policy_delivery." + string(p.Delivery)}
}

// policies est la liste des règles et des modèles fournis.
func (id *identity) policies(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	ps, err := id.Policies.List(r.Context(), acc.Org)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base := orgBase(acc)
	view := &policiesView{Page: render.Page{TitleKey: "policies.title", Nav: orgNav(acc, "policies")}, Base: base,
		NewHref: base + "/policies/new", FlashKey: flashKey(r), Max: policy.MaxPolicies}
	for _, p := range ps {
		view.Rows = append(view.Rows, id.policyRow(base, p))
	}
	for _, t := range policy.Templates() {
		view.Templates = append(view.Templates, templateRow{Key: t.Key, Subject: string(t.Subject), Available: t.Available,
			Blocking: t.Blocking, Href: base + "/policies/new?template=" + url.QueryEscape(t.Key)})
	}
	id.rd.Render(w, r, http.StatusOK, "org/policies", view)
}

// policyForm est la saisie d'une règle, renvoyée telle quelle.
type policyForm struct {
	Name        string
	Description string
	Subject     string
	Expression  string
	Template    string
	Enabled     bool
	Blocking    bool
	Delivery    string
	Channels    map[string]bool
}

type channelChoice struct {
	ID      string
	Name    string
	KindKey string
	Checked bool
	Enabled bool
}

type policyView struct {
	render.Page
	Base       string
	Action     string
	Cancel     string
	Editing    bool
	Form       policyForm
	Subjects   []option
	Deliveries []option
	Channels   []channelChoice
	Error      formError
	Expr       *exprError
	// Preview : aperçu calculé (nombre de sujets en violation aujourd'hui).
	Preview       *previewResult
	ExpressionMax int
	DescMax       int
	TemplateKey   string
	LastError     string
	ChannelsHref  string
	Help          []helpGroup
	Examples      []string
	SaveValue     string
	PreviewValue  string
}

// Valeurs du bouton qui envoie le formulaire d'une règle.
const (
	actionSave    = "save"
	actionPreview = "preview"
)

// helpGroup présente les variables d'un sujet : nom, description traduite et champs (les
// noms CEL, tirés des types du contexte).
type helpGroup struct {
	TitleKey string
	Vars     []helpVar
}

type helpVar struct {
	Name    string
	DescKey string
	Fields  string
}

func ruleHelp() []helpGroup {
	var out []helpGroup
	for _, s := range policy.Subjects() {
		g := helpGroup{TitleKey: "policy_subject." + string(s)}
		for _, v := range policy.Variables(s) {
			g.Vars = append(g.Vars, helpVar{Name: v.Name, DescKey: "policy_help." + v.Name, Fields: strings.Join(v.Fields, ", ")})
		}
		out = append(out, g)
	}
	return out
}

func ruleExamples() []string {
	var out []string
	for _, t := range policy.Templates() {
		if t.Available {
			out = append(out, t.Expression)
		}
	}
	return out
}

type previewResult struct {
	Subject  string
	Matches  int
	Failures int
}

func (id *identity) renderPolicyForm(w http.ResponseWriter, r *http.Request, status int, editID uuid.UUID, form policyForm,
	fe formError, ee *exprError, pv *previewResult, lastError string) {
	acc := access(r)
	base := orgBase(acc)
	chans, err := id.Notify.Channels(r.Context(), acc.Org)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view := &policyView{Page: render.Page{TitleKey: "policy_form.title_new", Nav: orgNav(acc, "policies"), Failed: status >= 400},
		Base: base, Action: base + "/policies", Cancel: base + "/policies", Form: form, Error: fe, Expr: ee, Preview: pv,
		ExpressionMax: policy.MaxExpression, DescMax: policy.MaxDescription, TemplateKey: form.Template, LastError: lastError,
		ChannelsHref: base + "/channels", Help: ruleHelp(), Examples: ruleExamples(),
		SaveValue: actionSave, PreviewValue: actionPreview}
	if editID != uuid.Nil {
		view.Editing, view.Action = true, base+"/policies/"+editID.String()
		view.Page.TitleKey, view.Page.TitleArgs = "policy_form.title_edit", map[string]any{"Name": form.Name}
	}
	for _, s := range policy.Subjects() {
		view.Subjects = append(view.Subjects, option{Value: string(s), LabelKey: "policy_subject." + string(s),
			Selected: string(s) == form.Subject})
	}
	for _, d := range policy.Deliveries() {
		view.Deliveries = append(view.Deliveries, option{Value: string(d), LabelKey: "policy_delivery." + string(d),
			Selected: string(d) == form.Delivery})
	}
	for _, c := range chans {
		view.Channels = append(view.Channels, channelChoice{ID: c.ID.String(), Name: c.Name, KindKey: "channel_kind." + string(c.Kind),
			Checked: form.Channels[c.ID.String()], Enabled: c.Enabled})
	}
	id.rd.Render(w, r, status, "org/policy", view)
}

// newPolicy est le formulaire d'une nouvelle règle, vide ou parti d'un modèle.
func (id *identity) newPolicy(w http.ResponseWriter, r *http.Request) {
	form := policyForm{Subject: string(policy.SubjectFinding), Enabled: true, Delivery: string(policy.DeliveryImmediate),
		Channels: map[string]bool{}}
	if key := r.URL.Query().Get("template"); key != "" {
		t, ok := policy.TemplateByKey(key)
		if !ok {
			id.rd.Error(w, r, http.StatusNotFound)
			return
		}
		loc := id.localizer(r)
		form.Template, form.Subject, form.Expression = t.Key, string(t.Subject), t.Expression
		form.Blocking, form.Delivery = t.Blocking, string(t.Delivery)
		form.Name, form.Description = loc.T("policy_template."+t.Key+".name"), loc.T("policy_template."+t.Key+".text")
	}
	id.renderPolicyForm(w, r, http.StatusOK, uuid.Nil, form, formError{}, nil, nil, "")
}

func readPolicyForm(r *http.Request) (policyForm, policy.Input) {
	f := policyForm{Name: r.PostFormValue("name"), Description: r.PostFormValue("description"),
		Subject: r.PostFormValue("subject"), Expression: r.PostFormValue("expression"), Template: r.PostFormValue("template"),
		Enabled: r.PostFormValue("enabled") == "1", Blocking: r.PostFormValue("blocking") == "1",
		Delivery: r.PostFormValue("delivery"), Channels: map[string]bool{}}
	in := policy.Input{Name: f.Name, Description: f.Description, Subject: policy.Subject(f.Subject), Expression: f.Expression,
		Template: f.Template, Enabled: f.Enabled, Blocking: f.Blocking, Delivery: policy.Delivery(f.Delivery)}
	for _, v := range r.PostForm["channels"] {
		if cid, err := uuid.Parse(v); err == nil {
			f.Channels[cid.String()] = true
			in.Channels = append(in.Channels, cid)
		}
	}
	return f, in
}

// policyFormError traduit une erreur de saisie ou de règle.
func policyFormError(err error) (formError, *exprError, bool) {
	if e, ok := policy.IsExprError(err); ok {
		ee := &exprError{Key: e.Key, Args: map[string]any{"Line": e.Line, "Column": e.Column, "Name": e.Name}, Detail: e.Detail}
		return formError{Key: e.Key, Field: "expression"}, ee, true
	}
	if fe, ok := validationOf(err); ok {
		return fe, nil, true
	}
	return formError{}, nil, false
}

// savePolicy crée (editID nul) ou modifie une règle ; le bouton « Aperçu » compte les
// violations actuelles sans rien enregistrer.
func (id *identity) savePolicy(w http.ResponseWriter, r *http.Request, editID uuid.UUID) {
	if !id.parseForm(w, r) {
		return
	}
	acc := access(r)
	form, in := readPolicyForm(r)
	if r.PostFormValue("action") == actionPreview {
		matches, failures, err := id.Policies.Preview(r.Context(), acc.Org, in.Subject, in.Expression)
		if err != nil {
			if fe, ee, ok := policyFormError(err); ok {
				id.renderPolicyForm(w, r, http.StatusUnprocessableEntity, editID, form, fe, ee, nil, "")
				return
			}
			id.serverError(w, r, err)
			return
		}
		id.renderPolicyForm(w, r, http.StatusOK, editID, form, formError{}, nil,
			&previewResult{Subject: form.Subject, Matches: matches, Failures: failures}, "")
		return
	}
	var err error
	if editID == uuid.Nil {
		_, err = id.Policies.Create(r.Context(), acc.Org, id.actor(r), in)
	} else {
		_, err = id.Policies.Update(r.Context(), acc.Org, id.actor(r), editID, in)
	}
	switch {
	case errors.Is(err, policy.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	case err != nil:
		if fe, ee, ok := policyFormError(err); ok {
			id.renderPolicyForm(w, r, http.StatusUnprocessableEntity, editID, form, fe, ee, nil, "")
			return
		}
		id.serverError(w, r, err)
	default:
		redirectDone(w, r, orgBase(acc)+"/policies", "policy_saved")
	}
}

func (id *identity) createPolicy(w http.ResponseWriter, r *http.Request) {
	id.savePolicy(w, r, uuid.Nil)
}

// policyFromPath lit la règle {policyID}.
func (id *identity) policyFromPath(w http.ResponseWriter, r *http.Request) (policy.Policy, bool) {
	pid, err := uuid.Parse(chi.URLParam(r, "policyID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return policy.Policy{}, false
	}
	p, err := id.Policies.Get(r.Context(), access(r).Org, pid)
	if errors.Is(err, policy.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return p, false
	}
	if err != nil {
		id.serverError(w, r, err)
		return p, false
	}
	return p, true
}

func (id *identity) policyPage(w http.ResponseWriter, r *http.Request) {
	p, ok := id.policyFromPath(w, r)
	if !ok {
		return
	}
	form := policyForm{Name: p.Name, Description: p.Description, Subject: string(p.Subject), Expression: p.Expression,
		Template: p.Template, Enabled: p.Enabled, Blocking: p.Blocking, Delivery: string(p.Delivery), Channels: map[string]bool{}}
	for _, c := range p.Channels {
		form.Channels[c.String()] = true
	}
	id.renderPolicyForm(w, r, http.StatusOK, p.ID, form, formError{}, nil, nil, p.LastError)
}

func (id *identity) updatePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := id.policyFromPath(w, r)
	if !ok {
		return
	}
	id.savePolicy(w, r, p.ID)
}

func (id *identity) confirmDeletePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := id.policyFromPath(w, r)
	if !ok {
		return
	}
	acc := access(r)
	id.confirm(w, r, confirmation{nav: orgNav(acc, "policies"), heading: "confirm.policy_heading", text: "confirm.policy_text",
		submit: "confirm.policy_submit", args: map[string]any{"Name": p.Name, "Count": p.Open}, cancel: orgBase(acc) + "/policies"})
}

func (id *identity) deletePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := id.policyFromPath(w, r)
	if !ok {
		return
	}
	acc := access(r)
	err := id.Policies.Delete(r.Context(), acc.Org, id.actor(r), p.ID)
	switch {
	case errors.Is(err, policy.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	case err != nil:
		id.serverError(w, r, err)
	default:
		redirectDone(w, r, orgBase(acc)+"/policies", "policy_deleted")
	}
}

// violationRow est une violation prête à afficher.
type violationRow struct {
	Policy    string
	Blocking  bool
	Agent     bool
	AgentName string
	AgentHref string
	// License : constat de licence (T20) ; VulnID porte alors les licences décisives et
	// VerdictKey le verdict.
	License     bool
	VerdictKey  string
	Denied      bool
	VulnID      string
	VulnHref    string
	Sev         sevBadge
	KEV         bool
	Component   string
	Project     string
	ProjectHref string
	Ref         string
	FindingHref string
	Opened      *stamp
	Resolved    *stamp
}

type violationsView struct {
	render.Page
	Base       string
	Resolved   bool
	Tabs       []violationTab
	Rows       []violationRow
	NextHref   string
	PolicyID   string
	PolicyName string
	ClearHref  string
	CanManage  bool
}

type violationTab struct {
	LabelKey string
	Href     string
	Current  bool
}

// violations est la liste des violations visibles, ouvertes ou résolues.
func (id *identity) violations(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	q := r.URL.Query()
	f := policy.Filter{Resolved: q.Get("state") == "resolved"}
	if v := q.Get("policy"); v != "" {
		pid, err := uuid.Parse(v)
		if err != nil {
			id.rd.Error(w, r, http.StatusNotFound)
			return
		}
		f.PolicyID = pid
	}
	page, err := id.Policies.Violations(r.Context(), acc.Org, acc.Visibility(), f, q.Get("cursor"), policy.ViolationPageDefault)
	if err != nil {
		if fe, ok := validationOf(err); ok && fe.Field == "cursor" {
			id.rd.Error(w, r, http.StatusBadRequest)
			return
		}
		id.serverError(w, r, err)
		return
	}
	base := orgBase(acc)
	params := func(state, cursor string) string {
		v := url.Values{}
		if state != "" {
			v.Set("state", state)
		}
		if f.PolicyID != uuid.Nil {
			v.Set("policy", f.PolicyID.String())
		}
		if cursor != "" {
			v.Set("cursor", cursor)
		}
		if len(v) == 0 {
			return base + "/violations"
		}
		return base + "/violations?" + v.Encode()
	}
	state := ""
	if f.Resolved {
		state = "resolved"
	}
	view := &violationsView{Page: render.Page{TitleKey: "violations.title", Nav: orgNav(acc, "violations")}, Base: base,
		Resolved: f.Resolved, CanManage: acc.Can(tenant.PermPolicyManage, uuid.Nil),
		Tabs: []violationTab{{LabelKey: "violations.tab_open", Href: params("", ""), Current: !f.Resolved},
			{LabelKey: "violations.tab_resolved", Href: params("resolved", ""), Current: f.Resolved}}}
	if page.NextCursor != "" {
		view.NextHref = params(state, page.NextCursor)
	}
	if f.PolicyID != uuid.Nil {
		view.PolicyID = f.PolicyID.String()
		v := url.Values{}
		if f.Resolved {
			v.Set("state", "resolved")
		}
		view.ClearHref = base + "/violations"
		if len(v) > 0 {
			view.ClearHref += "?" + v.Encode()
		}
	}
	for _, v := range page.Items {
		row := violationRow{Policy: v.Policy, Blocking: v.Blocking, Opened: stampAt(v.OpenedAt), Resolved: stampOf(v.ResolvedAt)}
		if f.PolicyID != uuid.Nil {
			view.PolicyName = v.Policy
		}
		if v.Subject == policy.SubjectAgent {
			row.Agent, row.AgentName, row.AgentHref = true, v.Agent, base+"/agents/"+v.AgentID.String()
		} else if v.Subject == policy.SubjectLicense {
			licenseRow(&row, v, base)
		} else {
			projectHref := base + "/projects/" + url.PathEscape(v.ProjectSlug)
			row.VulnID, row.VulnHref = v.VulnID, base+"/vulnerabilities/"+url.PathEscape(v.VulnID)
			row.Sev, row.KEV, row.Component = sevOf(vulnSeverity(v.Severity), nil), v.KEV, v.Component
			row.Project, row.ProjectHref, row.Ref = v.Project, projectHref, v.Ref
			row.FindingHref = projectHref + "/findings/" + v.FindingID.String()
		}
		view.Rows = append(view.Rows, row)
	}
	id.rd.Render(w, r, http.StatusOK, "org/violations", view)
}

// licenseRow remplit la ligne d'une violation de licence (T20) : licences décisives,
// verdict, composant, lien vers l'onglet des licences du projet.
func licenseRow(row *violationRow, v policy.Violation, base string) {
	projectHref := base + "/projects/" + url.PathEscape(v.ProjectSlug)
	row.License, row.VulnID, row.VerdictKey, row.Component = true, v.VulnID, "license_verdict."+v.Severity, v.Component
	row.Denied = v.Severity == string(license.StatusDenied)
	row.Project, row.ProjectHref, row.Ref = v.Project, projectHref, v.Ref
	row.FindingHref = projectHref + "/licenses"
}

// alertsView est la section « Alertes » du tableau de bord.
type alertsView struct {
	Open     int
	Blocking int
	Recent   []violationRow
	Href     string
}

func (id *identity) alertsOf(r *http.Request, base string) (*alertsView, error) {
	acc := access(r)
	s, err := id.Policies.Summary(r.Context(), acc.Org, acc.Visibility())
	if err != nil {
		return nil, err
	}
	out := &alertsView{Open: s.Open, Blocking: s.Blocking, Href: base + "/violations"}
	for _, v := range s.Recent {
		row := violationRow{Policy: v.Policy, Blocking: v.Blocking, Opened: stampAt(v.OpenedAt)}
		if v.Subject == policy.SubjectAgent {
			row.Agent, row.AgentName, row.AgentHref = true, v.Agent, base+"/agents/"+v.AgentID.String()
		} else if v.Subject == policy.SubjectLicense {
			licenseRow(&row, v, base)
		} else {
			projectHref := base + "/projects/" + url.PathEscape(v.ProjectSlug)
			row.VulnID, row.Sev, row.KEV, row.Component = v.VulnID, sevOf(vulnSeverity(v.Severity), nil), v.KEV, v.Component
			row.Project, row.ProjectHref = v.Project, projectHref
			row.FindingHref = projectHref + "/findings/" + v.FindingID.String()
		}
		out.Recent = append(out.Recent, row)
	}
	return out, nil
}

// localizer renvoie le localiseur de la requête (langue résolue par la garde).
func (id *identity) localizer(r *http.Request) *i18n.Localizer {
	if l, ok := locale.FromContext(r.Context()); ok {
		return l
	}
	return id.cat.Localizer(id.cat.Default())
}

func vulnSeverity(s string) vuln.Severity { return vuln.Severity(s) }
