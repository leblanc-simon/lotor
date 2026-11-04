package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/vuln"
)

func adminNav(current string) []render.NavItem {
	return []render.NavItem{
		{LabelKey: "nav.admin_users", Href: "/admin/users", Current: current == "users"},
		{LabelKey: "nav.admin_orgs", Href: "/admin/orgs", Current: current == "orgs"},
		{LabelKey: "nav.admin_signup", Href: "/admin/signup", Current: current == "signup"},
		{LabelKey: "nav.admin_vulndb", Href: "/admin/vulndb", Current: current == "vulndb"},
		{LabelKey: "nav.admin_jobs", Href: "/admin/jobs", Current: current == "jobs"},
		{LabelKey: "nav.audit", Href: "/admin/audit", Current: current == "audit"},
	}
}

// adminPage est l'en-tête commun de l'administration : les avertissements « un seul
// administrateur d'instance » (§ 10 de l'architecture) et « base de vulnérabilités trop
// ancienne » (§ 12) y figurent sur chaque page.
type adminPage struct {
	render.Page
	SingleAdmin bool
	VulnDBAlert *vulnDBAlert
	FlashKey    string
	Error       formError
}

func (id *identity) adminPage(r *http.Request, title, nav string) (adminPage, error) {
	n, err := id.Accounts.ActiveAdmins(r.Context())
	if err != nil {
		return adminPage{}, err
	}
	st, err := vuln.ReadState(r.Context(), id.Pool.DB())
	if err != nil {
		return adminPage{}, err
	}
	return adminPage{Page: render.Page{TitleKey: title, Nav: adminNav(nav)}, SingleAdmin: n < 2, VulnDBAlert: id.vulnDBAlert(st),
		FlashKey: flashKey(r)}, nil
}

type usersView struct {
	adminPage
	Users      []account.User
	NextCursor string
	Email      string
}

func (id *identity) usersPage(w http.ResponseWriter, r *http.Request, status int, fe formError, email string) {
	base, err := id.adminPage(r, "admin_users.title", "users")
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base.Error = fe
	page, err := id.Accounts.List(r.Context(), r.URL.Query().Get("cursor"), account.DefaultPage)
	if err != nil {
		if e, ok := validationOf(err); ok {
			base.Error, status = e, http.StatusBadRequest
		} else {
			id.serverError(w, r, err)
			return
		}
	}
	id.rd.Render(w, r, status, "admin/users", &usersView{adminPage: base, Users: page.Items, NextCursor: page.NextCursor, Email: email})
}

func (id *identity) adminUsers(w http.ResponseWriter, r *http.Request) {
	id.usersPage(w, r, http.StatusOK, formError{}, "")
}

type tempPasswordView struct {
	adminPage
	User       account.User
	Password   string
	HeadingKey string
}

// createUser crée un compte et affiche une seule fois son mot de passe temporaire (jamais
// dans une URL ni dans un journal).
func (id *identity) createUser(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	email := r.PostForm.Get("email")
	u, password, err := id.Accounts.Create(r.Context(), id.actor(r), email, r.PostForm.Get("admin") == "on")
	if err != nil {
		if fe, ok := validationOf(err); ok {
			id.usersPage(w, r, http.StatusUnprocessableEntity, fe, email)
			return
		}
		id.serverError(w, r, err)
		return
	}
	id.showTempPassword(w, r, u, password, "admin_password.created_heading")
}

// showTempPassword montre une fois le mot de passe temporaire d'un compte créé ou
// réinitialisé ; headingKey nomme ce qui vient d'arriver.
func (id *identity) showTempPassword(w http.ResponseWriter, r *http.Request, u account.User, password, headingKey string) {
	base, err := id.adminPage(r, "admin_password.title", "users")
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	id.rd.Render(w, r, http.StatusOK, "admin/temp_password", &tempPasswordView{adminPage: base, User: u, Password: password, HeadingKey: headingKey})
}

type userView struct {
	adminPage
	User account.User
	Self bool
	Orgs []crossorg.OrgRef
}

func (id *identity) userFromPath(w http.ResponseWriter, r *http.Request) (account.User, bool) {
	uid, ok := pathInt(chi.URLParam(r, "userID"))
	if !ok {
		id.rd.Error(w, r, http.StatusNotFound)
		return account.User{}, false
	}
	u, err := id.Accounts.Get(r.Context(), uid)
	if errors.Is(err, account.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return account.User{}, false
	}
	if err != nil {
		id.serverError(w, r, err)
		return account.User{}, false
	}
	return u, true
}

func (id *identity) userPage(w http.ResponseWriter, r *http.Request, u account.User, status int, fe formError) {
	base, err := id.adminPage(r, "admin_user.title", "users")
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base.Error = fe
	base.TitleArgs = map[string]any{"Email": u.Email}
	orgs, err := crossorg.UserOrgs(r.Context(), id.Pool.DB(), u.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	id.rd.Render(w, r, status, "admin/user", &userView{adminPage: base, User: u, Self: u.ID == viewerFrom(r).user.ID, Orgs: orgs})
}

func (id *identity) adminUser(w http.ResponseWriter, r *http.Request) {
	if u, ok := id.userFromPath(w, r); ok {
		id.userPage(w, r, u, http.StatusOK, formError{})
	}
}

// userAction applique une action d'administration à un compte (désactivation,
// réinitialisations, rôle). Chacune est journalisée par account.
func (id *identity) userAction(w http.ResponseWriter, r *http.Request) {
	u, ok := id.userFromPath(w, r)
	if !ok {
		return
	}
	ctx, actor := r.Context(), id.actor(r)
	var err error
	switch chi.URLParam(r, "action") {
	case "deactivate":
		err = id.Accounts.SetActive(ctx, actor, u.ID, false)
	case "activate":
		err = id.Accounts.SetActive(ctx, actor, u.ID, true)
	case "promote":
		err = id.Accounts.SetAdmin(ctx, actor, u.ID, true)
	case "demote":
		err = id.Accounts.SetAdmin(ctx, actor, u.ID, false)
	case "reset-totp", "reset-password":
		reset, heading := id.Accounts.ResetPassword, "admin_password.reset_heading"
		if chi.URLParam(r, "action") == "reset-totp" {
			reset, heading = id.Accounts.ResetTOTP, "admin_password.totp_reset_heading"
		}
		password, err := reset(ctx, actor, u.ID)
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		id.showTempPassword(w, r, u, password, heading)
		return
	default:
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	if err != nil {
		if fe, ok := validationOf(err); ok {
			id.userPage(w, r, u, http.StatusUnprocessableEntity, fe)
			return
		}
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, "/admin/users/"+strconv.FormatInt(u.ID, 10), "account_updated")
}

type orgsView struct {
	adminPage
	Orgs       []crossorg.OrgSummary
	NextCursor string
	Languages  []option
	Form       orgForm
}

type orgForm struct {
	Slug, Name, Language, AdminEmail string
}

func (id *identity) orgsPage(w http.ResponseWriter, r *http.Request, status int, fe formError, form orgForm) {
	base, err := id.adminPage(r, "admin_orgs.title", "orgs")
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base.Error = fe
	var after string
	if c := r.URL.Query().Get("cursor"); c != "" {
		if err := pagination.Decode(c, &after); err != nil {
			base.Error, status = formError{Key: "error.invalid_cursor.title", Field: "cursor"}, http.StatusBadRequest
		}
	}
	rows, err := crossorg.ListOrganizations(r.Context(), id.Pool.DB(), after, org.DefaultPage+1)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	page, err := pagination.Build(rows, org.DefaultPage, func(o crossorg.OrgSummary) any { return o.Slug })
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	if form.Language == "" {
		form.Language = "fr"
	}
	id.rd.Render(w, r, status, "admin/orgs", &orgsView{
		adminPage: base, Orgs: page.Items, NextCursor: page.NextCursor, Languages: languageOptions(form.Language), Form: form,
	})
}

func (id *identity) adminOrgs(w http.ResponseWriter, r *http.Request) {
	id.orgsPage(w, r, http.StatusOK, formError{}, orgForm{})
}

func (id *identity) createOrg(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	form := orgForm{Slug: r.PostForm.Get("slug"), Name: r.PostForm.Get("name"), Language: r.PostForm.Get("language"), AdminEmail: r.PostForm.Get("admin_email")}
	admin, err := id.Accounts.GetByEmail(r.Context(), form.AdminEmail)
	if errors.Is(err, account.ErrNotFound) {
		id.orgsPage(w, r, http.StatusUnprocessableEntity, formError{Key: org.KeyUnknownAccount, Field: "admin_email"}, form)
		return
	}
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	o, err := id.Orgs.Create(r.Context(), id.actor(r), form.Slug, form.Name, form.Language, admin.ID)
	if err != nil {
		if fe, ok := validationOf(err); ok {
			id.orgsPage(w, r, http.StatusUnprocessableEntity, fe, form)
			return
		}
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, "/admin/orgs/"+o.Slug, "org_created")
}

type adminOrgView struct {
	adminPage
	Org       org.Organization
	Admins    []org.Member
	Languages []option
	Name      string
}

func (id *identity) orgFromPath(w http.ResponseWriter, r *http.Request) (org.Organization, bool) {
	oid, err := crossorg.OrgIDBySlug(r.Context(), id.Pool.DB(), chi.URLParam(r, "slug"))
	if errors.Is(err, crossorg.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return org.Organization{}, false
	}
	if err != nil {
		id.serverError(w, r, err)
		return org.Organization{}, false
	}
	o, err := id.Orgs.Get(r.Context(), oid)
	if err != nil {
		id.serverError(w, r, err)
		return org.Organization{}, false
	}
	return o, true
}

func (id *identity) adminOrgPage(w http.ResponseWriter, r *http.Request, o org.Organization, status int, fe formError, name, lang string) {
	base, err := id.adminPage(r, "admin_org.title", "orgs")
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base.Error = fe
	base.TitleArgs = map[string]any{"Name": o.Name}
	admins, err := id.Orgs.Admins(r.Context(), o.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	id.rd.Render(w, r, status, "admin/org", &adminOrgView{adminPage: base, Org: o, Admins: admins, Languages: languageOptions(lang), Name: name})
}

func (id *identity) adminOrg(w http.ResponseWriter, r *http.Request) {
	if o, ok := id.orgFromPath(w, r); ok {
		id.adminOrgPage(w, r, o, http.StatusOK, formError{}, o.Name, o.DefaultLanguage)
	}
}

func (id *identity) adminOrgResult(w http.ResponseWriter, r *http.Request, o org.Organization, err error, done, name, lang string) {
	if err != nil {
		if fe, ok := validationOf(err); ok {
			id.adminOrgPage(w, r, o, http.StatusUnprocessableEntity, fe, name, lang)
			return
		}
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, "/admin/orgs/"+o.Slug, done)
}

func (id *identity) adminOrgAction(w http.ResponseWriter, r *http.Request) {
	o, ok := id.orgFromPath(w, r)
	if !ok || !id.parseForm(w, r) {
		return
	}
	ctx, actor := r.Context(), id.actor(r)
	switch chi.URLParam(r, "action") {
	case "update":
		name, lang := r.PostForm.Get("name"), r.PostForm.Get("language")
		id.adminOrgResult(w, r, o, id.Orgs.Update(ctx, actor, o.ID, name, lang), "org_saved", name, lang)
	case "archive":
		id.adminOrgResult(w, r, o, id.Orgs.SetArchived(ctx, actor, o.ID, true), "org_archived", o.Name, o.DefaultLanguage)
	case "unarchive":
		id.adminOrgResult(w, r, o, id.Orgs.SetArchived(ctx, actor, o.ID, false), "org_unarchived", o.Name, o.DefaultLanguage)
	case "admins":
		err := id.Orgs.AddMember(ctx, actor, o.ID, r.PostForm.Get("email"), tenant.RoleAdmin)
		if fe, ok := validationOf(err); ok && fe.Key == org.KeyMemberExists {
			// Déjà membre : il devient administrateur.
			var u account.User
			if u, err = id.Accounts.GetByEmail(ctx, r.PostForm.Get("email")); err == nil {
				err = id.Orgs.SetMemberRole(ctx, actor, o.ID, u.ID, tenant.RoleAdmin)
			}
		}
		id.adminOrgResult(w, r, o, err, "member_added", o.Name, o.DefaultLanguage)
	default:
		id.rd.Error(w, r, http.StatusNotFound)
	}
}

func (id *identity) adminAudit(w http.ResponseWriter, r *http.Request) {
	base, err := id.adminPage(r, "audit.instance_title", "audit")
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view := &auditView{Page: base.Page}
	status := http.StatusOK
	page, err := audit.ListInstance(r.Context(), id.Pool.DB(), r.URL.Query().Get("cursor"), audit.DefaultPage)
	if err != nil {
		fe, ok := validationOf(err)
		if !ok {
			id.serverError(w, r, err)
			return
		}
		view.Error, status = fe, http.StatusBadRequest
	}
	view.Rows, view.NextCursor = auditRows(page.Items), page.NextCursor
	id.rd.Render(w, r, status, "audit/list", view)
}
