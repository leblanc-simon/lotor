package web

import (
	"net/http"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
)

func accountNav(current string) []render.NavItem {
	return []render.NavItem{
		{LabelKey: "nav.profile", Href: "/account", Current: current == "profile"},
		{LabelKey: "nav.password", Href: pathPassword, Current: current == "password"},
		{LabelKey: "nav.security", Href: pathSecurity, Current: current == "security"},
		{LabelKey: "nav.tokens", Href: pathTokens, Current: current == "tokens"},
		{LabelKey: "nav.invitations", Href: pathInvitations, Current: current == "invitations"},
	}
}

// home envoie un compte vers son organisation par défaut, sinon la première ; sans
// organisation, il affiche une page d'attente.
func (id *identity) home(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r)
	orgs := v.state.Orgs
	for _, o := range orgs {
		if o.Org == v.state.Settings.DefaultOrg {
			http.Redirect(w, r, "/o/"+o.Slug, http.StatusSeeOther)
			return
		}
	}
	if len(orgs) > 0 {
		http.Redirect(w, r, "/o/"+orgs[0].Slug, http.StatusSeeOther)
		return
	}
	id.rd.Render(w, r, http.StatusOK, "home/index", &homeView{Page: render.Page{TitleKey: "home.title"}, NoOrg: true, Admin: v.admin()})
}

type option struct {
	Value    string
	LabelKey string // clé de traduction, ou vide si Label est déjà lisible
	Label    string
	// Lang est la langue du libellé quand elle diffère de celle de la page : nom d'une
	// langue écrit dans cette langue (« English »), restitué avec sa prononciation.
	Lang     string
	Selected bool
}

type profileView struct {
	render.Page
	Email     string
	Languages []option
	Themes    []option
	Orgs      []option
	FlashKey  string
	Error     formError
}

func (id *identity) profileView(r *http.Request, s account.Settings) *profileView {
	v := viewerFrom(r)
	view := &profileView{Page: render.Page{TitleKey: "profile.title", Nav: accountNav("profile")}, Email: v.user.Email}
	view.Languages = append(view.Languages, option{Value: "", LabelKey: "profile.language_auto", Selected: s.Language == ""})
	for _, l := range account.Languages {
		view.Languages = append(view.Languages, option{Value: l, LabelKey: "language." + l, Lang: l, Selected: s.Language == l})
	}
	view.Themes = append(view.Themes, option{Value: "", LabelKey: "theme.system", Selected: s.Theme == ""})
	for _, t := range account.Themes {
		view.Themes = append(view.Themes, option{Value: t, LabelKey: "theme." + t, Selected: s.Theme == t})
	}
	view.Orgs = append(view.Orgs, option{Value: "", LabelKey: "profile.default_org_first", Selected: s.DefaultOrg.IsZero()})
	for _, o := range v.state.Orgs {
		view.Orgs = append(view.Orgs, option{Value: o.Org.String(), Label: o.Name, Selected: o.Org == s.DefaultOrg})
	}
	return view
}

func (id *identity) profile(w http.ResponseWriter, r *http.Request) {
	view := id.profileView(r, viewerFrom(r).state.Settings)
	view.FlashKey = flashKey(r)
	id.rd.Render(w, r, http.StatusOK, "account/profile", view)
}

func (id *identity) saveProfile(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	v := viewerFrom(r)
	s := account.Settings{Language: r.PostForm.Get("language"), Theme: r.PostForm.Get("theme")}
	if raw := r.PostForm.Get("default_org"); raw != "" {
		org, err := tenant.ParseOrgID(raw)
		if err != nil {
			view := id.profileView(r, s)
			view.Error = formError{Key: account.KeyDefaultOrgInvalid, Field: "default_org"}
			id.rd.Render(w, r, http.StatusUnprocessableEntity, "account/profile", view)
			return
		}
		s.DefaultOrg = org
	}
	if err := id.Accounts.SaveSettings(r.Context(), id.actor(r), v.user.ID, s); err != nil {
		if fe, ok := validationOf(err); ok {
			view := id.profileView(r, s)
			view.Error = fe
			id.rd.Render(w, r, http.StatusUnprocessableEntity, "account/profile", view)
			return
		}
		id.serverError(w, r, err)
		return
	}
	// Le cookie de la bascule l'emporte sur la préférence : il suit le nouveau choix.
	theme := &http.Cookie{Name: render.ThemeCookie, Value: s.Theme, Path: "/", MaxAge: 365 * 24 * 3600,
		SameSite: http.SameSiteLaxMode, Secure: id.mgr.CookieSecure(r)}
	if s.Theme == "" {
		theme.MaxAge = -1
	}
	http.SetCookie(w, theme)
	redirectDone(w, r, "/account", "settings_saved")
}

type passwordView struct {
	render.Page
	Forced    bool // mot de passe temporaire à changer
	MinLength int
	FlashKey  string
	Error     formError
}

func (id *identity) passwordView(r *http.Request) *passwordView {
	v := viewerFrom(r)
	view := &passwordView{Page: render.Page{TitleKey: "password.title"}, Forced: v.user.MustChangePwd, MinLength: account.MinPasswordLength}
	if !view.Forced {
		view.Nav = accountNav("password")
	}
	return view
}

func (id *identity) password(w http.ResponseWriter, r *http.Request) {
	view := id.passwordView(r)
	view.FlashKey = flashKey(r)
	id.rd.Render(w, r, http.StatusOK, "account/password", view)
}

func (id *identity) changePassword(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	v := viewerFrom(r)
	// Un mot de passe temporaire suit une réinitialisation, qui a déjà révoqué les jetons.
	revoke := v.user.MustChangePwd || r.PostForm.Get("revoke_tokens") != ""
	err := id.Accounts.ChangePassword(r.Context(), id.actor(r), v.user.ID,
		r.PostForm.Get("current"), r.PostForm.Get("password"), r.PostForm.Get("confirm"), v.session.Token, revoke)
	if err != nil {
		if fe, ok := validationOf(err); ok {
			view := id.passwordView(r)
			view.Error = fe
			id.rd.Render(w, r, http.StatusUnprocessableEntity, "account/password", view)
			return
		}
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, pathPassword, "password_changed")
}
