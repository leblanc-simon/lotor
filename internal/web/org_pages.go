package web

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
)

func orgBase(acc tenant.Access) string { return "/o/" + acc.Slug }

func orgNav(acc tenant.Access, current string) []render.NavItem {
	base := orgBase(acc)
	nav := []render.NavItem{
		{LabelKey: "nav.org_overview", Href: base, Current: current == "overview"},
		{LabelKey: "nav.search", Href: base + "/search", Current: current == "search"},
		{LabelKey: "nav.projects", Href: base + "/projects", Current: current == "projects"},
		{LabelKey: "nav.agents", Href: base + "/agents", Current: current == "agents"},
		{LabelKey: "nav.teams", Href: base + "/teams", Current: current == "teams"},
		{LabelKey: "nav.members", Href: base + "/members", Current: current == "members"},
		{LabelKey: "nav.violations", Href: base + "/violations", Current: current == "violations"},
	}
	if acc.Can(tenant.PermTriageOrg, uuid.Nil) {
		nav = append(nav, render.NavItem{LabelKey: "nav.triage", Href: base + "/triage", Current: current == "triage"})
	}
	if acc.Can(tenant.PermPolicyManage, uuid.Nil) {
		nav = append(nav, render.NavItem{LabelKey: "nav.policies", Href: base + "/policies", Current: current == "policies"})
	}
	if acc.Can(tenant.PermChannelManage, uuid.Nil) {
		nav = append(nav, render.NavItem{LabelKey: "nav.channels", Href: base + "/channels", Current: current == "channels"})
	}
	if acc.Can(tenant.PermOrgManage, uuid.Nil) {
		nav = append(nav,
			render.NavItem{LabelKey: "nav.org_settings", Href: base + "/settings", Current: current == "settings"},
			render.NavItem{LabelKey: "nav.audit", Href: base + "/audit", Current: current == "audit"})
	}
	return nav
}

func access(r *http.Request) tenant.Access {
	acc, _ := tenant.AccessFrom(r.Context())
	return acc
}

type memberRow struct {
	org.Member
	RoleKey string
	Self    bool
}

type invitationRow struct {
	org.Invitation
	RoleKey string
	Created *stamp
	Expires *stamp
	Expired bool
}

type membersView struct {
	render.Page
	Base        string
	CanAdmin    bool
	Members     []memberRow
	Invitations []invitationRow
	Roles       []option
	NextCursor  string
	FlashKey    string
	Error       formError
	Email       string
	// InviteLink est le lien d'une invitation qui vient d'être créée sans envoi de
	// courriels : montré une seule fois, à transmettre à la main (T28).
	InviteLink *inviteLink
}

type inviteLink struct {
	URL     string
	Email   string
	Expires *stamp
}

func roleOptions(selected tenant.Role) []option {
	var out []option
	for _, role := range tenant.Roles() {
		out = append(out, option{Value: string(role), LabelKey: "role." + string(role), Selected: role == selected})
	}
	return out
}

func (id *identity) membersPage(w http.ResponseWriter, r *http.Request, status int, fe formError, email string) {
	id.membersPageWith(w, r, status, fe, email, nil)
}

func (id *identity) membersPageWith(w http.ResponseWriter, r *http.Request, status int, fe formError, email string, link *inviteLink) {
	acc := access(r)
	page, err := id.Orgs.Members(r.Context(), acc.Org, r.URL.Query().Get("cursor"), org.DefaultPage)
	if err != nil {
		if e, ok := validationOf(err); ok {
			fe, status = e, http.StatusBadRequest
		} else {
			id.serverError(w, r, err)
			return
		}
	}
	v := viewerFrom(r)
	view := &membersView{
		Page: render.Page{TitleKey: "members.title", Nav: orgNav(acc, "members")},
		Base: orgBase(acc), CanAdmin: acc.Can(tenant.PermMembersManage, uuid.Nil), Roles: roleOptions(tenant.RoleMember),
		NextCursor: page.NextCursor, FlashKey: flashKey(r), Error: fe, Email: email, InviteLink: link,
	}
	for _, m := range page.Items {
		view.Members = append(view.Members, memberRow{Member: m, RoleKey: "role." + string(m.Role), Self: m.UserID == v.user.ID})
	}
	if view.CanAdmin {
		invitations, err := id.Orgs.Invitations(r.Context(), acc.Org)
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		now := id.Agents.Now()
		for _, i := range invitations {
			view.Invitations = append(view.Invitations, invitationRow{Invitation: i, RoleKey: "role." + string(i.Role),
				Created: dateOf(&i.CreatedAt), Expires: dateOf(&i.ExpiresAt), Expired: i.Expired(now)})
		}
	}
	id.rd.Render(w, r, status, "org/members", view)
}

func (id *identity) members(w http.ResponseWriter, r *http.Request) {
	id.membersPage(w, r, http.StatusOK, formError{}, "")
}

// memberResult traite le résultat d'une modification des membres.
func (id *identity) memberResult(w http.ResponseWriter, r *http.Request, err error, done, email string) {
	switch {
	case err == nil:
		redirectDone(w, r, orgBase(access(r))+"/members", done)
	case errors.Is(err, org.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	default:
		if fe, ok := validationOf(err); ok {
			id.membersPage(w, r, http.StatusUnprocessableEntity, fe, email)
			return
		}
		id.serverError(w, r, err)
	}
}

// inviteMember invite une adresse à rejoindre l'organisation (SEC-09) : la réponse est la
// même que l'adresse ait un compte ou non. Avec l'envoi de courriels, le lien part dans la
// langue de l'invitant ; sans, il est montré une seule fois, à transmettre (T28).
func (id *identity) inviteMember(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	email := r.PostForm.Get("email")
	role := tenant.Role(r.PostForm.Get("role"))
	var mail org.InviteMail
	if id.Signup.Mail() {
		mail = org.InviteMail{Secrets: id.Secrets, Language: requestLanguage(w),
			RoleLabel: id.localizer(r).T("role."+string(role), nil)}
	}
	link, err := id.Orgs.InviteWithLink(r.Context(), id.actor(r), access(r).Org, email, role, mail)
	switch {
	case err != nil:
		id.memberResult(w, r, err, "", email)
	case link.Mailed:
		redirectDone(w, r, orgBase(access(r))+"/members", "invitation_mailed")
	case link.Token == "":
		redirectDone(w, r, orgBase(access(r))+"/members", "member_invited")
	default:
		noStore(w)
		normalized, _ := account.NormalizeEmail(email)
		id.membersPageWith(w, r, http.StatusOK, formError{}, "", &inviteLink{
			URL: id.invitationURL(r, org.InvitationPath(link.Token)), Email: normalized, Expires: dateOf(&link.ExpiresAt)})
	}
}

// confirmRevokeInvitation : révocation d'une invitation.
func (id *identity) confirmRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	iid, err := uuid.Parse(chi.URLParam(r, "invitationID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	inv, err := id.Orgs.Invitation(r.Context(), acc.Org, iid)
	if errors.Is(err, org.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	id.confirm(w, r, confirmation{nav: orgNav(acc, "members"), heading: "confirm.invitation_heading",
		text: "confirm.invitation_text", submit: "confirm.invitation_submit",
		args: map[string]any{"Email": inv.Email, "Org": acc.Name}, cancel: orgBase(acc) + "/members"})
}

func (id *identity) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	iid, err := uuid.Parse(chi.URLParam(r, "invitationID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	err = id.Orgs.RevokeInvitation(r.Context(), id.actor(r), access(r).Org, iid)
	id.memberResult(w, r, err, "invitation_revoked", "")
}

func (id *identity) setMemberRole(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathInt(chi.URLParam(r, "userID"))
	if !ok {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	if !id.parseForm(w, r) {
		return
	}
	err := id.Orgs.SetMemberRole(r.Context(), id.actor(r), access(r).Org, userID, tenant.Role(r.PostForm.Get("role")))
	id.memberResult(w, r, err, "member_updated", "")
}

func (id *identity) removeMember(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathInt(chi.URLParam(r, "userID"))
	if !ok {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	err := id.Orgs.RemoveMember(r.Context(), id.actor(r), access(r).Org, userID)
	id.memberResult(w, r, err, "member_removed", "")
}

type orgSettingsView struct {
	render.Page
	Base      string
	Name      string
	Languages []option
	FlashKey  string
	Error     formError
}

func languageOptions(selected string) []option {
	var out []option
	for _, l := range []string{"fr", "en"} {
		out = append(out, option{Value: l, LabelKey: "language." + l, Lang: l, Selected: l == selected})
	}
	return out
}

func (id *identity) orgSettingsPage(w http.ResponseWriter, r *http.Request, status int, name, lang string, fe formError) {
	acc := access(r)
	id.rd.Render(w, r, status, "org/settings", &orgSettingsView{
		Page: render.Page{TitleKey: "org_settings.title", Nav: orgNav(acc, "settings")},
		Base: orgBase(acc), Name: name, Languages: languageOptions(lang), FlashKey: flashKey(r), Error: fe,
	})
}

func (id *identity) orgSettings(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	id.orgSettingsPage(w, r, http.StatusOK, acc.Name, acc.Language, formError{})
}

func (id *identity) saveOrgSettings(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	acc := access(r)
	name, lang := r.PostForm.Get("name"), r.PostForm.Get("language")
	if err := id.Orgs.Update(r.Context(), id.actor(r), acc.Org, name, lang); err != nil {
		if fe, ok := validationOf(err); ok {
			id.orgSettingsPage(w, r, http.StatusUnprocessableEntity, name, lang, fe)
			return
		}
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, orgBase(acc)+"/settings", "org_saved")
}

type auditRow struct {
	audit.Entry
	ActionKey string
	Args      map[string]any
}

type auditView struct {
	render.Page
	Rows       []auditRow
	NextCursor string
	Error      formError
}

func auditRows(entries []audit.Entry) []auditRow {
	out := make([]auditRow, 0, len(entries))
	for _, e := range entries {
		actor := e.ActorEmail
		args := map[string]any{"Actor": actor, "Target": e.TargetLabel}
		for k, v := range e.Details {
			args["D_"+k] = v
		}
		out = append(out, auditRow{Entry: e, ActionKey: e.Action.Key(), Args: args})
	}
	return out
}

func (id *identity) orgAudit(w http.ResponseWriter, r *http.Request) {
	acc := access(r)
	view := &auditView{Page: render.Page{TitleKey: "audit.title", Nav: orgNav(acc, "audit")}}
	status := http.StatusOK
	err := id.Pool.InOrg(r.Context(), acc.Org, func(tx *db.OrgTx) error {
		page, err := audit.ListOrg(r.Context(), tx, r.URL.Query().Get("cursor"), audit.DefaultPage)
		if err != nil {
			return err
		}
		view.Rows, view.NextCursor = auditRows(page.Items), page.NextCursor
		return nil
	}, db.ReadOnly())
	if err != nil {
		fe, ok := validationOf(err)
		if !ok {
			id.serverError(w, r, err)
			return
		}
		view.Error, status = fe, http.StatusBadRequest
	}
	id.rd.Render(w, r, status, "audit/list", view)
}
