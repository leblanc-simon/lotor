package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"leblanc.io/open-go-base/authx"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/signup"
)

// Chemins de l'inscription (T28, ADR 0056).
const (
	pathSignup       = signup.SignupPath
	pathSignupVerify = "/signup/verify/{token}"
	pathInvitation   = "/invitation/{token}"
)

// requestLanguage est la langue de la réponse en cours, résolue par le middleware de
// langue (ou par la garde d'organisation, qui la recalcule).
func requestLanguage(w http.ResponseWriter) string {
	return w.Header().Get("Content-Language")
}

// noStore interdit la mise en cache d'une page dont l'URL porte un jeton.
func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// openSetupSession ouvre, pour le compte u qui vient d'être créé, une session de
// configuration : elle ne mène qu'à l'enrôlement du TOTP, obligatoire, après lequel mfax
// l'élève en session authentifiée et montre les codes de secours.
func (id *identity) openSetupSession(w http.ResponseWriter, r *http.Request, u account.User) {
	if _, err := id.mgr.OpenSession(w, r, &authx.User{ID: u.ID, Email: u.Email, IsActive: true}, authx.PurposeSetup); err != nil {
		id.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, pathTOTPSetup, http.StatusSeeOther)
}

// signupView est la page d'inscription : Direct, l'inscription en une étape (mode
// invitation sans envoi de courriels), y demande aussi l'organisation et le mot de passe.
type signupView struct {
	render.Page
	Invitation bool
	Direct     bool
	Domains    string
	MinLength  int
	Error      formError
	Email      string
	OrgName    string
}

// signupOpen refuse l'inscription d'une instance privée (404, comme une page absente) et
// renvoie un visiteur déjà connecté, ou en cours d'enrôlement, vers l'accueil.
func (id *identity) signupOpen(w http.ResponseWriter, r *http.Request) bool {
	if !id.Signup.Open() {
		id.rd.Error(w, r, http.StatusNotFound)
		return false
	}
	if viewerFrom(r) != nil {
		http.Redirect(w, r, pathHome, http.StatusSeeOther)
		return false
	}
	return true
}

func (id *identity) signupPage(w http.ResponseWriter, r *http.Request, status int, fe formError, email, orgName string) {
	s := id.Signup
	view := &signupView{Page: render.Page{TitleKey: "signup.title"}, Invitation: s.Mode() == signup.Invitation,
		Direct: s.Mode() == signup.Invitation && !s.Mail(), MinLength: account.MinPasswordLength, Error: fe,
		Email: email, OrgName: orgName}
	if s.Mode() == signup.Public {
		view.Domains = strings.Join(s.Domains(), ", ")
	}
	id.rd.Render(w, r, status, "signup/start", view)
}

func (id *identity) signupForm(w http.ResponseWriter, r *http.Request) {
	if !id.signupOpen(w, r) {
		return
	}
	id.signupPage(w, r, http.StatusOK, formError{}, "", "")
}

// signupSubmit : avec envoi de courriels, première étape (lien de vérification, réponse
// neutre) ; sans, inscription sur code en une étape. Le code n'est jamais renvoyé dans la
// page : il est ressaisi après une erreur.
func (id *identity) signupSubmit(w http.ResponseWriter, r *http.Request) {
	if !id.signupOpen(w, r) || !id.parseForm(w, r) {
		return
	}
	f := r.PostForm
	email, orgName := f.Get("email"), f.Get("org_name")
	if id.Signup.Mail() {
		err := id.Signup.Start(r.Context(), id.actor(r), signup.StartRequest{Email: email, Code: f.Get("code"),
			Language: requestLanguage(w)})
		if id.signupFailed(w, r, err, email, orgName) {
			return
		}
		id.rd.Render(w, r, http.StatusOK, "signup/sent", &plainView{Page: render.Page{TitleKey: "signup.sent_title"}})
		return
	}
	acc, err := id.Signup.Direct(r.Context(), id.actor(r), signup.DirectRequest{Code: f.Get("code"), Email: email,
		AccountRequest: accountRequest(w, r)})
	if id.signupFailed(w, r, err, email, orgName) {
		return
	}
	id.openSetupSession(w, r, acc.User)
}

func accountRequest(w http.ResponseWriter, r *http.Request) signup.AccountRequest {
	f := r.PostForm
	return signup.AccountRequest{OrgName: f.Get("org_name"), Password: f.Get("password"), Confirm: f.Get("confirm"),
		Language: requestLanguage(w)}
}

// signupFailed rend la page d'inscription avec l'erreur de saisie de err ; il renvoie
// false si err est nil.
func (id *identity) signupFailed(w http.ResponseWriter, r *http.Request, err error, email, orgName string) bool {
	if err == nil {
		return false
	}
	if fe, ok := validationOf(err); ok {
		id.signupPage(w, r, http.StatusUnprocessableEntity, fe, email, orgName)
		return true
	}
	id.serverError(w, r, err)
	return true
}

// plainView est une page sans donnée propre.
type plainView struct{ render.Page }

// linkInvalid rend la page d'un lien inconnu, expiré ou déjà utilisé.
func (id *identity) linkInvalid(w http.ResponseWriter, r *http.Request) {
	id.rd.Render(w, r, http.StatusNotFound, "signup/link_invalid", &plainView{Page: render.Page{TitleKey: "signup.link_invalid_title"}})
}

// completeView termine l'inscription d'une adresse vérifiée.
type completeView struct {
	render.Page
	Action    string
	Email     string
	OrgName   string
	MinLength int
	Error     formError
}

func (id *identity) signupVerifyPage(w http.ResponseWriter, r *http.Request, status int, email string, fe formError) {
	id.rd.Render(w, r, status, "signup/complete", &completeView{Page: render.Page{TitleKey: "signup.complete_title"},
		Action: signup.VerifyPath(chi.URLParam(r, "token")), Email: email, OrgName: r.PostForm.Get("org_name"),
		MinLength: account.MinPasswordLength, Error: fe})
}

// pendingVerification retrouve la vérification du lien de la requête ; un lien refusé
// rend sa page.
func (id *identity) pendingVerification(w http.ResponseWriter, r *http.Request) (signup.Pending, bool) {
	noStore(w)
	if !id.signupOpen(w, r) {
		return signup.Pending{}, false
	}
	p, err := id.Signup.Verification(r.Context(), chi.URLParam(r, "token"))
	if err != nil {
		if _, ok := validationOf(err); ok {
			id.linkInvalid(w, r)
		} else {
			id.serverError(w, r, err)
		}
		return signup.Pending{}, false
	}
	return p, true
}

func (id *identity) signupVerifyForm(w http.ResponseWriter, r *http.Request) {
	p, ok := id.pendingVerification(w, r)
	if !ok {
		return
	}
	id.signupVerifyPage(w, r, http.StatusOK, p.Email, formError{})
}

func (id *identity) signupVerifySubmit(w http.ResponseWriter, r *http.Request) {
	p, ok := id.pendingVerification(w, r)
	if !ok || !id.parseForm(w, r) {
		return
	}
	acc, err := id.Signup.Complete(r.Context(), id.actor(r), chi.URLParam(r, "token"), accountRequest(w, r))
	if err != nil {
		fe, ok := validationOf(err)
		switch {
		case ok && fe.Key == signup.KeyLinkInvalid:
			id.linkInvalid(w, r)
		case ok:
			id.signupVerifyPage(w, r, http.StatusUnprocessableEntity, p.Email, fe)
		default:
			id.serverError(w, r, err)
		}
		return
	}
	id.openSetupSession(w, r, acc.User)
}

// linkInvitationView est la page du lien d'une invitation d'organisation : création du
// compte de l'adresse invitée, ou acceptation par le compte connecté.
type linkInvitationView struct {
	render.Page
	Invitation signup.LinkInvitation
	RoleKey    string
	Expires    *stamp
	Action     string
	LoginURL   string
	// SignedIn : un compte est connecté ; OtherAccount : ce n'est pas celui de l'adresse
	// invitée.
	SignedIn     bool
	OtherAccount bool
	MinLength    int
	Error        formError
}

// linkInvitation retrouve l'invitation du lien de la requête ; un lien refusé rend sa
// page. Une session de configuration (enrôlement du TOTP en cours) y est renvoyée.
func (id *identity) linkInvitation(w http.ResponseWriter, r *http.Request) (signup.LinkInvitation, bool) {
	noStore(w)
	if v := viewerFrom(r); v != nil && !v.authenticated() {
		http.Redirect(w, r, pathTOTPSetup, http.StatusSeeOther)
		return signup.LinkInvitation{}, false
	}
	inv, err := id.Signup.InvitationByLink(r.Context(), chi.URLParam(r, "token"))
	if err != nil {
		if _, ok := validationOf(err); ok {
			id.linkInvalid(w, r)
		} else {
			id.serverError(w, r, err)
		}
		return signup.LinkInvitation{}, false
	}
	return inv, true
}

func (id *identity) linkInvitationPage(w http.ResponseWriter, r *http.Request, status int, inv signup.LinkInvitation, fe formError) {
	action := "/invitation/" + chi.URLParam(r, "token")
	view := &linkInvitationView{Page: render.Page{TitleKey: "link_invitation.title"}, Invitation: inv,
		RoleKey: "role." + string(inv.Role), Expires: dateOf(&inv.ExpiresAt), Action: action,
		LoginURL: pathLogin + "?next=" + url.QueryEscape(action), MinLength: account.MinPasswordLength, Error: fe}
	if v := viewerFrom(r); v != nil {
		view.SignedIn, view.OtherAccount = true, !strings.EqualFold(v.user.Email, inv.Email)
	}
	id.rd.Render(w, r, status, "signup/invitation", view)
}

func (id *identity) linkInvitationForm(w http.ResponseWriter, r *http.Request) {
	inv, ok := id.linkInvitation(w, r)
	if !ok {
		return
	}
	id.linkInvitationPage(w, r, http.StatusOK, inv, formError{})
}

// linkInvitationSubmit : le compte connecté accepte l'invitation ; un visiteur crée le
// compte de l'adresse invitée, puis enrôle son TOTP.
func (id *identity) linkInvitationSubmit(w http.ResponseWriter, r *http.Request) {
	inv, ok := id.linkInvitation(w, r)
	if !ok || !id.parseForm(w, r) {
		return
	}
	raw := chi.URLParam(r, "token")
	if v := viewerFrom(r); v != nil {
		_, err := id.Signup.AcceptByLink(r.Context(), id.actor(r), raw, v.user.ID, v.user.Email)
		if id.linkInvitationFailed(w, r, inv, err) {
			return
		}
		redirectDone(w, r, pathInvitations, "invitation_accepted")
		return
	}
	u, _, err := id.Signup.JoinByLink(r.Context(), id.actor(r), raw, r.PostForm.Get("password"), r.PostForm.Get("confirm"))
	if id.linkInvitationFailed(w, r, inv, err) {
		return
	}
	id.openSetupSession(w, r, u)
}

func (id *identity) linkInvitationFailed(w http.ResponseWriter, r *http.Request, inv signup.LinkInvitation, err error) bool {
	if err == nil {
		return false
	}
	fe, ok := validationOf(err)
	switch {
	case ok && fe.Key == signup.KeyLinkInvalid:
		id.linkInvalid(w, r)
	case ok:
		id.linkInvitationPage(w, r, http.StatusUnprocessableEntity, inv, fe)
	default:
		id.serverError(w, r, err)
	}
	return true
}

// signupLinks indique, pour la connexion et la présentation, si l'inscription est ouverte
// et sur code : "public", "invitation" ou "" (instance privée).
func (id *identity) signupLinks() string {
	if id.Signup == nil || !id.Signup.Open() {
		return ""
	}
	return string(id.Signup.Mode())
}

// invitationURL est l'URL absolue du lien d'invitation raw, à transmettre à la main : celle
// de web.public_url, sinon celle de la requête (mandataires de confiance pris en compte).
func (id *identity) invitationURL(r *http.Request, path string) string {
	if id.PublicURL != "" {
		return strings.TrimRight(id.PublicURL, "/") + path
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host + path
}
