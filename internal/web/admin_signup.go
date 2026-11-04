package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/mailer"
	"leblanc.io/lotor/internal/signup"
)

const pathAdminSignup = "/admin/signup"

// adminSignupView est la page « Inscription » de l'administration : mode de l'instance et,
// en mode invitation, codes d'inscription.
type adminSignupView struct {
	adminPage
	ModeKey    string
	Mail       bool
	Domains    string
	Invitation bool
	Codes      []codeRow
	Label      string
	Days       int
	MaxDays    int
	Recipient  string
}

type codeRow struct {
	signup.Code
	StatusKey string
	Active    bool
	Created   *stamp
	Expires   *stamp
	Used      *stamp
}

func (id *identity) adminSignupPage(w http.ResponseWriter, r *http.Request, status int, fe formError, label string, days int, recipient string) {
	base, err := id.adminPage(r, "admin_signup.title", "signup")
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base.Error = fe
	s := id.Signup
	view := &adminSignupView{adminPage: base, ModeKey: "signup.mode." + string(s.Mode()), Mail: s.Mail(),
		Domains: strings.Join(s.Domains(), ", "), Invitation: s.Mode() == signup.Invitation, Label: label, Days: days,
		MaxDays: signup.MaxCodeDays, Recipient: recipient}
	if view.Invitation {
		codes, err := s.Codes(r.Context())
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		now := time.Now()
		for _, c := range codes {
			st := c.Status(now)
			view.Codes = append(view.Codes, codeRow{Code: c, StatusKey: "signup.code_status." + string(st),
				Active: st == signup.CodeActive, Created: dateOf(&c.CreatedAt), Expires: dateOf(&c.ExpiresAt), Used: dateOf(c.UsedAt)})
		}
	}
	id.rd.Render(w, r, status, "admin/signup", view)
}

func (id *identity) adminSignup(w http.ResponseWriter, r *http.Request) {
	id.adminSignupPage(w, r, http.StatusOK, formError{}, "", signup.DefaultCodeDays, "")
}

type signupCodeView struct {
	adminPage
	Code     signup.Code
	Plain    string
	Expires  *stamp
	MailedTo string
	// SendFailed : le code est créé, mais son envoi a échoué ; il reste à le transmettre.
	SendFailed bool
}

// createSignupCode crée un code d'inscription et le montre une seule fois ; avec un
// destinataire, il lui est aussi envoyé sur-le-champ, sans que l'adresse soit conservée.
func (id *identity) createSignupCode(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	f := r.PostForm
	label, recipient := f.Get("label"), strings.TrimSpace(f.Get("recipient"))
	days, err := strconv.Atoi(strings.TrimSpace(f.Get("days")))
	if err != nil {
		days = 0 // refusé par CreateCode
	}
	var to string
	if recipient != "" && id.Mailer != nil {
		if to, err = account.NormalizeEmail(recipient); err != nil {
			fe, _ := validationOf(err)
			fe.Field = "recipient"
			id.adminSignupPage(w, r, http.StatusUnprocessableEntity, fe, label, days, recipient)
			return
		}
	}
	c, issued, err := id.Signup.CreateCode(r.Context(), id.actor(r), label, days)
	if err != nil {
		if fe, ok := validationOf(err); ok {
			id.adminSignupPage(w, r, http.StatusUnprocessableEntity, fe, label, days, recipient)
			return
		}
		id.serverError(w, r, err)
		return
	}
	base, err := id.adminPage(r, "admin_signup.code_title", "signup")
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view := &signupCodeView{adminPage: base, Code: c, Plain: issued.Plaintext, Expires: dateOf(&c.ExpiresAt)}
	if to != "" {
		msgID, err := uuid.NewV7()
		if err == nil {
			err = id.Mailer.Send(r.Context(), mailer.Message{To: to, Language: requestLanguage(w), Template: mailer.SignupCode,
				Path: signup.SignupPath, Code: issued.Plaintext, Params: map[string]string{"Expires": c.ExpiresAt.UTC().Format(time.DateOnly)}}, msgID)
		}
		if err != nil {
			id.logger.Warn("envoi d'un code d'inscription en échec", "code", c.ID, "err", err)
			view.SendFailed = true
		} else {
			view.MailedTo = to
		}
	}
	noStore(w)
	id.rd.Render(w, r, http.StatusOK, "admin/signup_code", view)
}

func (id *identity) signupCodeFromPath(w http.ResponseWriter, r *http.Request) (signup.Code, bool) {
	cid, err := uuid.Parse(chi.URLParam(r, "codeID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return signup.Code{}, false
	}
	c, err := id.Signup.CodeByID(r.Context(), cid)
	if errors.Is(err, signup.ErrCodeNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return signup.Code{}, false
	}
	if err != nil {
		id.serverError(w, r, err)
		return signup.Code{}, false
	}
	return c, true
}

// confirmRevokeSignupCode : révocation d'un code d'inscription.
func (id *identity) confirmRevokeSignupCode(w http.ResponseWriter, r *http.Request) {
	c, ok := id.signupCodeFromPath(w, r)
	if !ok {
		return
	}
	id.confirm(w, r, confirmation{nav: adminNav("signup"), heading: "confirm.signup_code_heading",
		text: "confirm.signup_code_text", submit: "confirm.signup_code_submit",
		args: map[string]any{"Label": c.Label}, cancel: pathAdminSignup})
}

func (id *identity) revokeSignupCode(w http.ResponseWriter, r *http.Request) {
	c, ok := id.signupCodeFromPath(w, r)
	if !ok {
		return
	}
	if err := id.Signup.RevokeCode(r.Context(), id.actor(r), c.ID); err != nil {
		if fe, ok := validationOf(err); ok {
			id.adminSignupPage(w, r, http.StatusUnprocessableEntity, fe, "", signup.DefaultCodeDays, "")
			return
		}
		if errors.Is(err, signup.ErrCodeNotFound) {
			id.rd.Error(w, r, http.StatusNotFound)
			return
		}
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, pathAdminSignup, "signup_code_revoked")
}
