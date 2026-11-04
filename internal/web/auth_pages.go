package web

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"leblanc.io/open-go-base/authx"
	"leblanc.io/open-go-base/mfax"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/web/middleware"
)

// authRenderer rend les pages dont authx et mfax ont besoin. Leurs erreurs arrivent sous
// forme de codes, traduits ici en clés.
type authRenderer struct{ id *identity }

type loginView struct {
	render.Page
	Next     string
	Email    string
	ErrorKey string
	InfoKey  string
	// Signup : inscription ouverte, "public" ou "invitation" (T28) ; vide sinon.
	Signup string
}

// RenderLogin rend le formulaire de connexion. Un échec est générique (jamais distinguer
// un e-mail inconnu d'un mot de passe faux) et journalisé ; authx égalise déjà le temps de
// réponse par une comparaison bcrypt factice.
func (a authRenderer) RenderLogin(w http.ResponseWriter, r *http.Request, v authx.LoginView) {
	view := &loginView{Page: render.Page{TitleKey: "login.title"}, Next: safeNext(v.Next), Email: v.Email,
		Signup: a.id.signupLinks()}
	status := http.StatusOK
	switch {
	case v.Code == authx.CodeInvalidCredentials:
		view.ErrorKey, status = "login.error.invalid_credentials", http.StatusUnauthorized
		a.record(r, audit.Event{Action: audit.LoginFailed, TargetType: "account", TargetLabel: v.Email})
	case r.URL.Query().Get("err") == string(mfax.CodeAttemptsExhausted):
		view.ErrorKey = "login.error.attempts_exhausted"
	case r.URL.Query().Get("err") == string(mfax.CodeLocked):
		view.ErrorKey = "login.error.locked"
	case r.URL.Query().Get("done") == doneTOTPReconfigured:
		view.InfoKey = "login.totp_reconfigured"
	}
	a.id.rd.Render(w, r, status, "auth/login", view)
}

func (a authRenderer) record(r *http.Request, ev audit.Event) {
	if err := audit.RecordInstance(r.Context(), a.id.Pool.DB(), a.id.actor(r), ev); err != nil {
		middleware.Logger(r.Context(), a.id.logger).Error("journal d'audit", "action", ev.Action, "err", err)
	}
}

type verifyView struct {
	render.Page
	Next     string
	ErrorKey string
	// Recovery : les codes de secours sont acceptés ; RecoveryError : le refus porte sur
	// un code de secours (le formulaire correspondant s'ouvre, son champ est signalé).
	Recovery      bool
	RecoveryError bool
}

// RenderVerify rend la saisie du code TOTP, et celle d'un code de secours ; un code refusé
// est journalisé pour le compte du défi en cours.
func (a authRenderer) RenderVerify(w http.ResponseWriter, r *http.Request, v mfax.VerifyView) {
	view := &verifyView{Page: render.Page{TitleKey: "verify.title"}, Next: safeNext(v.Next), Recovery: v.Recovery}
	status := http.StatusOK
	if v.Code == mfax.CodeInvalidCode || v.Code == mfax.CodeInvalidRecoveryCode {
		view.ErrorKey, status = "verify.error.invalid_code", http.StatusUnauthorized
		ev := audit.Event{Action: audit.TOTPFailed, TargetType: "account"}
		if v.Code == mfax.CodeInvalidRecoveryCode {
			view.ErrorKey, view.RecoveryError = "verify.error.invalid_recovery_code", true
			ev.Action = audit.RecoveryCodeFailed
		}
		if c, err := r.Cookie(a.id.mfa.ChallengeCookieName()); err == nil {
			if ch, err := a.id.challenges.Get(c.Value); err == nil {
				ev.TargetID = strconv.FormatInt(ch.UserID, 10)
				if u, err := a.id.Accounts.Get(r.Context(), ch.UserID); err == nil {
					ev.TargetLabel = u.Email
				}
			}
		}
		a.record(r, ev)
	}
	a.id.rd.Render(w, r, status, "auth/verify", view)
}

type setupView struct {
	render.Page
	Secret          string
	ProvisioningURL string
	QR              template.URL
	ErrorKey        string
}

// RenderSetup rend l'enrôlement du TOTP : QR et secret en clair, à saisir à la main au
// besoin.
func (a authRenderer) RenderSetup(w http.ResponseWriter, r *http.Request, v mfax.SetupView) {
	view := &setupView{
		Page:            render.Page{TitleKey: "totp_setup.title"},
		Secret:          groupBy4(v.Secret),
		ProvisioningURL: v.ProvisioningURL,
		// Sûr : data: URI entièrement produit par le serveur (mfax.QRDataURI), sans donnée
		// de l'utilisateur ; la CSP autorise img-src data:.
		QR: template.URL(v.QRDataURI),
	}
	switch v.Code {
	case mfax.CodeInvalidCode:
		view.ErrorKey = "totp_setup.error.invalid_code"
	case mfax.CodeLocked:
		view.ErrorKey = "totp_setup.error.locked"
	}
	a.id.rd.Render(w, r, http.StatusOK, "auth/totp_setup", view)
}

type recoveryCodesView struct {
	render.Page
	Codes []string
	Next  string
}

// RenderRecoveryCodes montre, une seule fois, les codes de secours tirés à l'enrôlement du
// TOTP (mfax.EnablePOST) ; la régénération depuis le compte passe par sa propre page.
func (a authRenderer) RenderRecoveryCodes(w http.ResponseWriter, r *http.Request, v mfax.RecoveryCodesView) {
	a.recordRecoveryCodes(r, len(v.Codes), "enrollment")
	a.id.rd.Render(w, r, http.StatusOK, "auth/recovery_codes",
		&recoveryCodesView{Page: render.Page{TitleKey: "recovery_codes.title"}, Codes: v.Codes, Next: pathHome})
}

// recordRecoveryCodes journalise la génération d'un jeu de codes de secours (jamais les
// codes eux-mêmes).
func (a authRenderer) recordRecoveryCodes(r *http.Request, count int, context string) {
	ev := audit.Event{Action: audit.RecoveryCodesGenerated, TargetType: "account",
		Details: map[string]string{"count": strconv.Itoa(count), "context": context}}
	if v := viewerFrom(r); v != nil {
		ev.TargetID, ev.TargetLabel = strconv.FormatInt(v.user.ID, 10), v.user.Email
	}
	a.record(r, ev)
}

// groupBy4 rend un secret base32 lisible à la recopie.
func groupBy4(s string) string {
	var b strings.Builder
	for i, c := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// deferredHeader retient le statut que mfax écrit avant d'appeler le Renderer : la page
// doit encore poser son Content-Type, ce qui n'est plus possible après WriteHeader.
type deferredHeader struct {
	http.ResponseWriter
	status int
	sent   bool
}

func (d *deferredHeader) WriteHeader(code int) {
	if d.status == 0 {
		d.status = code
	}
}

func (d *deferredHeader) Write(b []byte) (int, error) {
	d.flush()
	return d.ResponseWriter.Write(b)
}

func (d *deferredHeader) flush() {
	if d.sent {
		return
	}
	d.sent = true
	if d.status != 0 {
		d.ResponseWriter.WriteHeader(d.status)
	}
}

func (d *deferredHeader) Unwrap() http.ResponseWriter { return d.ResponseWriter }

func (id *identity) verifyPOST(w http.ResponseWriter, r *http.Request) {
	d := &deferredHeader{ResponseWriter: w}
	id.mfa.VerifyPOST(d, r)
	d.flush()
}

// logout journalise la déconnexion puis ferme la session.
func (id *identity) logout(w http.ResponseWriter, r *http.Request) {
	if v := viewerFrom(r); v != nil {
		a := authRenderer{id}
		a.record(r, audit.Event{Action: audit.Logout, TargetType: "account",
			TargetID: strconv.FormatInt(v.user.ID, 10), TargetLabel: v.user.Email})
	}
	id.login.Logout(w, r)
}
