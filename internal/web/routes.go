package web

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"leblanc.io/lotor/internal/render"
)

// registerUI déclare les routes de l'interface. Les écrans des lots suivants s'y ajoutent ;
// toute route de données d'organisation vit sous /o/{slug} (le test d'isolement le vérifie),
// déclarée avec son droit dans la table orgRoutes (guard.go).
func registerUI(r chi.Router, h *handlers, loginLimit func(http.Handler) http.Handler) {
	id := h.id
	if id == nil {
		r.Get("/", h.home)
		return
	}

	// Connexion : publiques, débit des POST borné par IP.
	r.Get(pathLogin, id.login.LoginGET)
	r.With(loginLimit).Post(pathLogin, id.login.LoginPOST)
	r.Get(pathVerify, id.mfa.VerifyGET)
	r.With(loginLimit).Post(pathVerify, id.verifyPOST)
	r.Post(pathLogout, id.logout)

	// Accueil : présentation de lotor pour un visiteur anonyme, sinon accueil du compte.
	r.Get("/", id.root)

	// Enrôlement du TOTP : session de configuration (premier login) ou authentifiée. mfax
	// refuse de re-provisionner un TOTP actif. La désactivation n'est pas montée : le TOTP
	// est obligatoire : seul un administrateur le réinitialise, ou son titulaire le
	// reconfigure depuis /account/security (nouvel enrôlement imposé à la connexion suivante).
	r.With(requireSession).Get(pathTOTPSetup, id.mfa.SetupGET)
	r.With(requireSession).Post(pathTOTPOn, id.enableTOTP)

	r.Group(func(r chi.Router) {
		r.Use(requireAuth)
		r.Get(pathSiteMap, id.siteMap)
		r.Get("/account", id.profile)
		r.Post("/account", id.saveProfile)
		r.Get(pathTokens, id.personalTokens)
		r.Post(pathTokens, id.createPersonalToken)
		r.Get(pathTokens+"/{tokenID}/revoke", id.confirmRevokePersonalToken)
		r.Post(pathTokens+"/{tokenID}/revoke", id.revokePersonalToken)
		r.Get(pathSecurity, id.security)
		r.Post(pathSecurity+"/recovery-codes", id.regenerateRecoveryCodes)
		r.Post(pathSecurity+"/reconfigure", id.reconfigureTOTP)
		r.Get(pathPassword, id.password)
		r.Post(pathPassword, id.changePassword)
		r.Get(pathInvitations, id.invitations)
		r.Post(pathInvitations+"/{invitationID}/accept", id.acceptInvitation)
		r.Get(pathInvitations+"/{invitationID}/decline", id.confirmDeclineInvitation)
		r.Post(pathInvitations+"/{invitationID}/decline", id.declineInvitation)

		r.Route("/admin", func(r chi.Router) {
			r.Use(id.requireInstanceAdmin)
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
			})
			r.Get("/users", id.adminUsers)
			r.Post("/users", id.createUser)
			r.Get("/users/{userID}", id.adminUser)
			r.Get("/users/{userID}/{action}", id.confirmUserAction)
			r.Post("/users/{userID}/{action}", id.userAction)
			r.Get("/orgs", id.adminOrgs)
			r.Post("/orgs", id.createOrg)
			r.Get("/orgs/{slug}", id.adminOrg)
			r.Post("/orgs/{slug}/{action}", id.adminOrgAction)
			r.Get("/audit", id.adminAudit)
			r.Get("/vulndb", id.vulnDB)
			r.Post(strings.TrimPrefix(pathVulnDBImport, "/admin"), id.importVulnDB)
			r.Post("/vulndb/purge", id.purgeVulnDB)
			r.Get("/jobs", id.adminJobs)
			r.Get("/jobs/{jobID}/discard", id.confirmDiscardJob)
			r.Post("/jobs/{jobID}/{action}", id.jobAction)
		})

		r.Route("/o/{slug}", func(r chi.Router) {
			r.Use(id.orgGuard)
			mountOrgRoutes(r, id)
		})
	})
}

type handlers struct {
	renderer *render.Renderer
	id       *identity
}

type homeView struct {
	render.Page
	NoOrg bool
	Admin bool
}

func (h *handlers) home(w http.ResponseWriter, r *http.Request) {
	h.renderer.Render(w, r, http.StatusOK, "home/index", &homeView{Page: render.Page{TitleKey: "home.title"}})
}
