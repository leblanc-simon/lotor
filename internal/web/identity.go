package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	authsql "leblanc.io/open-go-base/authx/sqlstore"
	"leblanc.io/open-go-base/mfax"
	mfasql "leblanc.io/open-go-base/mfax/sqlstore"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/dashboard"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/mailer"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/policy"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/search"
	"leblanc.io/lotor/internal/secret"
	"leblanc.io/lotor/internal/signup"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/web/middleware"
)

// Chemins du parcours de connexion.
const (
	pathLogin       = "/login"
	pathVerify      = "/login/2fa"
	pathTOTPSetup   = "/account/totp/setup"
	pathTOTPOn      = "/account/totp/enable"
	pathPassword    = "/account/password"
	pathTokens      = "/account/tokens"
	pathSecurity    = "/account/security"
	pathInvitations = "/account/invitations"
	pathLogout      = "/logout"
	pathHome        = "/"
)

// IdentityOptions branche les comptes, les sessions, le TOTP et les organisations sur
// l'interface. Sans elles (tests du socle), l'interface n'a que ses pages publiques.
type IdentityOptions struct {
	Pool     *db.Pool
	Accounts *account.Service
	Orgs     *org.Service
	Projects *project.Service
	Agents   *agent.Service
	// Inventory et Ingest servent les écrans des instantanés (T05).
	Inventory *inventory.Service
	Ingest    *ingest.Service
	// History sert la frise, les comparaisons d'instantanés et la politique de
	// rétention affichée (T17).
	History *inventory.History
	// Findings sert les constats, les fiches vulnérabilité et composant (T06).
	Findings *finding.Service
	// Triage sert le triage des constats et les VEX (T14).
	Triage *triage.Service
	// Search sert l'écran de recherche et ses exports (bornés par Exports), et compare
	// les versions de la fiche composant (T09).
	Search  *search.Service
	Exports *search.ExportLimiter
	// Reencodes borne les réencodages simultanés de SBOM téléchargés (CycloneDX, SPDX).
	Reencodes *search.ExportLimiter
	// Policies sert les politiques, les violations et la section « Alertes » du tableau
	// de bord ; Notify les canaux de notification (T15).
	Policies *policy.Service
	Notify   *notify.Service
	// Dashboard sert le tableau de bord et l'en-tête de la fiche projet (T10).
	Dashboard *dashboard.Service
	// VulnDB règle l'écran de la base de vulnérabilités et son alerte d'âge.
	VulnDB VulnDBOptions
	// Signup porte l'inscription (T28) : mode, codes, liens de vérification et
	// d'invitation. Mailer envoie sur-le-champ un code d'inscription (nil sans envoi de
	// courriels) ; PublicURL est web.public_url (vide si non réglée).
	Signup    *signup.Service
	Mailer    *mailer.Mailer
	PublicURL string
	// Secrets chiffre les secrets TOTP en base.
	Secrets *secret.Box
	Auth    appconf.Auth
	MFA     appconf.MFA
	// LoginRateLimit borne les POST de /login et /login/2fa par minute et par IP (0 : sans).
	LoginRateLimit int
	// SessionMaxAge est la durée absolue d'une session authentifiée, comptée depuis la
	// connexion, quelle que soit son activité (0 : sans).
	SessionMaxAge time.Duration
	// ContainerArchiveAfter est l'absence au-delà de laquelle un conteneur est archivé
	// (affichée sur la fiche d'un hôte ; 0 : project.DefaultArchiveAfter).
	ContainerArchiveAfter time.Duration
	// ForbidExternalAI : l'instance interdit tout fournisseur de modèle externe
	// (ai.forbid_external) ; le réglage « external » d'un projet n'est pas proposé.
	ForbidExternalAI bool

	// routeStub, s'il est posé (tests seulement, depuis le paquet), remplace le
	// gestionnaire de chaque route de l'organisation derrière sa garde de droit : le test
	// dérivé de la matrice éprouve ainsi toute la chaîne (session, CSRF, garde
	// d'organisation, droit de la route) sans effet de bord.
	routeStub http.HandlerFunc
}

// identity porte authx, mfax et ce que l'interface en tire : visiteur, gardes, rendu des
// pages de connexion.
type identity struct {
	IdentityOptions
	mgr        *authx.Manager
	login      *authx.Handlers
	mfa        *mfax.Service
	challenges mfax.ChallengeStore
	rd         *render.Renderer
	cat        *locale.Catalog
	logger     *slog.Logger
	clientIP   func(*http.Request) string
}

func newIdentity(o IdentityOptions, rd *render.Renderer, cat *locale.Catalog, logger *slog.Logger, clientIP func(*http.Request) string) (*identity, error) {
	if o.Pool == nil || o.Accounts == nil || o.Orgs == nil || o.Projects == nil || o.Agents == nil || o.Inventory == nil ||
		o.History == nil || o.Ingest == nil || o.Findings == nil || o.Triage == nil || o.Search == nil || o.Exports == nil || o.Reencodes == nil || o.Dashboard == nil || o.Policies == nil || o.Notify == nil || o.Signup == nil || o.Secrets == nil || o.VulnDB.MaxAge <= 0 {
		return nil, errors.New("web: dépendances de l'identité incomplètes")
	}
	if hostCookies(o.Auth.CookieSecure) {
		o.Auth.CookieName = hostCookie(o.Auth.CookieName)
	}
	id := &identity{IdentityOptions: o, rd: rd, cat: cat, logger: logger, clientIP: clientIP}
	d := appconf.DialectPostgres
	sqlDB := o.Pool.DB()
	sessions := account.NewSessionRecorder(authsql.NewSessionStore(sqlDB, d), o.Pool)
	id.mgr = authx.New(o.Auth, authsql.NewUserStore(sqlDB, d), sessions,
		authx.WithManagerErrorHandler(id.authError))
	id.challenges = mfasql.NewChallengeStore(sqlDB, d)
	totp := account.NewSealedTOTPStore(mfasql.NewTOTPStore(sqlDB, d), o.Secrets, o.Pool)
	// Enrôlement obligatoire : jamais mfax.WithOptionalEnrollment().
	// Verrouillage par compte : le plafond par défi ne borne pas une force brute du TOTP,
	// un nouveau défi s'obtenant en rejouant le mot de passe (ADR 0029).
	mfaOpts := []mfax.Option{
		mfax.WithRenderer(authRenderer{id}),
		mfax.WithPaths(pathVerify, pathTOTPSetup, pathHome),
		mfax.WithErrorHandler(id.mfaError),
		mfax.WithLockout(mfasql.NewLockoutStore(sqlDB, d)),
		mfax.WithLockoutHook(id.accountLocked),
		// Codes de secours (T18) : montrés à l'enrôlement, acceptés à la connexion à la
		// place d'un code TOTP ; une connexion par code de secours mène à la page du second
		// facteur, qui dit combien il en reste et propose de reconfigurer l'application.
		mfax.WithRecoveryCodes(mfasql.NewRecoveryStore(sqlDB, d)),
		mfax.WithRecoveryHook(id.recoveryCodeUsed),
		mfax.WithRecoveryLanding(pathSecurity + "?done=" + doneRecoverySignIn),
	}
	if hostCookies(o.Auth.CookieSecure) {
		mfaOpts = append(mfaOpts, mfax.WithChallengeCookieName(hostCookie(mfax.ChallengeCookieName)))
	}
	id.mfa = mfax.New(o.MFA, id.mgr, totp, id.challenges, mfaOpts...)
	id.login = authx.NewHandlers(id.mgr, authRenderer{id},
		authx.WithSecondFactor(id.mfa), authx.WithHomePath(pathHome), authx.WithErrorHandler(id.authError))
	return id, nil
}

// hostCookies indique si les cookies prennent le préfixe __Host- : il exige Secure, donc
// cookie_secure à on.
func hostCookies(cookieSecure string) bool { return cookieSecure == "on" }

// hostCookie préfixe name de __Host- : le navigateur refuse alors qu'un sous-domaine ou
// une réponse en clair l'écrase (Secure, Path=/, sans Domain).
func hostCookie(name string) string {
	if strings.HasPrefix(name, "__Host-") {
		return name
	}
	return "__Host-" + name
}

// accountLocked journalise le verrouillage d'un compte par mfax.
func (id *identity) accountLocked(r *http.Request, u *authx.User, until time.Time) {
	a := authRenderer{id}
	a.record(r, audit.Event{Action: audit.AccountLocked, TargetType: "account", TargetID: strconv.FormatInt(u.ID, 10),
		TargetLabel: u.Email, Details: map[string]string{"until": until.UTC().Format(time.RFC3339)}})
}

// recoveryCodeUsed journalise un code de secours consommé (connexion ou réauthentification)
// et le nombre restant. À la connexion, la requête n'a pas encore de visiteur : l'auteur est
// le titulaire du code.
func (id *identity) recoveryCodeUsed(r *http.Request, u *authx.User, remaining int) {
	actor := id.actor(r)
	if actor.UserID == 0 {
		actor.UserID, actor.Email = u.ID, u.Email
	}
	ev := audit.Event{Action: audit.RecoveryCodeUsed, TargetType: "account", TargetID: strconv.FormatInt(u.ID, 10),
		TargetLabel: u.Email, Details: map[string]string{"remaining": strconv.Itoa(remaining)}}
	if err := audit.RecordInstance(r.Context(), id.Pool.DB(), actor, ev); err != nil {
		middleware.Logger(r.Context(), id.logger).Error("journal d'audit", "action", ev.Action, "err", err)
	}
}

func (id *identity) authError(w http.ResponseWriter, r *http.Request, status int, code authx.ErrorCode, err error) {
	id.fail(w, r, status, string(code), err)
}

func (id *identity) mfaError(w http.ResponseWriter, r *http.Request, status int, code mfax.ErrorCode, err error) {
	id.fail(w, r, status, string(code), err)
}

func (id *identity) fail(w http.ResponseWriter, r *http.Request, status int, code string, err error) {
	if err != nil {
		middleware.Logger(r.Context(), id.logger).Error("authentification", "code", code, "err", err)
	}
	id.rd.Error(w, r, status)
}

// serverError journalise err et rend la page 500.
func (id *identity) serverError(w http.ResponseWriter, r *http.Request, err error) {
	middleware.Logger(r.Context(), id.logger).Error("requête", "err", err)
	id.rd.Error(w, r, http.StatusInternalServerError)
}

// actor décrit l'auteur de la requête pour le journal d'audit.
func (id *identity) actor(r *http.Request) audit.Actor {
	a := audit.Actor{IP: id.clientIP(r), RequestID: middleware.RequestIDFrom(r.Context())}
	if v := viewerFrom(r); v != nil {
		a.UserID, a.Email = v.user.ID, v.user.Email
	}
	return a
}

// viewer est le compte connecté d'une requête.
type viewer struct {
	user    *authx.User
	session *authx.Session
	state   account.ViewerState
}

func (v *viewer) authenticated() bool { return v != nil && v.session.Purpose == authx.PurposeAuth }
func (v *viewer) admin() bool         { return v != nil && v.user.Role == account.RoleAdmin }

type viewerKey struct{}

func viewerFrom(r *http.Request) *viewer {
	v, _ := r.Context().Value(viewerKey{}).(*viewer)
	return v
}

// trustClientIP réécrit X-Forwarded-For avec l'IP résolue (mandataires de confiance
// seulement) et retire X-Forwarded-Proto d'un pair non fiable : authx, qui lit ces
// en-têtes sans vérifier le pair, enregistre alors la bonne IP de session.
func trustClientIP(proxies middleware.TrustedProxies, clientIP func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r2 := r.Clone(r.Context())
			r2.Header.Set("X-Forwarded-For", clientIP(r))
			if !proxies.Trusts(r) {
				r2.Header.Del("X-Forwarded-Proto")
			}
			next.ServeHTTP(w, r2)
		})
	}
}

// loadViewer suit authx.LoadSession : il refuse une session authentifiée sans méthode
// enregistrée, dont le compte n'a plus de TOTP actif (réinitialisé entre-temps) ou ouverte
// depuis plus de SessionMaxAge (la session d'authx glisse à chaque requête : sans cette
// borne, un cookie volé et utilisé régulièrement ne mourrait jamais), et place le visiteur
// et l'en-tête dans le contexte.
func (id *identity) loadViewer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, sess := authx.UserFrom(r), authx.SessionFrom(r)
		if user == nil || sess == nil {
			next.ServeHTTP(w, r)
			return
		}
		st, err := id.Accounts.Viewer(r.Context(), user.ID, sess.Token)
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		v := &viewer{user: user, session: sess, state: st}
		if v.authenticated() && (!st.HasMethod || !st.TOTPEnabled) {
			id.mgr.Logout(w, r)
			http.Redirect(w, r, pathLogin, http.StatusSeeOther)
			return
		}
		if v.authenticated() && id.SessionMaxAge > 0 && time.Since(st.AuthenticatedAt) > id.SessionMaxAge {
			id.mgr.Logout(w, r)
			authx.RedirectToLogin(w, r)
			return
		}
		chrome := &render.Chrome{UserEmail: user.Email, Theme: st.Settings.Theme}
		if v.authenticated() {
			chrome.Authenticated, chrome.Admin = true, v.admin()
			for _, o := range st.Orgs {
				chrome.Orgs = append(chrome.Orgs, render.OrgEntry{Slug: o.Slug, Name: o.Name})
			}
		}
		ctx := context.WithValue(r.Context(), viewerKey{}, v)
		next.ServeHTTP(w, r.WithContext(render.WithChrome(ctx, chrome)))
	})
}

// accountLanguage est la source « préférence du compte » de l'ordre du § 18.
func accountLanguage(r *http.Request) string {
	if v := viewerFrom(r); v != nil {
		return v.state.Settings.Language
	}
	return ""
}

// mustChangePassword impose le changement d'un mot de passe temporaire avant toute autre
// page : ni authx ni mfax n'appliquent must_change_pwd.
func mustChangePassword(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := viewerFrom(r); v.authenticated() && v.user.MustChangePwd &&
			r.URL.Path != pathPassword && r.URL.Path != pathLogout {
			http.Redirect(w, r, pathPassword, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuth exige une session pleinement authentifiée ; une session de configuration est
// renvoyée vers l'enrôlement du TOTP, un visiteur anonyme vers la connexion.
func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := viewerFrom(r)
		switch {
		case v.authenticated():
			next.ServeHTTP(w, r)
		case v != nil:
			http.Redirect(w, r, pathTOTPSetup, http.StatusSeeOther)
		default:
			authx.RedirectToLogin(w, r)
		}
	})
}

// requireSession accepte aussi une session de configuration (enrôlement du TOTP).
func requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if viewerFrom(r) == nil {
			authx.RedirectToLogin(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireInstanceAdmin réserve l'administration de l'instance à ses administrateurs ; les
// autres reçoivent 404, comme pour une page qui n'existe pas.
func (id *identity) requireInstanceAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !viewerFrom(r).admin() {
			id.rd.Error(w, r, http.StatusNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// orgGuard établit l'organisation de /o/{slug} : le compte doit en être membre et elle doit
// être active, sinon 404 (jamais 403, pour ne rien révéler de son existence). Il place
// tenant.Access dans le contexte et recalcule la langue avec celle de l'organisation.
func (id *identity) orgGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := viewerFrom(r)
		acc, err := id.Orgs.Access(r.Context(), chi.URLParam(r, "slug"), v.user.ID)
		if errors.Is(err, org.ErrNoAccess) {
			id.rd.Error(w, r, http.StatusNotFound)
			return
		}
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		ctx := tenant.WithAccess(r.Context(), acc)
		tag := middleware.ResolveLanguage(id.cat, r, middleware.LanguageSources{
			Account: accountLanguage,
			Org:     func(*http.Request) string { return acc.Language },
		})
		w.Header().Set("Content-Language", tag.String())
		ctx = locale.NewContext(ctx, id.cat.Localizer(tag))
		if c := render.ChromeFrom(ctx); c != nil {
			cc := *c
			cc.Orgs = make([]render.OrgEntry, len(c.Orgs))
			for i, o := range c.Orgs {
				o.Current = o.Slug == acc.Slug
				cc.Orgs[i] = o
			}
			cc.Current = &render.OrgEntry{Slug: acc.Slug, Name: acc.Name, Current: true}
			ctx = render.WithChrome(ctx, &cc)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// safeNext ne garde qu'un chemin local pour ?next=.
func safeNext(next string) string {
	if p := authx.SafeRedirectPath(next, ""); p != "" && !strings.HasPrefix(p, pathLogin) {
		return p
	}
	return ""
}
