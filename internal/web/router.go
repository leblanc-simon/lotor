package web

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	"leblanc.io/open-go-base/corsx"
	"leblanc.io/open-go-base/csrfx"
	"leblanc.io/open-go-base/ratelimit"

	apiv1 "leblanc.io/lotor/internal/api"
	"leblanc.io/lotor/internal/api/problem"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/web/middleware"
)

// RouterOptions réunit les dépendances du routeur.
type RouterOptions struct {
	Logger   *slog.Logger
	Catalog  *locale.Catalog
	Renderer *render.Renderer
	Assets   *render.Assets
	Metrics  *middleware.HTTPMetrics
	// RateLimit est le nombre de requêtes par minute et par IP de l'interface (0 : sans).
	RateLimit int
	// TrustedProxies : mandataires dont on croit X-Forwarded-For et X-Forwarded-Proto.
	TrustedProxies []string
	// CORS s'applique à l'API utilisateur seulement.
	CORS appconf.CORS
	// CSRFSecure pilote l'attribut Secure du cookie CSRF : auto, on, off.
	CSRFSecure string
	// Identity branche comptes, sessions, TOTP et organisations ; nil, l'interface n'a que
	// sa page d'accueil publique (tests du socle).
	Identity *IdentityOptions
	// AgentAPI monte l'API des agents (catalogue, journal, mandataires et IP du client
	// sont repris du routeur) ; nil, elle n'a aucune opération.
	AgentAPI *apiv1.AgentOptions
	// UserAPI monte l'API utilisateur (catalogue, journal et mandataires repris du
	// routeur) ; nil, elle n'a aucune opération.
	UserAPI *apiv1.UserOptions

	// extraUI ajoute des routes à l'interface (tests du paquet).
	extraUI func(chi.Router)
}

// csrfCookieName est le nom par défaut du cookie de csrfx.
const csrfCookieName = "csrf_token"

// sessionSecret est le secret auquel csrfx lie son jeton : le jeton de la session d'authx
// (vide sans session).
func sessionSecret(r *http.Request) string {
	if s := authx.SessionFrom(r); s != nil {
		return s.Token
	}
	return ""
}

// clientNetwork est la clé des limiteurs de l'interface : une IPv6 compte pour son /64,
// qu'un seul client reçoit couramment en entier ; une IPv4 garde sa clé par IP (clé vide).
func clientNetwork(clientIP func(*http.Request) string) func(*http.Request) string {
	return func(r *http.Request) string {
		ip, err := netip.ParseAddr(clientIP(r))
		if err != nil || !ip.Is6() || ip.Is4In6() {
			return ""
		}
		p, err := ip.WithZone("").Prefix(64)
		if err != nil {
			return ""
		}
		return "net6:" + p.String()
	}
}

// crossOrigin refuse les requêtes mutantes d'une autre origine selon les en-têtes des
// navigateurs (http.CrossOriginProtection) ; denied rend la page 403.
func crossOrigin(denied http.Handler) func(http.Handler) http.Handler {
	p := http.NewCrossOriginProtection()
	p.SetDenyHandler(denied)
	return p.Handler
}

// NewRouter construit le routeur public et ses trois groupes de routes.
func NewRouter(o RouterOptions) (http.Handler, error) {
	if o.Logger == nil || o.Catalog == nil || o.Renderer == nil || o.Assets == nil || o.Metrics == nil {
		return nil, errors.New("web: dépendances du routeur incomplètes")
	}
	proxies, err := middleware.ParseTrustedProxies(o.TrustedProxies)
	if err != nil {
		return nil, err
	}
	https := middleware.TLSDetector(proxies)
	uiHeaders := middleware.SecurityHeaders(middleware.SecurityOptions{CSP: middleware.CSPInterface, HTTPS: https, NoStore: true})
	apiHeaders := middleware.SecurityHeaders(middleware.SecurityOptions{CSP: middleware.CSPAPI, HTTPS: https, NoStore: true})

	tooMany := uiHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.Renderer.Error(w, r, http.StatusTooManyRequests)
	}))
	// La résolution de l'IP du client précède les limiteurs : leur clé regroupe une IPv6
	// par /64 (clientNetwork).
	resolver, err := ratelimit.New(0, o.TrustedProxies)
	if err != nil {
		return nil, err
	}
	byNetwork := ratelimit.WithKeyFunc(clientNetwork(resolver.ClientIP))
	limiter, err := ratelimit.New(o.RateLimit, o.TrustedProxies, ratelimit.WithLimitHandler(tooMany), byNetwork)
	if err != nil {
		return nil, err
	}
	accessLog := middleware.AccessLog(o.Logger, limiter.ClientIP)
	pageError := func(status int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { o.Renderer.Error(w, r, status) })
	}

	csrfFailure := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.Renderer.ErrorWithKey(w, r, http.StatusForbidden, "error.csrf")
	})
	// Jeton lié à la session (s'il y a des sessions) : écrire le cookie (sous-domaine,
	// réponse en clair) ne suffit plus à forger un couple valable ; préfixe __Host- quand
	// les cookies sont Secure.
	csrfOpts := []csrfx.Option{csrfx.WithSecure(o.CSRFSecure), csrfx.WithFailureHandler(csrfFailure)}
	if o.Identity != nil {
		csrfOpts = append(csrfOpts, csrfx.WithSessionBinding(sessionSecret))
	}
	if hostCookies(o.CSRFSecure) {
		csrfOpts = append(csrfOpts, csrfx.WithCookieName(hostCookie(csrfCookieName)))
	}
	csrf := csrfx.New(csrfOpts...).Middleware

	var id *identity
	loginLimit := func(next http.Handler) http.Handler { return next }
	ui := chi.Chain(
		o.Metrics.Middleware("ui"),
		limiter.Middleware,
		accessLog,
		middleware.Recover(o.Logger, pageError(http.StatusInternalServerError)),
		uiHeaders,
	)
	if o.Identity == nil {
		ui = append(ui, limitBody(nil))
	} else {
		if id, err = newIdentity(*o.Identity, o.Renderer, o.Catalog, o.Logger, limiter.ClientIP); err != nil {
			return nil, err
		}
		login, err := ratelimit.New(o.Identity.LoginRateLimit, o.TrustedProxies, ratelimit.WithLimitHandler(tooMany), byNetwork)
		if err != nil {
			return nil, err
		}
		loginLimit = login.Middleware
		// Session (authx) et visiteur, puis changement de mot de passe imposé (§ 14). Le
		// téléversement est borné par uploadGate, qui a besoin du visiteur.
		ui = append(ui, limitBody(isUpload), trustClientIP(proxies, limiter.ClientIP), id.mgr.LoadSession, id.loadViewer,
			mustChangePassword, id.uploadGate)
	}
	// La langue précède la garde d'organisation, qui la recalcule (§ 18). La protection
	// inter-origines (Sec-Fetch-Site, Origin) double csrfx : elle refuse aussi une requête
	// mutante venue d'un sous-domaine du même site, connexion comprise.
	ui = append(ui, crossOrigin(pageError(http.StatusForbidden)), csrf,
		middleware.Language(o.Catalog, middleware.LanguageSources{Account: accountLanguage}))
	api := func(group string) chi.Middlewares {
		return chi.Chain(
			o.Metrics.Middleware(group),
			accessLog,
			middleware.Recover(o.Logger, problem.Handler(o.Catalog, http.StatusInternalServerError, problem.KeyInternal)),
			apiHeaders,
			middleware.Language(o.Catalog, middleware.LanguageSources{}),
		)
	}
	apiNotFound := problem.Handler(o.Catalog, http.StatusNotFound, problem.KeyNotFound)
	apiNotAllowed := problem.Handler(o.Catalog, http.StatusMethodNotAllowed, problem.KeyMethodNotAllowed)

	r := chi.NewRouter()
	// GetHead sert HEAD par les routes GET ; il doit précéder le routage pour cela.
	r.Use(middleware.RequestID, chimw.GetHead)

	r.Group(func(r chi.Router) {
		r.Use(o.Metrics.Middleware("static"),
			middleware.Recover(o.Logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			})),
			middleware.SecurityHeaders(middleware.SecurityOptions{CSP: middleware.CSPInterface, HTTPS: https}))
		r.Handle("/static/*", o.Assets.Handler())
	})

	// Groupes d'API, sans session ni CSRF. Les opérations générées déclarent leurs chemins
	// complets sous /api/v1 ; route inconnue et méthode refusée y répondent par un
	// problème RFC 9457.
	r.Route("/api/v1", func(r chi.Router) {
		r.NotFound(api("api").Handler(apiNotFound).ServeHTTP)
		r.MethodNotAllowed(api("api").Handler(apiNotAllowed).ServeHTTP)
		if o.AgentAPI != nil {
			ao := *o.AgentAPI
			ao.Catalog, ao.Logger, ao.TrustedProxies, ao.ClientIP = o.Catalog, o.Logger, o.TrustedProxies, limiter.ClientIP
			var mountErr error
			r.Group(func(r chi.Router) {
				r.Use(api("agent")...)
				mountErr = apiv1.MountAgent(r, ao)
			})
			if mountErr != nil {
				err = mountErr
			}
		}
		// API utilisateur (/api/v1/orgs/{org}/…, jeton personnel) : la chaîne du groupe
		// (CORS compris) s'applique au montage (With), avant le routage, pour les requêtes
		// préliminaires et pour une route inconnue.
		r.With(append(chi.Middlewares{corsx.Middleware(o.CORS)}, api("user")...)...).Route("/orgs/{org}", func(r chi.Router) {
			r.NotFound(apiNotFound.ServeHTTP)
			r.MethodNotAllowed(apiNotAllowed.ServeHTTP)
			if o.UserAPI != nil {
				uo := *o.UserAPI
				uo.Catalog, uo.Logger, uo.TrustedProxies = o.Catalog, o.Logger, o.TrustedProxies
				if mountErr := apiv1.MountUser(r, uo); mountErr != nil {
					err = mountErr
				}
			}
		})
	})
	if err != nil {
		return nil, err
	}
	r.With(api("api")...).Handle("/api/*", apiNotFound)
	// Point compatible Dependency-Track (T19, ADR 0058) : hors de /api/v1, qui reste à
	// l'API du projet.
	if o.AgentAPI != nil {
		ao := *o.AgentAPI
		ao.Catalog, ao.Logger, ao.TrustedProxies, ao.ClientIP = o.Catalog, o.Logger, o.TrustedProxies, limiter.ClientIP
		r.With(api("dt")...).Route("/dt", func(r chi.Router) {
			r.NotFound(apiNotFound.ServeHTTP)
			r.MethodNotAllowed(apiNotAllowed.ServeHTTP)
			err = apiv1.MountDT(r, ao)
		})
		if err != nil {
			return nil, err
		}
	}

	r.Group(func(r chi.Router) {
		r.Use(ui...)
		registerUI(r, &handlers{renderer: o.Renderer, id: id}, loginLimit)
		if o.extraUI != nil {
			o.extraUI(r)
		}
	})
	r.NotFound(ui.Handler(pageError(http.StatusNotFound)).ServeHTTP)
	r.MethodNotAllowed(ui.Handler(pageError(http.StatusMethodNotAllowed)).ServeHTTP)
	return r, nil
}
