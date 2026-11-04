package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"leblanc.io/open-go-base/ratelimit"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/api/gen/userapi"
	"leblanc.io/lotor/internal/api/problem"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/search"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/triage/vex"
	"leblanc.io/lotor/internal/web/middleware"
)

// UserOptions réunit les dépendances de l'API utilisateur (/api/v1/orgs/{org}/*).
type UserOptions struct {
	Pool     *db.Pool
	Accounts *account.Service
	Orgs     *org.Service
	Search   *search.Service
	Exports  *search.ExportLimiter
	// Projects, Inventory, History et Findings servent la frise et les comparaisons
	// d'instantanés (T17) ; Triage l'export VEX d'un projet (T14), Version nomme l'outil.
	Projects  *project.Service
	Inventory *inventory.Service
	History   *inventory.History
	Findings  *finding.Service
	Triage    *triage.Service
	// Agents et Ingest servent l'import des archives hors ligne (T23) ; sans eux, la route
	// n'est pas montée.
	Agents  *agent.Service
	Ingest  *ingest.Service
	Version string
	Catalog *locale.Catalog
	Logger  *slog.Logger
	// RateLimit borne les requêtes par minute et par jeton personnel (0 : sans limite).
	RateLimit int
	// FailureRateLimit borne les jetons refusés par minute et par IP (0 : sans limite).
	FailureRateLimit int
	TrustedProxies   []string
}

// MountUser monte l'API utilisateur sur r, sous-routeur de /api/v1/orgs/{org} : jeton personnel (lecture
// seule, ADR 0025), limitation par jeton, garde d'organisation (404 hors des organisations
// du compte), puis le serveur généré.
func MountUser(r chi.Router, o UserOptions) error {
	if o.Pool == nil || o.Accounts == nil || o.Orgs == nil || o.Search == nil || o.Exports == nil ||
		o.Projects == nil || o.Inventory == nil || o.History == nil || o.Findings == nil || o.Triage == nil ||
		o.Catalog == nil || o.Logger == nil {
		return errors.New("api: dépendances de l'API utilisateur incomplètes")
	}
	h := &userAPI{UserOptions: o}
	tooMany := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		problem.Write(w, r, o.Catalog, http.StatusTooManyRequests, problem.KeyTooManyRequests, nil)
	})
	perToken, err := ratelimit.New(o.RateLimit, o.TrustedProxies, ratelimit.WithLimitHandler(tooMany),
		ratelimit.WithKeyFunc(func(r *http.Request) string {
			if p, ok := r.Context().Value(userKey{}).(account.TokenPrincipal); ok {
				return p.RateKey()
			}
			return ""
		}))
	if err != nil {
		return err
	}
	failures, err := ratelimit.New(o.FailureRateLimit, o.TrustedProxies, ratelimit.WithLimitHandler(tooMany))
	if err != nil {
		return err
	}
	h.refuse = failures.Middleware(http.HandlerFunc(h.writeRefusal))
	// Le serveur généré enregistre les chemins complets du contrat (/orgs/{org}/…) ; r est
	// déjà le sous-routeur de /orgs/{org}, dont la chaîne (CORS compris) doit précéder le
	// routage pour les requêtes préliminaires. Les opérations y sont donc montées une à
	// une, par l'adaptateur généré qui lit et valide leurs paramètres.
	gen := &userapi.ServerInterfaceWrapper{Handler: h, ErrorHandlerFunc: h.badRequest}
	r.Group(func(r chi.Router) {
		r.Use(h.authenticate, perToken.Middleware, h.orgGuard)
		r.Get("/search", gen.SearchOrganization)
		r.Get("/search/export", gen.ExportSearch)
		r.Get("/projects/{project}/vex", gen.ExportProjectVEX)
		r.Get("/projects/{project}/snapshots", gen.ListProjectSnapshots)
		r.Get("/projects/{project}/compare", gen.CompareSnapshots)
		if o.Agents != nil && o.Ingest != nil {
			r.Post("/archives", gen.ImportArchive)
		}
	})
	return nil
}

type userAPI struct {
	UserOptions
	refuse http.Handler
}

var _ userapi.ServerInterface = (*userAPI)(nil)

type userKey struct{}

// authenticate vérifie le jeton personnel ; un refus répond 401 (limité par IP).
func (h *userAPI) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := h.Accounts.AuthenticateToken(r.Context(), bearer(r))
		if err != nil {
			var te *account.TokenError
			if !errors.As(err, &te) {
				h.internal(w, r, err)
				return
			}
			h.refuse.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), refusalKey{}, te.Key)))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, p)))
	})
}

func (h *userAPI) writeRefusal(w http.ResponseWriter, r *http.Request) {
	key, _ := r.Context().Value(refusalKey{}).(string)
	if key == "" {
		key = account.KeyTokenInvalid
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="lotor"`)
	problem.Write(w, r, h.Catalog, http.StatusUnauthorized, key, nil)
}

// orgGuard vérifie, à chaque requête, que le propriétaire du jeton est membre de
// l'organisation de l'URL (active) : sinon 404, comme l'interface, pour ne rien révéler.
// Ses rôles d'équipe du moment bornent ce que le jeton voit (ADR 0034).
func (h *userAPI) orgGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := r.Context().Value(userKey{}).(account.TokenPrincipal)
		acc, err := h.Orgs.Access(r.Context(), chi.URLParam(r, "org"), p.UserID)
		if errors.Is(err, org.ErrNoAccess) {
			problem.Write(w, r, h.Catalog, http.StatusNotFound, problem.KeyNotFound, nil)
			return
		}
		if err != nil {
			h.internal(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(tenant.WithAccess(r.Context(), acc)))
	})
}

func (h *userAPI) badRequest(w http.ResponseWriter, r *http.Request, _ error) {
	problem.Write(w, r, h.Catalog, http.StatusBadRequest, problem.KeyInvalidRequest, nil)
}

func (h *userAPI) internal(w http.ResponseWriter, r *http.Request, err error) {
	middleware.Logger(r.Context(), h.Logger).Error("api utilisateur", "err", err)
	problem.Write(w, r, h.Catalog, http.StatusInternalServerError, problem.KeyInternal, nil)
}

// searchError répond à une recherche refusée ; faux si err n'en est pas une.
func searchError(w http.ResponseWriter, r *http.Request, cat *locale.Catalog, err error) bool {
	if e, ok := search.IsError(err); ok {
		problem.Write(w, r, cat, http.StatusBadRequest, e.Key, nil)
		return true
	}
	return problem.FromPagination(w, r, cat, err)
}

// SearchOrganization répond comme l'écran de recherche : les paramètres de l'URL sont lus
// par search.ParseRequest, comme ceux de l'écran.
func (h *userAPI) SearchOrganization(w http.ResponseWriter, r *http.Request, _ userapi.Org, _ userapi.SearchOrganizationParams) {
	acc, _ := tenant.AccessFrom(r.Context())
	req, err := search.ParseRequest(r.URL.Query())
	if err == nil {
		var res search.Result
		if res, err = h.Search.Search(r.Context(), acc.Org, acc.Visibility(), req); err == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(SearchResult(res))
			return
		}
	}
	if !searchError(w, r, h.Catalog, err) {
		h.internal(w, r, err)
	}
}

// ExportSearch écrit l'export d'une recherche.
func (h *userAPI) ExportSearch(w http.ResponseWriter, r *http.Request, _ userapi.Org, params userapi.ExportSearchParams) {
	acc, _ := tenant.AccessFrom(r.Context())
	p, _ := r.Context().Value(userKey{}).(account.TokenPrincipal)
	ServeExport(w, r, ExportOptions{Search: h.Search, Exports: h.Exports, Catalog: h.Catalog, Logger: h.Logger,
		Org: acc.Org, Visibility: acc.Visibility(), Slug: acc.Slug, Format: string(params.Format), UserID: p.UserID})
}

// ExportOptions décrit un export de recherche servi par ServeExport.
type ExportOptions struct {
	Search  *search.Service
	Exports *search.ExportLimiter
	Catalog *locale.Catalog
	Logger  *slog.Logger
	Org     tenant.OrgID
	// Visibility borne l'export aux projets des équipes visibles du compte.
	Visibility tenant.Visibility
	Slug       string
	Format     string
	// UserID est le compte de l'export : ses exports simultanés sont bornés.
	UserID int64
}

// ServeExport sert l'export d'une recherche (écran et API) : requête vérifiée avant toute
// écriture (400), place réservée parmi les exports simultanés (429 sinon), délai borné,
// puis lignes écrites en flux. Une erreur après les premières lignes ne peut plus changer
// le statut : elle est journalisée et la réponse s'interrompt.
func ServeExport(w http.ResponseWriter, r *http.Request, o ExportOptions) {
	req, err := search.ParseRequest(r.URL.Query())
	if err == nil {
		_, err = search.Parse(req.Q, o.Search.Comparer())
	}
	format := search.Format(o.Format)
	if err == nil && format != search.FormatCSV && format != search.FormatJSON {
		err = &search.Error{Key: search.KeyFilterInvalid}
	}
	if err != nil {
		if !searchError(w, r, o.Catalog, err) {
			problem.Write(w, r, o.Catalog, http.StatusInternalServerError, problem.KeyInternal, nil)
		}
		return
	}
	release, ok := o.Exports.Acquire("user:" + strconv.FormatInt(o.UserID, 10))
	if !ok {
		w.Header().Set("Retry-After", "30")
		problem.Write(w, r, o.Catalog, http.StatusTooManyRequests, problem.KeyTooManyRequests, nil)
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), o.Exports.Timeout())
	defer cancel()
	// Le délai d'écriture du serveur (http.write_timeout) vaut pour une page ; un export
	// a le sien. Sans prise en charge par l'enveloppe de la réponse, le premier s'applique.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(o.Exports.Timeout()))
	contentType := "text/csv; charset=utf-8"
	if format == search.FormatJSON {
		contentType = "application/json"
	}
	name := "lotor-" + o.Slug + "-" + time.Now().UTC().Format("20060102-150405") + "." + string(format)
	lw := &lazyHeaders{w: w, set: func(hd http.Header) {
		hd.Set("Content-Type", contentType)
		hd.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}}
	if err := o.Search.Export(ctx, o.Org, o.Visibility, req, format, lw); err != nil {
		middleware.Logger(r.Context(), o.Logger).Error("export de recherche", "err", err, "format", string(format))
		if !lw.started {
			problem.Write(w, r, o.Catalog, http.StatusInternalServerError, problem.KeyInternal, nil)
		}
	}
}

// lazyHeaders pose les en-têtes d'un export à sa première écriture : une erreur survenue
// avant peut encore répondre par un problème.
type lazyHeaders struct {
	w       http.ResponseWriter
	set     func(http.Header)
	started bool
}

func (l *lazyHeaders) Write(p []byte) (int, error) {
	if !l.started {
		l.started = true
		l.set(l.w.Header())
		l.w.WriteHeader(http.StatusOK)
	}
	return l.w.Write(p)
}

// SearchResult traduit un résultat dans le schéma de l'API.
func SearchResult(res search.Result) userapi.SearchResult {
	out := userapi.SearchResult{Query: res.Query.Raw, Kind: userapi.SearchResultKind(res.Query.Kind),
		Projects: res.Projects, Occurrences: res.Hits, Truncated: res.Truncated, Approximate: res.Approx,
		OutOfRange: res.OutOfRange, Tokens: []userapi.SearchToken{}, Groups: []userapi.SearchGroup{},
		UnreadableVersions: []userapi.SearchVersionCount{}}
	if res.NextCursor != "" {
		next := res.NextCursor
		out.Page.NextCursor = &next
	}
	if res.Partial {
		partial := true
		out.Partial, out.RetentionHorizon = &partial, res.Horizon
	}
	for _, t := range res.Query.Tokens() {
		out.Tokens = append(out.Tokens, userapi.SearchToken{Kind: userapi.SearchTokenKind(strings.TrimPrefix(t.KindKey, "search.kind_")),
			Value: t.Value})
	}
	for _, v := range res.Unreadable {
		out.UnreadableVersions = append(out.UnreadableVersions, userapi.SearchVersionCount{Version: v.Version, Occurrences: v.Occurrences})
	}
	for _, g := range res.Groups {
		labels := map[string]string(g.Project.Labels)
		if labels == nil {
			labels = map[string]string{}
		}
		sg := userapi.SearchGroup{Project: userapi.SearchProject{Id: g.Project.ID, Slug: g.Project.Slug, Name: g.Project.Name,
			Kind: userapi.SearchProjectKind(g.Project.Kind), Labels: labels,
			Team: userapi.TeamRef{Id: g.Project.Team.ID, Name: g.Project.Team.Name}},
			Occurrences: g.HitCount, MaxRisk: g.MaxRisk, LastScannedAt: g.Scanned, Truncated: g.Truncated, Hits: []userapi.SearchHit{}}
		if pr := g.Project.Parent; pr != nil {
			sg.Project.Parent = &userapi.ProjectRef{Id: pr.ID, Slug: pr.Slug}
		}
		for _, x := range g.Hits {
			sg.Hits = append(sg.Hits, searchHit(x))
		}
		out.Groups = append(out.Groups, sg)
	}
	return out
}

func searchHit(x search.Hit) userapi.SearchHit {
	h := userapi.SearchHit{Ref: userapi.SearchRef{Id: x.RefID, Kind: userapi.SearchRefKind(x.RefKind), Name: x.RefName},
		Component:          userapi.SearchComponent{Id: x.ComponentID, Purl: x.PURL, Name: x.Name, Version: x.Version, Type: x.Type},
		WeakIdentification: x.Weak, OpenVulnerabilities: x.Open, Kev: x.KEV, Risk: x.Risk, FixedVersions: x.Fixed,
		Confidence: x.Confidence}
	if h.FixedVersions == nil {
		h.FixedVersions = []string{}
	}
	if x.SnapshotID != [16]byte{} {
		id := x.SnapshotID
		h.SnapshotId = &id
		ts := x.ScannedAt
		h.ScannedAt = &ts
	}
	if x.Commit != "" {
		c := x.Commit
		h.Commit = &c
	}
	if x.Origin != "" {
		o := userapi.SearchHitOrigin(x.Origin)
		h.Origin = &o
	}
	if x.Severity != "" {
		s := userapi.SearchHitMaxSeverity(x.Severity)
		h.MaxSeverity = &s
	}
	if x.VulnID != "" {
		v, s := x.VulnID, userapi.SearchHitStatus(x.Status)
		h.Vulnerability, h.Status = &v, &s
	}
	if x.Triage != "" {
		t := userapi.SearchHitTriageStatus(x.Triage)
		h.TriageStatus = &t
	}
	return h
}

// KeyVEXEmpty : le projet n'a aucune décision de triage à exporter.
const KeyVEXEmpty = "error.vex_empty"

// ExportProjectVEX sert le VEX d'un projet visible du propriétaire du jeton.
func (h *userAPI) ExportProjectVEX(w http.ResponseWriter, r *http.Request, _ userapi.Org, slug string, params userapi.ExportProjectVEXParams) {
	acc, _ := tenant.AccessFrom(r.Context())
	f, err := vex.ParseFormat(string(params.Format))
	if err != nil {
		h.badRequest(w, r, err)
		return
	}
	p, err := h.Projects.Get(r.Context(), acc.Org, acc.Visibility(), slug)
	if errors.Is(err, project.ErrNotFound) {
		problem.Write(w, r, h.Catalog, http.StatusNotFound, problem.KeyNotFound, nil)
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	data, err := vex.Export(r.Context(), h.Triage, acc.Org, p.ID, f, vex.Meta{Author: acc.Name, Tooling: "lotor " + h.Version})
	if errors.Is(err, vex.ErrNoStatement) {
		problem.Write(w, r, h.Catalog, http.StatusNotFound, KeyVEXEmpty, nil)
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	ctype := "application/json"
	if f == vex.FormatCycloneDX {
		ctype = "application/vnd.cyclonedx+json"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}
