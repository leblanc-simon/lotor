//go:build integration

package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/prometheus/client_golang/prometheus"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	"leblanc.io/open-go-base/csrfx"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/agent"
	apiv1 "leblanc.io/lotor/internal/api"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/dashboard"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/policy"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	"leblanc.io/lotor/internal/search"
	"leblanc.io/lotor/internal/secret"
	"leblanc.io/lotor/internal/signup"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/version/grypeversion"
	"leblanc.io/lotor/internal/web/middleware"
	"leblanc.io/lotor/locales"
	"leblanc.io/lotor/web"
)

var (
	validatorOnce sync.Once
	validator     *schema.Validator
	validatorErr  error
)

// testValidator compile une fois les schémas JSON des SBOM pour tous les tests.
func testValidator(t testing.TB) *schema.Validator {
	t.Helper()
	validatorOnce.Do(func() { validator, validatorErr = schema.New() })
	if validatorErr != nil {
		t.Fatal(validatorErr)
	}
	return validator
}

// testCost est le coût bcrypt des tests : bas pour la vitesse, mais réel (le
// chronométrage des échecs de connexion en dépend).
const testCost = 6

// app est un serveur complet (routeur, comptes, organisations) sur une base jetable.
type app struct {
	t        *testing.T
	srv      *httptest.Server
	tdb      *dbtest.DB
	accounts *account.Service
	orgs     *org.Service
	projects *project.Service
	agents   *agent.Service
	ingest   *ingest.Service
	inv      *inventory.Service
	history  *inventory.History
	search   *search.Service
	exports  *search.ExportLimiter
	reencode *search.ExportLimiter
	dash     *dashboard.Service
	triage   *triage.Service
	policies *policy.Service
	notify   *notify.Service
	sent     *notifyRecorder
	clock    *testClock
	box      *secret.Box
	handler  http.Handler
	logs     *syncBuffer

	mu    sync.Mutex
	steps map[int64]int // pas TOTP déjà consommés par compte (anti-rejeu)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// notifyRecorder est un envoyeur de notifications de test : il garde les requêtes et
// les courriels, et échoue si err est posé.
type notifyRecorder struct {
	mu       sync.Mutex
	requests []notify.Request
	mails    []notify.Mail
	err      error
}

func (n *notifyRecorder) Do(_ context.Context, r notify.Request) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.requests = append(n.requests, r)
	return n.err
}

func (n *notifyRecorder) Mail(_ context.Context, m notify.Mail) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mails = append(n.mails, m)
	return n.err
}

type appOption func(*RouterOptions)

func newApp(t *testing.T, opts ...appOption) *app {
	t.Helper()
	tdb := dbtest.New(t)
	box, err := secret.New(map[string][]byte{"test": bytes.Repeat([]byte{7}, 32)}, "test")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := locale.New(locales.FS, ".", "fr")
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := web.Templates()
	if err != nil {
		t.Fatal(err)
	}
	st, err := web.Static()
	if err != nil {
		t.Fatal(err)
	}
	assets, err := render.NewAssets(st)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	rd, err := render.New(render.Options{Templates: tpl, Assets: assets, Catalog: cat, Version: "test", Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	clock := &testClock{now: time.Now().UTC()}
	a := &app{t: t, tdb: tdb, box: box, logs: logs, steps: map[int64]int{}, clock: clock,
		accounts: account.NewService(tdb.App, testCost), orgs: org.NewService(tdb.App),
		projects: project.NewService(tdb.App), agents: agent.NewService(tdb.App, agent.WithClock(clock.Now)),
		inv: inventory.NewService(tdb.App), search: search.NewService(tdb.App, grypeversion.New()),
		exports: search.NewExportLimiter(2, time.Minute), reencode: search.NewExportLimiter(2, time.Minute),
		dash: dashboard.NewService(tdb.App, dashboard.WithClock(clock.Now))}
	a.triage = triage.NewService(triage.Options{Pool: tdb.App, Comparer: grypeversion.New(), Now: clock.Now,
		OnChange: policy.OnTriageChange})
	compiler, err := policy.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	a.policies = policy.NewService(policy.Options{Pool: tdb.App, Compiler: compiler, PublicURL: "https://sbom.example.org", Now: clock.Now})
	a.sent = &notifyRecorder{}
	a.notify = notify.NewService(notify.Options{Pool: tdb.App, Secrets: box, Sender: a.sent, Loader: a.policies, Catalog: cat,
		PublicURL: "https://sbom.example.org", Now: clock.Now})
	if a.history, err = inventory.NewHistory(inventory.HistoryOptions{Pool: tdb.App, Comparer: grypeversion.New(),
		Retention: inventory.DefaultRetention(), Clock: jobs.ClockFunc(clock.Now)}); err != nil {
		t.Fatal(err)
	}
	if a.ingest, err = ingest.NewService(ingest.Options{Pool: tdb.App, Validator: testValidator(t), Logger: logger,
		Limits: ingest.Limits{MaxUpload: 8 << 20, SBOM: sbom.Limits{MaxBytes: 32 << 20, MaxDepth: 64, MaxComponents: 20_000}}}); err != nil {
		t.Fatal(err)
	}
	o := RouterOptions{
		Logger: logger, Catalog: cat, Renderer: rd, Assets: assets,
		Metrics:    middleware.NewHTTPMetrics(prometheus.NewRegistry()),
		RateLimit:  0,
		CSRFSecure: "off",
		Identity: &IdentityOptions{
			Pool: tdb.App, Accounts: a.accounts, Orgs: a.orgs, Projects: a.projects, Agents: a.agents, Secrets: box,
			Inventory: a.inv, History: a.history, Ingest: a.ingest, Findings: finding.NewService(tdb.App), Triage: a.triage,
			Search: a.search, Exports: a.exports, Reencodes: a.reencode,
			Dashboard: dashboard.NewService(tdb.App, dashboard.WithClock(clock.Now)),
			Policies:  a.policies, Notify: a.notify,
			VulnDB: VulnDBOptions{MaxAge: 120 * time.Hour, ListingURL: "https://grype.anchore.io/databases/v6/latest.json",
				SyncInterval: time.Minute, MaxArchive: 1 << 20, UploadTimeout: time.Minute},
			Auth:           appconf.Auth{SessionTTL: time.Hour, CookieName: "lotor_session", CookieSecure: "off", BcryptCost: testCost},
			MFA:            appconf.MFA{Issuer: "lotor", ChallengeTTL: time.Minute, MaxAttempts: 3},
			LoginRateLimit: 0,
		},
		AgentAPI: &apiv1.AgentOptions{Agents: a.agents, Ingest: a.ingest, Verdicts: a.policies},
		UserAPI: &apiv1.UserOptions{Pool: tdb.App, Accounts: a.accounts, Orgs: a.orgs, Search: a.search,
			Exports: search.NewExportLimiter(2, time.Minute), Projects: a.projects, Inventory: a.inv, History: a.history,
			Findings: finding.NewService(tdb.App), Triage: a.triage, Version: "test"},
	}
	if o.Identity.Signup, err = signup.NewService(signup.Options{Pool: tdb.App, Accounts: a.accounts, Secrets: box,
		Mode: signup.Private}); err != nil {
		t.Fatal(err)
	}
	for _, opt := range opts {
		opt(&o)
	}
	h, err := NewRouter(o)
	if err != nil {
		t.Fatal(err)
	}
	a.handler = h
	a.srv = httptest.NewServer(h)
	t.Cleanup(a.srv.Close)
	return a
}

// testClock est l'horloge des agents en test : elle n'avance que sur demande.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// browser est un client avec ses cookies, qui ne suit pas les redirections.
type browser struct {
	t   *testing.T
	app *app
	c   *http.Client
}

func (a *app) browser() *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		a.t.Fatal(err)
	}
	return &browser{t: a.t, app: a, c: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type page struct {
	status   int
	location string
	body     string
	header   http.Header
}

func (b *browser) do(req *http.Request) page {
	b.t.Helper()
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return page{status: resp.StatusCode, location: resp.Header.Get("Location"), body: string(body), header: resp.Header}
}

func (b *browser) get(path string) page {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.app.srv.URL+path, nil)
	if err != nil {
		b.t.Fatal(err)
	}
	return b.do(req)
}

func (b *browser) cookie(name string) string {
	u, _ := url.Parse(b.app.srv.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// csrf renvoie le jeton CSRF que le serveur attend de ce navigateur : lié à la session
// (csrfx.WithSessionBinding), il se calcule par csrfx lui-même à partir des cookies
// CSRF et de session. Le cookie CSRF s'obtient au besoin par une page publique.
func (b *browser) csrf() string {
	b.t.Helper()
	if b.cookie("csrf_token") == "" {
		b.get("/login")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: b.cookie("csrf_token")})
	if s := b.cookie("lotor_session"); s != "" {
		req.AddCookie(&http.Cookie{Name: "lotor_session", Value: s})
	}
	session := func(r *http.Request) string {
		if c, err := r.Cookie("lotor_session"); err == nil {
			return c.Value
		}
		return ""
	}
	var token string
	csrfx.New(csrfx.WithSessionBinding(session)).Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		token = csrfx.Token(r)
	})).ServeHTTP(httptest.NewRecorder(), req)
	return token
}

// post envoie un formulaire avec le jeton CSRF.
func (b *browser) post(path string, form url.Values) page {
	b.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", b.csrf())
	req, err := http.NewRequest(http.MethodPost, b.app.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req)
}

// user crée un compte prêt à l'emploi : mot de passe connu, TOTP actif, sans changement
// de mot de passe imposé.
type user struct {
	ID       int64
	Email    string
	Password string
	Secret   string
}

func (a *app) user(email string, admin bool) user {
	a.t.Helper()
	ctx := context.Background()
	u, _, err := a.accounts.Create(ctx, audit.System, email, admin)
	if err != nil {
		a.t.Fatal(err)
	}
	password := "phrase de passe de " + email
	hash, err := authx.HashPassword(password, testCost)
	if err != nil {
		a.t.Fatal(err)
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: email})
	if err != nil {
		a.t.Fatal(err)
	}
	sealed, err := seal(a.box, u.ID, key.Secret())
	if err != nil {
		a.t.Fatal(err)
	}
	if err := a.tdb.App.InTx(ctx, func(tx *db.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = $1, must_change_pwd = 0 WHERE id = $2`, hash, u.ID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO mfa_totp (user_id, secret, enabled) VALUES ($1, $2, 1)`, u.ID, sealed)
		return err
	}); err != nil {
		a.t.Fatal(err)
	}
	return user{ID: u.ID, Email: email, Password: password, Secret: key.Secret()}
}

// seal chiffre un secret TOTP comme account.SealedTOTPStore.
func seal(box *secret.Box, userID int64, plain string) (string, error) {
	ct, keyID, err := box.Seal([]byte(plain), []byte("mfa_totp:"+itoa(userID)))
	if err != nil {
		return "", err
	}
	return "s1:" + keyID + ":" + base64.StdEncoding.EncodeToString(ct), nil
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// code renvoie un code TOTP d'un pas jamais consommé pour ce compte : -30 s, puis 0, puis
// +30 s (mfax tolère un pas d'écart et refuse un pas déjà utilisé).
func (a *app) code(userID int64, secretKey string) string {
	a.t.Helper()
	a.mu.Lock()
	n := a.steps[userID]
	a.steps[userID] = n + 1
	a.mu.Unlock()
	if n > 2 {
		a.t.Fatalf("plus de trois connexions TOTP pour le compte %d dans le même test", userID)
	}
	// Le code du pas précédent n'est plus accepté si un changement de pas survient entre
	// sa génération et sa vérification (instabilité vue en CI chargée) : près de la fin
	// d'un pas, attendre le suivant.
	if n == 0 {
		if left := 30*time.Second - time.Duration(time.Now().UnixNano()%int64(30*time.Second)); left < 5*time.Second {
			time.Sleep(left + 100*time.Millisecond)
		}
	}
	c, err := totp.GenerateCode(secretKey, time.Now().Add(time.Duration(n-1)*30*time.Second))
	if err != nil {
		a.t.Fatal(err)
	}
	return c
}

// signIn connecte u par le vrai parcours (mot de passe, puis code TOTP).
func (a *app) signIn(u user) *browser {
	a.t.Helper()
	b := a.browser()
	p := b.post("/login", url.Values{"email": {u.Email}, "password": {u.Password}})
	if p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, "/login/2fa") {
		a.t.Fatalf("mot de passe de %s : %d %q", u.Email, p.status, p.location)
	}
	p = b.post("/login/2fa", url.Values{"code": {a.code(u.ID, u.Secret)}})
	if p.status != http.StatusSeeOther {
		a.t.Fatalf("code TOTP de %s : %d\n%s", u.Email, p.status, p.body)
	}
	return b
}

// org crée une organisation dont admin est l'administrateur.
func (a *app) org(slug string, admin user) org.Organization {
	a.t.Helper()
	o, err := a.orgs.Create(context.Background(), audit.System, slug, "Org "+slug, "fr", admin.ID)
	if err != nil {
		a.t.Fatal(err)
	}
	return o
}

func (a *app) addMember(o org.Organization, u user, role tenant.Role) {
	a.t.Helper()
	if err := a.orgs.AddMember(context.Background(), audit.System, o.ID, u.Email, role); err != nil {
		a.t.Fatal(err)
	}
}

// addTeamMember fait de u un membre de l'organisation et de son équipe par défaut, avec le
// rôle d'équipe role.
func (a *app) addTeamMember(o org.Organization, u user, role tenant.TeamRole) {
	a.t.Helper()
	a.addMember(o, u, tenant.RoleMember)
	if err := a.orgs.AddTeamMember(context.Background(), audit.System, o.ID, a.defaultTeam(o.ID), u.Email, role); err != nil {
		a.t.Fatal(err)
	}
}

// defaultTeam renvoie l'équipe créée avec l'organisation (DefaultTeamName).
func (a *app) defaultTeam(o tenant.OrgID) uuid.UUID {
	a.t.Helper()
	teams, err := a.orgs.Teams(context.Background(), o, tenant.AllTeams())
	if err != nil || len(teams) == 0 {
		a.t.Fatalf("équipes : %v, %v", teams, err)
	}
	return teams[0].ID
}

// inTeam rattache une saisie sans équipe à l'équipe par défaut de l'organisation.
func (a *app) inTeam(o tenant.OrgID, in project.Input) project.Input {
	a.t.Helper()
	if in.TeamID == uuid.Nil {
		in.TeamID = a.defaultTeam(o)
	}
	return in
}

// enrollTeam fait de même pour un jeton d'inscription.
func (a *app) enrollTeam(o tenant.OrgID, in agent.EnrollmentInput) agent.EnrollmentInput {
	a.t.Helper()
	if in.TeamID == uuid.Nil {
		in.TeamID = a.defaultTeam(o)
	}
	return in
}

var secretPattern = regexp.MustCompile(`<code class="auth__secret">([A-Z2-7 ]+)</code>`)

func setupSecret(t *testing.T, body string) string {
	t.Helper()
	m := secretPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("clé TOTP absente de la page :\n%s", body)
	}
	return strings.ReplaceAll(m[1], " ", "")
}

func unescape(s string) string { return html.UnescapeString(s) }
