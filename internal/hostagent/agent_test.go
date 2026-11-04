package hostagent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/agentclient/gen"
)

// fakeServer imite l'API des agents : inscription, projets, envois, signaux de vie.
type fakeServer struct {
	mu          sync.Mutex
	projectID   uuid.UUID
	current     string // empreinte rangée (hexadécimal)
	lastScan    time.Time
	uploads     int
	heartbeats  []gen.HeartbeatRequest
	enrollments int
	failNext    bool // prochaine ingestion en échec
	noProject   bool
	scanPending bool
	lastContext gen.IngestionContext
	sbom        []byte
	// fingerprintOf calcule l'empreinte rangée d'après le SBOM reçu (gzip) ; nil :
	// pendingFingerprint.
	fingerprintOf func([]byte) string
	pending       string

	// Conteneurs : projets enfants par identité, inventaire rangé (empreinte), envois,
	// projets archivés par un utilisateur, signalements reçus.
	children     map[string]uuid.UUID
	childCurrent map[string]string
	childUploads map[string]int
	childWaiting map[string]string // ingestion → identité
	ignored      map[string]bool
	reports      []gen.ContainerReport
	// token : jeton d'agent remis à l'inscription (défaut lotor_agt_jeton).
	token string
}

func (f *fakeServer) agentToken() string {
	if f.token == "" {
		return "lotor_agt_jeton"
	}
	return f.token
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	write := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.URL.Path == "/api/v1/agent/enroll":
		if r.Header.Get("Authorization") != "Bearer lotor_enr_jeton" {
			write(http.StatusUnauthorized, gen.Problem{Type: "error.token.invalid", Status: 401})
			return
		}
		f.enrollments++
		write(http.StatusCreated, gen.EnrollmentResult{AgentId: uuid.New(), Token: f.agentToken(), Project: gen.ProjectRef{Id: f.projectID, Slug: "srv-test"}})
	case r.Header.Get("Authorization") != "Bearer "+f.agentToken():
		write(http.StatusUnauthorized, gen.Problem{Type: "error.token.invalid", Status: 401})
	case r.URL.Path == "/api/v1/agent/projects":
		list := gen.AgentProjectList{Projects: []gen.AgentProject{}}
		if !f.noProject {
			list.Projects = append(list.Projects, gen.AgentProject{Id: f.projectID, Kind: gen.AgentProjectKindHost, Slug: "srv-test",
				Refs: []gen.TrackedRef{{Id: uuid.New(), Kind: gen.TrackedRefKindHost, Name: "srv-test"}}})
		}
		write(http.StatusOK, list)
	case r.URL.Path == "/api/v1/agent/containers":
		var rep gen.ContainerReport
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			write(http.StatusBadRequest, gen.Problem{Type: "error.invalid_request"})
			return
		}
		f.reports = append(f.reports, rep)
		if f.children == nil {
			f.children, f.childCurrent, f.childUploads, f.childWaiting = map[string]uuid.UUID{}, map[string]string{}, map[string]int{}, map[string]string{}
		}
		out := gen.ContainerReportResult{Containers: []gen.ContainerState{}}
		for _, c := range rep.Containers {
			id, ok := f.children[c.Key]
			if !ok {
				id = uuid.New()
				f.children[c.Key] = id
			}
			st := gen.ContainerState{Key: c.Key, Project: gen.ProjectRef{Id: id, Slug: c.Key}, RefId: uuid.New(), Ignored: f.ignored[c.Key]}
			if c.Inventory != nil && !st.Ignored {
				v := gen.ContainerStateInventoryOutdated
				if c.Inventory.Fingerprint == f.childCurrent[c.Key] {
					v = gen.ContainerStateInventoryCurrent
				}
				st.Inventory = &v
			}
			out.Containers = append(out.Containers, st)
		}
		write(http.StatusOK, out)
	case r.URL.Path == "/api/v1/agent/heartbeat":
		var hb gen.HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&hb)
		f.heartbeats = append(f.heartbeats, hb)
		st := gen.HeartbeatStatus{ServerTime: time.Now(), ScanRequested: f.scanPending}
		f.scanPending = false
		if hb.Inventory != nil {
			v := gen.HeartbeatStatusInventoryOutdated
			if hb.Inventory.Fingerprint == f.current {
				v = gen.HeartbeatStatusInventoryCurrent
				f.lastScan = hb.Inventory.ScannedAt
			}
			st.Inventory = &v
		}
		write(http.StatusOK, st)
	case r.URL.Path == "/api/v1/agent/ingestions" && r.Method == http.MethodPost:
		mr, err := r.MultipartReader()
		if err != nil {
			write(http.StatusBadRequest, gen.Problem{Type: "error.invalid_request"})
			return
		}
		p, _ := mr.NextPart()
		_ = json.NewDecoder(p).Decode(&f.lastContext)
		p, _ = mr.NextPart()
		f.sbom, _ = io.ReadAll(p)
		if f.lastContext.Ref.Kind == gen.IngestionContextRefKindContainer {
			key := f.lastContext.Ref.Name
			if f.children[key] != f.lastContext.ProjectId {
				write(http.StatusNotFound, gen.Problem{Type: "error.ingest.ref_unknown", Status: 404})
				return
			}
			f.childUploads[key]++
			id := uuid.New()
			f.childWaiting[id.String()] = key
			zr, _ := gzip.NewReader(bytes.NewReader(f.sbom))
			raw, _ := io.ReadAll(zr)
			// Le faux scanner d'images met l'empreinte de l'image dans le SBOM.
			f.childCurrent["attente:"+key] = string(raw)
			write(http.StatusAccepted, gen.Ingestion{Id: id, Status: gen.Queued, ProjectId: f.lastContext.ProjectId})
			return
		}
		f.uploads++
		f.pending = pendingFingerprint
		if f.fingerprintOf != nil {
			f.pending = f.fingerprintOf(f.sbom)
		}
		id := uuid.New()
		write(http.StatusAccepted, gen.Ingestion{Id: id, Status: gen.Queued, ProjectId: f.projectID})
		if f.failNext {
			f.failNext = false
			f.current = "échec:" + id.String()
		} else {
			f.current = "attente:" + id.String()
		}
	case strings.HasPrefix(r.URL.Path, "/api/v1/agent/ingestions/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/agent/ingestions/")
		in := gen.Ingestion{Id: uuid.MustParse(id), Status: gen.Done}
		if key, ok := f.childWaiting[id]; ok {
			f.childCurrent[key] = f.childCurrent["attente:"+key]
			write(http.StatusOK, in)
			return
		}
		if f.current == "échec:"+id {
			in.Status, in.Error = gen.Failed, &gen.IngestionError{Key: "error.ingest.schema_invalid"}
			f.current = ""
		} else if f.current == "attente:"+id {
			f.current = f.pending
		}
		write(http.StatusOK, in)
	default:
		write(http.StatusNotFound, gen.Problem{Type: "error.not_found"})
	}
}

// pendingFingerprint est l'empreinte que le faux serveur range : celle du faux scanner.
var pendingFingerprint string

// fakeScanner renvoie un inventaire réglable.
type fakeScanner struct {
	mu    sync.Mutex
	fp    [32]byte
	scans int
	err   error
}

func (s *fakeScanner) Scan(context.Context) (Inventory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans++
	if s.err != nil {
		return Inventory{}, s.err
	}
	return Inventory{SBOM: []byte(`{"artifacts":[]}`), Fingerprint: s.fp, Components: 3, Started: time.Now().UTC(), Duration: time.Second}, nil
}

type harness struct {
	srv     *fakeServer
	scanner *fakeScanner
	agent   *Agent
	dir     string
}

func newHarness(t *testing.T, mutate ...func(*Config)) *harness {
	t.Helper()
	fs := &fakeServer{projectID: uuid.New()}
	srv := httptest.NewTLSServer(fs)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "enrollment-token")
	if err := os.WriteFile(tokenPath, []byte("lotor_enr_jeton\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := validConfig()
	cfg.Server.URL, cfg.StateDir, cfg.EnrollmentTokenFile, cfg.Hostname = srv.URL, filepath.Join(dir, "etat"), tokenPath, "SRV-Test"
	cfg.Scan.Root = testRoot(t)
	cfg.Labels = map[string]string{"role": "db"}
	for _, m := range mutate {
		m(&cfg)
	}
	client, err := agentclient.New(agentclient.Options{ServerURL: srv.URL, Transport: srv.Client().Transport,
		Retry: agentclient.Retry{Attempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	sc := &fakeScanner{fp: [32]byte{1, 2, 3}}
	pendingFingerprint = "0102030000000000000000000000000000000000000000000000000000000000"
	a, err := New(Options{Config: cfg, Version: "1.2.3", Client: client, Scanner: sc, Store: store,
		Logger: slog.New(slog.DiscardHandler), IngestionWait: 5 * time.Second, IngestionPoll: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{srv: fs, scanner: sc, agent: a, dir: dir}
}

// TestUnchangedScanSendsOnce : deux scans sans changement donnent un seul envoi, puis un
// signal de vie qui confirme l'inventaire ; un inventaire changé repart en envoi.
func TestUnchangedScanSendsOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res, err := h.agent.Cycle(ctx)
	if err != nil || res.Outcome != OutcomeSent {
		t.Fatalf("premier cycle : %+v %v", res, err)
	}
	if h.srv.enrollments != 1 || h.srv.uploads != 1 {
		t.Fatalf("%d inscriptions, %d envois", h.srv.enrollments, h.srv.uploads)
	}
	c := h.srv.lastContext
	if c.Ref.Kind != gen.IngestionContextRefKindHost || c.Ref.Name != "srv-test" || c.Commit != nil || c.AgentVersion != "1.2.3" ||
		c.Host == nil || *c.Host.OsId != "debian" || *c.Host.Hostname != "srv-test" || *c.Host.ScanDurationMs != 1000 {
		t.Errorf("contexte de l'envoi %+v", c)
	}
	res, err = h.agent.Cycle(ctx)
	if err != nil || res.Outcome != OutcomeConfirmed {
		t.Fatalf("second cycle : %+v %v", res, err)
	}
	if h.srv.uploads != 1 || len(h.srv.heartbeats) != 1 || h.srv.heartbeats[0].Inventory == nil || h.srv.heartbeats[0].Host == nil {
		t.Fatalf("%d envois, signaux %+v", h.srv.uploads, h.srv.heartbeats)
	}
	if h.srv.enrollments != 1 {
		t.Error("réinscription alors que le jeton est gardé")
	}
	// Le serveur ne connaît plus cet inventaire (base restaurée) : il réclame le SBOM.
	h.srv.current = "autre"
	if res, err = h.agent.Cycle(ctx); err != nil || res.Outcome != OutcomeSent || h.srv.uploads != 2 {
		t.Fatalf("inventaire réclamé : %+v %v (%d envois)", res, err, h.srv.uploads)
	}
	h.scanner.fp = [32]byte{9}
	pendingFingerprint = "0900000000000000000000000000000000000000000000000000000000000000"
	if res, err = h.agent.Cycle(ctx); err != nil || res.Outcome != OutcomeSent || h.srv.uploads != 3 {
		t.Fatalf("inventaire changé : %+v %v", res, err)
	}
	// Un nouvel agent sur le même répertoire d'état reprend son jeton.
	again, err := New(Options{Config: h.agent.o.Config, Version: "1.2.3", Client: h.agent.o.Client, Scanner: h.scanner,
		Store: h.agent.o.Store, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := again.Cycle(ctx); err != nil || res.Outcome != OutcomeConfirmed || h.srv.enrollments != 1 {
		t.Fatalf("après redémarrage : %+v %v", res, err)
	}
}

// TestRefusedIngestionIsRetried : un SBOM refusé n'est pas retenu, le cycle suivant le
// renvoie.
func TestRefusedIngestionIsRetried(t *testing.T) {
	h := newHarness(t)
	h.srv.failNext = true
	if _, err := h.agent.Cycle(context.Background()); err == nil || !strings.Contains(err.Error(), "error.ingest.schema_invalid") {
		t.Fatalf("ingestion refusée : %v", err)
	}
	if res, err := h.agent.Cycle(context.Background()); err != nil || res.Outcome != OutcomeSent || h.srv.uploads != 2 {
		t.Fatalf("renvoi : %+v %v (%d envois)", res, err, h.srv.uploads)
	}
}

func TestCycleErrors(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.EnrollmentTokenFile = "/inexistant" })
	if _, err := h.agent.Cycle(context.Background()); !errors.Is(err, ErrNotEnrolled) || !fatal(err) {
		t.Errorf("sans jeton : %v", err)
	}
	h = newHarness(t)
	h.srv.noProject = true
	if _, err := h.agent.Cycle(context.Background()); !errors.Is(err, ErrNoHostProject) {
		t.Errorf("sans projet : %v", err)
	}
	h.srv.noProject = false
	h.scanner.err = errors.New("disque illisible")
	if _, err := h.agent.Cycle(context.Background()); err == nil || h.srv.uploads != 0 {
		t.Errorf("scan en échec : %v", err)
	}
	// Jeton d'agent refusé par le serveur.
	if err := h.agent.o.Store.SaveToken("lotor_agt_revoque"); err != nil {
		t.Fatal(err)
	}
	h.agent.client = nil
	if _, err := h.agent.Heartbeat(context.Background()); !fatal(err) || !agentclient.IsKey(err, agentclient.KeyTokenInvalid) {
		t.Errorf("jeton refusé : %v", err)
	}
}

// fakeClock avance quand le démon dort.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// TestDaemonScansOnRequest : le démon scanne au démarrage, envoie des signaux de vie
// entre deux scans, scanne dès qu'un scan est demandé, puis à l'échéance de l'intervalle.
func TestDaemonScansOnRequest(t *testing.T) {
	h := newHarness(t)
	clock := &fakeClock{now: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sleeps := 0
	h.agent.o.Now = clock.Now
	h.agent.o.Sleep = func(ctx context.Context, d time.Duration) error {
		clock.mu.Lock()
		clock.now = clock.now.Add(d)
		clock.mu.Unlock()
		sleeps++
		switch sleeps {
		case 3:
			h.srv.mu.Lock()
			h.srv.scanPending = true // « Scanner maintenant » dans l'interface
			h.srv.mu.Unlock()
		case 400:
			cancel()
		}
		return ctx.Err()
	}
	if err := h.agent.Run(ctx); err != nil {
		t.Fatal(err)
	}
	// 1 scan au démarrage, 1 sur demande, puis un par intervalle de 24 h : 400 attentes
	// de 5 min environ couvrent un peu plus d'une journée.
	if h.scanner.scans < 3 || h.scanner.scans > 4 {
		t.Errorf("%d scans", h.scanner.scans)
	}
	if h.srv.uploads != 1 {
		t.Errorf("%d envois, 1 attendu (inventaire inchangé)", h.srv.uploads)
	}
	plain := 0
	for _, hb := range h.srv.heartbeats {
		if hb.Inventory == nil {
			plain++
		}
	}
	if plain < 300 {
		t.Errorf("%d signaux de vie simples", plain)
	}
}

func TestJitter(t *testing.T) {
	for range 50 {
		if d := jitter(time.Minute); d < 54*time.Second || d > 66*time.Second {
			t.Fatalf("gigue %v", d)
		}
	}
	if jitter(5) != 5 {
		t.Error("durée minuscule")
	}
}
