package hostagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/sbom"
	sbomsyft "leblanc.io/lotor/internal/sbom/syft"
)

// fakeDT imite les deux routes de Dependency-Track qu'emploie l'agent, aux formats
// relevés sur Dependency-Track 5.2.1 (BomSubmitRequest, BomUploadResponse,
// IsTokenBeingProcessedResponse).
type fakeDT struct {
	mu      sync.Mutex
	uploads []map[string]any
	boms    [][]byte
	polls   int
	fail    bool
}

func (f *fakeDT) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-Api-Key") != "odt_cle" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPut && r.URL.Path == "/api/v1/bom":
		if f.fail {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"status":400,"title":"The uploaded BOM is invalid"}`))
			return
		}
		var body map[string]any
		if r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		bom, err := base64.StdEncoding.DecodeString(body["bom"].(string))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.uploads, f.boms = append(f.uploads, body), append(f.boms, bom)
		_, _ = w.Write([]byte(`{"token":"` + uuid.NewString() + `","projectUuid":"` + uuid.NewString() + `"}`))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/event/token/"):
		f.polls++
		// Une interrogation « en cours », puis terminé.
		_, _ = w.Write([]byte(`{"processing":` + map[bool]string{true: "true", false: "false"}[f.polls%2 == 1] + `}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// syftScanner renvoie un vrai SBOM Syft JSON (alpine), d'empreinte réglable.
type syftScanner struct {
	data []byte
	fp   [32]byte
}

func (s *syftScanner) Scan(context.Context) (Inventory, error) {
	return Inventory{SBOM: s.data, Fingerprint: s.fp, Components: 14, Started: time.Now().UTC()}, nil
}

func newDTHarness(t *testing.T, only bool) (*harness, *fakeDT, *syftScanner) {
	t.Helper()
	h := newHarness(t)
	dt := &fakeDT{}
	srv := httptest.NewTLSServer(dt)
	t.Cleanup(srv.Close)
	c, err := agentclient.NewDT(agentclient.DTOptions{URL: srv.URL, APIKey: "odt_cle", Transport: srv.Client().Transport,
		Retry: agentclient.Retry{Attempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../testdata/sbom/alpine-3.20.syft.json")
	if err != nil {
		t.Fatal(err)
	}
	sc := &syftScanner{data: data, fp: [32]byte{1, 2, 3}}
	cfg := h.agent.o.Config
	cfg.DependencyTrack = DependencyTrack{URL: srv.URL, ProjectVersion: "host", AutoCreate: true, Only: only}
	o := h.agent.o
	o.Config, o.Scanner, o.DT = cfg, sc, DTSenderOf(c)
	if only {
		o.Client = nil
	}
	if h.agent, err = New(o); err != nil {
		t.Fatal(err)
	}
	return h, dt, sc
}

// En plus de lotor : le SBOM part en CycloneDX 1.6 vers Dependency-Track au premier cycle,
// pas au suivant (inventaire inchangé), de nouveau quand il change ; un échec de
// Dependency-Track ne fait pas échouer le cycle et l'envoi est retenté.
func TestDependencyTrackAlso(t *testing.T) {
	h, dt, sc := newDTHarness(t, false)
	ctx := context.Background()
	res, err := h.agent.Cycle(ctx)
	if err != nil || res.Outcome != OutcomeSent || !res.DTSent || h.srv.uploads != 1 || len(dt.uploads) != 1 {
		t.Fatalf("premier cycle : %+v %v (%d, %d envois)", res, err, h.srv.uploads, len(dt.uploads))
	}
	u := dt.uploads[0]
	if u["projectName"] != "srv-test" || u["projectVersion"] != "host" || u["autoCreate"] != true {
		t.Errorf("cible %+v", u)
	}
	doc, err := sbomsyft.Decode(sbom.FormatCycloneDX, dt.boms[0])
	var head struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}
	_ = json.Unmarshal(dt.boms[0], &head)
	if err != nil || len(doc.Components) == 0 || head.BOMFormat != "CycloneDX" || head.SpecVersion != "1.6" {
		t.Fatalf("SBOM CycloneDX : %d composants, %v", len(doc.Components), err)
	}
	if dt.polls < 2 {
		t.Errorf("suivi du traitement : %d interrogations", dt.polls)
	}
	if res, err = h.agent.Cycle(ctx); err != nil || res.Outcome != OutcomeConfirmed || res.DTSent || len(dt.uploads) != 1 {
		t.Fatalf("inventaire inchangé : %+v %v", res, err)
	}
	// Dependency-Track refuse : le cycle réussit quand même, et l'envoi est retenté.
	sc.fp = [32]byte{9}
	pendingFingerprint = "0900000000000000000000000000000000000000000000000000000000000000"
	dt.fail = true
	if res, err = h.agent.Cycle(ctx); err != nil || res.Outcome != OutcomeSent || res.DTSent {
		t.Fatalf("Dependency-Track en échec : %+v %v", res, err)
	}
	dt.fail = false
	if res, err = h.agent.Cycle(ctx); err != nil || !res.DTSent || len(dt.uploads) != 2 {
		t.Fatalf("envoi retenté : %+v %v", res, err)
	}
}

// À la place de lotor : ni inscription ni signal de vie, envoi seulement quand
// l'inventaire change ; le démon ne fait aucun signal de vie.
func TestDependencyTrackOnly(t *testing.T) {
	h, dt, sc := newDTHarness(t, true)
	ctx := context.Background()
	if res, err := h.agent.Cycle(ctx); err != nil || res.Outcome != OutcomeSent || len(dt.uploads) != 1 {
		t.Fatalf("premier cycle : %+v %v", res, err)
	}
	if res, err := h.agent.Cycle(ctx); err != nil || res.Outcome != OutcomeUnchanged || len(dt.uploads) != 1 {
		t.Fatalf("inventaire inchangé : %+v %v", res, err)
	}
	sc.fp = [32]byte{7}
	if res, err := h.agent.Cycle(ctx); err != nil || res.Outcome != OutcomeSent || len(dt.uploads) != 2 {
		t.Fatalf("inventaire changé : %+v %v", res, err)
	}
	if h.srv.enrollments != 0 || h.srv.uploads != 0 || len(h.srv.heartbeats) != 0 {
		t.Errorf("serveur lotor contacté : %d inscriptions, %d envois, %d signaux", h.srv.enrollments, h.srv.uploads, len(h.srv.heartbeats))
	}
	// Le démon : un cycle, puis des attentes sans signal de vie.
	cctx, cancel := context.WithCancel(ctx)
	sleeps := 0
	h.agent.o.Sleep = func(context.Context, time.Duration) error {
		if sleeps++; sleeps > 3 {
			cancel()
			return context.Canceled
		}
		return nil
	}
	if err := h.agent.Run(cctx); err != nil {
		t.Fatal(err)
	}
	if len(h.srv.heartbeats) != 0 {
		t.Errorf("%d signaux de vie en sortie seule", len(h.srv.heartbeats))
	}
	if _, err := New(Options{Config: h.agent.o.Config, Scanner: sc, Store: h.agent.o.Store, Logger: slog.New(slog.DiscardHandler)}); err == nil {
		t.Error("sortie seule sans client de Dependency-Track acceptée")
	}
}

func TestDependencyTrackConfig(t *testing.T) {
	c := validConfig()
	c.Server.URL = ""
	c.DependencyTrack = DependencyTrack{URL: "https://dtrack.example.org", ProjectVersion: "host", Only: true}
	if err := c.Validate(); err != nil {
		t.Errorf("sortie seule sans serveur : %v", err)
	}
	c.DependencyTrack.Only = false
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "server.url") {
		t.Errorf("sans serveur ni sortie seule : %v", err)
	}
	c = validConfig()
	for name, d := range map[string]DependencyTrack{
		"adresse http":       {URL: "http://dtrack", ProjectVersion: "host"},
		"version vide":       {URL: "https://dtrack", ProjectVersion: " "},
		"clé relative":       {URL: "https://dtrack", ProjectVersion: "host", APIKeyFile: "cle"},
		"seule sans adresse": {Only: true, ProjectVersion: "host"},
	} {
		c.DependencyTrack = d
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "dependency_track") {
			t.Errorf("%s : %v", name, err)
		}
	}
	c.DependencyTrack = DependencyTrack{URL: "https://dtrack", ProjectVersion: "host", Only: true}
	c.Containers.Enabled = true
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "containers.enabled") {
		t.Errorf("conteneurs en sortie seule : %v", err)
	}
}
