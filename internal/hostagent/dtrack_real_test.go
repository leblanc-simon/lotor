//go:build dtrack

package hostagent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"leblanc.io/lotor/internal/agentclient"
)

// Recette contre un vrai Dependency-Track 5 (make test-dtrack, hors CI) :
// LOTOR_TEST_DTRACK_URL (adresse de base, http accepté : un mandataire TLS de test est
// interposé, l'agent ne parlant qu'en HTTPS) et LOTOR_TEST_DTRACK_API_KEY_FILE (clé d'une
// équipe qui a BOM_UPLOAD, PROJECT_CREATION_UPLOAD et VIEW_PORTFOLIO). L'agent scanne
// testdata/rootfs en sortie seule vers Dependency-Track ; le projet créé doit porter des
// composants une fois le traitement terminé.
func TestRealDependencyTrack(t *testing.T) {
	base := os.Getenv("LOTOR_TEST_DTRACK_URL")
	keyFile := os.Getenv("LOTOR_TEST_DTRACK_API_KEY_FILE")
	if base == "" || keyFile == "" {
		t.Skip("LOTOR_TEST_DTRACK_URL et LOTOR_TEST_DTRACK_API_KEY_FILE absents")
	}
	key, err := readSecret(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(target))
	defer proxy.Close()
	dt, err := agentclient.NewDT(agentclient.DTOptions{URL: proxy.URL, APIKey: key, Transport: proxy.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := validConfig()
	cfg.Server.URL, cfg.StateDir, cfg.Hostname = "", filepath.Join(dir, "etat"), "lotor-recette-"+time.Now().UTC().Format("20060102-150405")
	cfg.DependencyTrack = DependencyTrack{URL: proxy.URL, ProjectVersion: "host", AutoCreate: true, Only: true}
	store, err := OpenStore(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	sc := testScanner(t)
	a, err := New(Options{Config: cfg, Version: "recette", DT: DTSenderOf(dt), Scanner: sc, Store: store,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)), IngestionWait: 5 * time.Minute, IngestionPoll: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Cycle(context.Background())
	if err != nil || res.Outcome != OutcomeSent {
		t.Fatalf("cycle : %+v %v", res, err)
	}
	// Le projet existe et porte les composants de l'hôte.
	get := func(path string, out any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		req.Header.Set("X-Api-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || json.Unmarshal(data, out) != nil {
			t.Fatalf("%s : %d %s", path, resp.StatusCode, data)
		}
	}
	var p struct {
		UUID string `json:"uuid"`
	}
	get("/api/v1/project/lookup?name="+url.QueryEscape(cfg.Hostname)+"&version=host", &p)
	var comps []struct {
		Name string `json:"name"`
		PURL string `json:"purl"`
	}
	get("/api/v1/component/project/"+p.UUID+"?pageSize=500", &comps)
	if len(comps) == 0 || len(comps) < res.Components/2 {
		t.Fatalf("%d composants dans Dependency-Track pour %d inventoriés", len(comps), res.Components)
	}
	t.Logf("projet %s (%s) : %d composants dans Dependency-Track, %d inventoriés", cfg.Hostname, p.UUID, len(comps), res.Components)
}
