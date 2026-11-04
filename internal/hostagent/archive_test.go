package hostagent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/offline"
)

func archives(t *testing.T, dir string) []offline.Archive {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []offline.Archive
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") || !strings.HasSuffix(e.Name(), offline.Extension) {
			continue
		}
		info, _ := e.Info()
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s en %v", e.Name(), info.Mode().Perm())
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		a, err := offline.Read(f, 1<<20)
		f.Close()
		if err != nil {
			t.Fatalf("%s : %v", e.Name(), err)
		}
		out = append(out, a)
	}
	return out
}

// Sortie seule hors ligne, agent jamais inscrit : le jeton d'agent est tiré et gardé, la
// première archive porte l'inscription signée par le jeton d'inscription et le code du
// jeton d'agent ; un inventaire inchangé n'écrit rien ; aucun appel au serveur.
func TestOfflineOnly(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Server.URL = "" })
	// Répertoire absent : l'agent le crée (0700), comme sous le répertoire d'état de
	// l'unité systemd.
	dir := filepath.Join(h.dir, "archives")
	raw, _, _, err := offline.NewAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	enrollment := "lotor_enr_" + strings.TrimPrefix(raw, "lotor_agt_")
	o := h.agent.o
	if err := os.WriteFile(o.Config.EnrollmentTokenFile, []byte(enrollment+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o.Config.Offline = Offline{Dir: dir, Only: true}
	o.Client = nil
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := a.Cycle(ctx)
	if err != nil || res.Outcome != OutcomeArchived || res.Archive == "" {
		t.Fatalf("premier cycle : %+v %v", res, err)
	}
	if res, err = a.Cycle(ctx); err != nil || res.Outcome != OutcomeUnchanged {
		t.Fatalf("inventaire inchangé : %+v %v", res, err)
	}
	h.scanner.fp = [32]byte{4}
	if res, err = a.Cycle(ctx); err != nil || res.Outcome != OutcomeArchived {
		t.Fatalf("inventaire changé : %+v %v", res, err)
	}
	got := archives(t, dir)
	if len(got) != 2 {
		t.Fatalf("%d archives", len(got))
	}
	tok, err := o.Store.Token()
	if err != nil {
		t.Fatal(err)
	}
	pub, agentKey, err := offline.ParseToken("agt", tok)
	if err != nil {
		t.Fatal(err)
	}
	enrID, enrKey, err := offline.ParseToken("enr", enrollment)
	if err != nil {
		t.Fatal(err)
	}
	for _, ar := range got {
		m := ar.Manifest
		if m.AgentToken != pub || m.Enrollment == nil || m.Enrollment.Hostname != "SRV-Test" || m.Enrollment.AgentHash != hex.EncodeToString(agentKey[:]) ||
			m.Context.Ref.Kind != "host" || m.Context.Ref.Name != "srv-test" || m.Context.Host == nil || m.Context.Host.OSID != "debian" {
			t.Errorf("manifeste %+v", m)
		}
		if !offline.Verify(agentKey[:], ar.RawManifest, ar.MAC.Agent) {
			t.Error("code du jeton d'agent invalide")
		}
		if m.Enrollment.TokenID != enrID || !offline.Verify(enrKey[:], ar.RawManifest, ar.MAC.Enrollment) {
			t.Error("inscription mal signée")
		}
		zr, err := gzip.NewReader(bytes.NewReader(ar.SBOM))
		if err != nil {
			t.Fatal(err)
		}
		if raw, _ := io.ReadAll(zr); string(raw) != `{"artifacts":[]}` {
			t.Errorf("SBOM %q", raw)
		}
	}
	if h.srv.enrollments != 0 || h.srv.uploads != 0 || len(h.srv.heartbeats) != 0 {
		t.Error("serveur contacté en sortie seule hors ligne")
	}
	if _, err := New(Options{Config: o.Config, Scanner: h.scanner, Store: o.Store, Logger: slog.New(slog.DiscardHandler)}); err != nil {
		t.Errorf("sortie seule sans client : %v", err)
	}
}

// En plus du réseau : l'archive porte le projet et la référence connus du serveur, sans
// inscription, après un envoi réussi.
func TestOfflineAlso(t *testing.T) {
	h := newHarness(t)
	raw, _, _, err := offline.NewAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	h.srv.token = raw
	dir := filepath.Join(h.dir, "archives")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	o := h.agent.o
	o.Config.Offline = Offline{Dir: dir}
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Cycle(context.Background())
	if err != nil || res.Outcome != OutcomeSent || res.Archive == "" || h.srv.uploads != 1 {
		t.Fatalf("cycle : %+v %v", res, err)
	}
	got := archives(t, dir)
	if len(got) != 1 || got[0].Manifest.Enrollment != nil || got[0].Manifest.Context.ProjectID != h.srv.projectID {
		t.Fatalf("archive %+v", got)
	}
	if sum := sha256.Sum256(got[0].RawManifest); sum != got[0].Digest() {
		t.Error("empreinte de l'archive")
	}
}

func TestOfflineConfig(t *testing.T) {
	c := validConfig()
	c.Server.URL = ""
	c.Offline = Offline{Dir: "/var/lib/lotor-host-agent/archives", Only: true}
	if err := c.Validate(); err != nil {
		t.Errorf("sortie seule : %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"sans répertoire": func(c *Config) { c.Offline.Dir = "" },
		"chemin relatif":  func(c *Config) { c.Offline.Dir = "archives" },
		"deux sorties seules": func(c *Config) {
			c.DependencyTrack = DependencyTrack{URL: "https://dtrack", ProjectVersion: "host", Only: true}
		},
		"conteneurs": func(c *Config) { c.Containers.Enabled = true },
	} {
		cc := c
		mutate(&cc)
		if err := cc.Validate(); err == nil {
			t.Errorf("%s accepté", name)
		}
	}
}
