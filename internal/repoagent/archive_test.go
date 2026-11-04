package repoagent

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/forge"
	"leblanc.io/lotor/internal/offline"
)

// L'archive d'un envoi de l'agent dépôt porte le projet, la référence et le commit, le
// SBOM tel qu'envoyé, et un code vérifiable avec l'empreinte du jeton.
func TestArchiveWriter(t *testing.T) {
	raw, pub, key, err := offline.NewAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "archives")
	w, err := NewArchiveWriter(dir, raw)
	if err != nil {
		t.Fatal(err)
	}
	pid := uuid.New()
	commit := "0123456789abcdef0123456789abcdef01234567"
	u := Upload{ProjectID: pid.String(), Ref: forge.Ref{Kind: forge.RefBranch, Name: "main"}, Commit: commit, AgentVersion: "0.3.0",
		ScannedAt: time.Now().UTC().Round(time.Second), SBOM: []byte(`{"bomFormat":"CycloneDX"}`)}
	path, err := w.Write(u, "portail")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != dir || filepath.Ext(path) != offline.Extension {
		t.Errorf("chemin %s", path)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("droits : %v %v", info, err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	a, err := offline.Read(f, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	m := a.Manifest
	if m.AgentToken != pub || m.Context.ProjectID != pid || m.Context.Ref != (offline.Ref{Kind: "branch", Name: "main"}) ||
		m.Context.Commit != commit || !m.Context.ScannedAt.Equal(u.ScannedAt) || m.Enrollment != nil {
		t.Errorf("manifeste %+v", m)
	}
	if !offline.Verify(key[:], a.RawManifest, a.MAC.Agent) {
		t.Error("code invalide")
	}
	zr, err := gzip.NewReader(bytes.NewReader(a.SBOM))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(zr); !bytes.Equal(got, u.SBOM) {
		t.Errorf("SBOM %q", got)
	}
	if _, err := NewArchiveWriter("relatif", raw); err == nil {
		t.Error("chemin relatif accepté")
	}
	if _, err := NewArchiveWriter(dir, "lotor_agt_x"); err == nil {
		t.Error("jeton illisible accepté")
	}
}
