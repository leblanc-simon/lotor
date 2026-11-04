package offline

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func sample(t *testing.T) ([]byte, [32]byte) {
	t.Helper()
	_, pub, key, err := NewAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{AgentToken: pub, CreatedAt: time.Now().UTC(), Context: Context{ProjectID: uuid.New(),
		Ref: Ref{Kind: "host", Name: "srv"}, AgentVersion: "1", ScannedAt: time.Now().UTC()}}
	var buf bytes.Buffer
	if err := Write(&buf, m, Keys{Agent: key}, []byte("sbom-gz")); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), key
}

func TestRoundTrip(t *testing.T) {
	data, key := sample(t)
	a, err := Read(bytes.NewReader(data), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.SBOM) != "sbom-gz" || !Verify(key[:], a.RawManifest, a.MAC.Agent) || a.Digest() != sha256.Sum256(a.RawManifest) {
		t.Fatalf("archive relue %+v", a.Manifest)
	}
	var other [32]byte
	if Verify(other[:], a.RawManifest, a.MAC.Agent) || Verify(key[:], append(a.RawManifest, ' '), a.MAC.Agent) || Verify(key[:16], a.RawManifest, a.MAC.Agent) {
		t.Error("code vérifié avec une autre clé ou un autre manifeste")
	}
	// Inscription et clé d'inscription vont ensemble.
	if err := Write(&bytes.Buffer{}, Manifest{Enrollment: &Enrollment{}}, Keys{Agent: key}, nil); err == nil {
		t.Error("inscription sans clé acceptée")
	}
}

// entries réécrit une archive avec d'autres entrées.
func entries(t *testing.T, files ...[2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f[0], Mode: 0o600, Size: int64(len(f[1])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestReadRefusals(t *testing.T) {
	data, _ := sample(t)
	a, err := Read(bytes.NewReader(data), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	man, mac := string(a.RawManifest), `{"agent":"`+a.MAC.Agent+`"}`
	cases := map[string][]byte{
		"vide":            nil,
		"pas un tar":      []byte("bonjour"),
		"ordre":           entries(t, [2]string{"mac.json", mac}, [2]string{"manifest.json", man}, [2]string{"sbom.json.gz", "sbom-gz"}),
		"SBOM modifié":    entries(t, [2]string{"manifest.json", man}, [2]string{"mac.json", mac}, [2]string{"sbom.json.gz", "sbom-gZ"}),
		"entrée en trop":  entries(t, [2]string{"manifest.json", man}, [2]string{"mac.json", mac}, [2]string{"sbom.json.gz", "sbom-gz"}, [2]string{"x", "y"}),
		"champ inconnu":   entries(t, [2]string{"manifest.json", strings.Replace(man, `{"format"`, `{"x":1,"format"`, 1)}, [2]string{"mac.json", mac}, [2]string{"sbom.json.gz", "sbom-gz"}),
		"autre format":    entries(t, [2]string{"manifest.json", strings.Replace(man, Format, "lotor-archive/9", 1)}, [2]string{"mac.json", mac}, [2]string{"sbom.json.gz", "sbom-gz"}),
		"sans code":       entries(t, [2]string{"manifest.json", man}, [2]string{"mac.json", `{}`}, [2]string{"sbom.json.gz", "sbom-gz"}),
		"jeton illisible": entries(t, [2]string{"manifest.json", strings.Replace(man, a.Manifest.AgentToken, "x", 1)}, [2]string{"mac.json", mac}, [2]string{"sbom.json.gz", "sbom-gz"}),
	}
	for name, raw := range cases {
		if _, err := Read(bytes.NewReader(raw), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s : %v", name, err)
		}
	}
	// SBOM au-delà de la borne.
	if _, err := Read(bytes.NewReader(data), 3); !errors.Is(err, ErrMalformed) {
		t.Errorf("SBOM trop gros : %v", err)
	}
}

func TestFileName(t *testing.T) {
	at := time.Date(2026, 11, 4, 18, 30, 5, 0, time.UTC)
	if got := FileName("SRV/01 ü", at, "0123456789abcdef"); got != "lotor-srv_01__-20261104T183005Z-01234567.lotor" {
		t.Errorf("%s", got)
	}
	if got := FileName("", at, ""); got != "lotor-agent-20261104T183005Z-.lotor" {
		t.Errorf("%s", got)
	}
}
