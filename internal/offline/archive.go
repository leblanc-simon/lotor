package offline

import (
	"archive/tar"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Format est la version du format d'archive.
const Format = "lotor-archive/1"

// Extension est l'extension des fichiers d'archive.
const Extension = ".lotor"

// Noms des entrées, dans cet ordre.
const (
	entryManifest = "manifest.json"
	entryMAC      = "mac.json"
	entrySBOM     = "sbom.json.gz"
)

// Bornes de lecture.
const (
	maxManifest = 64 << 10
	maxMAC      = 4 << 10
)

// ErrMalformed : l'archive n'a pas le format attendu (entrées, ordre, tailles, empreinte).
var ErrMalformed = errors.New("offline: archive illisible")

// Ref est la référence visée par l'envoi.
type Ref struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Host est le contexte de l'hôte, comme dans un envoi réseau.
type Host struct {
	Hostname       string `json:"hostname,omitempty"`
	OSID           string `json:"os_id,omitempty"`
	OSVersion      string `json:"os_version,omitempty"`
	OSName         string `json:"os_name,omitempty"`
	Kernel         string `json:"kernel,omitempty"`
	Arch           string `json:"arch,omitempty"`
	ScanDurationMs int64  `json:"scan_duration_ms,omitempty"`
}

// Context est le contexte d'un envoi. ProjectID est vide pour une archive d'inscription :
// le projet de l'hôte est alors celui que crée ou rattache l'inscription.
type Context struct {
	ProjectID    uuid.UUID `json:"project_id,omitzero"`
	Ref          Ref       `json:"ref"`
	Commit       string    `json:"commit,omitempty"`
	AgentVersion string    `json:"agent_version"`
	ScannedAt    time.Time `json:"scanned_at"`
	Host         *Host     `json:"host,omitempty"`
}

// Enrollment est l'inscription hors ligne d'un agent serveur jamais connecté au serveur :
// le jeton d'inscription qu'il détient (identifiant public), et l'identifiant public et
// l'empreinte du jeton d'agent qu'il a tiré lui-même. À l'import, le serveur l'inscrit avec
// ce jeton ; l'agent en connaît le secret et pourra s'en servir en ligne.
type Enrollment struct {
	TokenID   string            `json:"token_id"`
	Hostname  string            `json:"hostname"`
	Version   string            `json:"version"`
	Labels    map[string]string `json:"labels,omitempty"`
	AgentHash string            `json:"agent_token_hash"`
}

// SBOMEntry décrit le SBOM de l'archive.
type SBOMEntry struct {
	// SHA256 est l'empreinte du fichier compressé (sbom.json.gz), en hexadécimal.
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest est le manifeste d'une archive.
type Manifest struct {
	Format string `json:"format"`
	// AgentToken est l'identifiant public du jeton d'agent émetteur.
	AgentToken string      `json:"agent_token"`
	Enrollment *Enrollment `json:"enrollment,omitempty"`
	Context    Context     `json:"context"`
	SBOM       SBOMEntry   `json:"sbom"`
	CreatedAt  time.Time   `json:"created_at"`
}

// MAC porte les codes d'authentification du manifeste : HMAC-SHA256 dont la clé est
// l'empreinte SHA-256 du secret d'un jeton (celle que le serveur garde), si bien que le
// serveur vérifie l'origine sans stocker de nouveau secret, et qu'une archive ne révèle
// pas la clé. Agent : jeton d'agent ; Enrollment : jeton d'inscription (archive
// d'inscription).
type MAC struct {
	Agent      string `json:"agent"`
	Enrollment string `json:"enrollment,omitempty"`
}

// Sign calcule le code d'un manifeste avec la clé key (empreinte d'un secret).
func Sign(key [32]byte, manifest []byte) string {
	m := hmac.New(sha256.New, key[:])
	m.Write(manifest)
	return hex.EncodeToString(m.Sum(nil))
}

// Verify compare en temps constant le code mac à celui de manifest pour la clé key.
func Verify(key []byte, manifest []byte, mac string) bool {
	got, err := hex.DecodeString(mac)
	if err != nil || len(key) != sha256.Size {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write(manifest)
	return hmac.Equal(got, m.Sum(nil))
}

// Keys sont les clés de signature d'une archive : l'empreinte du secret du jeton d'agent,
// et, pour une archive d'inscription, celle du secret du jeton d'inscription.
type Keys struct {
	Agent      [32]byte
	Enrollment *[32]byte
}

// Write écrit une archive : manifeste (complété de l'empreinte et de la taille du SBOM),
// codes, puis le SBOM compressé en gzip. Le manifeste est écrit tel qu'il est signé.
func Write(w io.Writer, m Manifest, keys Keys, sbomGz []byte) error {
	m.Format = Format
	sum := sha256.Sum256(sbomGz)
	m.SBOM = SBOMEntry{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(sbomGz))}
	if (m.Enrollment != nil) != (keys.Enrollment != nil) {
		return errors.New("offline: inscription et clé d'inscription vont ensemble")
	}
	manifest, err := json.Marshal(m)
	if err != nil {
		return err
	}
	mac := MAC{Agent: Sign(keys.Agent, manifest)}
	if keys.Enrollment != nil {
		mac.Enrollment = Sign(*keys.Enrollment, manifest)
	}
	macJSON, err := json.Marshal(mac)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	for _, e := range []struct {
		name string
		data []byte
	}{{entryManifest, manifest}, {entryMAC, macJSON}, {entrySBOM, sbomGz}} {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), ModTime: m.CreatedAt,
			Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return err
		}
		if _, err := tw.Write(e.data); err != nil {
			return err
		}
	}
	return tw.Close()
}

// Archive est une archive lue, pas encore authentifiée : Manifest est le manifeste décodé,
// RawManifest ses octets signés.
type Archive struct {
	Manifest    Manifest
	RawManifest []byte
	MAC         MAC
	SBOM        []byte // gzip
}

// Digest est l'empreinte de l'archive : SHA-256 du manifeste signé, qui couvre le SBOM.
// Deux imports de la même archive ont la même empreinte.
func (a Archive) Digest() [32]byte { return sha256.Sum256(a.RawManifest) }

var tokenIDPattern = regexp.MustCompile(`^[a-z2-7]{26}$`)

// Read lit une archive, entrées dans l'ordre, chacune bornée (maxSBOM pour le SBOM
// compressé), et vérifie l'empreinte du SBOM. L'authenticité (codes) se vérifie ensuite,
// avec les clés que seul le serveur connaît.
func Read(r io.Reader, maxSBOM int64) (Archive, error) {
	tr := tar.NewReader(r)
	var a Archive
	read := func(name string, max int64) ([]byte, error) {
		h, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("%w : entrée %s : %w", ErrMalformed, name, err)
		}
		if h.Name != name || h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > max {
			return nil, fmt.Errorf("%w : entrée %q inattendue", ErrMalformed, h.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, max+1))
		if err != nil {
			return nil, fmt.Errorf("%w : entrée %s : %w", ErrMalformed, name, err)
		}
		if int64(len(data)) != h.Size {
			return nil, fmt.Errorf("%w : entrée %s tronquée", ErrMalformed, name)
		}
		return data, nil
	}
	var err error
	if a.RawManifest, err = read(entryManifest, maxManifest); err != nil {
		return Archive{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(a.RawManifest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a.Manifest); err != nil || a.Manifest.Format != Format {
		return Archive{}, fmt.Errorf("%w : manifeste", ErrMalformed)
	}
	if !tokenIDPattern.MatchString(a.Manifest.AgentToken) ||
		(a.Manifest.Enrollment != nil && !tokenIDPattern.MatchString(a.Manifest.Enrollment.TokenID)) {
		return Archive{}, fmt.Errorf("%w : identifiant de jeton", ErrMalformed)
	}
	macJSON, err := read(entryMAC, maxMAC)
	if err != nil {
		return Archive{}, err
	}
	if err := json.Unmarshal(macJSON, &a.MAC); err != nil || a.MAC.Agent == "" {
		return Archive{}, fmt.Errorf("%w : codes", ErrMalformed)
	}
	if a.SBOM, err = read(entrySBOM, maxSBOM); err != nil {
		return Archive{}, err
	}
	sum := sha256.Sum256(a.SBOM)
	if hex.EncodeToString(sum[:]) != a.Manifest.SBOM.SHA256 || int64(len(a.SBOM)) != a.Manifest.SBOM.Size {
		return Archive{}, fmt.Errorf("%w : empreinte du SBOM", ErrMalformed)
	}
	if _, err := tr.Next(); !errors.Is(err, io.EOF) {
		return Archive{}, fmt.Errorf("%w : entrée en trop", ErrMalformed)
	}
	return a, nil
}

// FileName renvoie le nom horodaté d'une archive :
// lotor-<hôte>-<AAAAMMJJThhmmssZ>-<8 premiers caractères de l'empreinte>.lotor ; deux
// inventaires écrits dans la même seconde ne s'écrasent pas.
func FileName(host string, at time.Time, fingerprint string) string {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		}
		return '_'
	}, host)
	if clean == "" {
		clean = "agent"
	}
	if len(fingerprint) > 8 {
		fingerprint = fingerprint[:8]
	}
	return "lotor-" + clean + "-" + at.UTC().Format("20060102T150405Z") + "-" + fingerprint + Extension
}
