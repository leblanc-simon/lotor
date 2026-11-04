package hostagent

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// Fichiers du répertoire d'état.
const (
	tokenFile = "agent-token"
	stateFile = "state.json"
)

// stateVersion versionne state.json : un état d'une autre version est ignoré (l'agent
// renvoie alors simplement son SBOM).
const stateVersion = 1

// State est ce que l'agent garde entre deux cycles, hors jeton : son identité et
// l'empreinte du dernier inventaire que le serveur a rangé ou confirmé.
type State struct {
	Version   int       `json:"version"`
	AgentID   uuid.UUID `json:"agent_id,omitzero"`
	ProjectID uuid.UUID `json:"project_id,omitzero"`
	// RefName est la référence d'hôte de Fingerprint.
	RefName string `json:"ref_name,omitempty"`
	// Fingerprint est l'empreinte d'inventaire (sbom.Fingerprint) du dernier SBOM rangé
	// ou confirmé par le serveur, en hexadécimal.
	Fingerprint string `json:"fingerprint,omitempty"`
	// LastScan est le début du dernier scan réussi ; LastSent, le dernier envoi d'un SBOM.
	LastScan time.Time `json:"last_scan,omitzero"`
	LastSent time.Time `json:"last_sent,omitzero"`
	// Images : inventaire des images des conteneurs qui tournent, rangé ou confirmé par
	// le serveur, par empreinte d'image (sha256:…) ; valable pour la version
	// ImagesVersion de l'agent seulement.
	Images        map[string]ImageRecord `json:"images,omitempty"`
	ImagesVersion string                 `json:"images_version,omitempty"`
	// DTFingerprint est l'empreinte du dernier inventaire accepté par Dependency-Track,
	// pour le projet et la version DTTarget (nom et version séparés par un octet nul).
	DTFingerprint string    `json:"dt_fingerprint,omitempty"`
	DTTarget      string    `json:"dt_target,omitempty"`
	DTLastSent    time.Time `json:"dt_last_sent,omitzero"`
	// ArchiveFingerprint est l'empreinte du dernier inventaire écrit en archive hors
	// ligne ; OfflineEnrollment, un jeton d'agent tiré par l'agent lui-même, que le serveur
	// apprend par l'inscription portée par chaque archive (T23).
	ArchiveFingerprint string    `json:"archive_fingerprint,omitempty"`
	LastArchive        time.Time `json:"last_archive,omitzero"`
	OfflineEnrollment  bool      `json:"offline_enrollment,omitempty"`
}

// fingerprint renvoie l'empreinte retenue, si elle est lisible.
func (s State) fingerprint() ([32]byte, bool) {
	var fp [32]byte
	b, err := hex.DecodeString(s.Fingerprint)
	if err != nil || len(b) != len(fp) {
		return fp, false
	}
	copy(fp[:], b)
	return fp, true
}

// Store lit et écrit l'état et le jeton d'agent dans le répertoire d'état (0700, fichiers
// 0600, écritures atomiques).
type Store struct{ dir string }

// OpenStore prépare le répertoire d'état.
func OpenStore(dir string) (*Store, error) {
	if err := ensureStateDir(dir); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Token renvoie le jeton d'agent, vide avant l'inscription.
func (s *Store) Token() (string, error) {
	tok, err := readSecret(filepath.Join(s.dir, tokenFile))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return tok, err
}

// SaveToken enregistre le jeton d'agent reçu à l'inscription.
func (s *Store) SaveToken(token string) error {
	return writeSecret(filepath.Join(s.dir, tokenFile), []byte(token+"\n"))
}

// Load renvoie l'état ; absent, illisible ou d'une autre version, un état vide (l'agent
// enverra son SBOM au prochain scan, ce qui est sans risque).
func (s *Store) Load() State {
	data, err := os.ReadFile(filepath.Join(s.dir, stateFile))
	if err != nil {
		return State{Version: stateVersion}
	}
	var st State
	if json.Unmarshal(data, &st) != nil || st.Version != stateVersion {
		return State{Version: stateVersion}
	}
	return st
}

// Save enregistre l'état.
func (s *Store) Save(st State) error {
	st.Version = stateVersion
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("hostagent: état : %w", err)
	}
	return writeSecret(filepath.Join(s.dir, stateFile), append(data, '\n'))
}
