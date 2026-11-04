package hostagent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxSecretFile borne la lecture d'un fichier secret (jeton, clé PEM).
const maxSecretFile = 64 << 10

// credentialsDirEnv est la variable par laquelle systemd désigne les credentials du
// service (LoadCredential=, LoadCredentialEncrypted=), déchiffrés dans un répertoire
// privé.
const credentialsDirEnv = "CREDENTIALS_DIRECTORY"

// Noms des credentials systemd lus par l'agent.
const (
	CredentialEnrollmentToken = "enrollment-token"
	CredentialClientKey       = "client-key"
	CredentialDTAPIKey        = "dependency-track-api-key"
)

// ErrInsecureSecret : fichier secret lisible par d'autres que son propriétaire.
var ErrInsecureSecret = errors.New("hostagent: fichier secret accessible au groupe ou aux autres (0600 attendu)")

// credentialPath renvoie le chemin du credential name s'il existe.
func credentialPath(name string) (string, bool) {
	dir := os.Getenv(credentialsDirEnv)
	if dir == "" {
		return "", false
	}
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	return p, true
}

// resolveSecret choisit le fichier d'un secret : celui de la configuration, sinon le
// credential systemd du même nom, sinon fallback (vide : pas de secret).
func resolveSecret(configured, credential, fallback string) string {
	if configured != "" {
		return configured
	}
	if p, ok := credentialPath(credential); ok {
		return p
	}
	return fallback
}

// readSecret lit un fichier secret. Hors du répertoire des credentials (que systemd rend
// privé), le fichier doit n'être accessible qu'à son propriétaire : un jeton lisible par
// tous serait déjà compromis.
func readSecret(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("hostagent: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("hostagent: %s n'est pas un fichier", path)
	}
	if fi.Mode().Perm()&0o077 != 0 && !inCredentials(path) {
		return "", fmt.Errorf("%w : %s (%s)", ErrInsecureSecret, path, fi.Mode().Perm())
	}
	if fi.Size() > maxSecretFile {
		return "", fmt.Errorf("hostagent: %s trop long", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hostagent: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func inCredentials(path string) bool {
	dir := os.Getenv(credentialsDirEnv)
	if dir == "" {
		return false
	}
	rel, err := filepath.Rel(dir, path)
	return err == nil && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

// writeSecret écrit un fichier secret en 0600, de façon atomique (fichier temporaire du
// même répertoire, puis renommage) : un arrêt en cours d'écriture ne laisse jamais un
// fichier tronqué.
func writeSecret(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("hostagent: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // sans effet après le renommage
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("hostagent: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("hostagent: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("hostagent: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("hostagent: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("hostagent: %w", err)
	}
	return nil
}

// ensureStateDir crée le répertoire d'état en 0700 et refuse un répertoire ouvert à
// d'autres.
func ensureStateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("hostagent: répertoire d'état : %w", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("hostagent: répertoire d'état : %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("hostagent: répertoire d'état %s : %w", dir, fs.ErrInvalid)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("hostagent: répertoire d'état %s accessible à d'autres (%s, 0700 attendu)", dir, fi.Mode().Perm())
	}
	return nil
}
