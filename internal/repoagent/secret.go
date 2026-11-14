package repoagent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// credentialPrefix désigne un credential systemd (LoadCredential=,
// LoadCredentialEncrypted=), lu dans $CREDENTIALS_DIRECTORY.
const credentialPrefix = "credential:"

// maxSecret borne la taille d'un fichier de secret (une clé RSA de 4 096 bits fait
// environ 3 Kio en PEM).
const maxSecret = 64 << 10

// ReadSecret lit un secret désigné dans la configuration : « credential:nom » pour un
// credential systemd, ou le chemin absolu d'un fichier qui n'est lisible ni par le groupe
// ni par les autres (0600 ou 0400). La valeur elle-même n'est jamais dans le fichier de
// configuration. Les fins de ligne finales sont retirées.
//
// Les droits d'un credential ne sont pas contrôlés : systemd les choisit (0440 sous
// DynamicUser=yes, groupe du compte dynamique) dans un répertoire réservé au service.
func ReadSecret(ref string) ([]byte, error) {
	_, credential := strings.CutPrefix(ref, credentialPrefix)
	path, err := secretPath(ref)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("secret %s : %w", ref, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("secret %s : %w", ref, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("secret %s : fichier ordinaire attendu", ref)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 && !credential {
		return nil, fmt.Errorf("secret %s : droits %#o trop larges (0600 ou 0400 attendus)", ref, perm)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecret+1))
	if err != nil {
		return nil, fmt.Errorf("secret %s : %w", ref, err)
	}
	if len(data) > maxSecret {
		return nil, fmt.Errorf("secret %s : plus de %d octets", ref, maxSecret)
	}
	data = bytes.TrimRight(data, "\r\n")
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("secret %s : vide", ref)
	}
	return data, nil
}

func secretPath(ref string) (string, error) {
	if ref == "" {
		return "", errors.New("secret non configuré")
	}
	if name, ok := strings.CutPrefix(ref, credentialPrefix); ok {
		dir := os.Getenv("CREDENTIALS_DIRECTORY")
		if dir == "" {
			return "", fmt.Errorf("secret %s : CREDENTIALS_DIRECTORY absent (credentials systemd)", ref)
		}
		if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
			return "", fmt.Errorf("secret %s : nom de credential invalide", ref)
		}
		return filepath.Join(dir, name), nil
	}
	if !filepath.IsAbs(ref) {
		return "", fmt.Errorf("secret %s : chemin absolu ou credential:nom attendu", ref)
	}
	return ref, nil
}
