package offline

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"
)

// Format des jetons de l'instance (internal/token, ADR 0014), recopié ici pour les agents,
// qui n'importent aucun paquet serveur : lotor_<nature>_<identifiant public>_<secret>,
// 16 et 32 octets en base32 minuscule sans remplissage. TestOfflineTokenFormat (paquet
// token) vérifie que le serveur lit les jetons tirés ici.
var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

const (
	agentPrefix = "lotor_agt_"
	publicBytes = 16
	secretBytes = 32
)

// ErrToken : jeton mal formé.
var ErrToken = errors.New("offline: jeton mal formé")

// NewAgentToken tire un jeton d'agent (inscription hors ligne) : sa forme en clair, à
// garder par l'agent, son identifiant public et l'empreinte de son secret, à remettre au
// serveur par l'archive.
func NewAgentToken() (plaintext, publicID string, hash [32]byte, err error) {
	buf := make([]byte, publicBytes+secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", hash, err
	}
	publicID = b32.EncodeToString(buf[:publicBytes])
	return agentPrefix + publicID + "_" + b32.EncodeToString(buf[publicBytes:]), publicID, sha256.Sum256(buf[publicBytes:]), nil
}

// ParseToken lit un jeton de nature kind (« agt », « enr ») : identifiant public et
// empreinte du secret, clé des codes d'une archive.
func ParseToken(kind, raw string) (publicID string, hash [32]byte, err error) {
	body, ok := strings.CutPrefix(strings.TrimSpace(raw), "lotor_"+kind+"_")
	pub, sec, ok2 := strings.Cut(body, "_")
	if !ok || !ok2 {
		return "", hash, ErrToken
	}
	p, err := b32.DecodeString(pub)
	if err != nil || len(p) != publicBytes || b32.EncodeToString(p) != pub {
		return "", hash, ErrToken
	}
	s, err := b32.DecodeString(sec)
	if err != nil || len(s) != secretBytes || b32.EncodeToString(s) != sec {
		return "", hash, ErrToken
	}
	return pub, sha256.Sum256(s), nil
}
