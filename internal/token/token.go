package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"io"
	"slices"
	"strings"
)

// Kind est la nature d'un jeton, lisible dans son préfixe (§ 10 de l'architecture).
type Kind string

// Natures de jetons.
const (
	Agent      Kind = "agt" // jeton d'agent : routes /api/v1/agent/* hors inscription
	Enrollment Kind = "enr" // jeton d'inscription d'un agent serveur
	Personal   Kind = "pat" // jeton d'accès personnel : API utilisateur en lecture (ADR 0025)
	// Inscription des comptes (T28, ADR 0056).
	SignupCode   Kind = "sgn" // code d'inscription du mode « invitation », à usage unique
	Verification Kind = "vrf" // lien de vérification d'une adresse, à usage unique
	Invitation   Kind = "inv" // lien d'une invitation d'organisation
)

// Format d'un jeton : lotor_<nature>_<identifiant public>_<secret>. L'identifiant public
// (128 bits) désigne la ligne ; le secret (256 bits) n'est jamais stocké, seulement son
// SHA-256. Les deux parties sont en base32 minuscule sans remplissage : ni « _ » ni « - »,
// donc un découpage sans ambiguïté et un jeton qu'un double-clic sélectionne en entier.
const (
	prefix      = "lotor_"
	publicBytes = 16
	secretBytes = 32
	publicIDLen = 26 // base32 de 16 octets
	secretLen   = 52 // base32 de 32 octets
	bodyLen     = publicIDLen + 1 + secretLen
	// displayLen est le nombre de caractères de l'identifiant public affichés pour
	// reconnaître un jeton (« lotor_agt_k7q2xa… »).
	displayLen = 6
)

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ErrMalformed : la valeur présentée n'a pas le format d'un jeton de la nature attendue.
// Aucune requête en base n'est faite pour elle.
var ErrMalformed = errors.New("token: jeton mal formé")

// SecretHash est le SHA-256 du secret d'un jeton.
type SecretHash [sha256.Size]byte

// Matches compare deux empreintes en temps constant.
func (h SecretHash) Matches(stored []byte) bool {
	return len(stored) == sha256.Size && subtle.ConstantTimeCompare(h[:], stored) == 1
}

// Issued est un jeton qui vient d'être tiré : Plaintext n'est montré qu'une fois et jamais
// stocké ni journalisé.
type Issued struct {
	Kind      Kind
	PublicID  string
	Hash      SecretHash
	Plaintext string
}

// issue tire un jeton de la nature kind depuis rnd (crypto/rand hors tests).
func issue(kind Kind, rnd io.Reader) (Issued, error) {
	buf := make([]byte, publicBytes+secretBytes)
	if _, err := io.ReadFull(rnd, buf); err != nil {
		return Issued{}, errors.Join(errors.New("token: tirage d'un jeton"), err)
	}
	pub, sec := buf[:publicBytes], buf[publicBytes:]
	t := Issued{Kind: kind, PublicID: b32.EncodeToString(pub), Hash: sha256.Sum256(sec)}
	t.Plaintext = prefix + string(kind) + "_" + t.PublicID + "_" + b32.EncodeToString(sec)
	return t, nil
}

// New tire un jeton de la nature kind.
func New(kind Kind) (Issued, error) { return issue(kind, rand.Reader) }

// Parse lit un jeton de la nature kind et renvoie son identifiant public et l'empreinte de
// son secret. Seule la forme canonique est acceptée.
func Parse(kind Kind, s string) (publicID string, hash SecretHash, err error) {
	body, ok := strings.CutPrefix(s, prefix+string(kind)+"_")
	if !ok || len(body) != bodyLen || body[publicIDLen] != '_' {
		return "", SecretHash{}, ErrMalformed
	}
	publicID, secretPart := body[:publicIDLen], body[publicIDLen+1:]
	pub, err := b32.DecodeString(publicID)
	if err != nil || len(pub) != publicBytes || b32.EncodeToString(pub) != publicID {
		return "", SecretHash{}, ErrMalformed
	}
	sec, err := b32.DecodeString(secretPart)
	if err != nil || len(sec) != secretBytes || b32.EncodeToString(sec) != secretPart {
		return "", SecretHash{}, ErrMalformed
	}
	return publicID, sha256.Sum256(sec), nil
}

// KindOf renvoie celle des natures kinds qu'annonce le préfixe d'un jeton, sans le valider.
func KindOf(s string, kinds ...Kind) (Kind, bool) {
	i := slices.IndexFunc(kinds, func(k Kind) bool { return strings.HasPrefix(s, prefix+string(k)+"_") })
	if i < 0 {
		return "", false
	}
	return kinds[i], true
}

// DisplayPrefix est le début reconnaissable d'un jeton, sans rien de son secret.
func DisplayPrefix(kind Kind, publicID string) string {
	if len(publicID) > displayLen {
		publicID = publicID[:displayLen]
	}
	return prefix + string(kind) + "_" + publicID
}
