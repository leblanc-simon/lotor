// Package mailer envoie les courriels transactionnels de l'instance (T28, ADR 0056) :
// vérification d'adresse, « vous avez déjà un compte », code d'inscription, invitation
// d'organisation. Chaque courriel porte un lien dont le chemin contient un jeton : ce
// chemin et l'adresse du destinataire ne sont jamais journalisés, et, dans la charge d'un
// job, ils sont chiffrés par les clés de l'instance (secrets.keys).
//
// Deux voies :
//   - Enqueue met le courriel en file (job mail.send) dans la transaction qui produit le
//     lien : il part, avec réessais, seulement si cette transaction aboutit ;
//   - Send l'envoie tout de suite, sans rien stocker (code d'inscription envoyé par un
//     administrateur : l'adresse saisie n'est pas conservée).
//
// Le texte est composé à l'envoi, dans la langue demandée, par les clés mail.<modèle>.*.
package mailer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/secret"
)

// Kind est le job d'envoi d'un courriel.
const Kind = "mail.send"

// Template est le modèle d'un courriel, qui choisit ses clés de traduction.
type Template string

// Modèles de courriels.
const (
	// SignupVerify : lien de vérification de l'adresse, qui mène à la fin de l'inscription.
	SignupVerify Template = "signup_verify"
	// SignupExisting : l'adresse a déjà un compte (réponse neutre de l'inscription).
	SignupExisting Template = "signup_existing"
	// SignupCode : code d'inscription envoyé par un administrateur d'instance.
	SignupCode Template = "signup_code"
	// OrgInvitation : invitation à rejoindre une organisation.
	OrgInvitation Template = "org_invitation"
)

// Templates renvoie les modèles, pour les tests de traductions.
func Templates() []Template {
	return []Template{SignupVerify, SignupExisting, SignupCode, OrgInvitation}
}

// Message est un courriel à composer. Path est le chemin du lien, relatif à l'URL publique
// (« /signup/verify/lotor_vrf_… ») : il porte souvent un jeton. Code est un code à recopier
// (code d'inscription), jamais journalisé non plus. Params complète les paramètres de
// traduction (nom de l'organisation, adresse de l'invitant…).
type Message struct {
	To       string
	Language string
	Template Template
	Path     string
	Code     string
	Params   map[string]string
}

// Sender est la partie d'un expéditeur de notifications qui envoie un courriel
// (internal/delivery).
type Sender interface {
	Mail(ctx context.Context, m notify.Mail) error
}

// Options branche le compositeur et l'expéditeur.
type Options struct {
	Sender    Sender
	Secrets   *secret.Box
	Catalog   *locale.Catalog
	PublicURL string
}

// Mailer compose et envoie les courriels.
type Mailer struct{ o Options }

// New prépare un Mailer ; PublicURL est l'URL publique du serveur, sans barre finale.
func New(o Options) (*Mailer, error) {
	if o.Sender == nil || o.Secrets == nil || o.Catalog == nil || o.PublicURL == "" {
		return nil, errors.New("mailer: expéditeur, clés, catalogue et URL publique obligatoires")
	}
	o.PublicURL = strings.TrimRight(o.PublicURL, "/")
	return &Mailer{o: o}, nil
}

// payload est la charge d'un job mail.send : destinataire, chemin et code chiffrés.
type payload struct {
	Sealed   []byte            `json:"sealed"`
	KeyID    string            `json:"key_id"`
	Language string            `json:"language"`
	Template Template          `json:"template"`
	Params   map[string]string `json:"params,omitempty"`
}

// sealedPart est la partie chiffrée d'une charge.
type sealedPart struct {
	To   string `json:"to"`
	Path string `json:"path,omitempty"`
	Code string `json:"code,omitempty"`
}

// aad lie le chiffré à la nature du job et à son modèle.
func aad(t Template) []byte { return []byte(Kind + "/" + string(t)) }

func (m Message) validate() error {
	if !slices.Contains(Templates(), m.Template) {
		return fmt.Errorf("mailer: modèle inconnu %q", m.Template)
	}
	if m.To == "" || strings.ContainsAny(m.To, "\r\n") {
		return errors.New("mailer: destinataire invalide")
	}
	if m.Path != "" && !strings.HasPrefix(m.Path, "/") {
		return errors.New("mailer: chemin relatif attendu")
	}
	return nil
}

// Enqueue met m en file dans la transaction q (job d'instance) : il part si elle aboutit.
// box chiffre le destinataire, le chemin et le code.
func Enqueue(ctx context.Context, q db.Querier, box *secret.Box, m Message) error {
	if err := m.validate(); err != nil {
		return err
	}
	plain, err := json.Marshal(sealedPart{To: m.To, Path: m.Path, Code: m.Code})
	if err != nil {
		return err
	}
	sealed, key, err := box.Seal(plain, aad(m.Template))
	if err != nil {
		return fmt.Errorf("mailer: chiffrement : %w", err)
	}
	_, err = jobs.Enqueue(ctx, q, jobs.Job{Kind: Kind, Payload: payload{Sealed: sealed, KeyID: key, Language: m.Language,
		Template: m.Template, Params: m.Params}})
	if err != nil {
		return fmt.Errorf("mailer: mise en file : %w", err)
	}
	return nil
}

// Send compose et envoie m tout de suite, sans rien stocker.
func (ml *Mailer) Send(ctx context.Context, m Message, id uuid.UUID) error {
	if err := m.validate(); err != nil {
		return err
	}
	return sendError(ml.o.Sender.Mail(ctx, ml.Compose(m, id)))
}

// sendError ramène un échec d'envoi à sa clé traduisible : la réponse d'un serveur SMTP
// cite souvent le destinataire, qui ne doit pas finir dans les journaux ni dans la file.
func sendError(err error) error {
	if err == nil {
		return nil
	}
	var se *notify.SendError
	if errors.As(err, &se) {
		return &notify.SendError{Key: se.Key}
	}
	return errors.New("mailer: envoi en échec")
}

// Compose renvoie le courriel de m dans sa langue (défaut du catalogue si elle n'est pas
// disponible), en texte et en HTML (gabarit commun des courriels, internal/delivery).
// id fait l'identifiant du message.
func (ml *Mailer) Compose(m Message, id uuid.UUID) notify.Mail {
	tag := ml.o.Catalog.Resolve(m.Language)
	loc := ml.o.Catalog.Localizer(tag)
	instance := ml.o.PublicURL
	if u, err := url.Parse(ml.o.PublicURL); err == nil && u.Host != "" {
		instance = u.Host
	}
	args := map[string]any{"Instance": instance}
	for k, v := range m.Params {
		args[k] = v
	}
	key := "mail." + string(m.Template)
	h := &notify.HTML{
		Lang:      tag.String(),
		Org:       m.Params["Org"],
		Title:     loc.T(key+".title", args),
		Intro:     loc.T(key+".intro", args),
		Code:      m.Code,
		CTALabel:  loc.T(key+".cta", args),
		Footer:    loc.T("mail.footer", args),
		Preheader: loc.T(key+".title", args),
	}
	if m.Path != "" {
		h.URL = ml.o.PublicURL + m.Path
	}
	var b strings.Builder
	b.WriteString(h.Title + "\n\n" + h.Intro + "\n")
	if h.Code != "" {
		b.WriteString("\n" + h.Code + "\n")
	}
	if h.URL != "" {
		b.WriteString("\n" + h.CTALabel + " : " + h.URL + "\n")
	}
	b.WriteString("\n-- \n" + h.Footer + "\n")
	return notify.Mail{To: []string{m.To}, Subject: loc.T(key+".subject", args), Text: b.String(), MessageID: id.String(), HTML: h}
}

// Handler envoie les courriels mis en file. Un modèle ou un chiffré illisible est une
// erreur définitive ; un échec d'envoi est réessayé par la file.
func (ml *Mailer) Handler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		var p payload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return jobs.Permanent(fmt.Errorf("mailer: charge illisible : %w", err))
		}
		plain, err := ml.o.Secrets.Open(p.Sealed, p.KeyID, aad(p.Template))
		if err != nil {
			return jobs.Permanent(fmt.Errorf("mailer: déchiffrement : %w", err))
		}
		var part sealedPart
		if err := json.Unmarshal(plain, &part); err != nil {
			return jobs.Permanent(fmt.Errorf("mailer: charge illisible : %w", err))
		}
		m := Message{To: part.To, Language: p.Language, Template: p.Template, Path: part.Path, Code: part.Code, Params: p.Params}
		if err := m.validate(); err != nil {
			return jobs.Permanent(err)
		}
		return sendError(ml.o.Sender.Mail(ctx, ml.Compose(m, e.ID)))
	})
}
