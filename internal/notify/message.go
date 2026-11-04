package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/text/language"

	"leblanc.io/open-go-base/i18n"
)

// event est la nature d'un message.
type event string

const (
	eventOpened event = "violations.opened"
	eventDigest event = "violations.digest"
	eventTest   event = "test"
)

// chatMax borne les violations détaillées dans un message lisible (courriel, salon) ; le
// webhook générique les porte toutes (100 au plus par message).
const chatMax = 20

// Message est un message composé, prêt à être mis en forme pour chaque nature de canal.
type Message struct {
	ID       uuid.UUID
	Event    event
	At       time.Time
	Org      orgInfo
	URL      string // page des violations, vide sans URL publique
	Subject  string // titre traduit
	Lines    []string
	More     int // violations non détaillées
	Items    []Item
	moreLine string
	intro    string
	html     *HTML // version HTML des courriels
}

// localizer renvoie le localiseur de la langue de l'organisation.
func (s *Service) localizer(lang string) *i18n.Localizer {
	tag, err := language.Parse(lang)
	if err != nil {
		tag = s.o.Catalog.Default()
	}
	return s.o.Catalog.Localizer(tag)
}

// compose prépare un message traduit dans la langue de l'organisation.
func (s *Service) compose(o orgInfo, ev event, items []Item, id uuid.UUID) Message {
	loc := s.localizer(o.Language)
	m := Message{ID: id, Event: ev, At: s.now(), Org: o, Items: items}
	if s.o.PublicURL != "" {
		m.URL = s.o.PublicURL + "/o/" + url.PathEscape(o.Slug) + "/violations"
	}
	args := map[string]any{"Org": o.Name, "Count": len(items)}
	switch ev {
	case eventTest:
		m.Subject = loc.T("notify.subject_test", args)
		m.intro = loc.T("notify.test_text", args)
	case eventDigest:
		m.Subject = loc.T("notify.subject_digest", args)
		m.intro = loc.T("notify.digest_text", args)
	default:
		m.Subject = loc.T("notify.subject_opened", args)
		m.intro = loc.T("notify.opened_text", args)
	}
	for i, it := range items {
		if i >= chatMax {
			m.More = len(items) - chatMax
			break
		}
		m.Lines = append(m.Lines, line(loc, it))
	}
	if m.More > 0 {
		m.moreLine = loc.T("notify.more", map[string]any{"Count": m.More})
	}
	m.html = s.composeHTML(loc, o, ev, m)
	return m
}

// composeHTML prépare la version HTML d'un courriel de notification, tous champs traduits.
func (s *Service) composeHTML(loc *i18n.Localizer, o orgInfo, ev event, m Message) *HTML {
	args := map[string]any{"Org": o.Name}
	title := map[event]string{eventTest: "notify.mail.title_test", eventDigest: "notify.mail.title_digest"}[ev]
	if title == "" {
		title = "notify.mail.title_opened"
	}
	h := &HTML{Lang: o.Language, Preheader: m.intro, Org: o.Name, Title: loc.T(title, args), Intro: m.intro,
		MoreLine: m.moreLine, URL: m.URL, CTALabel: loc.T("notify.mail.cta"), Footer: loc.T("notify.mail.footer", args)}
	if s.o.PublicURL != "" {
		h.ChannelsURL = s.o.PublicURL + "/o/" + url.PathEscape(o.Slug) + "/channels"
		h.ChannelsLabel = loc.T("notify.mail.channels")
	}
	for i, it := range m.Items {
		if i >= chatMax {
			break
		}
		args := map[string]any{"Policy": it.Policy, "Project": it.Project, "Ref": it.Ref, "Vuln": it.VulnID,
			"Component": it.Component, "Agent": it.Agent}
		item := HTMLItem{KEV: it.KEV, Blocking: it.Blocking, Policy: loc.T("notify.mail.policy", args)}
		if it.KEV {
			item.KEVLabel = loc.T("notify.mail.kev")
		}
		if it.Blocking {
			item.BlockingLabel = loc.T("notify.mail.blocking")
		}
		if it.Subject == "agent" {
			item.Headline = loc.T("notify.mail.agent_headline", args)
		} else {
			item.Severity, item.SeverityLabel = it.Severity, loc.T("severity."+it.Severity)
			item.Headline = loc.T("notify.mail.finding_headline", args)
			item.Detail = loc.T("notify.mail.finding_detail", args)
		}
		h.Items = append(h.Items, item)
	}
	return h
}

// line présente une violation en une ligne.
func line(loc *i18n.Localizer, it Item) string {
	args := map[string]any{"Policy": it.Policy, "Project": it.Project, "Ref": it.Ref, "Vuln": it.VulnID,
		"Severity": loc.T("severity." + it.Severity), "Component": it.Component, "Agent": it.Agent}
	key := "notify.line_finding"
	if it.Subject == "agent" {
		key = "notify.line_agent"
	}
	out := loc.T(key, args)
	if it.KEV {
		out += " " + loc.T("notify.kev")
	}
	if it.Blocking {
		out = loc.T("notify.blocking") + " " + out
	}
	return out
}

// text est le corps en texte brut (courriel, Matrix).
func (m Message) text(bullet string) string {
	var b strings.Builder
	b.WriteString(m.intro)
	b.WriteString("\n")
	for _, l := range m.Lines {
		b.WriteString("\n" + bullet + l)
	}
	if m.moreLine != "" {
		b.WriteString("\n" + bullet + m.moreLine)
	}
	if m.URL != "" {
		b.WriteString("\n\n" + m.URL)
	}
	return b.String()
}

// slackEscape échappe les caractères de contrôle du format de Slack et Mattermost, pour
// qu'un nom de règle ou de projet ne forme ni lien ni mention.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// webhookPayload est le corps JSON du webhook générique (docs/notifications.md).
type webhookPayload struct {
	ID           uuid.UUID          `json:"id"`
	Type         string             `json:"type"`
	OccurredAt   time.Time          `json:"occurred_at"`
	Organization webhookOrg         `json:"organization"`
	URL          string             `json:"url,omitempty"`
	Summary      string             `json:"summary"`
	Violations   []webhookViolation `json:"violations"`
}

type webhookOrg struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type webhookViolation struct {
	ID            uuid.UUID     `json:"id"`
	Policy        webhookPolicy `json:"policy"`
	Subject       string        `json:"subject"`
	OpenedAt      time.Time     `json:"opened_at"`
	Project       *webhookOrg   `json:"project,omitempty"`
	Ref           string        `json:"ref,omitempty"`
	Vulnerability *webhookVuln  `json:"vulnerability,omitempty"`
	Component     string        `json:"component,omitempty"`
	Agent         string        `json:"agent,omitempty"`
}

type webhookPolicy struct {
	Name     string `json:"name"`
	Blocking bool   `json:"blocking"`
}

type webhookVuln struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	KEV      bool   `json:"kev"`
}

func (m Message) webhookBody() ([]byte, error) {
	p := webhookPayload{ID: m.ID, Type: string(m.Event), OccurredAt: m.At, Organization: webhookOrg{Slug: m.Org.Slug, Name: m.Org.Name},
		URL: m.URL, Summary: m.Subject, Violations: []webhookViolation{}}
	for _, it := range m.Items {
		v := webhookViolation{ID: it.ViolationID, Policy: webhookPolicy{Name: it.Policy, Blocking: it.Blocking},
			Subject: it.Subject, OpenedAt: it.OpenedAt.UTC(), Agent: it.Agent}
		if it.Subject != "agent" {
			v.Project = &webhookOrg{Slug: it.ProjectSlug, Name: it.Project}
			v.Ref, v.Component = it.Ref, it.Component
			v.Vulnerability = &webhookVuln{ID: it.VulnID, Severity: it.Severity, KEV: it.KEV}
		}
		p.Violations = append(p.Violations, v)
	}
	return json.Marshal(p)
}

// Sign calcule la signature d'un webhook : HMAC-SHA256(secret, horodatage + "." + corps),
// en hexadécimal. Le destinataire la recalcule et refuse un horodatage trop ancien.
func Sign(secret []byte, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// En-têtes du webhook générique.
const (
	HeaderEvent     = "X-Lotor-Event"
	HeaderDelivery  = "X-Lotor-Delivery"
	HeaderTimestamp = "X-Lotor-Timestamp"
	HeaderSignature = "X-Lotor-Signature"
)

// deliver met le message en forme pour la nature du canal et l'envoie.
func (s *Service) deliver(ctx context.Context, t target, m Message) error {
	if s.o.Sender == nil {
		return &SendError{Key: KeySendFailed}
	}
	switch t.Kind {
	case KindEmail:
		return s.o.Sender.Mail(ctx, Mail{To: t.Settings.Recipients, Subject: m.Subject, Text: m.text("- "),
			MessageID: m.ID.String(), HTML: m.html})
	case KindWebhook:
		body, err := m.webhookBody()
		if err != nil {
			return err
		}
		ts := m.At.Unix()
		h := map[string]string{"Content-Type": "application/json", HeaderEvent: string(m.Event),
			HeaderDelivery: m.ID.String(), HeaderTimestamp: strconv.FormatInt(ts, 10)}
		if t.secret != "" {
			h[HeaderSignature] = "sha256=" + Sign([]byte(t.secret), ts, body)
		}
		return s.o.Sender.Do(ctx, Request{Method: "POST", URL: t.Settings.URL, Header: h, Body: body})
	case KindSlack, KindMattermost:
		var b strings.Builder
		b.WriteString("*" + slackEscape(m.Subject) + "*\n" + slackEscape(m.intro))
		for _, l := range m.Lines {
			b.WriteString("\n• " + slackEscape(l))
		}
		if m.moreLine != "" {
			b.WriteString("\n• " + slackEscape(m.moreLine))
		}
		if m.URL != "" {
			b.WriteString("\n" + m.URL)
		}
		body, err := json.Marshal(map[string]string{"text": b.String()})
		if err != nil {
			return err
		}
		return s.o.Sender.Do(ctx, Request{Method: "POST", URL: t.secret,
			Header: map[string]string{"Content-Type": "application/json"}, Body: body})
	case KindMatrix:
		body, err := json.Marshal(map[string]string{"msgtype": "m.notice", "body": m.Subject + "\n\n" + m.text("• ")})
		if err != nil {
			return err
		}
		// L'identifiant de transaction est celui du message : Matrix écarte de lui-même
		// une seconde tentative du même lot.
		u := t.Settings.Homeserver + "/_matrix/client/v3/rooms/" + url.PathEscape(t.Settings.Room) +
			"/send/m.room.message/" + m.ID.String()
		return s.o.Sender.Do(ctx, Request{Method: "PUT", URL: u, Body: body,
			Header: map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + t.secret}})
	}
	return fmt.Errorf("notify: nature de canal %q inconnue", t.Kind)
}
