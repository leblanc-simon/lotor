package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/secret"
	"leblanc.io/lotor/internal/tenant"
)

// Mode est le mode d'envoi d'une violation, fixé par sa politique.
type Mode string

// Modes d'envoi.
const (
	ModeImmediate Mode = "immediate"
	ModeDigest    Mode = "digest"
)

// Request est une requête HTTP sortante (webhook, Matrix, Slack, Mattermost).
type Request struct {
	Method string
	URL    string
	Header map[string]string
	Body   []byte
}

// Mail est un courriel.
type Mail struct {
	To        []string
	Subject   string
	Text      string
	MessageID string
	// HTML, s'il est posé, ajoute une version HTML au texte : l'expéditeur la met en forme
	// avec le gabarit des courriels (internal/delivery). Tous ses champs sont déjà traduits.
	HTML *HTML
}

// HTML est le contenu de la version HTML d'un courriel, mis en forme hors du métier.
// Seuls Title et Intro sont obligatoires ; un champ vide n'est pas affiché.
type HTML struct {
	Lang      string // étiquette BCP 47 du courriel
	Preheader string // aperçu affiché par la messagerie à côté du sujet
	Org       string // organisation concernée, au-dessus du titre
	Title     string
	Intro     string
	Code      string // code à recopier (code d'inscription)
	Items     []HTMLItem
	MoreLine  string // « … et 3 autres »
	URL       string // lien du bouton
	CTALabel  string
	Footer    string
	// ChannelsURL et ChannelsLabel : lien de gestion des canaux, en pied de message.
	ChannelsURL   string
	ChannelsLabel string
}

// HTMLItem est une violation présentée dans un courriel. Severity est la sévérité brute
// (critical, high, medium, low…), qui choisit les couleurs de l'étiquette SeverityLabel.
type HTMLItem struct {
	Severity      string
	SeverityLabel string
	KEV           bool
	KEVLabel      string
	Blocking      bool
	BlockingLabel string
	Headline      string
	Detail        string
	Policy        string
}

// Sender envoie les messages ; il est implémenté hors du métier par internal/delivery
// (HTTP sans redirection ni adresse privée, SMTP), qui renvoie des *SendError.
type Sender interface {
	Do(ctx context.Context, r Request) error
	Mail(ctx context.Context, m Mail) error
}

// SendError est un envoi en échec, porteur d'une clé d'erreur traduisible (error.notify.*)
// qui ne cite jamais de secret.
type SendError struct {
	Key string
	Err error
}

func (e *SendError) Error() string {
	if e.Err == nil {
		return "notify: " + e.Key
	}
	return "notify: " + e.Key + " : " + e.Err.Error()
}

func (e *SendError) Unwrap() error { return e.Err }

// Clés d'erreur d'un envoi.
const (
	KeySendFailed       = "error.notify.failed"
	KeySendUnreachable  = "error.notify.unreachable"
	KeySendForbidden    = "error.notify.private_address"
	KeySendStatus       = "error.notify.status"
	KeySendSMTP         = "error.notify.smtp"
	KeySendUnconfigured = "error.notify.smtp_unconfigured"
	KeySendSecret       = "error.notify.secret"
)

// ErrorKey renvoie la clé d'erreur d'un envoi.
func ErrorKey(err error) string {
	var se *SendError
	if errors.As(err, &se) && se.Key != "" {
		return se.Key
	}
	return KeySendFailed
}

// Item est une violation telle qu'un message la présente, lue par le Loader (policy).
type Item struct {
	ViolationID uuid.UUID
	Policy      string
	Blocking    bool
	Subject     string // finding ou agent
	OpenedAt    time.Time
	Project     string
	ProjectSlug string
	Ref         string
	VulnID      string
	Severity    string
	KEV         bool
	Component   string
	Agent       string
}

// Loader lit les violations à présenter, dans la transaction de l'envoi.
type Loader interface {
	Items(ctx context.Context, tx *db.OrgTx, violationIDs []uuid.UUID) ([]Item, error)
}

// Options règle le service.
type Options struct {
	Pool    *db.Pool
	Secrets *secret.Box
	Sender  Sender
	Loader  Loader
	Catalog *locale.Catalog
	// PublicURL est l'URL publique du serveur, pour les liens des messages (vide : sans lien).
	PublicURL string
	// DigestHour est l'heure UTC du résumé quotidien.
	DigestHour int
	Logger     *slog.Logger
	Now        func() time.Time
}

// Service tient les canaux et les envois.
type Service struct {
	o Options
}

// NewService renvoie le service.
func NewService(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	o.PublicURL = strings.TrimRight(o.PublicURL, "/")
	return &Service{o: o}
}

func (s *Service) now() time.Time { return s.o.Now().UTC().Round(time.Microsecond) }

// Jobs des envois.
const (
	// SendKind envoie les envois en attente d'un canal pour un mode (charge SendPayload).
	SendKind = "notify.send"
	// DigestAllKind met en file le résumé de chaque organisation (échéance quotidienne).
	DigestAllKind = "notify.digest_all"
	// DigestOrgKind met en file les résumés des canaux d'une organisation et relance les
	// envois immédiats restés en attente.
	DigestOrgKind = "notify.digest_org"
	// sendAttempts : avec les délais par défaut (10 s doublés jusqu'à 30 min), un canal
	// en panne reçoit ses messages s'il revient dans la dizaine d'heures ; au-delà, le
	// passage quotidien les relance.
	sendAttempts = 30
	// batchMax borne les violations d'un message.
	batchMax = 100
	// claimTTL est la durée d'une réservation d'envois (ADR 0052) : au-delà, l'envoi qui
	// l'a posée est tenu pour interrompu. Elle dépasse notify.timeout (5 min au plus).
	claimTTL = 10 * time.Minute
)

// ErrSendInProgress : les envois en attente du canal sont réservés par un autre envoi en
// cours ; le job est réessayé plus tard (une réservation expirée se reprend).
var ErrSendInProgress = errors.New("notify: envoi en cours sur ce canal")

// SendPayload est la charge de SendKind.
type SendPayload struct {
	ChannelID uuid.UUID `json:"channel_id"`
	Mode      Mode      `json:"mode"`
}

func enqueueSend(ctx context.Context, tx *db.OrgTx, channel uuid.UUID, mode Mode) error {
	_, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: SendKind, Payload: SendPayload{ChannelID: channel, Mode: mode},
		Priority: jobs.PriorityNormal, UniqueKey: "channel:" + channel.String() + ":" + string(mode), MaxAttempts: sendAttempts})
	return err
}

// enqueuePending remet en file les envois immédiats en attente d'un canal.
func enqueuePending(ctx context.Context, tx *db.OrgTx, channel uuid.UUID) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM notification_deliveries
		WHERE channel_id = $1 AND mode = 'immediate' AND state = 'pending'`, channel).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	return enqueueSend(ctx, tx, channel, ModeImmediate)
}

// Opened est une violation qui vient de s'ouvrir.
type Opened struct {
	ViolationID uuid.UUID
	PolicyID    uuid.UUID
	Mode        Mode
}

// Queue crée, dans la transaction qui ouvre les violations, un envoi par violation et par
// canal actif de sa politique, et met en file l'envoi immédiat des canaux concernés. Un
// couple (canal, violation) n'a jamais qu'un envoi.
func Queue(ctx context.Context, tx *db.OrgTx, now time.Time, opened []Opened) error {
	if len(opened) == 0 {
		return nil
	}
	ids, pols, modes := make([]uuid.UUID, len(opened)), make([]uuid.UUID, len(opened)), make([]string, len(opened))
	for i, o := range opened {
		ids[i], pols[i], modes[i] = o.ViolationID, o.PolicyID, string(o.Mode)
	}
	rows, err := tx.QueryContext(ctx, `
		INSERT INTO notification_deliveries (org_id, channel_id, violation_id, mode, state, created_at)
		SELECT $1, pc.channel_id, u.vid, u.mode, 'pending', $2
		  FROM unnest($3::uuid[], $4::uuid[], $5::text[]) AS u(vid, pid, mode)
		  JOIN policy_channels pc ON pc.policy_id = u.pid
		  JOIN notification_channels c ON c.org_id = pc.org_id AND c.id = pc.channel_id AND c.enabled
		 WHERE u.mode IN ('immediate', 'digest')
		ON CONFLICT DO NOTHING
		RETURNING channel_id, mode`, tx.OrgID(), now, ids, pols, modes)
	if err != nil {
		return fmt.Errorf("notify: envois des violations : %w", err)
	}
	immediate := map[uuid.UUID]bool{}
	for rows.Next() {
		var ch uuid.UUID
		var mode Mode
		if err := rows.Scan(&ch, &mode); err != nil {
			rows.Close()
			return err
		}
		if mode == ModeImmediate {
			immediate[ch] = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	chans := make([]uuid.UUID, 0, len(immediate))
	for ch := range immediate {
		chans = append(chans, ch)
	}
	slices.SortFunc(chans, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	for _, ch := range chans {
		if err := enqueueSend(ctx, tx, ch, ModeImmediate); err != nil {
			return err
		}
	}
	return nil
}

// SendHandler est le handler de SendKind.
func (s *Service) SendHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		var p SendPayload
		if err := e.Decode(&p); err != nil {
			return err
		}
		if e.OrgID.IsZero() || p.ChannelID == uuid.Nil || (p.Mode != ModeImmediate && p.Mode != ModeDigest) {
			return jobs.Permanent(errors.New("notify: envoi sans organisation, canal ni mode"))
		}
		return s.Send(ctx, e.OrgID, p.ChannelID, p.Mode)
	})
}

// batch est ce qu'un envoi a préparé dans sa transaction.
type batch struct {
	target  target
	org     orgInfo
	ids     []uuid.UUID
	items   []Item
	pending int // envois encore en attente au-delà du lot
}

type orgInfo struct {
	Slug, Name, Language string
}

func readOrg(ctx context.Context, tx *db.OrgTx) (orgInfo, error) {
	var o orgInfo
	err := tx.QueryRowContext(ctx, `SELECT slug, name, default_language FROM organizations WHERE id = $1`, tx.OrgID()).
		Scan(&o.Slug, &o.Name, &o.Language)
	return o, err
}

// Send envoie, en un message, les envois en attente d'un canal pour un mode (100 au plus
// par message, le reste par un job suivant). Les violations résolues entre-temps sont
// écartées sans envoi. Idempotent : seuls les envois en attente partent, et ils ne sont
// marqués envoyés qu'après le succès ; l'identifiant du message, dérivé des envois,
// permet au destinataire d'écarter le doublon d'une tentative dont la réponse s'est
// perdue (Matrix l'écarte de lui-même).
//
// Deux envois du même canal peuvent tourner en même temps (deux jobs, la clé d'unicité ne
// valant que pour les jobs en attente) : chacun réserve son lot sous le verrou de la ligne
// du canal (claimed_at) avant l'appel réseau et ne prend que des envois libres ; la
// réservation est levée par l'issue de l'envoi, ou expire après claimTTL (ADR 0052).
func (s *Service) Send(ctx context.Context, org tenant.OrgID, channelID uuid.UUID, mode Mode) error {
	var b batch
	skip := false
	claimed := false
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		// Verrou de la ligne du canal : les préparations d'envois du canal se suivent.
		c, err := getChannel(ctx, tx, channelID, true)
		if errors.Is(err, ErrNotFound) || (err == nil && !c.Enabled) {
			skip = true
			return nil
		}
		if err != nil {
			return err
		}
		now := s.now()
		if _, err := tx.ExecContext(ctx, `UPDATE notification_deliveries d SET state = 'skipped', done_at = $3, claimed_at = NULL
			  FROM policy_violations v
			 WHERE d.channel_id = $1 AND d.mode = $2 AND d.state = 'pending'
			   AND v.org_id = d.org_id AND v.id = d.violation_id AND v.resolved_at IS NOT NULL`,
			channelID, mode, now); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT violation_id FROM notification_deliveries
			WHERE channel_id = $1 AND mode = $2 AND state = 'pending' AND (claimed_at IS NULL OR claimed_at < $4)
			ORDER BY created_at, violation_id LIMIT $3`,
			channelID, mode, batchMax+1, now.Add(-claimTTL))
		if err != nil {
			return err
		}
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			b.ids = append(b.ids, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(b.ids) > batchMax {
			b.ids, b.pending = b.ids[:batchMax], 1
		}
		if len(b.ids) == 0 {
			return tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM notification_deliveries
				WHERE channel_id = $1 AND mode = $2 AND state = 'pending')`, channelID, mode).Scan(&claimed)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notification_deliveries SET claimed_at = $3
			WHERE channel_id = $1 AND state = 'pending' AND violation_id = ANY($2::uuid[])`, channelID, b.ids, now); err != nil {
			return err
		}
		if b.target, err = s.loadTarget(ctx, tx, channelID); err != nil {
			return &SendError{Key: KeySendSecret, Err: err}
		}
		if b.org, err = readOrg(ctx, tx); err != nil {
			return err
		}
		b.items, err = s.o.Loader.Items(ctx, tx, b.ids)
		return err
	})
	if err != nil {
		var se *SendError
		if errors.As(err, &se) {
			return jobs.Permanent(err)
		}
		return fmt.Errorf("notify: préparation de l'envoi : %w", err)
	}
	if claimed {
		return ErrSendInProgress
	}
	if skip || len(b.ids) == 0 {
		return nil
	}
	kind := eventOpened
	if mode == ModeDigest {
		kind = eventDigest
	}
	msg := s.compose(b.org, kind, b.items, deliveryID(channelID, b.ids))
	sendErr := s.deliver(ctx, b.target, msg)
	now := s.now()
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if sendErr != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE notification_deliveries SET claimed_at = NULL
				WHERE channel_id = $1 AND state = 'pending' AND violation_id = ANY($2::uuid[])`, channelID, b.ids); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `UPDATE notification_channels SET last_failure_at = $2, last_error_key = $3 WHERE id = $1`,
				channelID, now, ErrorKey(sendErr))
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notification_deliveries SET state = 'sent', done_at = $3, claimed_at = NULL
			WHERE channel_id = $1 AND state = 'pending' AND violation_id = ANY($2::uuid[])`, channelID, b.ids, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notification_channels SET last_success_at = $2 WHERE id = $1`, channelID, now); err != nil {
			return err
		}
		if b.pending > 0 {
			return enqueueSend(ctx, tx, channelID, mode)
		}
		return nil
	})
	if sendErr != nil {
		s.o.Logger.Warn("envoi de notification en échec", "org", org, "channel", channelID, "kind", b.target.Kind,
			"error_key", ErrorKey(sendErr))
		return fmt.Errorf("notify: envoi sur le canal %s : %w", channelID, sendErr)
	}
	return err
}

// deliveryID dérive l'identifiant d'un message de ses envois : une nouvelle tentative du
// même lot garde le même identifiant.
func deliveryID(channel uuid.UUID, ids []uuid.UUID) uuid.UUID {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = id.String()
	}
	slices.Sort(parts)
	return uuid.NewSHA1(channel, []byte(strings.Join(parts, ",")))
}

// TestChannel envoie un message de test sur un canal, tout de suite, et journalise
// l'essai (audit channel.tested, avec son issue). Il renvoie l'erreur d'envoi (clé par
// ErrorKey), nil si le message est parti.
func (s *Service) TestChannel(ctx context.Context, org tenant.OrgID, actor audit.Actor, channelID uuid.UUID) (sendErr error, err error) {
	var t target
	var o orgInfo
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		if t, err = s.loadTarget(ctx, tx, channelID); err != nil {
			return err
		}
		o, err = readOrg(ctx, tx)
		return err
	}, db.ReadOnly())
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		sendErr = &SendError{Key: KeySendSecret, Err: err}
	} else {
		id, idErr := uuid.NewV7()
		if idErr != nil {
			return nil, idErr
		}
		sendErr = s.deliver(ctx, t, s.compose(o, eventTest, nil, id))
	}
	outcome := "sent"
	if sendErr != nil {
		outcome = ErrorKey(sendErr)
	}
	now := s.now()
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		col := "last_success_at = $2, last_error_key = last_error_key"
		args := []any{channelID, now}
		if sendErr != nil {
			col = "last_failure_at = $2, last_error_key = $3"
			args = append(args, outcome)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notification_channels SET `+col+` WHERE id = $1`, args...); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, audit.Event{Action: audit.ChannelTested, TargetType: "channel",
			TargetID: channelID.String(), TargetLabel: t.Name, Details: map[string]string{"kind": string(t.Kind), "outcome": outcome}})
	})
	return sendErr, wrap("essai d'un canal", err)
}

// DigestSchedule est l'échéance quotidienne des résumés, à DigestHour UTC.
func (s *Service) DigestSchedule() jobs.Schedule {
	return jobs.Schedule{Name: DigestAllKind, Every: 24 * time.Hour, Offset: time.Duration(s.o.DigestHour) * time.Hour,
		Job: jobs.Job{Kind: DigestAllKind, Priority: jobs.PriorityLow}}
}

// DigestAllHandler met en file DigestOrgKind pour chaque organisation active.
func (s *Service) DigestAllHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, _ jobs.Execution) error {
		after := ""
		for {
			var page []crossorg.OrgSummary
			err := s.o.Pool.InTx(ctx, func(tx *db.Tx) error {
				var err error
				if page, err = crossorg.ListOrganizations(ctx, tx, after, crossorg.MaxPage); err != nil {
					return err
				}
				for _, o := range page {
					if o.ArchivedAt != nil {
						continue
					}
					if _, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: DigestOrgKind, OrgID: o.Org, Priority: jobs.PriorityLow,
						UniqueKey: "org:" + o.Org.String()}); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("notify: résumés du parc : %w", err)
			}
			if len(page) < crossorg.MaxPage {
				return nil
			}
			after = page[len(page)-1].Slug
		}
	})
}

// DigestOrgHandler met en file, pour chaque canal actif de l'organisation, l'envoi de son
// résumé s'il a des envois de résumé en attente, et relance ses envois immédiats restés en
// attente (canal en panne au-delà des réessais).
func (s *Service) DigestOrgHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		if e.OrgID.IsZero() {
			return jobs.Permanent(errors.New("notify: résumé sans organisation"))
		}
		return s.o.Pool.InOrg(ctx, e.OrgID, func(tx *db.OrgTx) error {
			rows, err := tx.QueryContext(ctx, `SELECT DISTINCT d.channel_id, d.mode FROM notification_deliveries d
				JOIN notification_channels c ON c.org_id = d.org_id AND c.id = d.channel_id AND c.enabled
				WHERE d.state = 'pending' ORDER BY 1, 2`)
			if err != nil {
				return err
			}
			type pair struct {
				ch   uuid.UUID
				mode Mode
			}
			var todo []pair
			for rows.Next() {
				var p pair
				if err := rows.Scan(&p.ch, &p.mode); err != nil {
					rows.Close()
					return err
				}
				todo = append(todo, p)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return err
			}
			rows.Close()
			for _, p := range todo {
				if err := enqueueSend(ctx, tx, p.ch, p.mode); err != nil {
					return err
				}
			}
			return nil
		})
	})
}
