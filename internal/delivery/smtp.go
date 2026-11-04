package delivery

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"leblanc.io/lotor/internal/notify"
)

// Modes de connexion SMTP.
const (
	// SMTPStartTLS : connexion en clair puis STARTTLS exigé (port 587).
	SMTPStartTLS = "starttls"
	// SMTPImplicit : TLS dès la connexion (port 465).
	SMTPImplicit = "tls"
	// SMTPNone : sans TLS, réservé à un relais local ; aucune authentification n'y est
	// envoyée (net/smtp la refuse hors TLS, sauf vers localhost).
	SMTPNone = "none"
)

// SMTPConfig décrit le serveur d'envoi des courriels de l'instance.
type SMTPConfig struct {
	Host     string
	Port     int
	TLS      string
	Username string
	Password string
	From     string
	// HELO est le nom annoncé (défaut : localhost).
	HELO string
	// TLSConfig remplace la configuration TLS par défaut (autorités de test).
	TLSConfig *tls.Config
}

// Configured indique si un serveur SMTP est configuré.
func (c SMTPConfig) Configured() bool { return c.Host != "" && c.From != "" }

func smtpError(err error) error {
	return &notify.SendError{Key: notify.KeySendSMTP, Err: err}
}

// Mail envoie un courriel par le serveur SMTP de l'instance.
func (s *Sender) Mail(ctx context.Context, m notify.Mail) error {
	c := s.o.SMTP
	if !c.Configured() {
		return &notify.SendError{Key: notify.KeySendUnconfigured}
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return &notify.SendError{Key: notify.KeySendUnconfigured, Err: err}
	}
	msg, err := buildMail(from, m, time.Now())
	if err != nil {
		return smtpError(err)
	}
	ctx, cancel := context.WithTimeout(ctx, s.o.Timeout)
	defer cancel()
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	// Le serveur SMTP est choisi par l'exploitant : la garde des adresses privées ne s'y
	// applique pas (relais local fréquent).
	d := &net.Dialer{Timeout: s.o.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return smtpError(transportError(err))
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tlsConf := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	if c.TLSConfig != nil {
		tlsConf = c.TLSConfig.Clone()
		tlsConf.ServerName = c.Host
	}
	if c.TLS == SMTPImplicit {
		tc := tls.Client(conn, tlsConf)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return smtpError(errors.New("négociation TLS en échec"))
		}
		conn = tc
	}
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return smtpError(err)
	}
	defer client.Close()
	helo := c.HELO
	if helo == "" {
		helo = "localhost"
	}
	if err := client.Hello(helo); err != nil {
		return smtpError(err)
	}
	if c.TLS == SMTPStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return smtpError(errors.New("STARTTLS non proposé par le serveur"))
		}
		if err := client.StartTLS(tlsConf); err != nil {
			return smtpError(errors.New("STARTTLS en échec"))
		}
	}
	if c.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			// Le message du serveur ne cite pas le mot de passe ; on ne garde que sa nature.
			return smtpError(errors.New("authentification refusée"))
		}
	}
	if err := client.Mail(from.Address); err != nil {
		return smtpError(err)
	}
	for _, to := range m.To {
		if err := client.Rcpt(to); err != nil {
			return smtpError(err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return smtpError(err)
	}
	if _, err := w.Write(msg); err != nil {
		return smtpError(err)
	}
	if err := w.Close(); err != nil {
		return smtpError(err)
	}
	return client.Quit()
}

// headerSafe retire les retours à la ligne d'une valeur d'en-tête (injection d'en-têtes).
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, s)
}

// buildMail compose un courriel en UTF-8 : texte en quoted-printable, et version HTML
// avec le logo joint quand m.HTML est posé (mailhtml.go).
func buildMail(from *mail.Address, m notify.Mail, now time.Time) ([]byte, error) {
	if len(m.To) == 0 {
		return nil, errors.New("aucun destinataire")
	}
	to := make([]string, len(m.To))
	for i, r := range m.To {
		a, err := mail.ParseAddress(r)
		if err != nil {
			return nil, fmt.Errorf("destinataire invalide")
		}
		to[i] = a.String()
	}
	domain := "lotor.invalid"
	if _, d, ok := strings.Cut(from.Address, "@"); ok {
		domain = d
	}
	var b bytes.Buffer
	hdr := func(k, v string) { b.WriteString(k + ": " + headerSafe(v) + "\r\n") }
	hdr("From", from.String())
	hdr("To", strings.Join(to, ", "))
	hdr("Subject", mime.QEncoding.Encode("utf-8", headerSafe(m.Subject)))
	hdr("Date", now.UTC().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+headerSafe(m.MessageID)+"@"+domain+">")
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")
	if err := writeBody(&b, hdr, m); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Compose renvoie le courriel m tel qu'il serait envoyé par from (en-têtes et corps MIME),
// pour les exemples de courriels et les recettes.
func Compose(from string, m notify.Mail, now time.Time) ([]byte, error) {
	a, err := mail.ParseAddress(from)
	if err != nil {
		return nil, err
	}
	return buildMail(a, m, now)
}
