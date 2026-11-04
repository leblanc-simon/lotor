package mailer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/delivery"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/secret"
	"leblanc.io/lotor/locales"
)

func testMailer(t *testing.T) *Mailer {
	t.Helper()
	cat, err := locale.New(locales.FS, ".", "fr")
	if err != nil {
		t.Fatal(err)
	}
	box, err := secret.Parse(map[string]string{"k": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}, "k")
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{Sender: nopSender{}, Secrets: box, Catalog: cat, PublicURL: "https://sbom.example.org/"})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func sampleMessages(lang string) map[string]Message {
	return map[string]Message{
		"verification": {To: "a@example.org", Language: lang, Template: SignupVerify, Path: "/signup/verify/lotor_vrf_x"},
		"compte-existant": {To: "a@example.org", Language: lang, Template: SignupExisting, Path: "/login"},
		"code": {To: "a@example.org", Language: lang, Template: SignupCode, Path: "/signup",
			Code: "lotor_sgn_abcdefghijklmnopqrstuvwxyz_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstu",
			Params: map[string]string{"Expires": "2026-12-04"}},
		"invitation": {To: "a@example.org", Language: lang, Template: OrgInvitation, Path: "/invitation/lotor_inv_x",
			Params: map[string]string{"Org": "Acme & Cie", "Inviter": "camille@acme.example", "Role": "administrateur", "Expires": "2026-12-04"}},
	}
}

// TestComposeTranslatesEveryTemplate : chaque modèle a ses textes dans chaque langue, en
// texte comme en HTML, et le lien est absolu.
func TestComposeTranslatesEveryTemplate(t *testing.T) {
	ml := testMailer(t)
	for _, lang := range []string{"fr", "en"} {
		for name, msg := range sampleMessages(lang) {
			m := ml.Compose(msg, uuid.New())
			if m.HTML == nil || m.HTML.Title == "" || m.HTML.Intro == "" || m.HTML.CTALabel == "" || m.HTML.Footer == "" {
				t.Fatalf("%s/%s : HTML incomplet %+v", lang, name, m.HTML)
			}
			for _, s := range []string{m.Subject, m.Text, m.HTML.Title, m.HTML.Intro, m.HTML.CTALabel, m.HTML.Footer} {
				if strings.Contains(s, "mail.") || strings.Contains(s, "<no value>") {
					t.Errorf("%s/%s : clé ou paramètre manquant dans %q", lang, name, s)
				}
			}
			if m.HTML.Lang != lang || !strings.HasPrefix(m.HTML.URL, "https://sbom.example.org/") || !strings.Contains(m.Text, m.HTML.URL) {
				t.Errorf("%s/%s : langue %q, lien %q", lang, name, m.HTML.Lang, m.HTML.URL)
			}
			if msg.Code != "" && (!strings.Contains(m.Text, msg.Code) || m.HTML.Code != msg.Code) {
				t.Errorf("%s/%s : code absent", lang, name)
			}
		}
	}
}

// TestWriteMailSamples écrit les courriels de l'inscription dans LOTOR_MAIL_SAMPLES (hors
// CI), pour vérifier leur rendu dans une vraie messagerie.
func TestWriteMailSamples(t *testing.T) {
	dir := os.Getenv("LOTOR_MAIL_SAMPLES")
	if dir == "" {
		t.Skip("LOTOR_MAIL_SAMPLES non défini")
	}
	ml := testMailer(t)
	for _, lang := range []string{"fr", "en"} {
		for name, msg := range sampleMessages(lang) {
			raw, err := delivery.Compose("lotor@example.org", ml.Compose(msg, uuid.New()), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name+"-"+lang+".eml"), raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// nopSender accepte tout courriel sans l'envoyer.
type nopSender struct{}

func (nopSender) Mail(context.Context, notify.Mail) error { return nil }
