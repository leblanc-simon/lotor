package delivery

import (
	"bytes"
	"image/png"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/notify"
)

func sampleHTML() *notify.HTML {
	return &notify.HTML{
		Lang: "fr", Preheader: "Nouvelles violations : 2.", Org: "Acme & Cie", Title: "Nouvelles violations de politiques",
		Intro: "Nouvelles violations de politiques : 2.", Code: "lotor_sgn_abc",
		Items: []notify.HTMLItem{
			{Severity: "critical", SeverityLabel: "Critique", KEV: true, KEVLabel: "KEV", Blocking: true, BlockingLabel: "Bloquante",
				Headline: "CVE-2021-44228 dans log4j-core", Detail: "Projet api, référence main", Policy: "Politique : KEV"},
			{Severity: "negligible", SeverityLabel: "Négligeable", Headline: "Agent srv-01", Policy: "Politique : muet"},
		},
		MoreLine: "… et 3 autres", URL: "https://sbom.example.org/o/acme/violations", CTALabel: "Voir les violations",
		Footer: "Ce canal reçoit les alertes.", ChannelsURL: "https://sbom.example.org/o/acme/channels", ChannelsLabel: "Gérer les canaux",
	}
}

func partBody(t *testing.T, p *multipart.Part) []byte {
	t.Helper()
	var r io.Reader = p
	if p.Header.Get("Content-Transfer-Encoding") == "quoted-printable" {
		r = quotedprintable.NewReader(p)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMailHTMLStructure : multipart/alternative { text/plain, multipart/related { text/html,
// image/png } }, logo appelé par cid: (contrainte 4), sans image externe, SVG ni data:.
func TestMailHTMLStructure(t *testing.T) {
	from := &mail.Address{Address: "lotor@example.org"}
	raw, err := buildMail(from, notify.Mail{To: []string{"a@example.org"}, Subject: "Sujet", Text: "texte\nbrut",
		MessageID: "id", HTML: sampleHTML()}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("type %q, %v", mt, err)
	}
	alt := multipart.NewReader(msg.Body, params["boundary"])
	text, err := alt.NextPart()
	if err != nil || !strings.HasPrefix(text.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("première partie : %v %v", text, err)
	}
	if got := string(partBody(t, text)); got != "texte\r\nbrut" {
		t.Errorf("texte %q", got)
	}
	relPart, err := alt.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err = mime.ParseMediaType(relPart.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/related" || params["type"] != "text/html" {
		t.Fatalf("seconde partie %q %v %v", mt, params, err)
	}
	rel := multipart.NewReader(relPart, params["boundary"])
	htmlPart, err := rel.NextPart()
	if err != nil || !strings.HasPrefix(htmlPart.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("partie HTML : %v", err)
	}
	html := string(partBody(t, htmlPart))
	for _, want := range []string{`src="cid:` + mailLogoCID + `"`, `width="17" height="40"`, "Acme &amp; Cie", "lotor_sgn_abc",
		"background-color:#6E1230;color:#FFFFFF;", "border:1px solid #838C9A", `href="https://sbom.example.org/o/acme/violations"`,
		`<html lang="fr"`, "<title>Sujet</title>"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML sans %q", want)
		}
	}
	for _, banned := range []string{"<svg", "data:", `src="http`, "@font-face", "url("} {
		if strings.Contains(html, banned) {
			t.Errorf("HTML avec %q", banned)
		}
	}
	logo, err := rel.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if logo.Header.Get("Content-Type") != "image/png" || logo.Header.Get("Content-ID") != "<"+mailLogoCID+">" ||
		!strings.HasPrefix(logo.Header.Get("Content-Disposition"), "inline") {
		t.Errorf("logo : %v", logo.Header)
	}
	if _, err := rel.NextPart(); err != io.EOF {
		t.Errorf("partie en trop dans multipart/related : %v", err)
	}
	if _, err := alt.NextPart(); err != io.EOF {
		t.Errorf("partie en trop dans multipart/alternative : %v", err)
	}
	// Un courriel sans version HTML reste en texte seul.
	raw, err = buildMail(from, notify.Mail{To: []string{"a@example.org"}, Subject: "S", Text: "t", MessageID: "id"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if msg, _ := mail.ReadMessage(bytes.NewReader(raw)); !strings.HasPrefix(msg.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("texte seul : %q", msg.Header.Get("Content-Type"))
	}
}

// TestMailLogoIsATransparentTail : une seule queue, PNG transparent au rapport de 17 × 40
// (contrainte 3).
func TestMailLogoIsATransparentTail(t *testing.T) {
	img, err := png.Decode(bytes.NewReader(mailLogo))
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	if b.Dx()*40 != b.Dy()*17 {
		t.Errorf("logo %d × %d, rapport 17 × 40 attendu", b.Dx(), b.Dy())
	}
	if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
		t.Error("coin du logo opaque : fond transparent attendu")
	}
}

var (
	tmplActions  = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	tmplComments = regexp.MustCompile(`(?s)<!--.*?-->`)
	tmplStyle    = regexp.MustCompile(`(?s)<style>.*?</style>`)
	tmplTags     = regexp.MustCompile(`(?s)<[^>]*>`)
	tmplAttrs    = regexp.MustCompile(`(?i)\s(alt|title|aria-label)="([^"]*)"`)
	tmplLetters  = regexp.MustCompile(`\p{L}+`)
)

// TestMailTemplateHasNoHardcodedText : aucun texte visible en dur hormis « lotor »
// (contrainte 7).
func TestMailTemplateHasNoHardcodedText(t *testing.T) {
	src := tmplActions.ReplaceAllString(tmplStyle.ReplaceAllString(tmplComments.ReplaceAllString(mailTemplateSource, ""), ""), "")
	for _, m := range tmplAttrs.FindAllStringSubmatch(src, -1) {
		if tmplLetters.MatchString(m[2]) {
			t.Errorf("attribut %s en dur : %q", m[1], m[2])
		}
	}
	for _, w := range tmplLetters.FindAllString(strings.ReplaceAll(tmplTags.ReplaceAllString(src, " "), "&nbsp;", " "), -1) {
		if w != "lotor" {
			t.Errorf("texte en dur : %q", w)
		}
	}
}

func luminance(hex string) float64 {
	v, err := strconv.ParseUint(strings.TrimPrefix(hex, "#"), 16, 32)
	if err != nil {
		panic(hex)
	}
	r, g, b := float64(v>>16&0xff), float64(v>>8&0xff), float64(v&0xff)
	return 0.2125*r + 0.7154*g + 0.0721*b
}

func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// TestMailColorsSurviveThunderbirdDarkMode : le mode sombre de Thunderbird garde un fond
// dont la luminance ne dépasse pas 200 et dont le contraste avec le texte atteint 3,5
// (contrainte 1) ; chaque étiquette et le bouton doivent le tenir, et sevStyle suit la
// table de la contrainte 5.
func TestMailColorsSurviveThunderbirdDarkMode(t *testing.T) {
	want := map[string]mailColor{"critical": {"#6E1230", "#FFFFFF"}, "high": {"#A92B21", "#FFFFFF"},
		"medium": {"#E5C56B", "#3D2C00"}, "low": {"#B5C9E2", "#12345C"}}
	all := map[string]mailColor{"kev": mailKEVColor, "bouton": mailButtonColor}
	for sev, c := range want {
		if mailSeverityColors[sev] != c {
			t.Errorf("%s : %v, attendu %v", sev, mailSeverityColors[sev], c)
		}
		if got := string(sevStyle(sev)); got != "background-color:"+c.bg+";color:"+c.fg+";" {
			t.Errorf("sevStyle(%s) = %q", sev, got)
		}
		all[sev] = c
	}
	if mailKEVColor != (mailColor{"#F5C518", "#161B26"}) || mailButtonColor != (mailColor{"#0A5452", "#FFFFFF"}) {
		t.Error("KEV ou bouton : couleurs de la contrainte 5 attendues")
	}
	for name, c := range all {
		if l := luminance(c.bg); l > 200 {
			t.Errorf("%s : luminance du fond %.1f > 200, retiré par Thunderbird", name, l)
		}
		if k := contrast(c.bg, c.fg); k < 3.5 {
			t.Errorf("%s : contraste %.2f < 3,5, fond retiré par Thunderbird", name, k)
		}
	}
	// Les couleurs du gabarit sont bien celles de la table (bouton et KEV en ligne).
	for _, s := range []string{"background-color:" + mailButtonColor.bg, "color:" + mailButtonColor.fg,
		"background-color:" + mailKEVColor.bg + ";color:" + mailKEVColor.fg} {
		if !strings.Contains(mailTemplateSource, s) {
			t.Errorf("gabarit sans %q", s)
		}
	}
}

// TestWriteMailSamples écrit un exemple de notification dans LOTOR_MAIL_SAMPLES (hors CI),
// pour vérifier le rendu dans une vraie messagerie ; les courriels de l'inscription sont
// écrits par le test homonyme d'internal/mailer.
func TestWriteMailSamples(t *testing.T) {
	dir := os.Getenv("LOTOR_MAIL_SAMPLES")
	if dir == "" {
		t.Skip("LOTOR_MAIL_SAMPLES non défini")
	}
	h := sampleHTML()
	h.Code = ""
	h.Items = append(h.Items,
		notify.HTMLItem{Severity: "high", SeverityLabel: "Élevée", Headline: "CVE-2023-44487 dans nghttp2", Detail: "Projet srv-web-01, référence srv-web-01", Policy: "Politique : critiques"},
		notify.HTMLItem{Severity: "medium", SeverityLabel: "Moyenne", Headline: "CVE-2024-6387 dans openssh-server", Detail: "Projet srv-db-01, référence srv-db-01", Policy: "Politique : exposés"},
		notify.HTMLItem{Severity: "low", SeverityLabel: "Faible", Headline: "CVE-2023-48795 dans golang.org/x/crypto", Detail: "Projet passerelle-api, référence main", Policy: "Politique : exposés"})
	raw, err := Compose("lotor@example.org", notify.Mail{To: []string{"equipe@example.org"}, Subject: "lotor : nouvelles violations (Acme & Cie)",
		Text: "Nouvelles violations de politiques : 5.", MessageID: "sample-notification", HTML: h}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notification-fr.eml"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}
