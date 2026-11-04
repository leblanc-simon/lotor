package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/locales"
)

// recorder est un Sender qui garde ce qu'on lui confie.
type recorder struct {
	requests []Request
	mails    []Mail
	err      error
}

func (r *recorder) Do(_ context.Context, req Request) error {
	r.requests = append(r.requests, req)
	return r.err
}

func (r *recorder) Mail(_ context.Context, m Mail) error {
	r.mails = append(r.mails, m)
	return r.err
}

func testService(t *testing.T, s Sender) *Service {
	t.Helper()
	cat, err := locale.New(locales.FS, ".", "fr")
	if err != nil {
		t.Fatal(err)
	}
	return NewService(Options{Sender: s, Catalog: cat, PublicURL: "https://sbom.example.org/",
		Now: func() time.Time { return time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC) }})
}

func TestSignature(t *testing.T) {
	// Vecteur recalculé indépendamment : HMAC-SHA256("secret", "1700000000.{}").
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte("1700000000.{}"))
	if got, want := Sign([]byte("secret"), 1700000000, []byte("{}")), hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Fatalf("%s != %s", got, want)
	}
	if Sign([]byte("secret"), 1700000001, []byte("{}")) == Sign([]byte("secret"), 1700000000, []byte("{}")) {
		t.Fatal("l'horodatage n'entre pas dans la signature")
	}
}

var items = []Item{
	{ViolationID: uuid.MustParse("0192f3a0-0000-7000-8000-000000000001"), Policy: "KEV en production", Blocking: true,
		Subject: "finding", Project: "API <b>", ProjectSlug: "api", Ref: "main", VulnID: "CVE-2021-44228", Severity: "critical",
		KEV: true, Component: "pkg:maven/log4j-core@2.14.1", OpenedAt: time.Date(2026, 11, 1, 7, 0, 0, 0, time.UTC)},
	{ViolationID: uuid.MustParse("0192f3a0-0000-7000-8000-000000000002"), Policy: "Agent muet", Subject: "agent", Agent: "srv-01"},
}

func TestDeliverEveryKind(t *testing.T) {
	rec := &recorder{}
	s := testService(t, rec)
	o := orgInfo{Slug: "acme", Name: "Acme", Language: "en"}
	m := s.compose(o, eventOpened, items, uuid.MustParse("0192f3a0-0000-7000-8000-0000000000aa"))
	ctx := context.Background()

	if err := s.deliver(ctx, target{Channel: Channel{Kind: KindEmail, Settings: Settings{Recipients: []string{"ops@example.org"}}}}, m); err != nil {
		t.Fatal(err)
	}
	mail := rec.mails[0]
	if mail.Subject != "lotor: new violations (Acme)" || !strings.Contains(mail.Text, "[blocking] KEV en production: CVE-2021-44228 (Critical)") ||
		!strings.Contains(mail.Text, "https://sbom.example.org/o/acme/violations") || !strings.Contains(mail.Text, "agent srv-01") {
		t.Fatalf("courriel %+v", mail)
	}
	// Version HTML (ADR 0056) : champs traduits, sévérité brute pour les couleurs, lien des
	// canaux ; le métier ne met rien en forme, il ne fait que traduire.
	h := mail.HTML
	if h == nil || h.Lang != "en" || h.Org != "Acme" || h.Title != "New policy violations" || h.CTALabel != "View violations" ||
		h.URL != "https://sbom.example.org/o/acme/violations" || h.ChannelsURL != "https://sbom.example.org/o/acme/channels" ||
		len(h.Items) != 2 {
		t.Fatalf("HTML %+v", h)
	}
	if it := h.Items[0]; it.Severity != "critical" || it.SeverityLabel != "Critical" || !it.KEV || it.KEVLabel != "KEV" ||
		!it.Blocking || it.BlockingLabel != "Blocking" || it.Headline != "CVE-2021-44228 in pkg:maven/log4j-core@2.14.1" ||
		it.Detail != "Project API <b>, reference main" || it.Policy != "Policy: KEV en production" {
		t.Errorf("violation %+v", it)
	}
	if it := h.Items[1]; it.Severity != "" || it.Headline != "Agent srv-01" || it.Detail != "" {
		t.Errorf("agent %+v", it)
	}

	wh := target{Channel: Channel{Kind: KindWebhook, Settings: Settings{URL: "https://hooks.example.org/x"}}, secret: "0123456789abcdef"}
	if err := s.deliver(ctx, wh, m); err != nil {
		t.Fatal(err)
	}
	req := rec.requests[0]
	ts := req.Header[HeaderTimestamp]
	if req.Method != "POST" || req.URL != wh.Settings.URL || req.Header[HeaderEvent] != "violations.opened" ||
		req.Header[HeaderDelivery] != m.ID.String() || ts != "1793520000" {
		t.Fatalf("requête %+v", req)
	}
	var tsn int64 = 1793520000
	if req.Header[HeaderSignature] != "sha256="+Sign([]byte(wh.secret), tsn, req.Body) {
		t.Fatal("signature fausse")
	}
	var body webhookPayload
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatal(err)
	}
	if body.Organization.Slug != "acme" || len(body.Violations) != 2 || body.Violations[0].Vulnerability.ID != "CVE-2021-44228" ||
		body.Violations[1].Agent != "srv-01" || body.Violations[1].Project != nil {
		t.Fatalf("corps %s", req.Body)
	}

	slack := target{Channel: Channel{Kind: KindSlack}, secret: "https://hooks.slack.com/services/T/B/X"}
	if err := s.deliver(ctx, slack, m); err != nil {
		t.Fatal(err)
	}
	req = rec.requests[1]
	var sb map[string]string
	_ = json.Unmarshal(req.Body, &sb)
	if req.URL != slack.secret || !strings.Contains(sb["text"], "API &lt;b&gt;") || strings.Contains(sb["text"], "API <b>") {
		t.Fatalf("slack %s", req.Body)
	}

	mx := target{Channel: Channel{Kind: KindMatrix, Settings: Settings{Homeserver: "https://matrix.example.org", Room: "!abc:example.org"}},
		secret: "syt_token"}
	if err := s.deliver(ctx, mx, m); err != nil {
		t.Fatal(err)
	}
	req = rec.requests[2]
	if req.Method != "PUT" || req.Header["Authorization"] != "Bearer syt_token" ||
		req.URL != "https://matrix.example.org/_matrix/client/v3/rooms/%21abc:example.org/send/m.room.message/"+m.ID.String() {
		t.Fatalf("matrix %+v", req)
	}
}

func TestComposeIsLocalizedAndBounded(t *testing.T) {
	s := testService(t, &recorder{})
	var many []Item
	for range chatMax + 5 {
		many = append(many, items[1])
	}
	m := s.compose(orgInfo{Slug: "acme", Name: "Acme", Language: "fr"}, eventDigest, many, uuid.New())
	if !strings.HasPrefix(m.Subject, "lotor : résumé quotidien") || len(m.Lines) != chatMax || m.More != 5 ||
		!strings.Contains(m.text("- "), "… et 5 autres") {
		t.Fatalf("%+v", m)
	}
	test := s.compose(orgInfo{Slug: "acme", Name: "Acme", Language: "xx"}, eventTest, nil, uuid.New())
	if !strings.Contains(test.Subject, "test") {
		t.Fatalf("%+v", test)
	}
}

func TestDeliveryIDIsStable(t *testing.T) {
	ch := uuid.New()
	a, b := uuid.New(), uuid.New()
	if deliveryID(ch, []uuid.UUID{a, b}) != deliveryID(ch, []uuid.UUID{b, a}) {
		t.Fatal("l'identifiant dépend de l'ordre")
	}
	if deliveryID(ch, []uuid.UUID{a}) == deliveryID(ch, []uuid.UUID{a, b}) {
		t.Fatal("deux lots différents ont le même identifiant")
	}
}

func TestNormalizeChannels(t *testing.T) {
	ok := []Input{
		{Name: " Ops ", Kind: KindEmail, Settings: Settings{Recipients: []string{"ops@example.org", "OPS@example.org", " "}}},
		{Name: "Hook", Kind: KindWebhook, Settings: Settings{URL: "https://hooks.example.org/x"}, Secret: "0123456789abcdef"},
		{Name: "Mx", Kind: KindMatrix, Settings: Settings{Homeserver: "https://matrix.example.org/", Room: "!abc:example.org"}, Secret: "syt"},
		{Name: "Slack", Kind: KindSlack, Secret: "https://hooks.slack.com/services/x"},
	}
	for _, in := range ok {
		out, err := normalize(in, true)
		if err != nil {
			t.Errorf("%s : %v", in.Name, err)
		}
		if in.Kind == KindEmail && (out.Name != "Ops" || len(out.Settings.Recipients) != 1) {
			t.Errorf("e-mail normalisé %+v", out)
		}
		if in.Kind == KindMatrix && out.Settings.Homeserver != "https://matrix.example.org" {
			t.Errorf("matrix normalisé %+v", out)
		}
	}
	for _, c := range []struct {
		in  Input
		key string
	}{
		{Input{Name: "", Kind: KindEmail}, KeyNameInvalid},
		{Input{Name: "x", Kind: "sms"}, KeyKindInvalid},
		{Input{Name: "x", Kind: KindEmail, Settings: Settings{Recipients: []string{"Ops <ops@example.org>"}}}, KeyRecipientsInvalid},
		{Input{Name: "x", Kind: KindEmail}, KeyRecipientsInvalid},
		{Input{Name: "x", Kind: KindWebhook, Settings: Settings{URL: "ftp://x"}, Secret: "0123456789abcdef"}, KeyURLInvalid},
		{Input{Name: "x", Kind: KindWebhook, Settings: Settings{URL: "https://u:p@x"}, Secret: "0123456789abcdef"}, KeyURLInvalid},
		{Input{Name: "x", Kind: KindWebhook, Settings: Settings{URL: "https://x"}, Secret: "short"}, KeySecretInvalid},
		{Input{Name: "x", Kind: KindWebhook, Settings: Settings{URL: "https://x"}}, KeySecretRequired},
		{Input{Name: "x", Kind: KindMatrix, Settings: Settings{Homeserver: "https://m", Room: "#alias:m"}, Secret: "t"}, KeyRoomInvalid},
		{Input{Name: "x", Kind: KindSlack, Secret: "not a url"}, KeySecretInvalid},
	} {
		_, err := normalize(c.in, true)
		v, ok := account.IsValidation(err)
		if !ok || v.Key != c.key {
			t.Errorf("%+v : %v", c.in, err)
		}
	}
	// À la modification, un secret vide garde l'existant.
	if _, err := normalize(Input{Name: "x", Kind: KindWebhook, Settings: Settings{URL: "https://x"}}, false); err != nil {
		t.Error(err)
	}
}

func TestErrorKey(t *testing.T) {
	if ErrorKey(&SendError{Key: KeySendStatus}) != KeySendStatus || ErrorKey(context.Canceled) != KeySendFailed {
		t.Fatal("clés d'erreur")
	}
}
