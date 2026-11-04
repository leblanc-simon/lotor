//go:build integration

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/policy"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/webtest"
)

func (a *app) countIn(org tenant.OrgID, query string, args ...any) int {
	a.t.Helper()
	var n int
	if err := a.tdb.App.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), query, args...).Scan(&n)
	}); err != nil {
		a.t.Fatal(err)
	}
	return n
}

// TestPolicyScreens : canaux (création, secret jamais réaffiché, essai), règles (modèle,
// refus d'une règle invalide avec un message traduit qui la situe, aperçu, enregistrement,
// suppression avec confirmation), violations et section « Alertes » du tableau de bord,
// verdict par l'API des agents ; droits (lecteur : 403 sur les règles et les canaux),
// deux langues, accessibilité, CSP, isolement.
func TestPolicyScreens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := newApp(t)
	admin, reader := a.user("admin@example.org", false), a.user("reader@example.org", false)
	f := repoSetup(t, a, "org-a", admin)
	a.addTeamMember(f.org, reader, tenant.TeamReader)
	if err := a.tdb.App.InOrg(ctx, f.org.ID, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(ctx, `UPDATE projects SET labels = '{"env": "production"}' WHERE id = $1`, f.p.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s := a.analysis()
	s.publish(t, time.Now().Add(-48*time.Hour), log4shellRules()...)
	a.pushLog4shell(f, 1, sbomFile(t, "log4shell.cdx16.json"))
	if out, err := s.analyzer.Analyze(ctx, f.org.ID, a.mainRef(f.org.ID, f.p.ID)); err != nil || out != finding.OutcomeAnalyzed {
		t.Fatalf("analyse : %s, %v", out, err)
	}
	ab := a.signIn(admin)

	// Canal webhook : le secret part chiffré et n'est jamais réaffiché.
	const secret = "webhook-secret-0123456789"
	p := ab.post("/o/org-a/channels", url.Values{"name": {"Astreinte"}, "kind": {"webhook"}, "enabled": {"1"},
		"url": {"https://hooks.example.org/lotor"}, "secret": {secret}})
	if p.status != http.StatusSeeOther || p.location != "/o/org-a/channels?done=channel_saved" {
		t.Fatalf("création du canal : %d %s", p.status, p.body)
	}
	if p := ab.post("/o/org-a/channels", url.Values{"name": {"Mauvais"}, "kind": {"webhook"}, "url": {"ftp://x"}, "secret": {secret}}); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("URL invalide : %d", p.status)
	}
	chans, err := a.notify.Channels(ctx, f.org.ID)
	if err != nil || len(chans) != 1 {
		t.Fatalf("canaux %v : %v", chans, err)
	}
	ch := chans[0]
	chURL := "/o/org-a/channels/" + ch.ID.String()
	for _, path := range []string{"/o/org-a/channels", chURL} {
		if body := ab.get(path).body; strings.Contains(body, secret) {
			t.Fatalf("%s réaffiche le secret", path)
		}
	}
	// Essai : le message part (envoyeur de test) et l'issue s'affiche.
	tp := ab.post(chURL+"/test", url.Values{})
	if tp.status != http.StatusOK || !strings.Contains(unescape(tp.body), "Le message de test est parti") {
		t.Fatalf("essai : %d", tp.status)
	}
	a.sent.mu.Lock()
	if len(a.sent.requests) != 1 || a.sent.requests[0].Header[notify.HeaderSignature] == "" {
		t.Fatalf("message de test %+v", a.sent.requests)
	}
	a.sent.err = &notify.SendError{Key: notify.KeySendStatus}
	a.sent.mu.Unlock()
	if tp := ab.post(chURL+"/test", url.Values{}); !strings.Contains(unescape(tp.body), "Le destinataire a refusé le message") {
		t.Fatal("échec de l'essai non affiché")
	}
	a.sent.mu.Lock()
	a.sent.err = nil
	a.sent.mu.Unlock()
	// Modification sans secret : le secret est gardé, sauf si l'URL change (SEC2-04).
	if p := ab.post(chURL, url.Values{"name": {"Astreinte"}, "kind": {"webhook"}, "enabled": {"1"},
		"url": {"https://hooks.example.org/lotor2"}}); p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, `aria-invalid="true"`) {
		t.Fatalf("URL changée sans ressaisir la clé : %d", p.status)
	}
	if p := ab.post(chURL, url.Values{"name": {"Astreinte (jour)"}, "kind": {"webhook"}, "enabled": {"1"},
		"url": {"https://hooks.example.org/lotor"}}); p.status != http.StatusSeeOther {
		t.Fatalf("modification du canal : %d %s", p.status, p.body)
	}
	if p := ab.post(chURL, url.Values{"name": {"Astreinte"}, "kind": {"webhook"}, "enabled": {"1"},
		"url": {"https://hooks.example.org/lotor2"}, "secret": {secret}}); p.status != http.StatusSeeOther {
		t.Fatalf("nouvelle URL avec la clé ressaisie : %d %s", p.status, p.body)
	}

	// Règle invalide : refusée, message traduit situé, saisie conservée.
	np := ab.get("/o/org-a/policies/new?template=" + policy.TemplateKEVProduction)
	if np.status != http.StatusOK || !strings.Contains(unescape(np.body), `finding.kev &amp;&amp; finding.actionable`) &&
		!strings.Contains(np.body, "finding.kev &amp;&amp; finding.actionable") {
		t.Fatalf("formulaire du modèle : %d", np.status)
	}
	if p := ab.get("/o/org-a/policies/new?template=" + policy.TemplateLicenseAGPL); p.status != http.StatusOK ||
		!strings.Contains(p.body, "license.ids.exists") {
		t.Fatalf("modèle AGPL (sujet licence, T20) : %d", p.status)
	}
	bad := url.Values{"name": {"KEV prod"}, "subject": {"finding"}, "expression": {"finding.sevrity == \"critical\""},
		"enabled": {"1"}, "blocking": {"1"}, "delivery": {"immediate"}, "channels": {ch.ID.String()}, "action": {"save"}}
	bp := ab.post("/o/org-a/policies", bad)
	if bp.status != http.StatusUnprocessableEntity || !strings.Contains(unescape(bp.body), "Champ inconnu « sevrity » ligne 1, colonne 8") {
		t.Fatalf("règle invalide : %d %s", bp.status, unescape(bp.body))
	}
	bad.Set("lang", "en")
	if bp := ab.post("/o/org-a/policies?lang=en", bad); !strings.Contains(unescape(bp.body), "Unknown field “sevrity” at line 1, column 8") {
		t.Fatal("message anglais absent")
	}
	// Aperçu : une violation aujourd'hui, rien d'enregistré.
	good := url.Values{"name": {"KEV prod"}, "subject": {"finding"}, "template": {policy.TemplateKEVProduction},
		"expression": {`finding.kev && finding.actionable && has(project.labels.env) && project.labels.env == "production"`},
		"enabled":    {"1"}, "blocking": {"1"}, "delivery": {"immediate"}, "channels": {ch.ID.String()}, "action": {"preview"}}
	pp := ab.post("/o/org-a/policies", good)
	if pp.status != http.StatusOK || !strings.Contains(unescape(pp.body), "La règle serait violée par 1 constat ouvert aujourd'hui") {
		t.Fatalf("aperçu : %d", pp.status)
	}
	if ps, _ := a.policies.List(ctx, f.org.ID); len(ps) != 0 {
		t.Fatal("l'aperçu a enregistré la règle")
	}
	good.Set("action", "save")
	if p := ab.post("/o/org-a/policies", good); p.status != http.StatusSeeOther || p.location != "/o/org-a/policies?done=policy_saved" {
		t.Fatalf("enregistrement : %d %s", p.status, p.body)
	}
	ps, _ := a.policies.List(ctx, f.org.ID)
	if len(ps) != 1 || len(ps[0].Channels) != 1 || !ps[0].Blocking {
		t.Fatalf("politiques %+v", ps)
	}
	pol := ps[0]
	if err := a.policies.EvaluateProject(ctx, f.org.ID, f.p.ID); err != nil {
		t.Fatal(err)
	}
	if n := a.countIn(f.org.ID, `SELECT count(*) FROM notification_deliveries WHERE state = 'pending'`); n != 1 {
		t.Fatalf("envois en attente : %d", n)
	}
	if err := a.notify.Send(ctx, f.org.ID, ch.ID, notify.ModeImmediate); err != nil {
		t.Fatal(err)
	}
	a.sent.mu.Lock()
	last := a.sent.requests[len(a.sent.requests)-1]
	a.sent.mu.Unlock()
	if last.URL != "https://hooks.example.org/lotor2" || !strings.Contains(string(last.Body), "CVE-2021-44228") {
		t.Fatalf("notification %s %s", last.URL, last.Body)
	}

	// Verdict par l'API des agents : non conforme.
	snap := a.snapshotOf(f)
	vr := a.api(http.MethodGet, "/api/v1/agent/snapshots/"+snap+"/verdict", f.token, nil)
	var v struct {
		State, Summary string
		Blocking       int
		Policies       []string
		URL            string `json:"url"`
	}
	if vr.status != http.StatusOK || json.Unmarshal([]byte(vr.body), &v) != nil || v.State != "fail" || v.Blocking != 1 ||
		len(v.Policies) != 1 || !strings.HasPrefix(v.Summary, "Non conforme") || !strings.Contains(v.URL, "/o/org-a/projects/") {
		t.Fatalf("verdict : %d %s", vr.status, vr.body)
	}
	if r := a.api(http.MethodGet, "/api/v1/agent/snapshots/"+pol.ID.String()+"/verdict", f.token, nil); r.status != http.StatusNotFound {
		t.Fatalf("instantané inconnu : %d", r.status)
	}

	// Lecteur : violations et tableau de bord, mais ni règles ni canaux.
	rb := a.signIn(reader)
	for _, path := range []string{"/o/org-a/policies", "/o/org-a/channels", "/o/org-a/policies/new", chURL} {
		if p := rb.get(path); p.status != http.StatusForbidden {
			t.Errorf("%s pour un lecteur : %d", path, p.status)
		}
	}
	vp := unescape(rb.get("/o/org-a/violations").body)
	if !strings.Contains(vp, "CVE-2021-44228") || !strings.Contains(vp, "KEV prod") {
		t.Fatal("violation absente de la liste d'un lecteur")
	}
	dp := unescape(rb.get("/o/org-a/").body)
	if !strings.Contains(dp, "Alertes") || !strings.Contains(dp, "Ouvertes : 1 · bloquantes : 1") {
		t.Fatal("section Alertes absente du tableau de bord")
	}

	// Écrans : deux langues, accessibilité, aucune ligne de code en ligne.
	polURL := "/o/org-a/policies/" + pol.ID.String()
	adminPages := []string{"/o/org-a/policies", "/o/org-a/policies/new", "/o/org-a/policies/new?template=" + policy.TemplateAgentSilent,
		polURL, polURL + "/delete", "/o/org-a/channels", "/o/org-a/channels/new", chURL, chURL + "/delete",
		"/o/org-a/violations", "/o/org-a/violations?state=resolved", "/o/org-a/violations?policy=" + pol.ID.String(), "/o/org-a/"}
	for _, u := range []struct {
		b     *browser
		pages []string
	}{{ab, adminPages}, {rb, []string{"/o/org-a/violations", "/o/org-a/"}}} {
		for _, lang := range []string{"fr", "en"} {
			for _, path := range u.pages {
				sep := "?"
				if strings.Contains(path, "?") {
					sep = "&"
				}
				pg := u.b.get(path + sep + "lang=" + lang)
				if pg.status != http.StatusOK {
					t.Fatalf("%s (%s) : %d %s", path, lang, pg.status, pg.body)
				}
				webtest.AssertAccessible(t, []byte(pg.body))
				webtest.AssertNoInlineCode(t, []byte(pg.body))
			}
		}
	}

	// Isolement : une autre organisation ne voit rien et reçoit 404.
	other := a.user("other@example.org", false)
	a.org("org-b", other)
	ob := a.signIn(other)
	for _, path := range []string{"/o/org-a/policies", polURL, chURL, "/o/org-a/violations"} {
		if p := ob.get(path); p.status != http.StatusNotFound {
			t.Errorf("%s depuis org-b : %d", path, p.status)
		}
	}
	if p := ob.get("/o/org-b/policies/" + pol.ID.String()); p.status != http.StatusNotFound {
		t.Errorf("politique de org-a sous org-b : %d", p.status)
	}
	if p := ob.post("/o/org-b/channels/"+ch.ID.String()+"/test", url.Values{}); p.status != http.StatusNotFound {
		t.Errorf("essai du canal de org-a depuis org-b : %d", p.status)
	}
	if body := unescape(ob.get("/o/org-b/violations").body); strings.Contains(body, "CVE-2021-44228") {
		t.Error("violation de org-a visible depuis org-b")
	}

	// Suppressions avec confirmation, journalisées.
	if p := ab.post(polURL+"/delete", url.Values{}); p.status != http.StatusSeeOther {
		t.Fatalf("suppression de la politique : %d", p.status)
	}
	if p := ab.post(chURL+"/delete", url.Values{}); p.status != http.StatusSeeOther {
		t.Fatalf("suppression du canal : %d", p.status)
	}
	if n := a.countIn(f.org.ID, `SELECT count(*) FROM audit_events WHERE action IN ('policy.created', 'policy.deleted',
		'channel.created', 'channel.updated', 'channel.deleted', 'channel.tested')`); n != 8 {
		t.Fatalf("audit : %d événements", n)
	}
	if n := a.countIn(f.org.ID, `SELECT count(*) FROM audit_events WHERE details::text LIKE '%' || $1 || '%'`, secret); n != 0 {
		t.Fatal("secret dans le journal d'audit")
	}
	if strings.Contains(a.logs.String(), secret) {
		t.Fatal("secret dans les journaux")
	}
}

// snapshotOf renvoie l'instantané courant de la branche main du dépôt.
func (a *app) snapshotOf(f repoFixture) string {
	a.t.Helper()
	var id string
	if err := a.tdb.App.InOrg(context.Background(), f.org.ID, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT snapshot_id::text FROM ref_current WHERE project_id = $1`, f.p.ID).Scan(&id)
	}); err != nil {
		a.t.Fatal(err)
	}
	return id
}
