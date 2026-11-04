//go:build integration

package web

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/hostagent"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/offline"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/webtest"
)

// hostArchive écrit l'archive d'un agent serveur : jeton d'agent token (en clair),
// projet projectID (nul pour une archive d'inscription), référence d'hôte host, SBOM data ;
// enrollment, s'il n'est pas vide, est le jeton d'inscription (en clair) d'une inscription
// hors ligne.
func hostArchive(t *testing.T, token, enrollment string, projectID uuid.UUID, host string, scanned time.Time, data []byte) []byte {
	t.Helper()
	pub, key, err := offline.ParseToken("agt", token)
	if err != nil {
		t.Fatal(err)
	}
	m := offline.Manifest{AgentToken: pub, CreatedAt: time.Now().UTC(), Context: offline.Context{ProjectID: projectID,
		Ref: offline.Ref{Kind: "host", Name: host}, AgentVersion: "0.3.0", ScannedAt: scanned,
		Host: &offline.Host{Hostname: host, OSID: "debian", OSVersion: "12"}}}
	keys := offline.Keys{Agent: key}
	if enrollment != "" {
		enrID, enrKey, err := offline.ParseToken("enr", enrollment)
		if err != nil {
			t.Fatal(err)
		}
		m.Enrollment = &offline.Enrollment{TokenID: enrID, Hostname: host, Version: "0.3.0", AgentHash: hexOf(key)}
		keys.Enrollment = &enrKey
	}
	var buf bytes.Buffer
	if err := offline.Write(&buf, m, keys, gzipBytes(t, data)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func hexOf(b [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, c := range b {
		out[2*i], out[2*i+1] = digits[c>>4], digits[c&15]
	}
	return string(out)
}

func (a *app) countIngestions(o tenant.OrgID) int {
	a.t.Helper()
	var n int
	if err := a.tdb.App.InOrg(context.Background(), o, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT count(*) FROM ingestions`).Scan(&n)
	}); err != nil {
		a.t.Fatal(err)
	}
	return n
}

// decodeAll décode les ingestions en attente d'une organisation (les jobs ne tournent pas
// dans les tests d'écran).
func (a *app) decodeAll(o tenant.OrgID) {
	a.t.Helper()
	ctx := context.Background()
	var ids []uuid.UUID
	if err := a.tdb.App.InOrg(ctx, o, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM ingestions WHERE status = 'queued'`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}); err != nil {
		a.t.Fatal(err)
	}
	for _, id := range ids {
		if err := a.ingest.Decode(ctx, o, id); err != nil {
			a.t.Fatal(err)
		}
	}
}

// Aller-retour agent → archive → import : même instantané qu'un envoi réseau, un seul
// instantané pour une archive importée deux fois, archive falsifiée ou d'une autre
// organisation refusée, inscription hors ligne par la première archive, droit de gérer les
// agents exigé.
func TestOfflineArchiveImport(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin, reader := a.user("admin@example.org", false), a.user("reader@example.org", false)
	oa := a.org("org-a", admin)
	ob := a.org("org-b", a.user("b@example.org", false))
	a.addTeamMember(oa, reader, tenant.TeamReader)
	ctx := context.Background()
	_, enr, err := a.agents.CreateEnrollment(ctx, audit.System, oa.ID, a.enrollTeam(oa.ID, agent.EnrollmentInput{Name: "parc", LifetimeHours: 24, MaxUses: 5}))
	if err != nil {
		t.Fatal(err)
	}
	_, e1 := a.enroll(enr.Plaintext, "srv-01")
	_, e2 := a.enroll(enr.Plaintext, "srv-02")
	data := sbomFile(t, "debian-12.cdx15.json")
	scanned := time.Now().UTC().Add(-2 * time.Hour).Round(time.Microsecond)

	// Envoi réseau de srv-02, archive de srv-01 : même ensemble d'inventaire.
	r := a.upload(e2.Token, []part{contextPart(t, map[string]any{"project_id": e2.Project.ID, "ref": map[string]string{"kind": "host", "name": "srv-02"},
		"agent_version": "0.3.0", "scanned_at": scanned}), {name: "sbom", contentType: "application/json", body: data}})
	if r.status != 202 {
		t.Fatalf("envoi réseau : %d %s", r.status, r.body)
	}
	archive := hostArchive(t, e1.Token, "", uuid.MustParse(e1.Project.ID), "srv-01", scanned, data)
	b := a.signIn(admin)
	page := b.get("/o/org-a/agents/import")
	if page.status != 200 {
		t.Fatalf("écran : %d", page.status)
	}
	webtest.AssertAccessible(t, []byte(page.body))
	webtest.AssertNoInlineCode(t, []byte(page.body))
	imp := b.uploadTo("/o/org-a/agents/import", uploadPart{name: "archive", file: "srv-01.lotor", value: string(archive)})
	if imp.status != 200 || !strings.Contains(unescape(imp.body), "Archive importée") {
		t.Fatalf("import : %d %s", imp.status, imp.body)
	}
	webtest.AssertAccessible(t, []byte(imp.body))
	a.decodeAll(oa.ID)
	var sets []string
	if err := a.tdb.App.InOrg(ctx, oa.ID, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT encode(cs.fingerprint, 'hex') FROM ref_current rc
			JOIN component_sets cs ON cs.org_id = rc.org_id AND cs.id = rc.set_id ORDER BY rc.project_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			sets = append(sets, s)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(sets) != 2 || sets[0] != sets[1] {
		t.Fatalf("ensembles réseau et archive : %v", sets)
	}
	// Même archive importée une seconde fois : la même réception, rien de neuf.
	before := a.countIngestions(oa.ID)
	if again := b.uploadTo("/o/org-a/agents/import", uploadPart{name: "archive", file: "srv-01.lotor", value: string(archive)}); again.status != 200 ||
		!strings.Contains(unescape(again.body), "Archive déjà importée") || a.countIngestions(oa.ID) != before {
		t.Fatalf("double import : %d", again.status)
	}
	// Archive modifiée après coup : son code ne correspond plus.
	forged := bytes.Replace(archive, []byte(`"0.3.0"`), []byte(`"9.9.9"`), 1)
	if p := b.uploadTo("/o/org-a/agents/import", uploadPart{name: "archive", file: "x.lotor", value: string(forged)}); p.status != 422 ||
		!strings.Contains(unescape(p.body), "pas de cet agent") {
		t.Errorf("archive falsifiée : %d", p.status)
	}
	// Archive d'un agent d'une autre organisation.
	_, enrB, err := a.agents.CreateEnrollment(ctx, audit.System, ob.ID, a.enrollTeam(ob.ID, agent.EnrollmentInput{Name: "b", LifetimeHours: 24, MaxUses: 1}))
	if err != nil {
		t.Fatal(err)
	}
	_, eb := a.enroll(enrB.Plaintext, "srv-b")
	foreign := hostArchive(t, eb.Token, "", uuid.MustParse(eb.Project.ID), "srv-b", scanned, data)
	if p := b.uploadTo("/o/org-a/agents/import", uploadPart{name: "archive", file: "b.lotor", value: string(foreign)}); p.status != 422 ||
		!strings.Contains(unescape(p.body), "appartient pas à cette organisation") {
		t.Errorf("archive d'une autre organisation : %d", p.status)
	}
	// Inscription hors ligne : agent jamais connecté, jeton tiré par lui.
	raw, pub, _, err := offline.NewAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	iso := hostArchive(t, raw, enr.Plaintext, uuid.Nil, "srv-iso", scanned, data)
	if p := b.uploadTo("/o/org-a/agents/import", uploadPart{name: "archive", file: "iso.lotor", value: string(iso)}); p.status != 200 ||
		!strings.Contains(unescape(p.body), "inscrit l") {
		t.Fatalf("inscription hors ligne : %d %s", p.status, p.body)
	}
	a.decodeAll(oa.ID)
	if _, err := a.projects.Get(ctx, oa.ID, tenant.AllTeams(), "srv-iso"); err != nil {
		t.Fatalf("projet de l'hôte inscrit hors ligne : %v", err)
	}
	// Le jeton tiré par l'agent ouvre ensuite l'API, en ligne ; une seconde archive (sans
	// projet, avec la même inscription) va au même projet.
	if hb := a.api("POST", "/api/v1/agent/heartbeat", raw, map[string]string{"version": "0.3.0"}); hb.status != 200 {
		t.Errorf("jeton hors ligne en ligne : %d %s", hb.status, hb.body)
	}
	iso2 := hostArchive(t, raw, enr.Plaintext, uuid.Nil, "srv-iso", scanned.Add(time.Hour), sbomFile(t, "ubuntu-24.04.cdx17.json"))
	if p := b.uploadTo("/o/org-a/agents/import", uploadPart{name: "archive", file: "iso2.lotor", value: string(iso2)}); p.status != 200 {
		t.Fatalf("seconde archive : %d %s", p.status, p.body)
	}
	if strings.Contains(a.logs.String(), raw) || strings.Contains(a.logs.String(), enr.Plaintext) || strings.Contains(a.logs.String(), pub+"_") {
		t.Error("jeton dans les journaux")
	}
	// Lecteur d'une équipe : pas le droit de gérer les agents.
	rb := a.signIn(reader)
	if p := rb.get("/o/org-a/agents/import"); p.status != 403 {
		t.Errorf("écran pour un lecteur : %d", p.status)
	}
	if p := rb.uploadTo("/o/org-a/agents/import", uploadPart{name: "archive", file: "x.lotor", value: string(archive)}); p.status != 403 {
		t.Errorf("import par un lecteur : %d", p.status)
	}
	// Par l'API utilisateur : jeton d'un administrateur, corps brut ; 201 puis 200.
	_, adminPAT, err := a.accounts.CreatePersonalToken(ctx, audit.System, admin.ID, "import", 30)
	if err != nil {
		t.Fatal(err)
	}
	_, readerPAT, err := a.accounts.CreatePersonalToken(ctx, audit.System, reader.ID, "import", 30)
	if err != nil {
		t.Fatal(err)
	}
	apiArchive := hostArchive(t, e1.Token, "", uuid.MustParse(e1.Project.ID), "srv-01", scanned.Add(30*time.Minute), sbomFile(t, "ubuntu-24.04.cdx17.json"))
	post := func(tok string, body []byte) apiResponse {
		return a.dtRequest("POST", "/api/v1/orgs/org-a/archives", "", "application/octet-stream", body, "Authorization", "Bearer "+tok)
	}
	if r := post(adminPAT.Plaintext, apiArchive); r.status != 201 || !strings.Contains(r.body, `"duplicate":false`) || !strings.Contains(r.body, e1.Project.ID) {
		t.Errorf("import par l'API : %d %s", r.status, r.body)
	}
	if r := post(adminPAT.Plaintext, apiArchive); r.status != 200 || !strings.Contains(r.body, `"duplicate":true`) {
		t.Errorf("second import par l'API : %d %s", r.status, r.body)
	}
	if r := post(readerPAT.Plaintext, apiArchive); r.status != 403 {
		t.Errorf("import par un lecteur : %d %s", r.status, r.body)
	}
	if r := post(adminPAT.Plaintext, foreign); r.status != 422 || r.problem(t)["type"] != agent.KeyArchiveForeign {
		t.Errorf("archive étrangère par l'API : %d %s", r.status, r.body)
	}
	if r := post(adminPAT.Plaintext, []byte("x")); r.status != 422 || r.problem(t)["type"] != agent.KeyArchiveInvalid {
		t.Errorf("corps illisible par l'API : %d %s", r.status, r.body)
	}
	if r := a.dtRequest("POST", "/api/v1/orgs/org-b/archives", "", "application/octet-stream", foreign, "Authorization", "Bearer "+adminPAT.Plaintext); r.status != 404 {
		t.Errorf("organisation dont il n'est pas membre : %d", r.status)
	}
	// Fichier qui n'est pas une archive.
	if p := b.uploadTo("/o/org-a/agents/import", uploadPart{name: "archive", file: "x.lotor", value: "pas une archive"}); p.status != 422 {
		t.Errorf("fichier illisible : %d", p.status)
	}
}

// Répertoire surveillé : chaque archive est importée dans l'organisation qu'elle désigne,
// rangée dans done/ (ou failed/ avec la clé du refus) ; la même archive déposée de nouveau
// ne crée rien ; les fichiers cachés et les autres extensions sont ignorés.
func TestOfflineWatchDir(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	oa := a.org("org-a", a.user("admin@example.org", false))
	ob := a.org("org-b", a.user("b@example.org", false))
	ctx := context.Background()
	enroll := func(o tenant.OrgID, host string) enrolled {
		_, enr, err := a.agents.CreateEnrollment(ctx, audit.System, o, a.enrollTeam(o, agent.EnrollmentInput{Name: host, LifetimeHours: 24, MaxUses: 1}))
		if err != nil {
			t.Fatal(err)
		}
		_, e := a.enroll(enr.Plaintext, host)
		return e
	}
	ea, eb := enroll(oa.ID, "srv-a"), enroll(ob.ID, "srv-b")
	scanned := time.Now().UTC().Add(-time.Hour)
	data := sbomFile(t, "debian-12.cdx15.json")
	good := hostArchive(t, ea.Token, "", uuid.MustParse(ea.Project.ID), "srv-a", scanned, data)
	other := hostArchive(t, eb.Token, "", uuid.MustParse(eb.Project.ID), "srv-b", scanned, data)
	forged := bytes.Replace(good, []byte(`"0.3.0"`), []byte(`"6.6.6"`), 1)
	dir := t.TempDir()
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.lotor", good)
	write("b.lotor", other)
	write("forged.lotor", forged)
	write(".en-cours.lotor", good)
	write("notes.txt", []byte("x"))
	w := &ingest.Watcher{Importer: &ingest.Importer{Ingest: a.ingest, Agents: a.agents, Logger: slog.New(slog.DiscardHandler)},
		Dir: dir, Interval: time.Hour}
	for _, d := range []string{"done", "failed"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := w.Scan(ctx)
	if err != nil || rep.Imported != 2 || rep.Failed != 1 || rep.Duplicates != 0 {
		t.Fatalf("premier passage : %+v %v", rep, err)
	}
	if a.countIngestions(oa.ID) != 1 || a.countIngestions(ob.ID) != 1 {
		t.Fatalf("ingestions : %d, %d", a.countIngestions(oa.ID), a.countIngestions(ob.ID))
	}
	reason, err := os.ReadFile(filepath.Join(dir, "failed", "forged.lotor.error"))
	if err != nil || strings.TrimSpace(string(reason)) != agent.KeyArchiveForged {
		t.Errorf("refus : %q %v", reason, err)
	}
	for _, f := range []string{"done/a.lotor", "done/b.lotor", "failed/forged.lotor", ".en-cours.lotor", "notes.txt"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s : %v", f, err)
		}
	}
	write("a-encore.lotor", good)
	if rep, err := w.Scan(ctx); err != nil || rep.Duplicates != 1 || a.countIngestions(oa.ID) != 1 {
		t.Errorf("archive redéposée : %+v %v", rep, err)
	}
}

// Aller-retour avec le vrai agent serveur (T23, critère 1) : un lotor-host-agent en sortie
// seule hors ligne, jamais inscrit, inventorie testdata/rootfs et écrit son archive ;
// importée, elle inscrit l'agent et donne le même ensemble d'inventaire qu'un envoi réseau
// du même scan par un autre agent, en ligne.
func TestOfflineHostAgentRoundTrip(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	a.decoder()
	admin := a.user("admin@example.org", false)
	o := a.org("org-a", admin)
	ctx := context.Background()
	_, enr, err := a.agents.CreateEnrollment(ctx, audit.System, o.ID, a.enrollTeam(o.ID, agent.EnrollmentInput{Name: "site", LifetimeHours: 24, MaxUses: 2}))
	if err != nil {
		t.Fatal(err)
	}
	srv, caFile := a.tlsAPI(nil)
	dir := filepath.Join(t.TempDir(), "archives")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	isolated := a.hostAgent(srv, caFile, enr.Plaintext, agentclient.TLSOptions{}, func(o *hostagent.Options) {
		o.Config.Offline = hostagent.Offline{Dir: dir, Only: true}
		o.Config.Hostname, o.Client = "srv-isole", nil
		o.Scanner = hostagent.SyftScanner{Root: o.Config.Scan.Root, Hostname: "srv-isole", Parallelism: 2, Version: "1.0.0-test"}
	})
	res, err := isolated.Cycle(ctx)
	if err != nil || res.Outcome != hostagent.OutcomeArchived || res.Components < 7 {
		t.Fatalf("cycle hors ligne : %+v %v", res, err)
	}
	if n := a.countIngestions(o.ID); n != 0 {
		t.Fatalf("%d ingestions avant l'import", n)
	}
	archive, err := os.ReadFile(res.Archive)
	if err != nil {
		t.Fatal(err)
	}
	b := a.signIn(admin)
	if p := b.uploadTo("/o/org-a/agents/import", uploadPart{name: "archive", file: filepath.Base(res.Archive), value: string(archive)}); p.status != 200 {
		t.Fatalf("import : %d %s", p.status, p.body)
	}
	// Le même scan par un agent en ligne.
	online := a.hostAgent(srv, caFile, enr.Plaintext, agentclient.TLSOptions{})
	if r, err := online.Cycle(ctx); err != nil || r.Outcome != hostagent.OutcomeSent {
		t.Fatalf("cycle en ligne : %+v %v", r, err)
	}
	waitFor(t, "décodage", func() bool {
		var n int
		_ = a.tdb.App.InOrg(ctx, o.ID, func(tx *db.OrgTx) error {
			return tx.QueryRowContext(ctx, `SELECT count(*) FROM ingestions WHERE status = 'done'`).Scan(&n)
		})
		return n == 2
	})
	var hosts []string
	var sets int
	if err := a.tdb.App.InOrg(ctx, o.ID, func(tx *db.OrgTx) error {
		if err := tx.QueryRowContext(ctx, `SELECT count(DISTINCT set_id) FROM ref_current`).Scan(&sets); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT r.name FROM ref_current rc JOIN tracked_refs r ON r.org_id = rc.org_id AND r.id = rc.ref_id ORDER BY 1`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err != nil {
				return err
			}
			hosts = append(hosts, h)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(hosts, ",") != "srv-agent-01,srv-isole" || sets != 1 {
		t.Fatalf("instantanés : %v, %d ensembles", hosts, sets)
	}
}

// waitFor attend cond (10 s au plus).
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s : délai dépassé", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
