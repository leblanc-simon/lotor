//go:build integration

package policy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/delivery"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	"leblanc.io/lotor/internal/secret"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/vuln"
	"leblanc.io/lotor/internal/vuln/vulntest"
	"leblanc.io/lotor/locales"
)

const log4j = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

var actor = audit.Actor{Email: "admin@example.org", IP: "192.0.2.1"}

// env : une base, la chaîne ingestion → analyse (base de vulnérabilités factice), le
// service des politiques et celui des notifications, et une organisation avec un dépôt.
type env struct {
	t        *testing.T
	pool     *db.Pool
	ingest   *ingest.Service
	analyzer *finding.Analyzer
	source   *vulntest.Source
	checker  *vuln.Checker
	engine   *vulntest.Engine
	dir      string
	policies *Service
	notifier *notify.Service
	box      *secret.Box
	catalog  *locale.Catalog
	clock    time.Time
	org      tenant.OrgID
	agent    uuid.UUID
	repo     uuid.UUID
	main     uuid.UUID
	scans    int
	pubs     int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	validator, err := schema.New()
	if err != nil {
		t.Fatal(err)
	}
	ing, err := ingest.NewService(ingest.Options{Pool: d.App, Validator: validator, Logger: slog.New(slog.DiscardHandler),
		Limits: ingest.Limits{MaxUpload: 8 << 20, SBOM: sbom.Limits{MaxBytes: 32 << 20, MaxDepth: 64, MaxComponents: 20_000}}})
	if err != nil {
		t.Fatal(err)
	}
	box, err := secret.New(map[string][]byte{"k1": []byte(strings.Repeat("k", 32))}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := locale.New(locales.FS, ".", "fr")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, pool: d.App, ingest: ing, source: &vulntest.Source{}, box: box, catalog: cat,
		clock: time.Now().UTC().Truncate(time.Second)}
	now := func() time.Time { return e.clock }
	e.policies = NewService(Options{Pool: d.App, Compiler: c, PublicURL: "https://sbom.example.org", Now: now})
	sender := delivery.New(delivery.Options{Timeout: 5 * time.Second, AllowPrivate: true})
	e.notifier = notify.NewService(notify.Options{Pool: d.App, Secrets: box, Sender: sender, Loader: e.policies, Catalog: cat,
		PublicURL: "https://sbom.example.org", Now: now})
	engine := &vulntest.Engine{}
	dir := t.TempDir()
	e.checker = vuln.NewChecker(vuln.CheckerOptions{Pool: d.App, Source: e.source, Engine: engine, Dir: dir, MaxArchive: 1 << 20})
	manager := vuln.NewManager(vuln.ManagerOptions{Pool: d.App, Engine: engine, Dir: dir})
	e.analyzer = finding.NewAnalyzer(finding.Options{Pool: d.App, Engine: manager, Blobs: ing, OnAnalyzed: OnAnalyzed})
	e.engine, e.dir = engine, dir
	e.org, e.agent, e.repo, e.main = e.newOrg("api", `{"env": "production"}`)
	return e
}

func newID() uuid.UUID { return uuid.Must(uuid.NewV7()) }

// newOrg crée une organisation, un agent dépôt et un dépôt « slug » aux étiquettes labels.
func (e *env) newOrg(slug, labels string) (tenant.OrgID, uuid.UUID, uuid.UUID, uuid.UUID) {
	e.t.Helper()
	org, err := tenant.NewOrgID()
	if err != nil {
		e.t.Fatal(err)
	}
	agent, repo, main := newID(), newID(), newID()
	suffix := strings.ReplaceAll(org.String()[24:], "-", "")
	e.exec(org, `WITH o AS (INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, 'Acme', 'en') RETURNING id)
		INSERT INTO teams (org_id, id, name) SELECT id, id, 'General' FROM o`, org, "o-"+suffix)
	e.exec(org, `INSERT INTO agents (org_id, id, kind, name) VALUES ($1, $2, 'repo', 'agent')`, org, agent)
	e.exec(org, `INSERT INTO projects (org_id, id, kind, slug, name, agent_id, team_id, labels)
		VALUES ($1, $2, 'repo', $3, $3, $4, $1, $5)`, org, repo, slug, agent, labels)
	e.exec(org, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', 'main')`,
		org, main, repo)
	return org, agent, repo, main
}

func (e *env) exec(org tenant.OrgID, query string, args ...any) {
	e.t.Helper()
	if err := e.pool.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(context.Background(), query, args...)
		return err
	}); err != nil {
		e.t.Fatalf("%s : %v", query, err)
	}
}

func (e *env) count(org tenant.OrgID, query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), query, args...).Scan(&n)
	}); err != nil {
		e.t.Fatalf("%s : %v", query, err)
	}
	return n
}

// jobs compte les jobs en attente d'un type (table globale).
func (e *env) jobs(kind string) int {
	e.t.Helper()
	var n int
	if err := e.pool.InTx(context.Background(), func(tx *db.Tx) error {
		return tx.QueryRowContext(context.Background(), `SELECT count(*) FROM jobs WHERE kind = $1 AND status = 'pending'`, kind).Scan(&n)
	}); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sbom", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// push envoie le SBOM log4shell sur la branche main du dépôt de org et le décode ; il
// renvoie l'instantané produit.
func (e *env) push(org tenant.OrgID, agent, repo uuid.UUID, data []byte) uuid.UUID {
	e.t.Helper()
	e.scans++
	c := ingest.Context{ProjectID: repo, RefKind: project.RefBranch, RefName: "main", Commit: fmt.Sprintf("%040x", e.scans),
		AgentVersion: "1.0.0", ScannedAt: time.Now().Add(-time.Hour + time.Duration(e.scans)*time.Second)}
	in, err := e.ingest.Receive(context.Background(), org, agent, c, strings.NewReader(string(data)))
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.ingest.Decode(context.Background(), org, in.ID); err != nil {
		e.t.Fatal(err)
	}
	got, err := e.ingest.Get(context.Background(), org, agent, in.ID)
	if err != nil || got.SnapshotID == nil {
		e.t.Fatalf("ingestion %+v : %v", got, err)
	}
	return *got.SnapshotID
}

// publish annonce une base contenant log4shell et en fait la cible.
func (e *env) publish(fix vuln.FixState) {
	e.t.Helper()
	rule := vulntest.Rule{PURL: log4j,
		Vuln: vuln.Vulnerability{ID: "CVE-2021-44228", Namespace: "nvd:cpe", Severity: vuln.SeverityCritical, KEV: &vuln.KEV{},
			CVSS: []vuln.CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", BaseScore: 10}}, Risk: 99},
		Match: vuln.Match{FixedVersions: []string{"2.15.0"}, FixState: fix, Risk: 99}}
	if fix != vuln.FixFixed {
		rule.Match.FixedVersions = nil
	}
	e.pubs++
	built := time.Now().UTC().Add(-time.Hour + time.Duration(e.pubs)*time.Minute).Truncate(time.Second)
	e.source.Publish(vulntest.Archive(e.t, vulntest.Content{Built: built, Rules: []vulntest.Rule{rule}}), built, "")
	if _, err := e.checker.Check(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) analyze(org tenant.OrgID, ref uuid.UUID) {
	e.t.Helper()
	if _, err := e.analyzer.Analyze(context.Background(), org, ref); err != nil {
		e.t.Fatal(err)
	}
}

// receiver est un destinataire de webhook simulé : il refuse les fail premières requêtes
// (canal en panne), puis accepte et garde chaque message accepté.
type receiver struct {
	srv *httptest.Server

	mu         sync.Mutex
	fail       int
	attempts   int
	accepted   []http.Header
	bodies     []string
	deliveries []string
}

func newReceiver(t *testing.T, fail int) *receiver {
	r := &receiver{fail: fail}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.attempts++
		r.deliveries = append(r.deliveries, req.Header.Get(notify.HeaderDelivery))
		if r.fail > 0 {
			r.fail--
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		r.accepted = append(r.accepted, req.Header.Clone())
		r.bodies = append(r.bodies, string(body))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) snapshot() (attempts int, accepted []string, deliveries []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempts, append([]string(nil), r.bodies...), append([]string(nil), r.deliveries...)
}

// webhook crée un canal webhook générique vers r.
func (e *env) webhook(org tenant.OrgID, r *receiver, secret string) notify.Channel {
	e.t.Helper()
	c, err := e.notifier.CreateChannel(context.Background(), org, actor, notify.Input{Name: "hook-" + newID().String()[30:],
		Kind: notify.KindWebhook, Enabled: true, Settings: notify.Settings{URL: r.srv.URL + "/hook"}, Secret: secret})
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// fromTemplate crée une politique à partir d'un modèle.
func (e *env) fromTemplate(org tenant.OrgID, key string, channels ...uuid.UUID) Policy {
	e.t.Helper()
	tpl, ok := TemplateByKey(key)
	if !ok {
		e.t.Fatalf("modèle %s", key)
	}
	p, err := e.policies.Create(context.Background(), org, actor, Input{Name: key, Subject: tpl.Subject,
		Expression: tpl.Expression, Template: key, Enabled: true, Blocking: tpl.Blocking, Delivery: tpl.Delivery, Channels: channels})
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *env) evaluate(org tenant.OrgID, projectID uuid.UUID) {
	e.t.Helper()
	if err := e.policies.EvaluateProject(context.Background(), org, projectID); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) open(org tenant.OrgID, policyID uuid.UUID) int {
	return e.count(org, `SELECT count(*) FROM policy_violations WHERE policy_id = $1 AND resolved_at IS NULL`, policyID)
}

func fmtSscan(s string, v *int64) (int, error) { return fmt.Sscan(s, v) }

func jobsExecution(org tenant.OrgID) jobs.Execution {
	return jobs.Execution{OrgID: org, Attempt: 1, MaxAttempts: 1}
}

func jobsExecutionWith(org tenant.OrgID, payload string) jobs.Execution {
	e := jobsExecution(org)
	e.Payload = []byte(payload)
	return e
}
