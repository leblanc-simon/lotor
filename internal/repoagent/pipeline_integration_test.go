//go:build integration

package repoagent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/forge"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	sbomsyft "leblanc.io/lotor/internal/sbom/syft"
)

// testRepo est un dépôt de test : une copie de travail et son dépôt nu.
type testRepo struct {
	t       *testing.T
	work    string
	bare    string // <root>/acme/app.git
	root    string
	outside string // répertoire hors du dépôt, visé par les liens piégés
	commits []string
}

// gitCmd lance git hors de toute configuration de la machine.
func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=Test", "-c", "user.email=t@example.org",
		"-c", "init.defaultBranch=main", "-c", "core.symlinks=true"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v : %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const goModV1 = `module example.org/app

go 1.22

require github.com/google/uuid v1.6.0
`

// newTestRepo crée un dépôt de trois commits : go.mod, puis requirements.txt, puis une
// seconde dépendance Go. Le premier commit porte des liens symboliques piégés vers un
// répertoire extérieur qui contient un manifeste « trap-pkg » : si un lien était suivi,
// ce paquet apparaîtrait dans le SBOM.
func newTestRepo(t *testing.T) *testRepo {
	t.Helper()
	base := t.TempDir()
	r := &testRepo{t: t, work: filepath.Join(base, "work"), root: filepath.Join(base, "forge"), outside: filepath.Join(base, "outside")}
	r.bare = filepath.Join(r.root, "acme", "app.git")
	writeFile(t, filepath.Join(r.outside, "requirements.txt"), "trap-pkg==6.6.6\n")
	writeFile(t, filepath.Join(r.outside, "go.mod"), "module trap.example/trap\n\ngo 1.22\n\nrequire trap.example/pkg v6.6.6\n")

	gitCmd(t, base, "init", "--quiet", r.work)
	writeFile(t, filepath.Join(r.work, "go.mod"), goModV1)
	for name, target := range map[string]string{
		"passwd":   "/etc/passwd",
		"escape":   r.outside,
		"relative": "../../outside/requirements.txt",
	} {
		if err := os.Symlink(target, filepath.Join(r.work, name)); err != nil {
			t.Fatal(err)
		}
	}
	r.commit("premier")
	writeFile(t, filepath.Join(r.work, "requirements.txt"), "requests==2.31.0\n")
	r.commit("python")
	writeFile(t, filepath.Join(r.work, "go.mod"), goModV1+"require golang.org/x/text v0.14.0\n")
	r.commit("go")

	gitCmd(t, base, "clone", "--quiet", "--bare", r.work, r.bare)
	gitCmd(t, r.bare, "config", "uploadpack.allowReachableSHA1InWant", "true")
	gitCmd(t, r.bare, "config", "http.receivepack", "false")
	return r
}

func (r *testRepo) commit(msg string) {
	gitCmd(r.t, r.work, "add", "-A")
	gitCmd(r.t, r.work, "commit", "--quiet", "-m", msg)
	r.commits = append(r.commits, gitCmd(r.t, r.work, "rev-parse", "HEAD"))
}

// push ajoute un commit et le publie dans le dépôt nu.
func (r *testRepo) push(file, content string) string {
	writeFile(r.t, filepath.Join(r.work, file), content)
	r.commit("suite")
	gitCmd(r.t, r.work, "push", "--quiet", r.bare, "main")
	return r.commits[len(r.commits)-1]
}

func (r *testRepo) fileURL() string { return "file://" + r.bare }

// recordingGit est un git enveloppé qui note ses arguments, pour vérifier qu'aucun
// identifiant n'y figure (ce que montrerait ps).
func recordingGit(t *testing.T) (binary, argLog string) {
	t.Helper()
	dir := t.TempDir()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	argLog = filepath.Join(dir, "args.log")
	binary = filepath.Join(dir, "git")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + argLog + "\nexec " + real + " \"$@\"\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return binary, argLog
}

func TestCheckoutNeutralisesSymlinks(t *testing.T) {
	r := newTestRepo(t)
	dir := filepath.Join(t.TempDir(), "src")
	g := gitRunner{binary: "git", maxBytes: 64 << 20, timeout: time.Minute}
	if err := g.checkout(context.Background(), dir, r.fileURL(), forge.Credentials{}, r.commits[0]); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"passwd", "escape", "relative"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("%s : %v, fichier ordinaire attendu", name, info.Mode())
		}
		data, _ := os.ReadFile(filepath.Join(dir, name))
		if strings.Contains(string(data), "root:") || strings.Contains(string(data), "trap-pkg") {
			t.Fatalf("%s : contenu de la cible extrait", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); !os.IsNotExist(err) {
		t.Fatal(".git conservé")
	}
	if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); !os.IsNotExist(err) {
		t.Fatal("un autre commit que le premier a été extrait")
	}

	// Commit inconnu du dépôt : échec net.
	other := filepath.Join(t.TempDir(), "src")
	if err := g.checkout(context.Background(), other, r.fileURL(), forge.Credentials{}, strings.Repeat("e", 40)); err == nil {
		t.Fatal("commit inconnu extrait")
	}
	if err := g.checkout(context.Background(), other, r.fileURL(), forge.Credentials{}, "--upload-pack=touch /tmp/x"); err == nil {
		t.Fatal("commit invalide accepté")
	}
	if err := g.checkout(context.Background(), other, "https://u:p@example.org/x.git", forge.Credentials{}, r.commits[0]); err == nil {
		t.Fatal("URL avec identifiants acceptée")
	}
}

func TestEnsureNoSymlinksRefuses(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "x")); err != nil {
		t.Fatal(err)
	}
	if err := ensureNoSymlinks(dir); !errors.Is(err, ErrSymlink) {
		t.Fatalf("%v", err)
	}
}

// decodeSBOM valide le SBOM produit par le schéma officiel strict, puis le décode comme
// le serveur.
// scan catalogue dir et encode le SBOM, comme le fait l'agent sans enrichissement.
func (s scanner) scan(ctx context.Context, dir, name, commit string) ([]byte, error) {
	bom, err := s.scanBOM(ctx, dir, name, commit)
	if err != nil {
		return nil, err
	}
	return encodeBOM(bom)
}

func decodeSBOM(t *testing.T, data []byte) sbom.Document {
	t.Helper()
	v, err := schema.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.ValidateStrict(sbom.FormatCycloneDX, "1.6", data); err != nil {
		t.Fatalf("SBOM invalide : %v", err)
	}
	doc, err := sbomsyft.Decode(sbom.FormatCycloneDX, data)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func names(doc sbom.Document) map[string]sbom.Component {
	out := map[string]sbom.Component{}
	for _, c := range doc.Components {
		out[c.Name] = c
	}
	return out
}

func TestScanProducesDeterministicCycloneDX(t *testing.T) {
	r := newTestRepo(t)
	dir := filepath.Join(t.TempDir(), "src")
	g := gitRunner{binary: "git", maxBytes: 64 << 20, timeout: time.Minute}
	if err := g.checkout(context.Background(), dir, r.fileURL(), forge.Credentials{}, r.commits[2]); err != nil {
		t.Fatal(err)
	}
	s := scanner{agentVersion: "1.0.0"}
	data, err := s.scan(context.Background(), dir, "app", r.commits[2])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), dir) || strings.Contains(string(data), r.outside) {
		t.Fatal("chemin local dans le SBOM")
	}
	var raw struct {
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Component struct {
				Name, Version string
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.SerialNumber != "" || raw.Metadata.Timestamp != "" {
		t.Fatal("numéro de série ou horodatage présent")
	}
	if raw.Metadata.Component.Name != "app" || raw.Metadata.Component.Version != r.commits[2] {
		t.Fatalf("composant décrit %+v", raw.Metadata.Component)
	}
	doc := decodeSBOM(t, data)
	got := names(doc)
	for _, want := range []string{"github.com/google/uuid", "golang.org/x/text", "requests"} {
		c, ok := got[want]
		if !ok {
			t.Fatalf("%s absent : %v", want, got)
		}
		if c.Origin != sbom.OriginSyft {
			t.Fatalf("%s : origine %q", want, c.Origin)
		}
	}
	for n := range got {
		if strings.Contains(n, "trap") {
			t.Fatalf("lien symbolique suivi : %s", n)
		}
	}
	again, err := s.scan(context.Background(), dir, "app", r.commits[2])
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(data) {
		t.Fatal("deux analyses du même commit diffèrent")
	}
}

func TestCloneTooLargeLeavesNothing(t *testing.T) {
	r := newTestRepo(t)
	big := make([]byte, 3<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	head := r.push("blob.bin", string(big))
	f := &fakeForge{name: "fake", cloneURL: r.fileURL()}
	f.setHead(mainRef, head)
	srv := &fakeServer{projects: []Project{{ID: "p1", Slug: "app", ForgeURL: "https://fake.example/acme/app", Refs: []TrackedRef{{Ref: mainRef}}}}}
	logs := &syncBuffer{}
	a := newTestAgent(t, srv, f, logs, func(o *Options) { o.Work.MaxCloneMiB = 1 })
	a.refresh(srv.projects)
	a.processRef(context.Background(), refKey{"p1", mainRef})
	if len(srv.uploads) != 0 || !strings.Contains(logs.String(), ErrTooLarge.Error()) {
		t.Fatalf("envois %d ; journal %s", len(srv.uploads), logs.String())
	}
	assertEmpty(t, a.opts.Work.Dir)
	// Échec définitif : le même commit n'est pas retenté.
	if !a.failures.has("p1" + head) {
		t.Fatal("échec définitif non retenu")
	}
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("fichiers résiduels : %v", entries)
	}
}

// fakeGitHub simule github.com pour une GitHub App : API (installation, jeton,
// références, comparaison) et service git HTTP (git http-backend), qui exige le jeton
// d'installation.
type fakeGitHub struct {
	srv   *httptest.Server
	repo  *testRepo
	token string
	delay time.Duration

	mu    sync.Mutex
	clone int
}

func newFakeGitHub(t *testing.T, r *testRepo) *fakeGitHub {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGitHub{repo: r, token: "ghs_installation_secret"}
	backend := &cgi.Handler{
		Path: gitPath, Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + r.root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/repos/acme/app/installation", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 7})
	})
	mux.HandleFunc("POST /api/app/installations/7/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": f.token, "expires_at": time.Now().Add(time.Hour)})
	})
	mux.HandleFunc("GET /api/repos/acme/app/commits/heads/main", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": gitCmd(t, f.repo.bare, "rev-parse", "main")})
	})
	mux.HandleFunc("GET /api/repos/acme/app/compare/{spec}", func(w http.ResponseWriter, r *http.Request) {
		base, head, _ := strings.Cut(r.PathValue("spec"), "...")
		out := gitCmd(t, f.repo.bare, "rev-list", "--reverse", base+".."+head)
		var commits []map[string]string
		for _, c := range strings.Fields(out) {
			commits = append(commits, map[string]string{"sha": c})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"commits": commits})
	})
	mux.Handle("/acme/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+f.token))
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		f.clone++
		delay := f.delay
		f.mu.Unlock()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		backend.ServeHTTP(w, r)
	}))
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) provider(t *testing.T, secret string) *forge.GitHub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	g, err := forge.NewGitHub(forge.GitHubConfig{
		Name: "github", URL: f.srv.URL, APIURL: f.srv.URL + "/api", AppID: "1", PrivateKey: key,
		WebhookSecret: []byte(secret), HTTPClient: f.srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func signedPush(t *testing.T, url, secret, delivery, after string) *http.Response {
	t.Helper()
	body := []byte(`{"ref":"refs/heads/main","after":"` + after + `","repository":{"full_name":"acme/app"}}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", delivery)
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// commits liste les commits envoyés au serveur simulé, dans l'ordre.
func (s *fakeServer) commits() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, u := range s.uploads {
		out = append(out, u.Commit)
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("délai dépassé : %s", what)
}

// TestPipelineGitHub parcourt tout le pipeline contre une GitHub App simulée : rattrapage
// au démarrage depuis le dernier commit connu du serveur (commits manqués du plus ancien
// au plus récent), puis push signé, push mal signé, rejeu ; identifiants absents des
// arguments de git et des journaux ; répertoire de travail vide à la fin.
func TestPipelineGitHub(t *testing.T) {
	r := newTestRepo(t)
	gh := newFakeGitHub(t, r)
	const secret = "webhook-secret"
	provider := gh.provider(t, secret)
	gitBin, argLog := recordingGit(t)

	srv := &fakeServer{projects: []Project{{
		ID: "p1", Slug: "app", Name: "Application", ForgeURL: gh.srv.URL + "/acme/app",
		Refs: []TrackedRef{{Ref: mainRef, LastCommit: r.commits[0]}},
	}}}
	logs := &syncBuffer{}
	dt := &recordingDT{}
	a := newTestAgent(t, srv, provider, logs, func(o *Options) {
		o.Work.Git = gitBin
		o.DT, o.DTConfig = dt, DTConfig{ProjectName: "{name}", ProjectVersion: "{ref}", AutoCreate: true}
	})
	rc, err := NewReceiver([]forge.Provider{provider}, a.OnPush, 1<<20, 0, nil, testLogger(logs))
	if err != nil {
		t.Fatal(err)
	}
	hooks := httptest.NewServer(rc.Handler())
	defer hooks.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- a.Run(ctx) }()

	// Redémarrage : le serveur connaît le premier commit ; les deux suivants sont rattrapés
	// dans l'ordre.
	waitFor(t, "rattrapage", func() bool { return len(srv.commits()) == 2 })
	if got := srv.commits(); got[0] != r.commits[1] || got[1] != r.commits[2] {
		t.Fatalf("ordre du rattrapage : %v", got)
	}
	srv.mu.Lock()
	u := srv.uploads[1]
	srv.mu.Unlock()
	if u.ProjectID != "p1" || u.Ref != mainRef || u.AgentVersion != "test" || u.ScannedAt.IsZero() {
		t.Fatalf("envoi %+v", u)
	}
	if _, ok := names(decodeSBOM(t, u.SBOM))["golang.org/x/text"]; !ok {
		t.Fatal("dépendance du dernier commit absente")
	}
	// Dependency-Track ne reçoit que le commit de tête du rattrapage, même SBOM que lotor.
	if got := dt.all(); len(got) != 1 || got[0].target != (agentclient.DTTarget{ProjectName: "Application", ProjectVersion: "main", AutoCreate: true}) ||
		!bytes.Equal(got[0].bom, u.SBOM) {
		t.Fatalf("envois à Dependency-Track : %+v", got)
	}

	// Push mal signé : refusé, rien n'est analysé.
	head := r.push("package.json", `{"name":"app","version":"1.0.0"}`)
	if resp := signedPush(t, hooks.URL+"/webhooks/github", "wrong", "d0", head); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("push mal signé : %d", resp.StatusCode)
	}
	// Push signé : instantané pour ce commit.
	if resp := signedPush(t, hooks.URL+"/webhooks/github", secret, "d1", head); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("push : %d", resp.StatusCode)
	}
	waitFor(t, "push", func() bool { return len(srv.commits()) == 3 })
	waitFor(t, "push vers Dependency-Track", func() bool { return len(dt.all()) == 2 })
	if got := srv.commits()[2]; got != head {
		t.Fatalf("commit envoyé %s, attendu %s", got, head)
	}
	// Rejeu de la même livraison : ignoré.
	if resp := signedPush(t, hooks.URL+"/webhooks/github", secret, "d1", head); resp.StatusCode != http.StatusOK {
		t.Fatalf("rejeu : %d", resp.StatusCode)
	}
	// Push signé d'un ancien commit (livraison neuve) : la tête est résolue, rien de neuf.
	if resp := signedPush(t, hooks.URL+"/webhooks/github", secret, "d2", r.commits[0]); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("ancien push : %d", resp.StatusCode)
	}
	time.Sleep(time.Second)
	if n := len(srv.commits()); n != 3 {
		t.Fatalf("%d envois après un push dépassé", n)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertEmpty(t, a.opts.Work.Dir)

	args, err := os.ReadFile(argLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "fetch") {
		t.Fatalf("git non appelé : %s", args)
	}
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + gh.token))
	for _, leak := range []string{gh.token, basic, secret} {
		if strings.Contains(string(args), leak) {
			t.Fatalf("identifiant dans les arguments de git : %s", args)
		}
		if strings.Contains(logs.String(), leak) {
			t.Fatalf("identifiant dans les journaux : %s", logs.String())
		}
	}
	if !strings.Contains(logs.String(), "signature invalide") {
		t.Fatal("refus non journalisé")
	}
}

func TestCloneTimeoutLeavesNothing(t *testing.T) {
	r := newTestRepo(t)
	gh := newFakeGitHub(t, r)
	gh.delay = 30 * time.Second
	provider := gh.provider(t, "s")
	srv := &fakeServer{projects: []Project{{ID: "p1", Slug: "app", ForgeURL: gh.srv.URL + "/acme/app", Refs: []TrackedRef{{Ref: mainRef}}}}}
	logs := &syncBuffer{}
	a := newTestAgent(t, srv, provider, logs, func(o *Options) { o.Work.CloneTimeout = time.Second })
	a.refresh(srv.projects)
	start := time.Now()
	a.processRef(context.Background(), refKey{"p1", mainRef})
	if time.Since(start) > 15*time.Second {
		t.Fatal("délai de clonage non respecté")
	}
	if len(srv.uploads) != 0 || !strings.Contains(logs.String(), ErrCloneTimeout.Error()) {
		t.Fatalf("journal : %s", logs.String())
	}
	assertEmpty(t, a.opts.Work.Dir)
	// Délai dépassé : l'erreur n'est pas définitive, le commit sera retenté.
	if a.failures.has("p1" + r.commits[2]) {
		t.Fatal("délai dépassé retenu comme définitif")
	}
}

func TestWrongCredentialsFailCleanly(t *testing.T) {
	r := newTestRepo(t)
	f := &fakeForge{name: "fake", cloneURL: r.fileURL(), history: r.commits, failCmp: true}
	f.setHead(mainRef, r.commits[2])
	srv := &fakeServer{
		projects:  []Project{{ID: "p1", Slug: "app", ForgeURL: "https://fake.example/acme/app", Refs: []TrackedRef{{Ref: mainRef, LastCommit: r.commits[0]}}}},
		uploadErr: errors.Join(ErrRejected, errors.New("413")),
	}
	logs := &syncBuffer{}
	a := newTestAgent(t, srv, f, logs)
	a.refresh(srv.projects)
	a.processRef(context.Background(), refKey{"p1", mainRef})
	// Comparaison impossible : la tête seule est analysée ; refus définitif retenu.
	if !strings.Contains(logs.String(), "comparaison impossible") || !a.failures.has("p1"+r.commits[2]) {
		t.Fatalf("journal : %s", logs.String())
	}
	assertEmpty(t, a.opts.Work.Dir)
}
