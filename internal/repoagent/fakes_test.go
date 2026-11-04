package repoagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"leblanc.io/lotor/internal/forge"
)

// fakeForge est une forge en mémoire : têtes de références, comparaisons et URL de
// clonage locales (file://).
type fakeForge struct {
	name     string
	cloneURL string
	creds    forge.Credentials
	secret   string

	mu        sync.Mutex
	heads     map[forge.Ref]string
	history   []string // commits de la branche, du plus ancien au plus récent
	resolves  int
	compares  int
	failCmp   bool
	files     []string // fichiers modifiés renvoyés par Compare
	statuses  []publishedStatus
	statusErr error
}

// publishedStatus est un statut de commit publié sur la fausse forge.
type publishedStatus struct {
	Commit string
	Status forge.CommitStatus
}

func (f *fakeForge) SetStatus(_ context.Context, _ string, commit string, s forge.CommitStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusErr != nil {
		return f.statusErr
	}
	f.statuses = append(f.statuses, publishedStatus{Commit: commit, Status: s})
	return nil
}

func (f *fakeForge) published() []publishedStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]publishedStatus(nil), f.statuses...)
}

func (f *fakeForge) Name() string     { return f.name }
func (f *fakeForge) Kind() forge.Kind { return forge.KindGitHub }

func (f *fakeForge) Repo(u string) (string, bool) {
	r, ok := strings.CutPrefix(u, "https://fake.example/")
	return r, ok && r != ""
}

func (f *fakeForge) CloneURL(string) string { return f.cloneURL }

func (f *fakeForge) Credentials(context.Context, string) (forge.Credentials, error) {
	return f.creds, nil
}

func (f *fakeForge) ResolveRef(_ context.Context, _ string, ref forge.Ref) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolves++
	h, ok := f.heads[ref]
	if !ok {
		return "", forge.ErrNotFound
	}
	return h, nil
}

func (f *fakeForge) Compare(_ context.Context, _ string, base, head string) (forge.Comparison, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.compares++
	if f.failCmp {
		return forge.Comparison{}, errors.New("comparaison impossible")
	}
	c := forge.Comparison{Files: append([]string(nil), f.files...)}
	in := false
	for _, x := range f.history {
		if in {
			c.Commits = append(c.Commits, x)
		}
		if x == base {
			in = true
		}
		if x == head {
			break
		}
	}
	return c, nil
}

func (f *fakeForge) VerifyWebhook(h http.Header, body []byte) (*forge.Push, error) {
	if h.Get("X-Test-Secret") != f.secret {
		return nil, forge.ErrSignature
	}
	if len(body) == 0 {
		return nil, nil
	}
	if body[0] != '{' {
		return nil, forge.ErrPayload
	}
	ref, _ := forge.ParseGitRef(h.Get("X-Test-Ref"))
	return &forge.Push{Delivery: h.Get("X-Test-Delivery"), Repo: h.Get("X-Test-Repo"), Ref: ref}, nil
}

func (f *fakeForge) setHead(ref forge.Ref, commit string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.heads == nil {
		f.heads = map[forge.Ref]string{}
	}
	f.heads[ref] = commit
}

// fakeServer est un serveur lotor en mémoire.
type fakeServer struct {
	mu         sync.Mutex
	projects   []Project
	uploads    []Upload
	heartbeats int
	listErr    error
	uploadErr  error
	ai         map[string][]PreviousComponent // composants IA par référence
	aiCalls    int
	aiErr      error
	// verdicts sont rendus dans l'ordre par PolicyVerdict (le dernier se répète) ; aucun :
	// conforme.
	verdicts     []PolicyVerdict
	verdictCalls int
}

func (s *fakeServer) AIComponents(_ context.Context, refID string) ([]PreviousComponent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aiCalls++
	return append([]PreviousComponent(nil), s.ai[refID]...), s.aiErr
}

func (s *fakeServer) Verdict(context.Context, Receipt) (PolicyVerdict, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verdictCalls++
	if len(s.verdicts) == 0 {
		return PolicyVerdict{State: VerdictPass, Summary: "ok"}, nil
	}
	v := s.verdicts[0]
	if len(s.verdicts) > 1 {
		s.verdicts = s.verdicts[1:]
	}
	return v, nil
}

func (s *fakeServer) Projects(context.Context) ([]Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Project(nil), s.projects...), s.listErr
}

func (s *fakeServer) Heartbeat(context.Context, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heartbeats++
	return nil
}

func (s *fakeServer) Upload(_ context.Context, u Upload) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uploadErr != nil {
		return Receipt{}, s.uploadErr
	}
	s.uploads = append(s.uploads, u)
	// Le serveur range l'instantané : son commit devient le dernier connu.
	for i, p := range s.projects {
		if p.ID == u.ProjectID {
			for j, r := range p.Refs {
				if r.Ref == u.Ref {
					s.projects[i].Refs[j].LastCommit = u.Commit
				}
			}
		}
	}
	return Receipt{IngestionID: fmt.Sprintf("ingestion-%d", len(s.uploads))}, nil
}

// syncBuffer est un tampon de journal partagé entre goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func testLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func newTestAgent(t *testing.T, srv Server, f forge.Provider, logs io.Writer, mutate ...func(*Options)) *Agent {
	t.Helper()
	opts := Options{
		Server: srv, Forges: []forge.Provider{f}, Logger: testLogger(logs), Version: "test",
		Work: WorkConfig{
			Dir: t.TempDir(), Parallelism: 1, QueueSize: 100, CloneTimeout: defaultTestTimeout,
			ScanTimeout: defaultTestTimeout, MaxCloneMiB: 64, Git: "git",
		},
		Catchup: CatchupConfig{Interval: defaultTestTimeout, MaxCommits: 20},
	}
	for _, m := range mutate {
		m(&opts)
	}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
