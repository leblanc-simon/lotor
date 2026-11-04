package repoagent

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"leblanc.io/lotor/internal/forge"
)

func writeSecret(t *testing.T, dir, name, value string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(value), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadSecret(t *testing.T) {
	dir := t.TempDir()
	ok := writeSecret(t, dir, "tok", "lotor_agt_x\n", 0o600)
	if got, err := ReadSecret(ok); err != nil || string(got) != "lotor_agt_x" {
		t.Fatalf("%q %v", got, err)
	}
	ro := writeSecret(t, dir, "ro", "v", 0o400)
	if _, err := ReadSecret(ro); err != nil {
		t.Fatal(err)
	}
	for name, ref := range map[string]string{
		"lisible par le groupe": writeSecret(t, dir, "g", "v", 0o640),
		"lisible par tous":      writeSecret(t, dir, "o", "v", 0o604),
		"vide":                  writeSecret(t, dir, "e", "\n", 0o600),
		"trop gros":             writeSecret(t, dir, "big", strings.Repeat("x", maxSecret+1), 0o600),
		"relatif":               "tok",
		"absent":                filepath.Join(dir, "absent"),
		"répertoire":            dir,
		"non configuré":         "",
	} {
		if _, err := ReadSecret(ref); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

func TestReadSecretFromSystemdCredential(t *testing.T) {
	dir := t.TempDir()
	writeSecret(t, dir, "agent-token", "secret", 0o400)
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if got, err := ReadSecret("credential:agent-token"); err != nil || string(got) != "secret" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"credential:", "credential:../agent-token", "credential:a/b", "credential:.."} {
		if _, err := ReadSecret(bad); err == nil {
			t.Errorf("%s accepté", bad)
		}
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := ReadSecret("credential:agent-token"); err == nil {
		t.Fatal("sans CREDENTIALS_DIRECTORY")
	}
}

func validConfig() Config {
	c := Defaults()
	c.Server = ServerConfig{URL: "https://sbom.example.org", TokenFile: "credential:agent-token", Timeout: time.Minute, Retries: 5}
	c.Webhook = WebhookConfig{Listen: ":1762", MaxBodyKiB: 1024, RateLimit: 60}
	c.Work = WorkConfig{Dir: "/var/lib/x", Parallelism: 2, QueueSize: 10, CloneTimeout: time.Minute, ScanTimeout: time.Minute, MaxCloneMiB: 10, Git: "git"}
	c.Catchup = CatchupConfig{Interval: 15 * time.Minute, MaxCommits: 20}
	c.AI = testAIConfig()
	c.Forges = []Forge{
		{Name: "github", Kind: forge.KindGitHub, AppID: "1", PrivateKeyFile: "credential:gh-key", WebhookSecretFile: "credential:gh-hook",
			AllowedNamespaces: []string{"*"}},
		{Name: "gitlab", Kind: forge.KindGitLab, URL: "https://gitlab.example.org", TokenFile: "credential:gl-token", WebhookSecretFile: "credential:gl-hook",
			AllowedNamespaces: []string{"g", "Plateforme/Equipe"}},
	}
	return c
}

func TestValidate(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Config){
		"url":            func(c *Config) { c.Server.URL = "sbom.example.org" },
		"url identifiée": func(c *Config) { c.Server.URL = "https://a:b@sbom" },
		"jeton":          func(c *Config) { c.Server.TokenFile = "" },
		"délai serveur":  func(c *Config) { c.Server.Timeout = 0 },
		"écoute":         func(c *Config) { c.Webhook.Listen = "1762" },
		"tls":            func(c *Config) { c.Webhook.TLSCertFile = "/c.pem" },
		"corps":          func(c *Config) { c.Webhook.MaxBodyKiB = 0 },
		"débit":          func(c *Config) { c.Webhook.RateLimit = -1 },
		"répertoire":     func(c *Config) { c.Work.Dir = "work" },
		"parallélisme":   func(c *Config) { c.Work.Parallelism = 0 },
		"file":           func(c *Config) { c.Work.QueueSize = 0 },
		"délais":         func(c *Config) { c.Work.CloneTimeout = 0 },
		"taille":         func(c *Config) { c.Work.MaxCloneMiB = 0 },
		"git":            func(c *Config) { c.Work.Git = "" },
		"intervalle":     func(c *Config) { c.Catchup.Interval = time.Second },
		"commits":        func(c *Config) { c.Catchup.MaxCommits = 0 },
		"sans forge":     func(c *Config) { c.Forges = nil },
		"doublon":        func(c *Config) { c.Forges[1].Name = "github" },
		"nom":            func(c *Config) { c.Forges[0].Name = "Git Hub" },
		"nature":         func(c *Config) { c.Forges[0].Kind = "forgejo" },
		"secret webhook": func(c *Config) { c.Forges[0].WebhookSecretFile = "" },
		"app github":     func(c *Config) { c.Forges[0].AppID = "" },
		"jeton github":   func(c *Config) { c.Forges[0].TokenFile = "/x" },
		"jeton gitlab":   func(c *Config) { c.Forges[1].TokenFile = "" },
		"app gitlab":     func(c *Config) { c.Forges[1].AppID = "1" },
		"délai forge":    func(c *Config) { c.Forges[1].Timeout = -time.Second },
		"sans périmètre": func(c *Config) { c.Forges[0].AllowedNamespaces = nil },
		"périmètre vide": func(c *Config) { c.Forges[0].AllowedNamespaces = []string{""} },
		"motif partiel":  func(c *Config) { c.Forges[0].AllowedNamespaces = []string{"acme*"} },
		"chemin absolu":  func(c *Config) { c.Forges[0].AllowedNamespaces = []string{"/acme"} },
	}
	for name, mutate := range cases {
		c := validConfig()
		c.Forges = append([]Forge(nil), c.Forges...)
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	c := validConfig()
	c.Webhook.Listen = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("sans récepteur : %v", err)
	}
}

func TestProviders(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	writeSecret(t, dir, "gh-key", string(pemKey), 0o600)
	writeSecret(t, dir, "gh-hook", "h1", 0o600)
	writeSecret(t, dir, "gl-token", "glpat", 0o600)
	writeSecret(t, dir, "gl-hook", "h2", 0o600)
	t.Setenv("CREDENTIALS_DIRECTORY", dir)

	ps, err := validConfig().Providers()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].Kind() != forge.KindGitHub || ps[1].Kind() != forge.KindGitLab {
		t.Fatalf("%v", ps)
	}
	if _, ok := ps[1].Repo("https://gitlab.example.org/g/p"); !ok {
		t.Fatal("URL GitLab")
	}
	// Périmètre de l'agent (SEC-10) : groupes autorisés et leurs sous-groupes, sans
	// tenir compte de la casse ; un préfixe de nom ne suffit pas.
	for url, want := range map[string]bool{
		"https://gitlab.example.org/plateforme/equipe/app": true,
		"https://gitlab.example.org/g/sous/p":              true,
		"https://gitlab.example.org/gg/p":                  false,
		"https://gitlab.example.org/plateforme/autre":      false,
		"https://gitlab.example.org/autre/p":               false,
	} {
		if _, ok := ps[1].Repo(url); ok != want {
			t.Errorf("%s : reconnu %v, attendu %v", url, ok, want)
		}
	}
	if _, ok := ps[0].Repo("https://github.com/quiconque/app"); !ok {
		t.Error("« * » n'autorise pas tout")
	}

	c := validConfig()
	c.Forges[0].PrivateKeyFile = "credential:gh-hook" // pas une clé
	if _, err := c.Providers(); err == nil {
		t.Fatal("clé invalide acceptée")
	}
	c = validConfig()
	c.Forges[1].TokenFile = "credential:absent"
	if _, err := c.Providers(); err == nil {
		t.Fatal("jeton absent accepté")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `server:
  url: https://sbom.example.org
work:
  dir: /var/lib/lotor-repo-agent/work
forges:
  - name: github
    kind: github
    app_id: "123"
    private_key_file: credential:github-key
    webhook_secret_file: credential:github-webhook
    allowed_namespaces: [acme]
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	os.Args = []string{"lotor-repo-agent", "-c", path}
	c, err := Load("lotor-repo-agent", "test", "/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.TokenFile != "credential:agent-token" || c.Work.Parallelism != 2 || c.Catchup.Interval != 15*time.Minute ||
		c.Webhook.Listen != ":1762" || c.Logging.Level != "info" || c.Forges[0].AppID != "123" {
		t.Fatalf("%+v", c)
	}
}

// La configuration d'exemple livrée se charge et se valide.
func TestExampleConfig(t *testing.T) {
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	os.Args = []string{"lotor-repo-agent", "-c", "../../deploy/lotor-repo-agent/config.example.yaml"}
	c, err := Load("lotor-repo-agent", "test", "/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Forges) != 2 || c.Forges[0].Kind != forge.KindGitHub || c.Forges[1].TokenFile != "credential:gitlab-token" {
		t.Fatalf("%+v", c.Forges)
	}
}

func TestDependencyTrackConfig(t *testing.T) {
	d := DTConfig{URL: "https://dtrack.example.org", APIKeyFile: "credential:dependency-track-api-key",
		ProjectName: "{name} ({slug})", ProjectVersion: "{ref}", AutoCreate: true}
	if got := d.Target("Portail", "portail", "main"); got.ProjectName != "Portail (portail)" || got.ProjectVersion != "main" || !got.AutoCreate {
		t.Errorf("gabarits : %+v", got)
	}
	c := validConfig()
	c.DependencyTrack = d
	if err := c.Validate(); err != nil {
		t.Errorf("configuration valide refusée : %v", err)
	}
	for name, bad := range map[string]DTConfig{
		"http":         {URL: "http://dtrack", APIKeyFile: "credential:x", ProjectName: "{name}", ProjectVersion: "{ref}"},
		"sans clé":     {URL: "https://dtrack", ProjectName: "{name}", ProjectVersion: "{ref}"},
		"gabarit vide": {URL: "https://dtrack", APIKeyFile: "credential:x", ProjectName: " ", ProjectVersion: "{ref}"},
		"identifiants": {URL: "https://u:p@dtrack", APIKeyFile: "credential:x", ProjectName: "{name}", ProjectVersion: "{ref}"},
	} {
		c.DependencyTrack = bad
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "dependency_track") {
			t.Errorf("%s : %v", name, err)
		}
	}
	// Sortie désactivée : rien n'est lu ni construit.
	if s, err := NewDTSender(DTConfig{}, ServerConfig{}, ServerOptions{}); s != nil || err != nil {
		t.Errorf("sortie désactivée : %v %v", s, err)
	}
}
