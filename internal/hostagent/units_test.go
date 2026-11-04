package hostagent

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestReadMounts(t *testing.T) {
	info := `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw
40 22 0:35 / /mnt/partage\040commun rw,relatime shared:20 - nfs4 srv:/export rw,vers=4.2
41 22 0:36 / /var/lib/docker/overlay2/abc/merged rw shared:21 - overlay overlay rw,lowerdir=x
ligne illisible
42 22 0:37 / /net rw - autofs systemd-1 rw
`
	got := readMounts(strings.NewReader(info))
	want := []mount{{"/", "ext4"}, {"/proc", "proc"}, {"/mnt/partage commun", "nfs4"},
		{"/var/lib/docker/overlay2/abc/merged", "overlay"}, {"/net", "autofs"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("montages %+v", got)
	}
	// /proc l'est aussi par son type, où qu'il soit monté.
	if s := skippedMounts(got, "/"); !reflect.DeepEqual(s, []string{"/mnt/partage commun", "/net", "/proc", "/var/lib/docker/overlay2/abc/merged"}) {
		t.Errorf("montages exclus de / : %v", s)
	}
	if s := skippedMounts(got, "/mnt"); !reflect.DeepEqual(s, []string{"/partage commun"}) {
		t.Errorf("montages exclus de /mnt : %v", s)
	}
	if s := skippedMounts([]mount{{"/", "overlay"}}, "/"); len(s) != 0 {
		t.Errorf("une racine en overlay reste inventoriée : %v", s)
	}
	if u := unescapeMount(`/a\134b\011c\0`); u != "/a\\b\tc\\0" {
		t.Errorf("échappements : %q", u)
	}
}

func TestExclusionPatterns(t *testing.T) {
	got := exclusionPatterns([]string{"/proc", "/srv/data/**/cache/", "/proc", "/"}, []string{"/mnt/a [b]*"})
	want := []string{"./proc", "./srv/data/**/cache", `./mnt/a \[b\]\*`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("motifs %q", got)
	}
}

func TestParseOSRelease(t *testing.T) {
	vals := parseOSRelease(strings.NewReader("# commentaire\nID=rhel\nVERSION_ID=\"8.6\"\nPRETTY_NAME='Red Hat Enterprise Linux 8.6 (Ootpa)'\nINVALIDE\n"))
	if vals["ID"] != "rhel" || vals["VERSION_ID"] != "8.6" || vals["PRETTY_NAME"] != "Red Hat Enterprise Linux 8.6 (Ootpa)" {
		t.Errorf("os-release %v", vals)
	}
	h := hostInfo(testRoot(t), "srv")
	if h.OSID != "debian" || h.OSVersion != "12" || h.OSName != "Debian GNU/Linux 12 (bookworm)" || h.Kernel == "" || h.Arch == "" {
		t.Errorf("contexte %+v", h)
	}
	if id, _, _ := osRelease(t.TempDir()); id != "" {
		t.Errorf("sans os-release : %q", id)
	}
	if c := clip("é\x01tête", 4); c != "ét" {
		t.Errorf("clip %q", c)
	}
}

func validConfig() Config {
	c := Defaults()
	c.Mode, c.StateDir, c.Server.URL = ModeDaemon, "/var/lib/lotor-host-agent", "https://sbom.example.org"
	c.Server.Timeout, c.Server.Retries, c.Server.Language = time.Minute, 5, "en"
	c.Scan = Scan{Root: "/", Interval: 24 * time.Hour, PollInterval: 5 * time.Minute, MaxDuration: time.Hour}
	c.Resources = Resources{MaxProcs: 1, MemoryLimitMiB: 512}
	c.Containers = Containers{MaxImageMiB: 4096, Timeout: 30 * time.Second}
	return c
}

func TestConfigValidate(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	for name, f := range map[string]func(*Config){
		"mode":            func(c *Config) { c.Mode = "cron" },
		"http":            func(c *Config) { c.Server.URL = "http://sbom.example.org" },
		"url vide":        func(c *Config) { c.Server.URL = "" },
		"clé sans cert":   func(c *Config) { c.Server.ClientKeyFile = "/etc/k.pem" },
		"état relatif":    func(c *Config) { c.StateDir = "etat" },
		"jeton relatif":   func(c *Config) { c.EnrollmentTokenFile = "jeton" },
		"racine relative": func(c *Config) { c.Scan.Root = "rootfs" },
		"exclusion":       func(c *Config) { c.Scan.Exclude = []string{"proc"} },
		"intervalle":      func(c *Config) { c.Scan.Interval = time.Minute },
		"signal de vie":   func(c *Config) { c.Scan.PollInterval = time.Second },
		"durée":           func(c *Config) { c.Scan.MaxDuration = time.Second },
		"délai":           func(c *Config) { c.Server.Timeout = 0 },
		"réessais":        func(c *Config) { c.Server.Retries = 0 },
		"processeurs":     func(c *Config) { c.Resources.MaxProcs = 0 },
		"mémoire":         func(c *Config) { c.Resources.MemoryLimitMiB = 10 },
		"étiquette":       func(c *Config) { c.Labels = map[string]string{" ": "x"} },
		"socket relative": func(c *Config) { c.Containers.Sockets = []string{"docker.sock"} },
		"travail relatif": func(c *Config) { c.Containers.WorkDir = "images" },
		"image":           func(c *Config) { c.Containers.MaxImageMiB = 1 },
		"délai moteur":    func(c *Config) { c.Containers.Timeout = 0 },
	} {
		c := validConfig()
		f(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	c := validConfig()
	c.Server.ClientCertFile, c.Resources.MemoryLimitMiB = "/etc/c.pem", 0
	if err := c.Validate(); err != nil {
		t.Errorf("certificat sans clé (credential) et mémoire sans limite : %v", err)
	}
}

func TestLoadReadsFileAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := "mode: oneshot\nserver:\n  url: https://sbom.example.org\nlabels:\n  env: prod\nscan:\n  exclude: [/srv/cache]\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOTOR_HOST_AGENT_SCAN_INTERVAL", "12h")
	t.Setenv("LOTOR_HOST_AGENT_LOG_LEVEL", "debug")
	old := os.Args
	os.Args = []string{"lotor-host-agent", "-c", path}
	defer func() { os.Args = old }()
	cfg, err := Load("lotor-host-agent", "test", "/inexistant.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeOneshot || cfg.Scan.Interval != 12*time.Hour || cfg.Scan.PollInterval != 5*time.Minute ||
		cfg.Labels["env"] != "prod" || cfg.Scan.Exclude[0] != "/srv/cache" || cfg.Logging.Level != "debug" ||
		cfg.StateDir != "/var/lib/lotor-host-agent" || cfg.Resources.MaxProcs != 1 || cfg.Resources.MemoryLimitMiB != 512 ||
		cfg.Containers.Enabled || cfg.Containers.MaxImageMiB != 4096 || cfg.ImagesDir() != "/var/lib/lotor-host-agent/images" {
		t.Errorf("configuration %+v", cfg)
	}
}

func TestStoreKeepsTokenAndState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etat")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("répertoire d'état en %s", fi.Mode().Perm())
	}
	if tok, err := s.Token(); err != nil || tok != "" {
		t.Fatalf("jeton avant inscription : %q %v", tok, err)
	}
	if err := s.SaveToken("lotor_agt_a_b"); err != nil {
		t.Fatal(err)
	}
	if tok, err := s.Token(); err != nil || tok != "lotor_agt_a_b" {
		t.Fatalf("jeton relu : %q %v", tok, err)
	}
	fi, _ := os.Stat(filepath.Join(dir, tokenFile))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("jeton en %s", fi.Mode().Perm())
	}
	if st := s.Load(); st.Version != stateVersion || st.Fingerprint != "" {
		t.Errorf("état initial %+v", st)
	}
	st := State{AgentID: uuid.New(), RefName: "srv", Fingerprint: strings.Repeat("ab", 32), LastScan: time.Now().UTC().Truncate(time.Second)}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	got := s.Load()
	if fp, ok := got.fingerprint(); !ok || fp[0] != 0xab || got.RefName != "srv" || !got.LastScan.Equal(st.LastScan) {
		t.Errorf("état relu %+v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(`{"version": 99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := s.Load(); got.Fingerprint != "" {
		t.Errorf("état d'une autre version gardé : %+v", got)
	}
	if _, ok := (State{Fingerprint: "zz"}).fingerprint(); ok {
		t.Error("empreinte illisible acceptée")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Error("répertoire d'état ouvert à tous accepté")
	}
}

func TestSecretsMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jeton")
	if err := os.WriteFile(path, []byte("  lotor_enr_a_b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecret(path); !errors.Is(err, ErrInsecureSecret) {
		t.Errorf("jeton lisible par tous : %v", err)
	}
	// Dans le répertoire des credentials systemd, les droits sont ceux de systemd.
	t.Setenv(credentialsDirEnv, dir)
	if tok, err := readSecret(path); err != nil || tok != "lotor_enr_a_b" {
		t.Errorf("credential : %q %v", tok, err)
	}
	if p := resolveSecret("", "jeton", "/defaut"); p != path {
		t.Errorf("credential non trouvé : %q", p)
	}
	if p := resolveSecret("/configure", "jeton", "/defaut"); p != "/configure" {
		t.Errorf("fichier configuré ignoré : %q", p)
	}
	if p := resolveSecret("", "absent", "/defaut"); p != "/defaut" {
		t.Errorf("repli : %q", p)
	}
	if _, err := readSecret(dir); err == nil {
		t.Error("répertoire lu comme secret")
	}
	if _, err := readSecret(filepath.Join(dir, "absent")); err == nil {
		t.Error("secret absent lu")
	}
}
