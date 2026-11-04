package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const testDSN = "postgres://lotor_app:pwd@localhost:5432/lotor"

// load appelle Load avec des arguments de ligne de commande maîtrisés (appconf lit
// os.Args, qui porte sinon les options de go test).
func load(t *testing.T, args ...string) (Config, error) {
	t.Helper()
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = append([]string{"lotor-server", "-c", filepath.Join(t.TempDir(), "absent.yaml")}, args...)
	return Load("lotor-server", "test")
}

func valid() Config {
	c := Defaults()
	c.Web.Host, c.Web.Port, c.Web.RateLimit = "127.0.0.1", 1758, 100
	c.HTTP = HTTP{ReadHeaderTimeout: time.Second, ShutdownTimeout: time.Second}
	c.Management = Management{Host: "127.0.0.1", Port: 1761}
	c.Logging.Format = "text"
	c.Database.DSN = testDSN
	c.Database.MaxOpenConns, c.Database.MaxIdleConns = 10, 5
	c.Database.StartupTimeout = time.Second
	c.Migration.MaxConns = 2
	c.Secrets = Secrets{Keys: map[string]string{"k1": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}, ActiveKey: "k1"}
	c.Auth.SessionTTL, c.Auth.CookieSecure, c.Auth.BcryptCost = time.Hour, "auto", 12
	c.MFA.ChallengeTTL, c.MFA.MaxAttempts = time.Minute, 5
	c.MFA.LockoutThreshold, c.MFA.LockoutWindow, c.MFA.LockoutDuration, c.MFA.LockoutMaxDuration = 10, 15*time.Minute, 15*time.Minute, 24*time.Hour
	c.MFA.RecoveryCodes = 10
	c.Login.RateLimit, c.Login.SessionMaxAge = 10, 168*time.Hour
	c.AgentAPI = AgentAPI{RateLimit: 120, FailureRateLimit: 30}
	c.UserAPI = UserAPI{RateLimit: 60, FailureRateLimit: 30, ExportTimeout: 5 * time.Minute, MaxExports: 4}
	c.Workers = Workers{Enabled: true, Concurrency: 4, PollInterval: time.Second, Lease: 30 * time.Second,
		RetryBase: 10 * time.Second, RetryMax: 30 * time.Minute, Retention: time.Hour,
		ScheduleInterval: 10 * time.Second, ShutdownTimeout: 30 * time.Second, OrgLimit: 2}
	c.Ingest = Ingest{MaxUploadMiB: 32, MaxDecompressedMiB: 64, MaxDepth: 64, MaxComponents: 50000, DecodeTimeout: 5 * time.Minute,
		MaxPerRefPerDay: 200, MaxOrgStorageMiB: 10240, MaxReencodes: 2}
	c.VulnDB = defaultVulnDB
	c.Containers = Containers{ArchiveAfter: 168 * time.Hour, PurgeAfter: 4320 * time.Hour, MaxPerHost: 1000}
	c.Retention.Days = 90
	c.Notify = Notify{Timeout: 30 * time.Second, DigestHour: 7}
	c.SMTP = SMTP{Port: 587, TLS: "starttls", HELO: "localhost"}
	return c
}

var defaultVulnDB = VulnDB{ListingURL: "https://grype.anchore.io/databases/v6/latest.json", Dir: "/var/lib/lotor/vulndb",
	CheckInterval: 6 * time.Hour, SyncInterval: time.Minute, MaxAge: 120 * time.Hour, DownloadTimeout: 30 * time.Minute,
	MaxArchiveMiB: 2048, AnalysisTimeout: 10 * time.Minute}

func TestLoadFromEnvironmentWithDefaults(t *testing.T) {
	t.Setenv("LOTOR_DB_DSN", testDSN)
	t.Setenv("LOTOR_PORT", "9000")
	t.Setenv("LOTOR_DB_MAX_OPEN_CONNS", "7")
	t.Setenv("LOTOR_SECRETS_KEYS", "k1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	t.Setenv("LOTOR_SECRETS_ACTIVE_KEY", "k1")
	cfg, err := load(t)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Driver != "postgres" || cfg.I18n.DefaultLanguage != "fr" || cfg.Logging.Level != "info" {
		t.Errorf("défauts du projet non appliqués : %q %q %q", cfg.Database.Driver, cfg.I18n.DefaultLanguage, cfg.Logging.Level)
	}
	if cfg.Web.Port != 9000 || cfg.Database.DSN != testDSN || cfg.Database.MaxOpenConns != 7 {
		t.Errorf("variables non lues : %+v", cfg)
	}
	if cfg.Database.MaxIdleConns != 10 || cfg.HTTP.ShutdownTimeout != 30*time.Second || cfg.Migration.MaxConns != 2 || cfg.Management.Port != 1761 {
		t.Errorf("défauts env-default non appliqués : %+v", cfg)
	}
	if !cfg.Workers.Enabled || cfg.Workers.Concurrency != 4 || cfg.Workers.Retention != 168*time.Hour || cfg.Workers.OrgLimit != 2 {
		t.Errorf("défauts des workers : %+v", cfg.Workers)
	}
	if cfg.Ingest != (Ingest{MaxUploadMiB: 32, MaxDecompressedMiB: 64, MaxDepth: 64, MaxComponents: 50000, DecodeTimeout: 5 * time.Minute,
		MaxPerRefPerDay: 200, MaxOrgStorageMiB: 10240, MaxReencodes: 2}) ||
		MiB(cfg.Ingest.MaxUploadMiB) != 32<<20 {
		t.Errorf("défauts de l'ingestion : %+v", cfg.Ingest)
	}
	if cfg.VulnDB != defaultVulnDB {
		t.Errorf("défauts de la base de vulnérabilités : %+v", cfg.VulnDB)
	}
	if cfg.Notify != (Notify{Timeout: 30 * time.Second, DigestHour: 7}) || cfg.SMTP != (SMTP{Port: 587, TLS: "starttls", HELO: "localhost"}) {
		t.Errorf("défauts des notifications : %+v %+v", cfg.Notify, cfg.SMTP)
	}
	// Hors ligne, la liste n'est pas exigée.
	off := valid()
	off.VulnDB.Offline, off.VulnDB.ListingURL = true, ""
	if err := off.Validate(); err != nil {
		t.Errorf("hors ligne : %v", err)
	}
	if cfg.Secrets.Keys["k1"] == "" {
		t.Errorf("clés de secrets non lues : %v", cfg.Secrets.Keys)
	}
}

func TestDefaultWebPort(t *testing.T) {
	t.Setenv("LOTOR_DB_DSN", testDSN)
	t.Setenv("LOTOR_SECRETS_KEYS", "k1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	t.Setenv("LOTOR_SECRETS_ACTIVE_KEY", "k1")
	cfg, err := load(t)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Web.Port != 1758 {
		t.Errorf("port web par défaut = %d, attendu 1758", cfg.Web.Port)
	}
}

// --help termine le processus : le test se relance lui-même.
func TestHelpAnnouncesProjectDefaults(t *testing.T) {
	if os.Getenv("LOTOR_TEST_HELP") == "1" {
		os.Args = []string{"lotor-server", "--help"}
		_, _ = Load("lotor-server", "test")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelpAnnouncesProjectDefaults$")
	cmd.Env = append(os.Environ(), "LOTOR_TEST_HELP=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help : %v\n%s", err, out)
	}
	for _, want := range []string{`Listen port (default "1758")`, `(default "1761")`, `(default "lotor_session")`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("--help n'annonce pas %s :\n%s", want, out)
		}
	}
	if strings.Contains(string(out), `"8080"`) {
		t.Errorf("--help annonce encore le défaut d'appconf :\n%s", out)
	}
}

func TestLoadFromFileThenEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `
database:
  driver: postgres
  dsn: ` + testDSN + `
  max_open_conns: 5
  max_idle_conns: 2
i18n:
  default_language: en
http:
  shutdown_timeout: 5s
secrets:
  keys:
    k1: ` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)) + `
  active_key: k1
workers:
  enabled: false
retention:
  monthly: false
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOTOR_DB_MAX_IDLE_CONNS", "3")
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = []string{"lotor-server", "-c", path}
	cfg, err := Load("lotor-server", "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.MaxOpenConns != 5 || cfg.I18n.DefaultLanguage != "en" || cfg.HTTP.ShutdownTimeout != 5*time.Second {
		t.Errorf("fichier mal lu : %+v", cfg)
	}
	// Un false écrit dans le fichier n'est pas écrasé par un défaut.
	if cfg.Workers.Enabled {
		t.Error("workers.enabled: false ignoré")
	}
	if cfg.Retention.Monthly || !cfg.Retention.Enabled || cfg.Retention.Days != 90 {
		t.Errorf("rétention mal lue : %+v", cfg.Retention)
	}
	if cfg.Database.MaxIdleConns != 3 {
		t.Errorf("la variable d'environnement ne l'emporte pas : %d", cfg.Database.MaxIdleConns)
	}
}

func TestLoadReportsInvalidConfiguration(t *testing.T) {
	t.Setenv("LOTOR_DB_DSN", testDSN)
	t.Setenv("LOTOR_DB_DRIVER", "sqlite")
	_, err := load(t)
	if err == nil || !strings.Contains(err.Error(), "database.driver (LOTOR_DB_DRIVER)") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"web.public_url":     func(c *Config) { c.Web.PublicURL = "ftp://x" },
		"notify.timeout":     func(c *Config) { c.Notify.Timeout = time.Hour },
		"notify.digest_hour": func(c *Config) { c.Notify.DigestHour = 24 },
		"smtp.tls":           func(c *Config) { c.SMTP.Host, c.SMTP.From, c.SMTP.TLS = "smtp", "a@example.org", "ssl" },
		"smtp.from":          func(c *Config) { c.SMTP.Host, c.SMTP.From = "smtp", "Lotor <a@example.org>" },
		"smtp.port":          func(c *Config) { c.SMTP.Host, c.SMTP.From, c.SMTP.Port = "smtp", "a@example.org", 0 },
		"smtp.username": func(c *Config) {
			c.SMTP.Host, c.SMTP.From, c.SMTP.TLS, c.SMTP.Username = "smtp", "a@example.org", "none", "u"
		},
	} {
		c := valid()
		mutate(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s : %v", name, err)
		}
	}
	ok := valid()
	ok.Web.PublicURL = "https://sbom.example.org"
	ok.SMTP = SMTP{Host: "smtp.example.org", Port: 465, TLS: "tls", Username: "u", Password: "p", From: "lotor@example.org"}
	if err := ok.Validate(); err != nil {
		t.Errorf("notifications valides refusées : %v", err)
	}
	if !ok.MailConfigured() {
		t.Error("SMTP et URL publique : envoi de courriels attendu")
	}
	if c := valid(); c.MailConfigured() {
		t.Error("sans SMTP : aucun envoi de courriel attendu")
	}
	testValidateSignup(t, ok)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		field string
		edit  func(*Config)
	}{
		{"pilote", "database.driver (LOTOR_DB_DRIVER)", func(c *Config) { c.Database.Driver = "sqlite" }},
		{"DSN absent", "database.dsn (LOTOR_DB_DSN)", func(c *Config) { c.Database.DSN = "" }},
		{"DSN illisible", "database.dsn", func(c *Config) { c.Database.DSN = "postgres://h:port/x" }},
		{"pool vide", "database.max_open_conns", func(c *Config) { c.Database.MaxOpenConns = 0 }},
		{"inactives négatives", "database.max_idle_conns", func(c *Config) { c.Database.MaxIdleConns = -1 }},
		{"attente nulle", "database.startup_timeout", func(c *Config) { c.Database.StartupTimeout = 0 }},
		{"pool de migration", "migration.max_conns (LOTOR_MIGRATION_MAX_CONNS)", func(c *Config) { c.Migration.MaxConns = 1 }},
		{"même rôle pour migrer", "migration.dsn", func(c *Config) { c.Migration.DSN = testDSN }},
		{"port web", "web.port", func(c *Config) { c.Web.Port = 70000 }},
		{"proxy", "web.trusted_proxies", func(c *Config) { c.Web.TrustedProxies = []string{"10.0.0.0/33"} }},
		{"gestion sur le port web", "management.port", func(c *Config) { c.Management.Port = 1758 }},
		{"gestion sur toutes les interfaces", "management.port", func(c *Config) { c.Management = Management{Host: "0.0.0.0", Port: 1758} }},
		{"niveau de journal", "logging.level", func(c *Config) { c.Logging.Level = "verbose" }},
		{"format de journal", "logging.format", func(c *Config) { c.Logging.Format = "xml" }},
		{"langue", "i18n.default_language", func(c *Config) { c.I18n.DefaultLanguage = "x!" }},
		{"arrêt", "http.shutdown_timeout", func(c *Config) { c.HTTP.ShutdownTimeout = 0 }},
		{"en-têtes", "http.read_header_timeout", func(c *Config) { c.HTTP.ReadHeaderTimeout = 0 }},
		{"certificat sans clé", "tls.key_file", func(c *Config) { c.TLS.CertFile = certFile }},
		{"clé sans certificat", "tls.cert_file", func(c *Config) { c.TLS.KeyFile = certFile }},
		{"mTLS sans TLS", "tls.client_ca_file", func(c *Config) { c.TLS.ClientCAFile = certFile }},
		{"certificat absent", "tls.cert_file", func(c *Config) {
			c.TLS.CertFile, c.TLS.KeyFile = filepath.Join(dir, "absent.pem"), certFile
		}},
		{"CORS", "cors.max_age", func(c *Config) { c.CORS.MaxAge = -1 }},
		{"clé absente", "secrets.keys", func(c *Config) { c.Secrets = Secrets{} }},
		{"clé active absente", "secrets.keys", func(c *Config) { c.Secrets.ActiveKey = "k2" }},
		{"durée de session", "auth.session_ttl", func(c *Config) { c.Auth.SessionTTL = 0 }},
		{"nom du cookie", "auth.cookie_name", func(c *Config) { c.Auth.CookieName = "" }},
		{"cookie Secure", "auth.cookie_secure", func(c *Config) { c.Auth.CookieSecure = "yes" }},
		{"coût bcrypt", "auth.bcrypt_cost", func(c *Config) { c.Auth.BcryptCost = 4 }},
		{"émetteur TOTP", "mfa.issuer", func(c *Config) { c.MFA.Issuer = "" }},
		{"durée du défi", "mfa.challenge_ttl", func(c *Config) { c.MFA.ChallengeTTL = 0 }},
		{"tentatives TOTP", "mfa.max_attempts", func(c *Config) { c.MFA.MaxAttempts = 0 }},
		{"seuil de verrouillage", "mfa.lockout_threshold", func(c *Config) { c.MFA.LockoutThreshold = 0 }},
		{"fenêtre de verrouillage", "mfa.lockout_window", func(c *Config) { c.MFA.LockoutWindow = 0 }},
		{"durée de verrouillage", "mfa.lockout_duration", func(c *Config) { c.MFA.LockoutDuration = 0 }},
		{"plafond de verrouillage", "mfa.lockout_max_duration", func(c *Config) { c.MFA.LockoutMaxDuration = time.Minute }},
		{"codes de secours", "mfa.recovery_codes", func(c *Config) { c.MFA.RecoveryCodes = 2 }},
		{"limite de connexion", "login.rate_limit", func(c *Config) { c.Login.RateLimit = -1 }},
		{"durée absolue négative", "login.session_max_age", func(c *Config) { c.Login.SessionMaxAge = -1 }},
		{"durée absolue sous la durée glissante", "login.session_max_age", func(c *Config) { c.Login.SessionMaxAge = time.Minute }},
		{"limite de l'API des agents", "agent_api.rate_limit", func(c *Config) { c.AgentAPI.RateLimit = -1 }},
		{"limite des jetons refusés", "agent_api.failure_rate_limit", func(c *Config) { c.AgentAPI.FailureRateLimit = -1 }},
		{"archivage des conteneurs", "containers.archive_after", func(c *Config) { c.Containers.ArchiveAfter = time.Minute }},
		{"purge des conteneurs sous la rétention", "containers.purge_after", func(c *Config) { c.Containers.PurgeAfter = 24 * time.Hour }},
		{"borne des conteneurs par hôte", "containers.max_per_host", func(c *Config) { c.Containers.MaxPerHost = 0 }},
		{"limite de l'API utilisateur", "user_api.rate_limit", func(c *Config) { c.UserAPI.RateLimit = -1 }},
		{"limite des jetons personnels refusés", "user_api.failure_rate_limit", func(c *Config) { c.UserAPI.FailureRateLimit = -1 }},
		{"durée d'un export", "user_api.export_timeout", func(c *Config) { c.UserAPI.ExportTimeout = 0 }},
		{"exports simultanés", "user_api.max_exports", func(c *Config) { c.UserAPI.MaxExports = 0 }},
		{"bootstrap sans mot de passe", "bootstrap.admin_password", func(c *Config) { c.Bootstrap.AdminEmail = "a@example.org" }},
		{"bootstrap e-mail invalide", "bootstrap.admin_email", func(c *Config) {
			c.Bootstrap.AdminEmail, c.Bootstrap.AdminPassword = "pas une adresse", "un mot de passe assez long"
		}},
		{"bootstrap mot de passe court", "bootstrap.admin_password", func(c *Config) {
			c.Bootstrap.AdminEmail, c.Bootstrap.AdminPassword = "a@example.org", "court"
		}},
		{"secours sans ticket", "bootstrap.rescue_ticket", func(c *Config) { c.Bootstrap.RescueEmail = "a@example.org" }},
		{"secours sans mot de passe", "bootstrap.rescue_ticket", func(c *Config) {
			c.Bootstrap.RescueEmail, c.Bootstrap.RescueTicket = "a@example.org", "INC-2026-1031"
		}},
		{"secours ticket court", "bootstrap.rescue_ticket", func(c *Config) {
			c.Bootstrap.RescueEmail, c.Bootstrap.RescueTicket, c.Bootstrap.RescuePassword = "a@example.org", "court", "mot de passe de secours"
		}},
		{"secours e-mail invalide", "bootstrap.rescue_totp_email", func(c *Config) {
			c.Bootstrap.RescueEmail, c.Bootstrap.RescueTicket, c.Bootstrap.RescuePassword = "x", "INC-2026-1031", "mot de passe de secours"
		}},
		{"secours mot de passe court", "bootstrap.rescue_password", func(c *Config) {
			c.Bootstrap.RescueEmail, c.Bootstrap.RescueTicket, c.Bootstrap.RescuePassword = "a@example.org", "INC-2026-1031", "court"
		}},
		{"workers", "workers.concurrency (LOTOR_WORKERS_CONCURRENCY)", func(c *Config) { c.Workers.Concurrency = 0 }},
		{"attente des workers", "workers.poll_interval", func(c *Config) { c.Workers.PollInterval = 0 }},
		{"bail", "workers.lease", func(c *Config) { c.Workers.Lease = 500 * time.Millisecond }},
		{"réessai", "workers.retry_base", func(c *Config) { c.Workers.RetryBase = 0 }},
		{"réessai maximal", "workers.retry_max", func(c *Config) { c.Workers.RetryMax = time.Second }},
		{"rétention", "workers.retention", func(c *Config) { c.Workers.Retention = 0 }},
		{"planificateur", "workers.schedule_interval", func(c *Config) { c.Workers.ScheduleInterval = 0 }},
		{"arrêt des workers", "workers.shutdown_timeout", func(c *Config) { c.Workers.ShutdownTimeout = 0 }},
		{"plafond par organisation", "workers.org_limit", func(c *Config) { c.Workers.OrgLimit = 0 }},
		{"durée de rétention", "retention.days", func(c *Config) { c.Retention.Days = 0 }},
		{"nombre gardé", "retention.count", func(c *Config) { c.Retention.Count = -1 }},
		{"envoi nul", "ingest.max_upload_mib", func(c *Config) { c.Ingest.MaxUploadMiB = 0 }},
		{"envoi démesuré", "ingest.max_upload_mib", func(c *Config) { c.Ingest.MaxUploadMiB, c.Ingest.MaxDecompressedMiB = 5000, 5000 }},
		{"décompressé plus petit que l'envoi", "ingest.max_decompressed_mib", func(c *Config) { c.Ingest.MaxDecompressedMiB = 16 }},
		{"profondeur", "ingest.max_depth", func(c *Config) { c.Ingest.MaxDepth = 4 }},
		{"composants", "ingest.max_components", func(c *Config) { c.Ingest.MaxComponents = 0 }},
		{"délai de décodage", "ingest.decode_timeout", func(c *Config) { c.Ingest.DecodeTimeout = 0 }},
		{"liste de la base", "vulndb.listing_url", func(c *Config) { c.VulnDB.ListingURL = "ftp://x" }},
		{"répertoire de la base", "vulndb.dir", func(c *Config) { c.VulnDB.Dir = "relatif" }},
		{"vérification trop fréquente", "vulndb.check_interval", func(c *Config) { c.VulnDB.CheckInterval = time.Minute }},
		{"synchronisation", "vulndb.sync_interval", func(c *Config) { c.VulnDB.SyncInterval = 0 }},
		{"âge maximal", "vulndb.max_age", func(c *Config) { c.VulnDB.MaxAge = time.Minute }},
		{"délai de téléchargement", "vulndb.download_timeout", func(c *Config) { c.VulnDB.DownloadTimeout = 0 }},
		{"délai d'analyse", "vulndb.analysis_timeout", func(c *Config) { c.VulnDB.AnalysisTimeout = 0 }},
		{"archive démesurée", "vulndb.max_archive_mib", func(c *Config) { c.VulnDB.MaxArchiveMiB = 1 << 20 }},
		{"clé trop courte", "secrets.keys", func(c *Config) {
			c.Secrets = Secrets{Keys: map[string]string{"k1": "c2hvcnQ="}, ActiveKey: "k1"}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := valid()
			c.edit(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), c.field) {
				t.Fatalf("err = %v, attendu une erreur sur %s", err, c.field)
			}
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("erreur sans champ : %v", err)
			}
		})
	}
}

func TestValidateReportsEveryError(t *testing.T) {
	cfg := valid()
	cfg.Database.Driver = "mysql"
	cfg.Web.Port = 0
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "database.driver") || !strings.Contains(err.Error(), "web.port") {
		t.Fatalf("err = %v", err)
	}
}

func TestFieldsHaveEnvAndDescription(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Fields() {
		if !strings.HasPrefix(f.Env, EnvPrefix) || f.Env == EnvPrefix {
			t.Errorf("%s : variable %q sans préfixe ou sans nom", f.Path, f.Env)
		}
		if f.Description == "" {
			t.Errorf("%s : pas de env-description (absent de --help)", f.Path)
		}
		if seen[f.Env] {
			t.Errorf("variable %s en double", f.Env)
		}
		seen[f.Env] = true
	}
	if !seen["LOTOR_DB_DSN"] || !seen["LOTOR_MIGRATION_DSN"] || !seen["LOTOR_TLS_CERT_FILE"] {
		t.Errorf("variables attendues manquantes : %v", seen)
	}
}

// TestHelpListsEveryVariable lance --help dans un sous-processus (appconf termine le
// programme) et vérifie que chaque variable y figure avec sa description.
func TestHelpListsEveryVariable(t *testing.T) {
	if os.Getenv("LOTOR_CONFIG_HELP_CHILD") == "1" {
		os.Args = []string{"lotor-server", "--help"}
		_, _ = Load("lotor-server", "test")
		os.Exit(3) // --help aurait dû terminer en code 0
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelpListsEveryVariable$")
	cmd.Env = append(os.Environ(), "LOTOR_CONFIG_HELP_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help : %v\n%s", err, out)
	}
	for _, f := range Fields() {
		if !bytes.Contains(out, []byte(f.Env)) || !bytes.Contains(out, []byte(f.Description)) {
			t.Errorf("--help ne documente pas %s (%s)", f.Env, f.Description)
		}
	}
}

// TestExampleConfiguration vérifie que config.example.yaml ne contient que des clés
// connues, les contient toutes et constitue une configuration valide.
func TestExampleConfiguration(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("clé inconnue ou valeur invalide : %v", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(body, &tree); err != nil {
		t.Fatal(err)
	}
	for _, f := range Fields() {
		if !hasPath(tree, strings.Split(f.Path, ".")) {
			t.Errorf("config.example.yaml ne documente pas %s", f.Path)
		}
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("config.example.yaml invalide : %v", err)
	}
}

func hasPath(tree map[string]any, path []string) bool {
	v, ok := tree[path[0]]
	if !ok {
		return false
	}
	if len(path) == 1 {
		return true
	}
	sub, ok := v.(map[string]any)
	return ok && hasPath(sub, path[1:])
}

// testValidateSignup couvre l'inscription (T28) : modes, domaines, et refus du mode public
// sans SMTP ou sans URL publique. mail est une configuration valide qui peut envoyer.
func testValidateSignup(t *testing.T, mail Config) {
	t.Helper()
	if d := Defaults(); d.Signup.Mode != SignupPrivate {
		t.Errorf("mode par défaut %q, attendu private", d.Signup.Mode)
	}
	for name, c := range map[string]Config{
		"invitation sans SMTP": func() Config { c := valid(); c.Signup.Mode = SignupInvitation; return c }(),
		"public avec SMTP":     func() Config { c := mail; c.Signup.Mode = SignupPublic; return c }(),
		"domaines": func() Config {
			c := mail
			c.Signup = Signup{Mode: SignupPublic, AllowedDomains: []string{"acme.fr", "Sub.Example.CO.uk"}}
			return c
		}(),
	} {
		if err := c.Validate(); err != nil {
			t.Errorf("%s refusé : %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		c    Config
		want string
	}{
		"mode inconnu": {func() Config { c := valid(); c.Signup.Mode = "open"; return c }(), "signup.mode"},
		"public sans SMTP": {func() Config {
			c := valid()
			c.Web.PublicURL = "https://x.example.org"
			c.Signup.Mode = SignupPublic
			return c
		}(), "smtp.host et smtp.from"},
		"public sans URL":    {func() Config { c := mail; c.Web.PublicURL = ""; c.Signup.Mode = SignupPublic; return c }(), "web.public_url obligatoire"},
		"domaine avec @":     {func() Config { c := mail; c.Signup.AllowedDomains = []string{"@acme.fr"}; return c }(), "signup.allowed_domains"},
		"domaine sans point": {func() Config { c := mail; c.Signup.AllowedDomains = []string{"localhost"}; return c }(), "signup.allowed_domains"},
		"motif":              {func() Config { c := mail; c.Signup.AllowedDomains = []string{"*.acme.fr"}; return c }(), "signup.allowed_domains"},
	} {
		if err := tc.c.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s : %v, attendu %q", name, err, tc.want)
		}
	}
}
