package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/text/language"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/secret"
)

// FieldError est une erreur de configuration qui nomme son champ.
type FieldError struct {
	Path string
	Msg  string
}

func (e *FieldError) Error() string {
	if env := envOf(e.Path); env != "" {
		return fmt.Sprintf("%s (%s) : %s", e.Path, env, e.Msg)
	}
	return e.Path + " : " + e.Msg
}

type validator struct{ errs []error }

func (v *validator) fail(path, format string, args ...any) {
	v.errs = append(v.errs, &FieldError{Path: path, Msg: fmt.Sprintf(format, args...)})
}

func (v *validator) port(path string, p int) {
	if p < 1 || p > 65535 {
		v.fail(path, "port invalide %d (1 à 65535)", p)
	}
}

func (v *validator) positive(path string, n int64) {
	if n <= 0 {
		v.fail(path, "doit être strictement positif")
	}
}

func (v *validator) nonNegative(path string, n int64) {
	if n < 0 {
		v.fail(path, "ne peut pas être négatif")
	}
}

func (v *validator) oneOf(path, got string, allowed ...string) {
	if !slices.Contains(allowed, got) {
		v.fail(path, "valeur %q invalide (attendu : %v)", got, allowed)
	}
}

func (v *validator) readable(path, file string) {
	if file == "" {
		return
	}
	f, err := os.Open(file)
	if err != nil {
		v.fail(path, "fichier illisible : %v", err)
		return
	}
	_ = f.Close()
}

// Validate vérifie la configuration et renvoie toutes les erreurs, chacune nommant son
// champ et sa variable d'environnement.
func (c Config) Validate() error {
	var v validator

	v.port("web.port", c.Web.Port)
	v.nonNegative("web.rate_limit", int64(c.Web.RateLimit))
	for _, p := range c.Web.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			v.fail("web.trusted_proxies", "CIDR invalide %q", p)
		}
	}

	v.positive("http.read_header_timeout", int64(c.HTTP.ReadHeaderTimeout))
	v.nonNegative("http.read_timeout", int64(c.HTTP.ReadTimeout))
	v.nonNegative("http.write_timeout", int64(c.HTTP.WriteTimeout))
	v.nonNegative("http.idle_timeout", int64(c.HTTP.IdleTimeout))
	v.positive("http.shutdown_timeout", int64(c.HTTP.ShutdownTimeout))

	switch {
	case c.TLS.CertFile != "" && c.TLS.KeyFile == "":
		v.fail("tls.key_file", "obligatoire avec tls.cert_file")
	case c.TLS.KeyFile != "" && c.TLS.CertFile == "":
		v.fail("tls.cert_file", "obligatoire avec tls.key_file")
	}
	if c.TLS.ClientCAFile != "" && !c.TLS.Enabled() {
		v.fail("tls.client_ca_file", "le mTLS des agents exige le TLS natif (tls.cert_file et tls.key_file)")
	}
	v.readable("tls.cert_file", c.TLS.CertFile)
	v.readable("tls.key_file", c.TLS.KeyFile)
	v.readable("tls.client_ca_file", c.TLS.ClientCAFile)

	v.port("management.port", c.Management.Port)
	if c.Management.Port == c.Web.Port && (c.Management.Host == c.Web.Host || c.Management.Host == "0.0.0.0" || c.Web.Host == "0.0.0.0") {
		v.fail("management.port", "doit différer de web.port : l'écoute de gestion est séparée")
	}

	v.oneOf("logging.level", c.Logging.Level, "debug", "info", "warn", "error")
	v.oneOf("logging.format", c.Logging.Format, "text", "json")

	if _, err := language.Parse(c.I18n.DefaultLanguage); err != nil {
		v.fail("i18n.default_language", "étiquette de langue invalide %q", c.I18n.DefaultLanguage)
	}

	v.nonNegative("cors.max_age", int64(c.CORS.MaxAge))

	// Le dialecte d'authx et de mfax se déduit du pilote : seul PostgreSQL est supporté.
	if c.Database.Driver != "postgres" {
		v.fail("database.driver", "doit valoir « postgres » (reçu %q)", c.Database.Driver)
	}
	appRole := ""
	if c.Database.DSN == "" {
		v.fail("database.dsn", "obligatoire (connexion du rôle d'exécution)")
	} else if r, err := db.RoleFromDSN(c.Database.DSN); err != nil {
		v.fail("database.dsn", "%v", err)
	} else {
		appRole = r
	}
	v.positive("database.max_open_conns", int64(c.Database.MaxOpenConns))
	v.nonNegative("database.max_idle_conns", int64(c.Database.MaxIdleConns))
	v.nonNegative("database.conn_max_lifetime", int64(c.Database.ConnMaxLifetime))
	v.positive("database.startup_timeout", int64(c.Database.StartupTimeout))

	if c.Migration.DSN != "" {
		if r, err := db.RoleFromDSN(c.Migration.DSN); err != nil {
			v.fail("migration.dsn", "%v", err)
		} else if r == appRole {
			v.fail("migration.dsn", "doit désigner le rôle propriétaire, distinct du rôle d'exécution %q", r)
		}
	}
	// Le verrou de migration tient une connexion pendant que les migrations en utilisent
	// une autre.
	if c.Migration.MaxConns < 2 {
		v.fail("migration.max_conns", "au moins 2 connexions (reçu %d)", c.Migration.MaxConns)
	}
	v.nonNegative("migration.lock_timeout", int64(c.Migration.LockTimeout))

	// Les secrets TOTP sont chiffrés en base : une clé est obligatoire.
	if len(c.Secrets.Keys) == 0 {
		v.fail("secrets.keys", "obligatoire : les secrets TOTP sont chiffrés en base (openssl rand -base64 32)")
	} else if _, err := secret.Parse(c.Secrets.Keys, c.Secrets.ActiveKey); err != nil {
		v.fail("secrets.keys", "%v", err)
	}

	v.positive("auth.session_ttl", int64(c.Auth.SessionTTL))
	if c.Auth.CookieName == "" {
		v.fail("auth.cookie_name", "obligatoire")
	}
	v.oneOf("auth.cookie_secure", c.Auth.CookieSecure, "auto", "on", "off")
	if c.Auth.BcryptCost < 10 || c.Auth.BcryptCost > 31 {
		v.fail("auth.bcrypt_cost", "doit être compris entre 10 et 31 (reçu %d)", c.Auth.BcryptCost)
	}
	if c.MFA.Issuer == "" {
		v.fail("mfa.issuer", "obligatoire")
	}
	v.positive("mfa.challenge_ttl", int64(c.MFA.ChallengeTTL))
	if c.MFA.MaxAttempts < 1 || c.MFA.MaxAttempts > 20 {
		v.fail("mfa.max_attempts", "doit être compris entre 1 et 20 (reçu %d)", c.MFA.MaxAttempts)
	}
	if c.MFA.LockoutThreshold < 1 || c.MFA.LockoutThreshold > 100 {
		v.fail("mfa.lockout_threshold", "doit être compris entre 1 et 100 (reçu %d)", c.MFA.LockoutThreshold)
	}
	v.positive("mfa.lockout_window", int64(c.MFA.LockoutWindow))
	v.positive("mfa.lockout_duration", int64(c.MFA.LockoutDuration))
	if c.MFA.LockoutMaxDuration < c.MFA.LockoutDuration {
		v.fail("mfa.lockout_max_duration", "doit être au moins égal à mfa.lockout_duration")
	}
	if c.MFA.RecoveryCodes < 5 || c.MFA.RecoveryCodes > 50 {
		v.fail("mfa.recovery_codes", "doit être compris entre 5 et 50 (reçu %d)", c.MFA.RecoveryCodes)
	}
	v.nonNegative("login.rate_limit", int64(c.Login.RateLimit))
	v.nonNegative("login.session_max_age", int64(c.Login.SessionMaxAge))
	if c.Login.SessionMaxAge > 0 && c.Login.SessionMaxAge < c.Auth.SessionTTL {
		v.fail("login.session_max_age", "doit être au moins égal à auth.session_ttl, ou 0 (sans durée absolue)")
	}
	v.nonNegative("agent_api.rate_limit", int64(c.AgentAPI.RateLimit))
	v.nonNegative("agent_api.failure_rate_limit", int64(c.AgentAPI.FailureRateLimit))
	v.nonNegative("user_api.rate_limit", int64(c.UserAPI.RateLimit))
	v.nonNegative("user_api.failure_rate_limit", int64(c.UserAPI.FailureRateLimit))
	v.positive("user_api.export_timeout", int64(c.UserAPI.ExportTimeout))
	if c.UserAPI.MaxExports < 1 || c.UserAPI.MaxExports > 64 {
		v.fail("user_api.max_exports", "doit être compris entre 1 et 64 (reçu %d)", c.UserAPI.MaxExports)
	}
	c.Bootstrap.validate(&v)
	v.positive("workers.concurrency", int64(c.Workers.Concurrency))
	v.positive("workers.poll_interval", int64(c.Workers.PollInterval))
	if c.Workers.Lease < time.Second {
		v.fail("workers.lease", "au moins 1s (reçu %s)", c.Workers.Lease)
	}
	v.positive("workers.retry_base", int64(c.Workers.RetryBase))
	if c.Workers.RetryMax < c.Workers.RetryBase {
		v.fail("workers.retry_max", "doit valoir au moins workers.retry_base (%s)", c.Workers.RetryBase)
	}
	v.positive("workers.retention", int64(c.Workers.Retention))
	v.positive("workers.schedule_interval", int64(c.Workers.ScheduleInterval))
	v.positive("workers.shutdown_timeout", int64(c.Workers.ShutdownTimeout))
	v.positive("workers.org_limit", int64(c.Workers.OrgLimit))
	c.Ingest.validate(&v)
	c.VulnDB.validate(&v)
	if c.Retention.Days < 1 || c.Retention.Days > 36500 {
		v.fail("retention.days", "doit être compris entre 1 et 36500 (reçu %d)", c.Retention.Days)
	}
	if c.Retention.Count < 0 || c.Retention.Count > 100000 {
		v.fail("retention.count", "doit être compris entre 0 et 100000 (reçu %d)", c.Retention.Count)
	}
	validPublicURL(&v, c.Web.PublicURL)
	c.validateSignup(&v)
	c.Notify.validate(&v)
	c.SMTP.validate(&v)
	if c.Containers.PurgeAfter != 0 && c.Containers.PurgeAfter < time.Duration(c.Retention.Days)*24*time.Hour {
		v.fail("containers.purge_after", "0 (jamais) ou au moins retention.days (%d jours ; reçu %s)", c.Retention.Days, c.Containers.PurgeAfter)
	}
	if d := c.Offline.WatchDir; d != "" && !filepath.IsAbs(d) {
		v.fail("offline.watch_dir", "chemin absolu attendu (reçu %q)", d)
	}
	if c.Offline.WatchDir != "" && (c.Offline.WatchInterval < time.Second || c.Offline.WatchInterval > 24*time.Hour) {
		v.fail("offline.watch_interval", "entre 1s et 24h (reçu %s)", c.Offline.WatchInterval)
	}
	if c.Containers.MaxPerHost < 1 || c.Containers.MaxPerHost > 100000 {
		v.fail("containers.max_per_host", "doit être compris entre 1 et 100000 (reçu %d)", c.Containers.MaxPerHost)
	}
	if c.Containers.ArchiveAfter < time.Hour {
		v.fail("containers.archive_after", "au moins 1h (reçu %s)", c.Containers.ArchiveAfter)
	}

	return errors.Join(v.errs...)
}

// Bornes de la base de vulnérabilités.
const (
	minVulnDBCheck   = 10 * time.Minute
	maxVulnDBArchive = 16384
)

func (d VulnDB) validate(v *validator) {
	if !d.Offline {
		if u, err := url.Parse(d.ListingURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			v.fail("vulndb.listing_url", "adresse http(s) attendue (reçu %q)", d.ListingURL)
		}
	}
	if !filepath.IsAbs(d.Dir) {
		v.fail("vulndb.dir", "chemin absolu attendu (reçu %q)", d.Dir)
	}
	if d.CheckInterval < minVulnDBCheck {
		v.fail("vulndb.check_interval", "au moins %s (reçu %s)", minVulnDBCheck, d.CheckInterval)
	}
	if d.SyncInterval < time.Second {
		v.fail("vulndb.sync_interval", "au moins 1s (reçu %s)", d.SyncInterval)
	}
	if d.MaxAge < time.Hour {
		v.fail("vulndb.max_age", "au moins 1h (reçu %s)", d.MaxAge)
	}
	v.positive("vulndb.download_timeout", int64(d.DownloadTimeout))
	v.positive("vulndb.analysis_timeout", int64(d.AnalysisTimeout))
	if d.MaxArchiveMiB < 1 || d.MaxArchiveMiB > maxVulnDBArchive {
		v.fail("vulndb.max_archive_mib", "doit être compris entre 1 et %d (reçu %d)", maxVulnDBArchive, d.MaxArchiveMiB)
	}
}

// Plafonds des bornes de l'ingestion : au-delà, un seul envoi suffirait à épuiser la
// mémoire d'un worker, ou la pile du lecteur préalable.
const (
	maxIngestMiB   = 4096
	maxIngestDepth = 1000
)

func (i Ingest) validate(v *validator) {
	if i.MaxUploadMiB < 1 || i.MaxUploadMiB > maxIngestMiB {
		v.fail("ingest.max_upload_mib", "doit être compris entre 1 et %d (reçu %d)", maxIngestMiB, i.MaxUploadMiB)
	}
	if i.MaxDecompressedMiB < i.MaxUploadMiB || i.MaxDecompressedMiB > maxIngestMiB {
		v.fail("ingest.max_decompressed_mib", "doit être compris entre ingest.max_upload_mib et %d (reçu %d)", maxIngestMiB, i.MaxDecompressedMiB)
	}
	if i.MaxDepth < 8 || i.MaxDepth > maxIngestDepth {
		v.fail("ingest.max_depth", "doit être compris entre 8 et %d (reçu %d)", maxIngestDepth, i.MaxDepth)
	}
	v.positive("ingest.max_components", int64(i.MaxComponents))
	v.positive("ingest.decode_timeout", int64(i.DecodeTimeout))
	v.nonNegative("ingest.max_per_ref_per_day", int64(i.MaxPerRefPerDay))
	v.nonNegative("ingest.max_org_storage_mib", int64(i.MaxOrgStorageMiB))
	if i.MaxReencodes < 1 || i.MaxReencodes > 64 {
		v.fail("ingest.max_reencodes", "doit être compris entre 1 et 64 (reçu %d)", i.MaxReencodes)
	}
}

func (b Bootstrap) validate(v *validator) {
	if (b.AdminEmail == "") != (b.AdminPassword == "") {
		v.fail("bootstrap.admin_password", "bootstrap.admin_email et bootstrap.admin_password vont ensemble")
	} else if b.AdminEmail != "" {
		if _, err := account.NormalizeEmail(b.AdminEmail); err != nil {
			v.fail("bootstrap.admin_email", "adresse invalide")
		} else if err := account.ValidatePassword(b.AdminPassword, b.AdminEmail); err != nil {
			v.fail("bootstrap.admin_password", "refusé par la politique de mot de passe (%d caractères au moins, différent de l'e-mail)", account.MinPasswordLength)
		}
	}
	if (b.RescueEmail == "") != (b.RescueTicket == "") || (b.RescueEmail == "") != (b.RescuePassword == "") {
		v.fail("bootstrap.rescue_ticket", "bootstrap.rescue_totp_email, bootstrap.rescue_ticket et bootstrap.rescue_password vont ensemble")
	} else if b.RescueEmail != "" {
		if _, err := account.NormalizeEmail(b.RescueEmail); err != nil {
			v.fail("bootstrap.rescue_totp_email", "adresse invalide")
		} else if err := account.ValidatePassword(b.RescuePassword, b.RescueEmail); err != nil {
			v.fail("bootstrap.rescue_password", "refusé par la politique de mot de passe (%d caractères au moins, différent de l'e-mail)", account.MinPasswordLength)
		}
		if len([]rune(strings.TrimSpace(b.RescueTicket))) < account.MinRescueTicket {
			v.fail("bootstrap.rescue_ticket", "%d caractères au moins", account.MinRescueTicket)
		}
	}
}

// validPublicURL vérifie l'URL publique du serveur : http(s), sans compte, requête ni
// fragment.
func validPublicURL(v *validator, raw string) {
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" {
		v.fail("web.public_url", "adresse http(s) sans requête attendue (reçu %q)", raw)
	}
}

// MailConfigured indique si le serveur peut envoyer des courriels porteurs d'un lien :
// SMTP configuré et URL publique connue. Sans cela, codes et liens d'invitation sont
// affichés pour être transmis à la main (T28).
func (c Config) MailConfigured() bool {
	return c.SMTP.Host != "" && c.SMTP.From != "" && c.Web.PublicURL != ""
}

func (c Config) validateSignup(v *validator) {
	s := c.Signup
	v.oneOf("signup.mode", s.Mode, SignupPrivate, SignupInvitation, SignupPublic)
	for _, d := range s.AllowedDomains {
		if !validDomain(d) {
			v.fail("signup.allowed_domains", "nom de domaine attendu (reçu %q)", d)
		}
	}
	if s.Mode == SignupPublic {
		if c.SMTP.Host == "" || c.SMTP.From == "" {
			v.fail("signup.mode", "l'inscription publique vérifie chaque adresse par courriel : smtp.host et smtp.from obligatoires")
		}
		if c.Web.PublicURL == "" {
			v.fail("signup.mode", "l'inscription publique envoie des liens de vérification : web.public_url obligatoire")
		}
	}
}

// validDomain accepte un nom de domaine en minuscules ou majuscules, sans « @ » ni
// caractère de motif : example.org, sub.example.co.uk.
func validDomain(d string) bool {
	d = strings.TrimSpace(d)
	if d == "" || len(d) > 253 || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || !strings.Contains(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func (n Notify) validate(v *validator) {
	if n.Timeout < time.Second || n.Timeout > 5*time.Minute {
		v.fail("notify.timeout", "doit être compris entre 1s et 5m (reçu %s)", n.Timeout)
	}
	if n.DigestHour < 0 || n.DigestHour > 23 {
		v.fail("notify.digest_hour", "doit être compris entre 0 et 23 (reçu %d)", n.DigestHour)
	}
}

func (s SMTP) validate(v *validator) {
	if s.Host == "" {
		return
	}
	switch s.TLS {
	case "starttls", "tls", "none":
	default:
		v.fail("smtp.tls", "starttls, tls ou none attendu (reçu %q)", s.TLS)
	}
	if s.Port < 1 || s.Port > 65535 {
		v.fail("smtp.port", "doit être compris entre 1 et 65535 (reçu %d)", s.Port)
	}
	if a, err := mail.ParseAddress(s.From); err != nil || a.Name != "" || strings.ContainsAny(s.From, "\r\n") {
		v.fail("smtp.from", "adresse e-mail nue attendue (reçu %q)", s.From)
	}
	if s.TLS == "none" && s.Username != "" {
		v.fail("smtp.username", "aucune authentification sans TLS (smtp.tls: none)")
	}
}
