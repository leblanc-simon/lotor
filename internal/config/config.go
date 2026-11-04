package config

import (
	"time"

	"leblanc.io/open-go-base/appconf"
)

// EnvPrefix préfixe toutes les variables d'environnement du serveur.
const EnvPrefix = "LOTOR_"

// Config est la configuration de lotor-server : fragments d'appconf (Web, Logging, I18n,
// CORS, base de données, Auth et MFA) et fragments propres au projet. Workers arrive avec
// la file (T02), Ingest et VulnDB avec leurs lots.
type Config struct {
	Web        Web             `yaml:"web"        env-prefix:"LOTOR_"`
	HTTP       HTTP            `yaml:"http"       env-prefix:"LOTOR_"`
	TLS        TLS             `yaml:"tls"        env-prefix:"LOTOR_"`
	Management Management      `yaml:"management" env-prefix:"LOTOR_"`
	Logging    appconf.Logging `yaml:"logging"    env-prefix:"LOTOR_"`
	I18n       appconf.I18n    `yaml:"i18n"       env-prefix:"LOTOR_"`
	CORS       appconf.CORS    `yaml:"cors"       env-prefix:"LOTOR_"`
	Database   Database        `yaml:"database"   env-prefix:"LOTOR_"`
	Migration  Migration       `yaml:"migration"  env-prefix:"LOTOR_"`
	Secrets    Secrets         `yaml:"secrets"    env-prefix:"LOTOR_"`
	Auth       appconf.Auth    `yaml:"auth"       env-prefix:"LOTOR_"`
	MFA        appconf.MFA     `yaml:"mfa"        env-prefix:"LOTOR_"`
	Login      Login           `yaml:"login"      env-prefix:"LOTOR_"`
	AgentAPI   AgentAPI        `yaml:"agent_api"  env-prefix:"LOTOR_"`
	UserAPI    UserAPI         `yaml:"user_api"   env-prefix:"LOTOR_"`
	AI         AI              `yaml:"ai"         env-prefix:"LOTOR_"`
	Bootstrap  Bootstrap       `yaml:"bootstrap"  env-prefix:"LOTOR_"`
	Workers    Workers         `yaml:"workers"    env-prefix:"LOTOR_"`
	Ingest     Ingest          `yaml:"ingest"     env-prefix:"LOTOR_"`
	VulnDB     VulnDB          `yaml:"vulndb"     env-prefix:"LOTOR_"`
	Retention  Retention       `yaml:"retention"  env-prefix:"LOTOR_"`
	Notify     Notify          `yaml:"notify"     env-prefix:"LOTOR_"`
	SMTP       SMTP            `yaml:"smtp"       env-prefix:"LOTOR_"`
	Containers Containers      `yaml:"containers" env-prefix:"LOTOR_"`
	Signup     Signup          `yaml:"signup"     env-prefix:"LOTOR_"`
}

// Web complète le fragment d'appconf de l'URL publique du serveur (T28) : liens des
// notifications, des verdicts de commit et des courriels de l'inscription.
type Web struct {
	appconf.Web `yaml:",inline"`

	PublicURL string `yaml:"public_url" env:"PUBLIC_URL" env-description:"Public URL of the server (https://sbom.example.org), for links in notifications, commit verdicts and sign-up e-mails; empty: no link, and no sign-up e-mail"`
}

// Modes d'inscription (T28, ADR 0056).
const (
	SignupPrivate    = "private"
	SignupInvitation = "invitation"
	SignupPublic     = "public"
)

// Signup règle l'inscription des comptes locaux (T28, ADR 0056) : privée (seules les
// invitations d'organisation ouvrent un compte), sur code d'inscription, ou publique.
type Signup struct {
	Mode string `yaml:"mode" env:"SIGNUP_MODE" env-default:"private" env-description:"Sign-up mode: private (organization invitations only), invitation (sign-up codes created by instance administrators) or public (anyone, e-mail verified; requires SMTP and web.public_url)"`
	// AllowedDomains restreint l'inscription publique aux adresses de ces domaines (vide :
	// aucune restriction).
	AllowedDomains []string `yaml:"allowed_domains" env:"SIGNUP_ALLOWED_DOMAINS" env-separator:"," env-description:"Public sign-up only: e-mail domains allowed to sign up, separated by commas (empty: any domain)"`
}

// Notify règle les notifications des politiques (T15, ADR 0046).
type Notify struct {
	Timeout              time.Duration `yaml:"timeout"                env:"NOTIFY_TIMEOUT"                env-default:"30s" env-description:"Maximum duration of one notification sent (HTTP request or SMTP session)"`
	AllowPrivateNetworks bool          `yaml:"allow_private_networks" env:"NOTIFY_ALLOW_PRIVATE_NETWORKS" env-description:"Allow notification channels to reach loopback, private and link-local addresses (default false: refused, against SSRF)"`
	DigestHour           int           `yaml:"digest_hour"            env:"NOTIFY_DIGEST_HOUR"            env-default:"7"   env-description:"Hour (UTC, 0 to 23) of the daily digest of violations"`
}

// SMTP décrit le serveur d'envoi des courriels (canaux e-mail, T15). Sans hôte, les
// canaux e-mail échouent avec une erreur explicite.
type SMTP struct {
	Host     string `yaml:"host"     env:"SMTP_HOST"     env-description:"SMTP server host; empty: e-mail channels disabled"`
	Port     int    `yaml:"port"     env:"SMTP_PORT"     env-default:"587"      env-description:"SMTP server port (587 for starttls, 465 for tls)"`
	TLS      string `yaml:"tls"      env:"SMTP_TLS"      env-default:"starttls" env-description:"Connection security: starttls (required), tls (implicit TLS) or none (local relay only, no authentication)"`
	Username string `yaml:"username" env:"SMTP_USERNAME" env-description:"SMTP user (PLAIN authentication over TLS); empty: no authentication"`
	Password string `yaml:"password" env:"SMTP_PASSWORD" env-description:"SMTP password"`
	From     string `yaml:"from"     env:"SMTP_FROM"     env-description:"Sender address of notifications (lotor@example.org)"`
	HELO     string `yaml:"helo"     env:"SMTP_HELO"     env-default:"localhost" env-description:"Name announced in EHLO"`
}

// Containers règle les conteneurs en projets enfants des hôtes (T13, ADR 0040).
type Containers struct {
	ArchiveAfter time.Duration `yaml:"archive_after" env:"CONTAINERS_ARCHIVE_AFTER" env-default:"168h" env-description:"Absence after which the project of a container is archived (it comes back when the container restarts)"`
	// PurgeAfter : archivé pour absence depuis plus longtemps, le projet d'un conteneur est
	// supprimé avec son historique par la rétention nocturne (T18, ADR 0048).
	PurgeAfter time.Duration `yaml:"purge_after" env:"CONTAINERS_PURGE_AFTER" env-default:"4320h" env-description:"Time archived for absence after which the project of a container is deleted with its history, by the nightly retention (0: never; at least retention.days)"`
	// MaxPerHost borne les projets enfants d'un hôte, actifs ou archivés (SEC2-05) : un
	// signalement qui en créerait davantage est refusé sans rien créer.
	MaxPerHost int `yaml:"max_per_host" env:"CONTAINERS_MAX_PER_HOST" env-default:"1000" env-description:"Maximum number of container projects (active or archived) under one host; a report that would create more is refused"`
}

// Retention règle la rétention des instantanés (T17, ADR 0039), appliquée chaque nuit
// par les workers. Enabled et Monthly, vrais par défaut, n'ont pas d'env-default (un
// false écrit dans le fichier serait écrasé) : Defaults les pose.
type Retention struct {
	Enabled bool `yaml:"enabled" env:"RETENTION_ENABLED" env-description:"Delete old snapshots according to the retention policy; orphan inventory sets and SBOMs are always deleted"`
	Days    int  `yaml:"days"    env:"RETENTION_DAYS"    env-default:"90" env-description:"Every snapshot younger than this many days is kept (1 to 36500)"`
	Count   int  `yaml:"count"   env:"RETENTION_COUNT"   env-default:"0"  env-description:"The latest snapshots of each reference kept whatever their age (0: none beyond the window)"`
	Monthly bool `yaml:"monthly" env:"RETENTION_MONTHLY" env-description:"Beyond the window, keep the last snapshot of each month, without time limit"`
}

// VulnDB règle la base de vulnérabilités (§ 12 de l'architecture, ADR 0017) : liste de
// distribution interrogée par l'échéance vulndb.check, copie locale de chaque instance
// worker, alerte d'âge.
type VulnDB struct {
	ListingURL      string        `yaml:"listing_url"      env:"VULNDB_LISTING_URL"      env-default:"https://grype.anchore.io/databases/v6/latest.json" env-description:"Grype database listing (latest.json, or a mirror of it)"`
	Dir             string        `yaml:"dir"              env:"VULNDB_DIR"              env-default:"/var/lib/lotor/vulndb" env-description:"Local directory of the vulnerability database of this worker instance (about 7 GiB free during a switch)"`
	Offline         bool          `yaml:"offline"          env:"VULNDB_OFFLINE"          env-description:"Never query the listing: databases are only imported (isolated sites)"`
	CheckInterval   time.Duration `yaml:"check_interval"   env:"VULNDB_CHECK_INTERVAL"   env-default:"6h"    env-description:"How often one instance queries the listing for a newer database"`
	SyncInterval    time.Duration `yaml:"sync_interval"    env:"VULNDB_SYNC_INTERVAL"    env-default:"1m"    env-description:"How often a worker instance checks that its local copy is the shared target"`
	MaxAge          time.Duration `yaml:"max_age"          env:"VULNDB_MAX_AGE"          env-default:"120h"  env-description:"Age beyond which the target database raises an administration alert"`
	DownloadTimeout time.Duration `yaml:"download_timeout" env:"VULNDB_DOWNLOAD_TIMEOUT" env-default:"30m"   env-description:"Maximum duration of one listing query, archive download or archive upload"`
	MaxArchiveMiB   int           `yaml:"max_archive_mib"  env:"VULNDB_MAX_ARCHIVE_MIB"  env-default:"2048"  env-description:"Maximum size of a database archive, downloaded or imported, in MiB"`
	AnalysisTimeout time.Duration `yaml:"analysis_timeout" env:"VULNDB_ANALYSIS_TIMEOUT" env-default:"10m"   env-description:"Maximum duration of one analysis job, local database synchronisation included"`
}

// Ingest borne la réception et le décodage des SBOM (§ 11 de l'architecture). Les tailles
// sont en Mio.
type Ingest struct {
	MaxUploadMiB       int           `yaml:"max_upload_mib"       env:"INGEST_MAX_UPLOAD_MIB"       env-default:"32"     env-description:"Maximum size of an uploaded SBOM as sent (gzip or raw JSON), in MiB"`
	MaxDecompressedMiB int           `yaml:"max_decompressed_mib" env:"INGEST_MAX_DECOMPRESSED_MIB" env-default:"64"     env-description:"Maximum size of an SBOM once decompressed, in MiB"`
	MaxDepth           int           `yaml:"max_depth"            env:"INGEST_MAX_DEPTH"            env-default:"64"     env-description:"Maximum JSON nesting depth of an SBOM"`
	MaxComponents      int           `yaml:"max_components"       env:"INGEST_MAX_COMPONENTS"       env-default:"50000"  env-description:"Maximum number of components (CycloneDX components, SPDX packages, Syft artifacts)"`
	DecodeTimeout      time.Duration `yaml:"decode_timeout"       env:"INGEST_DECODE_TIMEOUT"       env-default:"5m"     env-description:"Maximum duration of one SBOM decoding job"`
	MaxPerRefPerDay    int           `yaml:"max_per_ref_per_day"  env:"INGEST_MAX_PER_REF_PER_DAY"  env-default:"200"    env-description:"Stored SBOM uploads per reference over 24 hours, beyond which 429 is returned (0: unlimited)"`
	MaxOrgStorageMiB   int           `yaml:"max_org_storage_mib"  env:"INGEST_MAX_ORG_STORAGE_MIB"  env-default:"10240"  env-description:"Compressed SBOM storage per organization, in MiB, beyond which uploads get 429 (0: unlimited)"`
	MaxReencodes       int           `yaml:"max_reencodes"        env:"INGEST_MAX_REENCODES"        env-default:"2"      env-description:"SBOM downloads re-encoded (CycloneDX, SPDX) at once on this instance, one per account, beyond which 429 is returned"`
}

// MiB convertit une taille de la configuration, en Mio, en octets.
func MiB(n int) int64 { return int64(n) << 20 }

// Login borne les tentatives de connexion (requêtes POST sur /login et /login/2fa par
// minute et par IP, une IPv6 comptant pour son /64, en plus de la limite générale de
// l'interface) et la durée absolue d'une session, quelle que soit son activité.
type Login struct {
	RateLimit     int           `yaml:"rate_limit"      env:"LOGIN_RATE_LIMIT"      env-default:"10"   env-description:"Login and second-factor attempts per minute and per IP (per /64 for IPv6)"`
	SessionMaxAge time.Duration `yaml:"session_max_age" env:"LOGIN_SESSION_MAX_AGE" env-default:"168h" env-description:"Absolute lifetime of a session from sign-in, whatever its activity (auth.session_ttl slides within it)"`
}

// AgentAPI borne le débit de l'API des agents (/api/v1/agent/*) : par jeton, pour que des
// hôtes derrière une même sortie NAT ne se gênent pas, et par IP pour les seuls jetons
// refusés.
type AgentAPI struct {
	RateLimit        int `yaml:"rate_limit"         env:"AGENT_API_RATE_LIMIT"         env-default:"120" env-description:"Agent API requests per minute and per token (0: unlimited)"`
	FailureRateLimit int `yaml:"failure_rate_limit" env:"AGENT_API_FAILURE_RATE_LIMIT" env-default:"30"  env-description:"Refused agent API tokens per minute and per IP (0: unlimited)"`
}

// UserAPI borne l'API utilisateur (/api/v1/orgs/{org}/*, jetons personnels) et les exports
// de la recherche (écran et API) : débit par jeton, jetons refusés par IP, durée et nombre
// d'exports simultanés par instance (un export garde une transaction en lecture ouverte
// pendant qu'il écrit, ADR 0024).
type UserAPI struct {
	RateLimit        int           `yaml:"rate_limit"         env:"USER_API_RATE_LIMIT"         env-default:"60" env-description:"User API requests per minute and per personal token (0: unlimited)"`
	FailureRateLimit int           `yaml:"failure_rate_limit" env:"USER_API_FAILURE_RATE_LIMIT" env-default:"30" env-description:"Refused personal tokens per minute and per IP (0: unlimited)"`
	ExportTimeout    time.Duration `yaml:"export_timeout"     env:"USER_API_EXPORT_TIMEOUT"     env-default:"5m" env-description:"Maximum duration of one search export (CSV or JSON)"`
	MaxExports       int           `yaml:"max_exports"        env:"USER_API_MAX_EXPORTS"        env-default:"4"  env-description:"Search exports running at once on this instance, beyond which 429 is returned"`
}

// AI est la politique de l'instance sur l'enrichissement IA des agents dépôt (T12,
// ADR 0043) : elle peut interdire tout fournisseur de modèle externe, quels que soient
// les réglages des projets (le réglage « external » est alors transmis comme « local »).
type AI struct {
	ForbidExternal bool `yaml:"forbid_external" env:"AI_FORBID_EXTERNAL" env-default:"false" env-description:"Forbid any external model provider for the AI enrichment of repository agents (projects set to external are treated as local)"`
}

// Bootstrap crée le premier administrateur d'instance sur une base sans compte (ignoré dès
// qu'un compte existe), et porte la procédure de secours d'un administrateur qui a perdu
// son TOTP. Ces valeurs sont lues au démarrage, et à retirer ensuite.
type Bootstrap struct {
	AdminEmail    string `yaml:"admin_email"       env:"BOOTSTRAP_ADMIN_EMAIL"       env-description:"E-mail of the first instance administrator, created when no account exists"`
	AdminPassword string `yaml:"admin_password"    env:"BOOTSTRAP_ADMIN_PASSWORD"    env-description:"Temporary password of the first administrator (12 characters at least, changed at first login)"`
	RescueEmail   string `yaml:"rescue_totp_email" env:"BOOTSTRAP_RESCUE_TOTP_EMAIL" env-description:"Rescue: e-mail of an instance administrator whose TOTP is reset at startup (audited)"`
	RescueTicket  string `yaml:"rescue_ticket"     env:"BOOTSTRAP_RESCUE_TICKET"     env-description:"Rescue: incident reference (8 characters at least); each ticket is applied once"`
	// RescuePassword devient le mot de passe temporaire de l'administrateur secouru : sans
	// lui, quiconque connaît l'ancien enrôlerait son propre TOTP (ADR 0029).
	RescuePassword string `yaml:"rescue_password" env:"BOOTSTRAP_RESCUE_PASSWORD" env-description:"Rescue: temporary password given to the rescued administrator (12 characters at least, changed at next sign-in)"`
}

// HTTP règle les délais des serveurs HTTP (public et gestion) et l'arrêt propre.
type HTTP struct {
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout" env:"HTTP_READ_HEADER_TIMEOUT" env-default:"10s"  env-description:"Maximum time to read request headers"`
	ReadTimeout       time.Duration `yaml:"read_timeout"        env:"HTTP_READ_TIMEOUT"        env-default:"60s"  env-description:"Maximum time to read a whole request, body included"`
	WriteTimeout      time.Duration `yaml:"write_timeout"       env:"HTTP_WRITE_TIMEOUT"       env-default:"60s"  env-description:"Maximum time to write a response"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"        env:"HTTP_IDLE_TIMEOUT"        env-default:"120s" env-description:"Keep-alive idle connection timeout"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout"    env:"HTTP_SHUTDOWN_TIMEOUT"    env-default:"30s"  env-description:"Grace period for in-flight requests on SIGTERM"`
}

// TLS active le TLS natif du serveur public. Sans lui, le serveur est placé derrière un
// mandataire inverse qui termine TLS, et le mTLS des agents est indisponible.
type TLS struct {
	CertFile     string `yaml:"cert_file"      env:"TLS_CERT_FILE"      env-description:"PEM certificate chain; enables native TLS with key_file"`
	KeyFile      string `yaml:"key_file"       env:"TLS_KEY_FILE"       env-description:"PEM private key of the certificate"`
	ClientCAFile string `yaml:"client_ca_file" env:"TLS_CLIENT_CA_FILE" env-description:"PEM CA bundle to verify agent client certificates (mTLS)"`
}

// Enabled indique si le TLS natif est configuré.
func (t TLS) Enabled() bool { return t.CertFile != "" || t.KeyFile != "" }

// Management décrit l'écoute de gestion : /healthz, /readyz et /metrics, séparés de
// l'interface publique pour ne jamais les exposer par erreur.
type Management struct {
	Host string `yaml:"host" env:"MANAGEMENT_HOST" env-default:"127.0.0.1" env-description:"Listen IP for probes and metrics"`
	Port int    `yaml:"port" env:"MANAGEMENT_PORT" env-default:"1761"      env-description:"Listen port for probes and metrics"`
}

// Database complète le fragment d'appconf (pilote et DSN du rôle d'exécution) par les
// réglages du pool.
type Database struct {
	appconf.Database `yaml:",inline"`

	MaxOpenConns    int           `yaml:"max_open_conns"    env:"DB_MAX_OPEN_CONNS"    env-default:"20"  env-description:"Maximum open connections of the runtime pool"`
	MaxIdleConns    int           `yaml:"max_idle_conns"    env:"DB_MAX_IDLE_CONNS"    env-default:"10"  env-description:"Maximum idle connections of the runtime pool"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" env:"DB_CONN_MAX_LIFETIME" env-default:"30m" env-description:"Maximum lifetime of a pooled connection"`
	StartupTimeout  time.Duration `yaml:"startup_timeout"   env:"DB_STARTUP_TIMEOUT"   env-default:"60s" env-description:"How long to wait for the database at startup"`
}

// Migration désigne la connexion du rôle propriétaire, utilisée seulement pour migrer.
// Sans DSN, le serveur ne migre pas et vérifie que le schéma est à jour.
type Migration struct {
	DSN         string        `yaml:"dsn"          env:"MIGRATION_DSN"          env-description:"Owner role connection, used only to migrate; empty to skip migrations"`
	MaxConns    int           `yaml:"max_conns"    env:"MIGRATION_MAX_CONNS"    env-default:"2"  env-description:"Connections of the migration pool (at least 2)"`
	LockTimeout time.Duration `yaml:"lock_timeout" env:"MIGRATION_LOCK_TIMEOUT" env-default:"5m" env-description:"Maximum wait for another instance's migration lock"`
}

// Secrets porte les clés de chiffrement des secrets stockés (internal/secret) : clés de
// 32 octets en base64, nommées, et le nom de la clé active.
type Secrets struct {
	Keys      map[string]string `yaml:"keys"       env:"SECRETS_KEYS"       env-description:"Encryption keys as id:base64 pairs separated by commas"`
	ActiveKey string            `yaml:"active_key" env:"SECRETS_ACTIVE_KEY" env-description:"Id of the key used to encrypt"`
}

// Workers règle la file de traitements (internal/jobs) : workers et planificateur de
// l'instance. Enabled n'a pas d'env-default : un défaut d'appconf l'emporterait sur un
// false écrit dans le fichier (il ne s'applique qu'à une valeur zéro) ; Defaults le pose.
type Workers struct {
	Enabled          bool          `yaml:"enabled"           env:"WORKERS_ENABLED"           env-description:"Run job workers and the scheduler on this instance"`
	Concurrency      int           `yaml:"concurrency"       env:"WORKERS_CONCURRENCY"       env-default:"4"    env-description:"Number of jobs this instance runs at the same time"`
	PollInterval     time.Duration `yaml:"poll_interval"     env:"WORKERS_POLL_INTERVAL"     env-default:"1s"   env-description:"Wait of an idle worker before looking for work again"`
	Lease            time.Duration `yaml:"lease"             env:"WORKERS_LEASE"             env-default:"30s"  env-description:"Job lease, renewed while the job runs; a vanished worker's job is taken over after it"`
	RetryBase        time.Duration `yaml:"retry_base"        env:"WORKERS_RETRY_BASE"        env-default:"10s"  env-description:"Delay before the first retry of a failed job, doubled at each attempt"`
	RetryMax         time.Duration `yaml:"retry_max"         env:"WORKERS_RETRY_MAX"         env-default:"30m"  env-description:"Maximum retry delay, before jitter"`
	Retention        time.Duration `yaml:"retention"         env:"WORKERS_RETENTION"         env-default:"168h" env-description:"How long finished jobs are kept"`
	ScheduleInterval time.Duration `yaml:"schedule_interval" env:"WORKERS_SCHEDULE_INTERVAL" env-default:"10s"  env-description:"How often the scheduler looks for due schedules"`
	ShutdownTimeout  time.Duration `yaml:"shutdown_timeout"  env:"WORKERS_SHUTDOWN_TIMEOUT"  env-default:"30s"  env-description:"Grace period for running jobs on SIGTERM, after which they are released"`
	OrgLimit         int           `yaml:"org_limit"         env:"WORKERS_ORG_LIMIT"         env-default:"2"    env-description:"Heavy jobs (SBOM decoding, analysis) running at the same time per organization, across all instances"`
}

// Defaults renvoie les valeurs qui diffèrent des défauts d'appconf : appconf ne pose un
// défaut que sur un champ vide, ces valeurs l'emportent donc tant que la configuration ne
// les change pas.
func Defaults() Config {
	var c Config
	c.Web.Port = 1758 // année de la description de Procyon lotor
	c.Database.Driver = "postgres"
	c.I18n.DefaultLanguage = "fr"
	c.Logging.Level = "info"
	c.Auth.CookieName = "lotor_session"
	c.MFA.Issuer = "lotor"
	c.Workers.Enabled = true
	c.Retention.Enabled, c.Retention.Monthly = true, true
	c.Signup.Mode = SignupPrivate
	return c
}

// Load lit la configuration (fichier -c s'il existe, sinon environnement ; --help et
// --version terminent le programme), puis la valide.
func Load(name, version string) (Config, error) {
	cfg := Defaults()
	if err := appconf.Load(&cfg, appconf.Options{Name: name, Version: version}); err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}
