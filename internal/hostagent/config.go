package hostagent

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"leblanc.io/open-go-base/appconf"
)

// EnvPrefix préfixe les variables d'environnement de l'agent serveur.
const EnvPrefix = "LOTOR_HOST_AGENT_"

// Modes de fonctionnement.
const (
	// ModeDaemon : scan à intervalle, signal de vie entre deux scans (demande de scan
	// depuis l'interface).
	ModeDaemon = "daemon"
	// ModeOneshot : un cycle (inscription au besoin, scan, envoi ou signal de vie), puis
	// sortie ; pour un timer systemd.
	ModeOneshot = "oneshot"
)

// Config est la configuration de lotor-host-agent (config.example.yaml de deploy/). Aucun
// secret n'y figure : le jeton d'inscription et la clé du certificat client sont des
// fichiers en 0600 ou des credentials systemd, le jeton d'agent vit dans le répertoire
// d'état.
type Config struct {
	Mode     string `yaml:"mode"      env:"LOTOR_HOST_AGENT_MODE"      env-default:"daemon" env-description:"daemon (interval scans and heartbeats) or oneshot (one cycle, for a systemd timer)"`
	Hostname string `yaml:"hostname"  env:"LOTOR_HOST_AGENT_HOSTNAME"  env-description:"Host name reported to the server (default: the system host name)"`
	StateDir string `yaml:"state_dir" env:"LOTOR_HOST_AGENT_STATE_DIR" env-default:"/var/lib/lotor-host-agent" env-description:"State directory: agent token and last inventory fingerprint (0700)"`
	// EnrollmentTokenFile est lu tant que l'agent n'a pas de jeton d'agent ; vide : le
	// credential systemd « enrollment-token », sinon DefaultEnrollmentTokenFile.
	EnrollmentTokenFile string            `yaml:"enrollment_token_file" env:"LOTOR_HOST_AGENT_ENROLLMENT_TOKEN_FILE" env-description:"File holding the enrollment token (0600), read until the agent is enrolled"`
	Labels              map[string]string `yaml:"labels"                env:"LOTOR_HOST_AGENT_LABELS"                env-description:"Labels of the host project created at enrollment, as key:value pairs separated by commas"`
	Server              Server            `yaml:"server"`
	Scan                Scan              `yaml:"scan"`
	Containers          Containers        `yaml:"containers"`
	Resources           Resources         `yaml:"resources"`
	Logging             appconf.Logging   `yaml:"logging" env-prefix:"LOTOR_HOST_AGENT_"`
}

// DefaultEnrollmentTokenFile est le jeton d'inscription déposé par l'assistant
// d'installation.
const DefaultEnrollmentTokenFile = "/etc/lotor-host-agent/enrollment-token"

// Server décrit la connexion au serveur.
type Server struct {
	URL            string `yaml:"url"              env:"LOTOR_HOST_AGENT_SERVER_URL"              env-description:"Server address (https://…)"`
	CAFile         string `yaml:"ca_file"          env:"LOTOR_HOST_AGENT_SERVER_CA_FILE"          env-description:"PEM bundle of a private certificate authority (replaces the system ones)"`
	ClientCertFile string `yaml:"client_cert_file" env:"LOTOR_HOST_AGENT_SERVER_CLIENT_CERT_FILE" env-description:"Client certificate (PEM) for mTLS"`
	// ClientKeyFile : vide, le credential systemd « client-key » s'il existe.
	ClientKeyFile string        `yaml:"client_key_file" env:"LOTOR_HOST_AGENT_SERVER_CLIENT_KEY_FILE" env-description:"Client certificate key (PEM, 0600) for mTLS; default: the client-key systemd credential"`
	Proxy         string        `yaml:"proxy"           env:"LOTOR_HOST_AGENT_SERVER_PROXY"           env-description:"HTTP(S) proxy URL (default: HTTPS_PROXY and NO_PROXY)"`
	Timeout       time.Duration `yaml:"timeout"         env:"LOTOR_HOST_AGENT_SERVER_TIMEOUT"         env-default:"2m" env-description:"Timeout of one request attempt, body included"`
	Retries       int           `yaml:"retries"         env:"LOTOR_HOST_AGENT_SERVER_RETRIES"         env-default:"5"  env-description:"Attempts of one request (transient errors, 429, 5xx)"`
	Language      string        `yaml:"language"        env:"LOTOR_HOST_AGENT_SERVER_LANGUAGE"        env-default:"en" env-description:"Language of server error messages (en, fr)"`
}

// Scan règle l'inventaire.
type Scan struct {
	// Root est la racine inventoriée ; autre chose que « / » ne sert qu'aux essais.
	Root         string        `yaml:"root"          env:"LOTOR_HOST_AGENT_SCAN_ROOT"          env-default:"/"   env-description:"Root of the inventory (/ on a host)"`
	Interval     time.Duration `yaml:"interval"      env:"LOTOR_HOST_AGENT_SCAN_INTERVAL"      env-default:"24h" env-description:"Daemon: time between two scans"`
	PollInterval time.Duration `yaml:"poll_interval" env:"LOTOR_HOST_AGENT_SCAN_POLL_INTERVAL" env-default:"5m"  env-description:"Daemon: time between two heartbeats (on-demand scan requests)"`
	MaxDuration  time.Duration `yaml:"max_duration"  env:"LOTOR_HOST_AGENT_SCAN_MAX_DURATION"  env-default:"1h"  env-description:"Maximum duration of one scan"`
	// Exclude complète les exclusions par défaut (DefaultExclusions) : chemins absolus,
	// motifs doublestar admis (/home/*/www, /srv/data/**/cache), comparés au chemin complet
	// depuis la racine du scan (TestConfiguredExclusionPatterns).
	Exclude []string `yaml:"exclude" env:"LOTOR_HOST_AGENT_SCAN_EXCLUDE" env-separator:"," env-description:"Absolute paths excluded from the scan, besides the defaults"`
}

// Containers règle l'inventaire des conteneurs en cours d'exécution (T13, ADR 0041).
// L'accès à la socket d'un moteur de conteneurs équivaut à root sur l'hôte : l'inventaire
// est désactivé par défaut, et l'agent n'ouvre alors aucune socket.
type Containers struct {
	Enabled bool `yaml:"enabled" env:"LOTOR_HOST_AGENT_CONTAINERS_ENABLED" env-description:"Inventory the running containers through the Docker or Podman socket (access to an engine socket is equivalent to root)"`
	// Sockets : vide, DefaultSockets (une socket absente est ignorée).
	Sockets []string `yaml:"sockets" env:"LOTOR_HOST_AGENT_CONTAINERS_SOCKETS" env-separator:"," env-description:"Engine sockets (Docker API), separated by commas; default /run/docker.sock and /run/podman/podman.sock"`
	// WorkDir reçoit l'archive d'une image le temps de son scan ; vide : <state_dir>/images.
	WorkDir     string        `yaml:"work_dir"      env:"LOTOR_HOST_AGENT_CONTAINERS_WORK_DIR"      env-description:"Directory holding an exported image while it is scanned (default: <state_dir>/images)"`
	MaxImageMiB int           `yaml:"max_image_mib" env:"LOTOR_HOST_AGENT_CONTAINERS_MAX_IMAGE_MIB" env-default:"4096" env-description:"Largest image exported for a scan, in MiB; a larger image is skipped"`
	Timeout     time.Duration `yaml:"timeout"       env:"LOTOR_HOST_AGENT_CONTAINERS_TIMEOUT"       env-default:"30s"  env-description:"Timeout of one engine API call (image exports excepted)"`
}

// ImagesDir renvoie le répertoire des archives d'images.
func (c Config) ImagesDir() string {
	if c.Containers.WorkDir != "" {
		return c.Containers.WorkDir
	}
	return filepath.Join(c.StateDir, "images")
}

// Resources borne ce que l'agent consomme.
type Resources struct {
	MaxProcs       int `yaml:"max_procs"        env:"LOTOR_HOST_AGENT_MAX_PROCS"        env-default:"1"   env-description:"GOMAXPROCS and scan parallelism"`
	MemoryLimitMiB int `yaml:"memory_limit_mib" env:"LOTOR_HOST_AGENT_MEMORY_LIMIT_MIB" env-default:"512" env-description:"Soft memory limit of the Go runtime (GOMEMLIMIT), in MiB; 0 to disable"`
}

// Defaults renvoie les valeurs posées avant le chargement (appconf ne pose un défaut que
// sur un champ vide).
func Defaults() Config {
	var c Config
	c.Logging.Level = "info"
	return c
}

// Load lit la configuration (fichier -c, sinon l'environnement ; --help et --version
// terminent le programme), puis la valide.
func Load(name, version, defaultPath string) (Config, error) {
	cfg := Defaults()
	if err := appconf.Load(&cfg, appconf.Options{Name: name, Version: version, DefaultCfgPath: defaultPath}); err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}

// Validate vérifie la configuration et renvoie toutes les erreurs.
func (c Config) Validate() error {
	var errs []error
	fail := func(path, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s : %s", path, fmt.Sprintf(format, args...)))
	}
	if !slices.Contains([]string{ModeDaemon, ModeOneshot}, c.Mode) {
		fail("mode", "%q invalide (daemon ou oneshot)", c.Mode)
	}
	if u, err := url.Parse(c.Server.URL); err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.User != nil {
		fail("server.url", "adresse https://hôte attendue")
	}
	if c.Server.ClientKeyFile != "" && c.Server.ClientCertFile == "" {
		fail("server.client_cert_file", "obligatoire avec server.client_key_file")
	}
	if !filepath.IsAbs(c.StateDir) {
		fail("state_dir", "chemin absolu attendu")
	}
	if c.EnrollmentTokenFile != "" && !filepath.IsAbs(c.EnrollmentTokenFile) {
		fail("enrollment_token_file", "chemin absolu attendu")
	}
	if !filepath.IsAbs(c.Scan.Root) {
		fail("scan.root", "chemin absolu attendu")
	}
	for _, e := range c.Scan.Exclude {
		if !filepath.IsAbs(e) {
			fail("scan.exclude", "%q : chemin absolu attendu", e)
		}
	}
	for _, s := range c.Containers.Sockets {
		if !filepath.IsAbs(s) {
			fail("containers.sockets", "%q : chemin absolu attendu", s)
		}
	}
	if c.Containers.WorkDir != "" && !filepath.IsAbs(c.Containers.WorkDir) {
		fail("containers.work_dir", "chemin absolu attendu")
	}
	if c.Containers.MaxImageMiB < 16 || c.Containers.MaxImageMiB > 65536 {
		fail("containers.max_image_mib", "entre 16 et 65536")
	}
	if c.Containers.Timeout < time.Second {
		fail("containers.timeout", "une seconde au moins")
	}
	if c.Scan.Interval < time.Hour {
		fail("scan.interval", "une heure au moins")
	}
	if c.Scan.PollInterval < 30*time.Second || c.Scan.PollInterval > c.Scan.Interval {
		fail("scan.poll_interval", "entre 30 s et scan.interval")
	}
	if c.Scan.MaxDuration < time.Minute {
		fail("scan.max_duration", "une minute au moins")
	}
	if c.Server.Timeout < time.Second {
		fail("server.timeout", "une seconde au moins")
	}
	if c.Server.Retries < 1 || c.Server.Retries > 20 {
		fail("server.retries", "entre 1 et 20")
	}
	if c.Resources.MaxProcs < 1 || c.Resources.MaxProcs > 1024 {
		fail("resources.max_procs", "entre 1 et 1024")
	}
	if c.Resources.MemoryLimitMiB < 0 || (c.Resources.MemoryLimitMiB > 0 && c.Resources.MemoryLimitMiB < 64) {
		fail("resources.memory_limit_mib", "0 (sans limite) ou 64 au moins")
	}
	if len(c.Labels) > 32 {
		fail("labels", "32 au plus")
	}
	for k := range c.Labels {
		if strings.TrimSpace(k) == "" {
			fail("labels", "clé vide")
		}
	}
	return errors.Join(errs...)
}
