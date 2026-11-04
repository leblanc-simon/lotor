package repoagent

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"leblanc.io/open-go-base/appconf"

	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/forge"
	"leblanc.io/lotor/internal/llm"
)

// EnvPrefix préfixe les variables d'environnement de l'agent dépôt.
const EnvPrefix = "LOTOR_REPO_"

// Config est la configuration de lotor-repo-agent. Aucun secret n'y figure : jeton
// d'agent, clé privée de la GitHub App, jetons des comptes de service et secrets de
// webhook sont désignés par « credential:nom » (credentials systemd) ou par le chemin d'un
// fichier en 0600 (ReadSecret).
type Config struct {
	Logging appconf.Logging `yaml:"logging" env-prefix:"LOTOR_REPO_"`
	Server  ServerConfig    `yaml:"server"  env-prefix:"LOTOR_REPO_"`
	Webhook WebhookConfig   `yaml:"webhook" env-prefix:"LOTOR_REPO_"`
	Work    WorkConfig      `yaml:"work"    env-prefix:"LOTOR_REPO_"`
	Catchup CatchupConfig   `yaml:"catchup" env-prefix:"LOTOR_REPO_"`
	AI      AIConfig        `yaml:"ai"      env-prefix:"LOTOR_REPO_"`
	Status  StatusConfig    `yaml:"status"  env-prefix:"LOTOR_REPO_"`
	// DependencyTrack : sortie supplémentaire vers Dependency-Track (T19, ADR 0057).
	DependencyTrack DTConfig `yaml:"dependency_track" env-prefix:"LOTOR_REPO_"`
	// Offline : archive hors ligne de chaque envoi, en plus de l'envoi réseau (T23).
	Offline OfflineConfig `yaml:"offline" env-prefix:"LOTOR_REPO_"`
	// Forges ne se déclarent que dans le fichier de configuration.
	Forges []Forge `yaml:"forges"`
}

// ServerConfig décrit le serveur lotor et le jeton d'agent.
type ServerConfig struct {
	URL       string        `yaml:"url"        env:"SERVER_URL"        env-description:"URL of the lotor server (https://sbom.example.org)"`
	TokenFile string        `yaml:"token_file" env:"SERVER_TOKEN_FILE" env-default:"credential:agent-token" env-description:"Agent token: credential:<name> (systemd credential) or absolute path of a 0600 file"`
	CAFile    string        `yaml:"ca_file"    env:"SERVER_CA_FILE"    env-description:"PEM file of the authority that signed the server certificate (system roots if empty)"`
	Timeout   time.Duration `yaml:"timeout"    env:"SERVER_TIMEOUT"    env-default:"2m"  env-description:"Maximum duration of one request to the server (SBOM upload included)"`
	// ClientCertFile et ClientKeyFile : certificat client du mTLS (la clé est un secret :
	// credential:<nom> ou fichier en 0600).
	ClientCertFile string `yaml:"client_cert_file" env:"SERVER_CLIENT_CERT_FILE" env-description:"Client certificate (PEM) for mTLS"`
	ClientKeyFile  string `yaml:"client_key_file"  env:"SERVER_CLIENT_KEY_FILE"  env-description:"Client certificate key for mTLS: credential:<name> or absolute path of a 0600 file"`
	Proxy          string `yaml:"proxy"            env:"SERVER_PROXY"            env-description:"HTTP(S) proxy URL (default: HTTPS_PROXY and NO_PROXY)"`
	Retries        int    `yaml:"retries"          env:"SERVER_RETRIES"          env-default:"5" env-description:"Attempts of one request (network errors, 429, 5xx; Retry-After honoured)"`
}

// WebhookConfig décrit le récepteur de webhooks, exposé aux forges.
type WebhookConfig struct {
	Listen         string   `yaml:"listen"          env:"WEBHOOK_LISTEN"          env-default:":1762" env-description:"Listen address of the webhook receiver (POST /webhooks/<forge>); empty: no receiver, catch-up only"`
	TLSCertFile    string   `yaml:"tls_cert_file"   env:"WEBHOOK_TLS_CERT_FILE"   env-description:"PEM certificate for native TLS (otherwise behind a TLS reverse proxy)"`
	TLSKeyFile     string   `yaml:"tls_key_file"    env:"WEBHOOK_TLS_KEY_FILE"    env-description:"Private key for native TLS: credential:<name> or absolute path of a 0600 file"`
	MaxBodyKiB     int      `yaml:"max_body_kib"    env:"WEBHOOK_MAX_BODY_KIB"    env-default:"1024" env-description:"Maximum webhook body size, in KiB"`
	RateLimit      int      `yaml:"rate_limit"      env:"WEBHOOK_RATE_LIMIT"      env-default:"120"  env-description:"Webhook requests per minute and per IP (0: unlimited)"`
	TrustedProxies []string `yaml:"trusted_proxies" env:"WEBHOOK_TRUSTED_PROXIES" env-separator:"," env-description:"Reverse proxies (IP or CIDR) whose X-Forwarded-For is trusted for rate limiting"`
}

// WorkConfig borne le travail d'analyse.
type WorkConfig struct {
	Dir          string        `yaml:"dir"           env:"WORK_DIR"           env-default:"/var/lib/lotor-repo-agent/work" env-description:"Working directory: one subdirectory per analysis, always removed"`
	Parallelism  int           `yaml:"parallelism"   env:"WORK_PARALLELISM"   env-default:"2"    env-description:"Analyses run at the same time"`
	QueueSize    int           `yaml:"queue_size"    env:"WORK_QUEUE_SIZE"    env-default:"1000" env-description:"Maximum references waiting for analysis (in memory, deduplicated)"`
	CloneTimeout time.Duration `yaml:"clone_timeout" env:"WORK_CLONE_TIMEOUT" env-default:"10m"  env-description:"Maximum duration of a clone"`
	ScanTimeout  time.Duration `yaml:"scan_timeout"  env:"WORK_SCAN_TIMEOUT"  env-default:"15m"  env-description:"Maximum duration of a Syft scan"`
	MaxCloneMiB  int           `yaml:"max_clone_mib" env:"WORK_MAX_CLONE_MIB" env-default:"1024" env-description:"Maximum size of a clone on disk, in MiB"`
	Git          string        `yaml:"git"           env:"WORK_GIT"           env-default:"git"  env-description:"git binary"`
}

// CatchupConfig règle le rattrapage : au démarrage puis à intervalle, chaque référence suivie
// est comparée au dernier commit connu du serveur.
type CatchupConfig struct {
	Interval   time.Duration `yaml:"interval"    env:"CATCHUP_INTERVAL"    env-default:"15m" env-description:"Interval between two catch-up passes"`
	MaxCommits int           `yaml:"max_commits" env:"CATCHUP_MAX_COMMITS" env-default:"20"  env-description:"Maximum missed commits analysed per reference (the most recent ones)"`
}

// AIConfig règle l'enrichissement IA (T12). Sans modèle configuré, l'agent envoie le SBOM
// Syft seul, quel que soit le réglage des projets ; un projet réglé « IA désactivée »
// n'appelle jamais de modèle, quelle que soit cette configuration.
type AIConfig struct {
	Local    LocalAIConfig    `yaml:"local"`
	External ExternalAIConfig `yaml:"external"`
	// Budget d'une analyse : au-delà, l'analyse s'arrête et le SBOM part sans composant IA,
	// marqué « enrichissement incomplet ».
	MaxTurns        int           `yaml:"max_turns"         env:"AI_MAX_TURNS"         env-default:"40"     env-description:"Maximum model turns of one AI analysis"`
	MaxInputTokens  int64         `yaml:"max_input_tokens"  env:"AI_MAX_INPUT_TOKENS"  env-default:"600000" env-description:"Maximum input tokens of one AI analysis (all turns, cache included)"`
	MaxOutputTokens int64         `yaml:"max_output_tokens" env:"AI_MAX_OUTPUT_TOKENS" env-default:"40000"  env-description:"Maximum output tokens of one AI analysis"`
	MaxReadKiB      int           `yaml:"max_read_kib"      env:"AI_MAX_READ_KIB"      env-default:"1024"   env-description:"Maximum repository content returned to the model by the tools, in KiB"`
	ResponseTokens  int           `yaml:"response_tokens"   env:"AI_RESPONSE_TOKENS"   env-default:"8192"   env-description:"Maximum output tokens of one model response"`
	Timeout         time.Duration `yaml:"timeout"           env:"AI_TIMEOUT"           env-default:"20m"    env-description:"Maximum duration of one AI analysis"`
	FullInterval    time.Duration `yaml:"full_interval"     env:"AI_FULL_INTERVAL"     env-default:"168h"   env-description:"A reference gets a full AI analysis at least this often (otherwise changed files only)"`
	// Exclude complète DefaultExclude (fichiers jamais montrés au modèle).
	Exclude []string `yaml:"exclude" env:"AI_EXCLUDE" env-separator:"," env-description:"Extra file patterns never shown to the model (added to the built-in list of secrets and keys)"`
}

// LocalAIConfig décrit le modèle local (Ollama), qui reste dans l'infrastructure de
// l'exploitant.
type LocalAIConfig struct {
	URL           string        `yaml:"url"            env:"AI_LOCAL_URL"            env-description:"Ollama server URL (http://127.0.0.1:11434); empty: no local model"`
	Model         string        `yaml:"model"          env:"AI_LOCAL_MODEL"          env-description:"Ollama model (with tool calling)"`
	ContextTokens int           `yaml:"context_tokens" env:"AI_LOCAL_CONTEXT_TOKENS" env-default:"32768" env-description:"Context window requested from Ollama"`
	Timeout       time.Duration `yaml:"timeout"        env:"AI_LOCAL_TIMEOUT"        env-default:"5m"    env-description:"Maximum duration of one request to Ollama"`
}

// ExternalAIConfig décrit le fournisseur externe (Anthropic). Il ne reçoit le code que des
// projets qu'un administrateur d'organisation a autorisés, si l'instance le permet.
type ExternalAIConfig struct {
	Provider   string        `yaml:"provider"     env:"AI_EXTERNAL_PROVIDER"     env-description:"External provider: anthropic, or empty for none"`
	Model      string        `yaml:"model"        env:"AI_EXTERNAL_MODEL"        env-default:"claude-sonnet-5-5" env-description:"Model of the external provider"`
	APIKeyFile string        `yaml:"api_key_file" env:"AI_EXTERNAL_API_KEY_FILE" env-default:"credential:anthropic-api-key" env-description:"API key: credential:<name> or absolute path of a 0600 file"`
	BaseURL    string        `yaml:"base_url"     env:"AI_EXTERNAL_BASE_URL"     env-default:"https://api.anthropic.com" env-description:"API URL of the external provider"`
	Timeout    time.Duration `yaml:"timeout"      env:"AI_EXTERNAL_TIMEOUT"      env-default:"5m" env-description:"Maximum duration of one request to the provider"`
	Retries    int           `yaml:"retries"      env:"AI_EXTERNAL_RETRIES"      env-default:"2"  env-description:"Retries of one request (429, 5xx, network errors)"`
}

// OfflineConfig règle la sortie « fichier » de l'agent dépôt : une archive par SBOM envoyé
// au serveur, écrite dans Dir (vide : désactivée).
type OfflineConfig struct {
	Dir string `yaml:"dir" env:"OFFLINE_DIR" env-description:"Directory receiving an offline archive of every uploaded SBOM, besides the upload; empty: no file output"`
}

// DTConfig règle la sortie vers Dependency-Track : le SBOM du commit de tête de chaque
// référence analysée part aussi vers un Dependency-Track, après son envoi au serveur
// lotor (les commits intermédiaires d'un rattrapage n'y vont pas). Le nom et la version
// du projet sont des gabarits : {name} (nom du projet lotor), {slug}, {ref} (branche ou
// étiquette).
type DTConfig struct {
	URL            string `yaml:"url"             env:"DT_URL"             env-description:"Dependency-Track base address (https://…); empty: no Dependency-Track output"`
	APIKeyFile     string `yaml:"api_key_file"    env:"DT_API_KEY_FILE"    env-default:"credential:dependency-track-api-key" env-description:"Dependency-Track API key: credential:<name> or absolute path of a 0600 file"`
	CAFile         string `yaml:"ca_file"         env:"DT_CA_FILE"         env-description:"PEM file of the authority that signed the Dependency-Track certificate (system roots if empty)"`
	Proxy          string `yaml:"proxy"           env:"DT_PROXY"           env-description:"HTTP(S) proxy URL for Dependency-Track (default: HTTPS_PROXY and NO_PROXY)"`
	ProjectName    string `yaml:"project_name"    env:"DT_PROJECT_NAME"    env-default:"{name}" env-description:"Dependency-Track project name template: {name}, {slug}, {ref}"`
	ProjectVersion string `yaml:"project_version" env:"DT_PROJECT_VERSION" env-default:"{ref}"  env-description:"Dependency-Track project version template: {name}, {slug}, {ref}"`
	AutoCreate     bool   `yaml:"auto_create"     env:"DT_AUTO_CREATE"     env-description:"Create missing projects and versions in Dependency-Track (PROJECT_CREATION_UPLOAD permission)"`
}

// Enabled dit si la sortie vers Dependency-Track est configurée.
func (d DTConfig) Enabled() bool { return d.URL != "" }

// Target remplit les gabarits du projet et de la version pour une référence.
func (d DTConfig) Target(name, slug, ref string) agentclient.DTTarget {
	r := strings.NewReplacer("{name}", name, "{slug}", slug, "{ref}", ref)
	return agentclient.DTTarget{ProjectName: r.Replace(d.ProjectName), ProjectVersion: r.Replace(d.ProjectVersion),
		AutoCreate: d.AutoCreate}
}

func (d DTConfig) validate() []error {
	if !d.Enabled() {
		return nil
	}
	var errs []error
	if u, err := url.Parse(d.URL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" {
		errs = append(errs, errors.New("dependency_track.url : URL https absolue sans identifiants attendue"))
	}
	if d.APIKeyFile == "" {
		errs = append(errs, errors.New("dependency_track.api_key_file obligatoire"))
	}
	for field, v := range map[string]string{"project_name": d.ProjectName, "project_version": d.ProjectVersion} {
		if strings.TrimSpace(v) == "" || len(v) > 255 {
			errs = append(errs, fmt.Errorf("dependency_track.%s : gabarit de 1 à 255 caractères", field))
		}
	}
	return errs
}

// Forge décrit une forge. GitHub : app_id, private_key_file et facultativement
// installation_id ; GitLab : token_file. AllowedNamespaces borne les dépôts que l'agent
// accepte d'analyser (propriétaires GitHub, groupes GitLab, « * » pour tous) : le choix
// des dépôts vient du serveur, c'est-à-dire des administrateurs d'organisation ; c'est à
// l'exploitant de l'agent de dire ce que ses identifiants peuvent lire pour eux (SEC-10).
type Forge struct {
	Name              string        `yaml:"name"`
	AllowedNamespaces []string      `yaml:"allowed_namespaces"`
	Kind              forge.Kind    `yaml:"kind"`
	URL               string        `yaml:"url"`
	APIURL            string        `yaml:"api_url"`
	AppID             string        `yaml:"app_id"`
	InstallationID    int64         `yaml:"installation_id"`
	PrivateKeyFile    string        `yaml:"private_key_file"`
	TokenFile         string        `yaml:"token_file"`
	WebhookSecretFile string        `yaml:"webhook_secret_file"`
	Timeout           time.Duration `yaml:"timeout"`
}

// Defaults renvoie les valeurs posées avant le chargement.
func Defaults() Config {
	var c Config
	c.Logging.Level = "info"
	return c
}

// Load lit la configuration (fichier -c s'il existe, sinon environnement ; --help et
// --version terminent le programme), puis la valide.
func Load(name, version, defaultPath string) (Config, error) {
	cfg := Defaults()
	if err := appconf.Load(&cfg, appconf.Options{Name: name, Version: version, DefaultCfgPath: defaultPath}); err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}

// Plafonds de configuration.
const (
	maxParallelism = 64
	maxQueue       = 100_000
	maxCommits     = 250
	maxBodyKiB     = 25 << 10 // 25 Mio : la limite des webhooks de GitHub
)

var forgeName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Validate vérifie la configuration, sans lire les secrets.
func (c Config) Validate() error {
	var errs []error
	if err := validServerURL(c.Server.URL); err != nil {
		errs = append(errs, err)
	}
	if c.Server.TokenFile == "" {
		errs = append(errs, errors.New("server.token_file obligatoire"))
	}
	if (c.Server.ClientCertFile == "") != (c.Server.ClientKeyFile == "") {
		errs = append(errs, errors.New("server.client_cert_file et server.client_key_file vont ensemble"))
	}
	if c.Server.Retries < 1 || c.Server.Retries > 20 {
		errs = append(errs, errors.New("server.retries : entre 1 et 20"))
	}
	if c.Server.Timeout <= 0 {
		errs = append(errs, errors.New("server.timeout doit être positif"))
	}
	if c.Webhook.Listen != "" {
		if _, _, err := net.SplitHostPort(c.Webhook.Listen); err != nil {
			errs = append(errs, fmt.Errorf("webhook.listen : %w", err))
		}
	}
	if (c.Webhook.TLSCertFile == "") != (c.Webhook.TLSKeyFile == "") {
		errs = append(errs, errors.New("webhook.tls_cert_file et webhook.tls_key_file vont ensemble"))
	}
	if c.Webhook.MaxBodyKiB < 1 || c.Webhook.MaxBodyKiB > maxBodyKiB {
		errs = append(errs, fmt.Errorf("webhook.max_body_kib entre 1 et %d", maxBodyKiB))
	}
	if c.Webhook.RateLimit < 0 {
		errs = append(errs, errors.New("webhook.rate_limit négatif"))
	}
	if c.Work.Dir == "" || !strings.HasPrefix(c.Work.Dir, "/") {
		errs = append(errs, errors.New("work.dir : chemin absolu attendu"))
	}
	if c.Work.Parallelism < 1 || c.Work.Parallelism > maxParallelism {
		errs = append(errs, fmt.Errorf("work.parallelism entre 1 et %d", maxParallelism))
	}
	if c.Work.QueueSize < 1 || c.Work.QueueSize > maxQueue {
		errs = append(errs, fmt.Errorf("work.queue_size entre 1 et %d", maxQueue))
	}
	if c.Status.Enabled && (c.Status.Context == "" || len(c.Status.Context) > 100 || c.Status.Timeout <= 0 ||
		c.Status.Timeout > 2*time.Hour || c.Status.Poll <= 0) {
		errs = append(errs, errors.New("status : context de 1 à 100 caractères, timeout dans ]0, 2h], poll positif"))
	}
	if c.Work.CloneTimeout <= 0 || c.Work.ScanTimeout <= 0 {
		errs = append(errs, errors.New("work.clone_timeout et work.scan_timeout doivent être positifs"))
	}
	if c.Work.MaxCloneMiB < 1 {
		errs = append(errs, errors.New("work.max_clone_mib doit être positif"))
	}
	if c.Work.Git == "" {
		errs = append(errs, errors.New("work.git obligatoire"))
	}
	if c.Catchup.Interval < time.Minute {
		errs = append(errs, errors.New("catchup.interval : une minute au moins"))
	}
	if c.Catchup.MaxCommits < 1 || c.Catchup.MaxCommits > maxCommits {
		errs = append(errs, fmt.Errorf("catchup.max_commits entre 1 et %d", maxCommits))
	}
	errs = append(errs, c.AI.validate()...)
	errs = append(errs, c.DependencyTrack.validate()...)
	if d := c.Offline.Dir; d != "" && !strings.HasPrefix(d, "/") {
		errs = append(errs, errors.New("offline.dir : chemin absolu attendu"))
	}
	if len(c.Forges) == 0 {
		errs = append(errs, errors.New("forges : au moins une forge"))
	}
	seen := map[string]bool{}
	for i, f := range c.Forges {
		if err := f.validate(); err != nil {
			errs = append(errs, fmt.Errorf("forges[%d] : %w", i, err))
		}
		if seen[f.Name] {
			errs = append(errs, fmt.Errorf("forges[%d] : nom %q en double", i, f.Name))
		}
		seen[f.Name] = true
	}
	return errors.Join(errs...)
}

func validServerURL(s string) error {
	u, err := url.Parse(s)
	if s == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("server.url : URL https absolue sans identifiants attendue (l'agent ne parle qu'en HTTPS)")
	}
	return nil
}

func (f Forge) validate() error {
	if !forgeName.MatchString(f.Name) {
		return errors.New("name : minuscules, chiffres et tirets (63 caractères au plus)")
	}
	if f.WebhookSecretFile == "" {
		return errors.New("webhook_secret_file obligatoire")
	}
	if f.Timeout < 0 {
		return errors.New("timeout négatif")
	}
	if len(f.AllowedNamespaces) == 0 {
		return errors.New(`allowed_namespaces obligatoire : propriétaires ou groupes autorisés, ou "*" pour tous`)
	}
	for _, ns := range f.AllowedNamespaces {
		if ns != "*" && (ns == "" || strings.HasPrefix(ns, "/") || strings.HasSuffix(ns, "/") || strings.Contains(ns, "//") || strings.Contains(ns, "*")) {
			return fmt.Errorf("allowed_namespaces : %q n'est ni « * » ni un chemin de propriétaire ou de groupe", ns)
		}
	}
	switch f.Kind {
	case forge.KindGitHub:
		if f.AppID == "" || f.PrivateKeyFile == "" {
			return errors.New("GitHub : app_id et private_key_file obligatoires")
		}
		if f.TokenFile != "" {
			return errors.New("GitHub : token_file est réservé à GitLab")
		}
	case forge.KindGitLab:
		if f.TokenFile == "" {
			return errors.New("GitLab : token_file obligatoire")
		}
		if f.AppID != "" || f.PrivateKeyFile != "" || f.APIURL != "" || f.InstallationID != 0 {
			return errors.New("GitLab : app_id, private_key_file, api_url et installation_id sont réservés à GitHub")
		}
	default:
		return fmt.Errorf("kind %q inconnu (github, gitlab)", f.Kind)
	}
	return nil
}

func (a AIConfig) validate() []error {
	var errs []error
	if a.MaxTurns < 1 || a.MaxTurns > 500 {
		errs = append(errs, errors.New("ai.max_turns entre 1 et 500"))
	}
	if a.MaxInputTokens < 1000 || a.MaxOutputTokens < 100 || a.ResponseTokens < 256 || int64(a.ResponseTokens) > a.MaxOutputTokens {
		errs = append(errs, errors.New("ai : budgets de jetons trop petits, ou response_tokens au-delà de max_output_tokens"))
	}
	if a.MaxReadKiB < 16 {
		errs = append(errs, errors.New("ai.max_read_kib : 16 au moins"))
	}
	if a.Timeout <= 0 || a.FullInterval < time.Hour {
		errs = append(errs, errors.New("ai.timeout positif et ai.full_interval d'une heure au moins"))
	}
	if _, err := newExclusions(a.Exclude); err != nil {
		errs = append(errs, fmt.Errorf("ai.exclude : %w", err))
	}
	if a.Local.URL != "" {
		if u, err := url.Parse(a.Local.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			errs = append(errs, errors.New("ai.local.url : URL http(s) absolue sans identifiants attendue"))
		}
		if a.Local.Model == "" {
			errs = append(errs, errors.New("ai.local.model obligatoire avec ai.local.url"))
		}
		if a.Local.Timeout <= 0 {
			errs = append(errs, errors.New("ai.local.timeout doit être positif"))
		}
	}
	switch a.External.Provider {
	case "":
	case "anthropic":
		if u, err := url.Parse(a.External.BaseURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			errs = append(errs, errors.New("ai.external.base_url : URL https absolue sans identifiants attendue"))
		}
		if a.External.Model == "" || a.External.APIKeyFile == "" {
			errs = append(errs, errors.New("ai.external.model et ai.external.api_key_file obligatoires"))
		}
		if a.External.Timeout <= 0 || a.External.Retries < 0 || a.External.Retries > 10 {
			errs = append(errs, errors.New("ai.external.timeout positif et ai.external.retries entre 0 et 10"))
		}
	default:
		errs = append(errs, fmt.Errorf("ai.external.provider %q inconnu (anthropic, ou vide)", a.External.Provider))
	}
	return errs
}

// Models construit les modèles configurés (nil pour un modèle absent), en lisant la clé
// d'API du fournisseur externe.
func (a AIConfig) Models() (local, external llm.Provider, err error) {
	if a.Local.URL != "" {
		local, err = llm.NewOllama(llm.OllamaConfig{URL: a.Local.URL, Model: a.Local.Model,
			ContextTokens: a.Local.ContextTokens, Timeout: a.Local.Timeout})
		if err != nil {
			return nil, nil, err
		}
	}
	if a.External.Provider == "anthropic" {
		key, err := ReadSecret(a.External.APIKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("clé d'API du fournisseur externe : %w", err)
		}
		external, err = llm.NewAnthropic(llm.AnthropicConfig{APIKey: strings.TrimSpace(string(key)), Model: a.External.Model,
			BaseURL: a.External.BaseURL, Timeout: a.External.Timeout, MaxRetries: a.External.Retries})
		if err != nil {
			return nil, nil, err
		}
	}
	return local, external, nil
}

// Providers construit les forges, en lisant leurs secrets.
func (c Config) Providers() ([]forge.Provider, error) {
	var out []forge.Provider
	for _, f := range c.Forges {
		p, err := f.provider()
		if err != nil {
			return nil, fmt.Errorf("forge %s : %w", f.Name, err)
		}
		out = append(out, Scoped(p, f.AllowedNamespaces))
	}
	return out, nil
}

// Scoped borne p aux dépôts des espaces allowed (« * » : tous) : un dépôt hors périmètre
// n'est pas reconnu (Repo faux), donc jamais cloné ni analysé, quelle que soit l'URL de
// forge que le serveur envoie.
func Scoped(p forge.Provider, allowed []string) forge.Provider {
	if slices.Contains(allowed, "*") {
		return p
	}
	lower := make([]string, len(allowed))
	for i, ns := range allowed {
		lower[i] = strings.ToLower(ns)
	}
	return scopedProvider{Provider: p, allowed: lower}
}

type scopedProvider struct {
	forge.Provider
	allowed []string
}

func (s scopedProvider) Repo(forgeURL string) (string, bool) {
	repo, ok := s.Provider.Repo(forgeURL)
	if !ok {
		return "", false
	}
	r := strings.ToLower(repo)
	for _, ns := range s.allowed {
		if strings.HasPrefix(r, ns+"/") {
			return repo, true
		}
	}
	return "", false
}

func (f Forge) provider() (forge.Provider, error) {
	hook, err := ReadSecret(f.WebhookSecretFile)
	if err != nil {
		return nil, err
	}
	timeout := f.Timeout
	if timeout == 0 {
		timeout = forge.DefaultTimeout
	}
	client := &http.Client{Timeout: timeout}
	switch f.Kind {
	case forge.KindGitHub:
		pemKey, err := ReadSecret(f.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		key, err := forge.ParseRSAPrivateKey(pemKey)
		if err != nil {
			return nil, err
		}
		return forge.NewGitHub(forge.GitHubConfig{
			Name: f.Name, URL: f.URL, APIURL: f.APIURL, AppID: f.AppID, PrivateKey: key,
			InstallationID: f.InstallationID, WebhookSecret: hook, HTTPClient: client,
		})
	default:
		tok, err := ReadSecret(f.TokenFile)
		if err != nil {
			return nil, err
		}
		return forge.NewGitLab(forge.GitLabConfig{
			Name: f.Name, URL: f.URL, Token: string(tok), WebhookSecret: hook, HTTPClient: client,
		})
	}
}
