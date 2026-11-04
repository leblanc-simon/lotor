package hostagent

import (
	"fmt"
	"log/slog"
	"time"

	"leblanc.io/lotor/internal/agentclient"
)

// NewClient construit le client de l'API depuis la configuration : autorité privée,
// certificat client (clé lue dans le credential systemd « client-key » si aucun fichier
// n'est configuré), mandataire, délais et réessais.
func NewClient(cfg Config, version string, logger *slog.Logger) (*agentclient.Client, error) {
	tlsOpts := agentclient.TLSOptions{CAFile: cfg.Server.CAFile, ClientCertFile: cfg.Server.ClientCertFile}
	if cfg.Server.ClientCertFile != "" {
		tlsOpts.ClientKeyFile = resolveSecret(cfg.Server.ClientKeyFile, CredentialClientKey, "")
		if tlsOpts.ClientKeyFile == "" {
			return nil, fmt.Errorf("hostagent: server.client_key_file absent et aucun credential %q", CredentialClientKey)
		}
		// La clé privée est un secret : mêmes exigences que pour un jeton.
		if _, err := readSecret(tlsOpts.ClientKeyFile); err != nil {
			return nil, err
		}
	}
	return agentclient.New(agentclient.Options{
		ServerURL: cfg.Server.URL,
		UserAgent: "lotor-host-agent/" + version,
		Language:  cfg.Server.Language,
		TLS:       tlsOpts,
		Proxy:     cfg.Server.Proxy,
		Timeout:   cfg.Server.Timeout,
		Retry:     agentclient.Retry{Attempts: cfg.Server.Retries, Base: 2 * time.Second, Max: 5 * time.Minute},
		Logger:    logger,
	})
}

// NewDTClient construit le client de Dependency-Track depuis la configuration ; nil si la
// sortie n'est pas configurée. La clé d'API est lue dans son fichier (0600) ou dans le
// credential systemd « dependency-track-api-key ».
func NewDTClient(cfg Config, version string, logger *slog.Logger) (*agentclient.DTClient, error) {
	d := cfg.DependencyTrack
	if !d.Enabled() {
		return nil, nil
	}
	path := resolveSecret(d.APIKeyFile, CredentialDTAPIKey, "")
	if path == "" {
		return nil, fmt.Errorf("hostagent: dependency_track.api_key_file absent et aucun credential %q", CredentialDTAPIKey)
	}
	key, err := readSecret(path)
	if err != nil {
		return nil, err
	}
	return agentclient.NewDT(agentclient.DTOptions{
		URL: d.URL, APIKey: key, UserAgent: "lotor-host-agent/" + version,
		TLS: agentclient.TLSOptions{CAFile: d.CAFile}, Proxy: d.Proxy, Timeout: cfg.Server.Timeout,
		Retry:  agentclient.Retry{Attempts: cfg.Server.Retries, Base: 2 * time.Second, Max: 5 * time.Minute},
		Logger: logger,
	})
}
