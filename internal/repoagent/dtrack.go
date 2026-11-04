package repoagent

import (
	"context"

	"leblanc.io/lotor/internal/agentclient"
)

// DTSender envoie un SBOM à Dependency-Track (agentclient.DTClient).
type DTSender interface {
	Upload(ctx context.Context, t agentclient.DTTarget, cyclonedx []byte) (agentclient.DTUpload, error)
}

// NewDTSender construit le client de Dependency-Track depuis la configuration ; nil si la
// sortie n'est pas configurée. La clé d'API est un secret (credential:<nom> ou fichier en
// 0600).
func NewDTSender(cfg DTConfig, server ServerConfig, o ServerOptions) (DTSender, error) {
	if !cfg.Enabled() {
		return nil, nil
	}
	key, err := ReadSecret(cfg.APIKeyFile)
	if err != nil {
		return nil, err
	}
	return agentclient.NewDT(agentclient.DTOptions{
		URL: cfg.URL, APIKey: string(key), UserAgent: "lotor-repo-agent/" + o.Version,
		TLS: agentclient.TLSOptions{CAFile: cfg.CAFile}, Proxy: cfg.Proxy, Timeout: server.Timeout,
		Retry: retryOf(server), Logger: o.Logger, Transport: o.Transport,
	})
}

// forwardDT envoie le SBOM du commit de tête d'une référence à Dependency-Track, après
// son envoi au serveur lotor. Un échec est journalisé sans faire échouer l'analyse : le
// SBOM est rangé par lotor, et le prochain commit repartira vers Dependency-Track.
func (a *Agent) forwardDT(ctx context.Context, t tracked, doc []byte) {
	if a.opts.DT == nil {
		return
	}
	target := a.opts.DTConfig.Target(t.project.Name, t.project.Slug, t.ref.Ref.Name)
	up, err := a.opts.DT.Upload(ctx, target, doc)
	if err != nil {
		if ctx.Err() == nil {
			a.log.ErrorContext(ctx, "envoi à Dependency-Track en échec", "project", t.project.Slug, "ref", t.ref.Ref.Name,
				"err", err.Error())
		}
		return
	}
	a.log.InfoContext(ctx, "SBOM envoyé à Dependency-Track", "project", target.ProjectName, "version", target.ProjectVersion,
		"token", up.Token.String())
}
