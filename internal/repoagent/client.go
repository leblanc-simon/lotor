package repoagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/agentclient/gen"
	"leblanc.io/lotor/internal/forge"
)

// apiServer est l'implémentation de Server sur l'API des agents, par le client commun
// d'internal/agentclient : réessais bornés (erreurs réseau, 429, 5xx, Retry-After),
// autorité privée, mTLS facultatif, envoi gzip.
type apiServer struct {
	client *agentclient.Client
}

var _ Server = (*apiServer)(nil)

// ServerOptions complète ServerConfig.
type ServerOptions struct {
	// Version de l'agent, annoncée dans l'en-tête User-Agent.
	Version string
	Logger  *slog.Logger
	// Transport remplace le transport HTTPS (tests contre un serveur HTTP local).
	Transport http.RoundTripper
}

// retryOf est la politique de réessais des appels sortants de l'agent.
func retryOf(cfg ServerConfig) agentclient.Retry {
	return agentclient.Retry{Attempts: cfg.Retries, Base: 2 * time.Second, Max: 5 * time.Minute}
}

// NewServer prépare le client de l'API des agents à partir de la configuration et du
// jeton d'agent. La clé du certificat client est un secret (credential:<nom> ou fichier en
// 0600), vérifié comme les autres.
func NewServer(cfg ServerConfig, token string, o ServerOptions) (Server, error) {
	tlsOpts := agentclient.TLSOptions{CAFile: cfg.CAFile, ClientCertFile: cfg.ClientCertFile}
	if cfg.ClientKeyFile != "" {
		if _, err := ReadSecret(cfg.ClientKeyFile); err != nil {
			return nil, fmt.Errorf("repoagent: clé du certificat client : %w", err)
		}
		path, err := secretPath(cfg.ClientKeyFile)
		if err != nil {
			return nil, err
		}
		tlsOpts.ClientKeyFile = path
	}
	c, err := agentclient.New(agentclient.Options{
		ServerURL: cfg.URL, Token: token, UserAgent: "lotor-repo-agent/" + o.Version, TLS: tlsOpts,
		Proxy: cfg.Proxy, Timeout: cfg.Timeout, Logger: o.Logger, Transport: o.Transport,
		Retry: retryOf(cfg),
	})
	if err != nil {
		return nil, fmt.Errorf("repoagent: client de l'API : %w", err)
	}
	return &apiServer{client: c}, nil
}

// Projects lit toutes les pages des projets confiés et garde les dépôts.
func (s *apiServer) Projects(ctx context.Context) ([]Project, error) {
	projects, err := s.client.Projects(ctx)
	if err != nil {
		return nil, fmt.Errorf("repoagent: projets confiés : %w", err)
	}
	var out []Project
	for _, p := range projects {
		if p.Kind != gen.AgentProjectKindRepo || p.ForgeUrl == nil {
			continue
		}
		proj := Project{ID: p.Id.String(), Slug: p.Slug, Name: p.Name, ForgeURL: *p.ForgeUrl, AIMode: aiModeOf(p.AiMode)}
		for _, r := range p.Refs {
			tr := TrackedRef{ID: r.Id.String(), Ref: forge.Ref{Kind: forge.RefKind(r.Kind), Name: r.Name}}
			if r.LastSnapshot != nil && r.LastSnapshot.Commit != nil {
				tr.LastCommit = strings.ToLower(*r.LastSnapshot.Commit)
			}
			proj.Refs = append(proj.Refs, tr)
		}
		out = append(out, proj)
	}
	return out, nil
}

// aiModeOf lit le réglage d'enrichissement ; une valeur inconnue vaut « désactivé ».
func aiModeOf(m gen.AgentProjectAiMode) AIMode {
	switch AIMode(m) {
	case AILocal, AIExternal:
		return AIMode(m)
	}
	return AIDisabled
}

// AIComponents lit les composants IA de l'instantané courant d'une référence.
func (s *apiServer) AIComponents(ctx context.Context, refID string) ([]PreviousComponent, error) {
	id, err := uuid.Parse(refID)
	if err != nil {
		return nil, fmt.Errorf("repoagent: référence %q : %w", refID, err)
	}
	comps, err := s.client.AIComponents(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("repoagent: composants IA : %w", err)
	}
	out := make([]PreviousComponent, 0, len(comps))
	for _, c := range comps {
		pc := PreviousComponent{PURL: c.Purl, Name: c.Name, Version: c.Version, File: c.File, Line: c.Line, Excerpt: c.Excerpt}
		if c.Confidence != nil {
			pc.Confidence = *c.Confidence
		}
		if c.Model != nil {
			pc.Model = *c.Model
		}
		out = append(out, pc)
	}
	return out, nil
}

// Heartbeat envoie le signal de vie.
func (s *apiServer) Heartbeat(ctx context.Context, version string) error {
	if _, err := s.client.Heartbeat(ctx, gen.HeartbeatRequest{Version: version}); err != nil {
		return fmt.Errorf("repoagent: signal de vie : %w", err)
	}
	return nil
}

// Upload envoie le SBOM (partie context puis sbom en gzip, réessais compris). Un refus du
// serveur autre que 429 ou 5xx (référence inconnue, trop gros, contexte invalide, jeton
// refusé) est définitif : l'erreur enveloppe ErrRejected et porte la clé du problème.
func (s *apiServer) Upload(ctx context.Context, u Upload) (Receipt, error) {
	pid, err := uuid.Parse(u.ProjectID)
	if err != nil {
		return Receipt{}, fmt.Errorf("repoagent: projet %q : %w", u.ProjectID, err)
	}
	ic := gen.IngestionContext{ProjectId: pid, AgentVersion: u.AgentVersion, Commit: &u.Commit, ScannedAt: u.ScannedAt}
	ic.Ref.Kind, ic.Ref.Name = gen.IngestionContextRefKind(u.Ref.Kind), u.Ref.Name
	in, err := s.client.Upload(ctx, ic, u.SBOM)
	if err != nil {
		var e *agentclient.Error
		if errors.As(err, &e) && e.Status >= 400 && e.Status < 500 && e.Status != http.StatusTooManyRequests {
			return Receipt{}, fmt.Errorf("%w : statut %d %s", ErrRejected, e.Status, printable(e.Key))
		}
		return Receipt{}, fmt.Errorf("repoagent: envoi : %w", err)
	}
	return Receipt{IngestionID: in.Id.String()}, nil
}

// PolicyVerdict suit l'ingestion d'un envoi puis lit le verdict de son instantané.
func (s *apiServer) Verdict(ctx context.Context, r Receipt) (PolicyVerdict, error) {
	id, err := uuid.Parse(r.IngestionID)
	if err != nil {
		return PolicyVerdict{}, fmt.Errorf("repoagent: ingestion %q : %w", r.IngestionID, err)
	}
	in, err := s.client.Ingestion(ctx, id)
	if err != nil {
		return PolicyVerdict{}, fmt.Errorf("repoagent: ingestion : %w", err)
	}
	switch {
	case in.Status == gen.Failed:
		v := PolicyVerdict{State: VerdictError}
		if in.Error != nil {
			v.Summary = in.Error.Title
		}
		return v, nil
	case !agentclient.Final(in) || in.SnapshotId == nil:
		return PolicyVerdict{State: VerdictPending}, nil
	}
	got, err := s.client.Verdict(ctx, *in.SnapshotId)
	if err != nil {
		return PolicyVerdict{}, fmt.Errorf("repoagent: verdict : %w", err)
	}
	v := PolicyVerdict{State: got.State, Summary: got.Summary}
	if got.Url != nil {
		v.URL = *got.Url
	}
	return v, nil
}
