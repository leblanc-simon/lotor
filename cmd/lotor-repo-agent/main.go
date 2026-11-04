// Commande lotor-repo-agent : agent dépôt, service externe aux CI qui détient seul les
// accès aux forges. Elle câble la configuration, les forges, le client du serveur, le
// pipeline et le récepteur de webhooks ; la logique vit dans internal/repoagent.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"leblanc.io/open-go-base/logx"

	"leblanc.io/lotor/internal/forge"
	"leblanc.io/lotor/internal/repoagent"
)

// version est injectée à la construction : -ldflags "-X 'main.version=…'".
var version = "develop"

const (
	name        = "lotor-repo-agent"
	defaultPath = "/etc/lotor-repo-agent/config.yaml"
	// shutdownTimeout laisse aux webhooks en cours le temps de recevoir leur réponse.
	shutdownTimeout = 10 * time.Second
)

func main() {
	cfg, err := repoagent.Load(name, version, defaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: configuration : %v\n", name, err)
		os.Exit(2)
	}
	log := logx.New(cfg.Logging)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log); err != nil {
		log.Error("arrêt sur erreur", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg repoagent.Config, log *slog.Logger) error {
	token, err := repoagent.ReadSecret(cfg.Server.TokenFile)
	if err != nil {
		return err
	}
	forges, err := cfg.Providers()
	if err != nil {
		return err
	}
	server, err := repoagent.NewServer(cfg.Server, string(token), repoagent.ServerOptions{Version: version, Logger: log})
	if err != nil {
		return err
	}
	dt, err := repoagent.NewDTSender(cfg.DependencyTrack, cfg.Server, repoagent.ServerOptions{Version: version, Logger: log})
	if err != nil {
		return err
	}
	local, external, err := cfg.AI.Models()
	if err != nil {
		return err
	}
	agent, err := repoagent.New(repoagent.Options{
		Server: server, Forges: forges, Logger: log, Version: version, Work: cfg.Work, Catchup: cfg.Catchup, Status: cfg.Status,
		AI: cfg.AI, LocalModel: local, ExternalModel: external, DT: dt, DTConfig: cfg.DependencyTrack,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hookErr := make(chan error, 1)
	var hooks *http.Server
	if cfg.Webhook.Listen != "" {
		if hooks, err = webhookServer(cfg.Webhook, forges, agent, log); err != nil {
			return err
		}
		go func() {
			log.Info("récepteur de webhooks à l'écoute", "addr", cfg.Webhook.Listen)
			var err error
			if hooks.TLSConfig != nil {
				err = hooks.ListenAndServeTLS("", "")
			} else {
				err = hooks.ListenAndServe()
			}
			if !errors.Is(err, http.ErrServerClosed) {
				hookErr <- fmt.Errorf("récepteur de webhooks : %w", err)
			}
		}()
	}
	agentErr := make(chan error, 1)
	go func() { agentErr <- agent.Run(ctx) }()
	log.Info("agent dépôt démarré", "version", version, "forges", len(forges),
		"ai_local", local != nil, "ai_external", external != nil, "dependency_track", cfg.DependencyTrack.URL)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-hookErr:
	case runErr = <-agentErr:
		agentErr <- nil
	}
	if hooks != nil {
		sctx, scancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer scancel()
		_ = hooks.Shutdown(sctx)
	}
	// L'agent tue ses clonages et supprime ses répertoires d'analyse avant de rendre la main.
	cancel()
	if err := <-agentErr; runErr == nil {
		runErr = err
	}
	log.Info("agent dépôt arrêté")
	return runErr
}

func webhookServer(cfg repoagent.WebhookConfig, forges []forge.Provider, agent *repoagent.Agent, log *slog.Logger) (*http.Server, error) {
	rc, err := repoagent.NewReceiver(forges, agent.OnPush, int64(cfg.MaxBodyKiB)<<10, cfg.RateLimit, cfg.TrustedProxies, log)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           rc.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	if cfg.TLSCertFile != "" {
		certPEM, err := os.ReadFile(cfg.TLSCertFile)
		if err != nil {
			return nil, fmt.Errorf("certificat du récepteur : %w", err)
		}
		keyPEM, err := repoagent.ReadSecret(cfg.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("certificat du récepteur : %w", err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	return srv, nil
}
