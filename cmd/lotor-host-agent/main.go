// Commande lotor-host-agent : agent serveur Linux. Elle charge la configuration, règle
// la sobriété du processus, câble le client de l'API, le scanner et l'état, puis lance le
// démon ou un seul cycle (mode oneshot, pour un timer systemd).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	"leblanc.io/open-go-base/logx"

	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/hostagent"
)

// version est injectée à la construction : -ldflags "-X 'main.version=…'".
var version = "develop"

// defaultConfig est le fichier installé par les paquets.
const defaultConfig = "/etc/lotor-host-agent/config.yaml"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "lotor-host-agent: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := hostagent.Load("lotor-host-agent", version, defaultConfig)
	if err != nil {
		return err
	}
	runtime.GOMAXPROCS(cfg.Resources.MaxProcs)
	if cfg.Resources.MemoryLimitMiB > 0 {
		debug.SetMemoryLimit(int64(cfg.Resources.MemoryLimitMiB) << 20)
	}
	if cfg.Hostname == "" {
		if cfg.Hostname, err = os.Hostname(); err != nil {
			return err
		}
	}
	logger := logx.New(cfg.Logging)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var client *agentclient.Client
	if !cfg.DependencyTrack.Only {
		if client, err = hostagent.NewClient(cfg, version, logger); err != nil {
			return err
		}
	}
	dt, err := hostagent.NewDTClient(cfg, version, logger)
	if err != nil {
		return err
	}
	store, err := hostagent.OpenStore(cfg.StateDir)
	if err != nil {
		return err
	}
	agent, err := hostagent.New(hostagent.Options{
		Config: cfg, Version: version, Client: client, DT: hostagent.DTSenderOf(dt), Store: store, Logger: logger,
		Scanner: hostagent.SyftScanner{Root: cfg.Scan.Root, Hostname: cfg.Hostname, Exclude: cfg.Scan.Exclude,
			Parallelism: cfg.Resources.MaxProcs, Version: version},
		// Aucun moteur, donc aucune socket ouverte, sans containers.enabled.
		Engines:      hostagent.Engines(cfg.Containers),
		ImageScanner: hostagent.SyftImageScanner{Parallelism: cfg.Resources.MaxProcs, Version: version},
	})
	if err != nil {
		return err
	}
	logger.Info("agent démarré", "version", version, "mode", cfg.Mode, "server", cfg.Server.URL, "containers", cfg.Containers.Enabled,
		"dependency_track", cfg.DependencyTrack.URL, "dependency_track_only", cfg.DependencyTrack.Only)
	if cfg.Mode == hostagent.ModeOneshot {
		return agent.RunOnce(ctx)
	}
	return agent.Run(ctx)
}
