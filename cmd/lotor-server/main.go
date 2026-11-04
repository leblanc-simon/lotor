// Commande lotor-server : interface web, API REST, workers et planificateur de la file de
// traitements. main ne fait que charger la configuration, construire les dépendances,
// lancer les serveurs et attendre le signal d'arrêt.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"leblanc.io/open-go-base/logx"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/api"
	"leblanc.io/lotor/internal/config"
	"leblanc.io/lotor/internal/dashboard"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/delivery"
	"leblanc.io/lotor/internal/download"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/license"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/mailer"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/policy"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	"leblanc.io/lotor/internal/search"
	"leblanc.io/lotor/internal/secret"
	"leblanc.io/lotor/internal/signup"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/version/grypeversion"
	"leblanc.io/lotor/internal/vuln"
	"leblanc.io/lotor/internal/vuln/grype"
	"leblanc.io/lotor/internal/web"
	"leblanc.io/lotor/internal/web/middleware"
	"leblanc.io/lotor/locales"
	webfs "leblanc.io/lotor/web"
)

const name = "lotor-server"

// version est injectée à la construction : -ldflags "-X 'main.version=…'".
var version = "develop"

func main() {
	// --help et --version terminent ici, en code 0.
	cfg, err := config.Load(name, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s : configuration invalide :\n%v\n", name, err)
		os.Exit(2)
	}
	logger := logx.New(cfg.Logging)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("arrêt sur erreur", "err", err)
		os.Exit(1)
	}
	logger.Info("arrêt terminé")
}

func run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	logger.Info("démarrage", "version", version)

	catalog, err := locale.New(locales.FS, ".", cfg.I18n.DefaultLanguage)
	if err != nil {
		return fmt.Errorf("i18n.default_language (LOTOR_I18N_DEFAULT_LANGUAGE) : %w", err)
	}

	pool, err := db.Start(ctx, db.StartOptions{
		DSN: cfg.Database.DSN,
		Pool: db.PoolConfig{
			MaxOpenConns:    cfg.Database.MaxOpenConns,
			MaxIdleConns:    cfg.Database.MaxIdleConns,
			ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
			ApplicationName: name,
		},
		StartupTimeout:    cfg.Database.StartupTimeout,
		MigrationDSN:      cfg.Migration.DSN,
		MigrationMaxConns: cfg.Migration.MaxConns,
		LockTimeout:       cfg.Migration.LockTimeout,
		Logger:            logger,
	})
	if err != nil {
		return fmt.Errorf("base de données : %w", err)
	}
	defer pool.Close()

	box, err := secret.Parse(cfg.Secrets.Keys, cfg.Secrets.ActiveKey)
	if err != nil {
		return fmt.Errorf("secrets.keys : %w", err)
	}
	if cfg.Auth.CookieSecure != "on" {
		logger.Warn("auth.cookie_secure n'est pas « on » : cookies sans préfixe __Host-, et sans Secure hors HTTPS détecté ; réservé au développement",
			"cookie_secure", cfg.Auth.CookieSecure)
	}
	accounts := account.NewService(pool, cfg.Auth.BcryptCost)
	orgs := org.NewService(pool)
	b := cfg.Bootstrap
	if err := accounts.Startup(ctx, account.StartupOptions{
		AdminEmail: b.AdminEmail, AdminPassword: b.AdminPassword, RescueEmail: b.RescueEmail, RescueTicket: b.RescueTicket,
		RescuePassword: b.RescuePassword,
	}, pool, box, logger); err != nil {
		return err
	}

	templates, err := webfs.Templates()
	if err != nil {
		return err
	}
	static, err := webfs.Static()
	if err != nil {
		return err
	}
	assets, err := render.NewAssets(static)
	if err != nil {
		return err
	}
	renderer, err := render.New(render.Options{Templates: templates, Assets: assets, Catalog: catalog, Version: version, Logger: logger})
	if err != nil {
		return err
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewDBStatsCollector(pool.DB(), "app"),
	)
	agents := agent.NewService(pool, agent.WithMaxContainersPerHost(cfg.Containers.MaxPerHost))
	dash := dashboard.NewService(pool)
	validator, err := schema.New()
	if err != nil {
		return err
	}
	ingester, err := ingest.NewService(ingest.Options{
		Pool: pool, Validator: validator, Logger: logger,
		Limits: ingest.Limits{
			MaxUpload:       config.MiB(cfg.Ingest.MaxUploadMiB),
			MaxPerRefPerDay: cfg.Ingest.MaxPerRefPerDay,
			MaxOrgStorage:   config.MiB(cfg.Ingest.MaxOrgStorageMiB),
			SBOM: sbom.Limits{
				MaxBytes: config.MiB(cfg.Ingest.MaxDecompressedMiB), MaxDepth: cfg.Ingest.MaxDepth,
				MaxComponents: cfg.Ingest.MaxComponents,
			},
		},
	})
	if err != nil {
		return err
	}
	searcher := search.NewService(pool, grypeversion.New())
	inv := inventory.NewService(pool)
	projects := project.NewService(pool)
	findings := finding.NewService(pool)
	history, err := inventory.NewHistory(inventory.HistoryOptions{Pool: pool, Comparer: grypeversion.New(), Logger: logger,
		Retention: inventory.RetentionPolicy{Enabled: cfg.Retention.Enabled, Days: cfg.Retention.Days, Count: cfg.Retention.Count,
			Monthly: cfg.Retention.Monthly, ContainerPurgeAfter: cfg.Containers.PurgeAfter}})
	if err != nil {
		return err
	}
	triager := triage.NewService(triage.Options{Pool: pool, Comparer: grypeversion.New(), Logger: logger,
		OnChange: policy.OnTriageChange})
	compiler, err := policy.NewCompiler()
	if err != nil {
		return err
	}
	policies := policy.NewService(policy.Options{Pool: pool, Compiler: compiler, PublicURL: cfg.Web.PublicURL, Logger: logger})
	// Licences (T20) : liste SPDX du schéma CycloneDX embarqué ; un changement de constat
	// réévalue les règles de politique du projet.
	licenses, err := license.NewService(license.Options{Pool: pool, Known: license.KnownFrom(validator.CycloneDXLicenseIDs("1.6")),
		OnChange: policy.OnLicenseChange})
	if err != nil {
		return err
	}
	sender := delivery.New(delivery.Options{Timeout: cfg.Notify.Timeout, AllowPrivate: cfg.Notify.AllowPrivateNetworks,
		UserAgent: name + "/" + version, SMTP: delivery.SMTPConfig{Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, TLS: cfg.SMTP.TLS,
			Username: cfg.SMTP.Username, Password: cfg.SMTP.Password, From: cfg.SMTP.From, HELO: cfg.SMTP.HELO}})
	notifier := notify.NewService(notify.Options{Pool: pool, Secrets: box, Sender: sender, Loader: policies, Catalog: catalog,
		PublicURL: cfg.Web.PublicURL, DigestHour: cfg.Notify.DigestHour, Logger: logger})
	if n, err := notifier.RotateSecrets(ctx); err != nil {
		return err
	} else if n > 0 {
		logger.Info("secrets des canaux rechiffrés avec la clé active", "count", n)
	}
	mail, signups, err := newSignup(cfg, pool, accounts, box, sender, catalog)
	if err != nil {
		return err
	}
	exports := search.NewExportLimiter(cfg.UserAPI.MaxExports, cfg.UserAPI.ExportTimeout)
	reencodes := search.NewExportLimiter(cfg.Ingest.MaxReencodes, cfg.UserAPI.ExportTimeout)
	vulndbScreen := web.VulnDBOptions{MaxAge: cfg.VulnDB.MaxAge, Offline: cfg.VulnDB.Offline, ListingURL: cfg.VulnDB.ListingURL,
		SyncInterval: cfg.VulnDB.SyncInterval, MaxArchive: config.MiB(cfg.VulnDB.MaxArchiveMiB),
		UploadTimeout: cfg.VulnDB.DownloadTimeout}
	router, err := web.NewRouter(web.RouterOptions{
		Logger:         logger,
		Catalog:        catalog,
		Renderer:       renderer,
		Assets:         assets,
		Metrics:        middleware.NewHTTPMetrics(registry),
		RateLimit:      cfg.Web.RateLimit,
		TrustedProxies: cfg.Web.TrustedProxies,
		CORS:           cfg.CORS,
		CSRFSecure:     cfg.Auth.CookieSecure,
		Identity: &web.IdentityOptions{
			Pool:                  pool,
			Accounts:              accounts,
			Orgs:                  orgs,
			Projects:              projects,
			Agents:                agents,
			Inventory:             inv,
			History:               history,
			Ingest:                ingester,
			Findings:              findings,
			Triage:                triager,
			Search:                searcher,
			Exports:               exports,
			Reencodes:             reencodes,
			Dashboard:             dash,
			Policies:              policies,
			Licenses:              licenses,
			Notify:                notifier,
			Signup:                signups,
			Mailer:                mail,
			PublicURL:             cfg.Web.PublicURL,
			VulnDB:                vulndbScreen,
			Secrets:               box,
			Auth:                  cfg.Auth,
			MFA:                   cfg.MFA,
			LoginRateLimit:        cfg.Login.RateLimit,
			SessionMaxAge:         cfg.Login.SessionMaxAge,
			ForbidExternalAI:      cfg.AI.ForbidExternal,
			ContainerArchiveAfter: cfg.Containers.ArchiveAfter,
		},
		AgentAPI: &api.AgentOptions{
			Agents:           agents,
			Ingest:           ingester,
			Verdicts:         policies,
			RateLimit:        cfg.AgentAPI.RateLimit,
			FailureRateLimit: cfg.AgentAPI.FailureRateLimit,
			// La validation de la configuration garantit le TLS natif avec client_ca_file.
			RequireClientCert: cfg.TLS.ClientCAFile != "",
			ForbidExternalAI:  cfg.AI.ForbidExternal,
		},
		UserAPI: &api.UserOptions{
			Pool:             pool,
			Accounts:         accounts,
			Orgs:             orgs,
			Search:           searcher,
			Exports:          exports,
			Projects:         projects,
			Inventory:        inv,
			History:          history,
			Findings:         findings,
			Triage:           triager,
			Agents:           agents,
			Ingest:           ingester,
			Version:          version,
			RateLimit:        cfg.UserAPI.RateLimit,
			FailureRateLimit: cfg.UserAPI.FailureRateLimit,
		},
	})
	if err != nil {
		return err
	}
	checks := []web.Check{
		{Name: "database", Run: pool.Ping},
		{Name: "schema", Run: func(ctx context.Context) error { return db.VerifySchema(ctx, pool.DB(), nil) }},
	}
	// Seule une instance worker a besoin d'une base de vulnérabilités chargée : une
	// instance purement web reste disponible (import sur un site isolé).
	var vulndb *vuln.Manager
	if cfg.Workers.Enabled {
		vulndb = vuln.NewManager(vuln.ManagerOptions{Pool: pool, Engine: grype.NewEngine(), Dir: cfg.VulnDB.Dir,
			SyncInterval: cfg.VulnDB.SyncInterval, Logger: logger})
		checks = append(checks, web.Check{Name: "vulndb", Run: vulndb.Ready})
	}
	if err := vuln.RegisterMetrics(registry, pool, vulndb, cfg.VulnDB.MaxAge, logger); err != nil {
		return err
	}
	readiness := web.NewReadiness(checks...)

	opts := web.ServerOptions{
		PublicAddr:     net.JoinHostPort(cfg.Web.Host, strconv.Itoa(cfg.Web.Port)),
		ManagementAddr: net.JoinHostPort(cfg.Management.Host, strconv.Itoa(cfg.Management.Port)),
		Public:         router,
		Management:     web.NewManagementHandler(registry, readiness),
		Timeouts: web.Timeouts{
			ReadHeader: cfg.HTTP.ReadHeaderTimeout,
			Read:       cfg.HTTP.ReadTimeout,
			Write:      cfg.HTTP.WriteTimeout,
			Idle:       cfg.HTTP.IdleTimeout,
			Shutdown:   cfg.HTTP.ShutdownTimeout,
		},
		Logger:     logger,
		OnShutdown: readiness.Drain,
	}
	if cfg.TLS.Enabled() {
		if opts.TLS, err = web.TLSConfig(cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.ClientCAFile); err != nil {
			return err
		}
	}
	jobMetrics, err := jobs.NewMetrics(registry, pool, logger)
	if err != nil {
		return err
	}
	services := []func(context.Context) error{web.NewServer(opts).Run}
	if cfg.Workers.Enabled {
		runner := jobs.NewRunner(pool, jobs.RunnerOptions{
			Concurrency:     cfg.Workers.Concurrency,
			PollInterval:    cfg.Workers.PollInterval,
			Lease:           cfg.Workers.Lease,
			Backoff:         jobs.Backoff{Base: cfg.Workers.RetryBase, Max: cfg.Workers.RetryMax, Jitter: jobs.DefaultRetryJitter},
			Retention:       cfg.Workers.Retention,
			ShutdownTimeout: cfg.Workers.ShutdownTimeout,
			Logger:          logger,
			Metrics:         jobMetrics,
		})
		scheduler := jobs.NewScheduler(pool, jobs.SchedulerOptions{
			Interval: cfg.Workers.ScheduleInterval,
			Logger:   logger,
			Metrics:  jobMetrics,
		})
		if err := runner.Register(account.PurgeKind, accounts.PurgeHandler()); err != nil {
			return err
		}
		if err := runner.Register(ingest.DecodeKind, ingester.DecodeHandler(),
			jobs.WithOrgLimit(cfg.Workers.OrgLimit), jobs.WithTimeout(cfg.Ingest.DecodeTimeout)); err != nil {
			return err
		}
		if err := registerAnalysis(cfg, runner, scheduler, pool, vulndb, ingester, triager, licenses, logger); err != nil {
			return err
		}
		if err := scheduler.Register(account.PurgeSchedule()); err != nil {
			return err
		}
		if err := registerDashboard(runner, scheduler, dash); err != nil {
			return err
		}
		if err := registerHistory(runner, scheduler, history); err != nil {
			return err
		}
		if err := registerAlerts(runner, scheduler, policies, notifier); err != nil {
			return err
		}
		if err := registerSignup(runner, scheduler, mail, signups); err != nil {
			return err
		}
		if err := registerContainers(runner, scheduler, project.NewArchiver(pool, cfg.Containers.ArchiveAfter, nil)); err != nil {
			return err
		}
		services = append(services, runner.Run, scheduler.Run, vulndb.Run)
	}
	if dir := cfg.Offline.WatchDir; dir != "" {
		// Répertoire surveillé des archives hors ligne (T23) : l'import ne fait que ranger
		// une ingestion ; son décodage passe par la file, comme un envoi réseau.
		watcher := &ingest.Watcher{Importer: &ingest.Importer{Ingest: ingester, Agents: agents, Logger: logger},
			Dir: dir, Interval: cfg.Offline.WatchInterval}
		services = append(services, watcher.Run)
		logger.Info("répertoire d'archives surveillé", "dir", dir, "interval", cfg.Offline.WatchInterval.String())
	}
	return runAll(ctx, services...)
}

// registerAnalysis enregistre l'analyse de vulnérabilités : analyses des références,
// réanalyse du parc, vérification de la liste de distribution (sauf hors ligne).
func registerAnalysis(cfg config.Config, runner *jobs.Runner, scheduler *jobs.Scheduler, pool *db.Pool, vulndb *vuln.Manager,
	ingester *ingest.Service, triager *triage.Service, licenses *license.Service, logger *slog.Logger) error {
	// Après chaque analyse : licences de la référence (T20), puis règles de politique.
	onAnalyzed := func(ctx context.Context, tx *db.OrgTx, refID, projectID uuid.UUID) error {
		if err := licenses.OnAnalyzed(ctx, tx, refID, projectID); err != nil {
			return err
		}
		return policy.OnAnalyzed(ctx, tx, refID, projectID)
	}
	analyzer := finding.NewAnalyzer(finding.Options{Pool: pool, Engine: vulndb, Blobs: ingester, Triage: triager,
		OnAnalyzed: onAnalyzed, Logger: logger})
	source, err := grype.NewSource(download.New(name+"/"+version, cfg.VulnDB.DownloadTimeout), cfg.VulnDB.ListingURL)
	if err != nil {
		return err
	}
	checker := vuln.NewChecker(vuln.CheckerOptions{Pool: pool, Source: source, Engine: grype.NewEngine(), Dir: cfg.VulnDB.Dir,
		MaxArchive: config.MiB(cfg.VulnDB.MaxArchiveMiB), Logger: logger})
	check := checker.Handler()
	if cfg.VulnDB.Offline {
		// Un job mis en file avant le passage hors ligne se termine sans réseau.
		check = jobs.HandlerFunc(func(context.Context, jobs.Execution) error { return nil })
	}
	for _, r := range []struct {
		kind string
		h    jobs.Handler
		opts []jobs.KindOption
	}{
		{inventory.AnalysisKind, analyzer.Handler(), []jobs.KindOption{jobs.WithOrgLimit(cfg.Workers.OrgLimit),
			jobs.WithTimeout(cfg.VulnDB.AnalysisTimeout)}},
		{vuln.RescanAllKind, analyzer.RescanAllHandler(), nil},
		{finding.RescanOrgKind, analyzer.RescanOrgHandler(), nil},
		// Réévaluation des licences après un changement de politique (T20).
		{license.EvaluateOrgKind, licenses.OrgHandler(), nil},
		// Échéance d'un risque accepté (triage).
		{triage.ExpireKind, triager.ExpireHandler(), nil},
		// Téléchargement, puis installation complète pour valider l'archive.
		{vuln.CheckKind, check, []jobs.KindOption{jobs.WithTimeout(2 * cfg.VulnDB.DownloadTimeout)}},
		// Archive téléversée depuis l'administration : même validation, même en mode hors ligne.
		{vuln.ImportKind, checker.ImportHandler(), []jobs.KindOption{jobs.WithTimeout(2 * cfg.VulnDB.DownloadTimeout)}},
	} {
		if err := runner.Register(r.kind, r.h, r.opts...); err != nil {
			return err
		}
	}
	if cfg.VulnDB.Offline {
		return nil
	}
	return scheduler.Register(vuln.CheckSchedule(cfg.VulnDB.CheckInterval))
}

// registerDashboard enregistre les statistiques quotidiennes du tableau de bord.
func registerDashboard(runner *jobs.Runner, scheduler *jobs.Scheduler, dash *dashboard.Service) error {
	if err := runner.Register(dashboard.StatsAllKind, dash.StatsAllHandler()); err != nil {
		return err
	}
	if err := runner.Register(dashboard.StatsOrgKind, dash.StatsOrgHandler()); err != nil {
		return err
	}
	return scheduler.Register(dashboard.StatsSchedule())
}

// registerHistory enregistre les différences d'instantanés et la rétention (T17).
func registerHistory(runner *jobs.Runner, scheduler *jobs.Scheduler, h *inventory.History) error {
	for _, r := range []struct {
		kind string
		h    jobs.Handler
	}{
		{inventory.DiffKind, h.DiffHandler()},
		{inventory.RetentionAllKind, h.RetentionAllHandler()},
		{inventory.RetentionOrgKind, h.RetentionOrgHandler()},
	} {
		if err := runner.Register(r.kind, r.h); err != nil {
			return err
		}
	}
	return scheduler.Register(inventory.RetentionSchedule())
}

// registerAlerts enregistre l'évaluation des politiques et l'envoi des notifications (T15).
func registerAlerts(runner *jobs.Runner, scheduler *jobs.Scheduler, policies *policy.Service, notifier *notify.Service) error {
	for _, r := range []struct {
		kind string
		h    jobs.Handler
	}{
		{policy.ProjectKind, policies.ProjectHandler()},
		{policy.OrgKind, policies.OrgHandler()},
		{policy.AllKind, policies.AllHandler()},
		{notify.SendKind, notifier.SendHandler()},
		{notify.DigestAllKind, notifier.DigestAllHandler()},
		{notify.DigestOrgKind, notifier.DigestOrgHandler()},
	} {
		if err := runner.Register(r.kind, r.h); err != nil {
			return err
		}
	}
	if err := scheduler.Register(policy.Schedule()); err != nil {
		return err
	}
	return scheduler.Register(notifier.DigestSchedule())
}

// newSignup prépare l'inscription (T28) : le Mailer n'existe que si l'envoi de courriels
// est configuré (SMTP et web.public_url) ; sans lui, codes et liens sont transmis à la main.
func newSignup(cfg config.Config, pool *db.Pool, accounts *account.Service, box *secret.Box, sender mailer.Sender,
	catalog *locale.Catalog) (*mailer.Mailer, *signup.Service, error) {
	var mail *mailer.Mailer
	if cfg.MailConfigured() {
		var err error
		if mail, err = mailer.New(mailer.Options{Sender: sender, Secrets: box, Catalog: catalog, PublicURL: cfg.Web.PublicURL}); err != nil {
			return nil, nil, err
		}
	}
	signups, err := signup.NewService(signup.Options{Pool: pool, Accounts: accounts, Secrets: box,
		Mode: signup.Mode(cfg.Signup.Mode), AllowedDomains: cfg.Signup.AllowedDomains, Mail: mail != nil})
	return mail, signups, err
}

// registerSignup enregistre l'envoi des courriels et la purge des vérifications d'adresse
// expirées (T28). Sans envoi configuré, un courriel resté en file (configuration retirée
// entre-temps) échoue définitivement au lieu d'attendre.
func registerSignup(runner *jobs.Runner, scheduler *jobs.Scheduler, mail *mailer.Mailer, signups *signup.Service) error {
	h := jobs.Handler(jobs.HandlerFunc(func(context.Context, jobs.Execution) error {
		return jobs.Permanent(errors.New("envoi de courriels non configuré (smtp, web.public_url)"))
	}))
	if mail != nil {
		h = mail.Handler()
	}
	if err := runner.Register(mailer.Kind, h); err != nil {
		return err
	}
	if err := runner.Register(signup.PurgeKind, signups.PurgeHandler()); err != nil {
		return err
	}
	return scheduler.Register(signup.PurgeSchedule())
}

// registerContainers enregistre l'archivage des conteneurs absents (T13).
func registerContainers(runner *jobs.Runner, scheduler *jobs.Scheduler, archiver *project.Archiver) error {
	if err := runner.Register(project.ArchiveAllKind, archiver.AllHandler()); err != nil {
		return err
	}
	if err := runner.Register(project.ArchiveOrgKind, archiver.OrgHandler()); err != nil {
		return err
	}
	return scheduler.Register(archiver.Schedule())
}

// runAll lance les services ensemble et attend qu'ils aient tous rendu la main ; le
// premier qui s'arrête, sur erreur ou non, arrête les autres.
func runAll(ctx context.Context, services ...func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(services))
	for _, run := range services {
		go func() {
			errs <- run(ctx)
			cancel()
		}()
	}
	var all []error
	for range services {
		all = append(all, <-errs)
	}
	return errors.Join(all...)
}
