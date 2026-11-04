package hostagent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"time"

	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/agentclient/gen"
)

// Outcome est l'issue d'un cycle.
type Outcome string

// Issues d'un cycle.
const (
	// OutcomeSent : SBOM envoyé et rangé par le serveur.
	OutcomeSent Outcome = "sent"
	// OutcomeConfirmed : inventaire inchangé, confirmé par un signal de vie.
	OutcomeConfirmed Outcome = "confirmed"
	// OutcomeUnchanged : inventaire inchangé depuis le dernier envoi à Dependency-Track
	// (sortie seule vers Dependency-Track).
	OutcomeUnchanged Outcome = "unchanged"
	// OutcomeArchived : inventaire écrit en archive hors ligne (sortie seule hors ligne).
	OutcomeArchived Outcome = "archived"
)

// Options réunit les dépendances d'un agent.
type Options struct {
	Config  Config
	Version string
	// Client parle au serveur lotor (sans jeton : l'agent pose le sien) ; nil seulement
	// avec la sortie seule vers Dependency-Track (dependency_track.only).
	Client *agentclient.Client
	// DT envoie aussi le SBOM à Dependency-Track (nil : sortie désactivée).
	DT      DTSender
	Scanner Scanner
	// Engines sont les moteurs de conteneurs interrogés (Engines(cfg.Containers)) : vide,
	// l'inventaire des conteneurs est désactivé et aucune socket n'est ouverte.
	Engines []ContainerEngine
	// ImageScanner inventorie les images des conteneurs (exigé avec Engines).
	ImageScanner ImageScanner
	Store        *Store
	Logger       *slog.Logger
	// Now remplace l'horloge du système (tests).
	Now func() time.Time
	// IngestionWait borne l'attente du rangement d'un SBOM par le serveur (défaut 15 min).
	IngestionWait time.Duration
	// IngestionPoll est le premier intervalle d'interrogation d'une ingestion (défaut 2 s).
	IngestionPoll time.Duration
	// Sleep remplace l'attente du démon (tests) ; elle rend la main plus tôt si ctx se
	// termine.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Agent est l'agent serveur : inscription, scan, envoi conditionnel et signaux de vie.
type Agent struct {
	o      Options
	client *agentclient.Client
}

// New construit un agent.
func New(o Options) (*Agent, error) {
	only := o.Config.DependencyTrack.Only
	noServer := only || o.Config.Offline.Only
	if (o.Client == nil && !noServer) || (only && o.DT == nil) || o.Scanner == nil || o.Store == nil || o.Logger == nil ||
		(len(o.Engines) > 0 && (o.ImageScanner == nil || noServer)) {
		return nil, errors.New("hostagent: dépendances incomplètes")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.IngestionWait <= 0 {
		o.IngestionWait = 15 * time.Minute
	}
	if o.IngestionPoll <= 0 {
		o.IngestionPoll = 2 * time.Second
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	if o.Config.Hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("hostagent: nom d'hôte : %w", err)
		}
		o.Config.Hostname = h
	}
	return &Agent{o: o}, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ErrNotEnrolled : ni jeton d'agent, ni jeton d'inscription.
var ErrNotEnrolled = errors.New("hostagent: agent non inscrit et aucun jeton d'inscription")

// ErrNoHostProject : le serveur ne confie aucun projet d'hôte à l'agent (désactivé, ou
// projet archivé).
var ErrNoHostProject = errors.New("hostagent: aucun projet d'hôte confié à l'agent")

// Result décrit un cycle.
type Result struct {
	Outcome    Outcome
	Components int
	Duration   time.Duration
	// ScanRequested : une demande de scan est arrivée pendant le cycle.
	ScanRequested bool
	// Containers résume l'inventaire des conteneurs (nil s'il est désactivé).
	Containers *ContainersResult
	// DTSent : le SBOM est aussi parti vers Dependency-Track pendant ce cycle.
	DTSent bool
	// Archive : chemin de l'archive hors ligne écrite pendant ce cycle.
	Archive string
}

// hostname renvoie le nom annoncé, tel que le serveur le range (minuscules).
func (a *Agent) hostname() string { return strings.ToLower(a.o.Config.Hostname) }

// authenticated renvoie un client muni du jeton d'agent, en inscrivant l'agent au besoin.
func (a *Agent) authenticated(ctx context.Context) (*agentclient.Client, error) {
	if a.client != nil {
		return a.client, nil
	}
	tok, err := a.o.Store.Token()
	if err != nil {
		return nil, err
	}
	if tok == "" {
		if tok, err = a.enroll(ctx); err != nil {
			return nil, err
		}
	}
	a.client = a.o.Client.WithToken(tok)
	return a.client, nil
}

// enroll échange le jeton d'inscription contre le jeton d'agent, enregistré aussitôt.
func (a *Agent) enroll(ctx context.Context) (string, error) {
	path := resolveSecret(a.o.Config.EnrollmentTokenFile, CredentialEnrollmentToken, DefaultEnrollmentTokenFile)
	enr, err := readSecret(path)
	if err != nil {
		return "", fmt.Errorf("%w (%v)", ErrNotEnrolled, err)
	}
	req := gen.EnrollRequest{Hostname: a.o.Config.Hostname, Version: a.o.Version}
	if len(a.o.Config.Labels) > 0 {
		labels := a.o.Config.Labels
		req.Labels = &labels
	}
	res, err := a.o.Client.Enroll(ctx, enr, req)
	if err != nil {
		return "", fmt.Errorf("hostagent: inscription : %w", err)
	}
	if err := a.o.Store.SaveToken(res.Token); err != nil {
		return "", err
	}
	st := a.o.Store.Load()
	st.AgentID, st.ProjectID = res.AgentId, res.Project.Id
	if err := a.o.Store.Save(st); err != nil {
		return "", err
	}
	a.o.Logger.InfoContext(ctx, "agent inscrit", "agent", res.AgentId.String(), "project", res.Project.Slug)
	return res.Token, nil
}

// hostRef renvoie le projet d'hôte confié à l'agent et sa référence d'hôte.
func hostRef(projects []gen.AgentProject) (gen.AgentProject, gen.TrackedRef, bool) {
	for _, p := range projects {
		if p.Kind != gen.AgentProjectKindHost {
			continue
		}
		for _, r := range p.Refs {
			if r.Kind == gen.TrackedRefKindHost {
				return p, r, true
			}
		}
	}
	return gen.AgentProject{}, gen.TrackedRef{}, false
}

// Cycle inscrit l'agent au besoin, inventorie l'hôte, puis envoie le SBOM si son
// empreinte a changé depuis le dernier envoi rangé, ou confirme l'inventaire par un
// signal de vie sinon (le serveur peut alors réclamer le SBOM).
func (a *Agent) Cycle(ctx context.Context) (Result, error) {
	if a.o.Config.DependencyTrack.Only {
		return a.dtOnlyCycle(ctx)
	}
	if a.o.Config.Offline.Only {
		return a.offlineCycle(ctx)
	}
	c, err := a.authenticated(ctx)
	if err != nil {
		return Result{}, err
	}
	projects, err := c.Projects(ctx)
	if err != nil {
		return Result{}, err
	}
	proj, ref, ok := hostRef(projects)
	if !ok {
		return Result{}, ErrNoHostProject
	}
	scanCtx, cancel := context.WithTimeout(ctx, a.o.Config.Scan.MaxDuration)
	inv, err := a.o.Scanner.Scan(scanCtx)
	cancel()
	if err != nil {
		return Result{}, err
	}
	res := Result{Components: inv.Components, Duration: inv.Duration}
	host := a.hostContext(inv)
	st := a.o.Store.Load()
	fp := hex.EncodeToString(inv.Fingerprint[:])
	if prev, ok := st.fingerprint(); ok && prev == inv.Fingerprint && st.RefName == ref.Name && st.ProjectID == proj.Id {
		hb, err := c.Heartbeat(ctx, gen.HeartbeatRequest{Version: a.o.Version, Host: host, Inventory: &gen.InventoryReport{
			ProjectId: proj.Id, Fingerprint: fp, ScannedAt: inv.Started,
			Ref: struct {
				Kind gen.InventoryReportRefKind `json:"kind"`
				Name string                     `json:"name"`
			}{Kind: gen.InventoryReportRefKindHost, Name: ref.Name}}})
		if err != nil {
			return Result{}, err
		}
		res.ScanRequested = hb.ScanRequested
		if hb.Inventory != nil && *hb.Inventory == gen.HeartbeatStatusInventoryCurrent {
			st.LastScan = inv.Started
			res.Outcome = OutcomeConfirmed
			a.o.Logger.InfoContext(ctx, "inventaire inchangé, confirmé", "components", inv.Components, "duration", inv.Duration.String())
			if err := a.o.Store.Save(st); err != nil {
				return res, err
			}
			a.alsoDT(ctx, inv, &res)
			a.alsoArchive(ctx, inv, &res)
			return a.withContainers(ctx, c, res), nil
		}
		a.o.Logger.InfoContext(ctx, "inventaire inchangé mais inconnu du serveur : envoi du SBOM")
	}
	if err := a.send(ctx, c, proj, ref, inv, host); err != nil {
		return res, err
	}
	st.ProjectID, st.RefName, st.Fingerprint = proj.Id, ref.Name, fp
	st.LastScan, st.LastSent = inv.Started, a.o.Now().UTC()
	res.Outcome = OutcomeSent
	if err := a.o.Store.Save(st); err != nil {
		return res, err
	}
	a.alsoDT(ctx, inv, &res)
	a.alsoArchive(ctx, inv, &res)
	return a.withContainers(ctx, c, res), nil
}

// withContainers complète un cycle réussi sur l'hôte par l'inventaire des conteneurs,
// s'il est activé. Ses échecs sont journalisés et comptés, sans faire échouer le cycle :
// l'inventaire de l'hôte est rangé, et le cycle suivant reprendra les conteneurs.
func (a *Agent) withContainers(ctx context.Context, c *agentclient.Client, res Result) Result {
	if len(a.o.Engines) == 0 {
		return res
	}
	cr, err := a.containers(ctx, c)
	if err != nil && ctx.Err() == nil {
		cr.Failed++
		a.o.Logger.ErrorContext(ctx, "inventaire des conteneurs en échec", "err", err.Error())
	}
	res.Containers = &cr
	a.o.Logger.InfoContext(ctx, "conteneurs inventoriés", "workloads", cr.Workloads, "images", cr.Images, "sent", cr.Sent,
		"confirmed", cr.Confirmed, "ignored", cr.Ignored, "failed", cr.Failed, "skipped", cr.Skipped)
	return res
}

// send envoie le SBOM et attend que le serveur l'ait rangé ; l'empreinte n'est retenue
// qu'ensuite, si bien qu'un envoi refusé ou perdu est refait au cycle suivant.
func (a *Agent) send(ctx context.Context, c *agentclient.Client, proj gen.AgentProject, ref gen.TrackedRef, inv Inventory, host *gen.HostContext) error {
	ic := gen.IngestionContext{ProjectId: proj.Id, AgentVersion: a.o.Version, ScannedAt: inv.Started, Host: host}
	ic.Ref.Kind, ic.Ref.Name = gen.IngestionContextRefKindHost, ref.Name
	return a.upload(ctx, c, ic, inv)
}

// upload envoie un SBOM et attend son rangement par le serveur.
func (a *Agent) upload(ctx context.Context, c *agentclient.Client, ic gen.IngestionContext, inv Inventory) error {
	in, err := c.Upload(ctx, ic, inv.SBOM)
	if err != nil {
		if agentclient.IsKey(err, agentclient.KeyTooLarge) {
			return fmt.Errorf("hostagent: SBOM de %d octets refusé, trop gros pour le serveur (ingest.max_upload_mib) : %w", len(inv.SBOM), err)
		}
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, a.o.IngestionWait)
	defer cancel()
	if in, err = c.Wait(waitCtx, in, a.o.IngestionPoll); err != nil {
		return err
	}
	if in.Status == gen.Failed {
		key := ""
		if in.Error != nil {
			key = in.Error.Key
		}
		return fmt.Errorf("hostagent: SBOM refusé par le serveur (ingestion %s) : %s", in.Id, key)
	}
	outcome := ""
	if in.Outcome != nil {
		outcome = string(*in.Outcome)
	}
	a.o.Logger.InfoContext(ctx, "SBOM envoyé et rangé", "ref", ic.Ref.Name, "ingestion", in.Id.String(), "outcome", outcome,
		"components", inv.Components, "bytes", len(inv.SBOM), "duration", inv.Duration.String())
	return nil
}

// hostContext construit le contexte de l'hôte, borné comme le serveur l'exige.
func (a *Agent) hostContext(inv Inventory) *gen.HostContext {
	h := hostInfo(a.o.Config.Scan.Root, a.hostname())
	str := func(s string, n int) *string {
		s = clip(s, n)
		if s == "" {
			return nil
		}
		return &s
	}
	ms := int(min(inv.Duration, 24*time.Hour).Milliseconds())
	return &gen.HostContext{Hostname: str(h.Hostname, 255), OsId: str(h.OSID, 64), OsVersion: str(h.OSVersion, 64),
		OsName: str(h.OSName, 128), Kernel: str(h.Kernel, 128), Arch: str(h.Arch, 32), ScanDurationMs: &ms}
}

// Heartbeat envoie un signal de vie seul et dit si un scan est demandé.
func (a *Agent) Heartbeat(ctx context.Context) (bool, error) {
	c, err := a.authenticated(ctx)
	if err != nil {
		return false, err
	}
	st, err := c.Heartbeat(ctx, gen.HeartbeatRequest{Version: a.o.Version})
	if err != nil {
		return false, err
	}
	if skew := a.o.Now().Sub(st.ServerTime); skew > 30*time.Minute || skew < -30*time.Minute {
		a.o.Logger.WarnContext(ctx, "horloge de l'hôte décalée par rapport au serveur", "skew", skew.Round(time.Second).String())
	}
	return st.ScanRequested, nil
}

// fatal dit si une erreur ne se corrigera pas d'elle-même : jeton refusé, agent
// désactivé. Le démon continue d'essayer, à son rythme de signaux de vie, pour reprendre
// dès qu'un administrateur a corrigé la situation (nouvelle inscription, par exemple).
func fatal(err error) bool {
	return errors.Is(err, ErrNotEnrolled) || agentclient.HasStatus(err, http.StatusUnauthorized)
}

// RunOnce exécute un cycle (mode oneshot).
func (a *Agent) RunOnce(ctx context.Context) error {
	res, err := a.Cycle(ctx)
	if err != nil {
		return err
	}
	a.o.Logger.InfoContext(ctx, "cycle terminé", "outcome", string(res.Outcome))
	return nil
}

// retryAfterFailure espace les cycles après un échec : bien moins qu'un intervalle, sans
// marteler le serveur.
const retryAfterFailure = 15 * time.Minute

// Run fait tourner le démon jusqu'à l'annulation de ctx : un cycle à l'échéance (au
// démarrage si le dernier scan est trop ancien), un signal de vie toutes les
// PollInterval, et un cycle aussitôt qu'un scan est demandé depuis l'interface.
func (a *Agent) Run(ctx context.Context) error {
	cfg := a.o.Config.Scan
	next := a.o.Store.Load().LastScan.Add(cfg.Interval)
	requested := false
	for {
		now := a.o.Now()
		if requested || !now.Before(next) {
			res, err := a.Cycle(ctx)
			switch {
			case ctx.Err() != nil:
				return nil
			case err != nil:
				a.o.Logger.ErrorContext(ctx, "cycle en échec", "err", err.Error(), "fatal", fatal(err))
				next = now.Add(min(retryAfterFailure, cfg.Interval))
			default:
				a.o.Logger.InfoContext(ctx, "cycle terminé", "outcome", string(res.Outcome))
				next = a.o.Now().Add(cfg.Interval)
			}
			requested = res.ScanRequested
			if requested {
				continue
			}
		}
		// Gigue de ±10 % : des agents démarrés ensemble ne se synchronisent pas.
		wait := min(jitter(cfg.PollInterval), max(next.Sub(a.o.Now()), 0))
		if err := a.o.Sleep(ctx, wait); err != nil {
			return nil
		}
		if a.o.Now().Before(next) && !a.o.Config.DependencyTrack.Only && !a.o.Config.Offline.Only {
			var err error
			if requested, err = a.Heartbeat(ctx); err != nil && ctx.Err() == nil {
				a.o.Logger.WarnContext(ctx, "signal de vie en échec", "err", err.Error())
			}
		}
	}
}

func jitter(d time.Duration) time.Duration {
	spread := d / 10
	if spread <= 0 {
		return d
	}
	return d - spread + rand.N(2*spread+1)
}
