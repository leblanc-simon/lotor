package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
)

// Valeurs par défaut de RunnerOptions.
const (
	DefaultConcurrency         = 4
	DefaultPollInterval        = time.Second
	DefaultLease               = 30 * time.Second
	DefaultRetention           = 7 * 24 * time.Hour
	DefaultMaintenanceInterval = time.Minute
	DefaultShutdownTimeout     = 30 * time.Second
)

// minLease borne le bail : il est renouvelé au tiers de sa durée.
const minLease = 100 * time.Millisecond

// Stop garde pour libérer les baux le quart de son délai, au plus maxStopMargin.
const maxStopMargin = 2 * time.Second

// RunnerOptions paramètre NewRunner ; une valeur zéro prend son défaut.
type RunnerOptions struct {
	// Concurrency est le nombre de workers, donc de jobs simultanés de l'instance.
	Concurrency int
	// PollInterval est l'attente d'un worker qui n'a rien trouvé à faire.
	PollInterval time.Duration
	// Lease est la durée du bail, renouvelé au tiers de sa durée tant que le handler
	// tourne : un worker disparu voit son job repris au plus Lease plus tard.
	Lease time.Duration
	// Backoff calcule le délai des réessais (Base et Max zéro : 10 s et 30 min, gigue
	// 20 %).
	Backoff Backoff
	// Retention est la durée de conservation des jobs terminés (statut done).
	Retention time.Duration
	// MaintenanceInterval espace la purge des jobs terminés et le passage en dead des
	// jobs épuisés dont le bail a expiré.
	MaintenanceInterval time.Duration
	// ShutdownTimeout est le délai donné à Stop par Run.
	ShutdownTimeout time.Duration
	// WorkerID identifie l'instance dans la colonne worker (défaut : hôte et PID).
	WorkerID string
	// Clock et Rand (tirage de la gigue dans [0, 1)) sont remplacés dans les tests.
	Clock   Clock
	Rand    func() float64
	Logger  *slog.Logger
	Metrics *Metrics
}

func (o RunnerOptions) withDefaults() RunnerOptions {
	o.Concurrency = cmp(o.Concurrency, DefaultConcurrency)
	o.PollInterval = cmp(o.PollInterval, DefaultPollInterval)
	o.Lease = cmp(o.Lease, DefaultLease)
	o.Retention = cmp(o.Retention, DefaultRetention)
	o.MaintenanceInterval = cmp(o.MaintenanceInterval, DefaultMaintenanceInterval)
	o.ShutdownTimeout = cmp(o.ShutdownTimeout, DefaultShutdownTimeout)
	if o.Backoff.Base == 0 && o.Backoff.Max == 0 {
		o.Backoff = Backoff{Base: DefaultRetryBase, Max: DefaultRetryMax, Jitter: DefaultRetryJitter}
	}
	if o.WorkerID == "" {
		host, _ := os.Hostname()
		o.WorkerID = host + ":" + strconv.Itoa(os.Getpid())
	}
	if o.Clock == nil {
		o.Clock = SystemClock()
	}
	if o.Rand == nil {
		o.Rand = rand.Float64
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return o
}

func cmp[T int | time.Duration](v, def T) T {
	if v == 0 {
		return def
	}
	return v
}

func (o RunnerOptions) validate() error {
	switch {
	case o.Concurrency < 1:
		return fmt.Errorf("jobs: au moins un worker (reçu %d)", o.Concurrency)
	case o.Lease < minLease:
		return fmt.Errorf("jobs: bail trop court (%s, au moins %s)", o.Lease, minLease)
	case o.PollInterval < 0, o.Retention < 0, o.MaintenanceInterval < 0, o.ShutdownTimeout < 0:
		return errors.New("jobs: durée négative")
	case o.Backoff.Base <= 0 || o.Backoff.Max < o.Backoff.Base:
		return fmt.Errorf("jobs: délais de réessai invalides (base %s, max %s)", o.Backoff.Base, o.Backoff.Max)
	case o.Backoff.Jitter < 0 || o.Backoff.Jitter > 1:
		return fmt.Errorf("jobs: gigue hors de [0, 1] (%v)", o.Backoff.Jitter)
	}
	return nil
}

// KindOption règle un type de job à son enregistrement.
type KindOption func(*kindConfig)

type kindConfig struct {
	handler  Handler
	orgLimit int
	timeout  time.Duration
}

// WithOrgLimit plafonne le nombre de jobs de ce type exécutés en même temps pour une même
// organisation, toutes instances confondues : une organisation ne peut pas affamer les
// autres. Réservé aux types lourds (décodage, analyse).
func WithOrgLimit(n int) KindOption { return func(k *kindConfig) { k.orgLimit = n } }

// WithTimeout borne la durée d'une exécution : au-delà, le contexte du handler est
// annulé et la tentative compte comme un échec.
func WithTimeout(d time.Duration) KindOption { return func(k *kindConfig) { k.timeout = d } }

// Runner exécute les jobs des types enregistrés avec un nombre fixe de workers.
type Runner struct {
	pool  *db.Pool
	o     RunnerOptions
	clock Clock
	log   *slog.Logger

	mu       sync.Mutex
	kinds    map[string]kindConfig
	started  bool
	stopping bool
	// inflight liste les jobs pris et pas encore conclus. Un job interrompu par l'arrêt y
	// reste après la fin de son handler : Stop, qui les relève après avoir annulé les
	// handlers, libère ainsi aussi le bail de ceux qui ont rendu la main avant le relevé.
	inflight map[uuid.UUID]*claimed
	// claiming est tenu en lecture par chaque prise jusqu'à l'inscription du job dans
	// inflight, et en écriture par Stop avant de relever les jobs à libérer : aucun job
	// pris ne lui échappe.
	claiming sync.RWMutex

	// Figés par Start pour la requête de prise.
	kindNames []string
	capKinds  []string
	caps      []int

	stop    chan struct{} // fermé par Stop : plus aucune prise
	wg      sync.WaitGroup
	aborted atomic.Bool // délai de Stop écoulé : les handlers sont annulés

	// afterCancel, nil hors des tests, s'exécute dans Stop entre l'annulation des handlers
	// et le relevé des jobs à libérer : il rend la course déterministe.
	afterCancel func()

	base       context.Context // opérations en base, jusqu'à la fin de Stop
	cancelBase context.CancelFunc
	jobs       context.Context // parent des contextes des handlers
	cancelJobs context.CancelFunc
}

// NewRunner prépare un runner ; les types s'enregistrent avant Start.
func NewRunner(pool *db.Pool, o RunnerOptions) *Runner {
	o = o.withDefaults()
	return &Runner{
		pool: pool, o: o, clock: o.Clock, log: o.Logger,
		kinds: map[string]kindConfig{}, inflight: map[uuid.UUID]*claimed{},
		stop: make(chan struct{}),
	}
}

// Register associe un handler à un type de job.
func (r *Runner) Register(kind string, h Handler, opts ...KindOption) error {
	if err := validKind(kind); err != nil {
		return err
	}
	if h == nil {
		return fmt.Errorf("jobs: handler nil pour %s", kind)
	}
	k := kindConfig{handler: h}
	for _, opt := range opts {
		opt(&k)
	}
	if k.orgLimit < 0 || k.timeout < 0 {
		return fmt.Errorf("jobs: plafond ou délai négatif pour %s", kind)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return fmt.Errorf("jobs: %s enregistré après Start", kind)
	}
	if _, dup := r.kinds[kind]; dup {
		return fmt.Errorf("jobs: %s enregistré deux fois", kind)
	}
	r.kinds[kind] = k
	return nil
}

// Start lance les workers et la maintenance. ctx ne sert qu'à porter des valeurs : son
// annulation n'arrête pas le runner, c'est le rôle de Stop.
func (r *Runner) Start(ctx context.Context) error {
	if err := r.o.validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return errors.New("jobs: runner déjà démarré")
	}
	r.started = true
	for kind, k := range r.kinds {
		r.kindNames = append(r.kindNames, kind)
		if k.orgLimit > 0 {
			r.capKinds = append(r.capKinds, kind)
		}
	}
	slices.Sort(r.kindNames)
	slices.Sort(r.capKinds)
	for _, kind := range r.capKinds {
		r.caps = append(r.caps, r.kinds[kind].orgLimit)
	}
	r.base, r.cancelBase = context.WithCancel(context.WithoutCancel(ctx))
	r.jobs, r.cancelJobs = context.WithCancel(r.base)

	if len(r.kindNames) > 0 {
		for i := range r.o.Concurrency {
			r.wg.Go(func() { r.work(r.o.WorkerID + "/" + strconv.Itoa(i)) })
		}
	}
	r.wg.Go(r.maintain)
	r.log.Info("workers démarrés", "workers", r.o.Concurrency, "kinds", r.kindNames)
	return nil
}

// Run démarre le runner, attend l'annulation de ctx puis s'arrête en au plus
// ShutdownTimeout.
func (r *Runner) Run(ctx context.Context) error {
	if err := r.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.o.ShutdownTimeout)
	defer cancel()
	return r.Stop(sctx)
}

// Stop cesse de prendre du travail et attend les jobs en cours. Si le délai de ctx
// approche, il annule leurs handlers et libère leurs baux (le job revient en attente,
// sans que la tentative compte) : Stop rend la main avant l'échéance de ctx et ne
// laisse aucun bail actif. Un handler qui ignore l'annulation finit en arrière-plan ;
// son résultat est alors ignoré et le job sera rejoué.
func (r *Runner) Stop(ctx context.Context) error {
	r.mu.Lock()
	if !r.started || r.stopping {
		r.mu.Unlock()
		return nil
	}
	r.stopping = true
	close(r.stop)
	r.mu.Unlock()

	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	var expired <-chan time.Time
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		t := time.NewTimer(remaining - min(remaining/4, maxStopMargin))
		defer t.Stop()
		expired = t.C
	}
	select {
	case <-done:
		r.cancelBase()
		r.log.Info("workers arrêtés")
		return nil
	case <-expired:
	case <-ctx.Done():
	}

	r.aborted.Store(true)
	r.cancelJobs()
	if r.afterCancel != nil {
		r.afterCancel()
	}
	// Une prise en cours finit en quelques millisecondes ; si la base ne répond plus,
	// on n'attend pas au-delà du délai.
	for !r.claiming.TryLock() {
		if ctx.Err() != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	r.mu.Lock()
	pending := make([]*claimed, 0, len(r.inflight))
	for _, c := range r.inflight {
		pending = append(pending, c)
	}
	r.mu.Unlock()
	err := r.release(ctx, pending)
	for _, c := range pending {
		r.o.Metrics.observeRun(c.Kind, outcomeReleased)
	}
	r.cancelBase()
	r.log.Warn("arrêt des workers : jobs interrompus et remis en attente", "jobs", len(pending))
	if err != nil {
		return fmt.Errorf("%w (les baux expireront d'eux-mêmes)", err)
	}
	return nil
}

// work est la boucle d'un worker.
func (r *Runner) work(name string) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		c, err := r.take(name)
		if err != nil {
			r.log.Error("prise de job", "err", err)
		}
		if c != nil {
			r.execute(c)
			continue
		}
		timer.Reset(r.o.PollInterval)
		select {
		case <-r.stop:
			return
		case <-timer.C:
		}
	}
}

// take prend un job et l'inscrit parmi les jobs en cours, sauf si l'arrêt a commencé.
func (r *Runner) take(name string) (*claimed, error) {
	if !r.claiming.TryRLock() {
		return nil, nil // Stop relève les jobs à libérer
	}
	defer r.claiming.RUnlock()
	select {
	case <-r.stop:
		return nil, nil
	default:
	}
	c, err := r.claim(r.base, name)
	if c != nil {
		r.mu.Lock()
		r.inflight[c.ID] = c
		r.mu.Unlock()
	}
	return c, err
}

func (r *Runner) execute(c *claimed) {
	k := r.kinds[c.Kind]
	log := r.log.With("job", c.ID, "kind", c.Kind, "attempt", c.Attempt)
	if !c.OrgID.IsZero() {
		log = log.With("org", c.OrgID)
	}
	interrupted := false
	defer func() {
		if interrupted {
			return // Stop libère le bail (voir inflight)
		}
		r.mu.Lock()
		delete(r.inflight, c.ID)
		r.mu.Unlock()
	}()

	ctx, cancel := r.jobContext(k)
	defer cancel()
	var lost atomic.Bool
	renewDone := make(chan struct{})
	go func() {
		defer close(renewDone)
		r.keepLease(ctx, c, func() { lost.Store(true); cancel() }, log)
	}()

	start := time.Now()
	err := call(ctx, k.handler, c.Execution)
	cancel()
	<-renewDone
	r.o.Metrics.observeDuration(c.Kind, time.Since(start))

	if lost.Load() {
		log.Warn("bail perdu : le job a été repris par un autre worker ou libéré")
		r.o.Metrics.observeRun(c.Kind, outcomeLost)
		return
	}
	if r.aborted.Load() && err != nil {
		// Interrompu par l'arrêt : Stop libère le bail.
		interrupted = true
		return
	}
	r.conclude(c, err, log)
}

func (r *Runner) conclude(c *claimed, err error, log *slog.Logger) {
	var (
		ok      bool
		dbErr   error
		outcome string
	)
	switch {
	case err == nil:
		ok, dbErr = r.complete(r.base, c)
		outcome = outcomeDone
	case IsPermanent(err) || c.Attempt >= c.MaxAttempts:
		ok, dbErr = r.bury(r.base, c, err)
		outcome = outcomeDead
	default:
		runAt := r.clock.Now().Add(r.o.Backoff.Delay(c.Attempt, r.o.Rand()))
		ok, dbErr = r.requeue(r.base, c, runAt, err, false)
		outcome = outcomeRetry
		if ok {
			log.Warn("échec du job, nouvel essai programmé", "err", err, "run_at", runAt)
		}
	}
	switch {
	case dbErr != nil:
		// Le bail expirera et le job sera repris.
		log.Error("enregistrement de la fin du job", "err", dbErr, "handler_err", err)
	case !ok:
		log.Warn("bail perdu avant la fin du job : résultat ignoré")
		outcome = outcomeLost
	case outcome == outcomeDead:
		log.Error("job abandonné (dead)", "err", err)
	}
	r.o.Metrics.observeRun(c.Kind, outcome)
}

// keepLease renouvelle le bail au tiers de sa durée jusqu'à la fin de ctx ; onLost est
// appelé si le bail n'est plus à nous.
func (r *Runner) keepLease(ctx context.Context, c *claimed, onLost func(), log *slog.Logger) {
	t := time.NewTicker(r.o.Lease / 3)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ok, err := r.renew(r.base, c)
		if err != nil {
			log.Warn("renouvellement du bail", "err", err)
			continue
		}
		if !ok {
			onLost()
			return
		}
	}
}

func (r *Runner) jobContext(k kindConfig) (context.Context, context.CancelFunc) {
	if k.timeout > 0 {
		return context.WithTimeout(r.jobs, k.timeout)
	}
	return context.WithCancel(r.jobs)
}

// call exécute le handler ; une panique devient une erreur.
func call(ctx context.Context, h Handler, e Execution) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("jobs: panique dans le handler de %s : %v\n%s", e.Kind, v, debug.Stack())
		}
	}()
	return h.Handle(ctx, e)
}

// maintain passe en dead les jobs épuisés au bail expiré et purge les jobs terminés.
func (r *Runner) maintain() {
	t := time.NewTicker(r.o.MaintenanceInterval)
	defer t.Stop()
	for {
		if n, err := r.reapExhausted(r.base); err != nil {
			r.log.Error("maintenance de la file", "err", err)
		} else if n > 0 {
			r.log.Error("jobs abandonnés (dead) : bail expiré pendant la dernière tentative", "jobs", n)
		}
		if n, err := r.purge(r.base); err != nil {
			r.log.Error("purge des jobs terminés", "err", err)
		} else if n > 0 {
			r.log.Info("jobs terminés purgés", "jobs", n)
		}
		select {
		case <-r.stop:
			return
		case <-t.C:
		}
	}
}
