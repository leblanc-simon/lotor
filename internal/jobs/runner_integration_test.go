//go:build integration

package jobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/tenant"
)

// Critère : un job mis en file dans une transaction annulée n'est jamais exécuté.
func TestRolledBackEnqueueNeverRuns(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	ctx := context.Background()
	rollback := errors.New("annulation voulue")
	err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
		if _, err := Enqueue(ctx, tx, Job{Kind: "test.rollback"}); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("err = %v", err)
	}
	var runs atomic.Int32
	startRunner(t, tdb.App, RunnerOptions{}, func(r *Runner) {
		mustRegister(t, r, "test.rollback", func(context.Context, Execution) error { runs.Add(1); return nil })
		mustRegister(t, r, "test.marker", func(context.Context, Execution) error { return nil })
	})
	// Un job témoin, mis en file après, prouve que le runner a eu le temps de travailler.
	marker := enqueue(t, tdb.App, Job{Kind: "test.marker"})
	waitFor(t, 10*time.Second, "job témoin", func() bool { return status(t, tdb.App, marker) == "done" })
	if n := runs.Load(); n != 0 || count(t, tdb.App, "kind = 'test.rollback'") != 0 {
		t.Fatalf("job d'une transaction annulée exécuté %d fois", n)
	}
}

// Critère : avec trois runners concurrents et sans panne, aucun job n'est exécuté deux
// fois et aucun n'est perdu.
func TestThreeRunnersRunEachJobExactlyOnce(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	const total = 1500
	ids := make([]uuid.UUID, total)
	for i := range ids {
		ids[i] = enqueue(t, tdb.App, Job{Kind: "test.once", Priority: i % 3})
	}
	var mu sync.Mutex
	runs := map[uuid.UUID]int{}
	var done atomic.Int32
	h := func(_ context.Context, e Execution) error {
		mu.Lock()
		runs[e.ID]++
		mu.Unlock()
		done.Add(1)
		return nil
	}
	for range 3 {
		startRunner(t, tdb.App, RunnerOptions{Concurrency: 4}, func(r *Runner) { mustRegister(t, r, "test.once", h) })
	}
	waitFor(t, 60*time.Second, "tous les jobs", func() bool { return done.Load() >= total })
	waitFor(t, 10*time.Second, "statuts done", func() bool { return count(t, tdb.App, "status = 'done'") == total })
	mu.Lock()
	defer mu.Unlock()
	for _, id := range ids {
		if runs[id] != 1 {
			t.Errorf("job %s exécuté %d fois", id, runs[id])
		}
	}
	if len(runs) != total {
		t.Errorf("%d jobs exécutés, attendu %d", len(runs), total)
	}
}

const killChildEnv = "LOTOR_JOBS_KILL_CHILD_DSN"

// Critère : un worker tué en plein job voit son job repris après expiration du bail. Le
// worker tourne dans un sous-processus tué par SIGKILL : ni arrêt propre ni libération.
func TestKilledWorkerJobIsTakenOverAfterLease(t *testing.T) {
	if dsn := os.Getenv(killChildEnv); dsn != "" {
		runKillChild(dsn)
		return
	}
	t.Parallel()
	tdb := dbtest.New(t)
	id := enqueue(t, tdb.App, Job{Kind: "test.killed", MaxAttempts: 3})

	cmd := exec.Command(os.Args[0], "-test.run=^TestKilledWorkerJobIsTakenOverAfterLease$")
	cmd.Env = append(os.Environ(), killChildEnv+"="+tdb.AppDSN)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	waitFor(t, 30*time.Second, "prise par le sous-processus", func() bool { return status(t, tdb.App, id) == "running" })
	leaseEnd := readJob(t, tdb.App, id).LockedUntil.Time
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if st := readJob(t, tdb.App, id); st.Status != "running" || st.Attempts != 1 {
		t.Fatalf("après SIGKILL : %+v", st)
	}

	clock := &fakeClock{now: leaseEnd.Add(-time.Second)}
	var runs atomic.Int32
	startRunner(t, tdb.App, RunnerOptions{Clock: clock}, func(r *Runner) {
		mustRegister(t, r, "test.killed", func(context.Context, Execution) error { runs.Add(1); return nil })
	})
	time.Sleep(200 * time.Millisecond)
	if runs.Load() != 0 {
		t.Fatal("job repris avant l'expiration du bail")
	}
	clock.Set(leaseEnd.Add(time.Second))
	waitFor(t, 10*time.Second, "reprise du job", func() bool { return status(t, tdb.App, id) == "done" })
	if st := readJob(t, tdb.App, id); runs.Load() != 1 || st.Attempts != 2 {
		t.Fatalf("reprise : %d exécutions, %+v\nsous-processus :\n%s", runs.Load(), st, out.String())
	}
}

// runKillChild est le sous-processus : un worker qui prend le job et ne le finit jamais.
func runKillChild(dsn string) {
	sqlDB, err := db.Open(dsn, db.PoolConfig{MaxOpenConns: 4})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	r := NewRunner(db.NewPool(sqlDB), RunnerOptions{PollInterval: 10 * time.Millisecond, Lease: 30 * time.Second})
	block := make(chan struct{})
	if err := r.Register("test.killed", HandlerFunc(func(context.Context, Execution) error { <-block; return nil })); err != nil {
		os.Exit(1)
	}
	if err := r.Start(context.Background()); err != nil {
		os.Exit(1)
	}
	// Garde-fou si le parent disparaît sans tuer l'enfant.
	time.Sleep(2 * time.Minute)
	os.Exit(1)
}

// Critère : le calendrier des réessais suit la formule documentée ; un job épuisé passe
// dead avec sa dernière erreur.
func TestRetryScheduleFollowsBackoffThenDead(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	clock := newFakeClock()
	backoff := Backoff{Base: time.Minute, Max: 3 * time.Minute, Jitter: 0.5}
	const u = 0.5
	var attempts atomic.Int32
	startRunner(t, tdb.App, RunnerOptions{Clock: clock, Backoff: backoff, Rand: func() float64 { return u }}, func(r *Runner) {
		mustRegister(t, r, "test.flaky", func(_ context.Context, e Execution) error {
			attempts.Add(1)
			return fmt.Errorf("échec n° %d", e.Attempt)
		})
	})
	id := enqueue(t, tdb.App, Job{Kind: "test.flaky", MaxAttempts: 4})
	// Délais attendus : min(1 min × 2^(n−1), 3 min) × (1 + 0,5 × 0,5).
	want := []time.Duration{75 * time.Second, 150 * time.Second, 225 * time.Second}
	for n, delay := range want {
		attempt := n + 1
		waitFor(t, 10*time.Second, fmt.Sprintf("échec %d", attempt), func() bool {
			r := readJob(t, tdb.App, id)
			return r.Status == "pending" && r.Attempts == attempt
		})
		r := readJob(t, tdb.App, id)
		if got := r.RunAt.Sub(clock.Now()); got != delay {
			t.Fatalf("tentative %d : délai %s, attendu %s", attempt, got, delay)
		}
		if r.LastError.String != fmt.Sprintf("échec n° %d", attempt) {
			t.Fatalf("dernière erreur %q", r.LastError.String)
		}
		clock.Advance(delay - time.Second)
		time.Sleep(50 * time.Millisecond)
		if attempts.Load() != int32(attempt) {
			t.Fatalf("réessai avant l'échéance")
		}
		clock.Advance(time.Second)
	}
	waitFor(t, 10*time.Second, "statut dead", func() bool { return status(t, tdb.App, id) == "dead" })
	r := readJob(t, tdb.App, id)
	if r.Attempts != 4 || r.LastError.String != "échec n° 4" || !r.FinishedAt.Valid || r.LeaseToken.Valid {
		t.Fatalf("job mort : %+v", r)
	}
	time.Sleep(50 * time.Millisecond)
	if attempts.Load() != 4 {
		t.Fatalf("%d tentatives, attendu 4", attempts.Load())
	}
}

// Critère : une mise en file prioritaire sur une clé déjà en attente en basse priorité
// relève la priorité du job existant.
func TestUniqueKeyRaisesPriorityOfPendingJob(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	org := newOrg(t, tdb.App)
	later := time.Now().Add(time.Hour)
	low := enqueue(t, tdb.App, Job{Kind: "test.ref", OrgID: org, UniqueKey: "ref:1", Priority: PriorityLow, RunAt: later})
	other := enqueue(t, tdb.App, Job{Kind: "test.ref", OrgID: org, Priority: PriorityNormal})
	high := enqueue(t, tdb.App, Job{Kind: "test.ref", OrgID: org, UniqueKey: "ref:1", Priority: PriorityHigh})
	if high != low {
		t.Fatalf("second job créé au lieu du relèvement : %s ≠ %s", high, low)
	}
	r := readJob(t, tdb.App, low)
	if r.Priority != PriorityHigh || r.RunAt.After(time.Now()) {
		t.Fatalf("priorité %d, échéance %s : non relevées", r.Priority, r.RunAt)
	}
	// Une mise en file plus basse ne la redescend pas.
	enqueue(t, tdb.App, Job{Kind: "test.ref", OrgID: org, UniqueKey: "ref:1", Priority: PriorityLow, RunAt: later})
	if r := readJob(t, tdb.App, low); r.Priority != PriorityHigh || r.RunAt.After(time.Now()) {
		t.Fatalf("relèvement perdu : %+v", r)
	}
	// La même clé pour un autre type est un autre job.
	if id := enqueue(t, tdb.App, Job{Kind: "test.other", OrgID: org, UniqueKey: "ref:1"}); id == low {
		t.Fatal("clé partagée entre deux types")
	}
	// Jamais de fusion entre organisations.
	err := tdb.App.InTx(context.Background(), func(tx *db.Tx) error {
		_, err := Enqueue(context.Background(), tx, Job{Kind: "test.ref", OrgID: newOrg(t, tdb.App), UniqueKey: "ref:1"})
		return err
	})
	if !errors.Is(err, ErrUniqueKeyConflict) {
		t.Fatalf("err = %v, attendu ErrUniqueKeyConflict", err)
	}

	// Le job relevé passe avant le job normal mis en file avant lui.
	var mu sync.Mutex
	var order []uuid.UUID
	startRunner(t, tdb.App, RunnerOptions{Concurrency: 1}, func(r *Runner) {
		mustRegister(t, r, "test.ref", func(_ context.Context, e Execution) error {
			mu.Lock()
			order = append(order, e.ID)
			mu.Unlock()
			return nil
		})
	})
	waitFor(t, 10*time.Second, "deux jobs", func() bool { mu.Lock(); defer mu.Unlock(); return len(order) == 2 })
	if order[0] != low || order[1] != other {
		t.Fatalf("ordre %v, attendu [%s %s]", order, low, other)
	}
}

// Une mise en file pendant l'exécution d'un job de même clé crée un nouveau job : celui
// en cours a pu lire la donnée avant le changement.
func TestUniqueKeyWhileRunningCreatesNewJob(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	started, release := make(chan uuid.UUID, 2), make(chan struct{})
	startRunner(t, tdb.App, RunnerOptions{Concurrency: 1}, func(r *Runner) {
		mustRegister(t, r, "test.ref", func(_ context.Context, e Execution) error {
			started <- e.ID
			<-release
			if e.Attempt == 1 && e.Priority == PriorityLow {
				return errors.New("échec : remise en attente alors qu'un jumeau attend")
			}
			return nil
		})
	})
	first := enqueue(t, tdb.App, Job{Kind: "test.ref", UniqueKey: "k", Priority: PriorityLow})
	if got := <-started; got != first {
		t.Fatalf("job %s pris, attendu %s", got, first)
	}
	second := enqueue(t, tdb.App, Job{Kind: "test.ref", UniqueKey: "k"})
	if second == first {
		t.Fatal("job en cours réutilisé")
	}
	// Le premier échoue : sa remise en attente heurterait le jumeau, il s'efface.
	release <- struct{}{}
	if got := <-started; got != second {
		t.Fatalf("job %s pris, attendu %s", got, second)
	}
	close(release)
	waitFor(t, 10*time.Second, "jumeau terminé", func() bool { return status(t, tdb.App, second) == "done" })
	if n := count(t, tdb.App, "id = $1", first); n != 0 {
		t.Fatal("le job en échec n'a pas cédé la place à son jumeau")
	}
}

// Critère : une organisation au plafond n'empêche pas les jobs d'une autre de
// s'exécuter, et le plafond tient entre plusieurs runners.
func TestOrgLimitDoesNotStarveOtherOrgs(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	orgA, orgB := newOrg(t, tdb.App), newOrg(t, tdb.App)
	release := make(chan struct{})
	var mu sync.Mutex
	running := map[tenant.OrgID]int{}
	maxRunning := map[tenant.OrgID]int{}
	var bDone atomic.Bool
	h := func(ctx context.Context, e Execution) error {
		mu.Lock()
		running[e.OrgID]++
		maxRunning[e.OrgID] = max(maxRunning[e.OrgID], running[e.OrgID])
		mu.Unlock()
		defer func() { mu.Lock(); running[e.OrgID]--; mu.Unlock() }()
		if e.OrgID == orgB {
			bDone.Store(true)
			return nil
		}
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}
	var aIDs []uuid.UUID
	for range 10 {
		aIDs = append(aIDs, enqueue(t, tdb.App, Job{Kind: "test.heavy", OrgID: orgA, Priority: PriorityHigh}))
	}
	for range 2 {
		startRunner(t, tdb.App, RunnerOptions{Concurrency: 4}, func(r *Runner) {
			mustRegister(t, r, "test.heavy", h, WithOrgLimit(2))
		})
	}
	waitFor(t, 10*time.Second, "A au plafond", func() bool { return count(t, tdb.App, "status = 'running'") == 2 })
	// B, moins prioritaire, passe malgré les huit jobs de A en attente.
	bID := enqueue(t, tdb.App, Job{Kind: "test.heavy", OrgID: orgB, Priority: PriorityLow})
	waitFor(t, 10*time.Second, "job de B", func() bool { return bDone.Load() && status(t, tdb.App, bID) == "done" })
	time.Sleep(100 * time.Millisecond)
	if n := count(t, tdb.App, "status = 'running' AND org_id = $1", orgA); n != 2 {
		t.Fatalf("%d jobs de A en cours, attendu 2 (plafond)", n)
	}
	close(release)
	waitFor(t, 20*time.Second, "jobs de A", func() bool { return count(t, tdb.App, "status = 'done'") == 11 })
	for _, id := range aIDs {
		if s := status(t, tdb.App, id); s != "done" {
			t.Errorf("job %s de A : %s", id, s)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if maxRunning[orgA] != 2 {
		t.Fatalf("A a eu jusqu'à %d jobs simultanés, plafond 2", maxRunning[orgA])
	}
}

// Critère : deux planificateurs actifs, une seule mise en file par échéance.
func TestTwoSchedulersEnqueueOncePerOccurrence(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	ctx := context.Background()
	clock := newFakeClock()
	// Départ juste après un point de la grille horaire.
	sc := Schedule{Name: "test.hourly", Every: time.Hour, Job: Job{Kind: "test.tick", UniqueKey: "-"}}
	clock.Set(sc.lastPoint(clock.Now()).Add(time.Minute))
	var schedulers []*Scheduler
	for range 2 {
		s := NewScheduler(tdb.App, SchedulerOptions{Clock: clock})
		if err := s.Register(sc); err != nil {
			t.Fatal(err)
		}
		if err := s.sync(ctx); err != nil {
			t.Fatal(err)
		}
		schedulers = append(schedulers, s)
	}
	const periods = 5
	var fired atomic.Int32
	for p := range periods {
		// Les deux instances tentent plusieurs fois, en même temps, pendant la période.
		var wg sync.WaitGroup
		for _, s := range schedulers {
			for range 4 {
				wg.Go(func() {
					n, err := s.tick(ctx)
					if err != nil {
						t.Error(err)
					}
					fired.Add(int32(n))
				})
			}
		}
		wg.Wait()
		if got := fired.Load(); got != int32(p+1) {
			t.Fatalf("période %d : %d prises, attendu %d", p, got, p+1)
		}
		if p < periods-1 {
			clock.Advance(time.Hour)
		}
	}
	// Une clé d'unicité fixe dédoublonne les jobs en attente : un seul job, relevé.
	if n := count(t, tdb.App, "kind = 'test.tick'"); n != 1 {
		t.Fatalf("%d jobs test.tick, attendu 1", n)
	}
	var next time.Time
	err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT next_run_at FROM schedules WHERE name = $1`, sc.Name).Scan(&next)
	})
	if err != nil || !next.Equal(sc.nextPoint(clock.Now())) {
		t.Fatalf("prochaine échéance %s, attendu %s (%v)", next, sc.nextPoint(clock.Now()), err)
	}
}

// Critère : Stop rend la main dans le délai imparti et ne laisse aucun bail actif, même
// avec un handler qui ignore l'annulation.
func TestStopReturnsInTimeAndReleasesLeases(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	var started atomic.Int32
	r := NewRunner(tdb.App, fastOptions(RunnerOptions{Concurrency: 3}))
	mustRegister(t, r, "test.stuck", func(context.Context, Execution) error { started.Add(1); <-stuck; return nil })
	mustRegister(t, r, "test.polite", func(ctx context.Context, _ Execution) error {
		started.Add(1)
		<-ctx.Done()
		return ctx.Err()
	})
	mustRegister(t, r, "test.quick", func(context.Context, Execution) error {
		started.Add(1)
		time.Sleep(100 * time.Millisecond)
		return nil
	})
	stuckID := enqueue(t, tdb.App, Job{Kind: "test.stuck"})
	politeID := enqueue(t, tdb.App, Job{Kind: "test.polite"})
	quickID := enqueue(t, tdb.App, Job{Kind: "test.quick"})
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "trois jobs en cours", func() bool { return started.Load() == 3 })

	const grace = 1500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	begin := time.Now()
	if err := r.Stop(ctx); err != nil {
		t.Fatalf("Stop : %v", err)
	}
	if elapsed := time.Since(begin); elapsed > grace {
		t.Fatalf("Stop a rendu la main en %s, délai %s", elapsed, grace)
	}
	if n := count(t, tdb.App, "status = 'running' OR lease_token IS NOT NULL"); n != 0 {
		t.Fatalf("%d baux actifs après Stop", n)
	}
	if s := status(t, tdb.App, quickID); s != "done" {
		t.Errorf("job rapide : %s, attendu done (fini pendant le délai)", s)
	}
	for _, id := range []uuid.UUID{stuckID, politeID} {
		if r := readJob(t, tdb.App, id); r.Status != "pending" || r.Attempts != 0 {
			t.Errorf("job interrompu : %+v, attendu pending sans tentative comptée", r)
		}
	}
	// Plus aucune prise après Stop.
	late := enqueue(t, tdb.App, Job{Kind: "test.quick"})
	time.Sleep(100 * time.Millisecond)
	if s := status(t, tdb.App, late); s != "pending" {
		t.Fatalf("job pris après Stop : %s", s)
	}
}

// Un handler qui rend la main dès son annulation peut finir avant que Stop ne relève les
// jobs à libérer : son bail doit être libéré quand même (course vue en CI, un échec sur
// vingt de TestStopReturnsInTimeAndReleasesLeases). afterCancel attend la fin du job
// interrompu avant le relevé.
func TestStopReleasesLeaseOfJobInterruptedBeforeSnapshot(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	returned := make(chan struct{})
	r := NewRunner(tdb.App, fastOptions(RunnerOptions{Concurrency: 1}))
	mustRegister(t, r, "test.polite", func(ctx context.Context, _ Execution) error {
		defer close(returned)
		<-ctx.Done()
		return ctx.Err()
	})
	r.afterCancel = func() {
		<-returned
		// La sortie d'execute suit de près celle du handler.
		time.Sleep(200 * time.Millisecond)
	}
	id := enqueue(t, tdb.App, Job{Kind: "test.polite"})
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "job en cours", func() bool { return status(t, tdb.App, id) == "running" })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Stop(ctx); err != nil {
		t.Fatalf("Stop : %v", err)
	}
	if n := count(t, tdb.App, "status = 'running' OR lease_token IS NOT NULL"); n != 0 {
		t.Fatalf("%d baux actifs après Stop", n)
	}
	if j := readJob(t, tdb.App, id); j.Status != "pending" || j.Attempts != 0 {
		t.Errorf("job interrompu : %+v, attendu pending sans tentative comptée", j)
	}
}

// Stop sans job en cours rend la main tout de suite ; un second Stop est sans effet.
func TestStopIdle(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	r := startRunner(t, tdb.App, RunnerOptions{}, func(r *Runner) {
		mustRegister(t, r, "test.idle", func(context.Context, Execution) error { return nil })
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	begin := time.Now()
	if err := r.Stop(ctx); err != nil || time.Since(begin) > time.Second {
		t.Fatalf("Stop : %v en %s", err, time.Since(begin))
	}
	if err := r.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx); err == nil {
		t.Fatal("redémarrage accepté")
	}
}

// Run s'arrête proprement à l'annulation de son contexte.
func TestRunStopsOnCancel(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	r := NewRunner(tdb.App, fastOptions(RunnerOptions{ShutdownTimeout: time.Second}))
	done := make(chan struct{})
	mustRegister(t, r, "test.run", func(context.Context, Execution) error { close(done); return nil })
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- r.Run(ctx) }()
	enqueue(t, tdb.App, Job{Kind: "test.run"})
	<-done
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run ne rend pas la main")
	}
}

// Un job interrompu par l'arrêt dont un jumeau attend déjà s'efface devant lui.
func TestStopReleaseYieldsToPendingTwin(t *testing.T) {
	t.Parallel()
	tdb := dbtest.New(t)
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	started := make(chan struct{})
	r := NewRunner(tdb.App, fastOptions(RunnerOptions{Concurrency: 1}))
	mustRegister(t, r, "test.twin", func(context.Context, Execution) error { close(started); <-stuck; return nil })
	first := enqueue(t, tdb.App, Job{Kind: "test.twin", UniqueKey: "k"})
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-started
	twin := enqueue(t, tdb.App, Job{Kind: "test.twin", UniqueKey: "k"})
	// Stop libère les jobs pendant la dernière marge de son délai (le quart, 2 s au plus) ;
	// ici la libération enchaîne deux transactions (remise en attente refusée par la clé
	// d'unicité, puis suppression). Avec 500 ms, la marge de 125 ms ne tenait pas sur une
	// machine chargée (CI en -race) : délai de 4 s, marge de 1 s.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := r.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if count(t, tdb.App, "id = $1", first) != 0 || status(t, tdb.App, twin) != "pending" {
		t.Fatal("le job interrompu n'a pas cédé la place à son jumeau")
	}
}
