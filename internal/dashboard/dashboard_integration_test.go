//go:build integration

package dashboard

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/vuln"
)

func wantCounts(t *testing.T, what string, got Counts, crit, high, med, low, kev int) {
	t.Helper()
	if got.Of(vuln.SeverityCritical) != crit || got.Of(vuln.SeverityHigh) != high || got.Of(vuln.SeverityMedium) != med ||
		got.Of(vuln.SeverityLow) != low || got.KEV != kev {
		t.Errorf("%s : %+v, attendu %d/%d/%d/%d KEV %d", what, got, crit, high, med, low, kev)
	}
}

func wantFix(t *testing.T, got map[vuln.Severity]FixTime, sev vuln.Severity, fixed int, median time.Duration) {
	t.Helper()
	if f := got[sev]; f.Fixed != fixed || (fixed > 0 && f.Median != median) {
		t.Errorf("délai %s : %+v, attendu %d en %s", sev, f, fixed, median)
	}
}

// TestOrgIndicators vérifie chaque indicateur du tableau de bord contre le jeu construit à
// la main (reference) : seules les références actives des projets actifs comptent.
func TestOrgIndicators(t *testing.T) {
	t.Parallel()
	pool, _, s := newDB(t)
	f := reference(t, pool, "atelier")
	other := reference(t, pool, "autre") // même jeu dans une autre organisation : rien ne fuit
	other.finding("api/main", "openssl", "CVE-2099-0004", "low", false, 5, now.Add(-day24), nil)

	o, err := s.Org(context.Background(), f.org, tenant.AllTeams(), Period90)
	if err != nil {
		t.Fatal(err)
	}
	// Constats ouverts par sévérité, KEV : règle « références actives des projets actifs ».
	wantCounts(t, "ouverts", o.Open, 1, 1, 2, 1, 1)
	if o.Open.Total() != 5 || o.KEVVulns != 1 || o.KEVProjects != 1 {
		t.Errorf("total %d, KEV %d vulnérabilités dans %d projets", o.Open.Total(), o.KEVVulns, o.KEVProjects)
	}
	// Délai médian de correction : resolved_at − first_seen_at, constats résolus sur la
	// période, projets actifs.
	wantFix(t, o.FixTimes, vuln.SeverityCritical, 1, 8*day24)
	wantFix(t, o.FixTimes, vuln.SeverityHigh, 1, 35*time.Hour)
	wantFix(t, o.FixTimes, vuln.SeverityMedium, 1, 15*day24)
	wantFix(t, o.FixTimes, vuln.SeverityLow, 0, 0)
	// Sur 365 jours, le constat faible résolu il y a 95 jours compte.
	year, err := s.Org(context.Background(), f.org, tenant.AllTeams(), Period365)
	if err != nil {
		t.Fatal(err)
	}
	wantFix(t, year.FixTimes, vuln.SeverityLow, 1, 5*day24)

	if o.Projects[project.KindRepo] != 2 || o.Projects[project.KindHost] != 1 || o.ProjectCount() != 3 {
		t.Errorf("projets : %v", o.Projects)
	}
	if o.LastAnalysis == nil || !o.LastAnalysis.Equal(now.Add(-2*time.Hour)) {
		t.Errorf("dernière analyse : %v", o.LastAnalysis)
	}
	// Projets les plus exposés : risque maximal ouvert.
	if len(o.Exposed) != 2 || o.Exposed[0].Slug != "api" || o.Exposed[0].MaxRisk != 99 || o.Exposed[1].Slug != "srv" ||
		o.Exposed[1].MaxRisk != 45 {
		t.Fatalf("projets exposés : %+v", o.Exposed)
	}
	wantCounts(t, "exposition de api", o.Exposed[0].Open, 1, 1, 1, 0, 1)
	wantCounts(t, "exposition de srv", o.Exposed[1].Open, 0, 0, 1, 1, 0)
	// Composants vulnérables les plus répandus : familles, par projets touchés puis pire
	// sévérité.
	var bases []string
	for _, c := range o.Widespread {
		bases = append(bases, c.PURLBase)
	}
	if !slices.Equal(bases, []string{"pkg:npm/lodash", "pkg:deb/debian/openssl", "pkg:maven/org.apache.logging.log4j/log4j-core"}) {
		t.Fatalf("composants répandus : %v", bases)
	}
	lodash := o.Widespread[0]
	if lodash.Projects != 2 || !slices.Equal(lodash.Versions, []string{"4.17.15", "4.17.20"}) || lodash.VersionCount != 2 ||
		lodash.Worst != vuln.SeverityHigh || lodash.KEV || lodash.ID != f.id("lodash-20") || lodash.Name != "lodash-15" {
		t.Errorf("lodash : %+v", lodash)
	}
	if l := o.Widespread[2]; l.Projects != 1 || l.Worst != vuln.SeverityCritical || !l.KEV {
		t.Errorf("log4j : %+v", l)
	}
	// Agents muets (règle agent.Activity) : agent serveur sans inventaire depuis plus de 7
	// jours (ici depuis sa création, 60 jours), agent dépôt sans contact depuis plus de 7
	// jours ; désactivés et jamais vus exclus ; le plus ancien silence d'abord.
	if o.SilentAgents != 2 || len(o.Silent) != 2 || o.Silent[0].Name != "srv-agent" || o.Silent[1].Name != "lost-agent" {
		t.Errorf("agents muets : %d %+v", o.SilentAgents, o.Silent)
	}
	// Premier jour : la tendance n'a qu'un point, l'état courant.
	if len(o.Trend) != 1 || !o.Trend[0].Day.Equal(day(now)) || o.WeekAgo != nil {
		t.Errorf("tendance du premier jour : %+v, il y a 7 jours %v", o.Trend, o.WeekAgo)
	}
	wantCounts(t, "point du jour", o.Trend[0].Open, 1, 1, 2, 1, 1)
}

// TestProjectIndicators : les mêmes indicateurs à l'échelle d'un projet.
func TestProjectIndicators(t *testing.T) {
	t.Parallel()
	pool, _, s := newDB(t)
	f := reference(t, pool, "atelier")
	srv, err := s.Project(context.Background(), f.org, f.id("srv"), Period90)
	if err != nil {
		t.Fatal(err)
	}
	wantCounts(t, "srv", srv.Open, 0, 0, 1, 1, 0)
	if srv.KEVVulns != 0 || srv.KEVProjects != 0 || len(srv.Trend) != 1 {
		t.Errorf("srv : %+v", srv)
	}
	wantFix(t, srv.FixTimes, vuln.SeverityCritical, 1, 8*day24)
	wantFix(t, srv.FixTimes, vuln.SeverityHigh, 1, 35*time.Hour)
	wantFix(t, srv.FixTimes, vuln.SeverityMedium, 0, 0)
	if srv.LastAnalysis == nil || !srv.LastAnalysis.Equal(now.Add(-2*time.Hour)) {
		t.Errorf("dernière analyse : %v", srv.LastAnalysis)
	}
	// Un projet archivé garde ses indicateurs ; sa référence retirée non.
	old, err := s.Project(context.Background(), f.org, f.id("old"), Period90)
	if err != nil {
		t.Fatal(err)
	}
	wantCounts(t, "old", old.Open, 1, 0, 0, 0, 1)
	wantFix(t, old.FixTimes, vuln.SeverityHigh, 1, 2*day24)
	api, err := s.Project(context.Background(), f.org, f.id("api"), Period90)
	if err != nil {
		t.Fatal(err)
	}
	wantCounts(t, "api (sans la référence retirée)", api.Open, 1, 1, 1, 0, 1)
	if api.KEVVulns != 1 || api.KEVProjects != 1 {
		t.Errorf("api : KEV %d/%d", api.KEVVulns, api.KEVProjects)
	}
	quiet, err := s.Project(context.Background(), f.org, f.id("quiet"), Period90)
	if err != nil || quiet.Open.Total() != 0 || quiet.LastAnalysis != nil {
		t.Fatalf("quiet : %+v, %v", quiet, err)
	}
}

type orgRow struct {
	open                         [6]int
	kev, kevVulns, projects, mut int
	fixed                        [6]int
	p50                          [6]*float64
}

func readOrgRow(t *testing.T, f *fixture, d time.Time) (orgRow, int) {
	t.Helper()
	var r orgRow
	var n int
	err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		if err := tx.QueryRowContext(context.Background(), `SELECT count(*) FROM org_daily_stats`).Scan(&n); err != nil {
			return err
		}
		return tx.QueryRowContext(context.Background(), `SELECT open_critical, open_high, open_medium, open_low, open_negligible,
			open_unknown, open_kev, kev_vulns, projects, silent_agents, fixed_critical, fixed_high, fixed_medium, fixed_low,
			fixed_negligible, fixed_unknown, fix_p50_critical, fix_p50_high, fix_p50_medium, fix_p50_low, fix_p50_negligible,
			fix_p50_unknown FROM org_daily_stats WHERE day = $1`, d).Scan(
			&r.open[0], &r.open[1], &r.open[2], &r.open[3], &r.open[4], &r.open[5], &r.kev, &r.kevVulns, &r.projects, &r.mut,
			&r.fixed[0], &r.fixed[1], &r.fixed[2], &r.fixed[3], &r.fixed[4], &r.fixed[5],
			&r.p50[0], &r.p50[1], &r.p50[2], &r.p50[3], &r.p50[4], &r.p50[5])
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, n
}

// TestRecordDailyStats : la ligne du jour reprend les indicateurs ; un second passage le
// même jour la réécrit sans en créer d'autre (idempotence) ; les lignes par projet couvrent
// les projets actifs ; l'historique par projet est purgé au-delà de la rétention.
func TestRecordDailyStats(t *testing.T) {
	t.Parallel()
	pool, c, s := newDB(t)
	f := reference(t, pool, "atelier")
	f.exec(`INSERT INTO project_daily_stats (org_id, project_id, day, open_critical, open_high, open_medium, open_low,
		open_negligible, open_unknown, open_kev, recorded_at) VALUES ($1, $2, $3, 9, 0, 0, 0, 0, 0, 0, now())`,
		f.org, f.id("api"), day(now).AddDate(0, 0, -ProjectStatsRetention-1))

	d, err := s.Record(context.Background(), f.org)
	if err != nil {
		t.Fatal(err)
	}
	wantCounts(t, "jour", d.Open, 1, 1, 2, 1, 1)
	if !d.Day.Equal(day(now)) || d.KEVVulns != 1 || d.Projects != 3 || d.SilentAgents != 2 {
		t.Errorf("jour : %+v", d)
	}
	// Résolu aujourd'hui : l'élevé, en 35 heures.
	wantFix(t, d.Fixed, vuln.SeverityHigh, 1, 35*time.Hour)
	wantFix(t, d.Fixed, vuln.SeverityCritical, 0, 0)

	c.set(now.Add(5 * time.Hour))
	f.exec(`UPDATE findings SET status = 'resolved', resolution = 'not_matched', resolved_at = $1
		WHERE severity = 'low' AND status = 'open'`, now.Add(4*time.Hour))
	if _, err := s.Record(context.Background(), f.org); err != nil {
		t.Fatal(err)
	}
	row, n := readOrgRow(t, f, day(now))
	if n != 1 {
		t.Fatalf("%d lignes d'organisation après deux passages le même jour", n)
	}
	if row.open != [6]int{1, 1, 2, 0, 0, 0} || row.kev != 1 || row.kevVulns != 1 || row.projects != 3 || row.mut != 2 {
		t.Errorf("ligne réécrite : %+v", row)
	}
	if row.fixed != [6]int{0, 1, 0, 1, 0, 0} || row.p50[0] != nil || row.p50[1] == nil || *row.p50[1] != (35*time.Hour).Seconds() ||
		row.p50[3] == nil || *row.p50[3] != (now.Add(4*time.Hour).Sub(now.Add(-50*day24))).Seconds() {
		t.Errorf("délais du jour : %+v", row)
	}

	var rows int
	var apiCrit, quietTotal int
	if err := pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		if err := tx.QueryRowContext(context.Background(), `SELECT count(*) FROM project_daily_stats`).Scan(&rows); err != nil {
			return err
		}
		if err := tx.QueryRowContext(context.Background(), `SELECT open_critical FROM project_daily_stats WHERE project_id = $1 AND day = $2`,
			f.id("api"), day(now)).Scan(&apiCrit); err != nil {
			return err
		}
		return tx.QueryRowContext(context.Background(), `SELECT open_critical + open_high + open_medium + open_low
			FROM project_daily_stats WHERE project_id = $1`, f.id("quiet")).Scan(&quietTotal)
	}); err != nil {
		t.Fatal(err)
	}
	// api, srv, quiet (old archivé exclu) ; la ligne trop ancienne est purgée.
	if rows != 3 || apiCrit != 1 || quietTotal != 0 {
		t.Errorf("lignes des projets : %d, critique de api %d, quiet %d", rows, apiCrit, quietTotal)
	}
}

// TestTrendFromDailyStats : la série lit les lignes enregistrées, un jour sur Step, et se
// termine par l'état courant ; la variation sur 7 jours lit la ligne d'il y a 7 jours.
func TestTrendFromDailyStats(t *testing.T) {
	t.Parallel()
	pool, c, s := newDB(t)
	f := reference(t, pool, "atelier")
	// Huit jours d'historique enregistré par le job, de J−8 à J−1 ; à J−7, un constat élevé
	// de plus était ouvert.
	f.finding("srv/host", "log4j", "CVE-2099-0002", "high", false, 60, now.Add(-30*day24), nil)
	for i := 8; i >= 1; i-- {
		c.set(now.AddDate(0, 0, -i))
		if i == 6 {
			f.exec(`UPDATE findings SET status = 'resolved', resolution = 'not_matched', resolved_at = $1
				WHERE vuln_id = 'CVE-2099-0002' AND component_id = $2`, now.AddDate(0, 0, -i), f.id("log4j"))
		}
		if _, err := s.Record(context.Background(), f.org); err != nil {
			t.Fatal(err)
		}
	}
	c.set(now)
	o, err := s.Org(context.Background(), f.org, tenant.AllTeams(), Period30)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Trend) != 9 || !o.Trend[0].Day.Equal(day(now).AddDate(0, 0, -8)) || !o.Trend[8].Day.Equal(day(now)) {
		t.Fatalf("série : %d points, %+v", len(o.Trend), o.Trend)
	}
	if o.Trend[1].Open.Of(vuln.SeverityHigh) != 2 || o.Trend[2].Open.Of(vuln.SeverityHigh) != 1 {
		t.Errorf("élevés à J−7 et J−6 : %d, %d", o.Trend[1].Open.Of(vuln.SeverityHigh), o.Trend[2].Open.Of(vuln.SeverityHigh))
	}
	if o.WeekAgo == nil || o.WeekAgo.Of(vuln.SeverityHigh) != 2 || o.Open.Of(vuln.SeverityHigh) != 1 {
		t.Errorf("il y a 7 jours : %+v, maintenant %+v", o.WeekAgo, o.Open)
	}
	// Sur 365 jours, un point par semaine en remontant depuis aujourd'hui : J−7, puis
	// l'état courant.
	year, err := s.Org(context.Background(), f.org, tenant.AllTeams(), Period365)
	if err != nil {
		t.Fatal(err)
	}
	if len(year.Trend) != 2 || !year.Trend[0].Day.Equal(day(now).AddDate(0, 0, -7)) {
		t.Errorf("série annuelle : %+v", year.Trend)
	}
	// À l'échelle du projet, la même série.
	p, err := s.Project(context.Background(), f.org, f.id("srv"), Period30)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Trend) != 9 || p.Trend[1].Open.Of(vuln.SeverityHigh) != 1 || p.WeekAgo == nil || p.WeekAgo.Of(vuln.SeverityHigh) != 1 {
		t.Errorf("série du projet : %+v, il y a 7 jours %+v", p.Trend, p.WeekAgo)
	}
}

// TestStatsJobs : l'échéance met en file un job par organisation active, et le job
// enregistre la ligne du jour ; un job sans organisation échoue définitivement.
func TestStatsJobs(t *testing.T) {
	t.Parallel()
	pool, _, s := newDB(t)
	a := newFixture(t, pool, "active")
	archived := newFixture(t, pool, "archivee")
	if err := pool.InOrg(context.Background(), archived.org, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(context.Background(), `UPDATE organizations SET archived_at = now()`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.StatsAllHandler().Handle(context.Background(), jobs.Execution{Kind: StatsAllKind}); err != nil {
		t.Fatal(err)
	}
	// Une seconde fois : la clé d'unicité fond la mise en file.
	n, err := s.EnqueueAll(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("mises en file : %d, %v", n, err)
	}
	var queued []string
	if err := pool.InTx(context.Background(), func(tx *db.Tx) error {
		rows, err := tx.QueryContext(context.Background(), `SELECT org_id::text FROM jobs WHERE kind = $1 AND status = 'pending'`, StatsOrgKind)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			queued = append(queued, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(queued) != 1 || queued[0] != a.org.String() {
		t.Fatalf("jobs en file : %v, attendu %s", queued, a.org)
	}
	if err := s.StatsOrgHandler().Handle(context.Background(), jobs.Execution{Kind: StatsOrgKind, OrgID: a.org}); err != nil {
		t.Fatal(err)
	}
	if _, n := readOrgRow(t, a, day(now)); n != 1 {
		t.Fatalf("%d lignes après le job", n)
	}
	err = s.StatsOrgHandler().Handle(context.Background(), jobs.Execution{Kind: StatsOrgKind})
	if err == nil || !jobs.IsPermanent(err) {
		t.Fatalf("job sans organisation : %v", err)
	}
	if sc := StatsSchedule(); sc.Name != StatsAllKind || sc.Every != StatsEvery || sc.Job.Kind != StatsAllKind {
		t.Fatalf("échéance : %+v", sc)
	}
}

// TestReadsNeedTheOrganization : sous la RLS, une organisation inconnue ne lit rien.
func TestReadsNeedTheOrganization(t *testing.T) {
	t.Parallel()
	pool, _, s := newDB(t)
	reference(t, pool, "atelier")
	stranger, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.Org(context.Background(), stranger, tenant.AllTeams(), Period90)
	if err != nil || o.Open.Total() != 0 || len(o.Exposed) != 0 || len(o.Widespread) != 0 || o.SilentAgents != 0 || o.ProjectCount() != 0 {
		t.Fatalf("organisation étrangère : %+v, %v", o, err)
	}
	if _, err := s.Org(context.Background(), tenant.OrgID{}, tenant.AllTeams(), Period90); !errors.Is(err, tenant.ErrZeroOrgID) {
		t.Fatalf("organisation nulle : %v", err)
	}
}

// TestOrgIndicatorsFollowTeams : le tableau de bord d'un membre ne compte que les projets
// et agents de ses équipes ; sa tendance additionne les statistiques quotidiennes de ces
// projets ; sans équipe, il est vide.
func TestOrgIndicatorsFollowTeams(t *testing.T) {
	t.Parallel()
	pool, _, s := newDB(t)
	f := reference(t, pool, "atelier")
	ops := newID()
	f.exec(`INSERT INTO teams (org_id, id, name) VALUES ($1, $2, 'Exploitation')`, f.org, ops)
	f.exec(`UPDATE projects SET team_id = $2 WHERE id = $1`, f.id("srv"), ops)
	f.exec(`UPDATE agents SET team_id = $2 WHERE id = $1`, f.id("srv-agent"), ops)
	yesterday := day(now).AddDate(0, 0, -1)
	f.exec(`INSERT INTO project_daily_stats (org_id, project_id, day, open_critical, open_high, open_medium, open_low,
		open_negligible, open_unknown, open_kev, recorded_at) VALUES
		($1, $2, $4, 0, 0, 3, 0, 0, 0, 0, now()), ($1, $3, $4, 7, 0, 0, 0, 0, 0, 7, now())`, f.org, f.id("srv"), f.id("api"), yesterday)

	o, err := s.Org(context.Background(), f.org, tenant.OnlyTeams(ops), Period30)
	if err != nil {
		t.Fatal(err)
	}
	wantCounts(t, "ouverts de l'équipe", o.Open, 0, 0, 1, 1, 0)
	if len(o.Exposed) != 1 || o.Exposed[0].Slug != "srv" || o.ProjectCount() != 1 || o.KEVVulns != 0 {
		t.Errorf("équipe : exposés %+v, %d projets, %d KEV", o.Exposed, o.ProjectCount(), o.KEVVulns)
	}
	if o.SilentAgents != 1 || len(o.Silent) != 1 || o.Silent[0].Name != "srv-agent" {
		t.Errorf("agents muets de l'équipe : %d %+v", o.SilentAgents, o.Silent)
	}
	if len(o.Widespread) != 2 {
		t.Errorf("composants répandus de l'équipe : %+v", o.Widespread)
	}
	var past *Point
	for i := range o.Trend {
		if o.Trend[i].Day.Equal(yesterday) {
			past = &o.Trend[i]
		}
	}
	if past == nil || past.Open.Of(vuln.SeverityMedium) != 3 || past.Open.Of(vuln.SeverityCritical) != 0 {
		t.Errorf("tendance de l'équipe : %+v", o.Trend)
	}

	none, err := s.Org(context.Background(), f.org, tenant.OnlyTeams(), Period30)
	if err != nil {
		t.Fatal(err)
	}
	if none.Open.Total() != 0 || len(none.Exposed) != 0 || none.ProjectCount() != 0 || none.SilentAgents != 0 || len(none.Widespread) != 0 {
		t.Errorf("membre sans équipe : %+v", none)
	}
	all, err := s.Org(context.Background(), f.org, tenant.AllTeams(), Period30)
	if err != nil {
		t.Fatal(err)
	}
	wantCounts(t, "administrateur", all.Open, 1, 1, 2, 1, 1)
}

// TestMutedFindingsLeaveIndicators : un constat « non affecté » ou « faux positif »
// (triage, T14) ne compte plus parmi les constats ouverts du tableau de bord ; « risque
// accepté » ou « affecté » comptent toujours.
func TestMutedFindingsLeaveIndicators(t *testing.T) {
	t.Parallel()
	pool, _, s := newDB(t)
	f := reference(t, pool, "atelier")
	decision := newID()
	f.exec(`INSERT INTO triage_decisions (org_id, id, scope, vuln_id, purl_base, action, status, justification, author_label, created_at)
		VALUES ($1, $2, 'org', 'CVE-2021-44228', 'pkg:maven/org.apache.logging.log4j/log4j-core', 'set', 'not_affected',
		        'code_not_reachable', 'system', now())`, f.org, decision)
	f.exec(`UPDATE findings SET triage_status = 'not_affected', triage_decision_id = $2 WHERE vuln_id = 'CVE-2021-44228' AND component_id = $1`,
		f.id("log4j"), decision)
	f.exec(`UPDATE findings SET triage_status = 'risk_accepted', triage_decision_id = $1 WHERE vuln_id = 'CVE-2099-0003'`, decision)
	o, err := s.Org(context.Background(), f.org, tenant.AllTeams(), Period90)
	if err != nil {
		t.Fatal(err)
	}
	wantCounts(t, "ouverts à traiter", o.Open, 0, 1, 2, 1, 0)
	if o.KEVVulns != 0 || o.KEVProjects != 0 {
		t.Errorf("KEV : %d vulnérabilités, %d projets", o.KEVVulns, o.KEVProjects)
	}
}

// TestOpenByProject : constats ouverts à traiter par projet (liste des projets), selon la
// règle de la fiche projet : références actives, projets archivés compris, triage
// « non affecté » et « faux positif » exclus, équipes invisibles et autres
// organisations absentes.
func TestOpenByProject(t *testing.T) {
	t.Parallel()
	pool, _, s := newDB(t)
	f := reference(t, pool, "atelier")
	other := reference(t, pool, "autre")
	ids := []uuid.UUID{f.id("api"), f.id("srv"), f.id("old"), f.id("quiet"), other.id("api")}
	ctx := context.Background()

	got, err := s.OpenByProject(ctx, f.org, tenant.AllTeams(), ids)
	if err != nil {
		t.Fatal(err)
	}
	wantCounts(t, "api", got[f.id("api")], 1, 1, 1, 0, 1) // la référence retirée « dev » ne compte pas
	wantCounts(t, "srv", got[f.id("srv")], 0, 0, 1, 1, 0)
	wantCounts(t, "old (archivé)", got[f.id("old")], 1, 0, 0, 0, 1)
	if _, ok := got[f.id("quiet")]; ok {
		t.Error("projet sans constat présent")
	}
	if _, ok := got[other.id("api")]; ok || len(got) != 3 {
		t.Errorf("projets lus : %v", got)
	}

	decision := newID()
	f.exec(`INSERT INTO triage_decisions (org_id, id, scope, vuln_id, purl_base, action, status, author_label, created_at)
		VALUES ($1, $2, 'org', 'CVE-2099-0002', 'pkg:npm/lodash', 'set', 'false_positive', 'system', now())`, f.org, decision)
	f.exec(`UPDATE findings SET triage_status = 'false_positive', triage_decision_id = $2 WHERE project_id = $1 AND vuln_id = 'CVE-2099-0002'`,
		f.id("api"), decision)
	ops := newID()
	f.exec(`INSERT INTO teams (org_id, id, name) VALUES ($1, $2, 'Exploitation')`, f.org, ops)
	f.exec(`UPDATE projects SET team_id = $2 WHERE id = $1`, f.id("srv"), ops)
	if got, err = s.OpenByProject(ctx, f.org, tenant.AllTeams(), ids); err != nil {
		t.Fatal(err)
	}
	wantCounts(t, "api après triage", got[f.id("api")], 1, 0, 1, 0, 1)
	if got, err = s.OpenByProject(ctx, f.org, tenant.OnlyTeams(ops), ids); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("équipe Exploitation : %v", got)
	}
	wantCounts(t, "srv pour son équipe", got[f.id("srv")], 0, 0, 1, 1, 0)
	if got, err = s.OpenByProject(ctx, f.org, tenant.AllTeams(), nil); err != nil || len(got) != 0 {
		t.Errorf("sans projet : %v, %v", got, err)
	}
}
