//go:build integration

package search

import (
	"context"
	"io"
	"net/url"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"leblanc.io/lotor/internal/benchdata"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// TestSearchBenchmark mesure la recherche sur le jeu de référence (1 000 projets,
// 1 million de liens) selon docs/benchmarks.md : rôle d'exécution, RLS active, froid puis
// 50 passages chauds, 95e centile sous 2 s. Long : seulement avec LOTOR_BENCH=1
// (make bench-search).
func TestSearchBenchmark(t *testing.T) {
	if os.Getenv("LOTOR_BENCH") != "1" {
		t.Skip("LOTOR_BENCH=1 pour mesurer la recherche sur le jeu de référence")
	}
	ctx := context.Background()
	start := time.Now()
	tp := benchdata.ReferenceTeams()
	d, org, ts := planDatasetWith(t, benchdata.Reference(), &tp)
	// Membre d'une seule équipe (1 sur 10) : la recherche passe le filtre des équipes.
	member := tenant.OnlyTeams(ts.Teams[1])
	team := "&team=" + ts.Teams[1].String()
	t.Logf("jeu de référence et compléments générés et analysés en %s", time.Since(start).Round(time.Second))
	svc := NewService(d.App, cmp)
	req := func(params string) Request {
		v, err := url.ParseQuery(params)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseRequest(v)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	second := req("q=lib-1&sort=name")
	first, err := svc.Search(ctx, org, tenant.AllTeams(), second)
	if err != nil {
		t.Fatal(err)
	}
	second.Cursor = first.NextCursor
	cases := []struct {
		name string
		run  func(i int) (Result, error)
	}{
		{"nom large (lib-1, 1 000 composants)", func(int) (Result, error) { return svc.Search(ctx, org, tenant.AllTeams(), req("q=lib-1")) }},
		{"nom précis (lib-<i>)", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=lib-"+strconv.Itoa(1234+i)))
		}},
		{"plage vers sur lodash (une occurrence par projet)", func(int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=pkg:npm/lodash+vers:npm/<4.17.20"))
		}},
		{"purl d'un paquet", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=pkg:maven/org.bench/lib-"+strconv.Itoa(5*i+1)))
		}},
		{"vulnérabilité", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=CVE-2099-"+[]string{"00001", "00002", "00941", "00050", "00100"}[i%5]))
		}},
		{"empreinte", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q="+url.QueryEscape(benchdata.SearchHash(i))))
		}},
		{"nom large filtré (sévérité moyenne, dépôts, tri par instantané)", func(int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=lib-1&severity=medium&type=repo&sort=snapshot"))
		}},
		{"page suivante (curseur)", func(int) (Result, error) { return svc.Search(ctx, org, tenant.AllTeams(), second) }},
		// Lot 2 (T18) : équipes, conteneurs, statut de triage.
		{"nom large, membre d'une équipe", func(int) (Result, error) { return svc.Search(ctx, org, member, req("q=lib-1")) }},
		{"nom large, filtre équipe", func(int) (Result, error) { return svc.Search(ctx, org, tenant.AllTeams(), req("q=lib-1"+team)) }},
		{"nom large, conteneurs compris", func(int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=lib-1&containers=1"))
		}},
		{"vulnérabilité, membre d'une équipe", func(i int) (Result, error) {
			return svc.Search(ctx, org, member, req("q=CVE-2099-"+[]string{"00001", "00002", "00941", "00050", "00100"}[i%5]))
		}},
		{"vulnérabilité, filtre triage (affecté, à analyser)", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(),
				req("q=CVE-2099-"+[]string{"00001", "00002", "00941", "00050", "00100"}[i%5]+"&triage=affected&triage=in_triage&containers=1"))
		}},
	}
	for _, c := range cases {
		var ds []time.Duration
		var cold time.Duration
		var res Result
		for i := range 51 {
			s := time.Now()
			r, err := c.run(i)
			if err != nil {
				t.Fatalf("%s : %v", c.name, err)
			}
			if i == 0 {
				cold, res = time.Since(s), r
				continue
			}
			ds = append(ds, time.Since(s))
		}
		slices.Sort(ds)
		p95 := ds[len(ds)*95/100]
		t.Logf("%s : %d occurrences, %d projets ; froid %s, p50 %s, p95 %s, max %s", c.name, res.Hits, res.Projects,
			cold.Round(time.Millisecond), ds[len(ds)/2].Round(time.Millisecond), p95.Round(time.Millisecond), ds[len(ds)-1].Round(time.Millisecond))
		if p95 > 2*time.Second {
			t.Errorf("%s : p95 %s au-delà de 2 s", c.name, p95)
		}
	}
	// Export de toutes les occurrences d'une recherche large.
	var ds []time.Duration
	for range 20 {
		s := time.Now()
		if err := svc.Export(ctx, org, tenant.AllTeams(), req("q=lib-1"), FormatCSV, io.Discard); err != nil {
			t.Fatal(err)
		}
		ds = append(ds, time.Since(s))
	}
	slices.Sort(ds)
	t.Logf("export CSV (lib-1) : p50 %s, p95 %s, max %s", ds[len(ds)/2].Round(time.Millisecond),
		ds[len(ds)*95/100].Round(time.Millisecond), ds[len(ds)-1].Round(time.Millisecond))
	ds = ds[:0]
	for range 20 {
		s := time.Now()
		if err := svc.Export(ctx, org, tenant.AllTeams(), req("q=lib-1&containers=1"), FormatCSV, io.Discard); err != nil {
			t.Fatal(err)
		}
		ds = append(ds, time.Since(s))
	}
	slices.Sort(ds)
	t.Logf("export CSV (lib-1, conteneurs compris) : p50 %s, p95 %s, max %s", ds[len(ds)/2].Round(time.Millisecond),
		ds[len(ds)*95/100].Round(time.Millisecond), ds[len(ds)-1].Round(time.Millisecond))

	// Plans réels (EXPLAIN ANALYZE, RLS active) consignés dans docs/benchmarks.md.
	resolve := func(q string) target {
		var tg target
		query, err := Parse(q, cmp)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
			var err error
			tg, err = svc.resolve(ctx, tx, query)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return tg
	}
	for _, q := range []string{"pkg:npm/lodash vers:npm/<4.17.20", "lib-1", "CVE-2099-00001"} {
		a := &args{}
		hits := hitsSQL(resolve(q), Filters{}, nil, a)
		t.Logf("plan des occurrences de %q :\n%s", q, explain(t, d.App, org, true, `SELECT count(*) FROM (`+hits+`) h`, a.list...))
	}
}

// TestSearchAtBenchmark mesure la recherche à une date passée (T21) sur le jeu de
// référence enrichi de 12 mois d'historique (un instantané par semaine et par référence) :
// 95e centile sous 5 s, RLS active. Seulement avec LOTOR_BENCH=1 (make bench-search).
func TestSearchAtBenchmark(t *testing.T) {
	if os.Getenv("LOTOR_BENCH") != "1" {
		t.Skip("LOTOR_BENCH=1 pour mesurer la recherche à une date passée")
	}
	ctx := context.Background()
	start := time.Now()
	tp := benchdata.ReferenceTeams()
	d, org, ts := planDatasetWith(t, benchdata.Reference(), &tp)
	n, err := benchdata.AddHistory(ctx, d.App, org, benchdata.HistoryWeeks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Owner(t).ExecContext(ctx, "ANALYZE"); err != nil {
		t.Fatal(err)
	}
	t.Logf("jeu de référence et %d instantanés d'historique générés en %s", n, time.Since(start).Round(time.Second))
	svc := NewService(d.App, cmp)
	member := tenant.OnlyTeams(ts.Teams[1])
	req := func(params string) Request {
		v, err := url.ParseQuery(params)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseRequest(v)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	at := func(weeks int) string {
		return "&at=" + time.Now().UTC().AddDate(0, 0, -7*weeks-3).Format(time.DateOnly)
	}
	cases := []struct {
		name string
		run  func(i int) (Result, error)
	}{
		{"nom large (lib-1) il y a 6 mois", func(int) (Result, error) { return svc.Search(ctx, org, tenant.AllTeams(), req("q=lib-1"+at(26))) }},
		{"nom large (lib-1) à une date variable", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=lib-1"+at(i%52)))
		}},
		{"nom précis (lib-<i>) il y a 11 mois", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=lib-"+strconv.Itoa(1234+i)+at(48)))
		}},
		{"plage vers sur lodash il y a 3 mois", func(int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q=pkg:npm/lodash+vers:npm/<4.17.20"+at(13)))
		}},
		{"empreinte il y a 9 mois", func(i int) (Result, error) {
			return svc.Search(ctx, org, tenant.AllTeams(), req("q="+url.QueryEscape(benchdata.SearchHash(i))+at(39)))
		}},
		{"nom large, membre d'une équipe, conteneurs compris, il y a 6 mois", func(int) (Result, error) {
			return svc.Search(ctx, org, member, req("q=lib-1&containers=1"+at(26)))
		}},
	}
	for _, c := range cases {
		var ds []time.Duration
		var cold time.Duration
		var res Result
		for i := range 51 {
			s := time.Now()
			r, err := c.run(i)
			if err != nil {
				t.Fatalf("%s : %v", c.name, err)
			}
			if i == 0 {
				cold, res = time.Since(s), r
				continue
			}
			ds = append(ds, time.Since(s))
		}
		slices.Sort(ds)
		p95 := ds[len(ds)*95/100]
		t.Logf("%s : %d occurrences, %d projets ; froid %s, p50 %s, p95 %s, max %s", c.name, res.Hits, res.Projects,
			cold.Round(time.Millisecond), ds[len(ds)/2].Round(time.Millisecond), p95.Round(time.Millisecond), ds[len(ds)-1].Round(time.Millisecond))
		if res.Hits == 0 {
			t.Errorf("%s : aucune occurrence, la mesure ne porte sur rien", c.name)
		}
		if p95 > 5*time.Second {
			t.Errorf("%s : p95 %s au-delà de 5 s", c.name, p95)
		}
	}
	var ds []time.Duration
	for range 20 {
		s := time.Now()
		if err := svc.Export(ctx, org, tenant.AllTeams(), req("q=lib-1"+at(26)), FormatCSV, io.Discard); err != nil {
			t.Fatal(err)
		}
		ds = append(ds, time.Since(s))
	}
	slices.Sort(ds)
	t.Logf("export CSV (lib-1, il y a 6 mois) : p50 %s, p95 %s", ds[len(ds)/2].Round(time.Millisecond), ds[len(ds)*95/100].Round(time.Millisecond))
	a := &args{}
	var tg target
	query, err := Parse("lib-1", cmp)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		tg, err = svc.resolve(ctx, tx, query)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().AddDate(0, -6, 0)
	hits := hitsSQL(tg, Filters{At: &past}, nil, a)
	t.Logf("plan des occurrences de \"lib-1\" il y a 6 mois :\n%s", explain(t, d.App, org, true, `SELECT count(*) FROM (`+hits+`) h`, a.list...))
}
