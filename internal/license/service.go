package license

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/tenant"
)

// Clés de saisie de la politique.
const (
	KeyIDInvalid  = "validation.license_id_invalid"
	KeyTooMany    = "validation.license_too_many"
	KeyStatusFlag = "validation.license_default_invalid"
)

// ValidationKeys liste les clés de saisie du paquet (tests de traduction).
func ValidationKeys() []string { return []string{KeyIDInvalid, KeyTooMany, KeyStatusFlag} }

// MaxListed borne chaque liste de la politique.
const MaxListed = 500

// Types des jobs.
const (
	// EvaluateOrgKind réévalue toutes les références d'une organisation après un
	// changement de politique.
	EvaluateOrgKind = "license.evaluate_org"
)

// Service tient les politiques et les constats de licence.
type Service struct {
	pool  *db.Pool
	known Known
	now   func() time.Time
	// OnChange, facultatif, est appelé dans la transaction qui a changé des constats d'un
	// projet (évaluation des règles de politique de sujet « licence », T15).
	onChange func(ctx context.Context, tx *db.OrgTx, projectID uuid.UUID) error
}

// Options règle le service.
type Options struct {
	Pool *db.Pool
	// Known dit si un identifiant figure dans la liste SPDX (KnownFrom).
	Known    Known
	Now      func() time.Time
	OnChange func(ctx context.Context, tx *db.OrgTx, projectID uuid.UUID) error
}

// NewService construit le service.
func NewService(o Options) (*Service, error) {
	if o.Pool == nil || o.Known == nil {
		return nil, errors.New("license: dépendances incomplètes")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{pool: o.Pool, known: o.Known, now: o.Now, onChange: o.OnChange}, nil
}

// KnownFrom construit Known depuis une liste d'identifiants SPDX (celle qu'embarque le
// schéma de CycloneDX : schema.Validator.CycloneDXLicenseIDs).
func KnownFrom(ids map[string]bool) Known {
	lower := make(map[string]bool, len(ids))
	for id := range ids {
		lower[strings.ToLower(id)] = true
	}
	return func(id string) bool { return lower[strings.ToLower(id)] }
}

func invalid(field, key string) error { return &account.ValidationError{Field: field, Key: key} }

// ReadPolicy lit la politique de l'organisation de la transaction ; la politique par
// défaut sans ligne.
func ReadPolicy(ctx context.Context, tx *db.OrgTx) (Policy, error) {
	var p Policy
	var def string
	err := tx.QueryRowContext(ctx, `SELECT default_status, allowed, review, denied, require_license FROM license_policies`).
		Scan(&def, db.Array(&p.Allowed), db.Array(&p.Review), db.Array(&p.Denied), &p.RequireLicense)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultPolicy(), nil
	}
	p.Default = Status(def)
	return p, err
}

// Policy renvoie la politique d'une organisation.
func (s *Service) Policy(ctx context.Context, org tenant.OrgID) (Policy, error) {
	var p Policy
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		p, err = ReadPolicy(ctx, tx)
		return err
	}, db.ReadOnly())
	return p, wrap("politique de licences", err)
}

// validate vérifie une politique saisie : identifiants lisibles comme une licence SPDX ou
// une référence LicenseRef-, au plus MaxListed par liste.
func validate(p Policy) error {
	if rank(p.Default) < 0 {
		return invalid("default", KeyStatusFlag)
	}
	for field, ids := range map[string][]string{"allowed": p.Allowed, "review": p.Review, "denied": p.Denied} {
		if len(ids) > MaxListed {
			return invalid(field, KeyTooMany)
		}
		for _, id := range ids {
			n, err := Parse(id)
			if err != nil || n.ID == "" || n.Exception != "" || len(id) > 100 {
				return invalid(field, KeyIDInvalid)
			}
		}
	}
	return nil
}

// SetPolicy enregistre la politique d'une organisation, la journalise et met en file la
// réévaluation de toutes ses références.
func (s *Service) SetPolicy(ctx context.Context, actor audit.Actor, org tenant.OrgID, p Policy) error {
	p = p.Normalize()
	if err := validate(p); err != nil {
		return err
	}
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var by any
		if actor.UserID != 0 {
			by = actor.UserID
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO license_policies (org_id, default_status, allowed, review, denied, require_license, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (org_id) DO UPDATE SET default_status = EXCLUDED.default_status, allowed = EXCLUDED.allowed,
			    review = EXCLUDED.review, denied = EXCLUDED.denied, require_license = EXCLUDED.require_license,
			    updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
			tx.OrgID(), string(p.Default), nonNil(p.Allowed), nonNil(p.Review), nonNil(p.Denied), p.RequireLicense, s.now(), by); err != nil {
			return err
		}
		if err := audit.RecordOrg(ctx, tx, actor, audit.Event{Action: audit.LicensePolicyUpdated, TargetType: "license_policy",
			Details: map[string]string{"default": string(p.Default), "allowed": count(p.Allowed), "review": count(p.Review),
				"denied": count(p.Denied)}}); err != nil {
			return err
		}
		_, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: EvaluateOrgKind, OrgID: tx.OrgID(), Payload: struct{}{},
			UniqueKey: "license-org:" + tx.OrgID().String()})
		return err
	})
	return wrap("politique de licences", err)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func count(s []string) string { return fmt.Sprint(len(s)) }

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := account.IsValidation(err); ok {
		return err
	}
	return fmt.Errorf("license: %s : %w", what, err)
}

// item est un élément de l'inventaire courant d'une référence.
type item struct {
	component uuid.UUID
	licenses  []string
}

// EvaluateRef évalue, dans la transaction de l'appelant, les licences de l'inventaire
// courant de la référence refID : un constat ouvert par composant refusé ou à revoir
// (rouvert s'il existait, mis à jour si son verdict change), résolu pour les autres et
// pour une référence sans inventaire courant. Point d'accroche de finding.Analyzer
// (OnAnalyzed) : les licences sont évaluées à chaque analyse. Idempotent.
func (s *Service) EvaluateRef(ctx context.Context, tx *db.OrgTx, refID, projectID uuid.UUID) error {
	p, err := ReadPolicy(ctx, tx)
	if err != nil {
		return err
	}
	var snapshot uuid.NullUUID
	var setID uuid.NullUUID
	err = tx.QueryRowContext(ctx, `SELECT rc.snapshot_id, rc.set_id FROM ref_current rc
		JOIN tracked_refs r ON r.org_id = rc.org_id AND r.id = rc.ref_id AND r.removed_at IS NULL
		WHERE rc.ref_id = $1`, refID).Scan(&snapshot, &setID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var items []item
	if setID.Valid {
		rows, err := tx.QueryContext(ctx, `SELECT component_id, licenses FROM component_set_items WHERE set_id = $1`, setID.UUID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.component, db.Array(&it.licenses)); err != nil {
				rows.Close()
				return err
			}
			items = append(items, it)
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	now := s.now().UTC()
	var comps, verdicts, licenses, ids []string
	var missing []bool
	for _, it := range items {
		v := p.Evaluate(it.licenses, s.known)
		if v.Status == StatusAllowed {
			continue
		}
		comps, verdicts = append(comps, it.component.String()), append(verdicts, string(v.Status))
		licenses, ids = append(licenses, strings.Join(it.licenses, "\x1f")), append(ids, strings.Join(v.IDs(), "\x1f"))
		missing = append(missing, v.Missing)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE license_findings f SET status = 'resolved', resolved_at = greatest($3, f.first_seen_at), last_seen_at = greatest($3, f.last_seen_at)
		 WHERE f.ref_id = $1 AND f.status = 'open' AND f.component_id <> ALL($2::uuid[])`, refID, nonNil(comps), now)
	if err != nil {
		return err
	}
	resolved, _ := res.RowsAffected()
	var snap any
	if snapshot.Valid {
		snap = snapshot.UUID
	}
	res, err = tx.ExecContext(ctx, `
		INSERT INTO license_findings (org_id, id, project_id, ref_id, component_id, status, verdict, licenses, license_ids,
		                              missing, snapshot_id, first_seen_at, last_seen_at)
		SELECT $1, gen_random_uuid(), $2, $3, u.c, 'open', u.v, string_to_array(u.l, E'\x1f'), string_to_array(u.i, E'\x1f'),
		       u.m, $4, $5, $5
		  FROM unnest($6::uuid[], $7::text[], $8::text[], $9::text[], $10::boolean[]) AS u(c, v, l, i, m)
		 ORDER BY u.c
		ON CONFLICT (org_id, ref_id, component_id) DO UPDATE SET
		    verdict = EXCLUDED.verdict, licenses = EXCLUDED.licenses, license_ids = EXCLUDED.license_ids,
		    missing = EXCLUDED.missing, snapshot_id = EXCLUDED.snapshot_id, last_seen_at = greatest(EXCLUDED.last_seen_at, license_findings.last_seen_at),
		    status = 'open', resolved_at = NULL,
		    first_seen_at = CASE WHEN license_findings.status = 'resolved' THEN EXCLUDED.first_seen_at ELSE license_findings.first_seen_at END
		 WHERE license_findings.status = 'resolved' OR license_findings.verdict <> EXCLUDED.verdict
		    OR license_findings.licenses <> EXCLUDED.licenses OR license_findings.snapshot_id IS DISTINCT FROM EXCLUDED.snapshot_id`,
		tx.OrgID(), projectID, refID, snap, now, nonNil(comps), nonNil(verdicts), nonNil(licenses), nonNil(ids), missingArray(missing))
	if err != nil {
		return err
	}
	changed, _ := res.RowsAffected()
	if (resolved > 0 || changed > 0) && s.onChange != nil {
		return s.onChange(ctx, tx, projectID)
	}
	return nil
}

func missingArray(m []bool) []bool {
	if m == nil {
		return []bool{}
	}
	return m
}

// OnAnalyzed est le point d'accroche de finding.Analyzer : les licences de la référence
// analysée sont évaluées dans la même transaction.
func (s *Service) OnAnalyzed(ctx context.Context, tx *db.OrgTx, refID, projectID uuid.UUID) error {
	return s.EvaluateRef(ctx, tx, refID, projectID)
}

// EvaluateOrg réévalue toutes les références suivies de l'organisation (changement de
// politique), une transaction par projet.
func (s *Service) EvaluateOrg(ctx context.Context, org tenant.OrgID) error {
	type pair struct{ ref, project uuid.UUID }
	var pairs []pair
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT r.id, r.project_id FROM tracked_refs r ORDER BY r.project_id, r.id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p pair
			if err := rows.Scan(&p.ref, &p.project); err != nil {
				return err
			}
			pairs = append(pairs, p)
		}
		return rows.Err()
	}, db.ReadOnly())
	if err != nil {
		return wrap("réévaluation", err)
	}
	for start := 0; start < len(pairs); {
		end := start
		for end < len(pairs) && pairs[end].project == pairs[start].project {
			end++
		}
		batch := pairs[start:end]
		if err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
			for _, p := range batch {
				if err := s.EvaluateRef(ctx, tx, p.ref, p.project); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return wrap("réévaluation", err)
		}
		start = end
	}
	return nil
}

// OrgHandler est le handler du job EvaluateOrgKind.
func (s *Service) OrgHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		if e.OrgID.IsZero() {
			return jobs.Permanent(errors.New("license: job sans organisation"))
		}
		return s.EvaluateOrg(ctx, e.OrgID)
	})
}
