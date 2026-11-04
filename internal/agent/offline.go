package agent

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/offline"
	"leblanc.io/lotor/internal/tenant"
)

// Clés des refus d'une archive hors ligne (T23, ADR 0060).
const (
	KeyArchiveInvalid = "error.archive.invalid"
	KeyArchiveForeign = "error.archive.foreign"
	KeyArchiveUnknown = "error.archive.unknown_agent"
	KeyArchiveForged  = "error.archive.forged"
	KeyArchiveProject = "error.archive.project"
)

// ArchiveErrorKeys liste les clés d'erreur des archives (tests de traduction).
func ArchiveErrorKeys() []string {
	return []string{KeyArchiveInvalid, KeyArchiveForeign, KeyArchiveUnknown, KeyArchiveForged, KeyArchiveProject}
}

// ArchiveError est le refus d'une archive : sa clé dit pourquoi, sans rien révéler d'une
// autre organisation.
type ArchiveError struct{ Key string }

func (e *ArchiveError) Error() string { return "agent: archive refusée : " + e.Key }

// ArchiveSender est l'émetteur authentifié d'une archive.
type ArchiveSender struct {
	Principal Principal
	// ProjectID est le projet visé : celui du manifeste, ou le projet d'hôte de l'agent
	// (archive d'un agent serveur inscrit hors ligne, qui ne connaît pas son projet).
	ProjectID uuid.UUID
	// Enrolled : l'archive a inscrit l'agent.
	Enrolled bool
}

// ArchiveSender authentifie l'émetteur d'une archive importée dans org : le jeton d'agent
// du manifeste doit être de cette organisation (sinon KeyArchiveForeign, comme pour un
// jeton inconnu d'une autre), actif, et le code de l'archive vérifié avec l'empreinte de
// son secret. Un jeton encore inconnu, avec une inscription hors ligne, inscrit l'agent
// serveur avec le jeton qu'il a tiré, si le jeton d'inscription est de l'organisation,
// utilisable, et le code vérifié avec son empreinte. L'import n'est pas un contact de
// l'agent : sa date de dernier contact ne change pas.
func (s *Service) ArchiveSender(ctx context.Context, org tenant.OrgID, a offline.Archive, actor audit.Actor) (ArchiveSender, error) {
	m := a.Manifest
	owner, err := crossorg.AgentTokenOrg(ctx, s.pool.DB(), m.AgentToken)
	switch {
	case err == nil && owner != org:
		return ArchiveSender{}, &ArchiveError{Key: KeyArchiveForeign}
	case err == nil:
		return s.knownSender(ctx, org, a)
	case !errors.Is(err, crossorg.ErrUnknownToken):
		return ArchiveSender{}, wrap("archive", err)
	case m.Enrollment == nil:
		return ArchiveSender{}, &ArchiveError{Key: KeyArchiveUnknown}
	}
	owner, err = crossorg.EnrollmentTokenOrg(ctx, s.pool.DB(), m.Enrollment.TokenID)
	switch {
	case errors.Is(err, crossorg.ErrUnknownToken):
		return ArchiveSender{}, &ArchiveError{Key: KeyArchiveUnknown}
	case err != nil:
		return ArchiveSender{}, wrap("archive", err)
	case owner != org:
		return ArchiveSender{}, &ArchiveError{Key: KeyArchiveForeign}
	}
	hash, err := hex.DecodeString(m.Enrollment.AgentHash)
	if err != nil || len(hash) != len(SecretHash{}) {
		return ArchiveSender{}, &ArchiveError{Key: KeyArchiveInvalid}
	}
	proposed := ProposedToken{PublicID: m.AgentToken}
	copy(proposed.Hash[:], hash)
	verify := func(r enrollmentRow) error {
		if !offline.Verify(r.stored, a.RawManifest, a.MAC.Enrollment) {
			return &ArchiveError{Key: KeyArchiveForged}
		}
		return r.check(SecretHash(r.stored[:len(SecretHash{})]), s.Now())
	}
	req := EnrollRequest{Hostname: m.Enrollment.Hostname, Version: m.Enrollment.Version, Labels: m.Enrollment.Labels}
	out, err := s.enroll(ctx, org, m.Enrollment.TokenID, verify, req, &proposed, actor)
	if err != nil {
		return ArchiveSender{}, err
	}
	return ArchiveSender{Principal: Principal{Kind: KindAgent, Org: org, PublicID: m.AgentToken, AgentID: out.Agent.ID,
		AgentKind: KindHost, AgentName: out.Agent.Name}, ProjectID: out.Project.ID, Enrolled: true}, nil
}

// knownSender vérifie le jeton d'agent connu d'une archive et son code.
func (s *Service) knownSender(ctx context.Context, org tenant.OrgID, a offline.Archive) (ArchiveSender, error) {
	m := a.Manifest
	var out ArchiveSender
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var stored []byte
		var revoked, disabled bool
		var expired bool
		var kind string
		p := Principal{Kind: KindAgent, Org: org, PublicID: m.AgentToken}
		err := tx.QueryRowContext(ctx, `
			SELECT t.id, t.secret_hash, t.revoked_at IS NOT NULL, t.expires_at IS NOT NULL AND t.expires_at <= $2,
			       a.id, a.kind, a.name, a.disabled_at IS NOT NULL
			  FROM agent_tokens t JOIN agents a ON a.org_id = t.org_id AND a.id = t.agent_id
			 WHERE t.public_id = $1`, m.AgentToken, s.Now()).
			Scan(&p.TokenID, &stored, &revoked, &expired, &p.AgentID, &kind, &p.AgentName, &disabled)
		if errors.Is(err, sql.ErrNoRows) {
			return &ArchiveError{Key: KeyArchiveUnknown}
		}
		if err != nil {
			return err
		}
		if !offline.Verify(stored, a.RawManifest, a.MAC.Agent) {
			return &ArchiveError{Key: KeyArchiveForged}
		}
		switch {
		case revoked:
			return &AuthError{Key: KeyTokenRevokedErr}
		case disabled:
			return &AuthError{Key: KeyAgentDisabledErr}
		case expired:
			return &AuthError{Key: KeyTokenExpired}
		}
		p.AgentKind = Kind(kind)
		out.Principal, out.ProjectID = p, m.Context.ProjectID
		if out.ProjectID != uuid.Nil {
			return nil
		}
		if p.AgentKind != KindHost {
			return &ArchiveError{Key: KeyArchiveProject}
		}
		err = tx.QueryRowContext(ctx, `SELECT id FROM projects WHERE agent_id = $1 AND kind = 'host' AND archived_at IS NULL`,
			p.AgentID).Scan(&out.ProjectID)
		if errors.Is(err, sql.ErrNoRows) {
			return &ArchiveError{Key: KeyArchiveProject}
		}
		return err
	}, db.ReadOnly())
	if err != nil {
		var ae *ArchiveError
		if errors.As(err, &ae) {
			return ArchiveSender{}, err
		}
		return ArchiveSender{}, wrap("archive", err)
	}
	return out, nil
}

// ArchiveOrg renvoie l'organisation d'une archive, par son jeton d'agent, sinon par le
// jeton d'inscription de son inscription hors ligne (répertoire surveillé : l'archive dit
// elle-même où elle va ; son code est vérifié ensuite par ArchiveSender).
func (s *Service) ArchiveOrg(ctx context.Context, a offline.Archive) (tenant.OrgID, error) {
	org, err := crossorg.AgentTokenOrg(ctx, s.pool.DB(), a.Manifest.AgentToken)
	if err == nil || !errors.Is(err, crossorg.ErrUnknownToken) {
		return org, err
	}
	if a.Manifest.Enrollment == nil {
		return tenant.OrgID{}, &ArchiveError{Key: KeyArchiveUnknown}
	}
	org, err = crossorg.EnrollmentTokenOrg(ctx, s.pool.DB(), a.Manifest.Enrollment.TokenID)
	if errors.Is(err, crossorg.ErrUnknownToken) {
		return tenant.OrgID{}, &ArchiveError{Key: KeyArchiveUnknown}
	}
	return org, err
}
