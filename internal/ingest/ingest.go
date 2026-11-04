package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	"leblanc.io/lotor/internal/tenant"
)

// DecodeKind est le type du job de décodage d'une ingestion.
const DecodeKind = "ingest.decode"

// DecodePayload est la charge d'un job ingest.decode.
type DecodePayload struct {
	IngestionID uuid.UUID `json:"ingestion_id"`
}

// Clés des refus de la réception (problèmes de l'API, traduits par <clé>.title et
// <clé>.text) et des erreurs de saisie du contexte.
const (
	KeyRefUnknown     = "error.ingest.ref_unknown"
	KeyMissingPart    = "error.ingest.missing_part"
	KeyQuota          = "error.ingest.quota"
	KeyCommitInvalid  = "validation.ingest.commit"
	KeyCommitRequired = "validation.ingest.commit_required"
	KeyCommitForbid   = "validation.ingest.commit_forbidden"
	KeyRefInvalid     = "validation.ingest.ref"
	KeyVersionInvalid = "validation.ingest.agent_version"
	KeyScannedAt      = "validation.ingest.scanned_at"
)

// ErrorKeys liste les clés d'erreur du paquet (tests de traduction).
func ErrorKeys() []string {
	return []string{KeyRefUnknown, KeyMissingPart, KeyQuota}
}

// ValidationKeys liste les clés de saisie du paquet (tests de traduction).
func ValidationKeys() []string {
	return []string{KeyCommitInvalid, KeyCommitRequired, KeyCommitForbid, KeyRefInvalid, KeyVersionInvalid, KeyScannedAt}
}

var (
	// ErrRefUnknown : la référence n'existe pas, n'est pas active ou son projet n'est pas
	// confié à l'agent. L'API répond 404 sans distinguer les cas.
	ErrRefUnknown = errors.New("ingest: référence inconnue pour cet agent")
	// ErrUploadTooLarge : l'envoi dépasse la taille reçue admise (413, sans ingestion).
	ErrUploadTooLarge = errors.New("ingest: envoi trop volumineux")
	// ErrNotFound : ingestion introuvable pour cet agent.
	ErrNotFound = errors.New("ingest: ingestion introuvable")
	// ErrQuota : la référence a reçu trop d'envois sur 24 h, ou l'organisation a atteint
	// son volume de SBOM stockés (429, rien n'est stocké).
	ErrQuota = errors.New("ingest: quota atteint")
)

// Status est l'état d'une ingestion.
type Status string

// États d'une ingestion.
const (
	StatusQueued     Status = "queued"
	StatusProcessing Status = "processing"
	StatusDone       Status = "done"
	StatusFailed     Status = "failed"
)

// Statuses liste les états dans l'ordre d'affichage.
func Statuses() []Status { return []Status{StatusQueued, StatusProcessing, StatusDone, StatusFailed} }

// Limits sont les bornes de l'ingestion.
type Limits struct {
	// MaxUpload borne l'envoi tel que reçu (compressé ou non).
	MaxUpload int64
	// SBOM borne le document décompressé (taille, profondeur, composants).
	SBOM sbom.Limits
	// MaxPerRefPerDay borne les envois stockés par référence sur 24 glissantes (0 : sans).
	// Un doublon (même commit, même document) n'est pas compté.
	MaxPerRefPerDay int
	// MaxOrgStorage borne le volume compressé des SBOM stockés d'une organisation, en
	// octets (0 : sans). Un agent compromis ne remplit ainsi que la part de son
	// organisation, pas le disque de toute l'instance (SEC-05).
	MaxOrgStorage int64
}

// Options réunit les dépendances du service.
type Options struct {
	Pool      *db.Pool
	Validator *schema.Validator
	Limits    Limits
	Logger    *slog.Logger
	// Now date les ingestions (horloge du système par défaut).
	Now func() time.Time
}

// Service reçoit et décode les SBOM.
type Service struct {
	pool      *db.Pool
	validator *schema.Validator
	limits    Limits
	logger    *slog.Logger
	now       func() time.Time
}

// NewService construit le service.
func NewService(o Options) (*Service, error) {
	if o.Pool == nil || o.Validator == nil || o.Logger == nil {
		return nil, errors.New("ingest: dépendances incomplètes")
	}
	l := o.Limits
	if l.MaxUpload <= 0 || l.SBOM.MaxBytes < l.MaxUpload || l.SBOM.MaxDepth <= 0 || l.SBOM.MaxComponents <= 0 ||
		l.MaxPerRefPerDay < 0 || l.MaxOrgStorage < 0 {
		return nil, fmt.Errorf("ingest: bornes invalides %+v", l)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{pool: o.Pool, validator: o.Validator, limits: l, logger: o.Logger, now: o.Now}, nil
}

// Limits renvoie les bornes du service (l'API en déduit celle du corps multipart).
func (s *Service) Limits() Limits { return s.limits }

// Validator renvoie le validateur des schémas (réencodage des téléchargements).
func (s *Service) Validator() *schema.Validator { return s.validator }

// Context est le contexte d'un envoi, tel que le décrit l'agent.
type Context struct {
	ProjectID uuid.UUID
	RefKind   project.RefKind
	RefName   string
	// Commit (SHA-1 ou SHA-256 en hexadécimal minuscule) est exigé pour une branche ou
	// une étiquette, interdit pour un hôte, un conteneur ou une version (point compatible
	// Dependency-Track).
	Commit       string
	AgentVersion string
	ScannedAt    time.Time
}

// machine dit si l'envoi vise un hôte ou un conteneur (sans commit).
func (c Context) machine() bool {
	return c.RefKind == project.RefHost || c.RefKind == project.RefContainer || c.RefKind == project.RefVersion
}

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// maxClockSkew borne l'avance d'une date de scan sur l'horloge du serveur.
const maxClockSkew = time.Hour

func invalid(field, key string) error { return &account.ValidationError{Field: field, Key: key} }

func (s *Service) validate(c *Context) error {
	c.Commit = strings.ToLower(strings.TrimSpace(c.Commit))
	switch {
	case c.ProjectID == uuid.Nil || c.RefName == "" || len(c.RefName) > 255:
		return invalid("ref", KeyRefInvalid)
	case c.RefKind != project.RefBranch && c.RefKind != project.RefTag && c.RefKind != project.RefHost &&
		c.RefKind != project.RefContainer && c.RefKind != project.RefVersion:
		return invalid("ref", KeyRefInvalid)
	case c.machine() && c.Commit != "":
		return invalid("commit", KeyCommitForbid)
	case !c.machine() && c.Commit == "":
		return invalid("commit", KeyCommitRequired)
	case c.Commit != "" && !commitPattern.MatchString(c.Commit):
		return invalid("commit", KeyCommitInvalid)
	case len(c.AgentVersion) > 64 || strings.ContainsFunc(c.AgentVersion, func(r rune) bool { return !unicode.IsPrint(r) || unicode.IsSpace(r) }):
		return invalid("agent_version", KeyVersionInvalid)
	case c.ScannedAt.IsZero() || c.ScannedAt.After(s.now().Add(maxClockSkew)) || c.ScannedAt.Year() < 2000:
		return invalid("scanned_at", KeyScannedAt)
	}
	c.ScannedAt = c.ScannedAt.UTC()
	return nil
}

// Authorize vérifie le contexte et que la référence est confiée à l'agent, avant toute
// lecture du SBOM : un envoi refusé n'est pas lu.
func (s *Service) Authorize(ctx context.Context, org tenant.OrgID, agentID uuid.UUID, c Context) error {
	if err := s.validate(&c); err != nil {
		return err
	}
	return s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		_, err := refForAgent(ctx, tx, agentID, c)
		return err
	}, db.ReadOnly())
}

func refForAgent(ctx context.Context, tx *db.OrgTx, agentID uuid.UUID, c Context) (project.Ref, error) {
	ref, err := project.RefForAgent(ctx, tx, agentID, c.ProjectID, c.RefKind, c.RefName)
	if errors.Is(err, project.ErrNotFound) {
		return project.Ref{}, ErrRefUnknown
	}
	return ref, err
}

// Ingestion est l'état d'une réception.
type Ingestion struct {
	ID          uuid.UUID
	AgentID     uuid.UUID
	ProjectID   uuid.UUID
	RefID       uuid.UUID
	Commit      string
	Status      Status
	ErrorKey    string
	ErrorDetail string
	Format      sbom.Format
	SpecVersion string
	Components  *int
	Skipped     *int
	SnapshotID  *uuid.UUID
	Outcome     string
	ReceivedAt  time.Time
	FinishedAt  *time.Time
	// Duplicate : envoi identique à une ingestion existante, renvoyée telle quelle.
	Duplicate bool
}

// upload est un SBOM reçu, prêt à stocker.
type upload struct {
	gz     []byte
	sum    [32]byte
	size   int64
	reject *sbom.Error // envoi impossible à stocker : ingestion en échec
}

var gzipMagic = []byte{0x1f, 0x8b}

// read lit l'envoi sous la borne MaxUpload, puis en calcule l'empreinte et la taille du
// JSON. Un envoi gzip est gardé tel quel et décompressé en flux sous la borne du
// document ; un envoi brut est compressé.
func (s *Service) read(r io.Reader) (upload, error) {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, s.limits.MaxUpload+1))
	if err != nil {
		return upload{}, fmt.Errorf("ingest: lecture de l'envoi : %w", err)
	}
	if n > s.limits.MaxUpload {
		return upload{}, ErrUploadTooLarge
	}
	raw := buf.Bytes()
	if len(raw) == 0 {
		return upload{reject: sbom.Reject(sbom.KeyMalformed, "", nil)}, nil
	}
	h := sha256.New()
	if bytes.HasPrefix(raw, gzipMagic) {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return upload{reject: sbom.Reject(sbom.KeyMalformed, "", err)}, nil
		}
		size, err := io.Copy(h, io.LimitReader(zr, s.limits.SBOM.MaxBytes+1))
		switch {
		case err != nil:
			return upload{reject: sbom.Reject(sbom.KeyMalformed, "", err)}, nil
		case size > s.limits.SBOM.MaxBytes:
			return upload{reject: sbom.Reject(sbom.KeyTooLarge, "", nil)}, nil
		case size == 0:
			return upload{reject: sbom.Reject(sbom.KeyMalformed, "", nil)}, nil
		}
		u := upload{gz: raw, size: size}
		h.Sum(u.sum[:0])
		return u, nil
	}
	h.Write(raw)
	var gz bytes.Buffer
	zw, err := gzip.NewWriterLevel(&gz, gzip.BestSpeed)
	if err != nil {
		return upload{}, err
	}
	if _, err := zw.Write(raw); err != nil {
		return upload{}, err
	}
	if err := zw.Close(); err != nil {
		return upload{}, err
	}
	u := upload{gz: gz.Bytes(), size: int64(len(raw))}
	h.Sum(u.sum[:0])
	return u, nil
}

// Receive reçoit un SBOM (voir la documentation du paquet). L'organisation et l'agent
// viennent du jeton, jamais de la requête.
func (s *Service) Receive(ctx context.Context, org tenant.OrgID, agentID uuid.UUID, c Context, r io.Reader) (Ingestion, error) {
	if err := s.validate(&c); err != nil {
		return Ingestion{}, err
	}
	up, err := s.read(r)
	if err != nil {
		return Ingestion{}, err
	}
	var out Ingestion
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		// Revérifiée ici : l'affectation a pu changer pendant la lecture de l'envoi.
		ref, err := refForAgent(ctx, tx, agentID, c)
		if err != nil {
			return err
		}
		if up.reject != nil {
			out, err = s.insert(ctx, tx, agentID, ref.ID, c, uuid.Nil, up.reject)
			return err
		}
		blobID, err := storeBlob(ctx, tx, up)
		if err != nil {
			return err
		}
		if c.Commit != "" {
			dup, found, err := findDuplicate(ctx, tx, ref.ID, c.Commit, blobID)
			if err != nil || found {
				out = dup
				return err
			}
		}
		// Après le stockage du blob : le refus annule la transaction, blob compris.
		if err := s.checkQuota(ctx, tx, ref.ID); err != nil {
			return err
		}
		if out, err = s.insert(ctx, tx, agentID, ref.ID, c, blobID, nil); err != nil {
			return err
		}
		_, err = jobs.Enqueue(ctx, tx, jobs.Job{Kind: DecodeKind, Payload: DecodePayload{IngestionID: out.ID},
			Priority: jobs.PriorityHigh, UniqueKey: "ingestion:" + out.ID.String()})
		return err
	})
	if err != nil {
		return Ingestion{}, wrap("réception", err)
	}
	if out.Status == StatusFailed {
		s.logger.InfoContext(ctx, "ingestion refusée à la réception", "org", org.String(), "ingestion", out.ID.String(), "key", out.ErrorKey)
	}
	return out, nil
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := account.IsValidation(err); ok || errors.Is(err, ErrRefUnknown) || errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrUploadTooLarge) || errors.Is(err, ErrQuota) {
		return err
	}
	return fmt.Errorf("ingest: %s : %w", what, err)
}

// checkQuota refuse un envoi au-delà des quotas : envois stockés de la référence sur
// 24 h, volume stocké de l'organisation (blob de l'envoi compris). Deux envois
// simultanés peuvent dépasser la borne d'un envoi : elle protège le disque, pas un compte
// exact.
func (s *Service) checkQuota(ctx context.Context, tx *db.OrgTx, refID uuid.UUID) error {
	if n := s.limits.MaxPerRefPerDay; n > 0 {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ingestions
			WHERE ref_id = $1 AND blob_id IS NOT NULL AND received_at > $2`, refID, s.now().Add(-24*time.Hour)).Scan(&count); err != nil {
			return err
		}
		if count >= n {
			return ErrQuota
		}
	}
	if max := s.limits.MaxOrgStorage; max > 0 {
		var used int64
		if err := tx.QueryRowContext(ctx, `SELECT coalesce(sum(compressed_size), 0) FROM sbom_blobs`).Scan(&used); err != nil {
			return err
		}
		if used > max {
			return ErrQuota
		}
	}
	return nil
}

// storeBlob stocke le SBOM compressé, ou retrouve celui de même empreinte. Le SBOM
// retrouvé est verrouillé (FOR KEY SHARE) jusqu'à la fin de la transaction, qui le
// référence : la rétention saute les SBOM verrouillés. Supprimé par elle juste avant la
// lecture, il est stocké de nouveau.
func storeBlob(ctx context.Context, tx *db.OrgTx, up upload) (uuid.UUID, error) {
	for range 3 {
		id, err := uuid.NewV7()
		if err != nil {
			return uuid.Nil, err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO sbom_blobs (org_id, id, sha256, size, compressed_size, content) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (org_id, sha256) DO NOTHING`, tx.OrgID(), id, up.sum[:], up.size, len(up.gz), up.gz)
		if err != nil {
			return uuid.Nil, err
		}
		err = tx.QueryRowContext(ctx, `SELECT id FROM sbom_blobs WHERE sha256 = $1 FOR KEY SHARE`, up.sum[:]).Scan(&id)
		if !errors.Is(err, sql.ErrNoRows) {
			return id, err
		}
	}
	return uuid.Nil, errors.New("SBOM introuvable après trois essais")
}

func findDuplicate(ctx context.Context, tx *db.OrgTx, refID uuid.UUID, commit string, blobID uuid.UUID) (Ingestion, bool, error) {
	in, err := scanIngestion(tx.QueryRowContext(ctx, `SELECT `+ingestionColumns+` FROM ingestions
		WHERE ref_id = $1 AND commit_sha = $2 AND blob_id = $3 AND status <> 'failed'
		ORDER BY received_at DESC, id DESC LIMIT 1`, refID, commit, blobID))
	if errors.Is(err, sql.ErrNoRows) {
		return Ingestion{}, false, nil
	}
	if err != nil {
		return Ingestion{}, false, err
	}
	in.Duplicate = true
	return in, true, nil
}

func (s *Service) insert(ctx context.Context, tx *db.OrgTx, agentID, refID uuid.UUID, c Context, blobID uuid.UUID, reject *sbom.Error) (Ingestion, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return Ingestion{}, err
	}
	now := s.now().UTC()
	status, key, detail := StatusQueued, "", ""
	var finished *time.Time
	if reject != nil {
		status, key, detail, finished = StatusFailed, reject.Key, reject.Detail, &now
	}
	return scanIngestion(tx.QueryRowContext(ctx, `
		INSERT INTO ingestions (org_id, id, agent_id, project_id, ref_id, commit_sha, agent_version, scanned_at, blob_id,
		                        status, error_key, error_detail, received_at, finished_at)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, $8, $9, $10, NULLIF($11, ''), $12, $13, $14)
		RETURNING `+ingestionColumns,
		tx.OrgID(), id, agentID, c.ProjectID, refID, c.Commit, c.AgentVersion, c.ScannedAt, nullUUID(blobID),
		string(status), key, detail, now, finished))
}

func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

const ingestionColumns = `id, agent_id, project_id, ref_id, coalesce(commit_sha, ''), status, coalesce(error_key, ''), error_detail,
	coalesce(format, ''), coalesce(spec_version, ''), component_count, skipped_count, snapshot_id, coalesce(outcome, ''),
	received_at, finished_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanIngestion(row rowScanner) (Ingestion, error) {
	var in Ingestion
	var status, format string
	var comps, skipped sql.NullInt64
	var snap uuid.NullUUID
	var finished sql.NullTime
	err := row.Scan(&in.ID, &in.AgentID, &in.ProjectID, &in.RefID, &in.Commit, &status, &in.ErrorKey, &in.ErrorDetail,
		&format, &in.SpecVersion, &comps, &skipped, &snap, &in.Outcome, &in.ReceivedAt, &finished)
	if err != nil {
		return Ingestion{}, err
	}
	in.Status, in.Format = Status(status), sbom.Format(format)
	if comps.Valid {
		n := int(comps.Int64)
		in.Components = &n
	}
	if skipped.Valid {
		n := int(skipped.Int64)
		in.Skipped = &n
	}
	if snap.Valid {
		in.SnapshotID = &snap.UUID
	}
	if finished.Valid {
		in.FinishedAt = &finished.Time
	}
	return in, nil
}
