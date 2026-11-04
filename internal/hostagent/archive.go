package hostagent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/offline"
)

// writeArchive écrit l'inventaire dans une archive hors ligne (T23, ADR 0060) du
// répertoire offline.dir, s'il a changé depuis la dernière archive écrite (empreinte
// d'inventaire). L'archive porte le jeton d'agent (identifiant public) et son code ; pour
// un agent qui a tiré son jeton lui-même, l'inscription hors ligne. Écriture atomique :
// le fichier n'apparaît sous son nom qu'une fois complet.
func (a *Agent) writeArchive(ctx context.Context, inv Inventory, projectID uuid.UUID) (string, error) {
	o := a.o.Config.Offline
	if o.Dir == "" {
		return "", nil
	}
	st := a.o.Store.Load()
	fp := hex.EncodeToString(inv.Fingerprint[:])
	if st.ArchiveFingerprint == fp {
		return "", nil
	}
	tok, err := a.o.Store.Token()
	if err != nil {
		return "", err
	}
	if tok == "" {
		return "", ErrNotEnrolled
	}
	pub, agentKey, err := offline.ParseToken("agt", tok)
	if err != nil {
		return "", fmt.Errorf("hostagent: jeton d'agent illisible : %w", err)
	}
	m := offline.Manifest{AgentToken: pub, CreatedAt: a.o.Now().UTC(), Context: offline.Context{ProjectID: projectID,
		Ref: offline.Ref{Kind: "host", Name: a.hostname()}, AgentVersion: a.o.Version, ScannedAt: inv.Started}}
	if h := a.hostContext(inv); h != nil {
		m.Context.Host = &offline.Host{Hostname: deref(h.Hostname), OSID: deref(h.OsId), OSVersion: deref(h.OsVersion),
			OSName: deref(h.OsName), Kernel: deref(h.Kernel), Arch: deref(h.Arch)}
		if h.ScanDurationMs != nil {
			m.Context.Host.ScanDurationMs = int64(*h.ScanDurationMs)
		}
	}
	keys := offline.Keys{Agent: agentKey}
	if st.OfflineEnrollment {
		// Jeton tiré par l'agent : tant que le serveur ne l'a peut-être pas reçu, chaque
		// archive porte l'inscription, signée avec l'empreinte du jeton d'inscription.
		path := resolveSecret(a.o.Config.EnrollmentTokenFile, CredentialEnrollmentToken, DefaultEnrollmentTokenFile)
		enr, err := readSecret(path)
		if err != nil {
			return "", fmt.Errorf("%w (%v)", ErrNotEnrolled, err)
		}
		enrID, enrKey, err := offline.ParseToken("enr", enr)
		if err != nil {
			return "", fmt.Errorf("hostagent: jeton d'inscription illisible : %w", err)
		}
		_, agentHash, _ := offline.ParseToken("agt", tok)
		m.Enrollment = &offline.Enrollment{TokenID: enrID, Hostname: a.o.Config.Hostname, Version: a.o.Version,
			Labels: a.o.Config.Labels, AgentHash: hex.EncodeToString(agentHash[:])}
		keys.Enrollment = &enrKey
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(inv.SBOM); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := offline.Write(&buf, m, keys, gz.Bytes()); err != nil {
		return "", fmt.Errorf("hostagent: archive : %w", err)
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return "", fmt.Errorf("hostagent: offline.dir : %w", err)
	}
	path := filepath.Join(o.Dir, offline.FileName(a.hostname(), m.CreatedAt, fp))
	if err := writeSecret(path, buf.Bytes()); err != nil {
		return "", err
	}
	st = a.o.Store.Load()
	st.ArchiveFingerprint, st.LastArchive = fp, m.CreatedAt
	if err := a.o.Store.Save(st); err != nil {
		return path, err
	}
	a.o.Logger.InfoContext(ctx, "archive hors ligne écrite", "file", path, "components", inv.Components, "bytes", buf.Len())
	return path, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// offlineToken renvoie le jeton d'agent de la sortie seule hors ligne : celui du
// répertoire d'état, sinon un jeton tiré ici et gardé, l'inscription partant alors dans
// chaque archive (le serveur l'inscrit à l'import de la première).
func (a *Agent) offlineToken() error {
	tok, err := a.o.Store.Token()
	if err != nil || tok != "" {
		return err
	}
	path := resolveSecret(a.o.Config.EnrollmentTokenFile, CredentialEnrollmentToken, DefaultEnrollmentTokenFile)
	if _, err := readSecret(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w (%v)", ErrNotEnrolled, err)
		}
		return err
	}
	raw, _, _, err := offline.NewAgentToken()
	if err != nil {
		return err
	}
	if err := a.o.Store.SaveToken(raw); err != nil {
		return err
	}
	st := a.o.Store.Load()
	st.OfflineEnrollment = true
	return a.o.Store.Save(st)
}

// offlineCycle est le cycle de la sortie seule hors ligne : scan, puis archive si
// l'inventaire a changé ; ni réseau, ni conteneurs.
func (a *Agent) offlineCycle(ctx context.Context) (Result, error) {
	if err := a.offlineToken(); err != nil {
		return Result{}, err
	}
	scanCtx, cancel := context.WithTimeout(ctx, a.o.Config.Scan.MaxDuration)
	inv, err := a.o.Scanner.Scan(scanCtx)
	cancel()
	if err != nil {
		return Result{}, err
	}
	res := Result{Components: inv.Components, Duration: inv.Duration, Outcome: OutcomeUnchanged}
	path, err := a.writeArchive(ctx, inv, a.o.Store.Load().ProjectID)
	if err != nil {
		return res, err
	}
	if path != "" {
		res.Outcome, res.Archive = OutcomeArchived, path
	}
	st := a.o.Store.Load()
	st.LastScan = inv.Started
	return res, a.o.Store.Save(st)
}

// alsoArchive complète un cycle réussi vers lotor par l'archive hors ligne : son échec est
// journalisé sans faire échouer le cycle.
func (a *Agent) alsoArchive(ctx context.Context, inv Inventory, res *Result) {
	path, err := a.writeArchive(ctx, inv, a.o.Store.Load().ProjectID)
	if err != nil && ctx.Err() == nil {
		a.o.Logger.ErrorContext(ctx, "archive hors ligne en échec", "err", err.Error())
	}
	res.Archive = path
}
