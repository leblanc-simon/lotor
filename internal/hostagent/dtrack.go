package hostagent

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	sbomsyft "leblanc.io/lotor/internal/sbom/syft"
)

// DTSender envoie le SBOM de l'hôte à Dependency-Track (agentclient.DTClient).
type DTSender interface {
	Upload(ctx context.Context, t agentclient.DTTarget, cyclonedx []byte) (agentclient.DTUpload, error)
	Wait(ctx context.Context, token uuid.UUID, poll time.Duration) error
}

// dtClient adapte agentclient.DTClient à DTSender.
type dtClient struct{ c *agentclient.DTClient }

func (d dtClient) Upload(ctx context.Context, t agentclient.DTTarget, cdx []byte) (agentclient.DTUpload, error) {
	return d.c.Upload(ctx, t, cdx)
}

func (d dtClient) Wait(ctx context.Context, token uuid.UUID, poll time.Duration) error {
	return d.c.Wait(ctx, token, poll)
}

// DTSenderOf enveloppe un client de Dependency-Track ; nil pour une sortie désactivée.
func DTSenderOf(c *agentclient.DTClient) DTSender {
	if c == nil {
		return nil
	}
	return dtClient{c}
}

// cdxLicenses est la liste des licences admises par le schéma de CycloneDX 1.6, lue une
// fois : Dependency-Track valide le document reçu.
var cdxLicenses = sync.OnceValues(func() (map[string]bool, error) {
	v, err := schema.New()
	if err != nil {
		return nil, err
	}
	return v.CycloneDXLicenseIDs("1.6"), nil
})

// toCycloneDX réencode le SBOM de l'hôte (Syft JSON) en CycloneDX 1.6, seul format
// qu'accepte Dependency-Track, par l'adaptateur du serveur (licences hors schéma écrites
// en nom).
func toCycloneDX(syftJSON []byte) ([]byte, error) {
	ids, err := cdxLicenses()
	if err != nil {
		return nil, fmt.Errorf("hostagent: schémas CycloneDX : %w", err)
	}
	var buf bytes.Buffer
	if err := sbomsyft.Encode(&buf, sbom.FormatSyft, syftJSON, sbomsyft.TargetCycloneDX16, ids); err != nil {
		return nil, fmt.Errorf("hostagent: SBOM CycloneDX pour Dependency-Track : %w", err)
	}
	return buf.Bytes(), nil
}

// dtTarget renvoie le projet et la version de Dependency-Track de l'hôte.
func (a *Agent) dtTarget() agentclient.DTTarget {
	d := a.o.Config.DependencyTrack
	name := d.ProjectName
	if name == "" {
		name = a.hostname()
	}
	return agentclient.DTTarget{ProjectName: name, ProjectVersion: d.ProjectVersion, AutoCreate: d.AutoCreate}
}

// forwardDT envoie l'inventaire à Dependency-Track s'il a changé depuis le dernier envoi
// accepté (empreinte d'inventaire, comme pour le serveur lotor), puis attend la fin de son
// traitement. L'empreinte n'est retenue qu'après : un envoi refusé ou perdu est refait au
// cycle suivant.
func (a *Agent) forwardDT(ctx context.Context, inv Inventory) (bool, error) {
	if a.o.DT == nil {
		return false, nil
	}
	fp := hex.EncodeToString(inv.Fingerprint[:])
	t := a.dtTarget()
	st := a.o.Store.Load()
	if st.DTFingerprint == fp && st.DTTarget == t.ProjectName+"\x00"+t.ProjectVersion {
		return false, nil
	}
	cdx, err := toCycloneDX(inv.SBOM)
	if err != nil {
		return false, err
	}
	up, err := a.o.DT.Upload(ctx, t, cdx)
	if err != nil {
		return false, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, a.o.IngestionWait)
	defer cancel()
	if err := a.o.DT.Wait(waitCtx, up.Token, a.o.IngestionPoll); err != nil {
		return false, fmt.Errorf("hostagent: suivi de l'envoi Dependency-Track %s : %w", up.Token, err)
	}
	st = a.o.Store.Load()
	st.DTFingerprint, st.DTTarget, st.DTLastSent = fp, t.ProjectName+"\x00"+t.ProjectVersion, a.o.Now().UTC()
	if err := a.o.Store.Save(st); err != nil {
		return true, err
	}
	a.o.Logger.InfoContext(ctx, "SBOM envoyé à Dependency-Track", "project", t.ProjectName, "version", t.ProjectVersion,
		"token", up.Token.String(), "components", inv.Components, "bytes", len(cdx))
	return true, nil
}

// alsoDT complète un cycle réussi vers lotor par l'envoi à Dependency-Track : son échec
// est journalisé sans faire échouer le cycle, et l'envoi sera retenté au suivant.
func (a *Agent) alsoDT(ctx context.Context, inv Inventory, res *Result) {
	sent, err := a.forwardDT(ctx, inv)
	if err != nil && ctx.Err() == nil {
		a.o.Logger.ErrorContext(ctx, "envoi à Dependency-Track en échec", "err", err.Error())
	}
	res.DTSent = sent
}

// dtOnlyCycle est le cycle de la sortie seule vers Dependency-Track : scan, puis envoi si
// l'inventaire a changé ; ni inscription, ni signal de vie, ni conteneurs.
func (a *Agent) dtOnlyCycle(ctx context.Context) (Result, error) {
	scanCtx, cancel := context.WithTimeout(ctx, a.o.Config.Scan.MaxDuration)
	inv, err := a.o.Scanner.Scan(scanCtx)
	cancel()
	if err != nil {
		return Result{}, err
	}
	res := Result{Components: inv.Components, Duration: inv.Duration, Outcome: OutcomeUnchanged}
	sent, err := a.forwardDT(ctx, inv)
	if err != nil {
		return res, err
	}
	if sent {
		res.Outcome, res.DTSent = OutcomeSent, true
	}
	st := a.o.Store.Load()
	st.LastScan = inv.Started
	return res, a.o.Store.Save(st)
}
