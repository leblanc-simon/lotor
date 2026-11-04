package agentclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DTOptions règle un client de Dependency-Track (T19, ADR 0057) : la sortie
// supplémentaire des agents, vers un Dependency-Track ou vers le point compatible d'un
// serveur lotor (adresse de base https://<serveur>/dt).
type DTOptions struct {
	// URL est l'adresse de base de Dependency-Track (https://dtrack.example.org), sans
	// /api.
	URL string
	// APIKey est la clé d'API (permission BOM_UPLOAD, et PROJECT_CREATION_UPLOAD pour
	// autoCreate) ; jamais journalisée.
	APIKey    string
	UserAgent string
	TLS       TLSOptions
	Proxy     string
	Timeout   time.Duration
	Retry     Retry
	Logger    *slog.Logger
	// Transport remplace le transport construit depuis TLS et Proxy (tests).
	Transport http.RoundTripper
}

// DTClient envoie des SBOM CycloneDX à Dependency-Track par PUT /api/v1/bom (SBOM en
// base64 dans un corps JSON), et suit leur traitement par GET /api/v1/event/token/{uuid}.
// Mêmes transport, réessais et bornes de réponse que le client de l'API des agents ;
// aucune redirection suivie : la clé ne part jamais ailleurs que vers URL.
type DTClient struct {
	opts DTOptions
	base string
	doer *retryDoer
}

// NewDT construit un client de Dependency-Track.
func NewDT(opts DTOptions) (*DTClient, error) {
	u, err := url.Parse(strings.TrimSpace(opts.URL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || opts.Transport == nil)) {
		return nil, fmt.Errorf("agentclient: adresse de Dependency-Track invalide (https://hôte attendu) : %q", opts.URL)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("agentclient: l'adresse de Dependency-Track ne prend ni requête, ni fragment, ni identifiants")
	}
	if strings.TrimSpace(opts.APIKey) == "" {
		return nil, errors.New("agentclient: clé d'API de Dependency-Track absente")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	opts.Retry = opts.Retry.withDefaults()
	transport := opts.Transport
	if transport == nil {
		if transport, err = newTransport(opts.TLS, opts.Proxy); err != nil {
			return nil, err
		}
	}
	return &DTClient{opts: opts, base: strings.TrimSuffix(u.String(), "/") + "/api/v1",
		doer: &retryDoer{client: &http.Client{Transport: transport, Timeout: opts.Timeout, CheckRedirect: noRedirect},
			retry: opts.Retry, logger: opts.Logger, sleep: sleepContext}}, nil
}

// DTTarget désigne le projet et la version de Dependency-Track qui reçoivent un SBOM.
type DTTarget struct {
	ProjectName    string
	ProjectVersion string
	// AutoCreate crée le projet ou la version s'ils n'existent pas (permission
	// PROJECT_CREATION_UPLOAD côté Dependency-Track).
	AutoCreate bool
}

// DTUpload est la réponse d'un envoi : le jeton de suivi et, depuis Dependency-Track 5,
// l'identifiant du projet (absent en 4.x).
type DTUpload struct {
	Token       uuid.UUID `json:"token"`
	ProjectUUID uuid.UUID `json:"projectUuid"`
}

// Upload envoie un SBOM CycloneDX (JSON) à Dependency-Track.
func (c *DTClient) Upload(ctx context.Context, t DTTarget, cyclonedx []byte) (DTUpload, error) {
	const op = "dependency-track:upload"
	if t.ProjectName == "" || t.ProjectVersion == "" {
		return DTUpload{}, errors.New("agentclient: projet et version Dependency-Track requis")
	}
	body, err := json.Marshal(map[string]any{
		"projectName": t.ProjectName, "projectVersion": t.ProjectVersion, "autoCreate": t.AutoCreate,
		"bom": base64.StdEncoding.EncodeToString(cyclonedx),
	})
	if err != nil {
		return DTUpload{}, err
	}
	var out DTUpload
	if err := c.do(withOp(ctx, op), op, http.MethodPut, c.base+"/bom", body, &out); err != nil {
		return DTUpload{}, err
	}
	if out.Token == uuid.Nil {
		return DTUpload{}, fmt.Errorf("agentclient: %s : réponse sans jeton", op)
	}
	return out, nil
}

// DTStatus est l'état d'un envoi. Status (PENDING, RUNNING, COMPLETED, FAILED) n'existe
// que depuis Dependency-Track 5 ; vide pour un jeton inconnu ou un Dependency-Track 4.
type DTStatus struct {
	Processing bool
	Status     string
}

// DTFailed est l'état d'un envoi que Dependency-Track n'a pas pu traiter.
const DTFailed = "FAILED"

// ErrDTFailed : Dependency-Track annonce l'échec du traitement de l'envoi.
var ErrDTFailed = errors.New("agentclient: traitement de l'envoi en échec chez Dependency-Track")

// Processing renvoie l'état de l'envoi de jeton token. Comme Dependency-Track le
// documente, « processing: false » ne garantit pas que le jeton soit connu.
func (c *DTClient) Processing(ctx context.Context, token uuid.UUID) (DTStatus, error) {
	const op = "dependency-track:token"
	var out struct {
		Processing *bool   `json:"processing"`
		Status     *string `json:"status"`
	}
	if err := c.do(withOp(ctx, op), op, http.MethodGet, c.base+"/event/token/"+token.String(), nil, &out); err != nil {
		return DTStatus{}, err
	}
	if out.Processing == nil {
		return DTStatus{}, fmt.Errorf("agentclient: %s : réponse sans état", op)
	}
	st := DTStatus{Processing: *out.Processing}
	if out.Status != nil {
		st.Status = *out.Status
	}
	return st, nil
}

// Wait attend la fin du traitement d'un envoi, en interrogeant à intervalle croissant
// (poll, doublé jusqu'à une minute), jusqu'à l'échéance de ctx ; ErrDTFailed si
// Dependency-Track annonce un échec.
func (c *DTClient) Wait(ctx context.Context, token uuid.UUID, poll time.Duration) error {
	if poll <= 0 {
		poll = 2 * time.Second
	}
	for {
		st, err := c.Processing(ctx, token)
		if err != nil {
			return err
		}
		if !st.Processing {
			if st.Status == DTFailed {
				return ErrDTFailed
			}
			return nil
		}
		if err := sleepContext(ctx, poll); err != nil {
			return err
		}
		poll = min(2*poll, time.Minute)
	}
}

func (c *DTClient) do(ctx context.Context, op, method, target string, body []byte, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Api-Key", c.opts.APIKey)
	if c.opts.UserAgent != "" {
		req.Header.Set("User-Agent", c.opts.UserAgent)
	}
	rsp, err := c.doer.Do(req)
	if err != nil {
		return wrapTransport(op, err)
	}
	defer rsp.Body.Close()
	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return wrapTransport(op, err)
	}
	if rsp.StatusCode/100 != 2 {
		return responseError(op, rsp, data)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("agentclient: %s : réponse illisible : %w", op, err)
	}
	return nil
}
