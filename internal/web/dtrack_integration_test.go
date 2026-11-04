//go:build integration

package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/agentclient"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// dtRequest envoie une requête au point compatible Dependency-Track, clé d'API dans
// X-Api-Key comme les clients de Dependency-Track.
func (a *app) dtRequest(method, path, key, contentType string, body []byte, headers ...string) apiResponse {
	a.t.Helper()
	req, err := http.NewRequest(method, a.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		a.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if key != "" {
		req.Header.Set("X-Api-Key", key)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return apiResponse{status: resp.StatusCode, header: resp.Header, body: string(raw)}
}

// dtPut envoie un SBOM en JSON (PUT /api/v1/bom, SBOM en base64).
func (a *app) dtPut(key string, fields map[string]any, bom []byte) apiResponse {
	a.t.Helper()
	body := map[string]any{"bom": base64.StdEncoding.EncodeToString(bom)}
	for k, v := range fields {
		body[k] = v
	}
	raw, err := json.Marshal(body)
	if err != nil {
		a.t.Fatal(err)
	}
	return a.dtRequest(http.MethodPut, "/dt/api/v1/bom", key, "application/json", raw)
}

// dtPost envoie un SBOM en multipart (POST /api/v1/bom), champs dans l'ordre donné ; le
// champ « bom » est le fichier.
func (a *app) dtPost(key string, fields [][2]string, bom []byte) apiResponse {
	a.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range fields {
		if f[0] == "bom" {
			w, err := mw.CreateFormFile("bom", "bom.json")
			if err != nil {
				a.t.Fatal(err)
			}
			if _, err := w.Write(bom); err != nil {
				a.t.Fatal(err)
			}
			continue
		}
		if err := mw.WriteField(f[0], f[1]); err != nil {
			a.t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		a.t.Fatal(err)
	}
	return a.dtRequest(http.MethodPost, "/dt/api/v1/bom", key, mw.FormDataContentType(), buf.Bytes())
}

type dtUpload struct {
	Token       string `json:"token"`
	ProjectUUID string `json:"projectUuid"`
}

func decodeDT(t *testing.T, r apiResponse) dtUpload {
	t.Helper()
	var u dtUpload
	if r.status != http.StatusOK || json.Unmarshal([]byte(r.body), &u) != nil || u.Token == "" {
		t.Fatalf("envoi : %d %s", r.status, r.body)
	}
	return u
}

func (a *app) dtProcessing(key, token string) bool {
	a.t.Helper()
	r := a.dtRequest(http.MethodGet, "/dt/api/v1/event/token/"+token, key, "", nil)
	var st struct {
		Processing *bool `json:"processing"`
	}
	if r.status != http.StatusOK || json.Unmarshal([]byte(r.body), &st) != nil || st.Processing == nil {
		a.t.Fatalf("suivi : %d %s", r.status, r.body)
	}
	return *st.Processing
}

// teamRepoAgent crée un agent dépôt d'équipe et l'autorise ou non à créer projets et
// versions.
func (a *app) teamRepoAgent(o tenant.OrgID, name string, autoCreate bool) (agent.Agent, string) {
	a.t.Helper()
	ctx := context.Background()
	team := a.defaultTeam(o)
	ag, tok, err := a.agents.CreateRepoAgent(ctx, audit.System, o, &team, name, "ci", 90)
	if err != nil {
		a.t.Fatal(err)
	}
	if autoCreate {
		if err := a.agents.SetDTAutoCreate(ctx, audit.System, o, ag.ID, true); err != nil {
			a.t.Fatal(err)
		}
	}
	return ag, tok.Plaintext
}

// Bout en bout : un envoi JSON avec création automatique crée le projet, sa version et un
// instantané ; le suivi du jeton passe à « terminé » ; le même nom et une autre version
// ajoutent une référence ; l'identifiant renvoyé désigne la version au renvoi suivant.
func TestDTUploadEndToEnd(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", false)
	o := a.org("org-a", admin)
	ag, key := a.teamRepoAgent(o.ID, "ci", true)
	ctx := context.Background()
	data := sbomFile(t, "portail-client.cdx16.json")

	u := decodeDT(t, a.dtPut(key, map[string]any{"projectName": "Portail client", "projectVersion": "1.4.0",
		"autoCreate": true, "projectTags": []map[string]string{{"name": "web"}}, "isLatest": true}, data))
	if !a.dtProcessing(key, u.Token) {
		t.Error("envoi en attente annoncé terminé")
	}
	if err := a.ingest.Decode(ctx, o.ID, uuid.MustParse(u.Token)); err != nil {
		t.Fatal(err)
	}
	if a.dtProcessing(key, u.Token) {
		t.Error("envoi rangé annoncé en cours")
	}
	in, err := a.ingest.Get(ctx, o.ID, ag.ID, uuid.MustParse(u.Token))
	if err != nil || in.SnapshotID == nil || in.Status != "done" || in.RefID.String() != u.ProjectUUID {
		t.Fatalf("ingestion %+v %v", in, err)
	}
	p, err := a.projects.Get(ctx, o.ID, tenant.AllTeams(), "portail-client")
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != project.KindRepo || p.Agent == nil || p.Agent.ID != ag.ID || p.TeamID != a.defaultTeam(o.ID) ||
		len(p.Refs) != 1 || p.Refs[0].Kind != project.RefVersion || p.Refs[0].Name != "1.4.0" {
		t.Fatalf("projet créé %+v", p)
	}
	// Multipart, champs après le SBOM, autre version : nouvelle référence du même projet.
	u2 := decodeDT(t, a.dtPost(key, [][2]string{{"bom", ""}, {"projectName", "Portail client"}, {"projectVersion", "1.5.0"},
		{"autoCreate", "true"}, {"parentName", "ignoré"}}, data))
	if u2.ProjectUUID == u.ProjectUUID {
		t.Error("même référence pour deux versions")
	}
	// Par l'identifiant de la version, sans création automatique.
	u3 := decodeDT(t, a.dtPost(key, [][2]string{{"project", u.ProjectUUID}, {"bom", ""}}, data))
	if u3.ProjectUUID != u.ProjectUUID {
		t.Errorf("identifiant de version : %+v", u3)
	}
	if err := a.ingest.Decode(ctx, o.ID, uuid.MustParse(u3.Token)); err != nil {
		t.Fatal(err)
	}
	if in, err := a.ingest.Get(ctx, o.ID, ag.ID, uuid.MustParse(u3.Token)); err != nil || in.Outcome != "unchanged" {
		t.Errorf("même inventaire pour la même version : %+v %v", in, err)
	}
	p, err = a.projects.Get(ctx, o.ID, tenant.AllTeams(), "portail-client")
	if err != nil || len(p.RefNames(project.RefVersion)) != 2 {
		t.Fatalf("versions %+v %v", p.Refs, err)
	}
	// Les versions ne sont pas confiées à l'analyse de l'agent dépôt.
	if r := a.api(http.MethodGet, "/api/v1/agent/projects", key, nil); r.status != http.StatusOK || strings.Contains(r.body, "1.4.0") {
		t.Errorf("projets de l'agent : %d %s", r.status, r.body)
	}
	// Création et version journalisées au nom du jeton.
	var created, added int
	if err := a.tdb.App.InOrg(ctx, o.ID, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE action = 'project.created' AND details->>'source' = 'dependency-track'),
		       count(*) FILTER (WHERE action = 'project.version_added') FROM audit_events WHERE actor_email LIKE 'lotor_agt_%'`).
			Scan(&created, &added)
	}); err != nil {
		t.Fatal(err)
	}
	if created != 1 || added != 2 {
		t.Errorf("journal : %d créations, %d versions", created, added)
	}
	// La fiche du projet montre les versions et leur identifiant.
	b := a.signIn(admin)
	page := b.get("/o/org-a/projects/portail-client")
	if page.status != http.StatusOK || !strings.Contains(page.body, u.ProjectUUID) || !strings.Contains(page.body, "1.5.0") {
		t.Errorf("fiche : %d", page.status)
	}
	if strings.Contains(a.logs.String(), key) || strings.Contains(a.logs.String(), "bomFormat") {
		t.Error("clé d'API ou contenu de SBOM dans les journaux")
	}
}

// Refus : clé absente, inconnue, révoquée, d'inscription ou d'un agent serveur ; cible
// absente, inconnue sans création automatique, création non autorisée ; autre
// organisation ; bornes ; même contrôle que l'ingestion native (version retirée).
func TestDTUploadRefusals(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	ctx := context.Background()
	o := a.org("org-a", a.user("admin@example.org", false))
	other := a.org("org-b", a.user("b@example.org", false))
	_, key := a.teamRepoAgent(o.ID, "ci", false)
	_, otherKey := a.teamRepoAgent(other.ID, "ci", true)
	data := sbomFile(t, "portail-client.cdx16.json")
	allowedAg, allowed := a.teamRepoAgent(o.ID, "ci-auto", true)
	// Un dépôt de l'autre organisation, au même nom.
	decodeDT(t, a.dtPut(otherKey, map[string]any{"projectName": "Portail", "projectVersion": "1.0", "autoCreate": true}, data))

	revokedAg, revokedTok, err := a.agents.CreateRepoAgent(ctx, audit.System, o.ID, nil, "révoqué", "x", 90)
	if err != nil {
		t.Fatal(err)
	}
	full, err := a.agents.Get(ctx, o.ID, tenant.AllTeams(), revokedAg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.agents.RevokeToken(ctx, audit.System, o.ID, revokedAg.ID, full.Tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	_, enr, err := a.agents.CreateEnrollment(ctx, audit.System, o.ID, a.enrollTeam(o.ID, agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 5}))
	if err != nil {
		t.Fatal(err)
	}
	_, host := a.enroll(enr.Plaintext, "srv-dt")

	target := map[string]any{"projectName": "Portail", "projectVersion": "1.0"}
	auto := map[string]any{"projectName": "Portail", "projectVersion": "1.0", "autoCreate": true}
	cases := []struct {
		name   string
		key    string
		fields map[string]any
		status int
		ptype  string
	}{
		{"sans clé", "", target, 401, agent.KeyTokenInvalid},
		{"clé inconnue", "lotor_agt_aaaaaaaaaaaaaaaaaaaaaaaaaa_" + strings.Repeat("a", 43), target, 401, agent.KeyTokenInvalid},
		{"clé révoquée", revokedTok.Plaintext, target, 401, agent.KeyTokenRevokedErr},
		{"jeton d'inscription", enr.Plaintext, target, 401, agent.KeyTokenInvalid},
		{"agent serveur", host.Token, target, 403, agent.KeyDTAgentKind},
		{"sans cible", key, map[string]any{"projectName": "Portail"}, 400, "error.validation"},
		{"identifiant illisible", key, map[string]any{"project": "x"}, 400, "error.validation"},
		{"version de l'autre organisation", key, map[string]any{"project": decodeDT(t, a.dtPut(otherKey, auto, data)).ProjectUUID}, 404, agent.KeyDTProjectUnknown},
		{"projet inconnu", key, target, 404, agent.KeyDTProjectUnknown},
		{"création non autorisée", key, auto, 403, agent.KeyDTAutoCreate},
		{"version illisible", key, map[string]any{"projectName": "Portail", "projectVersion": "a\x01"}, 400, "error.validation"},
	}
	for _, c := range cases {
		r := a.dtPut(c.key, c.fields, data)
		if r.status != c.status || r.problem(t)["type"] != c.ptype {
			t.Errorf("%s : %d %s", c.name, r.status, r.body)
		}
	}
	// Corps illisibles : JSON cassé, base64 invalide, type de contenu, multipart sans bom.
	if r := a.dtRequest(http.MethodPut, "/dt/api/v1/bom", allowed, "application/json", []byte("{")); r.status != 400 {
		t.Errorf("JSON cassé : %d", r.status)
	}
	if r := a.dtRequest(http.MethodPut, "/dt/api/v1/bom", allowed, "application/json", []byte(`{"projectName":"A","projectVersion":"1","bom":"!!"}`)); r.status != 400 || r.problem(t)["type"] != "error.validation" {
		t.Errorf("base64 : %d %s", r.status, r.body)
	}
	if r := a.dtRequest(http.MethodPut, "/dt/api/v1/bom", allowed, "text/plain", []byte(`{}`)); r.status != 400 {
		t.Errorf("type de contenu : %d", r.status)
	}
	if r := a.dtPost(allowed, [][2]string{{"projectName", "A"}, {"projectVersion", "1"}}, nil); r.status != 400 {
		t.Errorf("multipart sans bom : %d %s", r.status, r.body)
	}
	// Au-delà de la borne d'envoi : 413, sans ingestion.
	big := bytes.Repeat([]byte(" "), 9<<20)
	if r := a.dtPost(allowed, [][2]string{{"projectName", "A"}, {"projectVersion", "1"}, {"autoCreate", "true"}, {"bom", ""}}, big); r.status != http.StatusRequestEntityTooLarge {
		t.Errorf("trop gros : %d %s", r.status, r.body)
	}
	// Une version retirée du projet n'accepte plus d'envoi par son identifiant.
	u := decodeDT(t, a.dtPut(allowed, auto, data))
	p, err := a.projects.Get(ctx, o.ID, tenant.AllTeams(), "portail")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.projects.Update(ctx, audit.System, o.ID, p.Slug, project.Input{Name: p.Name, Labels: p.Labels, Versions: []string{"2.0"}}, false); err != nil {
		t.Fatal(err)
	}
	if r := a.dtPut(allowed, map[string]any{"project": u.ProjectUUID}, data); r.status != 404 {
		t.Errorf("version retirée : %d %s", r.status, r.body)
	}
	// Suivi d'un jeton d'un autre agent : « false », comme Dependency-Track.
	if a.dtProcessing(key, u.Token) {
		t.Error("jeton d'un autre agent annoncé en cours")
	}
	if r := a.dtRequest(http.MethodGet, "/dt/api/v1/bom/token/pas-un-uuid", key, "", nil); r.status != 200 || !strings.Contains(r.body, `"processing":false`) {
		t.Errorf("jeton illisible : %d %s", r.status, r.body)
	}
	// La création automatique est retirée avec l'équipe de l'agent.
	if err := a.agents.SetDTAutoCreate(ctx, audit.System, o.ID, allowedAg.ID, false); err != nil {
		t.Fatal(err)
	}
	if r := a.dtPut(allowed, map[string]any{"projectName": "Neuf", "projectVersion": "1", "autoCreate": true}, data); r.status != 403 {
		t.Errorf("création retirée : %d %s", r.status, r.body)
	}
	if err := a.agents.SetDTAutoCreate(ctx, audit.System, o.ID, revokedAg.ID, true); err == nil {
		t.Error("création automatique accordée à un agent d'organisation")
	}
	// Route inconnue sous /dt : problème 404.
	if r := a.dtRequest(http.MethodGet, "/dt/api/v1/project", key, "", nil); r.status != 404 {
		t.Errorf("route inconnue : %d", r.status)
	}
}

// Requête d'un client Dependency-Track réel : celle de l'action GitHub
// DependencyTrack/gh-upload-sbom (multipart d'undici, SBOM en premier, en-tête X-API-Key),
// reconstituée d'après son code et acceptée telle quelle par un Dependency-Track 5.2.1
// (testdata/dtrack/README.md). Le client ne garde pas de chemin dans l'adresse du
// serveur : un mandataire inverse préfixe /dt, ce que le test reproduit.
func TestDTRecordedClientRequest(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	o := a.org("org-a", a.user("admin@example.org", false))
	ag, key := a.teamRepoAgent(o.ID, "ci", true)
	ctx := context.Background()
	raw, err := os.ReadFile("../../testdata/dtrack/gh-upload-sbom.http")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(bytes.Replace(raw, []byte("$API_KEY"), []byte(key), 1))))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	out, err := http.NewRequest(req.Method, a.srv.URL+"/dt"+req.URL.Path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	out.Header = req.Header.Clone()
	resp, err := http.DefaultClient.Do(out)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	u := decodeDT(t, apiResponse{status: resp.StatusCode, header: resp.Header, body: string(data)})
	if err := a.ingest.Decode(ctx, o.ID, uuid.MustParse(u.Token)); err != nil {
		t.Fatal(err)
	}
	in, err := a.ingest.Get(ctx, o.ID, ag.ID, uuid.MustParse(u.Token))
	if err != nil || in.SnapshotID == nil || in.Components == nil || *in.Components == 0 {
		t.Fatalf("instantané %+v %v", in, err)
	}
	p, err := a.projects.Get(ctx, o.ID, tenant.AllTeams(), "portail-client")
	if err != nil || len(p.RefNames(project.RefVersion)) != 1 || p.RefNames(project.RefVersion)[0] != "2.0.0" {
		t.Fatalf("projet %+v %v", p, err)
	}
	r := a.dtRequest(http.MethodGet, "/dt/api/v1/event/token/"+u.Token, key, "", nil)
	if r.status != 200 || r.body != "{\"processing\":false,\"status\":\"COMPLETED\"}\n" {
		t.Errorf("suivi : %d %q", r.status, r.body)
	}
}

// Un agent dont la sortie Dependency-Track vise le point compatible d'un serveur lotor
// (adresse de base …/dt) : même client que vers un vrai Dependency-Track, suivi jusqu'à
// COMPLETED, échec de l'ingestion vu comme FAILED.
func TestDTAgentClientAgainstServer(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	o := a.org("org-a", a.user("admin@example.org", false))
	_, key := a.teamRepoAgent(o.ID, "ci", true)
	ctx := context.Background()
	c, err := agentclient.NewDT(agentclient.DTOptions{URL: a.srv.URL + "/dt", APIKey: key, Transport: http.DefaultTransport,
		Retry: agentclient.Retry{Attempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	up, err := c.Upload(ctx, agentclient.DTTarget{ProjectName: "srv-01", ProjectVersion: "host", AutoCreate: true}, sbomFile(t, "debian-12.cdx15.json"))
	if err != nil {
		t.Fatal(err)
	}
	if st, err := c.Processing(ctx, up.Token); err != nil || !st.Processing || st.Status != "PENDING" {
		t.Fatalf("en attente : %+v %v", st, err)
	}
	if err := a.ingest.Decode(ctx, o.ID, up.Token); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(ctx, up.Token, time.Millisecond); err != nil {
		t.Fatalf("suivi : %v", err)
	}
	bad, err := c.Upload(ctx, agentclient.DTTarget{ProjectName: "srv-01", ProjectVersion: "host"}, []byte(`<bom/>`))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ingest.Decode(ctx, o.ID, bad.Token); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(ctx, bad.Token, time.Millisecond); !errors.Is(err, agentclient.ErrDTFailed) {
		t.Errorf("SBOM refusé : %v", err)
	}
	// Clé refusée : 401 portant la clé d'erreur de lotor.
	bogus, err := agentclient.NewDT(agentclient.DTOptions{URL: a.srv.URL + "/dt", APIKey: "x", Transport: http.DefaultTransport,
		Retry: agentclient.Retry{Attempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bogus.Upload(ctx, agentclient.DTTarget{ProjectName: "a", ProjectVersion: "1"}, []byte("{}")); !agentclient.IsKey(err, agent.KeyTokenInvalid) {
		t.Errorf("clé refusée : %v", err)
	}
}
