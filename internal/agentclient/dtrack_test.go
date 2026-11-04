package agentclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func dtFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../testdata/dtrack", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Contrat du client : requête de Dependency-Track 5 (PUT /api/v1/bom, champs de
// BomSubmitRequest, SBOM en base64, X-Api-Key), réponses enregistrées sur un
// Dependency-Track 5.2.1 réel, suivi jusqu'à COMPLETED.
func TestDTClientContract(t *testing.T) {
	polls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "odt_cle" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/dt/api/v1/bom":
			var body map[string]any
			if r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			bom, err := base64.StdEncoding.DecodeString(body["bom"].(string))
			if err != nil || string(bom) != `{"bomFormat":"CycloneDX"}` || body["projectName"] != "app" ||
				body["projectVersion"] != "1.0" || body["autoCreate"] != true || len(body) != 4 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write(dtFixture(t, "dt5-upload-response.json"))
		case r.URL.Path == "/dt/api/v1/event/token/01a1a784-dcf6-7332-8fc7-6a2956d352e4":
			polls++
			if polls == 1 {
				_, _ = w.Write(dtFixture(t, "dt5-token-running.json"))
				return
			}
			_, _ = w.Write(dtFixture(t, "dt5-token-completed.json"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c, err := NewDT(DTOptions{URL: srv.URL + "/dt/", APIKey: "odt_cle", Transport: srv.Client().Transport, Retry: Retry{Attempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	up, err := c.Upload(context.Background(), DTTarget{ProjectName: "app", ProjectVersion: "1.0", AutoCreate: true}, []byte(`{"bomFormat":"CycloneDX"}`))
	if err != nil || up.Token.String() != "01a1a784-dcf6-7332-8fc7-6a2956d352e4" || up.ProjectUUID.String() != "48374e73-e7a3-4c17-90a6-aef1464a7187" {
		t.Fatalf("envoi : %+v %v", up, err)
	}
	if err := c.Wait(context.Background(), up.Token, time.Millisecond); err != nil || polls != 2 {
		t.Fatalf("suivi : %v (%d interrogations)", err, polls)
	}
	// Un jeton inconnu : 404 côté serveur de test, erreur portant le statut.
	if _, err := c.Processing(context.Background(), uuid.New()); !HasStatus(err, http.StatusNotFound) {
		t.Errorf("jeton inconnu : %v", err)
	}
}

// Dependency-Track 4 ne renvoie pas de statut ; un échec annoncé par Dependency-Track 5
// (ou par le point compatible de lotor) devient ErrDTFailed ; une clé refusée garde son
// statut ; une redirection n'est pas suivie.
func TestDTClientStatuses(t *testing.T) {
	reply := ""
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch reply {
		case "401":
			w.WriteHeader(http.StatusUnauthorized)
		case "redirect":
			http.Redirect(w, r, "https://ailleurs.example.org/api/v1/bom", http.StatusTemporaryRedirect)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(reply))
		}
	}))
	defer srv.Close()
	c, err := NewDT(DTOptions{URL: srv.URL, APIKey: "k", Transport: srv.Client().Transport, Retry: Retry{Attempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	reply = string(dtFixture(t, "dt4-token-done.json"))
	if err := c.Wait(ctx, uuid.New(), time.Millisecond); err != nil {
		t.Errorf("Dependency-Track 4 : %v", err)
	}
	reply = `{"processing":false,"status":"FAILED"}`
	if err := c.Wait(ctx, uuid.New(), time.Millisecond); !errors.Is(err, ErrDTFailed) {
		t.Errorf("échec annoncé : %v", err)
	}
	reply = `{"status":"RUNNING"}`
	if _, err := c.Processing(ctx, uuid.New()); err == nil {
		t.Error("réponse sans processing acceptée")
	}
	reply = "401"
	if _, err := c.Upload(ctx, DTTarget{ProjectName: "a", ProjectVersion: "1"}, []byte("{}")); !HasStatus(err, http.StatusUnauthorized) {
		t.Errorf("clé refusée : %v", err)
	}
	reply = "redirect"
	if _, err := c.Upload(ctx, DTTarget{ProjectName: "a", ProjectVersion: "1"}, []byte("{}")); !HasStatus(err, http.StatusTemporaryRedirect) {
		t.Errorf("redirection : %v", err)
	}
	if _, err := c.Upload(ctx, DTTarget{ProjectName: "a"}, []byte("{}")); err == nil {
		t.Error("envoi sans version accepté")
	}
	for _, o := range []DTOptions{{URL: "http://dtrack", APIKey: "k"}, {URL: "https://dtrack?x=1", APIKey: "k"}, {URL: "https://dtrack"},
		{URL: "https://u:p@dtrack", APIKey: "k"}} {
		if _, err := NewDT(o); err == nil {
			t.Errorf("options %+v acceptées", o)
		}
	}
}
