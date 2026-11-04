package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/pagination"
)

// maxFormBytes borne le corps d'un formulaire de l'interface.
const maxFormBytes = 64 << 10

// limitBody borne le corps des requêtes de l'interface, avant que CSRF ne le lise, sauf
// celui des requêtes que defer désigne : un middleware placé avant CSRF le borne alors
// lui-même (uploadGate).
func limitBody(deferred func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if deferred == nil || !deferred(r) {
				r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// flashes associe le paramètre ?done= d'une redirection à son message : seules ces
// valeurs sont affichées, jamais un texte reçu.
var flashes = map[string]string{
	"settings_saved":   "flash.settings_saved",
	"scan_requested":   "flash.scan_requested",
	"password_changed": "flash.password_changed",
	"member_added":     "flash.member_added",
	"member_updated":   "flash.member_updated",
	"member_removed":   "flash.member_removed",
	"org_saved":        "flash.org_saved",
	"org_created":      "flash.org_created",
	"org_archived":     "flash.org_archived",
	"org_unarchived":   "flash.org_unarchived",
	"account_updated":  "flash.account_updated",

	"member_invited":       "flash.member_invited",
	"invitation_revoked":   "flash.invitation_revoked",
	"invitation_mailed":    "flash.invitation_mailed",
	"invitation_accepted":  "flash.invitation_accepted",
	"invitation_declined":  "flash.invitation_declined",
	"team_created":         "flash.team_created",
	"team_renamed":         "flash.team_renamed",
	"team_deleted":         "flash.team_deleted",
	"team_member_added":    "flash.team_member_added",
	"team_member_updated":  "flash.team_member_updated",
	"team_member_removed":  "flash.team_member_removed",
	"project_team_changed": "flash.project_team_changed",

	"project_created":     "flash.project_created",
	"project_saved":       "flash.project_saved",
	"project_archived":    "flash.project_archived",
	"project_unarchived":  "flash.project_unarchived",
	"project_agent_saved": "flash.project_agent_saved",
	"token_revoked":       "flash.token_revoked",
	"dt_auto_create_on":   "flash.dt_auto_create_on",
	"dt_auto_create_off":  "flash.dt_auto_create_off",
	"agent_disabled":      "flash.agent_disabled",
	"enrollment_revoked":  "flash.enrollment_revoked",

	"personal_token_revoked": "flash.personal_token_revoked",
	doneRecoverySignIn:       "flash.recovery_signin",

	"job_retried":          "flash.job_retried",
	"job_discarded":        "flash.job_discarded",
	"vulndb_import_queued": "flash.vulndb_import_queued",
	"vulndb_purged":        "flash.vulndb_purged",
	"signup_code_revoked":  "flash.signup_code_revoked",

	"triage_saved":     "flash.triage_saved",
	"triage_withdrawn": "flash.triage_withdrawn",
	"vex_empty":        "flash.vex_empty",

	"policy_saved":    "flash.policy_saved",
	"policy_deleted":  "flash.policy_deleted",
	"channel_saved":   "flash.channel_saved",
	"channel_deleted": "flash.channel_deleted",
}

func flashKey(r *http.Request) string { return flashes[r.URL.Query().Get("done")] }

func redirectDone(w http.ResponseWriter, r *http.Request, path, done string) {
	http.Redirect(w, r, path+"?done="+url.QueryEscape(done), http.StatusSeeOther)
}

// formError est l'erreur d'un formulaire : clé de traduction et champ en cause.
type formError struct {
	Key   string
	Field string
}

// validationOf renvoie l'erreur de saisie de err, si c'en est une.
func validationOf(err error) (formError, bool) {
	if v, ok := account.IsValidation(err); ok {
		return formError{Key: v.Key, Field: v.Field}, true
	}
	var lim *pagination.LimitError
	if errors.Is(err, pagination.ErrInvalidCursor) || errors.As(err, &lim) {
		return formError{Key: "error.invalid_cursor.title", Field: "cursor"}, true
	}
	return formError{}, false
}

// parseForm lit le formulaire ; un corps illisible ou trop gros donne une page 400.
func (id *identity) parseForm(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		id.rd.Error(w, r, http.StatusBadRequest)
		return false
	}
	return true
}

func pathInt(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n > 0
}
