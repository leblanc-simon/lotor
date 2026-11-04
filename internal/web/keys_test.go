package web

import (
	"slices"
	"strconv"
	"testing"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/agent"
	apiv1 "leblanc.io/lotor/internal/api"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/dashboard"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/policy"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/locales"
)

// TestDynamicKeysExist couvre les clés que les gabarits composent à l'exécution : actions
// du journal, rôles, messages flash, erreurs de saisie.
func TestDynamicKeysExist(t *testing.T) {
	keys, err := locales.Keys()
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, a := range audit.Actions() {
		want = append(want, a.Key())
	}
	for _, r := range tenant.Roles() {
		want = append(want, "role."+string(r))
	}
	for _, r := range tenant.TeamRoles() {
		want = append(want, "team_role."+string(r))
	}
	for _, k := range flashes {
		want = append(want, k)
	}
	for _, l := range account.Languages {
		want = append(want, "language."+l)
	}
	want = append(want,
		account.KeyEmailInvalid, account.KeyPasswordTooShort, account.KeyPasswordTooLong, account.KeyPasswordIsEmail,
		account.KeyPasswordUnchanged, account.KeyPasswordMismatch, account.KeyPasswordWrong, account.KeyLanguageInvalid,
		account.KeyThemeInvalid, account.KeyDefaultOrgInvalid, account.KeyEmailTaken, account.KeyLastAdmin,
		account.KeyCannotTargetSelf, account.KeyRescueTicketTooShort,
		"login.error.invalid_credentials", "login.error.attempts_exhausted", "verify.error.invalid_code",
		"totp_setup.error.invalid_code", "error.csrf.title", "error.csrf.text")
	want = append(want, org.ValidationKeys()...)
	want = append(want, project.ValidationKeys()...)
	want = append(want, agent.ValidationKeys()...)
	for _, k := range agent.ErrorKeys() {
		want = append(want, k+".title", k+".text")
	}
	// Point compatible Dependency-Track (T19).
	want = append(want, agent.DTValidationKeys()...)
	want = append(want, apiv1.KeyDTBase64)
	for _, k := range agent.DTErrorKeys() {
		want = append(want, k+".title", k+".text")
	}
	want = append(want, ingest.ValidationKeys()...)
	for _, k := range append(sbom.ErrorKeys(), ingest.ErrorKeys()...) {
		want = append(want, k+".title", k+".text")
	}
	for _, s := range ingest.Statuses() {
		want = append(want, "ingestion_status."+string(s))
	}
	for _, o := range []inventory.Outcome{inventory.OutcomeCreated, inventory.OutcomeReplaced, inventory.OutcomeUnchanged} {
		want = append(want, "ingestion_outcome."+string(o))
	}
	for _, o := range sbom.Origins() {
		want = append(want, "origin."+string(o))
	}
	for _, s := range []sbom.Scope{sbom.ScopeRequired, sbom.ScopeOptional, sbom.ScopeExcluded} {
		want = append(want, "scope."+string(s))
	}
	for _, f := range []sbom.Format{sbom.FormatCycloneDX, sbom.FormatSPDX, sbom.FormatSyft} {
		want = append(want, "format.sbom_"+string(f))
	}
	for _, k := range []project.RefKind{project.RefBranch, project.RefTag, project.RefHost, project.RefContainer, project.RefVersion} {
		want = append(want, "ref_kind."+string(k))
	}
	for _, k := range append(project.Kinds(), project.KindContainer) {
		want = append(want, "project_type."+string(k))
	}
	for _, e := range []string{project.EngineDocker, project.EnginePodman} {
		want = append(want, "container_engine."+e)
	}
	for _, k := range agent.Kinds() {
		want = append(want, "agent_type."+string(k))
	}
	for _, k := range append(project.Kinds(), project.KindContainer) {
		want = append(want, "dashboard.kind_"+string(k))
	}
	for _, p := range dashboard.Periods() {
		want = append(want, "dashboard.period_"+strconv.Itoa(int(p)))
	}
	for _, s := range []agent.State{agent.StateActive, agent.StatePending, agent.StateDisabled} {
		want = append(want, "agent_state."+string(s))
	}
	for _, d := range agent.TokenLifetimes {
		want = append(want, "agents.expiry_"+strconv.Itoa(d))
	}
	for _, h := range agent.EnrollmentLifetimes {
		want = append(want, "enrollment.expiry_"+strconv.Itoa(h))
	}
	want = append(want, apiv1.KeyClientCertRequired+".title", apiv1.KeyClientCertRequired+".text")
	// Politiques et notifications (T15).
	want = append(want, policy.KeyExprRequired, policy.KeyExprTooLong, policy.KeyExprSyntax, policy.KeyExprUnknownField,
		policy.KeyExprUnknownName, policy.KeyExprType, policy.KeyExprInvalid, policy.KeyExprNotBool, policy.KeyExprTooCostly,
		policy.KeyNameInvalid, policy.KeyNameTaken, policy.KeyDescriptionTooLong, policy.KeySubjectInvalid,
		policy.KeyDeliveryInvalid, policy.KeyChannelsInvalid, policy.KeyTooMany, policy.KeyTemplateInvalid,
		notify.KeyNameInvalid, notify.KeyNameTaken, notify.KeyKindInvalid, notify.KeyRecipientsInvalid, notify.KeyURLInvalid,
		notify.KeyRoomInvalid, notify.KeySecretRequired, notify.KeySecretInvalid, notify.KeyTooMany,
		notify.KeySendFailed, notify.KeySendUnreachable, notify.KeySendForbidden, notify.KeySendStatus, notify.KeySendSMTP,
		notify.KeySendUnconfigured, notify.KeySendSecret, "verdict.pending", "verdict.pass", "verdict.pass_warnings", "verdict.fail")
	for _, s := range policy.Subjects() {
		want = append(want, "policy_subject."+string(s), "policy_subject."+string(s)+"_desc", "policy_form.preview_"+string(s))
	}
	for _, d := range policy.Deliveries() {
		want = append(want, "policy_delivery."+string(d))
	}
	for _, tpl := range policy.Templates() {
		want = append(want, "policy_template."+tpl.Key+".name", "policy_template."+tpl.Key+".text")
	}
	for _, k := range notify.Kinds() {
		want = append(want, "channel_kind."+string(k), "channel_kind."+string(k)+"_desc")
	}
	for _, s := range policy.Subjects() {
		for _, v := range policy.Variables(s) {
			want = append(want, "policy_help."+v.Name)
		}
	}
	for _, st := range hostAgentInstall("https://sbom.example.org", "t") {
		want = append(want, st.TitleKey)
		if st.HintKey != "" {
			want = append(want, st.HintKey)
		}
	}
	for _, k := range want {
		if !slices.Contains(keys, k) {
			t.Errorf("clé %s absente des traductions", k)
		}
	}
}

func TestGroupBy4(t *testing.T) {
	if got := groupBy4("ABCDEFGHIJ"); got != "ABCD EFGH IJ" {
		t.Fatal(got)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/o/a": "/o/a", "//evil": "", "/login?x": "", "https://x": ""} {
		if got := safeNext(in); got != want {
			t.Errorf("%q : %q", in, got)
		}
	}
}
