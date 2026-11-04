package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// target désigne la ressource dont une route d'organisation tire l'équipe à laquelle
// s'applique sa permission (tenant.Access.Can).
type target int

const (
	targetOrg        target = iota // l'organisation : permission d'organisation
	targetAnyTeam                  // la permission dans au moins une équipe (formulaires de création)
	targetTeam                     // l'équipe {teamID}
	targetProject                  // le projet {project}
	targetAgent                    // l'agent {agentID} (sans équipe : agent d'organisation)
	targetEnrollment               // le jeton d'inscription {tokenID}
)

// orgRoute est une route de /o/{slug} et le droit qu'elle exige : la table des routes
// (orgRoutes) est la seule déclaration des droits de l'interface, et le test
// TestRoutePermissionsFollowMatrix en dérive ses attentes à partir de tenant.Matrix.
type orgRoute struct {
	method  string
	pattern string // relatif à /o/{slug}
	perm    tenant.Permission
	target  target
	handler http.HandlerFunc
}

// orgRoutes renvoie la table des routes de l'organisation. id peut être nul (lecture de la
// table par les tests) : les gestionnaires ne sont alors que des valeurs de méthode.
func orgRoutes(id *identity) []orgRoute {
	const (
		get  = http.MethodGet
		post = http.MethodPost
	)
	return []orgRoute{
		{get, "/", tenant.PermOrgView, targetOrg, id.orgOverview},
		{get, "/search", tenant.PermOrgView, targetOrg, id.search},
		{get, "/search/export", tenant.PermOrgView, targetOrg, id.searchExport},
		{get, "/vulnerabilities/{vulnID}", tenant.PermOrgView, targetOrg, id.vulnerability},
		{get, "/components/{componentID}", tenant.PermOrgView, targetOrg, id.component},
		{get, "/projects", tenant.PermOrgView, targetOrg, id.projects},
		{get, "/agents", tenant.PermOrgView, targetOrg, id.agents},
		{get, "/teams", tenant.PermOrgView, targetOrg, id.teams},

		{get, "/members", tenant.PermMembersView, targetOrg, id.members},
		{post, "/members", tenant.PermMembersManage, targetOrg, id.inviteMember},
		{post, "/members/{userID}/role", tenant.PermMembersManage, targetOrg, id.setMemberRole},
		{get, "/members/{userID}/remove", tenant.PermMembersManage, targetOrg, id.confirmRemoveMember},
		{post, "/members/{userID}/remove", tenant.PermMembersManage, targetOrg, id.removeMember},
		{get, "/invitations/{invitationID}/revoke", tenant.PermMembersManage, targetOrg, id.confirmRevokeInvitation},
		{post, "/invitations/{invitationID}/revoke", tenant.PermMembersManage, targetOrg, id.revokeInvitation},
		{get, "/settings", tenant.PermOrgManage, targetOrg, id.orgSettings},
		{post, "/settings", tenant.PermOrgManage, targetOrg, id.saveOrgSettings},
		{get, "/audit", tenant.PermOrgManage, targetOrg, id.orgAudit},
		{post, "/teams", tenant.PermTeamsManage, targetOrg, id.createTeam},
		{get, "/triage", tenant.PermTriageOrg, targetOrg, id.orgTriage},
		{post, "/triage/import", tenant.PermTriageOrg, targetOrg, id.orgVEXImport},
		{get, "/triage/decisions/{decisionID}/withdraw", tenant.PermTriageOrg, targetOrg, id.confirmWithdrawOrgDecision},
		{post, "/triage/decisions/{decisionID}/withdraw", tenant.PermTriageOrg, targetOrg, id.withdrawOrgDecision},

		{get, "/violations", tenant.PermOrgView, targetOrg, id.violations},
		{get, "/policies", tenant.PermPolicyManage, targetOrg, id.policies},
		{get, "/policies/new", tenant.PermPolicyManage, targetOrg, id.newPolicy},
		{post, "/policies", tenant.PermPolicyManage, targetOrg, id.createPolicy},
		{get, "/policies/{policyID}", tenant.PermPolicyManage, targetOrg, id.policyPage},
		{post, "/policies/{policyID}", tenant.PermPolicyManage, targetOrg, id.updatePolicy},
		{get, "/policies/{policyID}/delete", tenant.PermPolicyManage, targetOrg, id.confirmDeletePolicy},
		{post, "/policies/{policyID}/delete", tenant.PermPolicyManage, targetOrg, id.deletePolicy},
		{get, "/channels", tenant.PermChannelManage, targetOrg, id.channels},
		{get, "/channels/new", tenant.PermChannelManage, targetOrg, id.newChannel},
		{post, "/channels", tenant.PermChannelManage, targetOrg, id.createChannel},
		{get, "/channels/{channelID}", tenant.PermChannelManage, targetOrg, id.channelPage},
		{post, "/channels/{channelID}", tenant.PermChannelManage, targetOrg, id.updateChannel},
		{post, "/channels/{channelID}/test", tenant.PermChannelManage, targetOrg, id.testChannel},
		{get, "/channels/{channelID}/delete", tenant.PermChannelManage, targetOrg, id.confirmDeleteChannel},
		{post, "/channels/{channelID}/delete", tenant.PermChannelManage, targetOrg, id.deleteChannel},

		{get, "/teams/{teamID}", tenant.PermTeamView, targetTeam, id.teamPage},
		{post, "/teams/{teamID}", tenant.PermTeamsManage, targetTeam, id.renameTeam},
		{get, "/teams/{teamID}/delete", tenant.PermTeamsManage, targetTeam, id.confirmDeleteTeam},
		{post, "/teams/{teamID}/delete", tenant.PermTeamsManage, targetTeam, id.deleteTeam},
		{post, "/teams/{teamID}/members", tenant.PermTeamMembers, targetTeam, id.addTeamMember},
		{post, "/teams/{teamID}/members/{userID}/role", tenant.PermTeamMembers, targetTeam, id.setTeamMemberRole},
		{get, "/teams/{teamID}/members/{userID}/remove", tenant.PermTeamMembers, targetTeam, id.confirmRemoveTeamMember},
		{post, "/teams/{teamID}/members/{userID}/remove", tenant.PermTeamMembers, targetTeam, id.removeTeamMember},

		{get, "/projects/new", tenant.PermProjectCreate, targetAnyTeam, id.newProject},
		{post, "/projects", tenant.PermProjectCreate, targetAnyTeam, id.createProject},
		{get, "/projects/{project}", tenant.PermProjectView, targetProject, id.projectPage},
		{get, "/projects/{project}/findings", tenant.PermProjectView, targetProject, id.findings},
		{get, "/projects/{project}/findings/{findingID}", tenant.PermProjectView, targetProject, id.findingPage},
		{post, "/projects/{project}/findings/{findingID}/triage", tenant.PermFindingTriage, targetProject, id.triageFinding},
		{get, "/projects/{project}/decisions/{decisionID}/withdraw", tenant.PermFindingTriage, targetProject, id.confirmWithdrawProjectDecision},
		{post, "/projects/{project}/decisions/{decisionID}/withdraw", tenant.PermFindingTriage, targetProject, id.withdrawProjectDecision},
		{get, "/projects/{project}/vex", tenant.PermProjectView, targetProject, id.vexPage},
		{get, "/projects/{project}/vex/export", tenant.PermProjectView, targetProject, id.vexExport},
		{post, "/projects/{project}/vex/import", tenant.PermFindingTriage, targetProject, id.vexImport},
		{get, "/projects/{project}/snapshots", tenant.PermProjectView, targetProject, id.snapshots},
		{get, "/projects/{project}/snapshots/{snapshotID}", tenant.PermProjectView, targetProject, id.snapshotPage},
		{get, "/projects/{project}/snapshots/{snapshotID}/sbom", tenant.PermProjectView, targetProject, id.downloadSBOM},
		{get, "/projects/{project}/compare", tenant.PermProjectView, targetProject, id.compare},
		{post, "/projects/{project}/scan", tenant.PermProjectScan, targetProject, id.requestScan},
		{get, "/projects/{project}/settings", tenant.PermProjectManage, targetProject, id.projectSettings},
		{post, "/projects/{project}/settings", tenant.PermProjectManage, targetProject, id.saveProject},
		{post, "/projects/{project}/archive", tenant.PermProjectManage, targetProject, id.setProjectArchived(true, "project_archived")},
		{post, "/projects/{project}/unarchive", tenant.PermProjectManage, targetProject, id.setProjectArchived(false, "project_unarchived")},
		{post, "/projects/{project}/agent", tenant.PermProjectManage, targetProject, id.assignAgent},
		{post, "/projects/{project}/ai", tenant.PermProjectManage, targetProject, id.setProjectAI},
		{post, "/projects/{project}/team", tenant.PermProjectMove, targetProject, id.moveProject},

		{get, "/agents/new", tenant.PermAgentManage, targetAnyTeam, id.newAgent},
		{post, "/agents", tenant.PermAgentManage, targetAnyTeam, id.createAgent},
		{get, "/agents/{agentID}", tenant.PermAgentView, targetAgent, id.agentPage},
		{post, "/agents/{agentID}/tokens", tenant.PermAgentManage, targetAgent, id.createAgentToken},
		{get, "/agents/{agentID}/tokens/{tokenID}/revoke", tenant.PermAgentManage, targetAgent, id.confirmRevokeAgentToken},
		{post, "/agents/{agentID}/tokens/{tokenID}/revoke", tenant.PermAgentManage, targetAgent, id.revokeAgentToken},
		{get, "/agents/{agentID}/disable", tenant.PermAgentManage, targetAgent, id.confirmDisableAgent},
		{post, "/agents/{agentID}/disable", tenant.PermAgentManage, targetAgent, id.disableAgent},
		{post, "/agents/{agentID}/dt-auto-create", tenant.PermAgentManage, targetAgent, id.setAgentDTAutoCreate},
		{get, "/agents/import", tenant.PermAgentManage, targetAnyTeam, id.archiveImportPage},
		{post, "/agents/import", tenant.PermAgentManage, targetAnyTeam, id.importArchive},
		{get, "/enrollment-tokens/new", tenant.PermAgentManage, targetAnyTeam, id.newEnrollment},
		{post, "/enrollment-tokens", tenant.PermAgentManage, targetAnyTeam, id.createEnrollment},
		{get, "/enrollment-tokens/{tokenID}/revoke", tenant.PermAgentManage, targetEnrollment, id.confirmRevokeEnrollment},
		{post, "/enrollment-tokens/{tokenID}/revoke", tenant.PermAgentManage, targetEnrollment, id.revokeEnrollment},
	}
}

// mountOrgRoutes monte la table des routes, chacune derrière sa garde de droit.
func mountOrgRoutes(r chi.Router, id *identity) {
	for _, rt := range orgRoutes(id) {
		h := rt.handler
		if id.routeStub != nil {
			h = id.routeStub
		}
		r.With(id.require(rt.perm, rt.target)).Method(rt.method, rt.pattern, h)
	}
}

type projectKey struct{}

// projectFromContext renvoie le projet résolu par la garde de la route.
func projectFromContext(ctx context.Context) (project.Project, bool) {
	p, ok := ctx.Value(projectKey{}).(project.Project)
	return p, ok
}

// require vérifie la permission perm sur la ressource de la route. Une ressource
// invisible (équipe dont le compte n'est pas membre) répond 404, comme une ressource
// inconnue ou d'une autre organisation ; un droit manquant sur une ressource visible
// répond 403 (le membre la connaît déjà).
func (id *identity) require(perm tenant.Permission, t target) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acc, ok := tenant.AccessFrom(r.Context())
			if !ok {
				id.rd.Error(w, r, http.StatusNotFound)
				return
			}
			team, visible, p, err := id.resourceTeam(r, acc, t)
			if err != nil {
				id.serverError(w, r, err)
				return
			}
			if !visible {
				id.rd.Error(w, r, http.StatusNotFound)
				return
			}
			allowed := acc.Can(perm, team)
			if t == targetAnyTeam {
				allowed = acc.CanAny(perm)
			}
			if !allowed {
				id.rd.Error(w, r, http.StatusForbidden)
				return
			}
			if p != nil {
				r = r.WithContext(context.WithValue(r.Context(), projectKey{}, *p))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// resourceTeam résout l'équipe de la ressource de la route et dit si elle est visible ;
// elle renvoie aussi le projet résolu, que la garde range dans le contexte.
func (id *identity) resourceTeam(r *http.Request, acc tenant.Access, t target) (uuid.UUID, bool, *project.Project, error) {
	ctx := r.Context()
	vis := acc.Visibility()
	switch t {
	case targetTeam:
		teamID, err := uuid.Parse(chi.URLParam(r, "teamID"))
		if err != nil {
			return uuid.Nil, false, nil, nil
		}
		team, err := id.Orgs.Team(ctx, acc.Org, vis, teamID)
		if errors.Is(err, org.ErrNotFound) {
			return uuid.Nil, false, nil, nil
		}
		return team.ID, err == nil, nil, err
	case targetProject:
		p, err := id.Projects.Get(ctx, acc.Org, vis, chi.URLParam(r, "project"))
		if errors.Is(err, project.ErrNotFound) {
			return uuid.Nil, false, nil, nil
		}
		if err != nil {
			return uuid.Nil, false, nil, err
		}
		return p.TeamID, true, &p, nil
	case targetAgent:
		agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
		if err != nil {
			return uuid.Nil, false, nil, nil
		}
		team, err := id.Agents.Team(ctx, acc.Org, vis, agentID)
		if errors.Is(err, agent.ErrNotFound) {
			return uuid.Nil, false, nil, nil
		}
		if err != nil {
			return uuid.Nil, false, nil, err
		}
		if team == nil {
			return uuid.Nil, true, nil, nil
		}
		return *team, true, nil, nil
	case targetEnrollment:
		tokenID, err := uuid.Parse(chi.URLParam(r, "tokenID"))
		if err != nil {
			return uuid.Nil, false, nil, nil
		}
		team, err := id.Agents.EnrollmentTeam(ctx, acc.Org, tokenID)
		if errors.Is(err, agent.ErrNotFound) {
			return uuid.Nil, false, nil, nil
		}
		if err != nil {
			return uuid.Nil, false, nil, err
		}
		return team, vis.Sees(team), nil, nil
	}
	return uuid.Nil, true, nil, nil
}
