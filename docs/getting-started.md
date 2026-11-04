# Getting started

*[Version française](demarrage.md)*

This guide takes you from an installed instance to a first inventoried, queryable fleet:
sign-in, organization and teams, servers, repositories, reading the results, then triage
and alerts. Installing the server (deb package or by hand) and the agents is covered in
[`operations.md`](operations.md) (French); detailed usage in
[`utilisation.md`](utilisation.md) (French).

## 1. Sign in

1. The operator gives you the instance address (for example `https://sbom.example.org`),
   your sign-in e-mail and a **temporary password**, shown only once when the account is
   created. If the instance is open to sign-up, or if you received an invitation, create
   your account yourself instead (see below).
2. Open the address and sign in. At the first sign-in, the **Set up your second factor**
   screen shows a QR code: scan it with an authenticator app (FreeOTP, Aegis, Google
   Authenticator, 1Password…), or type the key shown, then enter the six-digit code. The
   second factor is mandatory for every local account.
3. The next screen shows your **recovery codes**, only once: write them down or print
   them and keep them away from your phone. Each one replaces an app code once.
4. Then choose your own password (at least 12 characters).

From then on, each sign-in asks for the password, then a code. Lost phone: at the code
step, choose “Use a recovery code”, then, in **My account › Two-factor authentication**,
“Change authenticator app” (with a new password) to set up the new phone. Without a recovery code, an instance
administrator resets your second factor and gives you a new temporary password. **My
account** (top right) sets the language (English or French) and the theme, changes the
password, manages your recovery codes and your access tokens.

**Creating your own account.** Depending on the instance's setting, the sign-in page offers
**Create an account** (public sign-up) or **Have a sign-up code?** (a code handed over by an
instance administrator). Enter your address: you receive a link to confirm it (unless the
instance sends no e-mail), then choose the name of your organization, of which you become
the administrator, and your password. The **link of an organization invitation** (e-mail,
or a link handed over by its administrator) likewise creates your account at the invited
address or, if you already have an account, has you sign in to accept. Either way, you set
up your second factor right away (steps 2 and 3); there is no temporary password to change.

## 2. Create the organization (instance administrator)

An **organization** groups projects and their members; nothing crosses from one
organization to another.

1. **Administration › Accounts**: create the future members' accounts (the temporary
   password is shown once; hand it over through a safe channel). Appoint a second instance
   administrator: the interface reminds you as long as there is only one.
2. **Administration › Organizations**: create the organization (short identifier such as
   `infra`, name, language) and appoint its first administrator.
3. In the organization, **Members**: **invite** each person by their address, as a
   **member** or an **administrator** of the organization; they accept from **My account ›
   Invitations** (30 days), or through the invitation link, which creates their account if
   it does not exist: e-mailed if the instance sends e-mail, otherwise shown only once, for
   you to hand over.
4. **Teams**: every project belongs to a team (“General” exists from the start); a member
   only sees the projects of their teams. Create the teams you need, then, on each team
   page, add members with their **team role** — **reader** (reads), **analyst** (reads,
   requests scans, triages findings), **team administrator** (manages the team's projects,
   agents and members). An organization administrator sees and manages everything
   ([details](utilisation.md#équipes-rôles-et-invitations), French).

## 3. Inventory servers

1. **Agents › Enroll servers** (organization or team administrator): choose the team of
   the future servers, the validity, the number of servers to enroll and, if needed,
   labels (`env=production`). The **enrollment
   token** and the installation commands are shown only once.
2. On each server, the operator installs the `lotor-host-agent` package, sets the server
   address, drops the token and starts the agent
   ([`operations.md`](operations.md#agent-serveur)).
3. On its first run, the server appears under **Projects** with its system, kernel and
   architecture, then its first **snapshot** and its **findings** a few seconds later. The
   agent rescans every day and sends an SBOM only when the inventory changed.
4. For an immediate inventory (after patching the server, for example): project page ›
   **Scan now** (analyst or administrator). The agent starts it at its next heartbeat
   (5 minutes at most in daemon mode).
5. Containers: if the operator enables `containers.enabled` on the agent (off by default,
   [`operations.md`](operations.md#conteneurs)), every Docker or Podman container of the
   server becomes a child project, with its own SBOM and findings, shown on the server's
   page ([details](utilisation.md#conteneurs-des-serveurs), French).

## 4. Inventory repositories

1. The operator sets up the organization's **repository agent**, with a GitHub App or a
   GitLab service account ([`operations.md`](operations.md#agent-dépôt)); the agent is
   created under **Agents › New repository agent**.
2. **Projects › New project**, kind **Repository**: name, repository URL on the forge
   (`https://github.com/acme/app`), tracked branches (one per line, for example `main`),
   tracked tags if any.
3. On the project page, entrust it to the repository agent. The agent analyses it on its
   next pass (15 minutes at most), then on every push received by webhook.
4. Optional: the repository's **Settings › AI enrichment** has a model look for components
   that no manifest declares (off by default; an external provider needs an organization
   administrator's approval; [details](utilisation.md#composants-trouvés-par-lia), French).

## 5. Read the results

- **Dashboard** (organization home): open findings by severity, actively exploited
  vulnerabilities (**KEV**), trend, median time to fix, agents silent for 7 days, most
  exposed projects and components.
- **Project page**: **Findings** tab (open vulnerabilities sorted by risk, with the fixed
  version), **Snapshots** tab (SBOMs received, downloadable as sent or as CycloneDX 1.6
  and SPDX 2.3).
- **Vulnerability page**: description, scores, and the projects of the organization it
  affects.
- The vulnerability database is updated daily and the whole fleet is re-analysed: a
  finding appears or is resolved without the agents sending anything new.

## 6. Query the fleet

**Search** answers "who uses this component?" and "who is affected by this CVE?" over the
current inventory of every project of the organization:

| Input | Result |
| --- | --- |
| `CVE-2023-48795` or `GHSA-45x7-px36-x8w8` | affected projects, components, status, fixed version |
| `openssl` | components whose name contains the text |
| `pkg:golang/golang.org/x/crypto vers:golang/<0.17.0` | versions of a package within a range |
| `sha256:…` | components carrying this file |

Filters (project kind, label, KEV, severity) and order are in the page address: copying
it shares the same result. **Export as CSV / JSON** gives every occurrence.

## 7. Automate with the API

**My account › Access tokens**: create a personal token (7 days to 1 year, TOTP code
required, shown only once). It grants read access to what your account sees:

```bash
curl -H "Authorization: Bearer $LOTOR_TOKEN" \
  "https://sbom.example.org/api/v1/orgs/infra/search?q=CVE-2023-48795"
```

The API contract is [`api/openapi.yaml`](../api/openapi.yaml).

## 8. Triage, compare, get alerted

- **Triage**: a finding's status (**Findings** tab) leads to its page, where an analyst
  decides “affected”, “not affected” (with a VEX justification), “false positive”, “risk
  accepted” until a date, or “fixed”. Decisions export as OpenVEX or CycloneDX (**VEX**
  tab), and a vendor's VEX can be imported
  ([details](utilisation.md#triage-des-constats-et-vex), French).
- **Compare**: the **Snapshots** tab shows, for each snapshot, the components added,
  removed, upgraded or downgraded, and compares two snapshots with their security impact
  ([details](utilisation.md#historique-et-comparaison-des-instantanés), French).
- **Get alerted**: an organization administrator enables **Policies** (for example “KEV
  on a production project”) and **Channels** (e-mail, webhook, Matrix, Mattermost,
  Slack); violations show under **Violations** and in the dashboard's “Alerts” section
  ([details](utilisation.md#politiques-et-alertes), [`notifications.md`](notifications.md),
  French).
