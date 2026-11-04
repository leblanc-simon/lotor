# CLAUDE.md

Ce fichier guide Claude Code lorsqu'il travaille sur ce dépôt.

## Projet

**lotor** : plateforme open source de gestion de SBOM par projet (dépôt git ou
serveur). Deux agents produisent les SBOM (agent dépôt avec enrichissement IA, agent serveur
en Go sans IA) ; un serveur central les historise, les analyse chaque jour avec Grype, et
offre recherche transverse, triage et tableaux de bord. Multi-organisation, en Go, sur
[`leblanc.io/open-go-base`](../open-go-base) et PostgreSQL. Licence WTFPL.

## Documents de référence, dans cet ordre

1. [`docs/cahier-des-charges.md`](docs/cahier-des-charges.md) — le besoin et les décisions
   produit.
2. [`specs/architecture.md`](specs/architecture.md) — **fait autorité** sur l'architecture,
   les noms et les conventions.
3. [`specs/README.md`](specs/README.md) — les 29 lots techniques, leur ordre, leur statut,
   la façon de travailler et la définition de « terminé ».
4. [`specs/lecons.md`](specs/lecons.md) — erreurs déjà commises et pièges connus : à lire
   avant chaque lot, à compléter à la fin.
5. `specs/lots/Txx-*.md` — la fiche du lot en cours, et le Journal des lots dont il dépend.
6. [`docs/adr/`](docs/adr/) — décisions d'architecture.

## État actuel

T00 et T01 terminés : `lotor-server` démarre, migre, sert une page d'accueil traduite,
ses sondes et ses métriques. Prochains lots, en parallèle :
[T02 — File de traitements](specs/lots/T02-file-de-traitements.md) et
[T03 — Comptes et organisations](specs/lots/T03-comptes-organisations.md). Le socle
réutilisable (config, `db.InOrg`, `dbtest`, rendu, i18n, problèmes RFC 9457, pagination,
`webtest`) est décrit dans les `doc.go` et dans le Journal de T01.
T02 terminé : file de traitements `internal/jobs` (`Enqueue` dans la transaction de
l'appelant, `Runner`, `Scheduler`, horloge injectable), voir son `doc.go` et l'ADR 0011.
T03 terminé : comptes (`internal/account`), TOTP obligatoire, organisations
(`internal/org`), garde `/o/{slug}`, journal d'audit (`internal/audit`), fonctions
`crossorg` (ADR 0012, 0013), harnais d'isolement SQL et par route.
T04 terminé : projets (`internal/project`), agents et jetons (`internal/agent`, ADR 0014),
API des agents générée (`internal/api`, `internal/api/gen`, `internal/agentclient/gen`),
limitation par jeton (`ratelimit.WithKeyFunc` d'open-go-base).
T05 terminé : modèle SBOM, purl canoniques et empreinte (`internal/sbom`), schémas
embarqués (`sbom/schema`), adaptateur Syft (`sbom/syft`), inventaire
(`internal/inventory`), réception et job `ingest.decode` (`internal/ingest`, ADR 0015,
0016), écrans des instantanés ; jeux d'essai dans `testdata/sbom/`. Prochains lots, en
parallèle : [T06](specs/lots/T06-analyse-vulnerabilites.md),
[T07](specs/lots/T07-agent-serveur.md) et [T08](specs/lots/T08-agent-depot.md).
T08 terminé : forges (`internal/forge` : GitHub App, GitLab par compte de service,
webhooks vérifiés), agent dépôt (`internal/repoagent` : récepteur de webhooks,
rattrapage, file en mémoire, git sous environnement maîtrisé, Syft hors ligne, SBOM
déterministe), `lotor-repo-agent` et `deploy/lotor-repo-agent/` (ADR 0023).
T06 terminé : base Grype commune (`internal/vuln`, `internal/vuln/grype`, ADR 0017 :
archives en blocs dans PostgreSQL, cible, copie locale par instance, `/readyz` des
workers), analyse et constats (`internal/finding`, ADR 0018), téléchargements par
`internal/download`, écrans des constats, des vulnérabilités et des composants, jeu de
mesure `internal/benchdata` et `docs/benchmarks.md` (ADR 0019), autoanalyse des binaires
en CI (`make selfscan`).
T07 terminé : agent serveur `lotor-host-agent` (`internal/hostagent`, ADR 0020, 0021),
client commun des agents `internal/agentclient` (réessais, mTLS, envoi gzip, suivi d'une
ingestion : voir son `doc.go`, à adopter par l'agent dépôt), compte rendu d'inventaire et
demande de scan par le signal de vie, mTLS exigé sur l'API des agents avec
`tls.client_ca_file`, unités systemd et paquets deb et rpm (`make packages`).
T09 terminé : recherche transverse (`internal/search`, ADR 0024 : fonctions de recherche
par nom et empreinte dans `crossorg`, pagination par projet, export en flux), comparaison
de versions et plages vers (`internal/version`, `version/grypeversion`, ADR 0026), jetons
d'accès personnels (`internal/account`, format commun `internal/token`, ADR 0025), API
utilisateur `GET /api/v1/orgs/{org}/search` (`internal/api/gen/userapi`), écran
`/o/{slug}/search`, guide d'utilisation `docs/utilisation.md`, `make bench-search`.
T10 terminé : tableau de bord d'organisation et en-tête de la fiche projet
(`internal/dashboard`, statistiques quotidiennes réécrites toutes les heures, ADR 0027),
graphiques SVG serveur (`internal/render/chart.go`, `partials/charts.html`), agent muet
au-delà de 7 jours (`agent.Silent`), contrôle des SVG par `webtest`.
T11 terminé, **lot 1 terminé** : administration de l'instance (traitements en échec,
version de la base par instance, import d'une archive, purge ; ADR 0028), revue de
sécurité corrigée (ADR 0029 à 0031 ; open-go-base v1.3.0 : verrouillage par compte de
mfax, `csrfx.WithSessionBinding`), audit RGAA (grille
[`docs/accessibilite/grille-rgaa-lot1.md`](docs/accessibilite/grille-rgaa-lot1.md),
conventions au § 14 de l'architecture), recette sur un parc pilote (trois conteneurs et
quatre dépôts publics, trois CVE de contrôle exactes), mesures consolidées
(`docs/benchmarks.md`), `docs/operations.md` complet, guides de démarrage
(`docs/demarrage.md`, `docs/getting-started.md`), préversion `v0.1.0` (`CHANGELOG.md`,
`.github/workflows/release.yml`, `scripts/release.sh`, unité
`deploy/systemd/lotor-server.service`, ADR 0032), publiée le 1er novembre 2026.
Projet renommé **lotor** (open-go-sbom, préfixe `ogsbom`, avant le 31 octobre 2026) :
module `leblanc.io/lotor`, commandes `lotor-*`, préfixe `LOTOR_`, objets SQL `lotor_*`,
identité visuelle dans `docs/logo/` (ADR 0033).
T16 terminé, premier lot du lot 2 : équipes et droits (ADR 0034). Rôle d'organisation
`member` ou `admin`, droits par rôle d'équipe (`reader`, `analyst`, `admin`) selon la
matrice de `internal/tenant` (`Matrix`, `Allowed`, `Access.Can`), dont dérivent
`docs/security/permissions.md` et la table des routes `orgRoutes` (`internal/web/guard.go`,
404 ressource invisible, 403 droit manquant) ; **toute lecture pour un compte** passe
`db.Visible(acc.Visibility())` et filtre par `lotor_team_visible(team_id)` (échec sans
déclaration) ; tout projet a une équipe, agent sans équipe = agent d'organisation ;
invitations (`/account/invitations`, SEC-09 corrigé, `crossorg` `lotor_user_invitations`).
Tests de référence : `TestRoutePermissionsFollowMatrix`, `TestTeamFilterOnEverySurface`.
Prochains lots, en parallèle : [T12](specs/lots/T12-enrichissement-ia.md),
[T13](specs/lots/T13-conteneurs.md), [T14](specs/lots/T14-triage-vex.md) et
[T17](specs/lots/T17-differences-instantanes.md).
T12 terminé : enrichissement IA de l'agent dépôt (`internal/llm` : `Provider`, boucle
`Run`, Anthropic par le SDK officiel sans environnement, Ollama, faux fournisseur
`llmtest` ; `internal/repoagent/ai_*.go` : outils sous `os.Root`, exclusions,
vérificateur seul juge, fusion, statut `lotor:enrichment`, analyse incrémentale ; ADR 0042
à 0044). Réglage par dépôt `ai_mode` (désactivé par défaut ; externe : permission
`ai.external`, audité ; `ai.forbid_external`), route agent `refs/{id}/ai-components`, bloc
« preuve » de la fiche composant. Corpus annoté `testdata/ai-corpus`, `make eval-ai`
(vrai modèle, hors CI : mesure à faire par l'utilisateur).
T17 terminé : différences d'instantanés (`internal/inventory` : `History`, job
`inventory.diff`, tables `set_diffs`/`set_diff_items` par couple d'ensembles consécutifs,
montée ou descente par `purl_base` ; ADR 0038), effet sur la sécurité calculé à la lecture
(`finding.SnapshotEffect`), frise et écran `/projects/{project}/compare`, API
`…/projects/{project}/snapshots` et `…/compare` ; rétention quotidienne (`retention.*` :
90 jours puis le dernier instantané de chaque mois, jamais le dernier d'une référence ;
orphelins supprimés ; horizon `snapshot_retention` pour T21 ; ADR 0039).
T14 terminé : triage et VEX (`internal/triage`, `internal/triage/vex`, ADR 0035 à 0037).
Décisions de projet (composant exact) ou d'organisation (`purl_base`, plage `vers`,
permission `triage.org`), journal `triage_decisions` en ajout seul, statut effectif rangé
sur chaque constat (`findings.triage_status`), recalculé à chaque décision et classé par
l'analyse (`finding.Classifier`) ; échéance des risques acceptés (job `triage.expire`) ;
export OpenVEX et CycloneDX (écran et API), import de VEX d'éditeurs. T15 réutilise
`triage_status` et `triage.Options.OnChange` (voir le `doc.go` de `triage`).
T13 terminé : conteneurs en projets enfants (ADR 0040, 0041). Projet de nature
`container`, enfant de l'hôte (`Project.Parent`), dans son équipe par clé étrangère en
cascade ; l'agent serveur (`containers.enabled`, désactivé par défaut : aucune socket
ouverte sans lui) lit l'API Docker de Docker ou Podman sur socket Unix, identité
`projet/service` Compose sinon nom (`hostagent.Identity`), signale ses conteneurs
(`POST /api/v1/agent/containers`, création sous son hôte seul), scanne chaque image
exportée une fois ; archivage après `containers.archive_after` (7 jours) et retour au
redémarrage ; fiche hôte par périmètre (`dashboard.Family`) ; conteneurs écartés des
listes et de la recherche sauf `containers=1`.
T15 terminé : politiques en CEL (`internal/policy` : contexte typé constat ou agent, coût
borné, modèles, violations datées, verdict `GET /api/v1/agent/snapshots/{id}/verdict` ;
ADR 0045), notifications (`internal/notify` : canaux e-mail, webhook signé, Matrix,
Mattermost, Slack, secrets chiffrés, envois uniques par canal × violation et réessayés ;
`internal/delivery` : HTTP gardé contre la SSRF, SMTP ; ADR 0046), statut de commit de
l'agent dépôt (`status.*`, désactivé par défaut ; ADR 0047), écrans des politiques, des
violations et des canaux, section « Alertes » du tableau de bord ; `docs/notifications.md`.
T18 (partie 1, compléments) : codes de secours du second facteur
(open-go-base v1.4.0, `mfax.WithRecoveryCodes` ; page `/account/security`, reconfiguration
de l'application par le titulaire `account.ReconfigureTOTP` ; ADR 0048), purge des
conteneurs archivés pour absence par la rétention (`containers.purge_after`, 180 jours ;
ADR 0049), filtre `team` et statut de triage dans la recherche (ADR 0050). Partie 2,
revue de sécurité du lot 2, faite (ADR 0051, modèle de menace version 3, open-go-base
v1.4.1 : `EnablePOST` sous verrouillage) : reconfiguration du second facteur avec nouveau
mot de passe, inscription par le nom bornée à l'équipe du jeton, IA externe retirée au
changement de dépôt, secret de canal à ressaisir au changement de destination,
`containers.max_per_host`, fichiers exclus jamais nommés au modèle, garde SSRF étendue,
`llm.Budget.MaxCallsPerTurn`. Partie 3 faite : audit RGAA des écrans du lot 2 (grille
[`docs/accessibilite/grille-rgaa-lot2.md`](docs/accessibilite/grille-rgaa-lot2.md), 100 %
après corrections ; conventions ajoutées au § 14 de l'architecture). Partie 4 faite, **T18
terminé, lot 2 terminé** : évaluation de l'IA sans modèle réel (contrôle indépendant des
preuves `checkProof`, corpus de 11 cas, échantillon pilote annoté `testdata/ai-pilot` et
`scripts/ai-pilot-fetch.sh`, `make eval-ai` par jeu et mode `credulous`), mesures avec les
équipes et les conteneurs (`benchdata.AddTeamsAndContainers`, `docs/benchmarks.md`),
recette sur une mise à jour réelle 0.1.0 → 0.2.0 (Docker, Compose et Podman), deux défauts
corrigés (composants IA d'image perdus à l'ingestion ; doublons de notification : envois
réservés, migration 023, ADR 0052), `CHANGELOG.md` `[0.2.0]` prêt. Restent à l'utilisateur
(`specs/avancement.md`) : mesure de l'IA avec une clé, publication de `v0.2.0`. Prochains
lots (lot 3), en parallèle :
[T19](specs/lots/T19-dependency-track.md), [T20](specs/lots/T20-licences.md),
[T21](specs/lots/T21-recherche-historique.md), [T22](specs/lots/T22-agent-windows.md),
[T23](specs/lots/T23-hors-ligne.md) et [T25](specs/lots/T25-sso-oidc.md) (T24 après T19
et T23).
T27 terminé : paquet deb `lotor-server` (ADR 0053 ; `deploy/server/`, debconf en anglais et en
français, rôles PostgreSQL créés en local, premier administrateur, site nginx ou Apache, aucun
démarrage sur une mise à jour), recette `make test-package` dans des conteneurs systemd.
Agent serveur, hors lot (ADR 0055) : index compact de l'arborescence (`hostagent.fsIndex`,
`indexSource`, `indexResolver`) au lieu de la source « répertoire » de Syft, qui ouvrait chaque
fichier ; répertoires de données exclus par défaut ; parité vérifiée par
`TestIndexSourceMatchesSyftDirectory` (`LOTOR_PARITY_ROOT=/` pour une vraie racine, à refaire
à chaque montée de version de Syft).
T28 terminé : inscription (`internal/signup`, ADR 0056). `signup.mode` `private` (défaut),
`invitation` (codes d'instance à usage unique, `/admin/signup`) ou `public` (adresse
vérifiée, `signup.allowed_domains`, SMTP et `web.public_url` exigés) ; une organisation par
inscription, compte administrateur, session de configuration puis TOTP. Lien secret sur
chaque invitation d'organisation (`/invitation/{jeton}`, tous modes). Courriels
transactionnels `internal/mailer` (job `mail.send` chiffré) et gabarit HTML commun des
courriels (`internal/delivery/mailhtml.go`, contraintes du mode sombre de Thunderbird dans
son commentaire). `web.public_url` remplace `notify.public_url`.
T19 terminé : point compatible Dependency-Track (`internal/api/dtrack.go`, ADR 0057) sous
`/dt` (clé = jeton d'agent dépôt, nom = dépôt confié, version = référence de nature
`version` sans commit, création automatique par agent d'équipe `agents.dt_auto_create`),
client `agentclient.DTClient`, sortie `dependency_track.*` des deux agents (agent serveur :
CycloneDX 1.6, `only`), `docs/dependency-track.md`, `make test-dtrack` (vrai
Dependency-Track 5, hors CI). Reste à l'utilisateur : exécution réelle de l'action GitHub.
T21 terminé : recherche à une date passée (`search.Filters.At`, paramètre `at`, ADR 0058) :
instantané en vigueur par référence (fin de journée UTC, `snapshots_ref_idx`), projets
archivés et références retirées compris, composants seulement, `Result.Partial` avant
l'horizon de la rétention ; `benchdata.AddHistory`, `TestSearchAtBenchmark`.
T23 terminé : mode hors ligne (ADR 0059, `docs/site-isole.md`). Format `internal/offline`
(tar manifeste, codes HMAC de clé l'empreinte du jeton, SBOM), agent serveur `offline.dir`
et `offline.only` (inscription par la première archive, jeton tiré par l'agent), agent
dépôt `offline.dir`, import `ingest.Importer` par Agents › Importer des archives,
`POST /api/v1/orgs/{org}/archives` et `offline.watch_dir`, dédoublonnage
`ingestions.archive_sha256` (migration 026).

## Règles de travail

- **La qualité prime sur la vitesse.** Pas de raccourci, pas de dette reportée.
- Un lot à la fois, sur une branche `lot/<id>-<sujet>` poussée sur GitHub ; PR vers `main`
  fusionnée dès que la CI est verte et les critères cochés (l'utilisateur relit a posteriori).
- Avant d'écrire du code : proposer un plan, et faire valider par l'utilisateur toute
  nouvelle dépendance tierce, tout écart à `architecture.md` et tout « point à trancher ».
- Toute décision structurante donne un ADR dans `docs/adr/` et, si besoin, une mise à jour
  d'`architecture.md` dans le même commit.
- En fin de lot : critères cochés, Journal de la fiche rempli, statut mis à jour dans
  `specs/README.md`, `make ci` vert.
- open-go-base est un autre dépôt (`../open-go-base`). Les évolutions du § 23 de
  l'architecture y sont autorisées : branche, PR fusionnée quand la CI est verte, étiquette
  semver, puis montée de version ici. Toute autre évolution demande l'accord de l'utilisateur.
- Décisions déjà prises pour le lot 1 : section « Décisions » de chaque fiche.

## Conventions qui reviennent sans cesse

- Code en anglais ; commentaires et documentation en français ; commentaires réservés au
  « pourquoi » non évident.
- Isolement des organisations (§ 9 de l'architecture) : RLS forcée sur toute table
  d'organisation, accès uniquement par `db.InOrg` (jamais `InTx`), `tenant.OrgID` en
  paramètre, clés étrangères composites, 404 pour une ressource d'une autre organisation,
  tests d'isolement par route et tests SQL de RLS. Les seules lectures
  inter-organisations passent par `internal/db/crossorg`.
- Deux rôles PostgreSQL : le propriétaire migre, l'application tourne avec un rôle qui ne
  peut pas contourner la RLS (vérifié au démarrage).
- Anchore (Syft, Grype, Grant) importé uniquement par ses adaptateurs (§ 4 de
  l'architecture, vérifié par `internal/archtest`).
- Traduction : aucune chaîne visible en dur ; clés anglaises `écran.élément` ; racines
  transverses `format.*`, `status.*`, `severity.*`, `validation.*`, `error.*` ; le JS reçoit
  ses libellés traduits via des attributs `data-`.
- Front sans npm ni bundler : `html/template`, modules ES natifs, CSS natif imbriqué
  (modificateur BEM `&.bloc--modificateur`, déclarations avant les règles imbriquées,
  `@media` imbriqués dans le composant). Aucun script ni style en ligne (CSP stricte).
- Migrations `internal/db/migrations/NNN_<sujet>.sql`, immuables une fois sur `main` : leur
  somme SHA-256 est vérifiée au démarrage.
- Comptes : authx ne fait que lire `users` ; c'est `internal/account` qui crée et modifie
  les comptes (`authx.HashPassword`, `must_change_pwd`).
- Évolutions attendues d'open-go-base : § 23 de l'architecture.
- TOTP obligatoire pour les comptes locaux : ne jamais utiliser
  `mfax.WithOptionalEnrollment()`.
- Jamais de mot de passe, jeton, secret ni contenu de SBOM dans les journaux.
- Jobs idempotents ; mise en file dans la transaction qui produit la donnée.

## Commandes

```bash
make help               # liste des cibles
make ci                 # fmt-check, generate-check, vet, lint, test-race, test-integration, vuln, build, packages
make test-race          # tests unitaires
make test-integration   # tests étiquetés integration ; PostgreSQL : docker compose -f deploy/compose.yaml up -d
                        # (LOTOR_TEST_DATABASE_DSN, par défaut postgres://postgres:postgres@localhost:5432/postgres)
make lint               # staticcheck (go tool), sans étiquette puis par étiquette de test
make vuln               # govulncheck (go tool)
make generate           # code généré depuis api/openapi.yaml (à committer avant make ci)
make test-grypedb       # vraie base Grype (LOTOR_TEST_GRYPEDB_DIR : base v6 installée)
make bench              # mesures sur le jeu de référence (docs/benchmarks.md)
make bench-search       # mesures de la recherche sur le jeu de référence, RLS active
make bench-ingest       # ingestion et analyse de 5 000 composants, vraie base Grype
make eval-ai            # enrichissement IA sur le corpus annoté, vrai modèle (LOTOR_EVAL_AI_*), hors CI
make selfscan           # SBOM des binaires (Syft) et analyse (Grype) ; échec sur une KEV
make build              # bin/lotor-server, bin/lotor-host-agent, bin/lotor-repo-agent (CGO_ENABLED=0)
make release VERSION=v0.1.0 RELEASE_DIR=/chemin/vide  # archives, paquets, SHA256SUMS (ADR 0032)
make packages           # agent serveur (deb, rpm) et serveur (deb), amd64 et arm64, dans dist/ (nfpm)
make test-package       # recette du paquet deb du serveur, conteneurs systemd (Docker), hors make ci
make run                # serveur avec config.yaml (cp config.example.yaml config.yaml)
```

Exploitation (configuration, rôles PostgreSQL, TLS, sondes) : [`docs/operations.md`](docs/operations.md).
