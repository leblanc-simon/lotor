# Architecture technique de référence

Ce document fait autorité sur l'architecture, les noms et les conventions de lotor.
Le besoin fonctionnel est dans [`docs/cahier-des-charges.md`](../docs/cahier-des-charges.md) ;
le découpage du travail est dans [`specs/README.md`](README.md). Toute décision qui s'en
écarte passe par un ADR (`docs/adr/`) et une mise à jour de ce document dans le même commit.

## 1. Principes directeurs

1. **La qualité prime sur la vitesse.** Un lot n'est terminé que lorsque ses tests, sa
   documentation et ses critères d'acceptation sont au vert ; on ne reporte pas la dette.
2. **Un binaire par rôle, tout embarqué.** Gabarits, CSS, JS, traductions et migrations sont
   compilés dans le binaire via `go:embed`. Le serveur n'a besoin que de PostgreSQL.
3. **La base est la seule source de vérité.** Un processus redémarré ne perd rien ; aucun
   état métier ne vit uniquement en mémoire ou sur le disque d'une seule instance.
4. **Le serveur calcule, le client affiche.** Aucune logique métier en JavaScript.
5. **Dépendances minimales et validées.** Toute nouvelle dépendance tierce est proposée à
   l'utilisateur avant d'être ajoutée (§ 5). Les bibliothèques d'Anchore sont isolées
   derrière des adaptateurs.
6. **Multi-organisation par construction.** Aucune donnée d'organisation ne vit dans une
   table globale ; l'isolement est garanti par PostgreSQL lui-même (RLS forcée sur toute
   table d'organisation), par le schéma (clés étrangères composites) et par les signatures
   de fonctions, pas par la discipline.
7. **Traduction dès le premier écran.** Aucune chaîne visible en dur, ni dans les gabarits,
   ni dans le code.
8. **Sécurité par défaut.** TOTP obligatoire hors SSO, CSP stricte, CSRF, limitation de
   débit, secrets chiffrés, journal d'audit, entrées bornées.

## 2. Binaires

| Binaire | Rôle | Lots |
| --- | --- | --- |
| `lotor-server` | Interface web, API REST, workers (ingestion, analyse, notifications), planificateur | T01 → |
| `lotor-host-agent` | Agent serveur Linux (puis Windows) : inventaire de l'hôte et de ses conteneurs | T07, T13, T19, T22, T23, T24 |
| `lotor-repo-agent` | Agent dépôt, service externe : forges, clonage, Syft, enrichissement IA | T08, T12, T15, T19, T23, T24 |

`lotor-server` lance web et workers dans le même processus ; `workers.enabled: false` sert à
séparer les rôles sur plusieurs instances (recommandé dès qu'on dépasse un usage modeste,
pour qu'un envoi lourd ne ralentisse pas l'interface).

Un `lotor-repo-agent` sert une organisation (un jeton d'agent). Plusieurs organisations sur
une instance → une instance d'agent dépôt par organisation qui en a besoin.

## 3. Arborescence du dépôt

```
cmd/
  lotor-server/            # main : chargement config, câblage, démarrage
  lotor-host-agent/
  lotor-repo-agent/
internal/
  config/                # Config composée : fragments appconf + fragments propres
  db/                    # pool, transactions (InTx, InOrg), démarrage, migrations
    crossorg/            # seules fonctions inter-organisations (SECURITY DEFINER), § 9
    dbtest/              # base et rôles jetables pour chaque test d'intégration
    migrations/          # NNN_<sujet>.sql, immuables une fois publiées
  locale/                # traductions embarquées, choix de la langue (§ 18), sans HTTP
  pagination/            # curseurs opaques et pages bornées (§ 15)
  jobs/                  # file de traitements PostgreSQL + planificateur
  secret/                # chiffrement des secrets stockés (AES-256-GCM, clés versionnées)
  audit/                 # journal d'audit
  tenant/                # type OrgID, contexte, rôles, matrice des droits, visibilité d'équipe
  account/               # comptes (écriture dans users), méthode d'authentification, rendu
  org/                   # organisations, membres, équipes, invitations, accès d'une requête
  project/               # projets, références suivies, hiérarchie hôte/conteneurs
  agent/                 # agents, jetons d'inscription et d'agent, signaux de vie
  token/                 # format des jetons (agt, enr, pat, sgn, vrf, inv), tirage, lecture, empreinte
  sbom/                  # modèle interne, normalisation purl, empreinte d'inventaire
    syft/                # décodage et encodage via Syft
  inventory/             # composants, ensembles d'inventaire, instantanés, différences, rétention
  ingest/                # réception, stockage brut, pipeline de décodage, import des archives hors ligne
  offline/               # format des archives hors ligne (T23), sans dépendance : agents et serveur
  version/               # comparaison de versions par écosystème, analyse de `vers`
    grypeversion/        # adaptateur vers les comparateurs de Grype
  vuln/                  # base de vulnérabilités, catalogue, interface Matcher
    grype/               # correspondance et cycle de vie de la base via Grype
    vulntest/            # fausse base (Engine, Source) pour les tests
  download/              # téléchargements HTTP(S) du serveur (vuln.Fetcher), hors métier
  delivery/              # envois des notifications (HTTP gardé contre la SSRF, SMTP, gabarit HTML des courriels), hors métier
  finding/               # cycle de vie des constats, analyse des références
  benchdata/             # jeu synthétique et SBOM des mesures (docs/benchmarks.md)
  search/                # analyse de requête, plan, exécution, export
  dashboard/             # agrégats et statistiques quotidiennes
  triage/                # décisions de triage, statut effectif des constats, échéances (T14)
    vex/                 # OpenVEX et CycloneDX VEX : écriture, lecture, schéma OpenVEX embarqué
  policy/                # règles CEL, évaluation, violations, verdict d'un instantané (T15)
  notify/                # canaux de notification, envois, messages traduits (T15)
  mailer/                # courriels transactionnels de l'instance : file mail.send, composition (T28)
  signup/                # inscription : modes, codes, vérifications d'adresse, liens d'invitation (T28)
  license/               # expressions SPDX, politique de licences, constats de licence (T20, ADR 0061)
  web/                   # routeur chi, handlers HTML par écran, gestion, serveurs
    middleware/          # identifiant de requête, journal, en-têtes, langue, métriques
    webtest/             # assistant de test : accessibilité, absence de code en ligne
  api/                   # handlers REST (interfaces générées depuis api/openapi.yaml)
    gen/                 # code généré, jamais modifié à la main (userapi/ : API utilisateur)
    problem/             # erreurs RFC 9457
  render/                # moteur de gabarits, FuncMap, empreinte des assets, SVG
  agentclient/           # client de l'API agent (généré), partagé par les deux agents
  hostagent/             # pipeline de l'agent serveur
  repoagent/             # pipeline de l'agent dépôt
  forge/                 # GitHub App, GitLab (Forgejo plus tard)
  llm/                   # fournisseurs de modèles, boucle d'outils (T12, ADR 0042)
    llmtest/             # faux fournisseur scénarisé et enregistreur des échanges
  archtest/              # tests d'architecture (§ 4)
api/openapi.yaml         # contrat de l'API, source unique
web/                     # paquet Go qui embarque gabarits et fichiers statiques
  templates/             # layout, partials, un dossier par écran
  static/css/            # tokens.css, fonts.css, base.css, components/*.css, screens/*.css
  static/js/             # modules ES, un par écran, sans build
  static/fonts/          # Atkinson Hyperlegible Next et Mono (WOFF2, licence OFL)
locales/                 # en.yaml, fr.yaml (paquet Go qui les embarque)
config.example.yaml      # configuration commentée du serveur
deploy/                  # compose.yaml (dev), unités systemd, configs de paquets, Containerfile
scripts/release.sh       # fichiers d'une version (make release, workflow release), ADR 0032
docs/                    # cahier des charges, adr/, operations.md, benchmarks.md, security/
specs/                   # ce document, index des lots, fiches de lots
testdata/                # SBOM d'exemple, systèmes de fichiers et dépôts de test
```

Nommage : paquets courts en anglais, jamais de paquet fourre-tout (`util`, `helper`,
`common`). Le code Go est en anglais ; les commentaires et la documentation en français.

## 4. Règles de dépendance entre paquets

- `cmd/*` câble, ne contient aucune logique.
- `web` et `api` dépendent des paquets métier ; jamais l'inverse.
- Les paquets métier ne dépendent ni de `net/http` ni de `html/template`.
- **Imports directs** autorisés des bibliothèques d'Anchore (Grype dépend lui-même de Syft,
  la règle porte donc sur les imports directs, pas sur le graphe transitif) :
  - `github.com/anchore/syft/...` : `sbom/syft`, `vuln/grype`, `hostagent`, `repoagent` ;
  - `github.com/anchore/stereoscope/...` : `hostagent` (références de fichier du résolveur
    de l'index compact, ADR 0055) ;
  - `github.com/anchore/grype/...` : `vuln/grype`, `version/grypeversion` ;
  - `github.com/anchore/grant/...` : `license/grant`, s'il devait être adopté ; T20 ne
    l'importe pas (ADR 0061 : les expressions SPDX sont évaluées par `internal/license`).
- Les types d'Anchore ne traversent jamais la frontière d'un adaptateur.
- Le métier n'ouvre aucune connexion : un téléchargement passe par une interface injectée
  (`vuln.Fetcher`), implémentée par `download`, paquet serveur hors métier (ADR 0017) ; de
  même, les notifications passent par `notify.Sender`, implémenté par `delivery` (ADR 0046),
  et les courriels transactionnels par `mailer.Sender`, qu'il implémente aussi (ADR 0056).
- `agentclient`, `hostagent`, `repoagent`, `forge`, `llm` ne dépendent d'aucun paquet
  serveur (`db`, `inventory`…) : les agents restent des binaires légers.
- Pas de variable globale mutable ; les dépendances sont injectées par constructeur.

`internal/archtest` lit les imports directs de chaque paquet, tests compris
(`go list -json`), et échoue en CI au premier écart. Les listes de paquets métier, de
présentation, d'agents et de serveur sont tenues dans `internal/archtest/rules.go` : un
nouveau paquet y est classé dans le commit qui le crée. « `cmd` ne contient aucune
logique » et « pas de variable globale mutable » ne se lisent pas dans les imports et
restent vérifiés en relecture.

## 5. Socle et dépendances

Versions minimales : Go 1.26, PostgreSQL 16. Validations du 31 octobre 2026 ; versions
relevées en T00 (une montée de version ultérieure ne demande pas de nouvelle validation).

| Besoin | Choix | Version (T00) | Statut |
| --- | --- | --- | --- |
| Configuration, journaux, i18n, CSRF, limitation de débit (par IP ou par clé), CORS, comptes, sessions, TOTP | `leblanc.io/open-go-base` | v1.0.1, puis commits de v1.1.0 (T03), v1.2.0 (T04) et v1.3.0 (T11), étiquettes à pousser | Décidé |
| Pilote PostgreSQL | `github.com/jackc/pgx/v5/stdlib` via `database/sql` (partagé avec les stores d'authx et mfax) | v5.12.0 | Validé (ADR 0002) |
| Routeur HTTP | `github.com/go-chi/chi/v5` (comme open-go-canivet) | v5.5.0 | Validé (ADR 0003) |
| SBOM, vulnérabilités, licences | `github.com/anchore/syft`, `grype` (`grant` étudié, non importé : ADR 0061) | v1.55.0, v0.121.0 | Décidé (ADR 0007, 0061) |
| Pilote SQLite pur Go, exigé par Syft pour les bases RPM récentes | `modernc.org/sqlite` (déjà dans le graphe d'open-go-base) | v1.60.1, import direct de `hostagent` (T07) | Validé en T00 (ADR 0007) |
| Manipulation CycloneDX côté agents et dans l'adaptateur `sbom/syft` (réencodage) | `github.com/CycloneDX/cyclonedx-go` (déjà dans le graphe de Syft) | v0.12.0 | Validé |
| purl | `github.com/package-url/packageurl-go` (déjà dans le graphe de Syft) | v0.1.7 | Validé |
| UUID v7 | `github.com/google/uuid` (déjà indirect) | v1.6.0 | Validé |
| Contrat d'API | `oapi-codegen` en directive `tool` + `github.com/oapi-codegen/runtime` | v2.8.1, v1.8.0 | Validé (ADR 0006) |
| Requêtes SQL | écrites à la main (sqlc impose `lib/pq` avec `database/sql`) | — | Tranché (ADR 0004) |
| File de traitements | maison, sur PostgreSQL (§ 16) | — | Retenu (ADR 0005) |
| Analyse statique | `staticcheck`, `govulncheck` en directives `tool` | v0.8.2, v1.9.0 | Validé |
| Validation des SBOM par schéma JSON | schémas officiels embarqués, `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | Validé |
| Métriques | `github.com/prometheus/client_golang` | v1.25.0 | Validé |
| Paquets deb et rpm | `nfpm` en directive `tool` (`make packages`, T07) | v2.48.0 | Validé |
| Fournisseur de modèle | `github.com/anthropics/anthropic-sdk-go/v2`, construit sans aucune valeur lue dans l'environnement ; Ollama par son API HTTP sans SDK | v2.4.0 | Validé en T12 (ADR 0042 ; modèle par défaut `claude-sonnet-5-5`, IA désactivée par défaut) |
| Règles de politique | `github.com/google/cel-go`, sous son nouveau chemin de module `cel.dev/cel-go` (dépendance transitive nouvelle : `github.com/antlr4-go/antlr/v4` v4.13.1) | v0.32.0 | Validé le 1er novembre 2026 (T15, ADR 0045) |
| OIDC | `oidcx` dans open-go-base, ou paquet local | — | Point ouvert, T25 |

Sans dépendance : client Git (binaire `git` du système), clients des forges (HTTP + JWT
RS256 en stdlib), client de l'API Docker et Podman (HTTP sur socket Unix, quatre appels ;
le client moby du graphe de stereoscope est écarté, ADR 0041), envoi de courriels (`net/smtp`), graphiques (SVG côté serveur),
confinement des fichiers (`os.Root`).

## 6. Configuration

`internal/config.Config` compose les fragments d'`appconf` avec le préfixe `LOTOR_` :
`Web` (complété par `public_url`, URL publique des liens des messages, des verdicts et des
courriels, T28), `Logging`, `I18n`, `Database` (complété par les réglages du pool et l'attente au
démarrage), `Auth` et `MFA` (avec authx et mfax, T03), `CORS` (API utilisateur). Fragments
propres au projet : `HTTP` (délais des serveurs, délai d'arrêt propre),
`TLS` (certificat, clé, autorité des certificats clients pour le mTLS des agents),
`Management` (écoute séparée métriques et sondes), `Workers` (activation, nombre de
workers, scrutation, bail, réessais, rétention, planificateur, délai d'arrêt, plafond de
jobs lourds par organisation), `Ingest` (bornes de taille reçue et décompressée, de profondeur
et de composants, délai du décodage, T05),
`VulnDB` (URL de la liste, répertoire local, mode hors ligne, fréquences de vérification
et de synchronisation, âge d'alerte, délais, taille d'archive, T06), `Secrets` (clés
de chiffrement versionnées, obligatoires depuis T03 : les secrets TOTP sont chiffrés),
`Bootstrap` (premier administrateur et procédure de secours, T03), `Login` (débit des
tentatives de connexion, T03), `AgentAPI` (débit de l'API des agents par jeton et des
jetons refusés par IP, T04), `UserAPI` (débit de l'API utilisateur par jeton personnel,
jetons refusés par IP, durée et nombre simultané des exports de la recherche, T09),
`AI` (`forbid_external` : interdire tout fournisseur de modèle externe aux agents dépôt,
T12, ADR 0043),
`Retention` (rétention des instantanés : fenêtre en jours, nombre gardé, dernier
instantané de chaque mois au-delà, T17, ADR 0039), `Notify` (délai d'un envoi, adresses
privées autorisées, heure du résumé quotidien, T15, ADR 0046), `Signup` (mode
d'inscription `private`, `invitation` ou `public`, domaines acceptés du mode public, T28,
ADR 0056), `SMTP`
(serveur d'envoi des courriels : hôte, port, `starttls`/`tls`/`none`, identifiants,
expéditeur, T15),
`Containers` (absence au-delà de laquelle le projet d'un conteneur est archivé, T13),
`Migration`
(`migration_dsn` : connexion du rôle propriétaire, utilisée uniquement pour migrer).
`Database.DSN` est la connexion du rôle d'exécution. `--help` liste toutes les variables
d'environnement. Un `config.example.yaml` commenté accompagne chaque binaire. Un fragment
n'entre dans `Config` qu'avec le lot qui l'utilise : aucune variable sans effet. Défauts
propres au projet, posés avant le chargement : pilote `postgres`, langue `fr`, journaux
`info`.

Contrôles au démarrage :

- `Database.Driver` doit valoir `postgres` (pour que `Dialect()` renvoie PostgreSQL ; le
  pool est ouvert avec le pilote `pgx`) ;
- le pool de migration doit autoriser au moins 2 connexions (le verrou de migration en tient
  une pendant que les migrations travaillent sur une autre) ;
- le rôle d'exécution ne doit être ni superutilisateur, ni `BYPASSRLS`, ni propriétaire des
  tables : sinon la RLS serait contournée, et le serveur refuse de démarrer ;
- `signup.mode: public` exige l'envoi de courriels (`smtp.host`, `smtp.from` et
  `web.public_url`) : sans lui, le serveur refuse de démarrer (ADR 0056) ;
- TLS natif facultatif ; sans lui, le serveur est placé derrière un mandataire inverse qui
  termine TLS, et le mTLS des agents est alors indisponible.

## 7. Base de données

- PostgreSQL 16 ou plus, seul moteur supporté. Connexion directe, ou via pgbouncer en mode
  session (le mode transaction est incompatible avec les migrations et les verrous).
- Deux rôles PostgreSQL (noms par défaut) :
  - `lotor_owner` possède le schéma, applique les migrations (y compris celles d'authx et
    de mfax) et possède les fonctions de `crossorg` ; il a l'attribut `BYPASSRLS`, sans
    lequel ces fonctions ne verraient rien sous la RLS forcée (ADR 0012) — il ne lui
    donne aucun pouvoir nouveau sur des tables qu'il possède ;
  - `lotor_app` exécute l'application : `SELECT`, `INSERT`, `UPDATE`, `DELETE` accordés
    par les migrations (privilèges par défaut sur les tables futures), rien d'autre.
- En fonctionnement, un pool `*sql.DB` unique sur `lotor_app`, partagé par les stores
  d'authx/mfax et par le code du projet ; le pool du propriétaire n'existe que le temps de
  migrer.
- Identifiants : UUID v7 générés en Go pour les entités du projet. Les comptes gardent
  l'identifiant `bigint` d'authx ; les tables du projet qui les référencent utilisent
  `bigint`. Les organisations et les projets ont aussi un `slug` pour les URL.
- Horodatages en `timestamptz`, toujours en UTC. Valeurs fermées en `text` + `CHECK`.
- `jsonb` uniquement pour des données sans requête relationnelle (étiquettes, preuves IA,
  contexte d'hôte).
- **Migrations** : celles d'authx et de mfax par leur `Migrate` ; celles du projet par
  l'exécuteur de `internal/db`, dans `internal/db/migrations/NNN_<sujet>.sql`, suivies dans
  la table `lotor_schema_migrations` avec leur somme SHA-256. Une migration publiée dont la
  somme a changé empêche le démarrage : l'immuabilité est vérifiée, pas seulement promise.
  Ordre au démarrage, avec le pool du rôle propriétaire : transaction de verrou
  (`LOCK TABLE lotor_schema_migrations IN EXCLUSIVE MODE`) sur une connexion dédiée →
  authx → mfax → projet (dont politiques RLS, droits du rôle d'exécution et fonctions de
  `crossorg`) → validation. Une seconde instance attend le verrou puis constate qu'il n'y a
  rien à faire. Les migrations du projet, leur enregistrement et la validation partagent
  la transaction du verrou (tout ou rien, donc pas de `CREATE INDEX CONCURRENTLY`) ; le
  rôle d'exécution, lu dans `database.dsn`, leur est déclaré dans `lotor.app_role` ; la
  validation refuse toute table d'organisation sans la RLS standard (ADR 0010). Sans
  `migration.dsn`, une instance ne migre pas et refuse un schéma en retard.
- Accès : un « store » par paquet métier, qui ne renvoie que des types du domaine.
- Transactions : `db.InOrg(ctx, orgID, func(tx) error)` pour toute donnée d'organisation
  (§ 9), `db.InTx(ctx, func(tx) error)` pour les seules tables globales ; aucune transaction
  ne traverse un appel réseau. Les upserts en lot trient leurs clés pour éviter les
  interblocages.

## 8. Modèle de données

Données **globales** (publiques ou propres à l'instance, jamais des données d'organisation) :

| Table | Contenu |
| --- | --- |
| `vulnerabilities` | identifiant (CVE, GHSA…), alias, sévérité, CVSS, description, références, EPSS, KEV |
| `vulndb_state`, `vulndb_archives`, `vulndb_archive_chunks` | version cible de la base Grype, archives vérifiées (téléchargées ou importées) stockées par blocs |
| `vulndb_instances` | version de la base chargée par chaque instance worker, rapportée à chaque synchronisation (T11) |
| `vulndb_imports`, `vulndb_import_chunks` | imports manuels d'une archive : état, demandeur, blocs téléversés jusqu'à l'installation (T11, ADR 0028) |
| `jobs`, `schedules` | file de traitements et échéances du planificateur |
| `users`, `sessions`, `mfa_*` | tables d'open-go-base ; `users` est écrit par `account` (§ 10) |
| `account_settings`, `session_auth` | préférences du compte ; méthode d'authentification de chaque session |
| `personal_access_tokens` | jetons d'accès personnels d'un compte, hachés (ADR 0025) : donnée du compte, sans donnée d'organisation |
| `instance_audit_events` | journal d'audit de l'instance (événements sans organisation) |
| `signup_codes`, `signup_verifications` | codes d'inscription (libellé, échéance, usage unique, révocation ; empreinte seule) ; vérifications d'adresse en attente (lien haché, 24 h, code éventuel) (T28, ADR 0056) |

Données **par organisation** (toutes portent `org_id`) :

| Table | Contenu |
| --- | --- |
| `organizations`, `org_memberships` | organisation (slug, nom, langue par défaut) ; compte × organisation × rôle (`member`, `admin`) |
| `teams`, `team_members`, `org_invitations` | équipes ; membre de l'organisation × équipe × rôle d'équipe (`reader`, `analyst`, `admin`) ; invitations à rejoindre l'organisation, avec leur lien secret haché (T16, ADR 0034 ; T28, ADR 0056) |
| `projects` | type (`repo`, `host`, `container`), nom, slug, étiquettes, équipe (obligatoire, T16), archivage, réglage de l'enrichissement IA `ai_mode` (`disabled` par défaut, `local`, `external` ; T12, ADR 0043) ; pour un conteneur, `parent_id` (l'hôte, dont il garde l'équipe par clé étrangère en cascade), identité dans l'hôte, contexte, dernier signalement, archivage pour absence (T13, ADR 0040) |
| `tracked_refs` | référence suivie (branche, tag, version reçue par le point compatible Dependency-Track, l'hôte, ou le conteneur nommé par son identité) |
| `agents`, `agent_tokens`, `enrollment_tokens` | agents (équipe facultative : sans équipe, agent d'organisation) et jetons hachés ; jeton d'inscription rattaché à une équipe, dont héritent projet et agent inscrits ; pour un agent serveur, demande de scan en attente et dernier contexte d'hôte (T07) |
| `components` | composant de l'organisation : purl canonique (unique par organisation), `purl_base`, type, nom, version, CPE, empreintes |
| `component_sets`, `component_set_items` | ensemble d'inventaire adressé par son empreinte ; ses composants avec origine (`syft`, `ia`), confiance, modèle, preuve, portée, licences, identification faible, emplacements (chemin réel, chemin d'accès, couche, preuve secondaire ; ADR 0057) |
| `sbom_blobs` | SBOM brut compressé, dédoublonné par empreinte SHA-256 |
| `ingestions` | réception d'un SBOM : statut, erreurs, instantané produit |
| `snapshots` | instantané d'une référence : commit, date, agent, version d'agent, blob, ensemble d'inventaire, statut et modèle de l'enrichissement IA déclarés par le SBOM (T12) |
| `ref_current` | instantané et ensemble courants de chaque référence (lecture rapide) |
| `set_diffs`, `set_diff_items` | différence entre deux ensembles d'inventaire d'instantanés consécutifs : décomptes, puis changements (ajout, retrait, montée, descente de version) (T17, ADR 0038) |
| `snapshot_retention` | dernier passage de la rétention : horizon (plus récente coupure appliquée), bilan (T17, ADR 0039) |
| `findings`, `finding_events` | constat (référence × composant × vulnérabilité) : première et dernière détection, résolution et motif, risque, base, statut de triage effectif et décision qui le donne (T14) ; historique (ouvert, résolu, rouvert) ; instantané qui l'a vu, mis à nul si la rétention le supprime |
| `ref_analyses` | dernière analyse de chaque référence : ensemble et base analysés |
| `audit_events`, `org_daily_stats`, `project_daily_stats` | journal d'audit ; statistiques quotidiennes de l'organisation et de chaque projet actif (une ligne par jour UTC, réécrite à chaque passage horaire, ADR 0027) |
| `triage_decisions` | journal des décisions de triage, en ajout seul : portée (projet et purl, ou organisation et `purl_base` avec plage `vers`), statut, justification VEX d'origine, commentaire, échéance d'un risque accepté, auteur (T14, ADR 0035) |
| `policies`, `policy_channels` | politiques : règle CEL, sujet (constat ou agent), active, bloquante, mode d'envoi, dernière erreur d'évaluation ; canaux de chaque politique (T15, ADR 0045) |
| `policy_violations`, `policy_evaluations` | violation d'une politique par un sujet (constat avec son projet et sa référence, ou agent), ouverte, prolongée, résolue, une seule ouverte par couple ; dernière évaluation de chaque référence, pour le verdict d'un instantané (T15) |
| `notification_channels`, `notification_deliveries` | canaux (e-mail, webhook, Matrix, Mattermost, Slack ; réglages en `jsonb`, secret chiffré par `internal/secret`, derniers envois) ; un envoi par couple (canal, violation), immédiat ou de résumé, en attente, envoyé ou écarté, réservé par l'envoi en cours (`claimed_at`) (T15, ADR 0046 ; T18, ADR 0052) |

Les **ensembles d'inventaire** sont adressés par contenu : deux instantanés au même
inventaire partagent le même ensemble. Un nouveau commit sans changement de dépendances
coûte une ligne, la différence entre instantanés est une différence entre ensembles, et la
rétention supprime les ensembles orphelins.

**Différences et rétention (T17).** La différence des instantanés consécutifs d'une
référence est calculée par le job `inventory.diff` (mis en file par l'ingestion d'un
instantané créé ou remplacé) et enregistrée par couple d'ensembles ; deux versions d'un
même `purl_base` forment une montée ou une descente, comparées par `internal/version` ;
une comparaison quelconque est calculée à la demande ; l'effet sur la sécurité (constats
introduits et résolus) est calculé à la lecture (ADR 0038). La rétention quotidienne
(`retention.snapshots_all`, puis une par organisation) garde tout `retention.days`
jours (90), puis le dernier instantané de chaque mois, jamais le dernier d'une référence
ni celui en vigueur au début de la fenêtre ; elle supprime les réceptions terminées hors
fenêtre, puis les ensembles et SBOM que plus rien ne référence (l'ingestion verrouille
ce qu'elle réutilise, la rétention le saute). Son horizon (`snapshot_retention`) dit à la
recherche à une date passée (T21) en deçà de quelle date l'historique est réduit
(ADR 0039). Le même passage supprime, avec tout leur historique, les projets des
conteneurs archivés pour absence depuis `containers.purge_after` (180 jours, jamais un
conteneur archivé à la main ni porteur d'une décision de triage), chaque suppression
journalisée (`project.purged`, T18, ADR 0049).

## 9. Multi-organisation

- Toute table d'organisation porte `org_id NOT NULL`. Les clés étrangères entre tables
  d'organisation sont **composites** : `snapshots (org_id, project_id)` référence
  `projects (org_id, id)`. Une ligne ne peut pas pointer vers une autre organisation.
- Les composants sont propres à chaque organisation : un purl de paquet privé ou une
  empreinte de fichier interne n'est jamais partagé. Seul le catalogue des vulnérabilités,
  public, est global.
- Les fonctions de store prennent un `tenant.OrgID` typé en premier paramètre métier.
- L'organisation courante vient de l'URL (`/o/{slug}/…`) côté web, du jeton côté agent et
  du chemin `/api/v1/orgs/{org}/…` côté API utilisateur. Un middleware vérifie
  l'appartenance avant tout handler et place `tenant.OrgID` dans le contexte.
- Une suite de tests d'isolement parcourt chaque route avec un compte d'une autre
  organisation et exige un 404 (jamais un 403, pour ne rien révéler).

### RLS obligatoire

- Toute table d'organisation a `ENABLE` et `FORCE ROW LEVEL SECURITY`, et une politique
  `USING (org_id = current_setting('lotor.org_id')::uuid)` avec la même condition en
  `WITH CHECK` (pour `organizations`, la colonne est `id`). PostgreSQL limite ainsi lecture
  et écriture à l'organisation déclarée, même si une requête oublie son filtre. Une
  migration la pose par `CALL lotor_enforce_org_rls('table')` (ou
  `('organizations', 'id')`) ; le démarrage refuse une table à `org_id NOT NULL` qui ne
  l'a pas, ou qui a en plus une politique permissive étrangère à `lotor.org_id`.
- `db.InOrg(ctx, orgID, fn)` ouvre une transaction et y déclare l'organisation par
  `set_config('lotor.org_id', $1, true)` : portée limitée à la transaction, donc
  compatible avec un pool de connexions et avec pgbouncer. C'est le seul accès aux tables
  d'organisation.
- Échec franc : hors `InOrg`, le paramètre est absent ou vide et sa conversion en `uuid`
  lève une erreur. Une requête sans organisation déclarée échoue ; elle ne renvoie jamais
  zéro ligne en silence.
- Le rôle d'exécution ne peut pas contourner la RLS (§ 6, § 7).
- Opérations inter-organisations : résolution d'un slug et de l'appartenance par la garde,
  liste des organisations d'un compte, liste des organisations pour la réanalyse (qui
  liste ensuite les références de chacune dans `InOrg`, ADR 0018) et pour les statistiques
  quotidiennes. Ce sont des fonctions
  `SECURITY DEFINER` du rôle propriétaire, à `search_path` fixé, qui ne renvoient que le
  strict nécessaire. Elles vivent toutes dans `internal/db/crossorg`, sont listées dans un
  ADR (0012 : `lotor_org_access`, `lotor_user_orgs`, `lotor_list_organizations`,
  `lotor_org_id_by_slug` ; 0014 : `lotor_agent_token_org`, `lotor_enrollment_token_org`,
  qui donnent l'organisation d'un jeton présenté à l'API des agents ; 0024 :
  `lotor_search_component_names`, `lotor_search_component_hashes`, qui ne sortent pas
  de l'organisation déclarée par `InOrg` mais contournent la RLS pour servir les index de
  recherche, § 13 ; 0034 : `lotor_user_invitations`, les invitations en attente adressées
  à l'e-mail d'un compte ; 0056 : `lotor_invitation_by_token`, l'invitation non expirée
  d'une organisation active désignée par l'identifiant public de son lien, pour le visiteur
  qui le présente), et tout ajout est relu comme un changement de sécurité.

### Équipes : filtre de visibilité à l'intérieur d'une organisation

- Tout projet appartient à une équipe. Un membre ne voit que les projets de ses équipes ;
  un administrateur d'organisation voit tout (ADR 0034).
- Une lecture pour un compte ouvre `InOrg` avec `db.Visible(tenant.Visibility)`, qui
  déclare les équipes visibles dans `lotor.teams` (« * » ou un tableau d'uuid), et filtre
  par la fonction SQL `lotor_team_visible(team_id)`. Sans déclaration, la fonction
  échoue : un filtre oublié ne montre jamais tous les projets.
- Ce filtre ne remplace pas la RLS : il s'applique à l'intérieur de l'organisation
  déclarée. Une ressource d'une équipe invisible répond 404, comme une ressource d'une
  autre organisation.
- La RLS s'ajoute aux autres protections sans les remplacer : PostgreSQL ne l'applique pas
  aux contrôles de clés étrangères (d'où les clés composites), et `tenant.OrgID` garde des
  erreurs claires et des plans de requête prévisibles.
- Les tables globales (§ 8) n'ont pas de RLS ; elles ne contiennent aucune donnée
  d'organisation.
- Tests propres à la RLS : dans `InOrg(A)`, des requêtes volontairement sans filtre
  `org_id` ne lisent ni n'écrivent aucune ligne de B ; hors `InOrg`, toute requête sur une
  table d'organisation échoue ; au démarrage, un rôle d'exécution trop puissant est refusé.

### Pourquoi pas un schéma par organisation

Écarté (ADR 0012). Tant qu'un seul rôle accède à tous les schémas, l'isolement reposerait
sur un `search_path` correctement positionné, soit la même discipline qu'un filtre oublié ;
un rôle par organisation imposerait un pool par organisation. Les migrations seraient
rejouées une fois par organisation, la création d'une organisation demanderait de créer des
tables à chaud (donc des droits de DDL pour l'application), et les traitements qui couvrent
toutes les organisations passeraient par du SQL dynamique. Le gain de volume est nul à
l'échelle visée : un index qui commence par `org_id` mène directement aux lignes de
l'organisation. Si une organisation devenait très volumineuse, le partitionnement des plus
grandes tables par `org_id` donnerait la même séparation physique en gardant la RLS.

## 10. Identité et accès

- Comptes : authx lit `users` et gère les sessions ; **la création et la modification des
  comptes reviennent au projet** (paquet `account`), qui écrit dans `users` avec
  `authx.HashPassword` et utilise sa colonne `must_change_pwd`. Ni authx ni mfax n'appliquent
  ce drapeau : un middleware du projet redirige vers le changement de mot de passe.
- Second facteur via `mfax` avec enrôlement **obligatoire** (ne jamais passer
  `WithOptionalEnrollment()`) et **verrouillage par compte** (`mfax.WithLockout`, table
  `mfa_lockouts`) : les codes faux sont comptés tous défis confondus (`mfa.lockout_*`),
  verrouillage journalisé (`account.locked`), levé par la réinitialisation du TOTP
  (ADR 0029).
- **Codes de secours** (`mfax.WithRecoveryCodes`, table `mfa_recovery_codes`, T18,
  ADR 0048) : un jeu de `mfa.recovery_codes` (10) codes à usage unique, hachés, montré une
  seule fois à l'enrôlement et à chaque régénération (code TOTP exigé) ; un code de secours
  remplace un code TOTP à la connexion et compte dans le verrouillage. Le titulaire
  reconfigure lui-même son application (`account.ReconfigureTOTP`, après un code TOTP ou
  un code de secours, et un **nouveau mot de passe** : SEC2-06, ADR 0051) : sessions fermées,
  nouvel enrôlement imposé par le nouveau mot de passe ; le TOTP reste obligatoire.
  `POST /account/totp/enable` ne « réactive » jamais un TOTP actif et ses codes faux comptent
  dans le verrouillage (open-go-base v1.4.1, SEC2-01).
- `session_auth` enregistre, pour chaque session (clé : SHA-256 du jeton de session), la
  méthode d'authentification : `local_totp`, ou `sso` avec l'organisation dont le
  fournisseur a authentifié. La garde d'organisation s'en sert pour imposer le SSO d'une
  organisation qui l'exige (T25), même pour un membre de plusieurs organisations.
- Premier administrateur créé au premier démarrage depuis `bootstrap.*` (ignoré dès qu'un
  compte existe) ; changement de mot de passe et enrôlement TOTP à la première connexion.
- Administrateur d'instance : rôle privilégié assumé (il peut réinitialiser le mot de passe
  et le TOTP d'un compte, chaque fois audité ; toute réinitialisation ferme les sessions
  et révoque les jetons personnels, celle du TOTP impose aussi un mot de passe temporaire,
  ADR 0029) ; deux administrateurs au moins sont
  recommandés et l'interface avertit s'il n'y en a qu'un. Procédure de secours documentée
  pour un administrateur unique qui perd son TOTP : `bootstrap.rescue_totp_email`,
  `bootstrap.rescue_ticket` et `bootstrap.rescue_password` (mot de passe temporaire
  imposé), lus au démarrage, appliqués une fois par ticket, audités, à retirer ensuite
  (ADR 0013, ADR 0029).
- Sessions : glissantes (`auth.session_ttl`) dans une durée absolue depuis la connexion
  (`login.session_max_age`, lue dans `session_auth.created_at`) ; jeton CSRF lié à la
  session (`csrfx.WithSessionBinding`), protection inter-origines, cookies `__Host-` quand
  `auth.cookie_secure` vaut `on` (ADR 0031).
- Secrets TOTP chiffrés en base par `internal/secret` (enveloppe du store de mfax),
  rechiffrés par la clé active au démarrage (ADR 0013).
- Un compte créé par un administrateur reçoit un mot de passe temporaire. **Inscription**
  (T28, ADR 0056) selon `signup.mode` : `private` (défaut, aucune), `invitation` (code
  d'inscription d'instance, usage unique) ou `public` (adresse vérifiée, domaines
  facultatifs) ; le compte inscrit choisit son mot de passe (`account.Register`), devient
  administrateur d'une organisation créée dans la même transaction `InOrg`, et passe par
  une session de configuration (`authx.PurposeSetup`) qui impose l'enrôlement du TOTP. Le
  courriel sert aux notifications et aux courriels transactionnels de l'inscription
  (`internal/mailer`) ; réinitialisation du mot de passe par courriel hors cahier des
  charges.
- Rôles (T16, décision du 1er novembre 2026, ADR 0034) : le rôle d'organisation vaut
  `member` ou `admin` (qui voit et gère tout) ; les droits sur un projet, un agent ou une
  équipe viennent du rôle dans l'équipe de la ressource : `reader` (consulte), `analyst`
  (trie les constats, importe un VEX pour un projet, demande un scan), `admin` (gère les
  projets, les agents, les jetons d'inscription et les membres de l'équipe). Décider du
  triage pour toute l'organisation (`triage.org`) revient à ses administrateurs (ADR 0035). Créer, renommer ou supprimer une équipe,
  inviter ou retirer un membre, les paramètres et le journal de l'organisation restent à
  ses administrateurs. La matrice est la source unique des contrôles, du document
  `docs/security/permissions.md` et des tests par route (`tenant.Matrix`, table
  `orgRoutes` de `internal/web`). L'existant est passé dans une équipe « Général ».
- Envoi du code d'un dépôt à un fournisseur de modèle externe : permission d'organisation
  `ai.external` (administrateur d'organisation), chaque changement de réglage audité ;
  `ai.forbid_external` l'interdit sur toute l'instance (T12, ADR 0043).
- Un compte devient membre d'une organisation en **acceptant une invitation** (30 jours ;
  réponse identique que le compte existe ou non, SEC-09) ; seul l'administrateur de
  l'instance ajoute directement un membre. Le lien secret d'une invitation (T28), envoyé
  dans la langue de l'invitant ou montré une fois, crée dans tous les modes le compte de
  l'adresse invitée (imposée) ou fait accepter le compte connecté de cette adresse.
- Jetons : préfixés par leur nature (`lotor_agt_`, `lotor_enr_`, `lotor_pat_` ; T28 :
  `lotor_sgn_` code d'inscription, `lotor_vrf_` vérification d'adresse, `lotor_inv_` lien
  d'invitation), puis un
  identifiant public (128 bits) et un secret de 256 bits, en base32 minuscule séparés par
  `_`. Seul le SHA-256 du secret est stocké ; comparaison en temps constant ; révocation
  immédiate ; date de dernier usage (écrite une fois par minute au plus). L'organisation
  d'un jeton d'agent est résolue par `crossorg`, le reste vérifié dans `InOrg` (ADR 0014).
  Un jeton personnel appartient au compte (table globale) : lecture seule, valable dans
  les organisations dont son propriétaire est membre au moment de chaque requête
  (`crossorg.Access`), avec ses rôles d'équipe du moment (ADR 0034), 7 jours à 1 an,
  20 actifs au plus (ADR 0025) ; création soumise à
  un code TOTP (`mfax.Service.Confirm`), révocation d'office à la réinitialisation ou au
  changement des identifiants, refus pour un compte en attente (ADR 0029).
- Agents : un projet est confié à au plus un agent de même nature (clé étrangère
  composite) ; un agent serveur couvre un seul hôte, dont le projet est créé ou rattaché à
  l'inscription (par le nom d'hôte déclaré, seulement dans l'équipe du jeton : SEC2-02) ;
  un agent dépôt reçoit ses dépôts depuis leur fiche.
- Limitation de débit : par IP pour l'interface (open-go-base ; une IPv6 compte pour son
  /64) ; **par jeton** pour l'API agent et l'API utilisateur, pour que des hôtes derrière
  une même sortie NAT ne se gênent pas.

## 11. Pipeline d'ingestion

1. `POST /api/v1/agent/ingestions` (jeton d'agent), multipart dans cet ordre : `context`
   (JSON : projet, référence, commit, version d'agent, date de scan) puis `sbom` (JSON, gzip
   de préférence). Contrôles synchrones : contexte, référence confiée à l'agent
   (`project.RefForAgent`, avant toute lecture du SBOM et de nouveau dans la transaction),
   taille reçue (413 au-delà, sans ingestion), taille décompressée d'un envoi gzip. Le blob
   (gzip, dédoublonné par le SHA-256 du JSON) est stocké, l'ingestion créée, un job
   `ingest.decode` mis en file dans la même transaction ; réponse `202`. Un envoi
   impossible à stocker (gzip corrompu, trop gros décompressé) donne une ingestion
   `failed` ; le même SBOM renvoyé pour la même référence et le même commit d'un dépôt
   renvoie l'ingestion existante (`200`), sans rien créer. Au-delà des quotas
   (`ingest.max_per_ref_per_day`, `ingest.max_org_storage_mib`), l'envoi est refusé (`429`)
   et rien n'est stocké (ADR 0030).
2. `ingest.decode` :
   - bornes préalables par lecture en flux, avant tout décodage complet : taille
     décompressée, profondeur JSON, nombre de composants (`sbom.Precheck`) ;
   - validation par le schéma officiel embarqué (`sbom/schema` ; l'énumération des
     licences SPDX de CycloneDX n'est pas imposée à la réception, ADR 0016) ;
   - décodage par `sbom/syft` (décodeurs de Syft, ceux de Grype) vers `sbom.Document`,
     normalisation des purl et fusion des doublons ;
   - calcul de l'**empreinte d'inventaire** (composants canoniques triés, origine, preuve,
     emplacements ; `lotor-inventory-v2`, ADR 0057), indépendante des horodatages et numéros de série du document ;
   - dans une transaction, référence verrouillée : upsert trié des composants de
     l'organisation, ensemble d'inventaire réutilisé ou créé, instantané, `ref_current`,
     fin de l'ingestion ; un SBOM refusé termine l'ingestion en `failed` avec sa clé, sans
     rien ranger.
3. Règle d'instantané : pour un dépôt, un instantané par (référence, commit), même si
   l'inventaire n'a pas changé (il réutilise alors l'ensemble existant) ; le même commit
   renvoyé avec un autre inventaire remplace l'ensemble de son instantané. Pour un hôte, un
   conteneur ou une version reçue par le point compatible Dependency-Track (sans commit),
   un inventaire identique au courant met seulement à jour la date de dernière analyse. L'instantané courant est le plus récent par date de scan.
4. Si l'ensemble courant de la référence a changé, job `analysis.ref` (charge
   `{"ref_id"}`, clé `ref:<id>`, priorité haute) mis en file dans la même transaction.
5. Archives hors ligne (T23, ADR 0060, `internal/offline`, `ingest.Importer`) : un tar
   manifeste, codes et SBOM, authentifié par un HMAC de clé l'empreinte du jeton de
   l'agent ; importé par l'écran, `POST /api/v1/orgs/{org}/archives` ou `offline.watch_dir`,
   puis `Authorize` et `Receive` au nom de l'agent ; dédoublonné par l'empreinte du
   manifeste (`ingestions.archive_sha256`). La première archive d'un agent serveur jamais
   connecté l'inscrit avec le jeton qu'il a tiré.
6. `GET /api/v1/agent/ingestions/{id}` expose le statut (`queued`, `processing`, `done`,
   `failed` + clé d'erreur traduisible) et l'instantané produit.

Formats acceptés : CycloneDX JSON 1.5 à 1.7, SPDX JSON 2.3, Syft JSON. Pas de XML.
Canonicalisation des purl : encodage, casse et tri des qualificatifs normalisés selon la
spécification purl, telle que l'applique `packageurl-go` (ADR 0016) ; **les qualificatifs
d'identité (`distro`, `arch`, `epoch`, `upstream`…) sont conservés**, car Grype en a
besoin. Un composant sans purl utilisable reçoit `pkg:generic/<nom>@<version>` et
l'« identification faible ». Les CPE sont conservés. Propriétés CycloneDX propres
au projet, espace de noms `lotor:` : `lotor:origin` (`syft` ou `ia`), `lotor:confidence` (0 à 1),
`lotor:model` ; la preuve IA utilise le champ standard `evidence` (occurrence : fichier,
ligne, extrait). Dans les métadonnées du document, `lotor:enrichment` (`complete`,
`incomplete`, `carried`), `lotor:enrichment-model` et `lotor:enrichment-prompt` décrivent
l'enrichissement IA ; le serveur range statut et modèle avec l'instantané (ADR 0043).
Les **emplacements** notés par Syft (`locations` du Syft JSON, propriétés
`syft:location:N:path` et `syft:location:N:layerID` de CycloneDX ; aucun en SPDX) sont
gardés par élément d'ensemble, 32 au plus, principaux d'abord (annotation `evidence` :
`supporting` les marque secondaires), et affichés avec les constats et les composants
(ADR 0057).

Le décodage s'exécute dans le processus worker ; les bornes préalables, le délai du job
et le plafond de jobs simultanés par organisation (`workers.org_limit`) empêchent un seul
agent de saturer une instance. L'isolation en sous-processus a été étudiée et écartée tant
qu'aucune mesure ne la justifie (ADR 0015).

## 12. Analyse de vulnérabilités

- **Grype reçoit le SBOM d'origine**, pas une reconstruction : `vuln.Matcher.Match(ctx,
  blob)` ; l'adaptateur `vuln/grype` décode le blob avec Syft (distribution, CPE,
  paquets sources, métadonnées intacts), lance la correspondance, puis rattache chaque
  résultat au composant par son purl canonique. Le reste du code ne connaît pas Grype.
- `analysis.ref` analyse **l'ensemble courant de la référence au moment de l'exécution**
  (le plus récent gagne). La correspondance se fait hors transaction ; l'écriture des
  constats se fait sous verrou de ligne sur la référence, après avoir vérifié que
  l'ensemble courant et la base cible sont toujours ceux de la correspondance (sinon
  l'analyse s'efface ou recommence) : deux analyses de la même référence ne mêlent jamais
  leurs écritures (ADR 0018). Même ensemble et même base que la dernière analyse : rien à
  faire. Constats : nouveaux couples créés, couples revus prolongés, couples absents
  résolus (composant retiré ou plus signalé), un couple résolu qui réapparaît est rouvert ;
  `finding_events` garde l'historique.
- Identifiants ramenés au CVE quand la source n'en cite qu'un (`--by-cve`) ; fiche du
  catalogue prise au NVD quand la base l'a.
- Base Grype, version cible commune à toutes les instances :
  - l'échéance `vulndb.check` (une seule instance l'exécute, § 16) interroge la liste de
    distribution, télécharge, vérifie la somme de contrôle, valide l'ouverture par une
    installation complète, stocke l'archive par blocs dans `vulndb_archives` et fixe la
    nouvelle cible dans `vulndb_state` (ADR 0017) ;
  - hors ligne, l'archive est téléversée depuis l'écran d'administration : lue en flux,
    rangée par blocs dans PostgreSQL (`vulndb_imports`), puis installée par un job
    `vulndb.import` sur une instance worker, avec les mêmes contrôles, et elle devient la
    cible (ADR 0028) ; la purge supprime les archives qui ne sont pas la cible ;
  - chaque instance worker synchronise sa copie locale sur la cible, bascule atomiquement et
    garde une seule base ouverte, derrière un verrou lecture/écriture ; elle rapporte la
    version chargée dans `vulndb_instances`, affichée par l'écran d'administration ;
  - un job d'analyse exige la version cible : un worker en retard se synchronise avant de
    le traiter. Chaque constat note la version de base qui l'a produit.
- Changement de cible → `analysis.rescan_all` met en file un `analysis.rescan_org` par
  organisation active, qui met en file un `analysis.ref` par référence active, en priorité
  basse.
- Une base plus vieille que `vulndb.max_age` (5 jours) déclenche une alerte sur chaque page
  d'administration et la métrique `lotor_vulndb_stale`.
- **Triage** (T14, ADR 0035) : les décisions s'appliquent aux constats après la
  correspondance, jamais dans Grype. Le statut effectif (décision du projet pour le
  composant, sinon la plus récente décision de l'organisation dont la plage contient la
  version, sinon « à analyser ») est rangé sur chaque constat ; `internal/triage` le
  recalcule à chaque décision pour tout le couple (`purl_base`, vulnérabilité), et
  `analysis.ref` classe les constats qu'il crée ou rouvre dans sa transaction
  (`finding.Classifier`), sous un verrou consultatif partagé par organisation que les
  décisions prennent en exclusif. Un risque accepté échoit par le job `triage.expire`,
  mis en file pour le lendemain de sa date à minuit UTC. Échanges VEX : OpenVEX 0.2.0 et
  CycloneDX 1.6 (ADR 0036).

- **Politiques** (T15, ADR 0045) : règles CEL sur un contexte typé (`project`, `component`,
  `finding`, `triage`, `ref` ou `agent`, et `now`), compilées et dont le coût estimé est
  borné à l'enregistrement, le coût réel à chaque évaluation. `analysis.ref` met en file
  `policy.evaluate_project` dans sa transaction (`finding.Options.OnAnalyzed`), comme un
  changement de statut de triage (`triage.Options.OnChange`) ; `policy.evaluate_all`
  (chaque jour) puis `policy.evaluate_org` évaluent les agents et chaque projet. Une
  violation par couple (règle, sujet), résolue dès que la règle cesse d'être vraie ;
  à son ouverture, `notify.Queue` crée ses envois. Le verdict d'un instantané est en
  attente tant que son ensemble n'est pas l'ensemble analysé et évalué de sa référence,
  non conforme s'il reste une violation ouverte d'une règle bloquante.

- **Licences** (T20, ADR 0061) : `internal/license` lit les expressions SPDX et les
  confronte à la politique de l'organisation (`license_policies` ; sans ligne, toute
  licence SPDX connue est acceptée ; une licence inconnue ou en texte libre est toujours à
  revoir ; `OR` retient le plus favorable, `AND` le moins favorable). La liste SPDX est
  celle du schéma CycloneDX 1.6 embarqué. Constats `license_findings` par (référence,
  composant), au cycle de vie des constats de vulnérabilité, évalués dans la transaction de
  l'analyse (`finding.Options.OnAnalyzed`, avant les politiques) et réévalués par
  `license.evaluate_org` après un changement de politique ; un changement met en file
  l'évaluation des politiques du projet, dont le sujet `license` ouvre des violations.

## 13. Recherche

- Une barre unique ; le type de requête est déduit : `pkg:` → purl, `CVE-`/`GHSA-` →
  vulnérabilité, `sha256:` ou 64 caractères hexadécimaux → empreinte, `license:` →
  licence, sinon nom de composant (approché par trigrammes). `license:<identifiant>`
  retient en Go les expressions de licence de l'organisation qui citent l'identifiant
  (`license_expressions`), puis SQL les éléments d'inventaire qui en portent une (ADR 0061).
- Une plage de versions `vers` ne s'applique qu'à un `purl_base` exact : SQL réduit
  l'ensemble à ce paquet (un nombre borné de versions), puis Go compare les versions par
  l'écosystème. Une recherche approchée par nom n'accepte pas de plage.
- Exécution sur `ref_current` + `component_set_items` + `components` (+ `findings` pour la
  pire vulnérabilité, ou pour une recherche par vulnérabilité), filtrée par organisation
  (RLS) et par équipe (`lotor_team_visible`, ADR 0034). Résultats groupés par projet, paginés par curseur sur les
  projets (risque, nom ou instantané), exportables en CSV et JSON en flux ; mêmes
  paramètres d'URL pour l'écran et l'API (`search.Request`).
- La RLS ajoute le filtre d'organisation à chaque requête, et un opérateur non
  `LEAKPROOF` (trigrammes, `ILIKE`, `@>` sur un tableau) ne peut alors pas servir de
  condition d'index. Les recherches par nom et par empreinte passent donc par deux
  fonctions `SECURITY DEFINER` de `crossorg` qui lisent l'organisation dans
  `lotor.org_id` et appliquent elles-mêmes la condition de la politique, sur des index
  GIN composites (`btree_gin`) qui commencent par `org_id` ; le reste de la recherche
  s'exécute sous la RLS sur des index B-tree (ADR 0024). Versions comparées par
  `internal/version` (ADR 0026).
- Les conteneurs (projets enfants des hôtes) sont écartés des résultats, comme des listes
  de projets, sauf avec le filtre « inclure les conteneurs » (`containers=1`), qui
  s'ajoute aux types retenus (ADR 0040).
- Filtre « équipe » (`team`, équipes propriétaires, sous la visibilité du compte) pour
  toute recherche ; une recherche par vulnérabilité montre et filtre (`triage`) le statut
  de triage effectif de chaque constat ; une recherche par composant ne compte pas les
  constats « non affecté » ou « faux positif » (T18, ADR 0050).
- Cible : moins de 2 s au 95e centile pour 1 000 projets et 1 million de liens, **RLS
  active**, selon le protocole de `docs/benchmarks.md`.
- À une date passée (T21, ADR 0059, paramètre `at`, `Filters.At`) : pour chaque référence,
  l'instantané en vigueur (le dernier scanné avant l'instant, fin de journée UTC pour une
  date) est lu par `snapshots_ref_idx`, au lieu de `ref_current` ; projets archivés et
  références retirées compris ; composants seulement (ni constats, ni sévérité, ni KEV) ;
  avertissement « partiel » avant l'horizon de la rétention (`inventory.ReadRetention`).
  Cible : moins de 5 s au 95e centile avec 12 mois d'historique hebdomadaire.

## 14. Interface web

- **Design de référence** : canevas
  [« lotor — Interface »](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj) (fondations,
  composants, huit écrans en thème clair, thème sombre, mobile). Sa feuille `project/ogs.css`
  est la source des tokens et des composants portés dans `web/static/css` (T01) ; sa
  racine `.ogs` devient `.lotor` au portage, et le thème se choisit par `data-theme`.
  Ses polices (Atkinson Hyperlegible Next et Mono, licence OFL) sont auto-hébergées et
  embarquées, jamais chargées depuis un CDN (CSP `'self'`). Chaque fiche de lot à écran
  nomme ses planches.
- Routeur chi avec **trois groupes de routes** :
  - interface : identifiant de requête → limitation par IP → journalisation → récupération
    de panique → en-têtes de sécurité → session (authx) → changement de mot de passe imposé
    → protection inter-origines → CSRF (csrfx, jeton lié à la session) → langue →
    organisation courante (rôles d'équipe compris) → droit de la route (table
    `orgRoutes` : permission et ressource qui porte l'équipe ; 404 pour une ressource
    invisible, 403 pour un droit manquant) → handler ;
  - API agent (`/api/v1/agent/`) : jeton d'agent, limitation par jeton, pas de session ni
    de CSRF ;
  - API utilisateur (`/api/v1/orgs/{org}/`) : jeton personnel sans CSRF, garde
    d'organisation à chaque requête (404 hors des organisations du compte), limitation par
    jeton ; la session avec en-tête CSRF viendra avec le premier écran qui appelle l'API
    en JavaScript (ADR 0025).
- Corps des requêtes de l'interface bornés à 64 Kio avant CSRF ; l'import d'un VEX
  (T14) est borné à 1 Mio pour un compte authentifié, lu en mémoire par csrfx (ADR 0036) ;
  seule autre exception, le
  téléversement d'une archive de la base (`POST /admin/vulndb/import`), borné à
  `vulndb.max_archive_mib` pour un administrateur d'instance seulement, lu en flux, jeton
  CSRF exigé en première partie du formulaire (ADR 0028).
- CSP : `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
  frame-ancestors 'none'; form-action 'self'; base-uri 'none'`. Aucun script ni style en
  ligne. Réponses d'API : `default-src 'none'; frame-ancestors 'none'; base-uri 'none'`.
- Gabarits `html/template` : un layout, des partials, un dossier par écran. Chaque écran a
  un modèle de vue typé construit dans `internal/web/<écran>` ; les gabarits ne font que de
  l'affichage. Les fonctions de traduction sont liées à un jeu de gabarits par page et par
  langue, préparé au démarrage ; ce qui dépend de la requête (jeton CSRF, thème,
  identifiant de requête) passe par `render.Page`, que le rendu remplit (ADR 0009).
- CSS natif imbriqué, sans préprocesseur : `tokens.css` (propriétés personnalisées, thèmes
  clair et sombre : couleurs en `light-dark()`, qui suit `prefers-color-scheme`, et
  `color-scheme` imposé par `[data-theme]`), `fonts.css`, `base.css`, un fichier par
  composant et par écran. Modificateurs BEM écrits `&.bloc--modificateur`. Au démarrage, le
  serveur concatène les feuilles embarquées en `css/app.css` et sert tous les fichiers
  statiques sous `/static/<empreinte>/` (immuables, un an de cache). La bascule de thème
  mémorise le choix dans `localStorage` et dans le cookie `lotor_theme`, que le serveur
  lit pour rendre `data-theme` dès la première peinture, sans script en ligne.
- **Exception : le gabarit HTML des courriels** (`internal/delivery/templates/`, ADR 0056)
  n'est pas une page de l'interface : CSS à plat et couleurs en styles en ligne (les
  messageries ne comprennent pas le CSS imbriqué, et le mode sombre de Thunderbird
  réécrit les styles), logo PNG joint au message (`cid:`), couleurs propres choisies pour
  survivre à ce mode sombre (seule « Critique » reprend `tokens.css`), textes traduits
  depuis Go hormis « lotor ».
- JavaScript : modules ES natifs, un par écran, amélioration progressive ; chaque page
  fonctionne sans JS. Les libellés arrivent traduits via des attributs `data-`.
- Graphiques en SVG produits côté serveur, avec titre, description et tableau de données :
  géométrie dans `internal/render/chart.go`, dessin dans `partials/charts.html`, couleurs
  par classes ; l'assistant de `webtest` exige qu'un `<svg>` soit décoratif
  (`aria-hidden`) ou une image nommée (`role="img"`), ADR 0027.
- Accessibilité RGAA / WCAG 2.1 AA : HTML sémantique, lien d'évitement, focus visible,
  sévérité jamais portée par la seule couleur ni la seule forme (libellé écrit, au moins
  abrégé). Des tests Go analysent le HTML rendu ; un audit manuel clôt chaque lot
  fonctionnel (grilles : `docs/accessibilite/grille-rgaa-lot1.md`,
  `docs/accessibilite/grille-rgaa-lot2.md`). Conventions issues de ces audits (T11, T18) :
  - **action irréversible** (révoquer, désactiver, retirer, réinitialiser, supprimer) :
    l'écran n'a qu'un lien vers l'URL de l'action ; un `GET` sur cette URL rend la page
    de confirmation commune (`confirm/action`, `identity.confirm` : objet nommé,
    conséquences, bouton d'action, lien « Annuler »), sans effet et avec les mêmes 404
    que le `POST`, qui agit. Une action réversible (archiver, réactiver, rétablir un
    rôle) agit en un clic ;
  - **titre de page** : « écran — organisation · lotor », préfixé « Erreur : »
    quand un écran est rendu avec un statut 4xx (`render.Page.Failed`) ;
  - **plan du site** `/sitemap`, lié du pied de page, construit par les fonctions des
    navigations latérales : une rubrique ajoutée à une navigation y paraît d'elle-même ;
  - zone défilante d'un tableau : `role="group"` nommé et `tabindex="0"`, jamais une
    seconde région du même nom que son panneau.
  - **une étiquette, un champ** : un champ révélé par un choix (justification d'un statut,
    date d'échéance) vit hors de l'étiquette du bouton radio, dans l'élément de liste
    (`li.choice-item`), jamais dans la `<label>` (`webtest` refuse une étiquette imbriquée
    ou à plusieurs champs) ;
  - **valeurs traduites** : une valeur d'énumération (statut, nature) paraît par son
    libellé traduit partout, titres et paramètres de traduction compris, jamais par sa
    valeur technique ; un décompte passe par `Tn` ;
  - **titre d'une fiche rattachée à un projet** : il nomme le projet (et la référence)
    quand le même objet peut exister dans plusieurs projets.

## 15. API REST

- `api/openapi.yaml` est la source unique, en OpenAPI 3.1.0 (ADR 0006) ; serveur et client
  des agents sont générés par oapi-codegen dans `internal/api/gen` et
  `internal/agentclient/gen`, le serveur de l'API utilisateur (non strict : l'export écrit
  en flux) dans `internal/api/gen/userapi`. `make generate-check` vérifie en CI que le code généré est à
  jour.
- Préfixe `/api/v1`. Routes des agents sous `/api/v1/agent/` (dont le verdict des
  politiques sur un instantané, `GET /api/v1/agent/snapshots/{id}/verdict`, T15), routes utilisateur sous
  `/api/v1/orgs/{org}/`. Le point compatible Dependency-Track (T19, ADR 0058) vit sous `/dt/`
  pour ne pas mêler son espace d'URL au nôtre : `PUT`/`POST /dt/api/v1/bom` et
  `GET /dt/api/v1/event/token/{uuid}` (et `bom/token`, chemin de la 4.x), écrits à la main
  (contrat de Dependency-Track, pas le nôtre), mêmes middlewares que l'API des agents, clé
  `X-Api-Key` = jeton d'agent dépôt, nom de projet = dépôt confié à l'agent, version =
  référence de nature `version`, création automatique autorisée par agent d'équipe. L'API utilisateur exporte le VEX d'un projet
  (`GET /api/v1/orgs/{org}/projects/{project}/vex`, T14).
- Erreurs au format RFC 9457 (`application/problem+json`) : `type` porte une clé stable
  (`error.ingest.too_large`), `title` et `detail` les messages traduits de
  `<clé>.title` et `<clé>.text` selon la langue de la requête, `instance` le chemin et
  `request_id` l'identifiant de requête (`internal/api/problem`).
- Pagination par curseur opaque. Toute réponse liste est bornée.

## 16. File de traitements

`internal/jobs`, sur PostgreSQL, sans dépendance, sémantique **au moins une fois** :

- Table `jobs` : type, organisation (facultative), charge JSON, priorité, statut,
  tentatives, prochaine exécution, bail (`locked_until`), clé d'unicité, dernière erreur.
- Prise par `SELECT … FOR UPDATE SKIP LOCKED` ; bail renouvelé pendant l'exécution ; un job
  dont le bail expire est repris. Chaque handler est idempotent (exigence de revue).
- La table `jobs` est globale ; un handler qui touche des données d'organisation travaille
  dans `InOrg(job.OrgID)`. Les rares jobs inter-organisations (`analysis.rescan_all`,
  statistiques quotidiennes, archivage des conteneurs absents) obtiennent leur liste par une fonction de `crossorg`, puis
  mettent en file un job par organisation.
- Réessais à délai exponentiel avec gigue ; au-delà du maximum, statut `dead`.
- Clé d'unicité sur les jobs en attente ; une seconde mise en file **relève la priorité** et
  avance l'échéance si besoin (`ON CONFLICT … DO UPDATE`) : une ingestion fraîche n'attend
  pas derrière une réanalyse de fond.
- Plafond de jobs simultanés par organisation pour les types lourds (décodage, analyse) :
  une organisation ne peut pas affamer les autres.
- Planificateur : une ligne par échéance dans `schedules` ; chaque instance tente
  `UPDATE schedules SET next_run_at = … WHERE name = … AND next_run_at <= now() RETURNING …`
  et seule celle qui obtient la ligne met le travail en file. Pas de verrou de session :
  robuste aux coupures de connexion et à pgbouncer.
- Détails (ADR 0011) : dates calculées par une horloge Go injectable (`jobs.Clock`),
  jamais par `now()` de PostgreSQL, d'où des instances synchronisées par NTP ; prise des
  jobs au bail expiré d'abord, puis des jobs en attente par l'index partiel ; plafond tenu
  strictement par un verrou consultatif de transaction par (type, organisation) ;
  `lease_token` pour ignorer le résultat d'un bail perdu ; transitions d'état du runner
  validées en `synchronous_commit = off` ; `Stop` remet en attente, sans compter la
  tentative, les jobs encore en cours à l'approche de son délai ; échéances sur une grille
  UTC fixe ; purge des jobs terminés et passage en `dead` des jobs épuisés au bail expiré
  par une maintenance sur chaque instance.

## 17. Agents

- Client API commun `agentclient` : le client généré (`agentclient/gen`) enveloppé d'un
  transport HTTPS (autorité privée, certificat client relu à chaud, mandataire, aucune
  redirection suivie), de réessais bornés (erreur réseau, 429, 5xx ; délai exponentiel à
  gigue ; `Retry-After` respecté, abandon s'il dépasse la politique), d'erreurs RFC 9457
  exposées par leur clé (`agentclient.Error`, `IsKey`), de l'envoi multipart d'un SBOM
  (contexte, puis SBOM en gzip, corps rejoué à chaque tentative) et du suivi d'une
  ingestion jusqu'à son état final (T07, `doc.go`) ; client de Dependency-Track
  `DTClient` (T19 : `PUT /api/v1/bom` en JSON, suivi par `event/token`, mêmes transport et
  réessais).
- Inscription : jeton d'inscription → jeton d'agent stocké dans le répertoire d'état
  (droits `0600`).
- Secrets des agents (jeton, clés de forge, clés d'API des modèles) : jamais dans le fichier
  de configuration. Ils sont fournis par les credentials systemd (`LoadCredentialEncrypted=`,
  chiffrés au repos) ou par des fichiers en `0600`, au choix de l'exploitant.
- `lotor-host-agent` (T07, ADR 0020 et 0021) : configuration `LOTOR_HOST_AGENT_*`
  (`deploy/host-agent/config.example.yaml`), modes `daemon` et `oneshot` ; scan de `/`
  par Syft (catalogueurs d'un système installé, sans catalogage de fichiers, systèmes
  virtuels, stockages de conteneurs, répertoires de données et montages réseau ou de
  conteneurs exclus), sur un index compact de l'arborescence au lieu de la source
  « répertoire » de Syft, qui lit l'en-tête de chaque fichier (ADR 0055) ;
  empreinte d'inventaire calculée par `sbom/syft.Decode` et `sbom.Fingerprint`, comme à
  l'ingestion ; inchangée, un signal de vie la soumet (`HeartbeatRequest.inventory`) et
  le serveur avance la date de dernière analyse ou réclame le SBOM ; changée, le SBOM part
  en Syft JSON. Le signal de vie remet une fois la demande « Scanner maintenant ». État
  muet d'un agent serveur fondé sur son dernier inventaire, d'un agent dépôt sur son
  dernier contact, au-delà de 7 jours (T10, ADR 0027). Unités systemd durcies (`CAP_DAC_READ_SEARCH` seule), paquets deb et
  rpm (nfpm, `make packages`). Avec `tls.client_ca_file`, l'API des agents exige un
  certificat client vérifié. Conteneurs (T13, ADR 0040 et 0041) : inventaire désactivé
  par défaut (`containers.enabled` ; sans lui, aucune socket ouverte), API Docker de
  Docker ou Podman sur socket Unix, identité `projet/service` Compose sinon nom du
  conteneur (`hostagent.Identity`), signalement `POST /api/v1/agent/containers` (le
  serveur crée les projets enfants sous l'hôte de l'agent seul), image exportée
  (`docker save`) et scannée hors ligne une fois par image, empreintes d'images gardées
  et confirmées par le serveur. Sortie vers Dependency-Track (T19, ADR 0058) : SBOM réencodé
  en CycloneDX 1.6 et envoyé quand l'empreinte diffère du dernier envoi accepté, en plus de
  lotor ou à sa place (`dependency_track.only`). Suite : T22 (Windows, containerd), T23
  (hors ligne, fait : ADR 0060, `offline.dir` et `offline.only`, inscription par archive).
- `lotor-repo-agent` : service externe qui détient seul les secrets des forges. Il reçoit les
  webhooks, clone, analyse, envoie, puis attend le verdict du serveur pour publier le statut
  de commit (T15, ADR 0047 : attente bornée par `status.timeout`, statut « en attente »
  puis verdict, désactivé par défaut ; jeton GitHub séparé limité à `statuses: write`).
  Tout accès au contenu d'un dépôt passe par `os.Root` (aucune sortie de
  l'arborescence, aucun lien symbolique suivi hors d'elle). Voir T08 et T12.
  Détails (ADR 0023) : un webhook vérifié n'est qu'un signal, l'agent résout lui-même la
  tête de la référence ; rattrapage au démarrage et à intervalle depuis le commit du
  dernier instantané, commits manqués du plus ancien au plus récent ; file en mémoire
  bornée, une référence jamais traitée deux fois à la fois ; extraction du commit exact
  par `git fetch --depth 1 <url> <commit>` sous environnement maîtrisé
  (`core.symlinks=false` : aucun lien symbolique sur disque, ce qu'un parcours par
  `os.Root` vérifie ; crochets et LFS inertes ; identifiants par `GIT_CONFIG_*`), taille
  mesurée pendant le clonage ; Syft, qui lit l'arborescence par son propre résolveur
  borné à sa racine, hors ligne et sans exécution (`golang.UsePackagesLib=false`) ; SBOM
  CycloneDX 1.6 déterministe (ni numéro de série ni horodatage) ; secrets désignés par
  `credential:<nom>` ou par un fichier `0600`. Configuration (`LOTOR_REPO_*`) et unité
  systemd : `deploy/lotor-repo-agent/`.
  Enrichissement IA (T12, ADR 0042 à 0044) : si le réglage effectif du projet transmis
  par le serveur le permet et qu'un modèle est configuré (`ai.local` Ollama,
  `ai.external` Anthropic), un modèle explore l'arborescence par `list_dir`, `read_file`
  et `search` (lecture seule, `os.Root`, bornés, fichiers sensibles exclus) et soumet ses
  candidats par `submit_candidates` (schéma JSON) ; un vérificateur déterministe, seul
  juge, relit chaque preuve dans le fichier ; les composants acceptés rejoignent le SBOM
  Syft (Syft l'emporte). Budget dépassé ou erreur du fournisseur : SBOM Syft seul, marqué
  incomplet. Analyse incrémentale (fichiers modifiés selon la forge, composants IA
  précédents lus par `GET /api/v1/agent/refs/{id}/ai-components` et revérifiés), complète
  à `ai.full_interval` ; prompt système versionné et embarqué ; analyse dans le processus
  de l'agent, confinée par la surface d'outils et `os.Root` (ADR 0044). Qualité mesurée
  sur le corpus annoté `testdata/ai-corpus` et sur l'échantillon pilote annoté
  `testdata/ai-pilot` (`make eval-ai`) ; chaque composant accepté est revérifié hors du
  vérificateur (`checkProof`, en CI sur le corpus). Un composant IA est toujours de type
  CycloneDX `library`, image comprise : le décodeur du serveur ignore le type
  `container` (T18). Sortie vers Dependency-Track (T19, ADR 0058) : SBOM du commit de tête
  de chaque référence, après lotor, projet et version par gabarits.

## 18. Internationalisation

- `locales/en.yaml` et `locales/fr.yaml`, embarqués (`i18n.NewFS`). Langue choisie dans cet
  ordre : `?lang=`, préférence du compte, `Accept-Language`, langue de l'organisation, langue
  par défaut de l'instance. Le middleware de langue précède la garde d'organisation
  (§ 14) : celle-ci (T03) recalcule la langue avec la langue de l'organisation
  (`middleware.ResolveLanguage`). Hors requête, `locale.Catalog` donne le localiseur
  d'une langue.
- Clés en anglais `écran.élément` (`login.email`, `search.placeholder`). Racines
  transverses : `format.*`, `status.*`, `severity.*`, `validation.*`, `error.*`, `nav.*`.
- Le code serveur ne concatène jamais de fragments traduits : il renvoie une clé et des
  paramètres que le gabarit résout, ou reçoit le traducteur.
- Les textes émis hors ligne de requête (notifications, résumés) utilisent la langue de
  l'organisation.
- Un test échoue si une clé manque dans une langue ou si un gabarit utilise une clé absente.

## 19. Sécurité transverse

- Modèle de menace tenu à jour dans `docs/security/threat-model.md` (créé en T00).
- Secrets stockés en base (secrets des canaux de notification, secret client OIDC…)
  chiffrés en AES-256-GCM par `internal/secret`, clé maîtresse en configuration,
  identifiant de clé stocké avec le chiffré pour permettre la rotation. Les secrets des
  forges ne sont jamais en base : ils restent dans l'agent dépôt.
- Aucune donnée sensible dans les journaux (mots de passe, jetons, contenu de SBOM).
- Requêtes sortantes vers une URL saisie par une organisation (canaux de notification) :
  adresses de bouclage, privées, de lien local, partagées et de multidiffusion refusées à
  la connexion, après résolution DNS (`notify.allow_private_networks` pour un relais
  interne), aucune redirection ni mandataire, durée et réponse bornées (`internal/delivery`,
  ADR 0046).
- Entrées bornées partout : taille de requête, taille décompressée, profondeur JSON, nombre
  de composants.
- Contenu des dépôts et des SBOM traité comme non fiable, y compris par l'agent IA
  (injection d'instructions).
- L'accès à la socket d'un moteur de conteneurs équivaut à root : désactivé par défaut,
  documenté comme tel.
- Journal d'audit : connexions et échecs, comptes et rôles, invitations, jetons, organisations, équipes et leurs membres, rattachement des projets,
  décisions de triage (et leur journal `triage_decisions`), politiques, canaux, paramètres d'organisation. **En ajout seul**
  pour le rôle d'exécution (ni `UPDATE`, ni `DELETE`, ni `TRUNCATE`, vérifié au
  démarrage), qui n'a pas non plus de droit `CREATE` (ADR 0030).
- Ressources bornées par compte autant que par instance : un export de recherche et un
  réencodage de SBOM à la fois par compte (ADR 0030).
- Gravité des faiblesses évaluée selon l'OWASP Risk Rating ; chaque revue de recette est
  menée par un relecteur distinct de l'auteur du code.

## 20. Observabilité et exploitation

- Journaux `slog` (via `logx`), JSON en production, champs `request_id`, `org`, `job`.
- Écoute de gestion séparée : `/metrics` (Prometheus), `/healthz`, `/readyz`. `/readyz`
  vérifie la base et les migrations sur toutes les instances, et la base Grype chargée
  seulement si `workers.enabled` : une instance purement web reste disponible, y compris
  pour importer une base sur un site isolé. Dès le début d'un arrêt, `/readyz` répond 503.
- Arrêt propre sur SIGTERM : fin des requêtes en cours, libération des baux de jobs.
- `docs/operations.md` : installation, configuration, sauvegarde, mise à jour, rotation des
  clés, sites isolés, procédure de secours des administrateurs.
- **Versions** (ADR 0032) : une étiquette `vX.Y.Z` sur `main` déclenche
  `.github/workflows/release.yml`, qui construit par `make release` les archives des trois
  rôles (linux amd64 et arm64), les paquets deb et rpm de l'agent serveur, le paquet deb du
  serveur (T27, ADR 0053), le paquet deb de l'agent dépôt (ADR 0062) et `SHA256SUMS`,
  et crée une préversion GitHub dont les notes viennent de `CHANGELOG.md` (Keep a
  Changelog). Préversions seulement jusqu'à T26.

## 21. Tests et barrières de qualité

- `make ci` (identique en CI) : `gofmt`, `go vet`, `staticcheck`, `govulncheck`, tests
  `-race`, tests d'intégration PostgreSQL (dont les tests RLS du § 9, exécutés avec le rôle
  d'exécution réel), tests d'architecture, complétude des traductions, code généré à jour.
- Tests d'intégration contre un vrai PostgreSQL (`LOTOR_TEST_DATABASE_DSN`, fourni par
  `deploy/compose.yaml` en local et par un service en CI), base jetable par test.
- SBOM d'exemple dans `testdata/sbom/` (CycloneDX 1.5, 1.6, 1.7, SPDX 2.3, Syft JSON),
  dont des SBOM d'hôtes Debian, RHEL et Alpine ; fichiers attendus (« golden »).
- Fuzzing natif Go : purl, `vers`, requêtes de recherche, bornes préalables, décodage.
- Grype est remplacé par un faux `vuln.Matcher` dans les tests unitaires ; un test
  d'intégration étiqueté `grypedb` utilise une vraie base.
- **Cibles chiffrées** mesurées selon `docs/benchmarks.md` (écrit en T06) : machine de
  référence, jeu de données synthétique, 95e centile, cache froid et chaud. Une cible non
  tenue garde le lot ouvert, sauf nouvelle cible validée par l'utilisateur et reportée au
  cahier des charges.
- Couverture : 80 % au moins sur les paquets métier, hors code généré ; chaque règle métier
  a un test qui la nomme.
- La plateforme publie son propre SBOM et s'analyse elle-même dès que T06 est livré.

## 22. Conventions de code

- `gofmt`, noms explicites, fonctions courtes, erreurs enveloppées avec `%w` et contexte.
- Commentaires : uniquement le « pourquoi » non évident ; doc de paquet dans `doc.go`.
- `context.Context` en premier paramètre de toute fonction qui fait des E/S.
- Pas de `panic` hors initialisation ; pas de goroutine sans propriétaire ni arrêt.
- Commits atomiques au format conventionnel en français (`feat(ingest): …`), comme dans
  open-go-base.

## 23. Évolutions à proposer à open-go-base

open-go-base est un autre dépôt ; ces évolutions y sont proposées par l'utilisateur ou avec
son accord, au plus tard au lot indiqué. En attendant, le projet les contourne sans les
dupliquer.

| Évolution | Pourquoi | Avant |
| --- | --- | --- |
| Erreurs d'authx, mfax et csrfx exposées comme clés plutôt qu'en texte français | Messages traduits (« Identifiants invalides », « Code invalide », « Accès interdit », réponse 403 de csrfx) | Fait en T03 (PR #1 d'open-go-base) |
| Gestionnaire d'échec configurable dans csrfx | Page 403 traduite et au format du projet | Fait en T03 (PR #1 d'open-go-base) |
| Clé de limitation configurable dans `ratelimit` (par jeton) | Évite le limiteur maison de `internal/ratelimit` | Fait en T04 (`WithKeyFunc`, PR #2 d'open-go-base) |
| Codes de secours dans mfax | Récupération sans administrateur d'instance | Fait en T18 (PR #5 d'open-go-base, commit `a0f777f`, étiquette `v1.4.0` à pousser ; ADR 0048) |
| `EnablePOST` de mfax sous verrouillage par compte, refusé sur un TOTP actif | Revue de sécurité du lot 2 (SEC2-01) | Fait en T18 (PR #6 d'open-go-base, commit `0900e0c`, étiquette `v1.4.1` à pousser) |
| `--help` d'appconf annonce les défauts préremplis par le projet | L'aide affichait les défauts du fragment au lieu de ceux de lotor (port 8080 pour 1758) | Fait (PR #7 d'open-go-base, commit `5d5e22c`, étiquette `v1.4.2`) |
| Verrouillage par compte et réauthentification dans mfax ; jeton CSRF lié à la session ; nom du cookie de défi | Revue de sécurité du lot 1 (SEC-01, SEC-02, SEC-08) | Fait en T11 (PR #3 d'open-go-base, commit `9a7b91f`, étiquette `v1.3.0` à pousser) |
| Composant `oidcx` | SSO réutilisable par les projets open-go | T25 |
