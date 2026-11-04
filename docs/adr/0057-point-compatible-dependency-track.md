# 0057 — Compatibilité Dependency-Track : point d'envoi `/dt`, versions de dépôt et sortie des agents

- Statut : Accepté
- Date : 2026-11-04
- Lot : T19

## Contexte

L'option C du cahier des charges veut que lotor coexiste avec Dependency-Track : les outils
configurés pour Dependency-Track (actions de CI, greffons Maven et Gradle, scripts `curl`)
doivent pouvoir envoyer leurs SBOM à lotor, et les agents de lotor doivent pouvoir envoyer
les leurs à un Dependency-Track. L'architecture (§ 15) place ce point sous `/dt` pour que
l'espace `/api/v1` reste au projet.

Étude préalable, faite sur l'image officielle `dependencytrack/apiserver:5.2.1` (contrat
OpenAPI embarqué dans le jar, essais réels) et sur les sources de la 4.x :

- `PUT /api/v1/bom` (JSON : `project` ou `projectName` + `projectVersion`, `autoCreate`,
  `bom` en base64, et `projectTags`, `parentUUID`, `parentName`, `parentVersion`,
  `isLatest`, `isActive`) et `POST /api/v1/bom` (multipart, mêmes champs, `bom` en partie
  fichier, éventuellement compressée en gzip ou zstd). Clé dans `X-Api-Key` (insensible à
  la casse : l'action GitHub écrit `X-API-Key`). Permissions `BOM_UPLOAD`, et
  `PROJECT_CREATION_UPLOAD` (ou la gestion du portefeuille) pour `autoCreate`.
- Réponse `200` : `{"token", "projectUuid"}` ; la 4.x ne renvoie que `token`.
- Suivi : `GET /api/v1/event/token/{uuid}` → `{"processing": bool, "status": …}` ; `status`
  (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, nul pour un jeton inconnu) n'existe que
  depuis la 5. `GET /api/v1/bom/token/{uuid}`, déprécié depuis la 4.11, reste servi. Un jeton
  inconnu répond `processing: false`, sans erreur.
- Une clé refusée répond `401` sans corps.
- Dans Dependency-Track, un projet est un couple (nom, version) : chaque version est un
  projet distinct, de même nom.
- L'action officielle `DependencyTrack/gh-upload-sbom` construit son adresse par
  `new URL("/api/v1/bom", "<protocole>://<hôte>[:port]")` : elle ne garde aucun chemin, et ne
  peut donc pas viser `https://<serveur>/dt` sans un mandataire inverse qui réécrit le chemin.

## Décision

### Correspondance

- **Clé d'API → jeton d'agent dépôt** (`lotor_agt_…`). Un jeton d'agent serveur est refusé
  (`403 error.dt.agent_kind`) : un agent serveur ne sert qu'un hôte. Un agent dépôt qui ne
  sert que des outils de CI est un agent dépôt sans processus `lotor-repo-agent` derrière ;
  son « dernier contact » est son dernier envoi.
- **Nom de projet → dépôt confié à l'agent**, par son nom exact (sensible à la casse, comme
  Dependency-Track). Deux dépôts homonymes du même agent rendent la cible ambiguë (`409`).
- **Version de projet → référence suivie de nature `version`**, nouvelle nature réservée
  aux dépôts (migration 025). Elle n'a pas de commit ; elle est rangée comme un hôte : un
  inventaire identique au courant n'avance que la date de dernière analyse, un inventaire
  changé crée un instantané. Les versions ne sont jamais remises à l'agent dépôt
  (`GET /api/v1/agent/projects` les omet) : aucun commit à analyser. Un dépôt peut ne suivre
  que des versions (adresse de forge facultative, déjà admise) ; 200 versions actives au plus
  par dépôt, saisissables et retirables dans les réglages du projet comme les branches.
- **Identifiant `project`** (UUID) → identifiant de la référence `version` : comme un
  projet de Dependency-Track, il désigne un projet et sa version. La réponse renvoie le même
  identifiant en `projectUuid`, et la fiche du projet l'affiche.
- **Jeton de suivi → identifiant de l'ingestion.** `processing` vaut vrai tant que
  l'ingestion est `queued` ou `processing` ; `status` vaut `PENDING`, `RUNNING`,
  `COMPLETED` ou `FAILED`. Un jeton inconnu, ou d'un autre agent, répond comme chez
  Dependency-Track (`processing: false`, `status: null`) : la réponse ne révèle rien.
- Champs ignorés : étiquettes, parent, `isLatest`, `isActive` (lus, bornés, sans effet).

### Création automatique

- `autoCreate=true` crée le dépôt et la version manquants seulement si l'agent y est
  autorisé : réglage `agents.dt_auto_create`, posé sur la fiche de l'agent par qui gère les
  agents (`agent.manage`), audité, et **seulement pour un agent d'équipe** : le dépôt créé
  appartient à l'équipe de l'agent et lui est confié. Si l'équipe disparaît, l'agent rendu à
  l'organisation ne crée plus rien (pas d'erreur de contrainte). Sans autorisation : `403
  error.dt.auto_create_forbidden` ; sans `autoCreate` : `404 error.dt.project_unknown`.
- Création de dépôt et ajout de version sont journalisés au nom du jeton (`project.created`
  avec `source=dependency-track`, `project.version_added`). Un verrou consultatif par agent
  évite deux dépôts homonymes créés par deux envois simultanés.

### Aucun contrôle contourné

L'envoi devient une ingestion ordinaire : `ingest.Authorize` puis `ingest.Receive` (référence
confiée à l'agent revérifiée dans la transaction, bornes de taille, quotas, même file, même
décodage). Mêmes middlewares que l'API des agents (limiteur par jeton, limiteur des refus
par IP, mTLS exigé si `tls.client_ca_file` l'impose). Corps borné : SBOM admis × 4/3 pour le
JSON en base64, SBOM admis pour le multipart, plus 1 Mio. Le SBOM multipart est lu en entier
avant la résolution, car Dependency-Track n'impose pas l'ordre des champs et l'action GitHub
envoie le fichier en premier ; rien n'est rangé avant que la cible soit vérifiée. Un SBOM
refusé au décodage (XML, schéma) donne une ingestion `failed`, visible au suivi (`FAILED`) et
à l'écran ; le point ne valide pas le document de façon synchrone comme Dependency-Track 5.
Quand T24 imposera la signature, ces envois non signés seront refusés comme les autres.

Routes hors contrat OpenAPI du projet (c'est le contrat de Dependency-Track) : écrites à la
main dans `internal/api/dtrack.go`, montées sous `/dt` avec la chaîne commune des API.

### Sortie des agents

- Client commun `agentclient.DTClient` : `PUT /api/v1/bom` en JSON (le format le plus
  ancien et le plus répandu), suivi par `event/token`, même transport, mêmes réessais, aucune
  redirection suivie. `FAILED` (5.x, ou point compatible de lotor) devient `ErrDTFailed`.
- `lotor-host-agent` : `dependency_track.*` ; le SBOM Syft JSON est réencodé en CycloneDX
  1.6 par l'adaptateur du serveur (`sbom/syft.Encode`, licences hors schéma écrites en nom),
  envoyé quand l'empreinte d'inventaire diffère du dernier envoi accepté (état
  `dt_fingerprint`), après l'envoi à lotor et sans le faire échouer. `only: true` remplace
  l'envoi à lotor : ni inscription, ni signal de vie, ni conteneurs. Projet par défaut : le
  nom d'hôte, version `host`.
- `lotor-repo-agent` : `dependency_track.*`, envoi du SBOM du **commit de tête** de chaque
  référence analysée, après lotor (les commits intermédiaires d'un rattrapage n'y vont pas,
  pour ne pas inonder Dependency-Track d'historique), sans attente du traitement ; gabarits
  `{name}`, `{slug}`, `{ref}` (défaut `{name}` et `{ref}`). Pas de mode « seul » : le serveur
  lotor reste la source des dépôts à analyser et de leur dernier commit.

## Conséquences

- Une instance lotor remplace un Dependency-Track pour les envois, sans toucher aux
  pipelines : seule l'adresse de base change (`…/dt`), et la clé (un jeton d'agent dépôt).
  Pour l'action GitHub et tout client qui n'accepte qu'un nom d'hôte, un nom d'hôte dédié
  derrière un mandataire qui préfixe `/dt` (exemple dans `docs/dependency-track.md`).
- Les conteneurs d'un hôte ne partent pas vers Dependency-Track ; l'échec d'un envoi à
  Dependency-Track par l'agent dépôt n'est pas retenté avant le commit suivant (journalisé).
- La nature `version` s'ajoute aux écrans (fiche, références, recherche) et à l'API
  utilisateur (`SearchRef.kind`).
- Le reste de l'API de Dependency-Track n'est pas reproduit.
