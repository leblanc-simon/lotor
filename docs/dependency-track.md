# Dependency-Track et lotor

lotor peut prendre la place de [Dependency-Track](https://dependencytrack.org) pour les
envois de SBOM, ou vivre à côté de lui. Deux sens :

- **Vers lotor** : un outil configuré pour Dependency-Track (action GitHub, greffon Maven
  ou Gradle, script `curl`) envoie ses SBOM au point compatible de lotor, sous `/dt`.
- **Vers Dependency-Track** : les agents de lotor envoient aussi (ou seulement, pour l'agent
  serveur) leurs SBOM à un Dependency-Track.

Décisions et étude des formats : [ADR 0057](adr/0057-point-compatible-dependency-track.md).
Vérifié avec Dependency-Track 5.2.1 ; les routes employées existent depuis la 4.x.

## Envoyer à lotor depuis un outil de Dependency-Track

### Ce que lotor comprend

| Dependency-Track | lotor |
| --- | --- |
| Adresse de base `https://dtrack.example.org` | `https://lotor.example.org/dt` |
| Clé d'API (`X-Api-Key`) | Jeton d'un **agent dépôt** (`lotor_agt_…`) |
| Nom de projet (`projectName`) | Dépôt confié à cet agent, par son nom exact |
| Version (`projectVersion`) | **Version** de ce dépôt (référence de nature « version ») |
| UUID de projet (`project`) | Identifiant d'une version, affiché sur la fiche du dépôt |
| `autoCreate=true` | Crée le dépôt et la version, si l'agent y est autorisé |
| Jeton de suivi (`token`) | Identifiant de l'ingestion |
| `PUT /api/v1/bom` (JSON, SBOM en base64), `POST /api/v1/bom` (multipart) | Identiques |
| `GET /api/v1/event/token/{uuid}`, `GET /api/v1/bom/token/{uuid}` | Identiques (`processing`, et `status` comme en 5.x) |

Le reste de l'API de Dependency-Track n'existe pas dans lotor (projets, constats, VEX :
utilisez l'interface et l'[API utilisateur](utilisation.md)). Étiquettes, parent,
`isLatest` et `isActive` sont acceptés et ignorés.

Différences à connaître :

- **Formats** : JSON seulement (CycloneDX 1.5 à 1.7, SPDX 2.3, Syft JSON), compressé en
  gzip ou non. Un SBOM CycloneDX XML est accepté à l'envoi, puis refusé au décodage :
  l'ingestion passe en échec, visible au suivi (`"status": "FAILED"`) et sur l'onglet
  Instantanés du projet.
- **Validation asynchrone** : Dependency-Track 5 refuse un document invalide dès l'envoi
  (`400`) ; lotor l'accepte (`200`) et le refuse au décodage, comme pour ses agents.
- **Une version = une référence** : l'historique de chaque version est conservé à part, et
  la recherche, le tableau de bord et les politiques la traitent comme une branche.
  Renvoyer le même inventaire pour la même version ne crée pas d'instantané nouveau.
- **Mêmes contrôles que les agents** : taille admise (`ingest.max_upload_mib`), quotas,
  limitation par jeton, mTLS si le serveur l'exige.

### Préparer lotor

1. Dans **Agents**, créer un agent dépôt **rattaché à une équipe** (par exemple « CI ») et
   garder son jeton : c'est la clé d'API des outils.
2. Pour que les pipelines créent eux-mêmes projets et versions (`autoCreate`), cliquer
   **Autoriser la création automatique** dans le panneau « Point Dependency-Track » de la
   fiche de l'agent (permission « gérer les agents »). Les dépôts créés appartiennent à
   l'équipe de l'agent et lui sont confiés. Sans cette autorisation, créer les dépôts à la
   main, leur confier l'agent et y saisir les versions attendues (réglages du projet, champ
   « Versions »).
3. Un même agent peut servir lotor-repo-agent et les outils de CI ; un agent dédié aux
   outils rend le suivi plus lisible (son « dernier contact » est son dernier envoi).

### Exemples

`curl`, comme la documentation de Dependency-Track :

```bash
curl -X POST https://lotor.example.org/dt/api/v1/bom \
  -H "X-Api-Key: $LOTOR_AGENT_TOKEN" \
  -F autoCreate=true -F projectName="Portail client" -F projectVersion=2.0.0 \
  -F bom=@bom.json
```

```bash
curl https://lotor.example.org/dt/api/v1/event/token/<token> -H "X-Api-Key: $LOTOR_AGENT_TOKEN"
```

Un client qui prend une adresse de base complète, chemin compris (le cas des greffons de
build qui demandent une « URL de Dependency-Track ») : y mettre
`https://lotor.example.org/dt`. Seule l'action GitHub a été vérifiée, sur son code.

**Action GitHub `DependencyTrack/gh-upload-sbom`** : elle ne prend qu'un nom d'hôte et
ignore tout chemin. Lui donner un nom d'hôte dédié, servi par un mandataire inverse qui
préfixe `/dt` ; par exemple avec nginx :

```nginx
server {
    listen 443 ssl;
    server_name dtrack.lotor.example.org;
    # certificats…
    location = /api/v1/bom                { proxy_pass http://127.0.0.1:1758/dt/api/v1/bom; }
    location   /api/v1/event/token/       { proxy_pass http://127.0.0.1:1758/dt/api/v1/event/token/; }
    location   /api/v1/bom/token/         { proxy_pass http://127.0.0.1:1758/dt/api/v1/bom/token/; }
    location / { return 404; }
    client_max_body_size 64m;
}
```

```yaml
- uses: DependencyTrack/gh-upload-sbom@v3
  with:
    server-hostname: dtrack.lotor.example.org
    api-key: ${{ secrets.LOTOR_AGENT_TOKEN }}
    project-name: Portail client
    project-version: ${{ github.ref_name }}
    auto-create: true
    bom-filename: bom.json
```

### Refus

| Statut | Clé | Cause |
| --- | --- | --- |
| 401 | `error.token.invalid`, `error.token.revoked`, `error.token.expired`, `error.agent.disabled` | Clé absente, inconnue, révoquée, expirée, agent désactivé |
| 403 | `error.dt.agent_kind` | Jeton d'un agent serveur |
| 403 | `error.dt.auto_create_forbidden` | `autoCreate` sans autorisation, ou agent sans équipe |
| 404 | `error.dt.project_unknown` | Dépôt ou version inconnus de cet agent (ou d'une autre organisation) |
| 409 | `error.dt.project_ambiguous` | Deux dépôts de l'agent portent ce nom |
| 409 | `error.dt.versions_limit` | 200 versions actives : en retirer dans les réglages du dépôt |
| 400 | `error.validation` | Cible absente, version illisible, `bom` hors base64 |
| 413 | `error.ingest.too_large` | SBOM au-delà de `ingest.max_upload_mib` |
| 429 | `error.ingest.quota`, `error.too_many_requests` | Quotas d'ingestion, limitation par jeton |

Les erreurs sont des problèmes RFC 9457 (`application/problem+json`), traduits selon
`Accept-Language`.

## Migrer depuis Dependency-Track

1. Recenser les pipelines qui envoient des SBOM et leurs couples (projet, version).
2. Créer l'agent dépôt des outils (ci-dessus), avec la création automatique si les
   pipelines comptent dessus ; sinon créer les dépôts et leurs versions.
3. Changer, pipeline par pipeline, l'adresse de base et la clé. Les deux systèmes peuvent
   recevoir en parallèle pendant la bascule : dupliquer l'étape d'envoi, ou laisser l'agent
   dépôt de lotor envoyer aussi à Dependency-Track (ci-dessous).
4. lotor relance chaque jour Grype sur le dernier instantané de chaque version ; triage,
   VEX et politiques se refont dans lotor : l'historique d'analyse de Dependency-Track n'est
   pas importé.
5. Quand plus rien n'arrive à Dependency-Track, l'arrêter.

## Envoyer aussi à Dependency-Track depuis les agents de lotor

La clé d'API est un secret : fichier en `0600` ou credential systemd
`dependency-track-api-key`, jamais dans le fichier de configuration. Elle demande
`BOM_UPLOAD`, et `PROJECT_CREATION_UPLOAD` avec `auto_create`. L'adresse peut aussi être le
point compatible d'un autre serveur lotor (`https://<serveur>/dt`).

### Agent serveur

```yaml
dependency_track:
  url: https://dtrack.example.org
  api_key_file: /etc/lotor-host-agent/dependency-track-api-key   # 0600 ; vide : credential systemd
  project_name: ""          # vide : le nom d'hôte
  project_version: host
  auto_create: true
  only: false               # true : Dependency-Track seulement, sans serveur lotor
```

- Le SBOM de l'hôte part en CycloneDX 1.6 quand son inventaire a changé depuis le dernier
  envoi accepté par Dependency-Track ; l'agent attend la fin du traitement. Un échec est
  journalisé sans faire échouer le cycle vers lotor, et l'envoi est retenté au cycle suivant.
- `only: true` : ni inscription, ni signal de vie, ni conteneurs (refusé avec
  `containers.enabled`) ; `server.url` devient facultatif.
- Les conteneurs ne partent pas vers Dependency-Track.

### Agent dépôt

```yaml
dependency_track:
  url: https://dtrack.example.org
  api_key_file: credential:dependency-track-api-key
  project_name: "{name}"     # {name} (nom du projet lotor), {slug}, {ref}
  project_version: "{ref}"
  auto_create: true
```

- Le SBOM du **commit de tête** de chaque référence analysée part vers Dependency-Track
  après son envoi à lotor ; les commits intermédiaires d'un rattrapage n'y vont pas.
- Un échec est journalisé ; le commit suivant repartira. Pas de mode « Dependency-Track
  seulement » : lotor donne à l'agent ses dépôts et leur dernier commit.

## Vérifier

- `make test-dtrack` (hors CI) : l'agent serveur scanne un système de test et l'envoie à un
  vrai Dependency-Track 5 (`LOTOR_TEST_DTRACK_URL`, `LOTOR_TEST_DTRACK_API_KEY_FILE`, clé
  d'une équipe qui a `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD` et `VIEW_PORTFOLIO`). Un
  Dependency-Track de test se lance avec l'image `dependencytrack/apiserver` et une base
  PostgreSQL (`DT_DATASOURCE_URL`, `DT_DATASOURCE_USERNAME`, `DT_DATASOURCE_PASSWORD`).
- Les requêtes de clients réels rejouées par les tests sont dans `testdata/dtrack/`.
