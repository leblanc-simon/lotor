# T19 — Compatibilité Dependency-Track

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | Terminé (exécution de l'action GitHub réelle contre lotor : action de l'utilisateur) |

## Objectif

Option C du cahier des charges : les agents savent aussi envoyer leurs SBOM à un
Dependency-Track, et le serveur accepte les envois des outils configurés pour
Dependency-Track.

## Périmètre

**Inclus**

- Agents : sortie supplémentaire « Dependency-Track » (URL, clé d'API, correspondance
  projet et version, création automatique), en plus ou à la place de lotor.
- Serveur : point d'envoi compatible avec celui de Dependency-Track (corps JSON avec SBOM en
  base64 et formulaire multipart, clé `X-Api-Key`), qui crée une ingestion ordinaire, et
  route de suivi du traitement au format attendu par les clients. Ces routes vivent sous le
  préfixe `/dt/` : un client Dependency-Track se configure avec l'URL de base
  `https://<serveur>/dt`, et l'espace `/api/v1` du projet reste à lui.
- Correspondance : clé d'API → jeton d'agent ; nom de projet → projet de l'organisation ;
  version de projet → référence suivie ; création automatique si le jeton l'autorise.
- Documentation : migration depuis Dependency-Track et usage conjoint.

**Exclu** : reproduction du reste de l'API de Dependency-Track.

## Conception

- Étude préalable : routes et formats exacts de Dependency-Track 5.x, différences avec la
  4.x ; résultat consigné.
- Le point compatible ne contourne aucun contrôle : mêmes bornes, même file, mêmes droits
  que l'ingestion native. Quand T24 imposera la signature, un envoi non signé par ce point
  sera refusé comme tout autre.

## Critères d'acceptation

- [x] Un SBOM envoyé par un agent arrive dans un Dependency-Track 5 de test
      (`make test-dtrack` sur `dependencytrack/apiserver:5.2.1` : projet créé, 8 composants
      pour 7 inventoriés sur `testdata/rootfs`).
- [ ] Une requête enregistrée d'un client Dependency-Track réel est acceptée par le serveur
      et produit un instantané. **Écart** : l'exécution du code téléchargé de l'action
      GitHub `gh-upload-sbom` a été refusée dans la session ; sa requête est reconstituée
      d'après son code (`testdata/dtrack/gh-upload-sbom.http`), acceptée telle quelle par
      un Dependency-Track 5.2.1 réel, puis rejouée contre lotor
      (`TestDTRecordedClientRequest` : instantané créé). L'enregistrement d'une exécution
      réelle reste à faire (`specs/avancement.md`).
- [x] Une clé d'API inconnue ou révoquée est refusée (`TestDTUploadRefusals` : absente,
      inconnue, révoquée, jeton d'inscription, agent serveur).

## Tests attendus

Tests de contrat sur des requêtes et réponses enregistrées ; intégration avec un
Dependency-Track en conteneur, hors CI par défaut.

## Points à trancher

Aucun.

## Journal

### 4 novembre 2026

Réalisation enchaînée avec T20, T21 et T23 à la demande de l'utilisateur, sans plan validé
au préalable : les décisions ci-dessous sont **[à relire]** ([ADR 0057](../../docs/adr/0057-point-compatible-dependency-track.md)).

- **Étude préalable** : contrat OpenAPI embarqué dans `dependencytrack/apiserver:5.2.1`
  (routes `PUT`/`POST /v1/bom`, `GET /v1/event/token/{uuid}`, `GET /v1/bom/token/{uuid}`
  déprécié depuis la 4.11, champs de `BomSubmitRequest`, `BomUploadResponse` avec
  `projectUuid` en 5.x, `IsTokenBeingProcessedResponse` avec `status` en 5.x), sources de la
  4.13, essais sur un Dependency-Track 5.2.1 lancé dans la session (PostgreSQL local). Différences
  4.x/5.x : `projectUuid` et `status` absents en 4.x ; la 5.x valide le document à l'envoi
  et accepte un SBOM compressé (gzip, zstd) en multipart.
- **Correspondance [à relire]** : clé = jeton d'agent **dépôt** (agent serveur refusé en
  403) ; nom = dépôt confié à l'agent, nom exact ; version = nouvelle nature de référence
  `version` (migration 025), sans commit, rangée comme un hôte ; `project` (UUID) =
  identifiant de la référence version, renvoyé en `projectUuid` et affiché sur la fiche ;
  jeton = identifiant d'ingestion ; jeton inconnu ou d'un autre agent = `processing:
  false`, `status: null`. Étiquettes, parent, `isLatest`, `isActive` ignorés.
- **Création automatique [à relire]** : réglage par agent (`agents.dt_auto_create`, fiche
  de l'agent, `agent.manage`, audité), seulement pour un agent d'équipe ; projet créé
  dans l'équipe de l'agent et confié à lui ; verrou consultatif par agent ; 200 versions
  actives au plus par dépôt (`project.MaxVersions`).
- **Versions dans l'interface [à relire]** : champ « Versions » des réglages d'un dépôt
  (une par ligne), liste avec identifiants sur la fiche ; un dépôt peut n'avoir que des
  versions ; les versions sont omises de `GET /api/v1/agent/projects` (aucun agent ne les
  analyse). Une modification du formulaire pendant qu'un envoi crée une version peut
  retirer celle-ci ; un envoi suivant avec `autoCreate` la réactive.
- **Sortie des agents [à relire]** : client commun `agentclient.DTClient` (PUT JSON) ;
  agent serveur : CycloneDX 1.6 réencodé par `sbom/syft.Encode`, envoi si l'empreinte
  diffère du dernier envoi accepté, attente du traitement, échec sans effet sur le cycle
  lotor ; `only` = sans serveur lotor (ni inscription, ni signal de vie, ni conteneurs).
  Agent dépôt : commit de tête seulement, après lotor, sans attente, gabarits `{name}`,
  `{slug}`, `{ref}` ; pas de mode seul. Conteneurs non envoyés.
- **Constat** : l'action officielle `gh-upload-sbom` ne garde aucun chemin de l'adresse
  (`new URL("/api/v1/bom", base)`) et ne peut viser `…/dt` : documenté avec un mandataire
  nginx qui préfixe `/dt` sur un nom d'hôte dédié (`docs/dependency-track.md`). Le préfixe
  `/dt` de l'architecture est gardé.
- **Écart** : l'exécution de l'action (code téléchargé) a été refusée dans la session ; sa
  requête a été reconstituée depuis son code et validée contre un vrai Dependency-Track
  (critère 2 non coché). Réponses réelles du 5.2.1 enregistrées dans `testdata/dtrack/`.
- **Tests** : `TestDTUploadEndToEnd`, `TestDTUploadRefusals`, `TestDTRecordedClientRequest`,
  `TestDTAgentClientAgainstServer` (intégration), `TestDTClientContract`,
  `TestDTClientStatuses`, `TestDependencyTrackAlso`, `TestDependencyTrackOnly`,
  `TestDependencyTrackConfig` (agents), pipeline GitHub de l'agent dépôt étendu,
  `TestRealDependencyTrack` (étiquette `dtrack`, `make test-dtrack`). Un test de rupture
  (gardes de nature d'agent et de création automatique retirées) fait échouer
  `TestDTUploadRefusals` sur quatre cas.
- **Documentation** : `docs/dependency-track.md` (correspondance, refus, migration, usage
  conjoint, sortie des agents), `docs/operations.md`, `specs/architecture.md` (§ 8, 11, 15,
  17), modèle de menace, exemples de configuration et unités systemd des agents,
  `CHANGELOG.md`.
