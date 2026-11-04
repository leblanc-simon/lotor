# T23 — Mode hors ligne

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | Terminé |

## Objectif

Couvrir les réseaux isolés : les agents écrivent leurs SBOM dans des fichiers, transportés
à la main jusqu'au serveur, qui les importe comme des envois ordinaires.

## Périmètre

**Inclus**

- Agents : sortie « fichier » (SBOM + contexte dans une archive unique, nom horodaté) à la
  place ou en plus de l'envoi réseau.
- Serveur : import d'archives depuis l'écran du projet et par l'API, avec les mêmes contrôles
  que l'ingestion ; import en lot depuis un répertoire surveillé.
- Documentation complète d'un site isolé : agents, transport, import, base Grype hors ligne
  (déjà possible depuis T06).

**Exclu** : synchronisation automatique entre deux serveurs.

## Conception

- L'archive porte l'identité de l'agent émetteur ; à l'import, le serveur vérifie que cet
  agent appartient à l'organisation et qu'il est autorisé pour la référence. Avec T24,
  la signature est vérifiée.
- Une archive importée deux fois ne crée qu'un instantané.

## Critères d'acceptation

- [x] Une archive produite par l'agent serveur et importée donne le même instantané qu'un
      envoi réseau (`TestOfflineHostAgentRoundTrip` : vrai agent, scan Syft de
      `testdata/rootfs`, même ensemble d'inventaire qu'un envoi en ligne du même scan).
- [x] Une archive d'un agent d'une autre organisation est refusée
      (`TestOfflineArchiveImport`, écran et API : `error.archive.foreign`).
- [x] Le guide « site isolé » est déroulé de bout en bout sur une machine sans réseau
      (voir le Journal : paquet deb installé dans un conteneur Debian 12 `--network none`,
      archive importée par le répertoire surveillé d'un vrai `lotor-server`).

## Tests attendus

Aller-retour agent → archive → import ; import en double ; isolement.

## Points à trancher

Aucun.

## Journal

### 4 novembre 2026

Réalisé à la suite de T19 et T21, sans plan validé au préalable : décisions **[à relire]**
([ADR 0060](../../docs/adr/0060-mode-hors-ligne.md)).

- **Format [à relire]** : tar de trois entrées dans l'ordre (manifeste, codes, SBOM gzip),
  paquet `internal/offline` sans dépendance ; nom horodaté avec l'empreinte d'inventaire
  (deux inventaires écrits dans la même seconde s'écrasaient : vu par le test).
- **Authenticité [à relire]** : HMAC-SHA256 du manifeste de clé l'empreinte du secret du
  jeton (celle que le serveur garde) : rien de nouveau à stocker, la clé n'est pas dans
  l'archive. T24 ajoutera la signature asymétrique.
- **Inscription par archive [à relire]** : l'agent sans jeton tire son jeton d'agent
  (format recopié de `internal/token`, vérifié par `TestOfflineTokenFormat`) et l'annonce
  par son empreinte dans un bloc d'inscription signé par le jeton d'inscription ; le
  serveur inscrit avec ce jeton (refactorisation d'`agent.Service.Enroll` en `enroll`, même
  transaction). L'agent peut ensuite passer en ligne sans réinscription.
- **Import [à relire]** : écran Agents › Importer des archives (`agent.manage` dans une
  équipe), API `POST /api/v1/orgs/{org}/archives` (**seule écriture** de l'API
  utilisateur, exception à l'ADR 0025), répertoire surveillé `offline.watch_dir` (réservation
  par renommage, `done/`, `failed/` et `.error`) ; dédoublonnage par
  `ingestions.archive_sha256` (migration 027) ; l'import n'est pas un contact de l'agent.
- **Agents [à relire]** : agent serveur `offline.dir` / `offline.only` (sans conteneurs) ;
  agent dépôt `offline.dir` en plus seulement.
- **Défauts trouvés et corrigés** : `uploadGate` appelait `MultipartReader` sur un corps non
  multipart, ce qui empêchait ensuite csrfx de lire le jeton (vu par le harnais des droits
  sur la nouvelle route) ; l'agent ne créait pas `offline.dir` (vu au déroulé réel).
- **Déroulé du guide (critère 3)** : serveur réel (`bin/lotor-server`, base et rôles
  dédiés, `offline.watch_dir`), organisation et jeton d'inscription créés par les services
  (l'écran demande une session TOTP, déjà couverte par les tests d'écran) ; sur un
  conteneur `debian:12` lancé **`--network none`** (aucune interface active), le paquet
  `lotor-host-agent` installé par `dpkg -i`, jeton d'inscription et configuration du guide
  (`offline.only`, `offline.dir` sous le répertoire d'état), deux cycles `oneshot` sous
  l'utilisateur de l'agent avec `CAP_DAC_READ_SEARCH` : une archive (363 composants,
  336 Kio, `0600`), puis « inventaire inchangé » ; l'archive, copiée sous un nom caché puis
  renommée dans le répertoire surveillé, a été importée en moins de 2 s : agent inscrit
  (`agent.enrolled` et `project.created` au nom de `offline.watch_dir`), projet
  `srv-isole-01`, instantané de 363 composants ; aucune erreur dans le journal du serveur.
  Base, rôles et jeton supprimés ensuite.
- **Tests** : `internal/offline` (aller-retour, refus de structure), `TestOfflineOnly`,
  `TestOfflineAlso`, `TestOfflineConfig`, `TestArchiveWriter`, `TestOfflineTokenFormat`,
  `TestOfflineArchiveImport` (écran, API, double import, falsifiée, étrangère, inscription
  hors ligne puis jeton utilisé en ligne, droits), `TestOfflineWatchDir`,
  `TestOfflineHostAgentRoundTrip`.
