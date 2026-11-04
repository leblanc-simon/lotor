# 0059 — Mode hors ligne : archives signées par le jeton, inscription par archive, import

- Statut : Accepté
- Date : 2026-11-04
- Lot : T23

## Contexte

Un réseau isolé n'a aucune route vers le serveur : les agents doivent écrire leurs SBOM
dans des fichiers transportés à la main, que le serveur importe comme des envois
ordinaires. La fiche demande que l'archive porte l'identité de l'agent, que le serveur
vérifie son organisation et la référence, qu'une archive importée deux fois ne crée qu'un
instantané. La signature des SBOM (T24, Ed25519) viendra ensuite. Un agent serveur
s'inscrit d'ordinaire en ligne (jeton d'inscription échangé contre un jeton d'agent) : un
hôte jamais connecté n'a pas de jeton d'agent.

## Décision

### Format

`internal/offline`, sans dépendance (agents et serveur) : un tar de trois entrées, dans
cet ordre, chacune bornée à la lecture : `manifest.json` (format `lotor-archive/1`,
identifiant public du jeton d'agent, inscription éventuelle, contexte comme un envoi réseau
avec la date de scan, empreinte SHA-256 et taille du SBOM compressé, champs inconnus
refusés), `mac.json` et `sbom.json.gz`. Nom horodaté :
`lotor-<hôte>-<AAAAMMJJThhmmssZ>-<8 caractères de l'empreinte d'inventaire>.lotor`.

### Authenticité sans nouveau secret

`mac.json` porte un **HMAC-SHA256 du manifeste dont la clé est l'empreinte SHA-256 du
secret du jeton d'agent** — la valeur que le serveur garde déjà (`agent_tokens.secret_hash`).
Le serveur vérifie l'origine sans stocker de nouveau secret ; l'archive ne révèle pas la clé
(un HMAC, pas l'empreinte) ; le manifeste couvre le SBOM par son empreinte. Une archive
modifiée, ou d'un autre agent, est refusée (`error.archive.forged`). Le code ne protège pas
contre qui détient le jeton de l'agent (l'hôte lui-même) : c'est le même niveau de
confiance qu'un envoi réseau. T24 ajoutera la signature asymétrique.

### Inscription par archive

Un agent serveur en sortie seule hors ligne (`offline.only`) sans jeton d'agent **tire son
jeton lui-même** (même format que `internal/token`, vérifié par `TestOfflineTokenFormat`),
le garde en `0600`, et chaque archive porte alors un bloc d'inscription : identifiant public
du jeton d'inscription, nom d'hôte, étiquettes, version, **empreinte du secret de son jeton
d'agent**, et un second HMAC dont la clé est l'empreinte du secret du jeton d'inscription.
À l'import d'une archive dont le jeton d'agent est inconnu, le serveur vérifie ce code et le
jeton d'inscription (organisation, révocation, échéance, utilisations), puis inscrit
l'agent comme en ligne (`agent.Service.enroll`, même transaction, même rattachement du
projet d'hôte, même journal) avec le jeton proposé (identifiant public et empreinte) :
l'agent en connaît le secret et peut ensuite parler en ligne sans nouvelle inscription.
Les archives suivantes, au jeton désormais connu, sont vérifiées avec le jeton d'agent ;
celles qui ne connaissent pas leur projet vont au projet d'hôte de l'agent.

### Import

- `ingest.Importer` : lecture bornée (taille admise d'un SBOM + 1 Mio), émetteur par
  `agent.Service.ArchiveSender` (organisation du jeton égale à celle de l'import, sinon
  `error.archive.foreign` ; jeton actif ; code vérifié), puis `Authorize` et `Receive` au
  nom de l'agent : mêmes contrôles qu'un envoi réseau. L'import n'est pas un contact de
  l'agent.
- **Dédoublonnage** : `ingestions.archive_sha256` (empreinte du manifeste signé, migration
  026, unique par organisation), cherché sous verrou consultatif : la même archive importée
  deux fois renvoie la première réception.
- **Écran** : Agents › Importer des archives (`agent.manage` dans une équipe au moins),
  fichier lu en flux après le jeton CSRF (`uploadGate`).
- **API** : `POST /api/v1/orgs/{org}/archives`, corps brut, jeton personnel d'un compte qui
  gère des agents. **Seule écriture de l'API utilisateur**, par exception à la lecture seule
  des jetons personnels (ADR 0025) : elle ne range que ce que l'archive prouve.
- **Répertoire surveillé** : `offline.watch_dir` sur le serveur ; chaque `*.lotor` est
  réservé par renommage (deux instances ne l'importent pas deux fois), importé dans
  l'organisation que désigne son jeton (`agent.Service.ArchiveOrg`), puis rangé dans
  `done/` ou `failed/` avec un fichier `.error` (clé du refus) ; une erreur interne rend le
  fichier pour le passage suivant. Acteur du journal : `offline.watch_dir`.

### Agents

- `lotor-host-agent` : `offline.dir` (archive par inventaire changé, en plus du réseau) et
  `offline.only` (sans serveur ; incompatible avec `containers.enabled` et
  `dependency_track.only`) ; répertoire créé en `0700`, sous le répertoire d'état par défaut
  dans la documentation (seul chemin inscriptible de l'unité durcie).
- `lotor-repo-agent` : `offline.dir`, une archive par SBOM envoyé, **en plus** seulement :
  le serveur reste la source des dépôts et de leur dernier commit.

## Conséquences

- Un site isolé s'inventorie avec la procédure habituelle (jeton d'inscription, paquets),
  plus le transport : `docs/site-isole.md`, déroulé sur un conteneur Debian sans réseau.
- Une archive ne contient aucun secret, mais l'inventaire des serveurs.
- Les conteneurs d'un hôte isolé ne sont pas inventoriés (ils supposent le signalement en
  ligne).
- La rétention qui purge une ingestion libère son empreinte : une très vieille archive
  réimportée crée une ingestion de plus, sans changer l'instantané courant (date de scan
  plus ancienne).
