# Site isolé : inventorier des serveurs sans réseau vers lotor

Un réseau isolé (sans route vers le serveur lotor) s'inventorie par fichiers : chaque agent
serveur écrit, à chaque inventaire changé, une **archive** (`.lotor`) qui contient son SBOM
et son contexte ; on la transporte à la main (support amovible, passerelle de dépôt) jusqu'au
serveur, qui l'importe comme un envoi réseau. Décisions : [ADR 0059](adr/0059-mode-hors-ligne.md).

Ce qui ne change pas : mêmes bornes, mêmes quotas, même décodage, même analyse quotidienne
par Grype qu'un envoi réseau. Ce qui change : l'archive se prouve elle-même. Son code
(HMAC-SHA256 du manifeste, de clé l'empreinte du secret du jeton de l'agent) ne peut être
produit que par l'agent ; une archive modifiée, ou d'un agent d'une autre organisation, est
refusée. Importer une archive ne donne donc aucun droit sur des données que l'agent
n'aurait pas pu envoyer lui-même.

## 1. Préparer le serveur

1. **Base de vulnérabilités hors ligne**, si le serveur lui-même est isolé :
   `vulndb.offline: true` et import manuel d'une archive Grype (**Administration › Base de
   vulnérabilités**, [`operations.md`](operations.md#base-de-vulnérabilités)).
2. **Jeton d'inscription** : **Agents › Nouveau jeton d'inscription**, dans l'équipe qui
   recevra les serveurs, avec autant d'utilisations que de serveurs et une **durée qui
   couvre le premier transport** (la première archive de chaque serveur doit être importée
   avant l'expiration du jeton ; ensuite, il ne sert plus). Le jeton n'est montré qu'une
   fois.
3. **Répertoire surveillé** (facultatif, pour de nombreuses archives) :

   ```yaml
   offline:
     watch_dir: /var/lib/lotor/archives   # 0700, propriété du compte du serveur
     watch_interval: 1m
   ```

   Sans lui, l'import se fait par l'interface ou l'API (étape 4).

## 2. Installer les agents du site

Copier les paquets `lotor-host-agent` (deb ou rpm de la publication, vérifiés par
`SHA256SUMS`) sur le support, puis sur chaque serveur :

```bash
sudo apt install ./lotor-host-agent_*.deb   # ou : sudo dnf install ./lotor-host-agent-*.rpm
```

```bash
sudo install -m 0600 -o lotor-host-agent /dev/null /etc/lotor-host-agent/enrollment-token
```

Coller le jeton d'inscription dans ce fichier, puis dans `/etc/lotor-host-agent/config.yaml` :

```yaml
offline:
  dir: /var/lib/lotor-host-agent/archives   # sous le répertoire d'état : seul inscriptible pour l'unité
  only: true                                # ni serveur, ni signal de vie
# server.url peut rester vide ; containers.enabled doit rester à false.
```

```bash
sudo systemctl enable --now lotor-host-agent-oneshot.timer
```

Le premier cycle tire le **jeton d'agent** de l'hôte (gardé en `0600` dans
`/var/lib/lotor-host-agent/agent-token`) et écrit la première archive, qui porte
l'inscription de l'agent. Les cycles suivants n'écrivent une archive que si l'inventaire a
changé. Les archives sont nommées `lotor-<hôte>-<date UTC>-<empreinte>.lotor`, en `0600` :
`journalctl -u lotor-host-agent-oneshot` donne le chemin de chacune.

Un agent déjà inscrit en ligne peut aussi écrire des archives **en plus** de ses envois
(`offline.dir` sans `only`), de même que l'agent dépôt (`offline.dir` de
`lotor-repo-agent`).

## 3. Transporter

Copier les fichiers `.lotor` sur le support, dans le sens site → serveur seulement. Ils ne
contiennent aucun secret (ni jeton, ni clé : seulement l'identifiant public du jeton et
l'empreinte de son secret), mais ils contiennent l'inventaire logiciel des serveurs :
les traiter comme un document interne. Les supprimer du serveur isolé une fois importés est
sans risque : un import en double ne crée rien.

## 4. Importer

Au choix :

- **Interface** : **Agents › Importer des archives**, un fichier à la fois (droit « gérer
  les agents »). Le résultat dit si l'archive est importée, déjà importée, ou si elle a
  inscrit l'agent, avec un lien vers les instantanés du projet.
- **API** (jeton d'accès personnel d'un compte qui gère des agents) :

  ```bash
  curl -sS -H "Authorization: Bearer $LOTOR_TOKEN" -H 'Content-Type: application/octet-stream' \
    --data-binary @lotor-srv-01-20261104T120000Z-0a1b2c3d.lotor \
    https://lotor.example.org/api/v1/orgs/<organisation>/archives
  ```

  `201` : importée ; `200` : déjà importée ; `422` : refusée (clé du problème).
- **Répertoire surveillé** : déposer les fichiers dans `offline.watch_dir` ; chacun est
  importé dans l'organisation de son agent, puis rangé dans `done/`, ou dans `failed/` avec
  un fichier `.error` qui donne la clé du refus. Écrire d'abord sous un nom caché
  (`.x.lotor`) puis renommer, pour que le serveur ne lise pas un fichier incomplet.

La première archive d'un serveur crée son projet (référence d'hôte : son nom) dans l'équipe
du jeton d'inscription ; il apparaît dans **Projets** et **Agents** comme un agent serveur
ordinaire. Son « dernier contact » est l'heure de l'import qui l'a inscrit (les imports
suivants ne sont pas des contacts) ; sa « dernière analyse » est la date de scan de la
dernière archive importée, qui fonde aussi l'état « muet » au-delà de 7 jours.

## Refus

| Clé | Cause | Que faire |
| --- | --- | --- |
| `error.archive.invalid` | Fichier tronqué, modifié dans sa structure, ou qui n'est pas une archive | Recopier le fichier depuis le serveur isolé |
| `error.archive.forged` | Le code ne correspond pas au jeton : contenu modifié, ou archive d'un autre agent | Écarter le fichier |
| `error.archive.foreign` | L'agent appartient à une autre organisation | L'importer dans la bonne organisation |
| `error.archive.unknown_agent` | Jeton d'agent inconnu, sans inscription (jeton révoqué puis supprimé, agent d'une autre instance) | Réinscrire l'agent |
| `error.token.expired`, `error.enrollment.exhausted` | Jeton d'inscription expiré ou épuisé avant la première archive | Nouveau jeton d'inscription sur le serveur, l'écrire sur l'hôte, supprimer `/var/lib/lotor-host-agent/agent-token` et `state.json`, relancer l'agent |
| `error.token.revoked`, `error.agent.disabled` | Jeton d'agent révoqué, agent désactivé | Voir la fiche de l'agent |
| `error.ingest.too_large`, `error.ingest.quota` | Bornes de l'ingestion | Comme pour un envoi réseau ([`operations.md`](operations.md#ingestion)) |

## Repasser en ligne

Le jeton d'agent tiré hors ligne est un vrai jeton d'agent : si le serveur devient
joignable, retirer `offline.only` (garder `offline.dir` pour une copie) et renseigner
`server.url` suffit ; l'agent reprend ses envois et ses signaux de vie sans nouvelle
inscription.
