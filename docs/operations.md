# Exploitation de lotor-server

Installation, configuration, exploitation et surveillance du serveur et des agents,
pour le lot 1 (version 0.1). Les premiers pas des utilisateurs sont dans le guide de
démarrage ([`demarrage.md`](demarrage.md), [English](getting-started.md)). Les lots
suivants complètent ce document (sites isolés : T23, SSO : T25…).

Sommaire : installation ([développement](#installation-de-développement),
[production](#installation-de-production)), [configuration](#configuration),
[base de données](#base-de-données), [TLS](#tls-et-mandataire-inverse),
[sondes](#gestion--sondes-et-métriques), [traitements](#traitements),
[comptes](#comptes-et-connexion), [agents](#agents-et-jetons) ([serveur](#agent-serveur),
[dépôt](#agent-dépôt)), [ingestion](#ingestion),
[base de vulnérabilités](#base-de-vulnérabilités), [recherche](#recherche-et-api-utilisateur),
[tableau de bord](#tableau-de-bord), [clés](#clés-de-chiffrement-des-secrets),
[sauvegarde](#sauvegarde-et-restauration), [mise à jour](#mise-à-jour),
[supervision](#supervision), [journaux](#journaux).

## Installation de développement

Prérequis : Go 1.26 (la chaîne exacte est téléchargée d'après `go.mod`), `make`,
PostgreSQL 16 ou plus.

1. PostgreSQL : `docker compose -f deploy/compose.yaml up -d` démarre un PostgreSQL 16 et
   crée la base `lotor`, le rôle propriétaire `lotor_owner` et le rôle d'exécution
   `lotor_app` (`deploy/initdb/01-roles.sql`, mots de passe de développement). Sur un
   PostgreSQL déjà installé, voir « Rôles et droits » ci-dessous.
2. Configuration : `cp config.example.yaml config.yaml` (valeurs prévues pour
   `deploy/compose.yaml`).
3. `make run` construit les binaires et lance `bin/lotor-server -c config.yaml`.
   L'interface répond sur <http://127.0.0.1:1758/>, la gestion sur
   <http://127.0.0.1:1761/readyz>.

Tests : `make test` (unitaires), `make test-integration` (PostgreSQL requis : chaque test
crée sa base et ses rôles jetables à partir de `LOTOR_TEST_DATABASE_DSN`, connexion
d'administration, par défaut celle de `deploy/compose.yaml`), `make ci` (tout ce que fait
la CI).

## Installation par le paquet deb

Sur **une machine Debian 13 ou Ubuntu 24.04** (ou une distribution plus ancienne avec
PostgreSQL 16 du dépôt PGDG), le paquet `lotor-server` enchaîne le parcours manuel de la
section suivante (ADR 0053).

1. **Prérequis** : installer PostgreSQL et le serveur web **avant** le paquet. Installés dans
   le même appel, apt peut configurer lotor en premier (voir plus bas).

   ```bash
   sudo apt install postgresql nginx   # ou apache2
   ```

2. **Fichiers** : télécharger `lotor-server_<version>_<arch>.deb` et `SHA256SUMS` depuis la
   page des versions, vérifier (`sha256sum -c --ignore-missing SHA256SUMS`).
3. **Installation** : `sudo apt install ./lotor-server_<version>_<arch>.deb`. Le paquet
   demande où se trouve la base, l'e-mail du premier administrateur, le nom public du site, le
   serveur web et le certificat.
4. **Mot de passe temporaire** : copier celui qui s'affiche, une seule fois. Se connecter sur
   `https://<nom public>/`, enrôler le TOTP, noter les codes de secours, choisir le mot de
   passe.
5. **Sauvegarder la clé de chiffrement** : `LOTOR_SECRETS_KEYS` de
   `/etc/lotor/lotor-server.env`, à part (« Clés de chiffrement des secrets »).
6. **Certificat** : l'autosigné provoque un avertissement du navigateur, et un agent le refuse
   sans `server.ca_file`. Le remplacer, par exemple avec `certbot --nginx -d <nom public>`,
   ou indiquer un certificat existant par `sudo dpkg-reconfigure lotor-server`.

**Ce que le paquet crée.**

| Élément | Emplacement |
| --- | --- |
| Rôles `lotor_owner`, `lotor_app` et base `lotor` (mode local) | cluster en marche de plus haute version, 16 ou plus |
| Configuration | `/etc/lotor/config.yaml` (`0644`), écrite une seule fois |
| Secrets (DSN, clé de chiffrement) | `/etc/lotor/lotor-server.env` (`0600`), écrits une seule fois |
| Site du mandataire | `/etc/nginx/sites-available/lotor.conf` ou `/etc/apache2/sites-available/lotor.conf` |
| Certificat autosigné | `/etc/lotor/tls/<nom public>.crt` et `.key` |

Le serveur écoute sur `127.0.0.1:1758`, la gestion sur `127.0.0.1:1761`, avec
`web.trusted_proxies: ["127.0.0.1/32"]` et `auth.cookie_secure: on`. Derrière ce mandataire,
le mTLS des agents est indisponible.

**Base distante.** Choisir « distante » et fournir les deux chaînes de connexion : les rôles et
la base doivent déjà exister (« Rôles et droits »). Aucun mot de passe de superutilisateur n'est
demandé. Si une base locale porte déjà ces noms, le mode local n'y touche pas et demande ce mode.

**Sans terminal** (Ansible, etc.) : prérenseigner les réponses, sans quoi la base est locale et
aucun compte n'est créé. Le mot de passe temporaire n'est alors pas affiché mais écrit dans
`/etc/lotor/initial-admin-password` (`0600`), **à supprimer** après la première connexion.

```bash
sudo debconf-set-selections <<'FIN'
lotor-server lotor-server/admin_email string admin@example.org
lotor-server lotor-server/server_name string sbom.example.org
lotor-server lotor-server/web_server select nginx
FIN
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./lotor-server_<version>_<arch>.deb
```

Questions : `database` (`local`, `remote`, `manual`), `db_dsn` et `migration_dsn` (mode distant),
`admin_email`, `server_name`, `web_server` (`nginx`, `apache2`, `none`), `tls_mode` (`selfsigned`,
`existing`), `tls_cert` et `tls_key`.

**Terminer ou changer l'installation** : `sudo dpkg-reconfigure lotor-server` repose les questions
et réécrit le site. C'est la marche à suivre si le paquet a indiqué que PostgreSQL n'était pas
prêt, ou que le test de configuration du serveur web a échoué (le site lotor est alors retiré,
et les autres sites restent intacts). Une base déjà configurée n'est pas reposée.

**Mise à jour** : le paquet **ne redémarre pas** le serveur, car un redémarrage applique des
migrations irréversibles. Installer le nouveau paquet, sauvegarder la base (« Mise à jour »),
puis `sudo systemctl restart lotor-server`.

**Suppression** : `apt remove` arrête le service et retire le site ; une réinstallation remet le
site en place, puis attend `sudo systemctl enable --now lotor-server`. `apt purge` retire aussi la
configuration et le certificat autosigné. **La base PostgreSQL et
`/etc/lotor/lotor-server.env` restent** : sans la clé de chiffrement, les secrets TOTP sont perdus.
Ils se suppriment à la main.

## Installation de production

Une instance = un binaire `lotor-server`, un fichier de configuration et un fichier
d'environnement pour les secrets, sous systemd. PostgreSQL 16 ou plus est commun à toutes
les instances. Parcours vérifié lors de la recette du lot 1 (T11).

**Prérequis** : Linux amd64 ou arm64 ; PostgreSQL 16+ accessible ; sur chaque instance à
workers, 8 Gio libres pour la base de vulnérabilités et, par job de décodage simultané,
environ trente fois la taille du plus gros SBOM attendu (voir « Ingestion ») ; horloge
synchronisée (NTP).

1. **Fichiers** : télécharger depuis la page des versions
   `lotor-server_<version>_linux_<arch>.tar.gz` et `SHA256SUMS`, vérifier
   (`sha256sum -c --ignore-missing SHA256SUMS`), extraire. L'archive contient le binaire,
   `config.example.yaml`, l'unité `lotor-server.service`, `LICENSE`, `README.md` et
   `CHANGELOG.md`.

   ```bash
   sudo install -m 0755 lotor-server /usr/local/bin/lotor-server
   sudo install -d -m 0755 /etc/lotor
   sudo install -m 0644 config.example.yaml /etc/lotor/config.yaml
   sudo install -m 0644 lotor-server.service /etc/systemd/system/lotor-server.service
   ```

2. **Base** : créer les deux rôles et la base (« Rôles et droits » ci-dessous), avec des
   mots de passe aléatoires (`openssl rand -base64 24`).
3. **Configuration** `/etc/lotor/config.yaml` : `web.host` et `web.port`, `tls.*` (ou
   `web.trusted_proxies` derrière un mandataire), `auth.cookie_secure: on`,
   `logging.format: json`, `vulndb.dir: /var/lib/lotor/vulndb` (répertoire d'état de
   l'unité), `i18n.default_language`. Retirer de la copie les DSN et les clés de
   l'exemple : ils passent par l'environnement.
4. **Secrets** `/etc/lotor/lotor-server.env` (`root`, `0600`), lu par systemd :

   ```bash
   LOTOR_DB_DSN=postgres://lotor_app:<mot de passe>@db.example.org:5432/lotor?sslmode=verify-full
   LOTOR_MIGRATION_DSN=postgres://lotor_owner:<mot de passe>@db.example.org:5432/lotor?sslmode=verify-full
   LOTOR_SECRETS_KEYS=2026-10:<openssl rand -base64 32>
   LOTOR_SECRETS_ACTIVE_KEY=2026-10
   # Premier démarrage seulement (base sans compte) :
   LOTOR_BOOTSTRAP_ADMIN_EMAIL=admin@example.org
   LOTOR_BOOTSTRAP_ADMIN_PASSWORD=<mot de passe temporaire>
   ```

   **Sauvegarder la clé de chiffrement à part** (coffre-fort) : sans elle, les secrets TOTP
   de tous les comptes sont perdus (« Clés de chiffrement des secrets »).
5. **TLS natif** : l'unité tourne sous un utilisateur dynamique, qui ne lit pas un fichier
   de `/etc` réservé à `root`. Déposer la clé en `/etc/lotor/tls.key` (`0600`),
   décommenter `LoadCredential=tls-key:/etc/lotor/tls.key` dans l'unité et poser
   `tls.key_file: /run/credentials/lotor-server.service/tls-key` ; le certificat et
   l'autorité des agents (`tls.client_ca_file`) peuvent rester en `0644`. Pour écouter sur
   443, l'unité indique la capacité à accorder.
6. **Démarrage** : `sudo systemctl daemon-reload && sudo systemctl enable --now
   lotor-server`, puis `journalctl -u lotor-server` (« schéma à jour », « serveur
   démarré ») et `curl -s http://127.0.0.1:1761/readyz`. Tant qu'aucune base de
   vulnérabilités n'est chargée, `/readyz` répond 503 avec `vulndb` en échec (premier
   téléchargement : quelques minutes ; site isolé : import manuel, voir « Base de
   vulnérabilités »).
7. **Premier administrateur** : se connecter avec l'e-mail et le mot de passe temporaire,
   enrôler le TOTP, choisir le mot de passe ; retirer les deux variables `BOOTSTRAP` du
   fichier d'environnement et redémarrer. Créer un second administrateur d'instance
   (guide de démarrage, [`demarrage.md`](demarrage.md)).

**Plusieurs instances** : même configuration et mêmes clés ; une seule a besoin de
`LOTOR_MIGRATION_DSN` (les autres refusent de démarrer tant que le schéma n'est pas à
jour) ; `workers.enabled: false` pour une instance purement web. Les limitations de débit
sont comptées par instance.

### Autorité privée et certificats des agents (mTLS)

Avec une autorité privée, chaque agent reçoit l'autorité du serveur (`server.ca_file`) ;
avec le mTLS, le serveur reçoit l'autorité des agents (`tls.client_ca_file`) et chaque
agent un certificat client. Exemple avec OpenSSL (autorité gardée hors ligne) :

```bash
# Autorité des agents (une fois)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -subj "/CN=lotor agents CA" -keyout agents-ca.key -out agents-ca.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
# Certificat client d'un hôte (clé générée sur l'hôte de préférence)
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=srv-01" \
  -keyout client.key -out client.csr
printf 'extendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in client.csr -CA agents-ca.crt -CAkey agents-ca.key -CAcreateserial \
  -days 825 -extfile client.ext -out client.crt
```

Le serveur vérifie la chaîne (autorité, validité) ; il ne lit pas le nom du certificat :
l'identité de l'agent reste son jeton. Un certificat d'une autre autorité est refusé à la
négociation TLS, une requête de l'API des agents sans certificat reçoit 401
(`error.client_cert_required`) ; l'interface web n'en demande pas. Le serveur ne consulte
pas de liste de révocation : pour couper un agent, **désactiver l'agent** (ses jetons sont
révoqués) ; pour couper un certificat, renouveler l'autorité.

## Configuration

Le serveur lit le fichier YAML désigné par `-c` (`config.yaml` par défaut) s'il existe,
sinon l'environnement. Chaque clé a sa variable `LOTOR_*`, qui l'emporte sur le fichier ;
`lotor-server --help` les liste toutes avec leur description, et
[`config.example.yaml`](../config.example.yaml) les documente. Une configuration invalide
arrête le démarrage (code de sortie 2) avec un message par champ fautif, par exemple :

```
database.driver (LOTOR_DB_DRIVER) : doit valoir « postgres » (reçu "sqlite")
```

Défauts propres au projet, qui s'appliquent bien que `--help` affiche ceux
d'open-go-base : `database.driver` vaut `postgres`, `i18n.default_language` `fr`,
`logging.level` `info`. `i18n.dir` est sans effet : les traductions sont embarquées.

Les secrets (DSN avec mot de passe, clés de chiffrement) se donnent de préférence par
variables d'environnement, par exemple depuis un fichier d'environnement de systemd en
`0600`, plutôt que dans le fichier de configuration.

## Base de données

### Rôles et droits

Deux rôles PostgreSQL :

- le **propriétaire** possède la base et le schéma ; il n'est utilisé que pour migrer
  (`migration.dsn`), au démarrage. Il a l'attribut `BYPASSRLS` : les fonctions
  inter-organisations qu'il possède (garde d'organisation, sélecteur) en dépendent, la
  RLS étant forcée jusque pour lui (ADR 0012). La migration échoue sans lui ;
- le **rôle d'exécution** fait tourner l'application (`database.dsn`) avec `SELECT`,
  `INSERT`, `UPDATE`, `DELETE` seulement. Il ne doit être ni superutilisateur, ni
  `BYPASSRLS`, ni propriétaire des tables, ni membre d'un rôle qui l'est : le serveur
  refuse sinon de démarrer, car la séparation des organisations repose sur la sécurité
  au niveau des lignes (RLS) de PostgreSQL.

Création sur un PostgreSQL existant (en superutilisateur) :

```sql
CREATE ROLE lotor_owner LOGIN BYPASSRLS PASSWORD '…';
-- base existante créée avant T03 : ALTER ROLE lotor_owner BYPASSRLS;
CREATE ROLE lotor_app LOGIN PASSWORD '…' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
CREATE DATABASE lotor OWNER lotor_owner;
REVOKE ALL ON DATABASE lotor FROM PUBLIC;
GRANT CONNECT ON DATABASE lotor TO lotor_app;
```

Les droits du rôle d'exécution sur les tables sont posés par les migrations (privilèges
par défaut du propriétaire, ADR 0010) : rien d'autre à accorder. Son nom est lu dans
`database.dsn`.

Au démarrage, le serveur refuse un rôle d'exécution qui pourrait contourner l'isolement
ou effacer ses traces : superutilisateur, `BYPASSRLS`, propriétaire (ou membre du
propriétaire) d'une table, droit `CREATE` sur la base ou sur le schéma `public`, droit
`UPDATE`, `DELETE` ou `TRUNCATE` sur `audit_events` ou `instance_audit_events` (journaux en
ajout seul, migration 015).

Changer de rôle d'exécution après coup (nouveau nom) : en propriétaire, accorder au
nouveau rôle les droits sur l'existant et les privilèges par défaut, puis retirer
l'ancien :

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nouveau;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nouveau;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO nouveau;
REVOKE INSERT, UPDATE, DELETE ON lotor_schema_migrations FROM nouveau;
REVOKE EXECUTE ON PROCEDURE lotor_enforce_org_rls(regclass, name) FROM nouveau;
-- Journaux d'audit en ajout seul (ADR 0030) : sans ces retraits, le serveur refuse de démarrer.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events, instance_audit_events FROM nouveau;
ALTER DEFAULT PRIVILEGES GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nouveau;
ALTER DEFAULT PRIVILEGES GRANT USAGE, SELECT ON SEQUENCES TO nouveau;
ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO nouveau;
```

### Connexion

Connexion directe, ou pgbouncer en mode **session** (le mode transaction est incompatible
avec le verrou de migration). Chaque connexion est réglée en UTC. Le pool se règle par
`database.max_open_conns`, `max_idle_conns` et `conn_max_lifetime`. Au démarrage, le
serveur attend la base au plus `database.startup_timeout`.

### Migrations

Au démarrage, si `migration.dsn` est renseigné, le serveur applique les migrations
manquantes avec le rôle propriétaire, sous un verrou : plusieurs instances peuvent
démarrer ensemble, une seule migre, les autres attendent (au plus
`migration.lock_timeout`) puis constatent qu'il n'y a rien à faire. Toutes les
migrations en attente s'appliquent dans une seule transaction : tout ou rien.

Sans `migration.dsn`, le serveur ne migre pas et refuse de démarrer si le schéma n'est
pas à jour : on peut réserver la connexion du propriétaire à une seule instance, ou à un
lancement ponctuel lors d'une mise à jour.

Le serveur refuse aussi de démarrer si :

- une migration déjà appliquée a été modifiée depuis (somme SHA-256 différente de celle
  enregistrée dans `lotor_schema_migrations`) : les migrations publiées sont immuables ;
- la base porte une migration inconnue du binaire (base migrée par une version plus
  récente) ;
- une table d'organisation n'a pas la RLS forcée et sa politique standard.

## TLS et mandataire inverse

Deux modes :

- **TLS natif** : `tls.cert_file` et `tls.key_file` (PEM). TLS 1.2 minimum.
  `tls.client_ca_file` active le mTLS des agents : un certificat présenté doit être
  signé par cette autorité, et toute requête de l'API des agents (`/api/v1/agent/*`) sans
  certificat client vérifié est refusée (401 `error.client_cert_required`), avant la
  lecture du jeton. L'interface web, servie par la même écoute, n'en demande pas.
- **Derrière un mandataire inverse** qui termine TLS (nginx, HAProxy, Caddy…) : le serveur
  écoute en HTTP sur `web.host:web.port`. Déclarer le mandataire dans
  `web.trusted_proxies` (CIDR) : seuls les mandataires listés peuvent indiquer l'IP du
  client (`X-Forwarded-For`, `X-Real-IP`, utilisés par la limitation de débit et les
  journaux) et le HTTPS (`X-Forwarded-Proto: https`). Le mTLS des agents est alors
  indisponible.

`Strict-Transport-Security` n'est envoyé que pour une requête arrivée en HTTPS (TLS natif
ou mandataire de confiance).

- Le mandataire doit **transmettre l'en-tête `Host`** tel quel : la protection
  inter-origines de l'interface compare `Origin` à l'hôte pour les navigateurs qui
  n'envoient pas `Sec-Fetch-Site` (requête mutante refusée en 403 sinon).
- L'IP du client vient de `X-Forwarded-For`, puis à défaut de `X-Real-IP` : un mandataire
  de confiance qui ne pose pas `X-Forwarded-For` doit **écraser** `X-Real-IP`, sinon le
  client choisit l'IP comptée par la limitation de débit et journalisée.
- **`auth.cookie_secure: on` en production** : cookies `Secure` et préfixés `__Host-`
  (`__Host-lotor_session`, `__Host-csrf_token`, `__Host-mfa_challenge`), qu'aucun
  sous-domaine ne peut écraser. En `auto` ou `off`, les noms restent sans préfixe et le
  serveur l'avertit au démarrage. Passer de `auto` à `on` ferme de fait les sessions en
  cours (nouveaux noms de cookie).

## Gestion : sondes et métriques

Une écoute séparée, `management.host:management.port` (par défaut `127.0.0.1:1761`), à ne
pas exposer publiquement :

| Chemin | Rôle |
| --- | --- |
| `/healthz` | vivacité : le processus répond (200), indépendamment de la base |
| `/readyz` | disponibilité : 200 si la base répond et si le schéma est à jour ; 503 sinon, avec la vérification en échec, et 503 dès le début d'un arrêt. Sur une instance à workers (`workers.enabled`), 503 aussi tant qu'aucune base de vulnérabilités n'est chargée (vérification `vulndb`). |
| `/metrics` | métriques Prometheus : `lotor_http_requests_total` et `lotor_http_request_duration_seconds` (par groupe de routes, méthode, motif de route, statut), file de traitements (`lotor_jobs`, `lotor_job_*`, voir « Traitements »), base de vulnérabilités (`lotor_vulndb_target_age_seconds`, `lotor_vulndb_stale`, `lotor_vulndb_loaded`, voir « Base de vulnérabilités »), pool de connexions (`go_sql_*`), processus et moteur Go |

## Traitements

Ingestions, analyses et échéances passent par une file en base (tables `jobs` et
`schedules`), partagée par toutes les instances : n'importe quelle instance à workers
prend n'importe quel job, et un job survit au redémarrage de toutes les instances.

- `workers.enabled` (vrai par défaut) lance sur l'instance `workers.concurrency` workers
  (4) et le planificateur. `false` donne une instance purement web, par exemple pour
  qu'un envoi lourd ne ralentisse pas l'interface ; il faut alors au moins une autre
  instance à workers.
- **Au moins une fois** : un job pris pose un bail de `workers.lease` (30 s), renouvelé
  tant qu'il tourne. Si l'instance disparaît (panne, `SIGKILL`), le job est repris par une
  autre instance après expiration du bail. Les traitements sont conçus pour être rejoués
  sans dommage.
- **Réessais** : un job en échec est réessayé après `retry_base × 2^(n−1)` (10 s, 20 s,
  40 s…), plafonné à `workers.retry_max` (30 min), plus une gigue de 0 à 20 %. Après son
  nombre maximal de tentatives (10 par défaut), ou sur une erreur définitive, il passe au
  statut `dead` avec sa dernière erreur ; il y reste jusqu'à ce qu'un administrateur le
  relance ou l'abandonne depuis **Administration → Traitements** (liste des traitements
  en échec avec leur organisation, leurs tentatives et leur dernière erreur ; compteurs de
  la file). Relancer remet le job en attente avec toutes ses tentatives ; abandonner le
  supprime. Chaque action est inscrite au journal d'audit de l'instance.
- **Priorités et plafonds** : un job prioritaire (une ingestion fraîche) passe avant le
  travail de fond (réanalyse de toutes les références). Les types lourds (décodage des
  SBOM, analyses) sont plafonnés à `workers.org_limit` (2) jobs simultanés par
  organisation, toutes instances confondues : une organisation très active ne prive pas
  les autres.
- **Échéances** : chaque échéance (vérification de la base de vulnérabilités, statistiques
  quotidiennes…) est cherchée toutes les `workers.schedule_interval` (10 s) et n'est prise
  que par une seule instance, même si toutes tournent. Les échéances suivent une grille en
  UTC ; un point manqué pendant une panne générale est rattrapé une fois au redémarrage.
- **Rétention** : les jobs terminés sont purgés après `workers.retention` (7 jours).
- **Horloges** : baux et échéances se calculent avec l'horloge de chaque instance, qui
  doit être synchronisée (NTP ou équivalent).

Métriques (`/metrics`) :

| Métrique | Contenu |
| --- | --- |
| `lotor_jobs{kind, status}` | jobs en attente (`pending`), en cours (`running`) et morts (`dead`), lus en base : même valeur sur toutes les instances |
| `lotor_job_runs_total{kind, outcome}` | exécutions de l'instance : `done`, `retry` et `dead` (échecs), `lost` (bail perdu, résultat ignoré), `released` (interrompu par l'arrêt) |
| `lotor_job_duration_seconds{kind}` | durée des exécutions de l'instance |
| `lotor_job_schedule_fires_total{schedule}` | échéances prises par l'instance |

À surveiller : `lotor_jobs{status="dead"}` qui croît, `lotor_jobs{status="pending"}`
qui ne décroît pas (workers absents ou sous-dimensionnés), `outcome="lost"` fréquent
(bail trop court ou base saturée).

## Arrêt

Sur `SIGTERM` (ou `SIGINT`), le serveur passe `/readyz` à 503, cesse d'accepter des
connexions et laisse aux requêtes en cours `http.shutdown_timeout` (30 s par défaut) pour
finir ; au-delà, il ferme les connexions restantes. En même temps, les workers cessent de
prendre des jobs et laissent aux jobs en cours `workers.shutdown_timeout` (30 s) ; à
l'approche de ce délai, les jobs encore en cours sont interrompus et remis en attente,
sans que la tentative compte, pour qu'une autre instance les reprenne aussitôt. Code de
sortie 0 après un arrêt propre. Côté systemd, `TimeoutStopSec` doit dépasser le plus grand
de `http.shutdown_timeout` et `workers.shutdown_timeout`.

## Comptes et connexion

Tout compte local se connecte par mot de passe **et** code TOTP (enrôlement obligatoire à
la première connexion). Les mots de passe comptent 12 caractères au moins.

**Premier administrateur.** Sur une base sans compte, définir au premier démarrage
`LOTOR_BOOTSTRAP_ADMIN_EMAIL` et `LOTOR_BOOTSTRAP_ADMIN_PASSWORD` (mot de passe
temporaire). Le compte est créé administrateur d'instance ; à sa connexion, il enrôle son
TOTP puis choisit un nouveau mot de passe. Les variables sont ignorées dès qu'un compte
existe : les retirer ensuite (le journal le rappelle). Deux instances qui démarrent
ensemble ne créent qu'un compte.

**Comptes.** L'administration (`/admin`) crée les comptes avec un mot de passe temporaire
affiché une seule fois, les désactive, réinitialise leur mot de passe ou leur TOTP,
nomme les administrateurs d'instance, crée et archive les organisations. Une
réinitialisation est un geste de remédiation : elle ferme les sessions **et révoque les
jetons d'accès personnels** du compte ; celle du TOTP impose aussi un **mot de passe
temporaire**, affiché une fois (à transmettre par un canal sûr), sans quoi quiconque
connaît l'ancien mot de passe enrôlerait son propre TOTP (ADR 0029). Chaque action est journalisée (`/admin/audit`). Garder **deux
administrateurs d'instance au moins** : l'interface avertit s'il n'y en a qu'un.

**Procédure de secours** (administrateur unique qui a perdu son TOTP) :

1. Ouvrir un ticket d'incident et choisir sa référence (8 caractères au moins, par
   exemple `INC-2026-0042`).
2. Redémarrer le serveur avec `LOTOR_BOOTSTRAP_RESCUE_TOTP_EMAIL=<e-mail de
   l'administrateur>`, `LOTOR_BOOTSTRAP_RESCUE_TICKET=<référence>` et
   `LOTOR_BOOTSTRAP_RESCUE_PASSWORD=<mot de passe temporaire>` (12 caractères au moins,
   transmis à l'administrateur par un canal sûr). Le TOTP de ce compte est retiré, le mot
   de passe temporaire imposé, ses sessions fermées et ses jetons personnels révoqués ;
   l'événement « procédure de secours » entre au journal d'audit avec la référence. Le
   compte doit être un administrateur d'instance actif, sinon le serveur refuse de
   démarrer.
3. L'administrateur se connecte avec le mot de passe temporaire, enrôle un nouveau TOTP
   puis choisit un nouveau mot de passe. L'ancien mot de passe ne sert plus.
4. Retirer les trois variables. Laissées en place, elles n'ont plus d'effet (un ticket ne
   s'applique qu'une fois) et le journal le signale à chaque démarrage. Un nouvel incident
   demande une nouvelle référence.

Un administrateur qui a perdu son mot de passe se le fait réinitialiser par un autre
administrateur. La procédure de secours ne couvre que le TOTP : un administrateur unique
qui perd aussi son mot de passe relève d'une intervention en base, hors de l'application
(à éviter en gardant deux administrateurs).

**Limitation.** `login.rate_limit` (10 par défaut) borne les `POST` de `/login` et
`/login/2fa` par minute et par IP, en plus de `web.rate_limit` ; une IPv6 compte pour son
/64. Un défi TOTP tolère `mfa.max_attempts` codes faux.

**Verrouillage.** Les codes TOTP faux sont aussi comptés **par compte**, tous défis et
réauthentifications confondus : au-delà de `mfa.lockout_threshold` (10) dans
`mfa.lockout_window` (15 min), le compte est verrouillé `mfa.lockout_duration` (15 min),
durée doublée à chaque récidive jusqu'à `mfa.lockout_max_duration` (24 h). Le
verrouillage est journalisé (« compte verrouillé ») : il signale que le mot de passe est
connu d'un tiers. Le titulaire attend la fin du verrouillage ; un administrateur peut le
lever en réinitialisant le TOTP (ce qui impose un nouveau mot de passe).

**Codes de secours** (T18, ADR 0048). À l'enrôlement du TOTP, chaque compte reçoit un jeu
de `mfa.recovery_codes` (10) codes à usage unique, montrés une seule fois ; seule leur
empreinte est gardée (table `mfa_recovery_codes`). Un code de secours remplace un code TOTP
à la connexion (« Utiliser un code de secours ») ; les codes faux comptent dans le
verrouillage comme des codes TOTP faux. Depuis **Mon compte → Second facteur**, le
titulaire voit le nombre de codes restants, en régénère un jeu (code TOTP exigé, l'ancien
jeu devient caduc) ou **reconfigure** son application : un code TOTP ou un code de secours
et un nouveau mot de passe retirent le second facteur, remplacent le mot de passe et ferment
ses sessions ; la connexion suivante impose un nouvel enrôlement (le nouveau mot de passe
ferme la fenêtre où l'ancien, peut-être dérobé, suffirait à enrôler un second facteur :
SEC2-06, ADR 0051). Un titulaire qui a perdu à la fois son application et ses codes passe toujours
par un administrateur (réinitialisation du TOTP). Les comptes enrôlés avant la mise à jour
n'ont pas de codes : la page **Second facteur** les invite à en générer. Le journal d'audit
enregistre chaque jeu généré, chaque code utilisé (avec le nombre restant) ou refusé, et
chaque reconfiguration.

**Sessions.** Une session glisse de `auth.session_ttl` (12 h) à chaque requête, dans la
limite absolue de `login.session_max_age` (7 jours) depuis la connexion. Un jeton CSRF est
lié à la session : un formulaire affiché avant une connexion ou une déconnexion est refusé
(« formulaire expiré », recharger la page).

**Membres, équipes et invitations** (T16, ADR 0034). Le rôle d'organisation vaut
membre ou administrateur ; les droits sur les projets viennent du rôle d'équipe (lecteur,
analyste, administrateur d'équipe), selon la matrice
[`security/permissions.md`](security/permissions.md). Un administrateur d'organisation
**invite** une adresse (page des membres) : la réponse est la même que l'adresse ait un
compte ou non, et le compte ne devient membre qu'en acceptant l'invitation
(`/account/invitations`, 30 jours). Un compte qui n'existe pas encore peut être créé par
l'administration de l'instance tant que l'invitation court. L'administration de
l'instance ajoute aussi directement un administrateur à une organisation. **À la mise à
jour vers la version des équipes**, la migration crée dans chaque organisation une équipe
« Général » (« General » en anglais) qui reçoit tous les projets, jetons d'inscription et
agents serveur, et dont chaque membre devient membre avec son ancien rôle (lecteur →
lecteur, analyste → analyste, administrateur → administrateur d'équipe) : personne ne perd
d'accès ; les agents dépôt deviennent des agents d'organisation.

**Jetons personnels.** Leur création exige un code TOTP ; changer de mot de passe propose
(case cochée) de les révoquer tous. Les sessions et défis expirés sont purgés toutes les
heures (job `auth.purge`, instances à workers).

## Agents et jetons

Les écrans **Projets** et **Agents** d'une organisation (`/o/<slug>/projects`,
`/o/<slug>/agents`) sont réservés en écriture à ses administrateurs.

- **Agent serveur** (`lotor-host-agent`, T07) : créer un **jeton d'inscription**
  (« Inscrire des serveurs ») : validité (1 heure à 30 jours), nombre d'usages (un par
  hôte), étiquettes des projets créés, ou projet de serveur existant à rattacher. Chaque
  hôte l'échange contre son propre jeton d'agent (`POST /api/v1/agent/enroll`) ; le
  serveur crée le projet de l'hôte, ou rattache l'agent au projet désigné, ou au projet
  qui suit déjà ce nom d'hôte s'il n'a plus d'agent actif **et s'il est dans l'équipe du
  jeton** ; un homonyme d'une autre équipe répond « hôte déjà suivi »
  (`error.enrollment.host_taken`) sans être pris : désigner le projet, ou créer le jeton
  dans la bonne équipe (SEC2-02).
- **Agent dépôt** (`lotor-repo-agent`, T08) : « Nouvel agent dépôt » crée l'agent et son
  premier jeton ; les dépôts lui sont confiés depuis leur fiche.
- Un jeton n'est **affiché qu'une fois** ; seul son SHA-256 est conservé. Le fournir à
  l'agent par un fichier en `0600` ou un credential systemd, jamais dans un fichier de
  configuration. **Rotation** : créer un second jeton sur la fiche de l'agent, le
  déployer, vérifier sa date de dernière utilisation, révoquer l'ancien. Une révocation
  vaut dès la requête suivante.
- **Désactiver** un agent révoque ses jetons et lui retire ses projets ; un hôte peut
  ensuite s'inscrire de nouveau sous le même nom.
- **Limitation** : `agent_api.rate_limit` (120 par défaut) borne les requêtes par minute et
  **par jeton**, `agent_api.failure_rate_limit` (30) les jetons refusés par minute et par
  IP. Au-delà : 429 avec `Retry-After`. Ces compteurs sont propres à chaque instance.
- Un agent est dit **muet** après 7 jours (décision de T10, ADR 0027) : sans inventaire de son hôte pour un agent
  serveur (même s'il répond encore : envois refusés, scans en échec), sans contact pour un
  agent dépôt.

## Agent serveur

`lotor-host-agent` inventorie un hôte Linux (amd64, arm64) avec Syft et n'envoie un SBOM
que lorsque l'inventaire a changé (ADR 0020, 0021).

### Installation

1. Installer le paquet (page des versions, ou `make packages` qui les produit dans `dist/` ;
   deb et rpm, amd64 et arm64, non signés, à vérifier par `SHA256SUMS`) : `sudo apt install ./lotor-host-agent_<version>_amd64.deb`
   ou `sudo dnf install ./lotor-host-agent-<version>.x86_64.rpm`. Le paquet crée
   l'utilisateur système `lotor-agent`, `/etc/lotor-host-agent/config.yaml`, les unités
   systemd ; il n'en active aucune.
2. Renseigner `server.url` (`https://…` seulement) dans la configuration, et au besoin
   `server.ca_file` (autorité privée, qui remplace celles du système), `server.proxy`,
   `server.client_cert_file` (mTLS), `labels`, `scan.exclude`. Chaque clé a sa variable
   `LOTOR_HOST_AGENT_*` (`lotor-host-agent --help`).
3. Déposer le **jeton d'inscription** (« Inscrire des serveurs », l'écran qui l'affiche
   donne ces commandes), lisible du seul agent :
   `printf '%s' '<jeton>' | sudo install -m 0600 -o lotor-agent -g lotor-agent /dev/stdin /etc/lotor-host-agent/enrollment-token`.
   Variante chiffrée : `printf '%s' '<jeton>' | sudo systemd-creds encrypt --name=enrollment-token - /etc/lotor-host-agent/enrollment-token.cred`,
   puis `sudo systemctl edit lotor-host-agent` et
   `LoadCredentialEncrypted=enrollment-token:/etc/lotor-host-agent/enrollment-token.cred`.
   La clé du certificat client suit le même chemin (fichier `server.client_key_file` en
   `0600`, ou credential `client-key`). Un fichier secret lisible par le groupe ou les
   autres est refusé.
4. Démarrer **une** des deux formes : `sudo systemctl enable --now lotor-host-agent.service`
   (démon : un scan par `scan.interval`, 24 h, et un signal de vie par
   `scan.poll_interval`, 5 min, qui reçoit les demandes « Scanner maintenant ») ou
   `sudo systemctl enable --now lotor-host-agent-oneshot.timer` (un scan par jour vers 2 h,
   heure tirée dans l'heure ; une demande de scan attend le passage suivant).
5. Au premier cycle, l'agent s'inscrit et garde son jeton d'agent dans
   `/var/lib/lotor-host-agent/agent-token` (`0600`) ; supprimer ensuite le jeton
   d'inscription. L'hôte apparaît dans les projets avec son contexte (système, noyau,
   architecture, durée du scan).

### Sans systemd (conteneur, Alpine, init sans systemd)

Vérifié en recette sur Debian 12, Rocky Linux 9 et Alpine 3.18 (conteneurs). Les paquets
s'installent sans systemd (`dpkg -i`, `rpm -i` : l'utilisateur `lotor-agent` est créé par
`useradd`, aucune unité n'est activée). Sur une distribution sans paquet (Alpine) : copier
le binaire de l'archive `lotor-host-agent_<version>_linux_<arch>.tar.gz` en
`/usr/bin/lotor-host-agent`, créer `/etc/lotor-host-agent` et
`/var/lib/lotor-host-agent` (`0700`).

- Poser `enrollment_token_file` (et `server.client_key_file` pour le mTLS) en chemins
  absolus : les credentials systemd n'existent pas hors systemd.
- Lancer l'agent sous `lotor-agent` avec la seule capacité `CAP_DAC_READ_SEARCH`, comme
  l'unité, par exemple
  `setpriv --reuid lotor-agent --regid lotor-agent --init-groups --inh-caps +dac_read_search --ambient-caps +dac_read_search --bounding-set -all,+dac_read_search lotor-host-agent`
  (conteneur : `--cap-add DAC_READ_SEARCH`). Sans `setpriv` (busybox), l'agent tourne en
  root.
- Forme démon sous le superviseur du système (OpenRC, runit, s6), ou `mode: oneshot` lancé
  par `cron` une fois par jour.
- Dans un conteneur, la racine en overlay est inventoriée (seuls les montages overlay
  **sous** la racine sont exclus) : l'agent décrit alors le conteneur, pas l'hôte qui le
  porte. Pour inventorier l'hôte, installer l'agent sur l'hôte.

### Fonctionnement

- **Scan** de `/` avec les catalogueurs d'un système installé (dpkg, rpm, apk, paquets
  Python, Ruby, Node.js installés, archives Java, binaires Go et Rust), sans catalogage de
  fichiers. L'agent parcourt l'arborescence une fois, sans ouvrir les fichiers, et Syft
  n'en lit que ceux qui l'intéressent (bases de paquets, manifestes, archives, binaires) :
  la mémoire et la durée suivent le nombre de fichiers, pas leur volume (ADR 0055).
  **Exclus** : `/proc`, `/sys`, `/dev`, `/run`, `/var/run`, les stockages de
  Docker, Podman (y compris sans root, `~/.local/share/containers`), containerd, kubelet,
  LXC/LXD, Rancher, les répertoires de données (`/tmp`, `/var/tmp`, `/var/log`,
  `/var/cache`, `/var/spool`, `/var/mail`, `/var/backups`, `/var/crash`, `/lost+found`,
  `/var/lib/apt/lists`, `~/.cache`, et les données de PostgreSQL, MySQL/MariaDB, MongoDB,
  Redis, Elasticsearch, OpenSearch, ClickHouse, InfluxDB, Cassandra, RabbitMQ et
  Prometheus sous `/var/lib`), les montages réseau (NFS, CIFS, sshfs, Ceph…), de conteneurs
  (overlay…), autofs et les systèmes de fichiers virtuels du noyau, plus `scan.exclude`.
  Un serveur qui garde de gros volumes de données ailleurs (`/srv/data`, `/data`) gagne à
  les ajouter à `scan.exclude`. Les conteneurs sont inventoriés à part,
  si l'option est activée (« Conteneurs » ci-dessous). Syft travaille hors ligne : il
  n'exécute aucun outil (`go list`) et ne sort pas sur le réseau.
- **Exclusions configurées** (`scan.exclude`) : chemins absolus ou motifs, comparés au
  chemin complet depuis la racine du scan ; un répertoire exclu n'est pas parcouru.
  `*` couvre un seul niveau de répertoire, `**` n'importe quelle profondeur, `?` un
  caractère, `[abc]` un caractère parmi d'autres, `{a,b}` une alternative ; une barre
  finale est ignorée.

  | Motif | Exclut | Garde |
  | --- | --- | --- |
  | `/srv/data` | `/srv/data` et tout son contenu | `/srv/data2` |
  | `/home/*/www` | `/home/alice/www`, `/home/bob/www` | `/home/alice/sites/www`, `/home/alice/www2` |
  | `/home/**/www` | tout répertoire `www` sous `/home`, à toute profondeur | `/srv/www` |
  | `/home/*/{www,public_html}` | `www` et `public_html` de chaque compte | `/home/bob/app` |
  | `/srv/data/**/cache` | tout répertoire `cache` sous `/srv/data` | `/srv/data/a/keep.jar` |

  Un motif qui ne commence pas par `/` empêche l'agent de démarrer. Avec la variable
  `LOTOR_HOST_AGENT_SCAN_EXCLUDE`, les motifs sont séparés par des virgules : un motif
  `{a,b}` s'écrit alors dans le fichier de configuration. Ce qui est exclu disparaît de
  l'inventaire : n'exclure que des données (médias, téléversements, caches), jamais des
  applications (`node_modules`, `vendor` de Composer, extensions WordPress, archives Java),
  dont les vulnérabilités ne seraient plus suivies.
- **Envoi conditionnel** : l'empreinte d'inventaire du SBOM est calculée comme par le
  serveur. Inchangée, l'agent envoie un signal de vie avec son empreinte ; le serveur
  avance la date de dernière analyse, ou réclame le SBOM s'il ne connaît pas cet
  inventaire. Changée, le SBOM part (Syft JSON compressé) et l'agent attend son rangement.
- **Réessais** : `server.retries` tentatives (erreurs réseau, 429, 5xx), délai
  exponentiel, `Retry-After` respecté. Un SBOM refusé (`error.ingest.*`) est renvoyé au
  cycle suivant ; un jeton refusé (401) demande une intervention (nouvelle inscription).
- **Sobriété** : `resources.max_procs` (1) borne `GOMAXPROCS` et les catalogueurs
  simultanés, `resources.memory_limit_mib` (512) la mémoire du runtime (limite douce),
  `scan.max_duration` (1 h) le scan ; l'unité ajoute `Nice=19`, `IOSchedulingClass=idle`,
  `MemoryMax=1536M`, et propose `CPUQuota=` (à décommenter, au prix d'un scan plus long).
- **Moindre privilège** : utilisateur `lotor-agent`, seule capacité
  `CAP_DAC_READ_SEARCH` (lecture de tout fichier), écriture limitée au répertoire d'état,
  unité durcie (`systemd-analyze security` : 1,9).
- **Mise à jour** : installer le nouveau paquet ; le démon redémarre, l'état est gardé.
  **Désinstallation** : arrête les unités ; `/var/lib/lotor-host-agent` et l'utilisateur
  restent (à supprimer à la main pour une réinscription propre, après avoir désactivé
  l'agent dans l'interface).
- **Journaux** : `journalctl -u lotor-host-agent` ; ni jeton ni contenu de SBOM.

### Conteneurs

Chaque conteneur qui tourne sur l'hôte peut devenir un **projet enfant** du projet de
l'hôte, avec son propre SBOM (ADR 0040 et 0041). Docker et Podman sont pris en charge ;
containerd seul (sans Docker ni Podman) ne l'est pas encore (T22).

**L'accès à la socket d'un moteur de conteneurs équivaut à root sur l'hôte** : qui peut
parler à `/run/docker.sock` peut lancer un conteneur privilégié qui monte `/`.
L'inventaire des conteneurs est donc **désactivé par défaut** ; sans
`containers.enabled: true`, l'agent n'ouvre aucune socket. L'activer, c'est accepter que
l'utilisateur `lotor-agent` (et quiconque le compromet) ait ce pouvoir.

- **Privilégier une socket Podman sans root** quand les conteneurs tournent sous un
  compte sans privilège : la socket de ce compte (`systemctl --user enable --now
  podman.socket`, puis `/run/user/<uid>/podman/podman.sock`) ne donne que les droits de
  ce compte. Donner l'accès à l'agent par une ACL
  (`setfacl -m u:lotor-agent:x /run/user/<uid> /run/user/<uid>/podman` et
  `setfacl -m u:lotor-agent:rw /run/user/<uid>/podman/podman.sock`, à reposer au
  redémarrage du service, par exemple dans un `ExecStartPost=` du `podman.socket` du
  compte) et la déclarer dans `containers.sockets`.
- **Docker, ou Podman avec root** (`/run/podman/podman.sock`) : ajouter l'agent au groupe
  propriétaire de la socket par un complément de l'unité, sans modifier le paquet :
  `sudo systemctl edit lotor-host-agent` puis
  `[Service]` / `SupplementaryGroups=docker` (Podman avec root : un groupe à qui la socket
  est ouverte par `podman.socket` et `SocketGroup=`).
- **Configuration** (`containers.*`, variables `LOTOR_HOST_AGENT_CONTAINERS_*`) :
  `enabled` (faux), `sockets` (vide : `/run/docker.sock` puis `/run/podman/podman.sock`,
  une socket absente étant ignorée), `work_dir` (vide : `<state_dir>/images`, `0700`),
  `max_image_mib` (4 096 : une image plus grosse n'est pas inventoriée), `timeout` (30 s
  par appel au moteur).
- **Fonctionnement** : après l'hôte, l'agent liste les conteneurs en cours, les regroupe
  par identité — `projet/service` pour un service Compose (étiquettes
  `com.docker.compose.*`, posées par docker compose et podman-compose ; ses répliques
  forment un seul projet), sinon le nom du conteneur — et les signale au serveur, qui crée
  les projets enfants sous l'hôte de l'agent, dans l'équipe de l'hôte. L'image de chaque
  conteneur que le serveur ne connaît pas encore est exportée (`docker save`) dans
  `work_dir`, scannée par Syft depuis ce fichier (hors ligne), puis supprimée ; une image
  partagée n'est scannée qu'une fois. L'agent garde l'empreinte d'inventaire de chaque
  image : au cycle suivant, le serveur la confirme sans nouveau scan.
- **Disque** : l'export demande la taille de l'image dans `work_dir`, et Syft extrait ses
  couches dans le répertoire temporaire du processus (`/tmp`, privé sous l'unité
  fournie). Pour de grosses images sur un `/tmp` en mémoire, poser
  `Environment=TMPDIR=/var/lib/lotor-host-agent/tmp` (répertoire `0700` créé au
  préalable) dans le complément de l'unité.
- **Échecs** : un moteur injoignable, une image trop grosse, un scan ou un envoi en
  échec sont journalisés et comptés sans arrêter les autres conteneurs ni le cycle de
  l'hôte ; le cycle suivant les reprend.
- **Côté serveur**, un conteneur que l'agent n'a plus signalé depuis
  `containers.archive_after` (7 jours ; `LOTOR_CONTAINERS_ARCHIVE_AFTER`) voit son projet
  archivé par une échéance horaire ; il revient de lui-même s'il redémarre. Un projet de
  conteneur archivé à la main n'est plus inventorié, même s'il tourne.
- **Purge** (T18, ADR 0049) : archivé pour absence depuis `containers.purge_after`
  (180 jours ; `LOTOR_CONTAINERS_PURGE_AFTER`, `0` : jamais, au moins `retention.days`),
  le projet d'un conteneur est **supprimé avec tout son historique** (instantanés,
  réceptions, constats, violations) par la rétention nocturne, qu'elle soit activée ou
  non (voir « Rétention des instantanés »). Chaque suppression est journalisée dans le
  journal d'audit de l'organisation (« conteneur … supprimé avec son historique »). Ne
  sont jamais purgés un conteneur archivé à la main (son archivage dit à l'agent de
  l'ignorer) ni un conteneur qui porte une décision de triage. S'il revient plus tard,
  le conteneur est un nouveau projet.
- **Borne par hôte** (T18, SEC2-05) : un hôte porte au plus `containers.max_per_host`
  projets de conteneurs, actifs ou archivés (1 000 ; `LOTOR_CONTAINERS_MAX_PER_HOST`). Un
  signalement qui en créerait davantage est refusé en entier (409,
  `error.agent.containers_limit`, journalisé par l'agent) : un jeton d'agent volé ne peut
  plus créer des milliers de projets et de lignes d'audit indélébiles. Seule la purge
  libère de la place ; sur un hôte qui crée beaucoup de conteneurs éphémères nommés au
  hasard, relever la borne ou nommer les conteneurs (services Compose).

### Mesures

Protocole (root requis, hors CI) : `make build GOARCH=amd64`, puis
`LOTOR_HOST_AGENT_BINARY=$PWD/bin/lotor-host-agent go test -tags measure -count=1 -v -run 'TestMeasure|TestLeastPrivilege' ./internal/hostagent/`
(agent sous `nobody` avec `CAP_DAC_READ_SEARCH`, contre un faux serveur ;
`LOTOR_MEASURE_ROOT` choisit la racine). Résultats et cibles : Journal de T07 et cahier
des charges.

## Ingestion

Un agent envoie un SBOM par `POST /api/v1/agent/ingestions` (deux parties : `context`
puis `sbom`, compressé en gzip de préférence) pour une référence d'un projet qui lui est
confié. Formats acceptés : **CycloneDX JSON 1.5 à 1.7, SPDX JSON 2.3, Syft JSON** ; pas
de XML. La requête stocke le SBOM et met son décodage en file ; l'agent suit l'état par
`GET /api/v1/agent/ingestions/{id}` (`queued`, `processing`, `done`, `failed` avec une
clé d'erreur traduite). L'onglet **Instantanés** de chaque projet montre les dernières
réceptions, leurs erreurs, et permet de télécharger le SBOM reçu ou réencodé en
CycloneDX 1.6 ou SPDX 2.3.

Bornes (`ingest.*`) :

| Réglage | Défaut | Au-delà |
| --- | --- | --- |
| `max_upload_mib` | 32 | refus 413 dans la requête, sans ingestion |
| `max_decompressed_mib` | 64 | ingestion `failed` (`error.ingest.too_large`) |
| `max_depth` | 64 | ingestion `failed` (`error.ingest.too_deep`) |
| `max_components` | 50 000 | ingestion `failed` (`error.ingest.too_many_components`) |
| `decode_timeout` | 5 min | job réessayé, puis `dead` |
| `max_per_ref_per_day` | 200 | refus 429 (`error.ingest.quota`), rien n'est stocké |
| `max_org_storage_mib` | 10 240 | refus 429 (`error.ingest.quota`), rien n'est stocké |
| `max_reencodes` | 2 | téléchargement réencodé refusé (429) ; un seul par compte |

- `decode_timeout` interrompt la lecture du document et coupe entre les étapes ; la
  validation par schéma et le décodage de Syft, linéaires en taille, vont au bout de
  l'étape commencée.
- Les quotas protègent le disque commun d'un agent compromis (ADR 0030) : un envoi en
  double (même commit, même document) ne compte pas. Relever `max_per_ref_per_day` pour
  une branche qui reçoit plus de 200 commits analysés par jour. Surveiller le volume :
  `SELECT org_id, pg_size_pretty(sum(compressed_size)) FROM sbom_blobs GROUP BY org_id`
  (rôle propriétaire). La rétention des anciens instantanés libère cet espace (voir
  « Rétention des instantanés »).

- Un JSON non compressé compte tout entier dans `max_upload_mib` : les agents envoient du
  gzip (un SBOM se compresse d'environ dix fois).
- **Mémoire** : le décodage charge le document ; le pic mesuré vaut environ **trente fois
  sa taille** (1,5 Mio pour un hôte de 800 paquets : quelques dizaines de Mio ; 10 Mio et
  50 000 composants : environ 330 Mio). Prévoir, par job de décodage simultané
  (`workers.concurrency`, et au plus `workers.org_limit` par organisation), trente fois le
  plus gros SBOM attendu, et poser `GOMEMLIMIT` à environ 80 % de la mémoire de
  l'instance. Une instance web (`workers.enabled: false`) ne garde en mémoire que l'envoi
  en cours de réception (`max_upload_mib` par requête simultanée).
- Le SBOM brut est conservé compressé et dédoublonné : renvoyer le même document ne le
  stocke pas deux fois. Un dépôt qui renvoie le même SBOM pour le même commit ne crée rien.
- Rien du contenu d'un SBOM n'est journalisé ; seuls l'identifiant de l'ingestion, sa clé
  d'erreur et le nombre de composants le sont.
- Décision de conception : ADR 0015 (décodage dans le worker) et ADR 0016 (règles de
  l'inventaire).

## Rétention des instantanés

Chaque nuit à 02:30 UTC, une instance à workers applique la rétention à chaque
organisation (jobs `retention.snapshots_all`, puis `retention.snapshots_org`). Réglages
`retention.*` (`LOTOR_RETENTION_*`) :

| Réglage | Défaut | Effet |
| --- | --- | --- |
| `enabled` | `true` | `false` : aucun instantané ni aucune réception n'est supprimé |
| `days` | 90 | fenêtre, en jours (1 à 36 500) : tout instantané scanné ou reçu depuis est gardé |
| `count` | 0 | derniers instantanés de chaque référence gardés en plus, quel que soit leur âge |
| `monthly` | `true` | au-delà de la fenêtre, garder le dernier instantané de chaque mois (UTC), sans limite de durée |

- **Jamais supprimés** : le dernier instantané d'une référence (son instantané courant),
  l'instantané en vigueur au début de la fenêtre (le dernier plus ancien que la coupure),
  un instantané reçu dans la fenêtre même s'il a été scanné avant (envoi en retard),
  l'instantané de la dernière analyse d'une référence.
- Avec les réglages par défaut, une référence garde tous ses instantanés des 90 derniers
  jours, puis environ douze par an : l'état de la fin de chaque mois.
- Partent avec un instantané supprimé : ses réceptions ; un constat qu'il a vu en dernier
  reste, sans lien vers lui. Sont supprimées ensuite les **réceptions terminées** plus
  anciennes que la fenêtre (journal de réception), puis les **ensembles d'inventaire et
  SBOM bruts que plus rien ne référence** — et eux seuls. Ces orphelins sont supprimés
  même `enabled: false`. Les composants restent (les constats les référencent).
- Une ingestion concurrente n'est jamais gênée : elle verrouille l'ensemble ou le SBOM
  qu'elle réutilise, que la rétention saute alors (ADR 0039).
- Le même passage **purge les conteneurs archivés pour absence** depuis
  `containers.purge_after` (180 jours, voir « Conteneurs ») ; leurs ensembles et SBOM
  partent avec les orphelins.
- Chaque passage journalise son bilan (`rétention des instantanés`, champs `snapshots`,
  `ingestions`, `sets`, `blobs`, `diffs`, `containers`, `recompute`) et l'enregistre dans
  `snapshot_retention` avec l'**horizon** (la plus récente coupure appliquée) : avant
  cette date, l'historique d'une référence est réduit à un instantané par mois, et la
  recherche à une date passée (lot 3) avertit que ses résultats sont partiels.
- Allonger `days` ne rend pas ce qui a déjà été supprimé ; le raccourcir prend effet au
  passage suivant. Le premier passage sur une instance ancienne peut être long : il
  avance référence par référence, en transactions courtes, et reprend le lendemain s'il
  est interrompu. Surveiller sa durée par `lotor_job_duration_seconds{kind="retention.snapshots_org"}`.
- Les différences entre instantanés consécutifs (frise, comparaison) sont calculées par
  le job `inventory.diff` à chaque instantané créé, et recalculées après une rétention
  qui a réduit un historique (ADR 0038). La rétention les remet en file pour toute
  référence dont une différence manque, y compris celles reçues avant la mise à jour qui
  a introduit la frise.

## Base de vulnérabilités

Les SBOM sont confrontés à la base de vulnérabilités de **Grype** (schéma v6, environ
200 Mio compressée, 3,2 Gio installée), **commune à toutes les instances** (ADR 0017) :

1. **Vérification** (échéance `vulndb.check`, toutes les `vulndb.check_interval`, une seule
   instance à la fois) : lecture de la liste de distribution (`vulndb.listing_url`), et si
   elle annonce une base plus récente que la cible, téléchargement, vérification de la
   SHA-256 annoncée, installation complète pour valider l'ouverture, stockage de l'archive
   dans PostgreSQL (`vulndb_archives`, par blocs de 8 Mio), puis la base devient la
   **cible** (`vulndb_state`). Une archive corrompue ou dont la somme diffère n'est jamais
   stockée ni activée ; l'erreur est notée et affichée.
2. **Synchronisation** : chaque instance worker installe la cible dans `vulndb.dir` depuis
   PostgreSQL (jamais depuis Internet) au démarrage, toutes les `vulndb.sync_interval` et
   avant chaque analyse, puis bascule sans interrompre les analyses en cours. Deux workers
   ne produisent donc jamais de constats contradictoires.
3. **Réanalyse** : chaque nouvelle cible met en file la réanalyse de toutes les
   références actives, en priorité basse ; une ingestion fraîche passe devant.

L'écran **Administration → Base de vulnérabilités** montre la cible (date de
construction, âge, schéma, taille, origine, somme), la dernière vérification et son
erreur, la **version chargée par chaque instance worker** (à jour, en retard, aucune base,
ou sans nouvelles depuis 15 min ou trois `vulndb.sync_interval` ; table
`vulndb_instances`, rapportée à chaque synchronisation, retirée à l'arrêt propre, oubliée
après 7 jours sans nouvelles), les derniers imports et les archives stockées. Au-delà de `vulndb.max_age` (5 jours par défaut), ou sans base, un
avertissement apparaît sur toutes les pages d'administration et `lotor_vulndb_stale`
vaut 1 : à surveiller (alerte Prometheus conseillée sur `lotor_vulndb_stale == 1`).

| Réglage | Défaut | Rôle |
| --- | --- | --- |
| `listing_url` | liste d'Anchore | `latest.json` de Grype, ou d'un miroir interne (même arborescence) |
| `dir` | `/var/lib/lotor/vulndb` | copie locale de l'instance (chemin absolu) |
| `offline` | `false` | `true` : aucune interrogation de la liste (site isolé) |
| `check_interval` | 6 h | fréquence de vérification (au moins 10 min ; Anchore publie chaque jour) |
| `sync_interval` | 1 min | fréquence de contrôle de la copie locale |
| `max_age` | 120 h | âge déclenchant l'avertissement |
| `download_timeout` | 30 min | interrogation, téléchargement ou téléversement d'une archive ; les jobs de vérification et d'import ont le double |
| `max_archive_mib` | 2 048 | taille maximale d'une archive |
| `analysis_timeout` | 10 min | durée maximale d'une analyse, synchronisation locale comprise |

- **Espace disque** : sur chaque instance worker, environ **3,5 Gio** pour la base
  installée et **le double pendant une bascule** (ancienne et nouvelle), plus l'archive
  le temps de l'installer : prévoir 8 Gio libres dans `vulndb.dir`. L'instance qui vérifie
  la liste a besoin du même espace. Côté PostgreSQL, environ 200 Mio par archive
  conservée : **Purger les archives précédentes** (même écran, case de confirmation)
  supprime toutes les archives qui ne sont pas la cible ; la purge est journalisée.
- **Mémoire et CPU** : une analyse de 5 000 composants prend environ 6 s sur 4 cœurs
  (`docs/benchmarks.md`) ; la base est ouverte une seule fois par instance et partagée par
  les analyses simultanées (`workers.concurrency`, au plus `workers.org_limit` par
  organisation).
- **Plusieurs instances** : toutes lisent la même cible ; une instance purement web
  (`workers.enabled: false`) n'a pas de copie locale et reste prête sans base. Le premier
  démarrage d'un parc neuf n'a aucune base : les instances worker ne sont pas prêtes
  (`/readyz` 503) jusqu'à la fin de la première vérification (téléchargement et
  installation : quelques minutes). Les analyses demandées entre-temps se terminent sans
  rien écrire ; la première cible réanalyse tout.
- **Accès réseau** : seule l'instance qui exécute la vérification sort, vers
  `listing_url` et l'adresse de l'archive qu'elle annonce (`grype.anchore.io` par défaut),
  en HTTPS, par le mandataire de l'environnement (`HTTPS_PROXY`).
- **Hors ligne** : `vulndb.offline: true`, et soit un **miroir interne** de la liste
  (`listing_url` vers lui, `offline: false`), soit l'**import** d'une archive téléchargée
  ailleurs (`vulnerability-db_v6.*.tar.zst`, liste d'Anchore) par **Import manuel** sur
  l'écran de la base (ADR 0028) :
  - le fichier (au plus `vulndb.max_archive_mib`) est lu en flux et rangé par blocs dans
    PostgreSQL (`vulndb_imports`, `vulndb_import_chunks`), sans passer par le disque de
    l'instance web ; le téléversement dispose de `vulndb.download_timeout` (les délais
    `http.read_timeout` et `http.write_timeout` sont repoussés pour lui seul) ; un
    mandataire inverse doit accepter un corps de cette taille (`client_max_body_size`
    pour nginx) et la même durée ;
  - un job `vulndb.import` installe ensuite l'archive sur une instance worker (mêmes
    contrôles d'installation qu'un téléchargement, sans somme annoncée) et en fait la
    cible, **même si elle est plus ancienne** que la cible actuelle (retour arrière
    volontaire) ; il faut donc au moins une instance à workers ; les blocs sont supprimés
    à la fin ;
  - un seul import à la fois ; une archive invalide est refusée sans nouvel essai, une
    autre erreur est réessayée trois fois au plus ; l'état et l'erreur s'affichent sur
    l'écran, la demande et son issue au journal d'audit.
- Rien du contenu des SBOM n'est journalisé par l'analyse.

## Recherche et API utilisateur

La recherche transverse (`/o/<slug>/search`, T09, ADR 0024) et l'API utilisateur
(`/api/v1/orgs/<slug>/…`) n'ont rien à installer en dehors de la base.

- **Extensions PostgreSQL** : la migration 013 crée `pg_trgm` et `btree_gin` (extensions
  « trusted », que le propriétaire de la base crée sans être superutilisateur). Sur une base
  gérée qui les réserve à un administrateur, les créer avant la mise à jour, dans le schéma
  `public` : `CREATE EXTENSION pg_trgm WITH SCHEMA public; CREATE EXTENSION btree_gin WITH
  SCHEMA public;` (la migration les trouve alors déjà présentes).
- **Jetons d'accès personnels** (`lotor_pat_…`, ADR 0025) : chaque compte les crée et les
  révoque depuis « Mon compte » → « Jetons d'accès » (7 jours à 1 an, 20 actifs au plus,
  secret affiché une seule fois). Lecture seule, sur les organisations dont le compte est
  membre **au moment de la requête** : retirer un membre lui coupe l'accès sans toucher à
  ses jetons. Un compte désactivé voit ses jetons refusés. Création et révocation figurent
  au journal d'audit de l'instance ; les jetons ne sont jamais journalisés.
- **Limitation** : `user_api.rate_limit` (60 par défaut) borne les requêtes par minute et
  par jeton, `user_api.failure_rate_limit` (30) les jetons refusés par minute et par IP.
- **Exports** (écran et API, CSV ou JSON) : lus et écrits en flux, chacun tient une
  connexion du pool pendant son écriture. `user_api.max_exports` (4) borne les exports
  simultanés de l'instance (429 au-delà, avec `Retry-After`) et `user_api.export_timeout`
  (5 min) leur durée, qui remplace pour eux `http.write_timeout`. Garder
  `max_exports` nettement sous `database.max_open_conns`.
- **Performance** : `make bench-search` mesure la recherche sur le jeu de référence
  (`docs/benchmarks.md`). Sur une grosse organisation, un `ANALYZE` après une première
  ingestion massive aide le planificateur à choisir les index de recherche.

## Tableau de bord

La page d'accueil d'une organisation (`/o/<slug>`) et l'en-tête de chaque fiche projet
montrent les constats ouverts par sévérité, les KEV, la tendance, le délai médian de
correction, les agents muets, les projets les plus exposés et les composants vulnérables
les plus répandus (ADR 0027).

- Les chiffres du moment se calculent à chaque affichage ; les courbes lisent les
  statistiques quotidiennes (`org_daily_stats`, `project_daily_stats`). L'échéance
  `dashboard.stats_all` passe **toutes les heures** sur une instance à workers et met en
  file un `dashboard.stats_org` par organisation active, qui réécrit la ligne du jour
  (UTC) : la ligne d'un jour écoulé est l'état de sa fin de journée.
- Sur une installation neuve ou après la mise à jour qui apporte T10, l'historique
  commence au premier passage : la courbe n'a d'abord qu'un point, puis s'allonge d'un
  point par jour. Aucun historique n'est reconstitué.
- L'historique par projet est purgé au-delà de 400 jours ; celui de l'organisation est
  conservé (une ligne par jour).
- Sans instance à workers, les courbes ne s'allongent plus (les chiffres du moment restent
  justes) : `lotor_job_schedule_fires_total{schedule="dashboard.stats_all"}` doit
  progresser d'une unité par heure sur l'ensemble des instances.
- Depuis T14, les constats « non affecté » et « faux positif » ne comptent plus parmi les
  constats ouverts ; les statistiques déjà enregistrées ne sont pas réécrites.

## Triage et VEX

Les décisions de triage (ADR 0035) sont rangées dans `triage_decisions`, en **ajout
seul** pour le rôle d'exécution (vérifié au démarrage, comme le journal d'audit) ; le
statut effectif est recopié sur chaque constat (`findings.triage_status`).

- Un **risque accepté** échoit par un job `triage.expire` mis en file avec la décision
  pour le lendemain de sa date, à minuit UTC : il faut une instance à workers pour que les
  constats reviennent « à analyser » le jour même. Un job en échec se voit, comme les
  autres, dans « Administration » → « Traitements ».
- La migration 018 donne à tous les constats existants le statut « à analyser ».
- L'**import d'un VEX** depuis l'interface accepte un fichier JSON de 1 Mio au plus et
  5 000 déclarations ; le mandataire inverse doit laisser passer ce corps sur
  `/o/<slug>/projects/<projet>/vex/import` et `/o/<slug>/triage/import`.
- Décisions et imports sont au journal d'audit de l'organisation (`triage.decided`,
  `triage.withdrawn`, `triage.expired`, `triage.vex_imported`).

## Politiques et notifications

Les politiques (ADR 0045) s'évaluent dans les workers : après chaque analyse
(`policy.evaluate_project`, priorité haute), après chaque changement de triage ou de règle,
et chaque jour à 02:00 UTC (`policy.evaluate_all`, puis `policy.evaluate_org` par
organisation). Les notifications (ADR 0046) partent par le job `notify.send` d'un canal ;
le résumé quotidien par `notify.digest_all` à `notify.digest_hour`. Il faut une instance à
workers. Format des messages et du webhook : [`notifications.md`](notifications.md).

Configuration (`config.example.yaml`) :

- `notify.public_url` : URL publique du serveur, pour les liens des messages et des
  verdicts de commit (`https://sbom.example.org`). Vide : messages sans lien.
- `notify.timeout` (30 s) : durée maximale d'un envoi.
- `notify.allow_private_networks` (`false`) : les canaux saisis par les administrateurs
  d'organisation ne peuvent joindre **aucune adresse de bouclage, privée, de lien local,
  partagée ni de multidiffusion**, ni les plages réservées (bancs d'essai, documentation,
  classe E), ni une adresse IPv6 qui porte une telle adresse IPv4 (NAT64 `64:ff9b::/96`,
  6to4 `2002::/16`) (protection contre les requêtes vers le réseau interne, SSRF) ; la
  vérification se fait à la connexion, après la résolution DNS. Les ports ne sont pas
  restreints : un administrateur d'organisation peut, par le test d'un canal, savoir si
  un port d'un hôte public répond depuis le serveur (risque accepté, SEC2-08). Ne le passer à
  `true` que si toutes les organisations de l'instance sont de confiance (relais
  interne). Les envois HTTP ne passent par **aucun mandataire** (`HTTPS_PROXY` est ignoré) :
  un serveur qui ne sort que par un proxy ne joint que les canaux e-mail.
- `smtp.*` : serveur d'envoi des courriels. `tls: starttls` (port 587, STARTTLS exigé
  avant tout mot de passe), `tls` (TLS implicite, port 465) ou `none` (relais local, sans
  authentification). `smtp.from` est l'expéditeur ; le mot de passe se donne de préférence
  par `LOTOR_SMTP_PASSWORD`. Sans `smtp.host`, un canal e-mail échoue avec « Aucun serveur
  SMTP n'est configuré » (visible sur la liste des canaux et à l'essai).

Exploitation :

- Un canal en panne voit ses envois réessayés une dizaine d'heures (30 tentatives), puis
  relancés chaque jour ; un job `notify.send` épuisé apparaît dans « Administration » →
  « Traitements » et peut être relancé.
- Les secrets des canaux sont chiffrés par `secrets.keys` (voir « Clés de chiffrement des
  secrets ») et rechiffrés avec la clé active au démarrage.
- Journal d'audit de l'organisation : `policy.created`, `policy.updated`,
  `policy.deleted`, `channel.created`, `channel.updated`, `channel.deleted`,
  `channel.tested`.
- La migration 021 crée les tables des politiques et des canaux et date le correctif des
  constats existants (`fixed_seen_at`) à leur première détection.

## Agent dépôt

`lotor-repo-agent` est un service externe aux CI : il détient seul les accès aux forges,
reçoit leurs webhooks de push, extrait le commit visé, l'analyse avec Syft et envoie le
SBOM (CycloneDX 1.6, composants marqués `lotor:origin=syft`). Configuration d'exemple
commentée et unité systemd durcie : `deploy/lotor-repo-agent/`.

### Installation

1. Dans l'organisation : **Agents › Nouvel agent dépôt** ; noter le jeton (affiché une
   fois).
2. Sur la machine de l'agent (git 2.30 ou plus, accès HTTPS aux forges et au serveur) :
   extraire `lotor-repo-agent_<version>_linux_<arch>.tar.gz`, puis
   `sudo install -m 0755 lotor-repo-agent /usr/bin/`,
   `sudo install -m 0644 lotor-repo-agent.service /etc/systemd/system/`,
   `sudo install -d -m 0700 /etc/lotor-repo-agent` et
   `sudo install -m 0644 config.example.yaml /etc/lotor-repo-agent/config.yaml`.
3. Créer la GitHub App ou le compte de service GitLab (ci-dessous), renseigner
   `server.*`, `forges[]` et `allowed_namespaces`, chiffrer les secrets (« Secrets et
   credentials systemd »), retirer de l'unité les credentials des forges non utilisées.
4. `sudo systemctl daemon-reload && sudo systemctl enable --now lotor-repo-agent` ;
   `journalctl -u lotor-repo-agent` montre le premier rattrapage (« rattrapage »,
   « SBOM envoyé »).
5. Confier les dépôts à l'agent depuis la fiche de chaque projet de type dépôt, puis
   déclarer le webhook sur la forge.

### Mode d'exploitation

- **Une instance par organisation** : elle porte le jeton d'un agent dépôt de cette
  organisation (« Agents › Nouvel agent dépôt »). Les dépôts lui sont confiés depuis leur
  fiche ; leur **URL de forge** (`https://github.com/acme/app`,
  `https://gitlab.example.org/groupe/sous-groupe/projet`) désigne la forge configurée dont
  l'URL web la préfixe. Un dépôt sans forge configurée est signalé au journal et ignoré.
- **Périmètre** : `forges[].allowed_namespaces` (obligatoire) liste les propriétaires
  GitHub ou les groupes GitLab (sous-groupes compris) dont l'agent accepte d'analyser les
  dépôts, ou `*` pour tout ce que ses identifiants lisent. Les URL de forge viennent du
  serveur, c'est-à-dire des administrateurs d'organisation : sans cette liste, un
  administrateur pourrait faire inventorier n'importe quel dépôt lisible par les
  identifiants de l'agent. Un dépôt hors périmètre est signalé au journal et ignoré.
- **TLS du récepteur** : il écoute en HTTP par défaut (`:1762`) ; `X-Gitlab-Token` y
  circulerait en clair. Le placer derrière un mandataire TLS, ou poser
  `webhook.tls_cert_file` et `webhook.tls_key_file`.
- **Webhooks** : l'URL publique de l'instance est `https://<hôte public>/webhooks/<nom de
  la forge>` (le `name` de la forge dans la configuration). Seule cette route et
  `GET /healthz` sont servies. Le récepteur borne le corps (`webhook.max_body_kib`),
  limite le débit par IP (`webhook.rate_limit`), **refuse tout webhook mal signé**
  (401, journalisé avec la forge et l'IP, sans contenu), ignore une livraison déjà reçue
  (`X-GitHub-Delivery`, `X-Gitlab-Event-UUID`) et répond aussitôt (202) : l'analyse est
  asynchrone. Un webhook ne sert que de signal : l'agent résout lui-même la tête de la
  référence auprès de la forge, si bien qu'un webhook rejoué ou en retard ne fait jamais
  analyser un commit dépassé.
- **Rattrapage** : il n'y a pas de file durable côté agent. Au démarrage puis toutes les
  `catchup.interval` (15 min), l'agent relit ses dépôts (`GET /api/v1/agent/projects`),
  envoie un signal de vie, compare la tête de chaque référence suivie au commit du
  dernier instantané du serveur et analyse les commits manqués, **du plus ancien au plus
  récent** (`catchup.max_commits`, 20 au plus, les plus récents). Un webhook perdu, une
  file pleine ou un agent arrêté sont donc rattrapés au passage suivant. Une étiquette, une
  première analyse ou une histoire réécrite donnent l'analyse de la seule tête. Coût : un
  appel d'API de forge par référence et par passage (plus une comparaison s'il y a du
  neuf) ; 500 références toutes les 15 minutes font environ 2 000 appels par heure, sous la
  limite de 5 000 par heure d'une installation de GitHub App.
- **Serveur** : client commun des agents (`internal/agentclient`) ; `server.retries`
  tentatives pour une erreur réseau, 429 ou 5xx, délai exponentiel, `Retry-After`
  respecté ; un refus 4xx (référence inconnue, SBOM trop gros) est définitif jusqu'au
  redémarrage. HTTPS seulement ; `server.ca_file` pour une autorité privée,
  `server.client_cert_file` et `server.client_key_file` (`credential:<nom>` ou fichier en
  `0600`) quand le serveur exige le mTLS, `server.proxy` pour un mandataire.
- **Analyse** : un sous-répertoire de `work.dir` par commit, supprimé à la fin quoi qu'il
  arrive (et au démarrage s'il en reste après un arrêt brutal). git est lancé avec un
  environnement maîtrisé : ni configuration système ni globale, aucune invite, crochets
  désactivés, `core.symlinks=false` (un lien symbolique du dépôt devient un simple fichier
  qui contient sa cible), LFS inerte, un seul protocole (celui de l'URL de clonage), pas de
  redirection, objets vérifiés (`transfer.fsckObjects`). Le commit exact est récupéré
  (`git fetch --depth 1 --no-tags <url> <commit>`), extrait puis vérifié ; `.git` est
  supprimé avant le scan. Syft ne lance aucun programme et n'accède pas au réseau (le
  catalogueur Go n'appelle pas `go list`). Aucun fichier du dépôt n'est exécuté.
- **Bornes** : `work.max_clone_mib` (1 024) mesuré pendant le clonage, qui est tué
  au-delà (échec définitif pour ce commit, non retenté avant redémarrage) ;
  `work.clone_timeout` (10 min) et `work.scan_timeout` (15 min), retentés au passage
  suivant ; `work.parallelism` (2) analyses simultanées, jamais deux à la fois pour une
  même référence ; `work.queue_size` (1 000) références en attente.
- Le SBOM produit ne porte ni numéro de série ni horodatage : deux analyses du même
  commit donnent les mêmes octets, que le serveur reconnaît comme un renvoi (200, rien de
  créé). Le composant décrit est le projet (son slug) à ce commit.
- **Réseau sortant** : le serveur lotor, l'API et le service git HTTPS des forges.
  Entrant : le récepteur de webhooks seul.

### GitHub : GitHub App

1. Paramètres de l'organisation GitHub › *Developer settings* › *GitHub Apps* › *New GitHub
   App*. URL du webhook : `https://<hôte public>/webhooks/github` ; secret de webhook : une
   valeur aléatoire (`openssl rand -hex 32`), conservée pour l'agent.
2. **Droits minimaux** (*Repository permissions*) : **Contents : Read-only** (clonage,
   lecture des références et comparaisons) ; *Metadata : Read-only* est imposé par GitHub.
   Aucun autre droit, aucun droit d'organisation ni de compte, sauf **Commit statuses :
   Read and write** si l'agent publie le verdict des politiques (« Statut de commit »
   ci-dessous). Événements : **Push** seulement.
3. Générer une clé privée (fichier PEM) ; noter l'*App ID*.
4. Installer l'application sur l'organisation, en limitant l'accès aux dépôts suivis
   (*Only select repositories*). L'installation est trouvée pour chaque dépôt ; la fixer
   par `installation_id` si l'application a plusieurs installations.

L'agent signe un JWT RS256 de 9 minutes avec la clé, obtient un jeton d'installation
**restreint à `contents: read` et au seul dépôt analysé** (même si l'application a
d'autres droits ou d'autres dépôts), le garde en mémoire, par dépôt, jusqu'à cinq minutes
de son expiration, et le présente à git dans un en-tête HTTP
(`x-access-token`). Vérification : un dépôt non sélectionné dans l'installation est refusé
(`installation de l'application : … introuvable` au journal), et un push sur un dépôt
suivi apparaît dans l'onglet *Advanced › Recent deliveries* de l'application avec une
réponse 202.

### GitLab : compte de service

1. Créer un compte de service (GitLab 16.1 et plus, Premium) ou, à défaut, un utilisateur
   dédié ; lui donner le rôle **Reporter** (le plus faible qui lit le code) sur les
   groupes ou projets suivis. Un jeton d'accès de groupe ou de projet, au rôle Reporter,
   convient aussi.
2. Jeton d'accès avec les **portées minimales** `read_api` (références et comparaisons) et
   `read_repository` (clonage) ; aucune portée d'écriture. Les droits de ce compte bornent
   ce que les organisations peuvent faire analyser : ne lui ouvrir que les groupes
   suivis, et les reporter dans `allowed_namespaces`. Prévoir sa rotation avant son
   expiration (déposer le nouveau credential et redémarrer l'agent).
3. Sur chaque projet (ou groupe) : *Settings › Webhooks*, URL
   `https://<hôte public>/webhooks/gitlab`, *Secret token* aléatoire, déclencheurs **Push
   events** et **Tag push events**, vérification SSL activée.

Le secret est comparé en temps constant à `X-Gitlab-Token`. Vérification : *Test › Push
events* sur la page du webhook doit répondre 202 ; un secret faux, 401.

### Statut de commit

Avec `status.enabled: true` (`LOTOR_REPO_STATUS_ENABLED`), l'agent attend le verdict des
politiques après chaque envoi (au plus `status.timeout`, 15 min) et le publie sur le commit
sous le nom `status.context` (`lotor`) ; voir [`notifications.md`](notifications.md#statut-de-commit-agent-dépôt)
et l'ADR 0047. Désactivé par défaut, car il demande un droit de plus :

- **GitHub** : permission *Commit statuses : Read and write* de l'application (puis
  accepter la nouvelle permission sur chaque installation). L'agent demande pour cela un
  jeton séparé, restreint au dépôt et à `statuses: write` ; le jeton du clonage reste en
  lecture seule.
- **GitLab** : portée `api` (au lieu de `read_api`) et rôle **Developer** sur les projets
  suivis pour le compte de service.

Le serveur doit avoir `notify.public_url` pour que le statut porte un lien. Pendant
l'attente, le commit suivant de la même référence attend son tour ; un verdict non rendu
dans le délai laisse le statut « en attente » (journal : `verdict non rendu dans le
délai`). Un refus de la forge est journalisé et n'empêche pas l'envoi du SBOM.

### Recette sur une vraie forge

La recette du lot 1 a exercé l'agent dépôt réel contre une **forge simulée** (API de
GitHub et de GitLab, git HTTP intelligent sur des clones de dépôts publics) : la session
de réalisation n'avait ni GitHub App ni compte de service GitLab. L'essai sur une vraie
forge reste à faire, en une demi-heure :

1. GitHub : créer une GitHub App de test (droits *Contents : Read-only*, événement *Push*)
   et l'installer sur **un** dépôt de test (*Only select repositories*) ; GitLab : créer
   un jeton de projet *Reporter* (`read_api`, `read_repository`) sur un projet de test.
2. Configurer l'agent (`allowed_namespaces` : le propriétaire ou le groupe de test),
   créer les projets dans l'organisation (URL `https://github.com/<propriétaire>/<dépôt>`,
   `https://gitlab.com/<groupe>/<projet>`), les confier à l'agent.
3. Vérifier, dans l'ordre : le journal montre « rattrapage » puis « SBOM envoyé » pour
   chaque dépôt ; l'onglet **Instantanés** de chaque projet porte le commit de la tête de
   branche ; un push sur le dépôt apparaît dans *Recent deliveries* (GitHub) ou *Test ›
   Push events* (GitLab) avec la réponse 202, et un nouvel instantané arrive ; un secret de
   webhook faux est refusé (401) ; un dépôt hors de `allowed_namespaces` confié à l'agent
   est ignoré (journal « dépôt sans forge configurée ou hors de allowed_namespaces ») ; GitHub : un dépôt non sélectionné dans
   l'installation est refusé (« installation de l'application : … introuvable »).
4. Rechercher une CVE connue d'une dépendance du dépôt : le projet apparaît.

### Secrets et credentials systemd

Les secrets (jeton d'agent, clé privée de la GitHub App, jeton GitLab, secrets de
webhook, clé TLS du récepteur) ne sont **jamais dans le fichier de configuration** : celui-ci
les désigne par `credential:<nom>` (credential systemd) ou par le chemin absolu d'un
fichier lisible du seul compte de l'agent (`0600` ou `0400`, refusé sinon). Avec l'unité
fournie (`DynamicUser=yes`, `StateDirectory=lotor-repo-agent`, durcissement
`ProtectSystem=strict`, `NoNewPrivileges=yes`, aucune capacité) :

```bash
install -d -m 0700 /etc/lotor-repo-agent
systemd-creds encrypt --name=agent-token agent-token.txt /etc/lotor-repo-agent/agent-token.cred
systemd-creds encrypt --name=github-app-key app.private-key.pem /etc/lotor-repo-agent/github-app-key.cred
systemd-creds encrypt --name=github-webhook-secret github-secret.txt /etc/lotor-repo-agent/github-webhook-secret.cred
systemd-creds encrypt --name=gitlab-token gitlab-token.txt /etc/lotor-repo-agent/gitlab-token.cred
systemd-creds encrypt --name=gitlab-webhook-secret gitlab-secret.txt /etc/lotor-repo-agent/gitlab-webhook-secret.cred
shred -u agent-token.txt app.private-key.pem github-secret.txt gitlab-token.txt gitlab-secret.txt
```

Retirer de l'unité les `LoadCredentialEncrypted=` des forges non utilisées. Les
identifiants de clonage n'apparaissent ni dans les arguments des processus (`ps`), ni
dans l'URL, ni dans les journaux : ils passent à git par l'environnement
(`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`, en-tête `Authorization`), que `ProtectProc=
invisible` cache aux autres comptes.

### Exploitation

- Journaux `slog` (`logging.format: json` en production) : rattrapages, pushs reçus et
  refusés, envois (`project`, `ref`, `commit`), échecs d'analyse avec leur cause.
- `GET /healthz` sur l'écoute du récepteur sert de sonde de vie.
- Arrêt sur SIGTERM : le récepteur termine ses requêtes (10 s), les clonages en cours
  sont tués et leurs répertoires supprimés ; le travail perdu est rattrapé au démarrage.
- Décision de conception : ADR 0023.

### Enrichissement IA

L'agent dépôt peut compléter l'inventaire de Syft par les composants qu'aucun manifeste ne
déclare : bibliothèques recopiées (JavaScript minifié, C, PHP), images de base des
Dockerfile, scripts chargés depuis un CDN, outils installés par `curl … | sh`. Décisions :
ADR 0042 (fournisseurs), 0043 (réglages, politique d'envoi de code, vérificateur), 0044
(confinement).

**Qui décide de quoi**

| Niveau | Réglage | Effet |
| --- | --- | --- |
| Instance (serveur) | `ai.forbid_external` (`LOTOR_AI_FORBID_EXTERNAL`, faux par défaut) | Vrai : aucun dépôt ne peut être envoyé à un fournisseur externe ; un dépôt réglé « fournisseur externe » est traité comme « modèle local uniquement » |
| Projet (interface) | **Paramètres du dépôt → Enrichissement IA** : IA désactivée (défaut), modèle local uniquement, fournisseur externe autorisé | « Fournisseur externe » est réservé aux administrateurs d'organisation ; les autres réglages aux administrateurs de l'équipe du projet ; chaque changement est journalisé (`project.ai_mode_changed`) ; changer l'URL de forge d'un dépôt « externe » sans ce droit ramène le réglage à « désactivé » (motif `forge_url_changed`, SEC2-03) |
| Agent dépôt | `ai.local` (Ollama) et `ai.external` (Anthropic) | Sans modèle configuré, l'agent envoie le SBOM Syft seul, quel que soit le réglage des projets |

Un dépôt réglé « IA désactivée » n'appelle jamais de modèle. « Modèle local uniquement »
n'utilise que `ai.local` (s'il est absent, pas d'IA) ; « fournisseur externe » utilise
`ai.external`, à défaut `ai.local`.

**Politique d'envoi de code.** Ce qui part vers le modèle : le prompt système (versionné,
embarqué dans le binaire), le slug du projet, le commit, la liste des fichiers modifiés,
et le contenu des fichiers que le modèle lit ou fouille par les outils, dans
l'arborescence du commit analysé et nulle part ailleurs. Ne partent jamais : les fichiers
exclus (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `.ssh/`, `.aws/`, `.npmrc`, `.netrc`,
`*.tfstate`, `*.tfvars`, `credentials*`, `secrets*`, `kubeconfig*`… et `ai.exclude`), tout
fichier qui contient une clé privée, les fichiers binaires ou de plus de 2 Mio, le
répertoire `.git`, les secrets de l'agent (jeton, clés des forges, clé d'API) et son
environnement. Un fichier exclu n'est pas non plus **nommé** : ni dans la liste des
fichiers modifiés, ni dans une liste de répertoire (SEC2-07 ; un fichier de plus de
64 Kio qui contiendrait une clé privée est listé, puis refusé à la lecture). Le volume
lu est borné par `ai.max_read_kib` par analyse.

**Modèle local (Ollama).** Un modèle qui sait appeler des outils, servi par Ollama dans
l'infrastructure de l'exploitant :

```yaml
ai:
  local:
    url: http://127.0.0.1:11434
    model: qwen3:14b
    context_tokens: 32768
```

L'URL doit rester dans le périmètre de confiance : l'agent ne vérifie pas où tourne le
serveur Ollama.

**Fournisseur externe (Anthropic).** Modèle par défaut `claude-sonnet-5-5`, à confirmer
ou changer au vu de l'évaluation ci-dessous. La clé d'API est un secret, comme les autres :

```bash
systemd-creds encrypt --name=anthropic-api-key anthropic-key.txt /etc/lotor-repo-agent/anthropic-api-key.cred
shred -u anthropic-key.txt
```

puis décommenter `LoadCredentialEncrypted=anthropic-api-key:…` dans l'unité et régler
`ai.external.provider: anthropic` (`api_key_file: credential:anthropic-api-key` par
défaut). Le client ignore toute variable `ANTHROPIC_*` de la machine : seule la
configuration de l'agent fixe l'adresse (`ai.external.base_url`, https) et la clé.

**Budget et repli.** Une analyse s'arrête au-delà de `ai.max_turns` (40),
`ai.max_input_tokens` (600 000, cache compris), `ai.max_output_tokens` (40 000),
`ai.max_read_kib` (1 Mio ; chaque recherche y coûte 2 Kio en plus de ses résultats) ou
`ai.timeout` (20 min, vérifié aussi entre deux outils et pendant une recherche) ; une
réponse du modèle n'exécute que 20 appels d'outils au plus ; une erreur ou un refus du fournisseur
a le même effet : le SBOM part avec les seuls composants de Syft, marqué « enrichissement
incomplet » (fiche de l'instantané). L'analyse est incrémentale (fichiers modifiés depuis
le dernier commit analysé par le modèle, selon la forge, et fichiers des composants IA
précédents), complète au premier passage, après un redémarrage et au moins tous les
`ai.full_interval` (7 jours). Les commits intermédiaires d'un rattrapage n'appellent pas
le modèle : leurs composants IA précédents sont revérifiés et reportés.

**Preuve.** Aucun composant n'est retenu sans que le vérificateur de l'agent ait relu sa
preuve dans le fichier, au commit analysé : extrait à la ligne annoncée (à trois lignes
près), nom et version présents, purl valide et cohérent avec le fichier ; jamais une
preuve tirée de la documentation (README, CHANGELOG, `*.md`), d'un manifeste que Syft lit
déjà, ou d'un fichier qui s'adresse à un modèle. Les motifs de rejet sont comptés dans
le journal (`enrichissement IA`, champs `rejected_*`), comme la consommation de jetons ;
jamais le contenu d'un fichier ni d'un candidat. La fiche d'un composant d'origine IA
montre sa preuve (fichier, ligne, extrait, confiance, modèle).

### Évaluer l'enrichissement IA

La qualité (taux de faux positifs, rappel) et le coût se mesurent avec un vrai modèle sur
le corpus annoté `testdata/ai-corpus` **et** sur l'échantillon pilote annoté
`testdata/ai-pilot` (les quatre dépôts publics du parc pilote du lot 1) ; seuils, sur
chacun des deux jeux : faux positifs ≤ 5 %, rappel ≥ 80 %. Hors CI, car l'évaluation
consomme des appels payants. Pas à pas :

1. Clé d'API dans un fichier lisible du seul utilisateur :
   `install -m 0600 /dev/null /tmp/anthropic-key`, puis y écrire la clé (`sk-ant-…`).
2. Cloner l'échantillon pilote à ses commits annotés (réseau, quelques Mio) :
   `scripts/ai-pilot-fetch.sh /tmp/lotor-ai-pilot` (le script vérifie chaque tête).
3. Contrôle à blanc, sans clé ni coût : `LOTOR_EVAL_AI_PROVIDER=credulous
   LOTOR_EVAL_AI_PILOT_DIR=/tmp/lotor-ai-pilot make eval-ai`. Un modèle fictif soumet tout
   ce qu'il trouve ; la cible vérifie que chaque composant annoté est prouvable et que
   chaque composant accepté a une preuve qui se revérifie contre le dépôt. Ses taux ne sont
   pas une mesure (ce modèle n'écarte aucun piège).
4. Mesure :

   ```bash
   LOTOR_EVAL_AI_PROVIDER=anthropic LOTOR_EVAL_AI_API_KEY_FILE=/tmp/anthropic-key \
   LOTOR_EVAL_AI_PILOT_DIR=/tmp/lotor-ai-pilot LOTOR_EVAL_AI_RUNS=3 \
   LOTOR_EVAL_AI_REPORT=/tmp/eval-ai.json make eval-ai
   # autre modèle : LOTOR_EVAL_AI_MODEL=… ; modèle local :
   # LOTOR_EVAL_AI_PROVIDER=ollama LOTOR_EVAL_AI_MODEL=qwen3:14b make eval-ai
   ```

   Trois passages des 11 cas du corpus et des 4 dépôts pilotes : 45 analyses. Durée et
   coût ne sont pas encore connus (aucune mesure réelle à ce jour) : ils s'affichent à la
   fin, par jeu.
5. Lire le rapport (sortie et `/tmp/eval-ai.json`) : pour chaque jeu (`corpus`, `pilote`),
   composants acceptés à raison, faux positifs (nommés), oubliés, ignorés, preuves
   revérifiées, motifs de rejet, tours, jetons, coût et durée, puis le taux de faux
   positifs, le rappel et le coût moyen par analyse (tarif de `claude-sonnet-5-5` par
   défaut, réglable par `LOTOR_EVAL_AI_PRICE_*`). La cible échoue si un seuil n'est pas
   tenu sur l'un des deux jeux, si un composant accepté n'a pas de preuve vérifiée ou si un
   témoin des dépôts hostiles atteint le fournisseur.
6. Reporter les deux jeux de chiffres (modèle, date, passages, faux positifs, rappel, coût
   moyen) dans le Journal de T18, cocher le critère des seuils s'ils sont tenus, et
   confirmer ou changer le modèle par défaut (`llm.DefaultAnthropicModel`). Un seuil non
   tenu : ajuster le prompt (nouvelle version de `prompts/system-v*.md`) et recommencer
   avant d'activer l'IA sur des projets ; un faux positif du pilote peut aussi révéler une
   annotation à revoir (`testdata/ai-pilot/README.md`, « Règles d'annotation »).

## Clés de chiffrement des secrets

Les secrets stockés en base (secrets TOTP, secrets des canaux de notification, puis OIDC)
sont chiffrés en AES-256-GCM par des clés nommées :
`secrets.keys` (`LOTOR_SECRETS_KEYS=id:base64,…`) et `secrets.active_key`. Générer une
clé : `openssl rand -base64 32`. Un nom de clé : minuscules, chiffres, `-` et `_`, 32
caractères au plus (par exemple la date : `2026-10`).

Les clés sont **obligatoires** : les secrets TOTP des comptes sont chiffrés en base. Les
perdre toutes impose de réinitialiser le TOTP de chaque compte.

Rotation : ajouter la nouvelle clé à côté de l'ancienne, la désigner comme active,
redémarrer ; les nouveaux secrets sont chiffrés avec elle, les anciens restent lisibles.
Au démarrage, le serveur rechiffre les secrets TOTP et ceux des canaux de notification
avec la clé active (le journal donne leur nombre) : l'ancienne clé peut être retirée au
démarrage suivant.

## Sauvegarde et restauration

Tout l'état du serveur est dans PostgreSQL : comptes, organisations, projets, SBOM reçus
(compressés), inventaire, constats, journaux d'audit, file de traitements, archives de la
base de vulnérabilités. À sauvegarder :

| Élément | Comment | Remarque |
| --- | --- | --- |
| Base PostgreSQL | `pg_dump -Fc` par le **rôle propriétaire**, ou sauvegarde physique (`pg_basebackup`, archivage WAL) | le propriétaire a `BYPASSRLS` : le vidage contient toutes les organisations |
| Clés `secrets.keys` | coffre-fort, **séparément** de la base | sans elles, les secrets TOTP restaurés sont illisibles |
| `/etc/lotor/` | configuration et fichier d'environnement | TLS : certificats, clés, autorité des agents |
| Agents | rien d'indispensable | un agent perdu se réinscrit (nouveau jeton) |

`vulndb.dir` n'est **pas** à sauvegarder : chaque instance le reconstruit depuis
PostgreSQL au démarrage. Les archives de la base de vulnérabilités pèsent environ 200 Mio
chacune dans le vidage (650 Mio pour une archive importée en gzip) : **Purger les
archives précédentes** avant la sauvegarde la réduit.

```bash
# Sauvegarde logique (cohérente, sans arrêt du service)
pg_dump -Fc -d 'postgres://lotor_owner:…@db:5432/lotor' -f lotor-$(date -u +%F).dump
```

**Restauration** (vérifiée en recette sur la base du parc pilote : vidage, restauration
dans une base neuve, démarrage, connexion et recherche identiques) :

1. Arrêter toutes les instances.
2. Créer les rôles (mêmes noms) et une base vide appartenant au propriétaire
   (« Rôles et droits ») ; sur un PostgreSQL neuf, créer `pg_trgm` et `btree_gin` si le
   propriétaire n'en a pas le droit (« Recherche et API utilisateur »).
3. Restaurer par le propriétaire :
   `pg_restore --no-owner --role=lotor_owner -d 'postgres://lotor_owner:…@db:5432/lotor' lotor-AAAA-MM-JJ.dump`.
   Les droits du rôle d'exécution, les privilèges par défaut et les retraits du journal en
   ajout seul sont dans le vidage : avec les mêmes noms de rôles, rien à reprendre. Avec un
   autre nom de rôle d'exécution, appliquer « Changer de rôle d'exécution ».
4. Démarrer une instance avec la même version (ou plus récente : elle migre) et les mêmes
   clés `secrets.keys` ; vérifier `/readyz`, la connexion et une recherche.

Les jobs en cours au moment du vidage sont repris après restauration (baux expirés) ; les
agents renvoient au cycle suivant ce que la base restaurée ne connaît pas encore (envoi
conditionnel, rattrapage de l'agent dépôt).

## Mise à jour

1. Lire [`CHANGELOG.md`](../CHANGELOG.md) (réglages renommés ou nouveaux, actions
   requises). Avant la v1.0, une version peut changer la configuration.
2. **Sauvegarder** la base (ci-dessus) : une migration ne se défait pas.
3. Remplacer le binaire de **toutes** les instances, puis les redémarrer : la première qui
   a `migration.dsn` applique les migrations sous verrou, en une transaction ; les autres
   attendent puis démarrent. Une instance restée sur l'ancienne version voit une migration
   inconnue : elle refuse de redémarrer et son `/readyz` passe à 503 (`schema`), ce qui la
   retire d'un répartiteur de charge. Prévoir donc une courte interruption, ou démarrer
   les nouvelles instances avant d'arrêter les anciennes.
4. Vérifier `journalctl -u lotor-server` (« migration appliquée », « schéma à jour ») et
   `/readyz`.
5. **Agents** : l'API des agents est versionnée (`/api/v1`) ; un changement incompatible
   serait annoncé dans `CHANGELOG.md`, avec l'ordre de mise à jour. Mettre à jour l'agent serveur par son
   paquet (le démon redémarre, l'inscription est gardée) et l'agent dépôt en remplaçant
   son binaire puis `systemctl restart lotor-repo-agent`.

Retour arrière : restaurer la sauvegarde prise avant la mise à jour et réinstaller
l'ancien binaire (un ancien binaire refuse une base migrée par une version plus récente).

**De 0.1.0 à 0.2.0** (lot 2), à décider **avant** la mise à jour :

- les ports par défaut changent : 1758 au lieu de 8080 pour `web.port`, 1761 au lieu de
  8081 pour `management.port`, `:1762` au lieu de `:8080` pour `webhook.listen` de l'agent
  dépôt. Une installation qui les fixe déjà ne change rien ; sinon, les fixer pour garder
  les anciens, ou adapter le mandataire inverse, les sondes, la collecte des métriques et
  l'adresse des webhooks déclarée dans les forges ;
- les migrations 016 à 023 s'appliquent au démarrage ; la 016 crée l'équipe « Général »
  de chaque organisation et y place tous les projets, les jetons d'inscription, les agents
  serveur et tous les membres à leur ancien rôle (`viewer` → lecteur, `analyst` →
  analyste, `admin` → administrateur d'équipe ; le rôle d'organisation devient « membre »,
  sauf les administrateurs) : vérifier ensuite la page **Équipes** de chaque organisation
  (essai de la recette : instance 0.1.0 réelle mise à jour, voir le Journal de T18) ;
- la première rétention nocturne garde tout depuis 90 jours puis le dernier instantané de
  chaque mois, et supprime réceptions et SBOM devenus orphelins
  ([Rétention des instantanés](#rétention-des-instantanés)) : régler `retention.*` avant
  si une autre politique est voulue (`retention.enabled: false` suspend la réduction) ;
- les conteneurs archivés pour absence depuis `containers.purge_after` (180 jours) sont
  supprimés avec leur historique : rien en 0.1.0, qui n'inventoriait pas de conteneurs,
  mais à régler avant d'activer `containers.enabled` sur les agents ;
- les comptes existants n'ont pas de codes de secours : les inviter à en générer depuis
  **Mon compte › Second facteur** ;
- agents : l'agent serveur 0.1.0 continue de fonctionner (vérifié par la recette ; les
  conteneurs demandent l'agent 0.2.0 et `containers.enabled`, et l'agent 0.2.0 reprend
  l'inscription et l'état du 0.1.0) ; l'agent dépôt 0.2.0 est nécessaire pour
  l'enrichissement IA et le statut de commit, tous deux désactivés par défaut.

## Supervision

| Quoi | Où | Seuil conseillé |
| --- | --- | --- |
| Disponibilité | `GET /readyz` (écoute de gestion) | 503 plus de 2 min hors démarrage |
| Base de vulnérabilités | `lotor_vulndb_stale == 1`, `lotor_vulndb_target_age_seconds` | âge > `vulndb.max_age` (5 jours) |
| Instance worker sans base | `lotor_vulndb_loaded == 0` | plus de 15 min |
| Traitements en échec | `lotor_jobs{status="dead"}` | toute hausse ; détail dans **Administration › Traitements** |
| File qui ne se vide pas | `lotor_jobs{status="pending"}` | croissante pendant 30 min |
| Baux perdus | `rate(lotor_job_runs_total{outcome="lost"}[15m])` | non nulle durablement |
| Statistiques du tableau de bord | `increase(lotor_job_schedule_fires_total{schedule="dashboard.stats_all"}[2h])` (somme des instances) | 0 |
| Erreurs HTTP | `lotor_http_requests_total{status=~"5.."}` | taux anormal |
| Pool de connexions | `go_sql_wait_count_total`, `go_sql_in_use_connections` | attentes croissantes |
| Disque | `vulndb.dir` (8 Gio libres), volume de PostgreSQL | < 20 % libre |
| Agents muets | tableau de bord de chaque organisation (« Agents muets », 7 jours) | tout agent muet |
| Sécurité | journal d'audit (« compte verrouillé », « procédure de secours », imports et purges de la base) | à relire |

Exemple de règles Prometheus :

```yaml
groups:
  - name: lotor
    rules:
      - alert: LotorVulnDBStale
        expr: max(lotor_vulndb_stale) == 1
        for: 1h
      - alert: LotorDeadJobs
        expr: max(lotor_jobs{status="dead"}) > 0
        for: 15m
      - alert: LotorQueueStuck
        expr: min_over_time(max(lotor_jobs{status="pending"})[30m:]) > 0 and deriv(max(lotor_jobs{status="pending"})[30m:]) >= 0
      - alert: LotorNotReady
        expr: up{job="lotor"} == 0
        for: 2m
```

L'écoute de gestion (`management.*`) ne doit pas être exposée publiquement : la faire
lire par Prometheus sur le réseau d'administration.

## Journaux

Journaux `slog` sur la sortie d'erreur, au format `logging.format` (`json` en production).
Chaque requête est journalisée avec `request_id` (renvoyé au client dans `X-Request-Id`
et affiché sur les pages d'erreur), méthode, chemin sans la chaîne de requête, motif de
route, statut, taille, durée et IP du client. Aucun mot de passe, jeton, secret ni contenu
de SBOM n'y figure.
