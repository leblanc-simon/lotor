# Leçons et pièges connus

À lire avant chaque lot ; à compléter à la fin de chaque lot avec les erreurs commises et
les pièges découverts, pour ne pas les reproduire. Une entrée = le constat, puis la règle.

## Environnement et outillage

- **Chaîne Go** : `go.mod` fixe `toolchain go1.26.10`. Une machine avec un Go plus ancien
  télécharge la bonne chaîne d'elle-même (`GOTOOLCHAIN=auto`) ; ne pas modifier la ligne
  `toolchain` pour s'adapter à la machine.
- **PostgreSQL local** : sans Docker, un PostgreSQL 16 natif convient ; le mot de passe du
  rôle `postgres` doit valoir `postgres` pour le DSN par défaut du Makefile.
- **Proxy réseau** : un téléchargement de module peut échouer ponctuellement
  (`ws_closed_mid_exchange`) ; relancer la commande, ne pas changer de version pour autant.

## Anchore

- `syft.GetSource(ctx, "dir:/chemin", nil)` interprète le préfixe comme un registre
  d'images : passer le chemin nu et `syft.DefaultGetSourceConfig().WithSources("dir")`.
- Syft échoue sur les bases RPM récentes sans pilote SQLite enregistré : importer
  `_ "modernc.org/sqlite"` dans tout binaire qui catalogue (agents, tests).
- La base Grype v6 fait environ 3,2 Gio décompressée et met plusieurs minutes à
  télécharger : jamais dans les tests unitaires ; tests réels sous l'étiquette `grypedb`,
  avec un répertoire de base fourni par variable d'environnement.
- Les identifiants de vulnérabilité de Grype sont ceux de la source (GHSA pour Java…) ;
  le rattachement aux CVE passe par les alias ou `NormalizeByCVE`.

## Git et intégration

- Ne pas réécrire une branche déjà poussée (force-push refusé) : préférer un commit
  correctif, ou une fusion « squash » de la PR.
- Commits signés « Simon Leblanc <contact@leblanc-simon.eu> », avec la ligne
  `Co-Authored-By` de Claude.

## Base de données (T01)

- **Tableaux pgx via `database/sql`** : passer une `[]string` en paramètre marche, mais la
  relire (`Scan(&slice)`) échoue (« unsupported Scan »). Règle : `row.Scan(db.Array(&s))`.
  Pour `[]uuid.UUID`, pgx exige d'enregistrer les types **pointeurs** (`*[]uuid.UUID`) :
  `db.Array` le fait.
- **RLS et `current_setting`** : jamais `current_setting('lotor.org_id', true)` dans une
  politique (NULL, donc zéro ligne en silence). Après un `set_config(…, true)`, le
  paramètre ne disparaît pas en fin de transaction : il vaut `''` sur la connexion, et
  `''::uuid` échoue. Les tests RLS couvrent les deux cas (connexion neuve, connexion
  réutilisée) avec un pool d'une connexion.
- **Privilèges par défaut** : `ALTER DEFAULT PRIVILEGES … REVOKE EXECUTE ON FUNCTIONS
  FROM PUBLIC` n'a d'effet que sans `IN SCHEMA`. Toute nouvelle table d'organisation :
  `CALL lotor_enforce_org_rls('table')`, sinon le serveur refuse de démarrer.
- **Migration sans nom de rôle en dur** : le rôle d'exécution est dans
  `current_setting('lotor.app_role')`, à citer par `format('%I')`. Une migration est
  exécutée dans la transaction du verrou : pas de `CREATE INDEX CONCURRENTLY`.
- **Tests d'intégration** : toujours `dbtest.New(t)` (base et rôles jetables) ; jamais de
  base nommée en dur. Une base de développement manuelle prend un nom propre au lot et se
  supprime après usage.

## Go, open-go-base et chi (T01)

- **appconf** : `Load` lit `os.Args` (les options de `go test` font échouer l'analyse) et
  termine le programme sur `--help`. Règle : dans les tests, fixer `os.Args`, et tester
  `--help` dans un sous-processus. Un `env-default` ne s'applique qu'à un champ vide :
  poser les défauts du projet avant `Load` (`config.Defaults`) ; `--help` affiche quand
  même celui d'appconf.
- **cleanenv** accepte un fragment embarqué avec `yaml:",inline"` : variables et YAML
  fonctionnent (`config.Database`).
- **go-i18n** prend pour un message toute table YAML qui contient un nom réservé
  (`description`, `id`, `hash`, `translation`…) : ses clés disparaissent en silence. Le
  test de `locales` l'interdit ; ne pas nommer un élément ainsi.
- **chi** : un sous-routeur sans aucune route n'exécute pas ses propres middlewares
  (sa réponse NotFound part sans en-têtes ni journal). Monter un groupe par
  `r.With(mws...).Route(…)`. `middleware.GetHead` ne marche qu'au niveau racine, avant le
  routage. Le `NotFound` racine ne passe pas par les middlewares d'un groupe : l'envelopper
  explicitement (`chi.Chain(...).Handler`).
- **html/template** échappe à la première exécution : `render` force l'échappement au
  démarrage pour qu'un gabarit ambigu échoue tôt. Cloner un jeu par requête coûte cher
  (ADR 0009).
- **Course de données** : `http.Server.Serve` modifie `TLSConfig` (HTTP/2) ; ne pas le
  relire depuis une autre goroutine. La sortie d'un `exec.Cmd` lue pendant qu'il tourne
  passe par un tampon protégé par un mutex.
- **TLS** : le client Go n'envoie pas un certificat client d'une autorité que le serveur
  n'annonce pas ; pour tester un refus, forcer `GetClientCertificate`.
- **`go get module/paquet` sans version** monte le module à sa dernière version : préciser
  la version du graphe (`@v0.61.0`) si on ne veut pas de montée.

## File de traitements (T02)

- **`SetMaxIdleConns(0)`** ne garde aucune connexion inactive (ce n'est pas « le défaut ») :
  chaque transaction rouvrait une connexion et refaisait l'authentification, 12 ms par
  transaction en test. Règle : `db.PoolConfig.MaxIdleConns` nul garde le défaut de
  `database/sql` ; un pool très sollicité règle `MaxIdleConns` égal à `MaxOpenConns`.
  Une lenteur uniforme d'environ 10 ms par transaction en local signale ce piège.
- **cleanenv et booléens** : un `env-default:"true"` s'applique à un champ resté à sa
  valeur zéro, donc écrase `enabled: false` lu dans le fichier. Règle : un booléen vrai
  par défaut n'a pas d'`env-default`, son défaut se pose dans `config.Defaults` (et
  un test charge un fichier qui le met à `false`).
- **Numéros de migration en dur dans les tests** : les tests de l'exécuteur ajoutaient
  `002_*.sql`, cassés dès la vraie migration 002. Règle : migrations de test nommées
  `+N_sujet.sql` (`withMigrations` calcule le numéro), et aucune table de test ne porte
  le nom d'une table réelle (`jobs`).
- **`OR` dans une requête de prise** : `(status = 'pending' AND …) OR (status = 'running'
  AND …)` empêche l'index partiel ordonné et trie toute la file à chaque prise (O(n)).
  Règle : une requête par cas, chacune sur son index partiel, vérifiée par `EXPLAIN
  ANALYZE` (attendu : `Index Scan using jobs_pending`, arrêt à la première ligne).
- **Arrêt et prise concurrente** : un job pris pendant que `Stop` relève les jobs à
  libérer lui échappe (son bail resterait actif). Règle : la prise et son inscription
  parmi les jobs en cours se font sous un verrou que `Stop` prend avant de relever.
- **Délai de `Stop` sous charge** : libérer les baux un par un à 150 ms de l'échéance a
  échoué sous charge (`driver: bad connection`, vraisemblablement le contexte expiré en cours de requête). Règle :
  une seule instruction pour tous les baux, et une marge d'un quart du délai (2 s au
  plus).
- **Horloge injectable et `Enqueue`** : `Enqueue` date avec l'horloge du système ; une
  horloge de test en retard sur l'heure réelle ne voit pas les jobs échus. Règle : la
  fausse horloge part après l'heure réelle et n'avance que vers l'avant ; elle est
  arrondie à la microseconde pour comparer exactement les `timestamptz` relus.
- **Tuer un worker pour de vrai** : le test « worker tué » relance le binaire de test en
  sous-processus (`os.Args[0] -test.run=…` et une variable d'environnement) et le tue par
  `SIGKILL`, plutôt que de simuler une panne dans le même processus.

## Outillage (T01)

- **`make generate-check`** échoue tant que le code généré n'est pas commité (fichiers
  non suivis ou seulement indexés) : committer avant de lancer `make ci`.
- **Variables d'environnement** : chaque appel de commande repart d'un shell neuf ; un
  `export` ne survit pas. Passer `LOTOR_TEST_DATABASE_DSN=…` sur la ligne, ou passer par
  `make test-integration` qui le pose.
- **Captures d'écran** : `google-chrome --headless=new --screenshot` est disponible ;
  `--blink-settings=preferredColorScheme=0` simule le thème sombre du système.

## Comptes, RLS et open-go-base (T03)

- **RLS forcée et `SECURITY DEFINER`** : `FORCE ROW LEVEL SECURITY` soumet aussi le
  propriétaire ; une fonction `SECURITY DEFINER` qu'il possède ne lit rien sans
  organisation déclarée (erreur sur `''::uuid`). Règle : le propriétaire a `BYPASSRLS`
  (ADR 0012), vérifié par la migration 005 ; dans `dbtest`, le rôle propriétaire est créé
  avec cet attribut.
- **Tables d'authx et de mfax créées avant 001** : sur une base neuve, leur `Migrate` passe
  avant les privilèges par défaut du projet ; le rôle d'exécution n'y a alors aucun droit.
  Règle : droits accordés explicitement par une migration du projet (003).
- **Paramètre SQL réutilisé avec deux types** : `VALUES ($1, … left($1::text, 8))` échoue
  (« inconsistent types deduced for parameter $1 »). Règle : caster chaque occurrence
  (`$1::uuid`). Et un UUID v7 commence par l'horodatage : ses 8 premiers caractères se
  répètent d'un test à l'autre, prendre la fin pour un slug unique.
- **Écrire après `WriteHeader`** : mfax appelle `w.WriteHeader(401)` avant le `Renderer` ;
  le rendu ne peut plus poser son `Content-Type`. Règle : envelopper le `ResponseWriter`
  (`deferredHeader`) pour retenir le statut jusqu'à la première écriture.
- **`wrap(err)` sans test de nil** : une fonction d'enveloppe d'erreur qui ne renvoie pas
  `nil` pour `nil` transforme chaque succès en échec (`%!w(<nil>)`). Règle : `if err ==
  nil { return nil }` en tête, et un test d'intégration du cas nominal dès le premier
  appel.
- **Gabarits et texte en dur** : le test de `render` refuse toute lettre hors action de
  gabarit, même « UTC ». Règle : clé `format.utc`. Un champ caché `<input hidden>` sans
  libellé fait aussi échouer l'assistant d'accessibilité.
- **Gabarit partagé entre pages** : un `{{define}}` placé dans le fichier d'une page n'est
  pas vu des autres pages (un jeu par page). Règle : les blocs communs vont dans
  `partials/`.
- **Outil d'isolement des agents** : les longues commandes shell composées (heredoc
  python, `for … do git`) sont refusées dans un worktree isolé. Règle : écrire les scripts
  d'édition dans le répertoire temporaire et les lancer par une commande simple ; une
  commande git par appel, avec `git -C` pour un autre dépôt.
- **Pousser une étiquette** : le mandataire git de la session refuse les pushs
  d'étiquettes (HTTP 403) mais accepte les branches. Règle : pseudo-version du commit
  fusionné (`go get module@<sha>`), étiquette annotée créée seulement dans le clone local,
  et action consignée pour l'utilisateur dans la section « Actions pour l'utilisateur » de
  `specs/avancement.md` (et dans le Journal). Ne pas chercher à la pousser autrement.
- **Tests d'un binaire et configuration obligatoire** : rendre un réglage obligatoire
  (`secrets.keys`) casse le test de bout en bout du binaire, qui part d'un environnement
  vide. Règle : mettre à jour `start()` de `cmd/lotor-server/main_integration_test.go`
  dans le même commit.
- **Codes TOTP en test** : mfax refuse un pas déjà consommé et tolère ±1 pas. Règle : au
  plus trois connexions TOTP par compte et par test, avec des pas croissants (−30 s, 0,
  +30 s) ; voir `app.code` dans `internal/web/app_integration_test.go`.

## Projets, agents et API générée (T04)

- **Index git partagé entre commits** : un `git rm` fait tôt reste indexé et part dans le
  commit suivant, même si celui-ci n'ajoute (`git add`) que d'autres chemins. Règle :
  supprimer un fichier dans le commit qui en tire la conséquence (`git rm` juste avant
  lui), et relire `git show --stat` après chaque commit.
- **oapi-codegen, client** : le client génère un type `<OperationId>Response` par
  opération ; un schéma nommé `EnrollResponse` pour l'opération `enroll` entre en
  collision (« redeclared »). Règle : nommer les schémas de réponse autrement
  (`EnrollmentResult`, `HeartbeatStatus`).
- **oapi-codegen, chi** : le serveur généré enregistre les chemins complets du contrat
  (`/agent/enroll`, relatifs à `servers: /api/v1`) sur le routeur fourni. Le monter dans
  `Route("/api/v1/agent")` donnerait `/api/v1/agent/agent/enroll`. Règle : groupe dans le
  sous-routeur `/api/v1`, `NotFound` et `MethodNotAllowed` de ce sous-routeur enveloppés
  dans la chaîne d'API (`chi.Chain(...).Handler`).
- **Limitation par clé** : une clé lue telle quelle dans la requête (identifiant public
  d'un jeton non vérifié) donnerait un compteur neuf par valeur inventée. Règle : la clé
  est posée par le middleware d'authentification, le limiteur passe après lui ; les refus
  passent par un limiteur par IP placé sur le seul chemin du refus.
- **Captures d'écran** : une page enregistrée en fichier et ouverte en `file://` ne charge
  pas les feuilles du serveur (`Cross-Origin-Resource-Policy: same-origin`). Règle : servir
  la page capturée depuis un serveur de test de même origine, qui relaie `/static/` vers
  l'application (`httputil.NewSingleHostReverseProxy`).
- **Onglets** : `overflow-x: auto` avec des liens à `margin-bottom: -1px` fait apparaître
  une barre de défilement verticale. Règle : `overflow-y: hidden` sur `.tabs`.
- **Couverture par paquet** : `go test -cover` ne compte que les tests du paquet lui-même ;
  `agent` qui appelle `project.ListForAgent` ne couvre pas `project`. Règle : chaque
  paquet métier teste ses propres fonctions exportées, même celles qu'un autre paquet
  exerce déjà.
- **Outil d'isolement des agents (suite)** : refusées aussi, les commandes qui citent un
  DSN entre guillemets (`'postgres://…'`) ou combinent `cd sous-dossier && heredoc`.
  Règle : DSN sans guillemets (`LOTOR_TEST_DATABASE_DSN=postgres://…?sslmode=disable go
  test …`), fichiers écrits par l'outil d'écriture, éditions multiples par un script
  Python du répertoire temporaire lancé seul.

## Ingestion, Syft et schémas (T05)

- **Énumérations figées des schémas officiels** : le `spdx.schema.json` de CycloneDX 1.6
  ne connaît pas « Artistic-dist », que Syft v1.55.0 écrit en `license.id` ; un SBOM
  légitime produit par Syft échouait à la validation. Règle : à la réception, ne pas
  imposer l'énumération des licences (`schema.Validator.Validate`) ; pour ce que le
  serveur produit, `ValidateStrict` et réécriture en `license.name`
  (`syft.Encode(…, CycloneDXLicenseIDs("1.6"))`). Un test le prouve sur un vrai SBOM.
- **packageurl-go canonicalise plus que prévu** : il met en minuscules les noms golang
  (`github.com/BurntSushi/toml` → `burntsushi`) et n'encode pas « : » dans la version
  (`1:2.36-9`), contrairement à la sortie de Syft (`1%3A…`). Règle : toute comparaison de
  purl passe par `sbom.CanonicalPURL`/`ComponentPURL` des deux côtés, jamais par la chaîne
  du document.
- **Fusion de doublons et ordre** : une première version de `merge` départageait deux
  mentions au même rang sans regarder la confiance (`nil` contre `0`) ; le résultat
  dépendait de l'ordre du document, trouvé par `FuzzNormalize` en quelques secondes. Règle :
  un départage par ordre total sur tous les champs non fusionnés, et un fuzz « ordre
  inversé = même empreinte » pour toute normalisation.
- **Les décodeurs JSON de Go ignorent la casse des clés** : `"COMPONENTS"` ou
  `"components"` sont lus comme `components` par `encoding/json`. Règle : un
  contrôle préalable compare les clés décodées (échappements `\u` compris) sans tenir
  compte de la casse, sinon il se contourne.
- **Mémoire du décodage** : le pic du tas vaut environ trente fois la taille du SBOM
  (décodeurs de Syft + schéma JSON). Règle : dimensionner les bornes par défaut sur cette
  mesure (64 Mio décompressés), la documenter pour l'exploitation (ADR 0015).
- **Syft décode `metadata.component` comme un paquet** et ne garde ni les empreintes, ni la
  portée, ni les propriétés inconnues d'un composant CycloneDX. Règle : relire le document
  pour ces champs (index par `bom-ref`, qui devient l'identifiant du paquet Syft ; SPDXID
  sans `SPDXRef-` pour SPDX) et exclure le composant décrit.
- **Jeux d'essai réalistes sans Docker** : un système de fichiers factice (`/etc/os-release`
  + base de paquets) catalogué par Syft donne de vrais SBOM d'hôte ; les bases RPM réelles
  existent dans les jeux d'essai de `github.com/anchore/go-rpmdb` (cache des modules). Les
  chemins absolus du répertoire temporaire se retrouvent dans les SBOM (noms de fichiers,
  SPDXID) : les retirer avant de committer.
- **Outil d'isolement des agents (suite)** : refusés aussi les `for` en shell, les
  accolades `{a,b}` dans un chemin et `cd … && python3 - <<EOF`. Règle : script dans le
  répertoire temporaire lancé seul (`python3 -I script.py`), ou `python3 -I -c "…"` sans
  `cd` préalable, ou l'outil d'édition.
- **`rm` d'un motif relatif après `cd`** est bloqué par la protection contre les
  suppressions : écrire dans un nouveau dossier plutôt que vider l'ancien, et supprimer un
  fichier par son chemin absolu.

## Analyse de vulnérabilités et base Grype (T06)

- **Le client de distribution de Grype décompresse au téléchargement** : `Download` passe
  par go-getter en mode répertoire, qui extrait le tar.zst ; il ne reste aucune archive à
  stocker, et l'appel ne prend pas de contexte. Règle : télécharger par un `vuln.Fetcher`
  injecté (`internal/download`, `net/http`) et n'utiliser de Grype que la lecture de
  `latest.json` (`NewLatestFromReader`) et `ResolveArchiveURL`.
- **Une vraie base Grype sans 3 Gio** : `v6.NewWriter` + `SetDBMetadata` + `Close` donne
  une base v6 vide mais valide, qu'une archive tar.gz (bibliothèque standard) rend
  installable par le curateur. Règle : `grypetest.TinyArchive` pour tout test
  d'installation, d'ouverture ou de bout en bout ; la vraie base reste sous `grypedb`.
- **Dates relues de PostgreSQL** : `timestamptz` arrondit à la microseconde ; comparer une
  date Go (nanosecondes) à sa relecture échouait (« base locale du …027, attendue du
  … »). Règle : arrondir (`Round(time.Microsecond)`) avant d'écrire une date qu'on
  comparera, et comparer après arrondi.
- **`NormalizeByCVE` ne remplace pas les métadonnées** : Grype change l'identifiant (GHSA
  → CVE) mais laisse la fiche de la source d'origine sur la correspondance. Règle : lire la
  fiche NVD du CVE (`VulnerabilityMetadata`, espace `nvd:cpe`) pour le catalogue ; une
  fiche absente revient comme une souche (sans CVSS ni description), à détecter.
- **Les attributs de gabarit numériques** : une largeur de jauge par `style="--p: 94%"`
  est refusée par la CSP. Règle : jauges en SVG, largeur en attribut (`<rect width>`),
  calculée par la fonction `barWidth` ; nombres localisés par `decimal` et `percent`
  (`golang.org/x/text/number`), jamais formatés en Go dans la vue.
- **Valeur d'attribut en dur** : le test de `render` refuse `value="resolved"` dans un
  gabarit. Règle : la valeur vient de la vue (`StatusValue`).
- **Nouveau SBOM d'exemple** : `TestGolden` parcourt tout `testdata/sbom/` ; un fichier
  ajouté sans attendu fait échouer `make ci`. Règle : `go test ./internal/sbom/syft -run
  TestGolden -update`, relire l'attendu, compléter `testdata/sbom/README.md`.
- **Instances worker et `/readyz`** : depuis T06, une instance à workers n'est prête
  qu'avec une base de vulnérabilités chargée ; le test de bout en bout du binaire importe
  une base (`grypetest`) et passe `LOTOR_VULNDB_OFFLINE=true` pour ne jamais sortir sur le
  réseau. Règle : tout nouveau test qui attend `/readyz` sur une instance à workers fait de
  même (ou `LOTOR_WORKERS_ENABLED=false`).
- **Commandes Anchore en CI sans action tierce** : `go run github.com/anchore/syft/cmd/syft@<version>`
  (et grype) fonctionne (aucune directive `replace`), compile en une quinzaine de secondes
  et reprend les versions de `go.mod` (`go list -m -f '{{.Version}}'`). Le champ KEV du
  JSON de grype est `.matches[].vulnerability.knownExploited`.
- **Tests concurrents d'une bascule** : un crochet (`Hook`) dans la fausse base qui bloque
  les correspondances sur un canal permet de prouver qu'une bascule attend les
  correspondances en cours, sans `time.Sleep` fragile pour la synchronisation.
- **Outil d'isolement des agents (suite)** : refusés aussi `cat >> fichier <<EOF` et
  `python3 script && git …` dans la même commande. Règle : écrire par l'outil d'écriture,
  une commande git seule par appel.

## Agent dépôt et forges (T08)

- **Syft exécute la chaîne Go par défaut** : `golang.DefaultCatalogerConfig()` met
  `UsePackagesLib: true`, qui lance `go list` (`golang.org/x/tools/go/packages`) sur le
  répertoire scanné, avec téléchargements possibles (`GOTOOLCHAIN`, modules). Règle : sur
  un contenu non fiable, partir de `pkgcataloging.DefaultConfig()` et couper
  `Golang.UsePackagesLib`, les recherches de licences distantes et locales, le réseau de
  Java (`repoagent.offlineCatalogers`). Chercher `os/exec` et `go/packages` dans les
  sources de Syft à chaque montée de version.
- **Pilote SQLite oublié** (piège déjà connu, retombé dedans) : le premier scan a échoué
  sur « sqlite driver is required ». Règle : l'import `_ "modernc.org/sqlite"` vit dans le
  paquet qui appelle `syft.CreateSBOM` (`repoagent/scan.go`), pas seulement dans le
  binaire, pour qu'aucun test ni binaire ne l'oublie.
- **SBOM de Syft non déterministe** : `serialNumber` aléatoire et `metadata.timestamp`
  rendent chaque analyse d'un même commit différente, donc une nouvelle ingestion côté
  serveur. Règle : les retirer (facultatifs en CycloneDX) et tester que deux analyses
  donnent les mêmes octets. Le composant décrit porte sinon le chemin temporaire : le
  nommer par `source.Alias`.
- **Clone d'une branche ≠ commit à rattraper** : `clone --depth 1 --single-branch` ne
  donne que la tête. Règle : `git init` + `git fetch --depth 1 <url> <commit>` ; un dépôt
  nu de test doit avoir `uploadpack.allowReachableSHA1InWant=true` pour le protocole v0,
  et l'URL locale doit être `file://` (un chemin nu ignore `--depth`).
- **git en test par HTTP sans service externe** : `net/http/cgi` avec `git http-backend`
  (`GIT_PROJECT_ROOT`, `GIT_HTTP_EXPORT_ALL=1`) sert un dépôt nu derrière un
  `httptest.Server`, ce qui permet de vérifier l'en-tête d'authentification et de
  simuler un clonage lent.
- **Vérifier « pas dans `ps` »** : envelopper git dans un script qui note `"$*"` et le
  passer comme binaire (`work.git`), puis chercher le jeton et sa forme base64 dans la
  trace et dans les journaux.
- **Réponse du client généré qui ne suit pas le contrat** : les méthodes
  `…WithResponse` d'oapi-codegen décodent le corps selon le statut et **échouent** si le
  JSON ne correspond pas (un faux serveur de test renvoyait un problème en 202). Règle :
  pour un appel où seuls le statut et la clé d'erreur comptent, utiliser la méthode brute
  et une lecture bornée.
- **Assistant de test appelé seulement par les tests `integration`** : staticcheck (sans
  étiquette) le signale inutilisé (U1000). Règle : le placer dans le fichier étiqueté, et
  lancer aussi `go tool staticcheck -tags integration` sur les paquets touchés.
- **Outil d'isolement des agents (suite)** : refusée aussi une commande qui enchaîne
  `git add`, `git commit` et `make` ; une commande git par appel.
## Agent serveur, paquets et lots parallèles (T07)

- **Numéros de migration attribués d'avance** : l'exécuteur exige des numéros contigus
  (« migrations non contiguës ») ; une migration 011 sans 009 ni 010 sur `main` ne passe
  pas. Règle : un numéro attribué est provisoire ; avant d'ouvrir la PR et à chaque
  intégration de `origin/main`, renommer sa migration au premier numéro libre après la
  dernière de `main`. Jamais de migration factice pour combler un trou.
- **`GOARCH=… go tool nfpm`** construit l'outil pour cette architecture
  (`exec format error`). Règle : ne jamais passer `GOOS`/`GOARCH` à un `go tool` ; nfpm
  lit ses propres variables (`PKG_ARCH`, `PKG_VERSION`).
- **nfpm ne développe pas les variables dans `contents.src`** (« Glob failed ») : copier
  le binaire de l'architecture courante vers un chemin fixe (`bin/package/`) avant chaque
  paquet.
- **`$(shell …)` de make et `case … )`** : la parenthèse fermante du motif clôt l'appel
  de fonction. Règle : `sed` ou un script plutôt qu'un `case` dans `$(shell …)`.
- **Valeurs YAML des traductions** : une valeur qui contient « : » (« Scan demandé :
  … ») casse tout le fichier (`mapping values are not allowed`). Règle : guillemets dès
  qu'une valeur contient « : », et relancer les tests de `locales` après chaque ajout.
- **Énumérations d'oapi-codegen** : sans collision, les constantes ne sont pas préfixées
  (`gen.Done`, `gen.Current`, pas `gen.IngestionStatusDone`). Règle : lire les noms
  générés (`grep '= "' client.gen.go`) avant de les employer ; un nouvel enum dont une
  valeur existe ailleurs renomme les deux.
- **Scanner « / » d'une machine de développement** : le cache des modules Go
  (380 000 fichiers sous `/root`) fait passer un scan Syft de « / » de 3 à 16 minutes et
  de 0,9 à 3 Gio de mémoire : Syft indexe chaque fichier parcouru. Règle :
  mesurer sur une racine représentative d'un serveur (protocole de `measure_test.go`,
  exclusions explicites), et le documenter.
- **`StateDirectory=` crée le répertoire en `0755`** : l'agent refuse un répertoire
  d'état ouvert. Règle : `StateDirectoryMode=0700` dans toute unité d'agent.
- **mTLS et interface sur la même écoute** : `RequireAndVerifyClientCert` refuserait les
  navigateurs. Règle : `VerifyClientCertIfGiven` au niveau TLS, refus de l'absence de
  chaîne vérifiée dans un middleware de l'API des agents.

## Recherche transverse et jetons personnels (T09)

- **RLS et index de recherche** : sous la RLS, un opérateur non `LEAKPROOF` ne peut pas
  servir de condition d'index ; `ILIKE`, `%` (pg_trgm), `@>`, `&&` et `lower()` ne le
  sont pas (`SELECT proname, proleakproof FROM pg_proc`), l'égalité de texte et d'uuid
  et `= ANY` le sont. Un index GIN `(org_id, name gin_trgm_ops)` est donc ignoré par une
  requête du rôle d'exécution. Règle : vérifier `proleakproof` avant de compter sur un
  index sous la RLS ; sinon une fonction `SECURITY DEFINER` qui lit l'organisation dans
  `lotor.org_id` (jamais en paramètre), dans `crossorg`, testée pour ne pas sortir de
  l'organisation (ADR 0024).
- **GIN composite `btree_gin`** : la clé `org_id` lit toute la liste de l'organisation ; sur
  une petite table, le planificateur lui préfère la clé primaire, même parcours
  séquentiels interdits. Règle : un test de plan d'un index GIN se fait sur un jeu assez
  gros (40 000 composants) et une valeur sélective, jamais sur quelques milliers de lignes.
- **Comparateurs de Grype** : faits pour la correspondance, pas pour trier. dpkg renvoie
  une différence (−9) au lieu d'un signe ; PEP 440 n'est pas antisymétrique sur les
  versions locales (`0+00` contre `0`, trouvé par `FuzzCompare` en cinq secondes) ; rpm
  ignore une époque présente d'un seul côté (`2.0-1` > `1:1.0-1`), même avec
  `MissingEpochStrategyZero` qui ne corrige que le côté gauche. Règle : combiner les deux
  sens de comparaison, écrire l'époque `0:` des deux côtés, et un fuzz d'antisymétrie
  pour tout comparateur.
- **Maven lit toute chaîne** : « latest » est un qualificatif, pas une version illisible.
  Règle : choisir les exemples de versions illisibles par écosystème (npm, PEP 440, Go,
  Debian), pas pour Maven.
- **Serveur généré et sous-routeur** : oapi-codegen enregistre les chemins complets du
  contrat ; monter l'API utilisateur dans un groupe de `/api/v1` fait perdre la chaîne
  CORS aux requêtes préliminaires (`OPTIONS` routé avant les middlewares d'un groupe).
  Règle : garder `r.With(cors, …).Route("/orgs/{org}", …)` et y monter chaque opération
  par `userapi.ServerInterfaceWrapper` (le test `TestUserAPICORS` l'a montré).
- **Deux serveurs générés dans un même paquet** : les noms (`ServerInterface`,
  `HandlerWithOptions`…) entrent en collision. Règle : un paquet par serveur généré
  (`internal/api/gen/userapi`), avec ses propres types.
- **`number` d'OpenAPI** devient `float32` chez oapi-codegen. Règle : `format: double`
  pour tout nombre relu en `float64`.
- **Paramètre de curseur inutilisé** : ajouter une valeur à la liste des arguments sans
  l'employer dans la requête donne « could not determine data type of parameter $n ».
  Règle : n'ajouter un argument qu'au moment où son texte est écrit, et typer les clés de
  curseur (`::float8`, `::timestamptz`, `::uuid`).
- **Export en flux et délai d'écriture** : `http.write_timeout` (60 s) coupe un export
  long. Règle : `http.NewResponseController(w).SetWriteDeadline` pour la durée de l'export
  (les enveloppes de la réponse exposent `Unwrap`), et un nombre d'exports simultanés
  borné, car chacun tient une connexion.
- **Outil d'isolement des agents (suite)** : refusés aussi `sed` ou `cat` sur un chemin
  passé par une variable shell (`$D/…`), une boucle `for`, et `python3 - <<EOF` même seul.
  Règle : chemins écrits en entier, scripts d'édition dans le répertoire temporaire lancés
  par `python3 -I chemin.py`, ou `python3 -I -c "…"` court.

## Tableau de bord et graphiques (T10)

- **Mesurer la page entière, pas les requêtes isolées** : chaque requête du tableau de bord
  prenait 20 à 280 ms sur le jeu de référence, mais la page complète a d'abord donné un
  p95 de 1,8 s (machine partagée par d'autres lots). Règle : un test de mesure par page
  (`TestReferenceDatasetDashboard`, garde, RLS et rendu compris), puis profiler requête
  par requête ; trois agrégats qui relisent les mêmes 67 000 constats se fondent en un
  seul passage groupé par projet et sévérité.
- **`count(DISTINCT …)` et `array_agg(DISTINCT …)` sur toute une table** : la liste des
  familles de composants coûtait 260 ms. Règle : réduire d'abord à des couples distincts
  (composant, projet) dans une CTE, regrouper, limiter, et ne lire les détails (versions)
  que pour les lignes retenues.
- **Alias joint deux fois** : une fonction qui ajoute des jointures à un fragment commun
  (`openWhere(joins)`) a produit « table name "p" specified more than once ». Règle : le
  fragment fixe ses jointures pour toutes les portées, l'appelant n'ajoute que des tables
  absentes.
- **SVG étirés (`preserveAspectRatio="none"`)** : cercles et textes s'y déforment. Règle :
  traits en `vector-effect: non-scaling-stroke`, point marqué par un tracé de longueur
  nulle à bouts ronds (`d="Mx,yh0"`), libellés et valeurs en HTML (barres rendues comme
  un tableau), jamais en `<text>`.
- **Grille CSS repliée en mobile** : passer `.trend` de trois à deux colonnes mélangeait
  libellé, valeur et courbe d'une ligne à l'autre. Règle : `grid-auto-flow: row dense` et
  colonne explicite de la valeur ; vérifier la capture mobile (390 px) de chaque écran.
- **Fusion pendant le lot : règle d'un autre lot** : T07 a refondu l'état « muet »
  (`agent.Activity`, dernier inventaire d'un agent serveur) pendant T10. Règle : tout calcul
  qui dépend d'une règle d'un autre paquet passe par sa fonction (`StateAt`,
  `Activity.Since`), en un seul point (`agent.SilentSince`), pour que la fusion ne touche
  qu'une ligne ; les jeux de test fixent `created_at` (un agent serveur sans inventaire est
  muet depuis sa création).
- **`webtest` et les SVG** : l'assistant ne vérifiait rien des `<svg>` ni des références
  `aria-labelledby`. Règle : un `<svg>` est `aria-hidden="true"` ou `role="img"` nommé,
  et toute référence ARIA vise un identifiant présent (vérifié sur toutes les pages).

## Administration de l'instance et recette, partie 1 (T11)

- **Test de bail perdu qui ne simule qu'à moitié** : `TestLostLeaseCancelsHandler`
  changeait le seul `lease_token` ; `locked_until` expirait 300 ms plus tard et, sous
  charge, le même runner reprenait le job (seconde exécution du handler) avant une
  vérification faite après `time.Sleep(50 ms)`. Règle : une simulation d'un autre worker
  pose son jeton **et** son bail ; un test attend un événement observable (métrique
  `lotor_job_runs_total{outcome="lost"}`, canal) au lieu de dormir ; un bail de test se
  dimensionne pour qu'un renouvellement retardé de plusieurs centaines de millisecondes ne
  le perde pas (3 s). `TestLeaseIsRenewedWhileHandlerRuns` (bail de 300 ms) a fini par échouer
  en CI (revue de sécurité de T11) : bail porté à 1,5 s, handler de 4 s.
- **Reproduire une instabilité de charge** : `GOMAXPROCS=1 taskset -c 0` seul ne suffit
  pas (50 passages verts) ; il faut partager le cœur avec des boucles actives
  (`taskset -c 0 sh -c 'while :; do :; done'` ×40) : 3 échecs sur 30. Un test de
  10 000 jobs en `-race` sur un cœur ne finit pas en un quart d'heure : cibler le test.
- **csrfx et formulaire multipart** : `PostFormValue` analyse le corps entier
  (`ParseMultipartForm`) et écrit tout fichier de plus de 32 Mio sur le disque **avant**
  la vérification du jeton et avant la garde d'administration ; le serveur ne supprime
  ensuite que les fichiers du formulaire de la requête d'origine, pas ceux d'une copie
  (`WithContext`). Règle : un téléversement passe par un middleware avant CSRF qui borne le
  corps selon le visiteur, lit le jeton en première partie et le présente à csrfx par son
  en-tête ; le handler lit le fichier en flux (`uploadGate`, ADR 0028).
- **Délais de connexion et téléversement long** : `http.write_timeout` court dès la fin
  des en-têtes de la requête ; un téléversement de plusieurs minutes perd sa réponse même
  si la lecture est prolongée. Règle : repousser **les deux** délais
  (`http.NewResponseController(w).SetReadDeadline` et `SetWriteDeadline`).
- **Fichier temporaire passé à un job** : l'instance qui reçoit un fichier n'est pas celle
  qui exécute le job (`workers.enabled`). Règle : toute donnée remise à un job passe par
  PostgreSQL (blocs bornés, un par transaction), jamais par un chemin local.
- **Écart d'horloge dans les tests d'écran** : les écrans datent avec l'horloge de test
  figée à la création de l'application ; une base « construite il y a 2 h » au moment de
  la publication n'a qu'1 h 59 pour l'écran (« 1 heure »). Règle : des âges de test au
  milieu de l'intervalle affiché (2 h 30, 5 h 30, 3 j + 1 h).
- **Outil d'isolement des agents (suite)** : refusés aussi `cat >> fichier <<EOF` suivi d'une
  autre commande, un `NODE_PATH=…` en tête de commande et `cd … && cat > … <<EOF && node …`. Règle : script
  écrit par l'outil d'écriture, module chargé par chemin absolu
  (`require('/opt/node22/lib/node_modules/playwright')`), commande lancée seule.
- **Capturer un écran qui exige une session** : un test temporaire (étiquette dédiée, non
  commité) démarre l'application de test, connecte un compte et sert un mandataire
  inverse sur un port fixe qui injecte les cookies de session ; Playwright navigue alors
  sur l'application réelle, CSS embarquées comprises. Une variante « avant correctif » se
  mesure en modifiant le style par le CSSOM (`element.style`), permis par la CSP.

## Revue de sécurité du lot 1 (T11)

- **Le plafond par défi n'est pas une borne** : mfax limitait les codes d'un défi, mais un
  défi neuf s'obtient en rejouant le mot de passe. Règle : toute limite d'essais se compte
  sur l'objet attaqué (le compte), jamais sur un objet que l'attaquant renouvelle à volonté
  (défi, session, IP) ; et une IPv6 se compte par /64.
- **Un geste de remédiation doit couper tout ce qu'une session a obtenu** : réinitialiser
  mot de passe ou TOTP laissait vivre les jetons personnels, et réinitialiser le TOTP
  laissait l'ancien mot de passe ouvrir l'enrôlement. Règle : pour chaque identifiant
  dérivé d'une session (jeton, session, défi), écrire le test « il ne survit pas à la
  réinitialisation » en même temps que la fonctionnalité ; un facteur réinitialisé ne
  laisse jamais l'autre seul juge.
- **Privilèges par défaut trop larges** : `ALTER DEFAULT PRIVILEGES … UPDATE, DELETE` de 001
  donnait au rôle d'exécution le droit d'effacer le journal d'audit. Règle : toute table à
  garantie particulière (journal, suivi) a ses `REVOKE` dans la migration qui la crée, et
  `CheckRuntimeRole` vérifie le droit ; le harnais RLS (`TestRLSOnEveryOrgTable`) a une
  liste `appendOnly` pour ces tables.
- **Jeton CSRF lié à la session et assistants de test** : l'assistant `browser.post`
  recopiait le cookie CSRF dans le champ ; avec `csrfx.WithSessionBinding`, tous les tests
  d'écran échouaient en 403. Règle : un test calcule le jeton attendu par csrfx lui-même
  (`browser.csrf()` fait passer une requête synthétique, cookies CSRF et de session, dans
  un `csrfx.Protector` lié de la même façon), jamais en dupliquant l'algorithme.
- **Cookies `Secure` et `cookiejar`** : le `cookiejar` de Go n'envoie pas un cookie `Secure`
  à une URL `http://` ; un test des cookies `__Host-` sur `httptest.NewServer` (HTTP)
  perdrait la session. Règle : vérifier les en-têtes `Set-Cookie` avec
  `httptest.NewRecorder` sur le handler, cookies posés à la main.
- **Nouvelle table d'open-go-base** : `mfa_lockouts` est créée par le `Migrate` de mfax,
  avant les migrations du projet (piège de T03 retrouvé) : sans `GRANT` explicite dans la
  migration du projet, le rôle d'exécution n'y a aucun droit. Règle : toute table ajoutée
  par une montée d'open-go-base reçoit ses droits dans une migration du projet du même
  commit que la montée.
- **Tester avant la PR d'open-go-base** : un `replace` local temporaire
  (`go mod edit -replace leblanc.io/open-go-base=/home/user/open-go-base`) a permis de
  passer les tests d'intégration PostgreSQL de lotor (store de verrouillage) avant
  d'ouvrir et de fusionner la PR, donc une seule PR. Règle : `-dropreplace` puis
  `go get …@<sha fusionné>` avant tout commit ; jamais de `replace` commité, sauf vers une
  copie corrigée de `third_party/` décidée par un ADR (ADR 0063).
- **Recherche d'une ancre de remplacement dans un YAML de traductions** : `expiry_365: 1 an`
  apparaît dans deux sections ; le script d'édition a refusé (deux occurrences) avant
  d'écrire. Règle : ancrer sur un contexte unique (clé parente) ou ajouter en fin de
  fichier quand la section y est ; le script vérifie le nombre d'occurrences avant
  d'enregistrer.
- **Code TOTP du pas précédent en test** : `TestRevokedAgentTokenRefusedAtNextRequest` a
  échoué en CI (401 sur le premier code, de -30 s) : un changement de pas entre la
  génération et la vérification sort le code de la tolérance de ±1 pas. Règle : l'assistant
  `app.code` attend le pas suivant quand il reste moins de 5 s au pas courant avant de
  générer le premier code.
- **Outil d'isolement des agents (suite)** : refusés aussi `cat >> fichier <<'EOF'` suivi de
  `go build`, `python3 - <<'EOF'` qui touche un autre dépôt (open-go-base), et un
  `python3 -I -c` dont le texte contient « git ». Règle : bibliothèque de remplacements
  exacts dans le répertoire temporaire (`edlib.py`) et un script par lot d'éditions, lancé
  seul ; commandes git par `git -C <dépôt>`, une par appel.
## Audit RGAA du lot 1 (T11)

- **Bouton recouvert dans une cellule d'actions** : `.data-table .cell-actions form`
  (`inline-block`) l'emportait par spécificité sur `.form--inline` ; la liste de rôles
  en `width: 100 %` remplissait la cellule et « Retirer » recouvrait « Modifier » sur
  chaque ligne des membres depuis T03, sans qu'aucun test ni capture ne le voie. Règle :
  dans une cellule, un contrôle de formulaire garde sa largeur naturelle
  (`.cell-actions .select { width: auto }`) ; capture de bureau de chaque tableau à
  actions, pas seulement du mobile.
- **Information portée par la couleur ou la forme** : une pastille « repère coloré +
  nombre » avec le libellé en `visually-hidden` reste non conforme (3.1, 10.9) pour un
  voyant. Règle : libellé écrit, au moins abrégé (`<abbr title="…" aria-hidden="true">`
  plus libellé complet masqué), et une espace entre texte masqué et texte visible
  (« Critique 1 », pas « Critique1 »). Une ligne sélectionnée se dit aussi en texte.
- **Aide de champ masquée** : `aria-describedby` vers un `.visually-hidden` donne le
  format aux seuls lecteurs d'écran (11.10). `webtest` le refuse désormais.
- **Région dans une région du même nom** : un panneau `section aria-labelledby=X` qui
  contient une zone de tableau `role="region" aria-labelledby=X` crée deux repères
  homonymes (axe `landmark-unique`, 116 rendus). Règle : la zone défilante d'un tableau
  est un `role="group"` nommé et `tabindex="0"`.
- **Actions irréversibles** : une action qui révoque, désactive, retire, réinitialise ou
  supprime passe par la page de confirmation commune (`GET` de l'URL de l'action,
  `identity.confirm`), jamais par un bouton `POST` dans une liste. Le harnais d'isolement
  par route couvre automatiquement les `GET` ajoutés : un objet d'une autre organisation
  y répond 404 comme au `POST`.
- **Titres identiques entre organisations** : chaque écran fixait son titre sans
  l'organisation. Règle : le layout ajoute l'organisation courante (`Chrome.Current`)
  et le préfixe « Erreur : » (statut 4xx) ; un écran ne répète pas le nom de
  l'organisation dans sa clé de titre.
- **Instance peuplée et `make ci`** : le test temporaire qui sert l'instance d'audit
  attend un fichier d'arrêt ; laissé dans `internal/web`, `make test-integration`
  l'exécute et ne finit jamais. Règle : le sortir du paquet (fichier hors dépôt) avant
  tout passage de la CI locale.
- **Outil d'isolement des agents (suite)** : refusés aussi une boucle shell qui lit des
  intervalles de lignes (`sed -n "$a,$b p"` calculé) et `node` lancé par un chemin en
  variable. Accepté : `python3 -I /dev/stdin <<'EOF' … EOF` seul dans sa commande, et
  `node scripts/x.js $PWD` après un `cd` littéral.

## Recette du lot 1 (T11)

- **Listes attendues fixées avant la recherche** : les trois CVE de contrôle et leurs
  projets attendus ont été établis à la main (paquets installés, fichiers de dépendances au
  commit, enregistrements de la base Grype lus en SQLite) et commités avant le montage du
  serveur. Règle : toute recette « la recherche renvoie la liste attendue » commence par
  ce commit, sinon la liste attendue se recopie sur le résultat.
- **Règles de correspondance de Grype à connaître pour prévoir un résultat** : Rocky (et
  Alma, CentOS) est lu comme RHEL de même version (`operating_system_specifier_overrides`) ;
  un paquet binaire Debian ou RPM est rapproché par son paquet source (`libc6` → `glibc`) ;
  les états `wont-fix` et `not-fixed` restent des constats (`zlib` sur Debian 12 pour
  CVE-2023-45853) ; Alpine ne publie que des correctifs (`< 0` = non affecté) ; une plage
  GitHub de module Go peut coexister avec une plage en pseudo-version. Règle : établir une
  attente sur les enregistrements de la base (`vulnerability_handles`,
  `affected_package_handles`, `blobs`), jamais de mémoire.
- **Parc réaliste sans hôtes** : des images de conteneurs anciennes et épinglées
  (`debian:12.0-slim`, `rockylinux:9.2-minimal`, `alpine:3.18.0`) donnent des CVE connues
  et corrigées depuis ; l'agent installé par ses vrais paquets s'y lance sans systemd par
  `setpriv … --ambient-caps +dac_read_search`, à condition de `--cap-add DAC_READ_SEARCH`
  sur le conteneur. Ne pas monter de répertoire de travail dans un conteneur inventorié
  (un montage hors overlay est scanné) : `docker cp` puis suppression.
- **Forge simulée** : l'agent dépôt réel parle à une fausse forge si son API et son git
  sont servis sous le même hôte que l'URL web des projets (`repoPath` compare hôte et
  port) : écoute sur 443, noms `github.pilot.test`/`gitlab.pilot.test` résolus par
  `--add-host …:host-gateway`, autorité de test ajoutée au magasin du conteneur de
  l'agent (git n'hérite d'aucune variable `GIT_SSL_*` : `gitEnv` repart de zéro).
- **Enrôlement TOTP par script** : recharger la page d'enrôlement tire un **nouveau**
  secret ; le code calculé sur l'ancien est refusé. Règle : lire le jeton CSRF dans la
  réponse qui affiche le secret, sans nouveau `GET`.
- **`requests` et le mandataire de la session** : avec `trust_env`, `REQUESTS_CA_BUNDLE`
  remplace l'autorité passée à la session (échec TLS vers le serveur local). Règle :
  `session.trust_env = False` pour parler au serveur de test ; `curl --noproxy '*'`.
- **Mesures muettes** : `make test-grypedb` lance les tests sans `-v` ; les résultats de
  `TestIngestAndAnalyze5000` (`t.Logf`) n'apparaissent pas. Règle : `make bench-ingest`.
- **Test interrompu = base jetable orpheline** : tuer un `go test` d'intégration laisse sa
  base `lotor_t_<suffixe>` et ses deux rôles (le nettoyage de `dbtest` ne passe pas).
  Règle : après une interruption, `DROP DATABASE … WITH (FORCE)` puis `DROP ROLE` des
  seuls objets créés après l'heure du lancement.
- **Disque** : base Grype installée (3,2 Gio), copie locale du serveur (3,2 Gio), archive
  d'import (650 Mio en gzip), vidage de la base (600 Mio) et images : la recette a fini à
  7 Gio libres sur 19. Règle : supprimer chaque artefact intermédiaire dès qu'il a servi
  (`df -h` avant chaque étape lourde).
- **Outil d'isolement des agents (suite)** : refusées aussi les commandes dont le texte
  contient « git » hors d'une commande git (`.gitignore`, motif `github` d'un `grep`,
  chemin `*.git`), un `git -C` vers un dépôt hors du worktree, `time` dans un script `sh`
  (n'existe pas en `sh`), une variable passée à `sed`. Règle : script Python du répertoire
  temporaire qui appelle git par `subprocess` (`git --git-dir <chemin absolu>`), lancé
  seul ; motifs de recherche sans « git » (`ithub`).

## Renommage en lotor

- Un remplacement de texte qui raccourcit un nom décale les colonnes que `gofmt` aligne
  (clés d'une table de cas dans `internal/db/pool_test.go`). Règle : après tout
  remplacement de masse, lancer `gofmt -l .`, puis `gofmt -w` sur les fichiers listés.
- `make generate-check` compare le code régénéré au dernier commit (`git status`), pas au
  fichier modifié : sur une copie de travail non commitée qui touche `api/openapi.yaml`, il
  échoue même si le code régénéré est juste. Règle : commiter avant de lancer `make ci`.
- `git grep -lz` : l'option `-z` se place avant les motifs, sinon la commande échoue et
  le `xargs` qui suit ne reçoit rien.

## Tests d'intégration sur un poste de développement

- **Connexions épuisées** : `go test` lance un paquet et un test parallèle par cœur, et
  chaque test de `dbtest` ouvre jusqu'à douze connexions (pool d'exécution à dix,
  propriétaire à deux). Environ 160 connexions au pic sur 16 cœurs, contre 100 par
  défaut : des dizaines d'échecs « remaining connection slots are reserved for roles with
  the SUPERUSER attribute » (SQLSTATE 53300). La CI, sur 4 vCPU, ne le voit pas. Règle :
  `max_connections=500` dans `deploy/compose.yaml` ; tout autre serveur de test reçoit la
  même limite, et un 53300 se règle par la limite, pas par moins de parallélisme.
- **Fuseau horaire** : pgx rend un `timestamptz` dans le fuseau local du processus Go,
  quel que soit le `timezone` de la session. Un `got.Hour() != 3` passe en CI (UTC) et
  échoue en Europe/Paris. Règle : comparer les instants par `Equal`, et passer par `.UTC()`
  avant `Hour`, `Day` ou `Format` ; vérifier un test qui lit une heure avec
  `TZ=Europe/Paris` et `TZ=UTC`.
- Un échec de `make ci` juste après une montée d'open-go-base n'en vient pas forcément :
  comparer d'abord les commits (`go mod download -json …@vX` donne `Origin.Hash`).

## Équipes et droits (T16)

- **Champ ajouté à une saisie, perdu par sa normalisation** : `project.clean` reconstruit un
  `Input` neuf ; le nouveau `TeamID` disparaissait avant l'insertion (« équipe invalide »
  pour chaque création). Règle : à l'ajout d'un champ à une structure de saisie, relire
  toute fonction qui la reconstruit (`clean`, `normalize`…) et tester le cas nominal par le
  service, pas seulement la validation.
- **Ordre d'évaluation en SQL** : `current_setting(x) = '*' OR id = ANY(current_setting(x)::uuid[])`
  n'assure pas que la conversion n'est jamais tentée sur « * ». Règle : `CASE WHEN … THEN
  … ELSE … END` fixe l'ordre ; une fonction SQL simple `STABLE` reste incorporée à la
  requête.
- **Filtre « fermé par défaut »** : un paramètre oublié renvoie tout en silence ; un réglage
  de transaction lu par `current_setting` sans `missing_ok` échoue (connexion neuve :
  paramètre inconnu ; connexion réutilisée : `''`). Règle : pour un filtre de visibilité,
  préférer un réglage déclaré par l'option de transaction et une fonction qui échoue sans
  lui, et tester les deux connexions (pool d'une connexion).
- **Changer une signature appelée par des dizaines de tests** : `go vet` s'arrête à la
  première erreur d'un paquet et `go test -run NONE` à dix. Règle : un script relance la
  compilation, lit les erreurs « not enough arguments … want (…) » et insère l'argument à
  la position indiquée, jusqu'à stabilité ; les imports manquants (`undefined: tenant`)
  se traitent avant, sinon le typage s'arrête.
- **Test dérivé d'une source qui passe du premier coup** : il peut ne rien vérifier.
  Règle : casser volontairement le code (garde qui autorise tout, filtre retiré) et
  constater l'échec avant de committer ; noter le résultat dans le Journal.
- **Test de migration de données** : repérer la migration par son sujet (`*_teams.sql`),
  jamais par son numéro (renumérotation possible avant la fusion) ; migrer jusqu'à la
  précédente avec `db.Migrate(…, Migrations: fstest.MapFS)`, peupler en propriétaire,
  puis migrer jusqu'au bout.
- **Tester une garde sans effet de bord** : rejouer chaque route (POST compris) pour
  chaque rôle modifierait les données d'un cas à l'autre. Règle : un point d'essai non
  exporté remplace les gestionnaires derrière leur garde (`routeStub`) ; un test à part
  vérifie que la table des droits est exactement celle du routeur réel (`chi.Walk`).
- **Délai de `Stop` trop court dans un test** : `TestStopReleaseYieldsToPendingTwin` (T02)
  donnait 500 ms à `Runner.Stop`, qui ne libère les jobs que dans le dernier quart du délai
  (125 ms) ; sa libération enchaîne deux transactions (remise en attente refusée par la clé
  d'unicité, puis suppression) et a dépassé la marge en CI (`-race`, paquets en parallèle).
  Reproduit à 14 échecs sur 15 sur un cœur partagé (`GOMAXPROCS=1 taskset -c 0`, 30
  boucles actives sur le même cœur). Règle : un test d'arrêt donne à `Stop` un délai dont
  le quart couvre plusieurs allers-retours chargés (4 s, marge 1 s), et l'instabilité se
  vérifie sous contention avant et après le correctif.
- **`pkill -f motif`** tue aussi la commande shell qui contient ce motif (code 144). Règle :
  borner les boucles de charge par `timeout`, sans `pkill`.
- **Outil d'isolement des agents (suite)** : `sleep N` suivi d'une autre commande est
  refusé. Règle : `run_in_background` pour une commande longue, puis lecture de sa sortie.

## Différences d'instantanés et rétention (T17)

- **SBOM de test modifié par le seul purl** : `bytes.ReplaceAll(…, "log4j-core@2.14.1",
  "…@2.17.1")` laisse le champ `version` du composant CycloneDX à 2.14.1 ; le composant
  normalisé garde cette version, et une « montée » devient un retrait plus un ajout de la
  même version. Règle : pour simuler un changement de version, remplacer le purl **et**
  le champ `version` du composant (`sbomWith` des tests de `finding` ne change que le
  purl : suffisant pour l'identité, pas pour une différence).
- **Test de concurrence qui bloque au lieu d'échouer** : en retirant `SKIP LOCKED` pour
  vérifier qu'un test échoue, la suppression a attendu le verrou de l'autre transaction ;
  le `timeout` de la commande a tué `go test` et laissé une base jetable orpheline.
  Règle : tout test qui attend qu'une opération **ne** bloque **pas** lui passe un
  contexte borné (`context.WithTimeout`), pour échouer proprement si elle bloque.
- **Énumérations de l'API et collisions d'oapi-codegen** : une valeur d'énumération déjà
  présente ailleurs (`open`, `critical`…) fait préfixer les constantes des deux types, ce
  qui change des noms utilisés par le code existant. Règle : une donnée seulement lue
  (sévérité, état d'un constat dans une réponse) est décrite en `string` avec ses valeurs
  dans la description ; l'énumération est réservée aux paramètres validés.
- **Suppression en masse et clés étrangères sans index** : chaque ligne supprimée
  déclenche un contrôle sur les tables qui la référencent (`findings.snapshot_id`,
  `snapshots.blob_id`…) ; sans index, un parcours complet par ligne. Règle : la migration
  qui introduit une purge indexe toutes les colonnes qui référencent les tables purgées.
- **Orphelins et ingestion concurrente** : `NOT EXISTS` lu au début d'un `DELETE` ne voit
  pas une référence validée pendant l'instruction. Règle : l'écrivain verrouille la ligne
  qu'il réutilise (`FOR KEY SHARE`), la purge sélectionne `FOR UPDATE SKIP LOCKED` puis
  supprime dans une instruction suivante qui revérifie la condition.
## Triage et VEX (T14)

- **Aller-retour entre deux vocabulaires** : noter la valeur d'origine seulement quand la
  correspondance « perd de l'information » (non réciproque) ne suffit pas : même une
  correspondance réciproque change de liste, et l'aller-retour ramenait
  `vulnerable_code_not_present` au lieu de `code_not_present` (trouvé par le test
  d'aller-retour d'un format à l'autre). Règle : pour tout échange entre formats, tester
  l'aller-retour dans le même format **et** d'un format à l'autre, sur toutes les valeurs.
- **Course entre une décision et une analyse** : sans verrou, un constat inséré par une
  analyse en cours échappe au recalcul d'une décision validée entre-temps (`READ
  COMMITTED`, chacune ignore l'écriture non validée de l'autre). Règle : verrou
  consultatif d'organisation, exclusif pour la décision, partagé pour l'analyse, pris
  **avant** toute lecture qui conditionne le travail — y compris un « existe-t-il des
  décisions ? » d'optimisation, qu'une première décision en cours de validation
  rendrait faux.
- **Schéma OpenVEX fermé** : `additionalProperties: false` à tous les niveaux ; une
  information propre au projet ne peut aller que dans un champ texte (`status_notes`),
  sous une forme relisible (`[lotor:clé=valeur;…]`).
- **Champ révélé en CSS et `required`** : un champ masqué par `display: none` (choix non
  coché, `:has(input:checked)`) mais `required` empêche l'envoi du formulaire sans
  message visible. Règle : pas de `required` sur un champ conditionnel, validation
  serveur.
- **Compteur global dans un test d'écran** : `a.countRows` passe par `InTx`, hors
  organisation ; sur une table d'organisation, la RLS échoue (`''::uuid`). Règle :
  compter dans `InOrg` pour une table d'organisation.
- **Statut matérialisé et CHECK** : une contrainte « décision nulle ⇒ à analyser » oblige
  les jeux de test qui posent un statut à insérer d'abord une décision ; prévoir l'aide
  dans le jeu de test du paquet qui lit le statut (tableau de bord).

## Enrichissement IA (T12)

- **SDK d'Anthropic et environnement** : `anthropic.NewClient()` lit `ANTHROPIC_API_KEY`,
  `ANTHROPIC_BASE_URL`, `ANTHROPIC_CUSTOM_HEADERS`, les profils sur disque et la
  fédération d'identité ; une variable posée sur la machine redirigerait le code. Règle :
  `option.WithoutEnvironmentDefaults()` en premier, puis clé, adresse et client explicites,
  et un test qui pose de fausses variables `ANTHROPIC_*`. La clé part en
  `Authorization: Bearer` dans la v2 du SDK, pas en `X-Api-Key` : un test ne fixe pas
  l'en-tête.
- **Choix d'outil forcé refusé** : `tool_choice` `any` ou `tool` répond 400 sur
  `claude-sonnet-5-5`. Règle : `auto`, l'outil final demandé par le prompt, une relance
  unique, et la validation de la soumission par schéma côté agent.
- **Soumission vide sérialisée `null`** : un faux modèle qui soumet `[]Candidate(nil)`
  envoie `"candidates": null`, refusé par le schéma ; les cas sans composant attendu
  échouaient en « scénario épuisé ». Règle : construire les listes JSON non nulles
  (`[]T{}`) dans les assistants de test comme dans le code.
- **Une instruction injectée est aussi une « preuve »** : le README hostile contient
  littéralement le purl qu'il demande de soumettre ; nom et version y figurent, le
  vérificateur de la fiche l'aurait accepté. Règle : refuser toute preuve tirée de la
  documentation, d'un fichier qui s'adresse à un modèle, ou d'un extrait qui cite un purl,
  et éprouver chaque règle par un faux modèle qui obéit au dépôt.
- **Enregistreur et fuite** : chercher un témoin dans tout l'échange trouve aussi les
  arguments que le modèle a lui-même écrits (sa recherche de « PRIVATE KEY »). Règle :
  `Recorder.Sent` ne rend que ce que l'agent envoie (système, outils, messages de
  l'utilisateur, résultats d'outils) ; chercher un marqueur de contenu
  (`-----BEGIN`) plutôt qu'un mot que le modèle peut taper.
- **`.gitignore` de la racine et corpus** : `.env` est ignoré à la racine ; les fichiers
  sensibles factices du corpus ne partaient pas dans le commit. Règle : un `.gitignore`
  local (`!.env`) dans `testdata/ai-corpus`, et `git check-ignore -v` sur chaque fichier
  piège ; secrets factices sans matériau de clé valide (analyse des secrets de GitHub).
- **`os.Root` et « / »** : `clean` ramène « / » à la racine du dépôt, pas du système ; un
  test qui attend un refus de `list_dir("/")` se trompe d'attente. Règle : tester que le
  contenu renvoyé est celui du dépôt.
- **Fonction utilisée par les seuls tests étiquetés** : `scanner.scan` n'était plus appelé
  que par un test `integration` (U1000 de staticcheck). Règle : déplacer l'assistant dans
  le fichier étiqueté ; et ajouter toute nouvelle étiquette (`evalai`) à `TEST_TAGS`.
- **Place libérée par `defer` après la réponse** : le téléchargement réencodé libérait sa
  place (`Reencodes`) au retour du gestionnaire, donc après l'envoi du corps ; sous charge,
  `TestSnapshotScreens` reprenait la place avant sa libération (« place de réencodage »).
  Règle : une place qui borne un calcul se libère dès la fin du calcul, avant l'écriture
  de la réponse, pas par `defer`.

## Conteneurs en projets enfants (T13)

- **Énumérations partagées d'oapi-codegen** (piège de T07 retrouvé) : ajouter l'énumération
  `current`/`outdated` à un second schéma a renommé les constantes existantes
  (`gen.Current` → `gen.HeartbeatStatusInventoryCurrent`) et cassé l'agent. Règle : avant
  de réutiliser des valeurs d'énumération, chercher leurs constantes (`grep '= "'`) et
  corriger tous les appelants dans le même commit.
- **Corps de l'API des agents borné à 64 Kio** pour tout ce qui n'est pas multipart : une
  liste de 500 conteneurs le dépasse. Règle : une borne propre par chemin dans
  `limitBody`, et un test qui envoie réellement plus de 64 Kio.
- **Un `{{with}}` ne prend pas de `{{else if}}`** dans `html/template` (« unexpected <if> in
  input », vu par `render` au démarrage) : écrire `{{if .X}}…{{else if …}}` et lire
  `.X.Champ` dans la branche.
- **Paramètre SQL à `nil` sans type** : `$7 IS NOT NULL` avec `$7` nul donne « could not
  determine data type of parameter » ; caster (`$7::timestamptz`).
- **Horloges de test différentes dans un même scénario** : le serveur de test date les
  signalements avec son horloge figée, l'agent réel avec l'heure du système ; pour un
  archivage « après 7 jours », avancer l'horloge du serveur entre deux cycles plutôt que
  de dater l'archiveur dans le futur (sinon tout est archivé).
- **Vrai moteur Docker dans l'environnement** : `dockerd` est installé (arrêté) ; Docker
  Hub peut répondre 429 : `mirror.gcr.io/library/<image>` sert les images officielles.
  Arrêter le démon et supprimer conteneurs et images après l'essai (`kill $(pidof
  dockerd)`, jamais `pkill -f`).
- **Syft exécute la chaîne Go aussi sur l'hôte** : le scan de `/` de T07 gardait
  `golang.UsePackagesLib` à vrai (piège de T08). Règle : tout scan Syft d'un agent passe
  par des catalogueurs hors ligne (`offlineCatalogers`).
## Politiques, alertes et statuts de commit (T15)

- **Module renommé en amont** : `github.com/google/cel-go` v0.32.0 déclare
  `module cel.dev/cel-go` ; `go get` échoue (« module declares its path as »). Règle :
  lire `go list -m -versions` sous les deux chemins et la date des versions (`go list -m
  -json …@vX`) avant de choisir ; consigner le changement de chemin dans l'ADR.
- **Contrainte « ssi » sur une colonne ajoutée** : `CHECK ((fix_state = 'fixed') =
  (fixed_seen_at IS NOT NULL))` cassait tous les jeux de test qui insèrent un constat
  `fixed` à la main (harnais RLS). Règle : une colonne ajoutée à une table très utilisée
  par les jeux de test ne contraint que le sens nécessaire (`fix_state = 'fixed' OR
  fixed_seen_at IS NULL`).
- **Nouvelle opération de l'API des agents** : `requireKind` refuse toute opération absente
  d'`operationKinds` (401 « jeton refusé ») ; le test de bout en bout l'a montré. Règle :
  ajouter l'opération à la table dans le commit qui l'ajoute au contrat.
- **Envoi qui lit un secret avant de savoir s'il y a quelque chose à envoyer** : un canal au
  secret illisible faisait échouer chaque passage, même sans envoi en attente. Règle :
  déchiffrer le secret au dernier moment, seulement s'il y a un message.
- **Base factice republiée à la même date** : deux `publish` de `vulntest` au même
  horodatage ne changent pas la cible ; l'analyse suivante ne voit rien. Règle : un
  compteur de publications fait avancer la date de construction de chaque base de test.
- **Colonne d'erreur de CEL** : CEL situe un champ inconnu sur le « . » qui le précède
  (`finding.sevrity` : colonne 8), pas sur le nom. Règle : les tests de position lisent la
  position de CEL au lieu de la supposer.
- **Fusion d'un lot parallèle et noms de types** : T12 a ajouté un type `Verdict` au
  paquet `repoagent` ; le mien est devenu `PolicyVerdict` à la fusion. Règle : dans un
  paquet partagé avec un lot en vol, préfixer les types nouveaux par leur domaine.
- **Valeurs d'attribut en dur** (piège de T06 retrouvé) : `value="save"` d'un bouton est
  refusé par le test de `render`. Règle : la valeur vient de la vue (constantes Go).

## Recette du lot 2, compléments (T18, partie 1)

- **Option ajoutée à open-go-base qui change une réponse existante** : avec les codes de
  secours, `EnablePOST` répond 200 (codes montrés) au lieu de rediriger ; deux tests
  d'intégration de lotor attendaient la redirection. Règle : après une montée
  d'open-go-base, chercher les tests qui frappent les routes de mfax et d'authx
  (`pathTOTPOn`, `pathVerify`) et lire la note de version.
- **Nouvelle interface de rendu dans une bibliothèque partagée** : ajouter une méthode à
  `mfax.Renderer` aurait cassé tous les projets à la compilation ; une interface
  facultative (`RecoveryRenderer`), vérifiée à l'exécution quand l'option est active,
  garde la compatibilité. Règle : une option nouvelle n'impose rien à qui ne l'active pas.
- **Validation de l'API avant celle du domaine** : un identifiant d'équipe illisible
  (`team=moi`) est refusé par le contrat OpenAPI (`error.invalid_request`) avant d'atteindre
  `search.ParseRequest` (`error.search.filter_invalid`), alors que l'écran donne le second.
  Règle : un test d'erreur de l'API attend la clé de la couche qui refuse en premier.
- **Nom de schéma OpenAPI déjà pris par un paramètre** : `SearchTeam` (schéma) entrait en
  collision avec le paramètre `SearchTeam` dans le code généré. Règle : nommer les schémas
  d'objet partagés sans le préfixe des paramètres (`TeamRef`).
- **Suppression d'un projet** : aucun chemin ne supprimait encore de projet ; références,
  instantanés, réceptions, constats et courant n'ont pas de cascade, et `triage_decisions`
  est en ajout seul (le rôle d'exécution ne peut pas l'effacer). Règle : supprimer dans
  l'ordre courant → analyses → constats → réceptions → instantanés → projet, et écarter un
  projet qui porte une décision de triage.
- **Ordre des étapes de la rétention** : une réception hors fenêtre est supprimée par
  l'étape commune avant la purge des conteneurs ; un test qui veut vérifier que la purge
  supprime une réception doit en créer une dans la fenêtre.

## Recette du lot 2, revue de sécurité (T18, partie 2)

- **Une protection qui suit une ressource doit tomber quand la ressource change** :
  l'autorisation d'IA externe survivait au changement d'URL du dépôt (SEC2-03), le secret
  d'un canal au changement de serveur (SEC2-04). Règle : pour tout réglage ou secret lié à
  une destination, se demander ce qui se passe quand la destination est modifiée par
  quelqu'un qui n'a pas le droit de poser le réglage ou ne connaît pas le secret.
- **Un nouvel acteur casse les hypothèses des risques acceptés** : le rattachement par le
  nom d'hôte (SEC-13, accepté au lot 1) devenait une faille inter-équipes avec T16
  (SEC2-02). Règle : à chaque nouvel acteur ou nouvelle frontière, relire les risques
  acceptés du modèle de menace.
- **Toutes les vérifications d'un code passent par le même verrou** : `EnablePOST`
  vérifiait le code hors du verrouillage par compte (SEC2-01) ; la v1.4.0 en a fait une
  source de codes de secours. Règle : dans mfax, tout code passe par `confirm` ; une
  option qui ajoute un effet à un chemin existant relit d'abord les gardes de ce chemin.
- **Données d'une source externe dans un prompt** : la liste des fichiers modifiés venait
  de la forge, sans le filtre appliqué aux outils (SEC2-07). Règle : tout ce qui part vers
  le modèle passe par les mêmes exclusions, quelle que soit sa provenance.
- **Valider avant de consommer** : la reconfiguration valide le nouveau mot de passe avant
  le code de secours, sinon une faute de frappe coûte un code. Règle : dans un formulaire
  qui consomme un facteur à usage unique, toutes les validations bon marché d'abord.
- **Tests qui comptent des objets partagés** : ajouter un cas à un test existant qui
  compte agents et jetons visibles a cassé ses totaux. Règle : un test de non-régression
  de sécurité vit dans sa propre fonction, avec ses propres données.
- **Tests de non-régression** : chaque test de reproduction de la revue a été rejoué sans
  le correctif (`git stash` des seuls fichiers de production, ou condition neutralisée)
  pour vérifier qu'il échoue. Règle : un test de non-régression qui passe sans le
  correctif ne prouve rien.

## Audit RGAA du lot 2 (T18, partie 3)

- **Champ dans l'étiquette d'un choix** : le panneau de triage mettait la justification
  VEX et la date d'échéance dans la `<label>` du bouton radio (étiquette dans une
  étiquette) ; ni axe-core ni `webtest` ne le voyaient, seul l'arbre d'accessibilité de
  Chromium (CDP `Accessibility.getPartialAXTree`) montrait le nom du radio gonflé de
  l'étiquette et de l'aide de la date. Règle : un champ révélé par un choix vit hors de la
  `<label>` (`li.choice-item`) ; `webtest` refuse une étiquette imbriquée ou à plusieurs
  champs ; à l'audit, relever les noms accessibles des champs, pas seulement leur présence.
- **Données qui révèlent un défaut d'un écran ancien** : la fiche composant du lot 1
  débordait à 320 px avec une version de paquet Alpine (`1.36.1-r29`) apportée par les
  conteneurs. Règle : l'instance d'audit charge des données réalistes de chaque nouvelle
  source (conteneurs, IA), et l'audit d'un lot repasse la redistribution sur **toutes**
  les pages, pas seulement les nouvelles.
- **Valeur technique dans un paramètre de traduction** : `{{.Status}}` recevait
  `not_affected` ; les gabarits traduisaient le statut partout sauf dans les paramètres
  passés depuis Go (titre de la confirmation). Règle : un paramètre de traduction est
  déjà traduit (`identity.localizer(r).T(…)`) ; rechercher dans le texte visible les mots
  à tiret bas (`[a-z]+_[a-z]+`) hors `code`.
- **Le script d'audit qui se déconnecte** : `page.click('form button[type=submit]')`
  visait le premier formulaire de la page, celui de « Se déconnecter » dans l'en-tête ;
  la session supprimée côté serveur coupait aussi les autres contextes de Playwright
  (121 pages auditées sur la page de connexion, sans erreur). Règle : viser
  `main form …` ; vérifier qu'aucun rendu audité n'a le titre de la connexion ; donner à
  l'instance d'audit des sessions longues (`SessionTTL`) et une sonde de session.
- **Fichier de l'instance d'audit** : l'étiquette `integration && rgaaserve` l'écarte de
  `make test-integration`, mais il ne doit jamais être commité ; le copier dans
  `internal/web` seulement le temps de la compilation.

## Recette du lot 2 (T18, partie 4)

- **Type CycloneDX ignoré par le décodeur du serveur** : l'agent dépôt émettait les
  composants IA d'image de conteneur (`FROM` d'un Dockerfile) en type `container` ; le
  décodeur CycloneDX de Syft, celui du serveur, ne garde que `application`, `framework`,
  `library`, `firmware` et `machine-learning-model` : l'image disparaissait à
  l'ingestion, sans erreur. Les tests de T12 relisaient le SBOM par le décodeur du
  serveur, mais seulement avec une bibliothèque JavaScript. Règle : tout composant qu'un
  agent produit est relu par `sbomsyft.Decode` dans un test, **pour chaque forme**
  (bibliothèque, image, outil) ; compter les composants relus, pas seulement en chercher
  un.
- **Contrôle indépendant du juge** : « aucun composant sans preuve vérifiée » se teste en
  revérifiant, hors du vérificateur, chaque composant du SBOM final (`checkProof`) contre
  des centaines de candidats adverses ; c'est ce contrôle qui a trouvé le défaut
  précédent (composants acceptés, absents du SBOM).
- **Mesures qui ne tournent qu'à la recette** : `make bench-search` échouait depuis T16
  dans son dernier pas (`EXPLAIN ANALYZE` sans `db.Visible` : `lotor_team_visible`
  exécutée sans déclaration ; sur une connexion réutilisée, `lotor.teams` vide donne
  « malformed array literal "" », sur une neuve « unrecognized configuration
  parameter ») : `EXPLAIN` seul, en CI, n'exécute pas la fonction. Règle : un lot qui
  touche une requête mesurée relance la cible de mesure correspondante, ou au moins son
  test sur un petit jeu ; une erreur SQL « malformed array literal "" » sur une requête
  d'équipe signale une visibilité non déclarée.
- **Disque de la session** : le cache de compilation Go atteint 14 Gio sur une longue
  session à plusieurs lots ; le disque plein fait tomber PostgreSQL en « recovery mode »
  au milieu d'une mesure et laisse une base jetable orpheline. Règle : `df -h /` avant
  les mesures (le jeu de référence complété pèse plusieurs Gio), `go clean -cache` si
  besoin, et supprimer la base jetable et ses deux rôles après un échec.
- **Échantillon pilote annoté** : sur des dépôts réels, presque tout est déjà déclaré
  (4 composants attendus sur 4 dépôts) ; ce que Syft voit déjà (actions GitHub des flux
  de travail) doit être annoté « ignoré », sinon chaque détection juste de l'IA, écartée
  ensuite par la fusion, compterait comme faux positif.
- **Clé d'unicité des jobs = jobs en attente seulement** : un job en cours ne bloque pas
  la mise en file d'un second job de même clé, qu'un autre worker prend aussitôt. Deux
  envois de notification du même canal envoyaient ainsi le même lot (vu seulement sur une
  vraie instance, avec quatre workers et une politique qui ouvre 195 violations). Règle :
  un handler dont l'effet est externe (réseau) réserve son travail sous verrou avant
  l'appel (ADR 0052) ; le tester avec deux exécutions simultanées et un faux envoi
  bloquant.
- **Recette scriptée** : `pkill -f <motif>` tue aussi le shell qui porte le motif dans sa
  ligne de commande (code 144) ; garder le PID au lancement (`echo $! > x.pid`) ou
  `pgrep -x`. Un code TOTP ne sert qu'une fois par fenêtre : un client de recette qui se
  reconnecte vite doit attendre la fenêtre suivante. Les images de Docker Hub tombent vite
  en 429 depuis la session : passer par `mirror.gcr.io` ou `public.ecr.aws/docker/library`.
- **Python et l'autorité de test** : Python 3.13 refuse une autorité sans
  `keyUsage` (« CA cert does not include key usage extension ») ; créer l'autorité de
  recette avec `basicConstraints=critical,CA:TRUE` et `keyUsage=critical,keyCertSign`.

## Paquet deb du serveur (T27)

- **Une recommandation n'ordonne rien** : apt configure `lotor-server` avant le PostgreSQL qu'il
  installe dans le même appel (`Recommends`). Règle : tout ce qu'un script de post-installation
  attend d'un paquet seulement recommandé doit échouer en douceur, avec une reprise documentée
  (`dpkg-reconfigure`).
- **Conteneurs de recette** : les images Debian et Ubuntu portent `/usr/sbin/policy-rc.d`, qui
  interdit de démarrer les services, et `docker-clean`, qui vide le cache d'apt : les retirer.
  systemd monte son propre `/tmp` : `docker cp` y dépose un fichier invisible, passer par `/root`.
- **debconf** : `db_input` renvoie 30 quand personne ne peut répondre, signal fiable pour ne pas
  compter sur une note ; une valeur invalide doit y être vidée, jamais redemandée en boucle.
  L'interface `teletype` ignore les valeurs par défaut (Entrée repose la question) : `yes ''`
  boucle sans fin et remplit le journal. Piloter sous pseudo-terminal, réponses prérenseignées.
  Les variables de `db_subst` restent dans `config.dat`, lisible par tous : les vider.
- **Python** : un script nommé `tty.py` masque le module `tty` et casse `import pty`.
- **Heredoc** : un script Python ou un document qui contient `EOF` dans un heredoc `<<'EOF'`
  coupe celui-ci, et bash exécute la suite comme des commandes (une ligne `sudo apt-get` d'une
  documentation, ici arrêtée par sa redirection). Règle : tout texte libre ou tout script un peu
  long passe par un fichier, avec l'outil d'écriture.

## Inscription (T28)

- **Pages d'une ligne** : `render` exécute `layout` avec `.Page.*` ; passer un `*render.Page`
  nu fait une erreur 500 (« can't evaluate field Page in type *render.Page »). Toute vue,
  même sans donnée, embarque `render.Page` (`plainView`).
- **Tests sur le HTML rendu** : `html/template` écrit l'apostrophe `&#39;` ; comparer un
  texte traduit au corps de la page à la fois brut et échappé (`html.EscapeString`).
- **Atomicité inter-tables** : une transaction `InOrg` déclarée pour l'identifiant d'une
  organisation pas encore créée peut aussi écrire dans les tables globales (`users`) : compte,
  organisation, code consommé et liens supprimés tiennent ou tombent ensemble. Un
  identifiant d'URL pris ne doit pas abandonner la transaction : `ON CONFLICT (slug) DO
  NOTHING` puis candidat suivant, jamais une erreur d'unicité rattrapée.
- **Réponse neutre sans courriel** : refuser une adresse déjà prise comme un code faux ne
  suffit pas, il faut aussi annuler la consommation du code (retour arrière de la même
  transaction) ; un test qui retire la consommation doit échouer (vérifié).
- **Mode sombre de Thunderbird** : il réécrit les styles en ligne et ignore `@media … !important`
  ; un fond survit si sa luminance ne dépasse pas 200 et si son contraste avec le texte atteint
  3,5. Le vérifier par test sur la table des couleurs, et dans un vrai Thunderbird (Xvfb,
  profil `ui.systemUsesDarkTheme=1`, `mail.dark-reader.enabled=true`).
- **Clé de configuration déplacée** : une clé inconnue est ignorée sans message par le
  chargement ; un script de paquet qui réécrit une clé par `sed` peut écrire l'ancienne
  position. Réécrire dans la bonne section (awk par section) et le dire dans le CHANGELOG.

## Emplacements des composants (hors lot, ADR 0057)

- **Ce que chaque format transporte des emplacements de Syft** : Syft JSON donne tout
  (`path`, `accessPath`, `layerID`, annotation `evidence`) ; CycloneDX, par les propriétés
  `syft:location:N:path` et `syft:location:N:layerID`, ni le chemin d'accès ni l'annotation ;
  SPDX, rien (`sourceInfo` est un texte). Règle : un emplacement sans annotation est
  principal ; ne marquer « secondaire » que ce que Syft annote `supporting`.
- **`LocationSet` de Syft dédoublonne par empreinte, et l'empreinte ignore `AccessPath`**
  (`hash:"ignore"`) : deux chemins d'accès vers le même fichier réel n'en font qu'un.
- **Une donnée par élément d'ensemble entre dans l'empreinte d'inventaire** : sinon deux
  instantanés aux valeurs différentes partagent l'ensemble et l'un montre les valeurs de
  l'autre. Changer l'empreinte, c'est changer `fingerprintVersion`, et le dire dans le
  CHANGELOG (un nouvel ensemble par référence au premier scan).
- **Lecture ajoutée à `rowColumns` des constats** : la requête est réutilisée par
  `finding/effect.go` (préfixe de colonne) ; une sous-requête scalaire dans les colonnes,
  plutôt qu'une jointure de plus dans `rowFrom`, ne touche ni aux alias ni aux filtres des
  autres requêtes.
## Compatibilité Dependency-Track (T19)

- **Code téléchargé d'un client tiers** : lancer le `dist/index.js` d'une action GitHub
  récupérée sur le réseau est refusé dans la session (code externe). Règle : lire son code
  pour reconstituer la requête (ordre des champs, en-têtes, format du multipart de la
  bibliothèque HTTP), valider la requête reconstituée contre le vrai serveur tiers, et
  laisser l'enregistrement d'une exécution réelle à l'utilisateur.
- **Un client qui ne garde pas le chemin de l'adresse** : `new URL("/api/v1/bom", base)`
  remplace tout chemin de `base` ; l'action `gh-upload-sbom` ne peut donc pas viser un
  préfixe comme `/dt`. Règle : pour tout point « compatible » sous un préfixe, vérifier
  dans le code de chaque client visé comment il compose l'URL, et documenter le mandataire
  qui préfixe quand le client n'accepte qu'un nom d'hôte.
- **Dependency-Track 5 en conteneur** : l'image `dependencytrack/apiserver:5.x` ne demande
  que PostgreSQL (`DT_DATASOURCE_URL`, `_USERNAME`, `_PASSWORD`, réseau de l'hôte) ; les
  erreurs TLS des miroirs de vulnérabilités au démarrage sont sans effet sur l'API. Compte
  `admin`/`admin` : `POST /api/v1/user/forceChangePassword`, puis `login`, puis `PUT
  /api/v1/team/{uuid}/key` ; le contrat OpenAPI exact est dans le jar
  (`org/dependencytrack/api/v1/openapi.yaml`).
- **Réponse d'un tiers plus riche que sa documentation** : `event/token` renvoie aussi
  `status` en 5.x, absent des pages consultées. Règle : relever les réponses réelles
  (fichiers de `testdata/`) plutôt que de s'en tenir à la documentation.
- **Nom déjà pris dans un paquet** : `writeJSON` existait dans `internal/api` (API
  utilisateur) avec une autre signature. Règle : chercher le nom (`grep -n "func nom"`)
  avant d'ajouter un assistant à un paquet partagé.

## Recherche à une date passée (T21)

- **Mesure et autres travaux en parallèle** : une mesure partage les quatre cœurs de la
  session ; une CI ou des compilations simultanées faussent les centiles. Règle : lancer
  `make bench-search` seul, ne rien compiler pendant (préparer le lot suivant hors du
  dépôt, ou dans un worktree, sans le compiler), et noter la machine dans
  `docs/benchmarks.md`.
- **Travailler pendant une longue CI** : modifier le dépôt pendant `make ci` peut faire
  tester un état mêlé. Règle : un `git worktree` séparé pour le lot suivant, rapatrié par
  `cherry-pick` puis `reset --soft` une fois la CI finie.
- **Texte de contrôle d'un écran** : « Critique » figure aussi dans les filtres de la
  page ; un test qui vérifie l'absence des vulnérabilités doit chercher un texte propre aux
  colonnes masquées (« Corrigée en »), pas un libellé présent ailleurs.

## Mode hors ligne (T23)

- **`MultipartReader` marque la requête** : appelé sur un corps qui n'est pas multipart, il
  échoue mais pose `r.MultipartForm` à sa sentinelle ; `PostFormValue` (donc csrfx) ne lit
  plus rien et la requête part en 403. Règle : vérifier le `Content-Type` avant d'appeler
  `MultipartReader` dans un middleware ; le harnais des droits par route (formulaires
  ordinaires) l'a montré.
- **Fichier nommé à la seconde** : deux archives écrites dans la même seconde
  s'écrasaient. Règle : tout nom de fichier horodaté porte aussi un discriminant du
  contenu (empreinte).
- **Répertoire de sortie configuré** : les tests créaient le répertoire, le vrai agent non.
  Règle : un agent crée lui-même (`0700`) tout répertoire qu'il écrit, et un test part d'un
  répertoire absent.
- **Paquet d'un domaine sans `net/http`** : `ingest` ne peut pas tester
  `*http.MaxBytesError` (règle d'architecture) ; la couche web traduit la borne du corps en
  `ingest.ErrUploadTooLarge` par un lecteur enveloppe, et les erreurs de lecture sont
  enveloppées par `%w` jusqu'au domaine.
- **Utilisateur d'un paquet** : l'agent serveur tourne sous `lotor-agent` (sysusers), pas
  sous le nom du paquet ; le lire dans `deploy/host-agent/sysusers.conf` avant de scripter
  une recette.

## Licences (T20)

- **Argument SQL ajouté mais non référencé** : la recherche `license:` construisait les
  deux conditions possibles et n'en gardait qu'une ; le paramètre des composants restait
  dans la liste sans figurer dans la requête, et PostgreSQL refusait (« could not
  determine data type of parameter $1 »). Le test unitaire de la requête ne l'a pas vu, un
  vrai inventaire si. Règle : avec un assembleur d'arguments numérotés (`args.add`),
  n'ajouter un argument que dans la branche qui l'écrit dans la requête.
- **Étude d'une bibliothèque avant l'adaptateur** : la fiche prévoyait Grant ; son
  évaluation contredisait le premier critère d'acceptation. Règle : confronter le
  comportement d'une dépendance prévue aux critères de la fiche, par un essai, avant d'en
  écrire l'adaptateur.
- **Nouveau sujet de règle** : un sujet de politique touche la contrainte `subject` de deux
  tables, le contexte CEL, l'aperçu, les violations (jointure, visibilité), les
  notifications (titre, ligne), l'écran des violations et les clés `policy_subject.*`,
  `policy_form.preview_*` et `policy_help.*` (vérifiées par `TestDynamicKeysExist`). Règle :
  chercher `SubjectAgent` dans tout le dépôt et traiter chaque occurrence.

## Credentials systemd de l'agent dépôt (correctif 0.3.2)

- **Droits d'un credential** : l'agent dépôt exigeait `0600` ou `0400` de tout secret, y
  compris dans `$CREDENTIALS_DIRECTORY`, où systemd dépose les credentials en `0440` sous
  `DynamicUser=yes` ; l'agent refusait de démarrer dès le premier vrai déploiement. Le test
  unitaire écrivait le credential lui-même en `0400`, avec les droits qu'on imaginait.
  L'agent serveur avait déjà l'exemption (`inCredentials`). Règle : un contrôle de droits
  sur un fichier produit par systemd se teste avec les droits que systemd lui donne
  réellement ; chercher l'équivalent dans l'autre agent avant d'écrire un contrôle.
- **Credentials dans la recette du paquet** : systemd 257, dans les conteneurs Docker de
  `make test-package`, ne livre aucun credential (`SetCredential=`, `LoadCredential=` ou
  chiffré : `$CREDENTIALS_DIRECTORY` est défini mais absent, même sans compte dynamique ni
  isolation). La recette ne peut pas couvrir la lecture d'un credential ; c'est le test
  unitaire en `0440` qui la garde, et la vérification se fait sur une vraie machine.
