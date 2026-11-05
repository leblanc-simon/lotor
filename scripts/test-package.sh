#!/usr/bin/env bash
# Recette des paquets deb de lotor-server et de lotor-repo-agent (make test-package) : chaque
# scénario installe le vrai paquet dans un conteneur systemd neuf. Exige Docker,
# dist/lotor-server_*_amd64.deb et dist/lotor-repo-agent_*_amd64.deb.
#
#   scripts/test-package.sh [scénario…]      # tous par défaut
#   PACKAGE_DISTROS="debian:13" …            # distributions, par défaut Debian 13 et Ubuntu 24.04
set -euo pipefail

cd "$(dirname "$0")/.."
DISTROS=${PACKAGE_DISTROS:-debian:13 ubuntu:24.04}
ALL_SCENARIOS="nginx apache no_web no_email order remote invalid_dsn broken_site lifecycle interactive teletype questions repo_agent"
SCENARIOS=${*:-$ALL_SCENARIOS}
HOST=lotor.example.org
EMAIL=admin@example.org
ENV=/etc/lotor/lotor-server.env
PWFILE=/etc/lotor/initial-admin-password

deb=$(ls -t dist/lotor-server_*_amd64.deb 2>/dev/null | head -n 1 || true)
[ -n "$deb" ] || { echo "paquet absent : make packages" >&2; exit 1; }
repo_deb=$(ls -t dist/lotor-repo-agent_*_amd64.deb 2>/dev/null | head -n 1 || true)
[ -n "$repo_deb" ] || { echo "paquet absent : make packages" >&2; exit 1; }

C=""
failures=0
trap '[ -n "$C" ] && docker rm -f "$C" >/dev/null 2>&1 || true' EXIT

x() { docker exec "$C" sh -c "$1"; }
fail() { echo "  ÉCHEC : $1" >&2; failures=$((failures + 1)); }
ok() { echo "  ok : $1"; }
check() { # libellé, commande
    if x "$2" >/dev/null 2>&1; then ok "$1"; else fail "$1"; fi
}
refute() { # libellé, commande qui doit échouer
    if x "$2" >/dev/null 2>&1; then fail "$1"; else ok "$1"; fi
}

image() { # distribution
    local tag="lotor-pkgtest:${1//:/-}"
    docker build -q -t "$tag" - >/dev/null <<EOF
FROM $1
ENV container=docker
RUN rm -f /etc/apt/apt.conf.d/docker-clean /usr/sbin/policy-rc.d; apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates curl netcat-openbsd python3 locales procps whiptail >/dev/null \
 && apt-get install -y -qq --download-only postgresql nginx apache2 >/dev/null \
 && sed -i 's/^# *fr_FR.UTF-8/fr_FR.UTF-8/' /etc/locale.gen && locale-gen >/dev/null \
 && rm -f /etc/machine-id && systemd-machine-id-setup >/dev/null
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
    echo "$tag"
}

start() { # image
    [ -n "$C" ] && docker rm -f "$C" >/dev/null 2>&1 || true
    C="lotor-pkgtest-$$"
    docker run -d --name "$C" --hostname srv1.example.net --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock "$1" >/dev/null
    local i=0
    until x 'systemctl is-system-running 2>/dev/null | grep -Eq "running|degraded"'; do
        i=$((i + 1))
        [ "$i" -lt 60 ] || { echo "systemd ne démarre pas" >&2; return 1; }
        sleep 1
    done
    docker cp "$deb" "$C:/root/lotor-server.deb"
    docker cp "$repo_deb" "$C:/root/lotor-repo-agent.deb"
    docker cp scripts/test-package-login.py "$C:/root/login.py"
    docker cp scripts/test-package-tty.py "$C:/root/run_tty.py"
    x "echo '127.0.0.1 $HOST' >> /etc/hosts"
}

preseed() { # lignes « question type valeur »
    local line
    for line in "$@"; do
        x "echo 'lotor-server lotor-server/$line' | debconf-set-selections"
    done
}

apt_quiet() { x "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends $1 >/dev/null 2>&1"; }

# Installation sans terminal ; la sortie reste dans /root/install.log.
install_package() { # options d'apt-get
    x "DEBIAN_FRONTEND=noninteractive apt-get install -y ${1:-} /root/lotor-server.deb >/root/install.log 2>&1"
}

wait_active() {
    local i=0
    until x 'curl -s -o /dev/null http://127.0.0.1:1761/livez || curl -s -o /dev/null http://127.0.0.1:1761/readyz'; do
        i=$((i + 1))
        [ "$i" -lt 30 ] || return 1
        sleep 1
    done
}

check_https() { # service
    check "$1 : redirection de HTTP vers HTTPS" \
        "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://$HOST/ | grep -q '^301 https://$HOST/'"
    check "$1 : cookie __Host- et HSTS en HTTPS" \
        "curl -sk -D- -o /dev/null https://$HOST/login | tee /root/h | grep -qi '^set-cookie: __Host-csrf_token' && grep -qi '^strict-transport-security' /root/h"
    check "$1 : aucun autre site modifié" "! grep -rl lotor /etc/nginx/sites-available/default /etc/apache2/sites-available/000-default.conf 2>/dev/null"
}

# En-têtes reçus par le serveur, en usurpant ceux du client.
check_proxy_headers() { # service
    x 'systemctl stop lotor-server; rm -f /root/req; (nc -l 127.0.0.1 1758 >/root/req 2>/dev/null &) ; sleep 1'
    x "curl -sk -m 3 -o /dev/null -H 'X-Forwarded-For: 6.6.6.6' -H 'X-Real-IP: 6.6.6.6' -H 'X-Forwarded-Proto: http' https://$HOST/probe" || true
    x 'pkill nc || true'
    check "$1 : Host transmis" "grep -qi '^Host: $HOST' /root/req"
    check "$1 : X-Forwarded-Proto https" "grep -qi '^X-Forwarded-Proto: https' /root/req"
    check "$1 : X-Forwarded-For écrasé" "grep -qi '^X-Forwarded-For: 127.0.0.1' /root/req"
    check "$1 : X-Real-IP écrasé" "grep -qi '^X-Real-IP: 127.0.0.1' /root/req"
    refute "$1 : IP usurpée absente" "grep -q 6.6.6.6 /root/req"
    x 'systemctl start lotor-server'
    wait_active
}

# Le mot de passe temporaire n'existe que dans le fichier réservé à root.
check_password_traces() {
    check "mot de passe temporaire : fichier en 0600" "[ \"\$(stat -c %a $PWFILE)\" = 600 ]"
    check "mot de passe temporaire : long de 24 caractères" "[ \"\$(wc -c < $PWFILE)\" -eq 25 ]"
    refute "mot de passe temporaire : absent de debconf, des journaux et de la sortie" \
        "grep -rlF \"\$(cat $PWFILE)\" /var/cache/debconf /var/log /root/install.log"
    refute "variables BOOTSTRAP retirées" "grep -q BOOTSTRAP $ENV"
    check "secrets en 0600" "[ \"\$(stat -c %a $ENV)\" = 600 ]"
}

full_install() { # serveur web
    apt_quiet "postgresql $1"
    x 'pg_lsclusters -h | awk "{print \$1, \$2}" | while read v c; do pg_ctlcluster $v $c start 2>/dev/null || true; done'
    preseed "admin_email string $EMAIL" "server_name string $HOST" "web_server select $1"
    install_package
    wait_active
}

login() { # libellé
    check "$1 : connexion, TOTP, codes de secours et nouveau mot de passe" \
        "python3 /root/login.py https://$HOST $EMAIL \"\$(cat $PWFILE)\""
}

scenario_nginx() {
    full_install nginx
    check "service actif" 'systemctl is-active lotor-server'
    check "service activé" 'systemctl is-enabled lotor-server'
    check "fichier de site en place" 'nginx -t'
    check_password_traces
    check_https nginx
    check_proxy_headers nginx
    login nginx
    check "readyz attend la base de vulnérabilités sans bloquer" "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:1761/readyz | grep -Eq '200|503'"
}

scenario_apache() {
    full_install apache2
    check "service actif" 'systemctl is-active lotor-server'
    check "configuration Apache valide" 'apache2ctl configtest'
    check_password_traces
    check_https apache
    check_proxy_headers apache
    login apache
}

scenario_no_web() {
    apt_quiet postgresql
    x 'pg_lsclusters -h | awk "{print \$1, \$2}" | while read v c; do pg_ctlcluster $v $c start 2>/dev/null || true; done'
    preseed "admin_email string $EMAIL" "server_name string $HOST" "web_server select none"
    install_package
    wait_active
    check "service actif" 'systemctl is-active lotor-server'
    check "écoute sur 127.0.0.1:1758" "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:1758/login | grep -q 200"
    refute "aucun certificat généré" "ls /etc/lotor/tls/* 2>/dev/null | grep -q ."
    check "message sur TLS" "grep -q 'no web server configured' /root/install.log"
    check_password_traces
}

scenario_no_email() {
    apt_quiet postgresql
    x 'pg_lsclusters -h | awk "{print \$1, \$2}" | while read v c; do pg_ctlcluster $v $c start 2>/dev/null || true; done'
    preseed "server_name string $HOST"
    install_package
    wait_active
    check "service actif" 'systemctl is-active lotor-server'
    refute "pas de fichier de mot de passe" "[ -e $PWFILE ]"
    refute "pas de variables BOOTSTRAP" "grep -q BOOTSTRAP $ENV"
    check "message sans administrateur" "grep -q 'no administrator' /root/install.log"
}

# apt peut configurer lotor-server avant PostgreSQL, seulement recommandé : l'installation
# réussit sans démarrer, et dpkg-reconfigure la termine.
scenario_order() {
    preseed "admin_email string $EMAIL" "server_name string $HOST" "web_server select none"
    install_package "--install-recommends"
    check "installation réussie" "dpkg-query -W -f '\${Status}' lotor-server | grep -q 'install ok installed'"
    if x "grep -q 'no running local PostgreSQL' /root/install.log"; then
        ok "lotor-server configuré avant PostgreSQL : message affiché"
        refute "service non démarré" 'systemctl is-active lotor-server'
    else
        ok "PostgreSQL déjà prêt à la configuration de lotor-server"
    fi
    x 'pg_lsclusters -h | awk "{print \$1, \$2}" | while read v c; do pg_ctlcluster $v $c start 2>/dev/null || true; done'
    x "DEBIAN_FRONTEND=noninteractive dpkg-reconfigure lotor-server >/root/install.log 2>&1"
    wait_active
    check "service actif après dpkg-reconfigure" 'systemctl is-active lotor-server'
    check_password_traces
    check "écoute sur 127.0.0.1:1758" "curl -s -o /dev/null http://127.0.0.1:1758/login"
}

scenario_remote() {
    apt_quiet postgresql
    x 'pg_lsclusters -h | awk "{print \$1, \$2}" | while read v c; do pg_ctlcluster $v $c start 2>/dev/null || true; done'
    docker exec -i "$C" sh -c 'cd / && runuser -u postgres -- psql -q -p $(pg_lsclusters -h | awk "{print \$3}" | tail -n 1)' >/dev/null <<'EOF'
CREATE ROLE lotor_owner LOGIN BYPASSRLS PASSWORD 'pw-owner-remote';
CREATE ROLE lotor_app LOGIN PASSWORD 'pw-app-remote' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
CREATE DATABASE lotor OWNER lotor_owner;
REVOKE ALL ON DATABASE lotor FROM PUBLIC;
GRANT CONNECT ON DATABASE lotor TO lotor_app;
EOF
    local port
    port=$(x 'pg_lsclusters -h | awk "{print \$3}" | tail -n 1')
    preseed "database select remote" "server_name string $HOST" "web_server select none" "admin_email string $EMAIL" \
        "db_dsn password postgres://lotor_app:pw-app-remote@127.0.0.1:$port/lotor?sslmode=disable" \
        "migration_dsn password postgres://lotor_owner:pw-owner-remote@127.0.0.1:$port/lotor?sslmode=disable"
    install_package
    wait_active
    check "service actif" 'systemctl is-active lotor-server'
    check "chaînes de connexion reprises" "grep -q 'pw-app-remote' $ENV && grep -q 'pw-owner-remote' $ENV"
    refute "chaînes absentes de debconf" "grep -rl 'pw-app-remote\|pw-owner-remote' /var/cache/debconf"
    check_password_traces
}

scenario_invalid_dsn() {
    apt_quiet postgresql
    preseed "database select remote" "server_name string $HOST" "web_server select none" "admin_email string $EMAIL" \
        "db_dsn password pas-une-chaine" "migration_dsn password pas-une-chaine"
    install_package
    check "installation réussie" "dpkg-query -W -f '\${Status}' lotor-server | grep -q 'install ok installed'"
    check "message explicite" "grep -q 'connection strings missing or invalid' /root/install.log"
    refute "service non démarré" 'systemctl is-active lotor-server'
}

# Un test de configuration qui échoue retire le site lotor, sans toucher aux autres.
scenario_broken_site() {
    full_install nginx
    x "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=a -keyout /root/a.key -out /root/a.crt >/dev/null 2>&1; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=$HOST -keyout /root/b.key -out /root/b.crt >/dev/null 2>&1"
    preseed "tls_mode select existing" "tls_cert string /root/a.crt" "tls_key string /root/b.key"
    x "DEBIAN_FRONTEND=noninteractive dpkg-reconfigure lotor-server >/root/reconf.log 2>&1"
    check "message d'échec" "grep -q 'configuration test failed' /root/reconf.log"
    refute "site lotor retiré" "[ -e /etc/nginx/sites-available/lotor.conf ] || [ -e /etc/nginx/sites-enabled/lotor.conf ]"
    check "nginx reste valide" 'nginx -t'
    check "serveur toujours actif" 'systemctl is-active lotor-server'
    preseed "tls_key string /root/a.key" "tls_cert string /root/a.crt"
    x "printf 'lotor-server lotor-server/server_name string a\n' | debconf-set-selections; DEBIAN_FRONTEND=noninteractive dpkg-reconfigure lotor-server >/root/reconf.log 2>&1"
    check "certificat existant utilisé" "grep -q 'ssl_certificate /root/a.crt' /etc/nginx/sites-available/lotor.conf"
    check "nom public mis à jour" "grep -q 'public_url: https://a/' /etc/lotor/config.yaml"
}

scenario_lifecycle() {
    full_install nginx
    local sum pid
    sum=$(x "sha256sum $ENV /etc/lotor/config.yaml")
    pid=$(x 'systemctl show -p MainPID --value lotor-server')

    x "dpkg -i /root/lotor-server.deb >/root/upgrade.log 2>&1 </dev/null"
    check "mise à jour : message de sauvegarde" "grep -q 'Back up the database' /root/upgrade.log"
    [ "$(x 'systemctl show -p MainPID --value lotor-server')" = "$pid" ] && ok "mise à jour : pas de redémarrage" || fail "mise à jour : pas de redémarrage"
    [ "$(x "sha256sum $ENV /etc/lotor/config.yaml")" = "$sum" ] && ok "mise à jour : secrets et configuration intacts" || fail "mise à jour : secrets et configuration intacts"

    x "DEBIAN_FRONTEND=noninteractive apt-get remove -y lotor-server >/root/remove.log 2>&1"
    refute "suppression : service arrêté" 'systemctl is-active lotor-server'
    refute "suppression : site retiré" '[ -e /etc/nginx/sites-available/lotor.conf ]'
    check "suppression : secrets conservés" "[ -e $ENV ]"
    check "suppression : nginx reste valide" 'nginx -t'

    x "DEBIAN_FRONTEND=noninteractive dpkg -i /root/lotor-server.deb >/root/reinstall.log 2>&1"
    [ "$(x "sha256sum $ENV /etc/lotor/config.yaml")" = "$sum" ] && ok "réinstallation : secrets intacts" || fail "réinstallation : secrets intacts"
    check "réinstallation : site remis en place" '[ -e /etc/nginx/sites-enabled/lotor.conf ] && nginx -t'
    refute "réinstallation : service non démarré" 'systemctl is-active lotor-server'
    check "réinstallation : message" "grep -q 'existing configuration kept' /root/reinstall.log"
    refute "réinstallation : aucun nouveau mot de passe" "grep -q 'temporary password' /root/reinstall.log"

    x "systemctl enable --now lotor-server >/dev/null 2>&1"
    wait_active
    check "réinstallation : le serveur repart sur la même base" 'systemctl is-active lotor-server'

    x "DEBIAN_FRONTEND=noninteractive apt-get purge -y lotor-server >/root/purge.log 2>&1"
    check "purge : secrets conservés" "[ -e $ENV ]"
    check "purge : message" "grep -q 'are kept' /root/purge.log"
    refute "purge : configuration retirée" '[ -e /etc/lotor/config.yaml ] || [ -e /etc/lotor/tls ]'
    check "purge : base conservée" "cd / && runuser -u postgres -- psql -At -p \$(pg_lsclusters -h | awk '{print \$3}' | tail -n 1) -c \"SELECT 1 FROM pg_database WHERE datname='lotor'\" | grep -q 1"
    refute "purge : questions debconf effacées" "grep -q 'lotor-server/' /var/cache/debconf/config.dat"
}

# Avec un terminal : le mot de passe s'affiche, en français, et aucun fichier ne le garde. Le
# contenu de term.log est constaté et consigné.
interactive() { # interface debconf, TERM
    apt_quiet "postgresql nginx"
    x 'pg_lsclusters -h | awk "{print \$1, \$2}" | while read v c; do pg_ctlcluster $v $c start 2>/dev/null || true; done'
    # Réponses déjà données : seule la note du mot de passe s'affiche (teletype exige une
    # saisie, sans valeur par défaut).
    preseed "database select local" "admin_email string $EMAIL" "server_name string $HOST" \
        "web_server select nginx" "tls_mode select selfsigned"
    x "LANG=fr_FR.UTF-8 LANGUAGE=fr LC_ALL=fr_FR.UTF-8 TERM=$2 DEBIAN_FRONTEND=$1 python3 /root/run_tty.py /root/tty.log apt-get install -y /root/lotor-server.deb >/dev/null 2>&1" || fail "$1 : apt-get a échoué"
    wait_active
    check "$1 : installation terminée" "dpkg-query -W -f '\${Status}' lotor-server | grep -q 'install ok installed'"
    check "$1 : service actif" 'systemctl is-active lotor-server'
    check "$1 : écran en français" "grep -aq 'temporaire' /root/tty.log"
    refute "$1 : aucun fichier de mot de passe" "[ -e $PWFILE ]"
    refute "$1 : variables BOOTSTRAP retirées" "grep -q BOOTSTRAP $ENV"
    local password
    password=$(x "grep -aoE '[^0-9a-f][0-9a-f]{24}([^0-9a-f]|\$)' /root/tty.log | grep -aoE '[0-9a-f]{24}' | head -n 1" || true)
    [ -n "$password" ] || { fail "$1 : mot de passe lu à l'écran"; return 0; }
    ok "$1 : mot de passe lu à l'écran"
    refute "$1 : absent de debconf" "grep -rlF '$password' /var/cache/debconf"
    refute "$1 : absent du journal systemd" "journalctl -u lotor-server --no-pager | grep -qF '$password'"
    refute "$1 : absent de /etc/lotor" "grep -rlF '$password' /etc/lotor"
    if x "grep -aqF '$password' /var/log/apt/term.log"; then
        ok "$1 : constat : présent dans /var/log/apt/term.log ($(x 'stat -c "%U:%G %a" /var/log/apt/term.log'))"
    else
        ok "$1 : constat : absent de /var/log/apt/term.log"
    fi
    check "$1 : le mot de passe affiché permet de se connecter" "python3 /root/login.py https://$HOST $EMAIL '$password'"
}

scenario_interactive() { interactive dialog xterm; }

scenario_teletype() { interactive teletype dumb; }

# Vraies réponses aux questions, dont un e-mail refusé puis corrigé (teletype n'attend pas de
# validation sur la note de refus).
scenario_questions() {
    apt_quiet "postgresql nginx"
    x 'pg_lsclusters -h | awk "{print \$1, \$2}" | while read v c; do pg_ctlcluster $v $c start 2>/dev/null || true; done'
    x "TTY_ANSWERS='1|pas-une-adresse|$EMAIL|$HOST|1|1' TERM=dumb DEBIAN_FRONTEND=teletype python3 /root/run_tty.py /root/tty.log apt-get install -y /root/lotor-server.deb >/dev/null 2>&1" || fail "apt-get a échoué"
    wait_active
    check "e-mail invalide refusé" "grep -aq 'Invalid value' /root/tty.log"
    check "question reposée après le refus" "[ \"\$(grep -ac 'Email address of the first administrator' /root/tty.log)\" -ge 2 ]"
    check "service actif" 'systemctl is-active lotor-server'
    check "site nginx au nom saisi" "grep -q 'server_name $HOST' /etc/nginx/sites-available/lotor.conf"
    local password
    password=$(x "grep -aoE '[^0-9a-f][0-9a-f]{24}([^0-9a-f]|\$)' /root/tty.log | grep -aoE '[0-9a-f]{24}' | head -n 1" || true)
    [ -n "$password" ] || { fail "mot de passe lu à l'écran"; return 0; }
    check "connexion avec l'e-mail corrigé" "python3 /root/login.py https://$HOST $EMAIL '$password'"
}

# Agent dépôt : installé sans être activé, configuration lue par le compte dynamique de
# l'unité, mise à jour qui garde la configuration modifiée, désinstallation qui désactive.
scenario_repo_agent() {
    x "DEBIAN_FRONTEND=noninteractive apt-get install -y /root/lotor-repo-agent.deb >/root/install.log 2>&1"
    check "installation réussie" "dpkg-query -W -f '\${Status}' lotor-repo-agent | grep -q 'install ok installed'"
    check "git installé par dépendance" 'git --version'
    check "unité valide" 'systemd-analyze verify lotor-repo-agent.service'
    refute "unité non activée" 'systemctl is-enabled lotor-repo-agent'
    refute "unité non démarrée" 'systemctl is-active lotor-repo-agent'
    check "configuration en 0644 dans un répertoire en 0755" \
        '[ "$(stat -c %a /etc/lotor-repo-agent)" = 755 ] && [ "$(stat -c %a /etc/lotor-repo-agent/config.yaml)" = 644 ]'
    # Sans aucun credential (remise à zéro par un fichier d'extension), l'agent s'arrête sur
    # le premier secret : la configuration a donc été lue sous le compte dynamique.
    x 'mkdir -p /etc/systemd/system/lotor-repo-agent.service.d && printf "[Service]\nLoadCredentialEncrypted=\n" > /etc/systemd/system/lotor-repo-agent.service.d/credentials.conf && systemctl daemon-reload'
    x 'systemctl start lotor-repo-agent' || true
    check "configuration lue sous le compte dynamique" \
        'for i in 1 2 3 4 5 6 7 8 9 10; do journalctl -u lotor-repo-agent -o cat | grep -q "CREDENTIALS_DIRECTORY absent" && exit 0; sleep 1; done; exit 1'
    x 'echo "# modification locale" >> /etc/lotor-repo-agent/config.yaml'
    x "DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall /root/lotor-repo-agent.deb >>/root/install.log 2>&1"
    check "mise à jour : configuration modifiée gardée" 'tail -n 1 /etc/lotor-repo-agent/config.yaml | grep -q "modification locale"'
    x 'systemctl enable lotor-repo-agent >/dev/null 2>&1'
    x 'DEBIAN_FRONTEND=noninteractive apt-get remove -y lotor-repo-agent >>/root/install.log 2>&1'
    refute "désinstallation : unité désactivée" 'systemctl is-enabled lotor-repo-agent'
    check "désinstallation : configuration gardée" 'test -f /etc/lotor-repo-agent/config.yaml'
    x 'DEBIAN_FRONTEND=noninteractive apt-get purge -y lotor-repo-agent >>/root/install.log 2>&1'
    refute "purge : configuration supprimée" 'test -f /etc/lotor-repo-agent/config.yaml'
}

# Le cluster d'une version trop ancienne n'est pas utilisé.
scenario_old_pg() {
    apt_quiet postgresql
    x 'pg_lsclusters -h | awk "{print \$1, \$2}" | while read v c; do pg_ctlcluster $v $c start 2>/dev/null || true; done'
    preseed "admin_email string $EMAIL" "server_name string $HOST" "web_server select none"
    install_package
    check "installation réussie" "dpkg-query -W -f '\${Status}' lotor-server | grep -q 'install ok installed'"
    check "message explicite" "grep -q 'lotor requires 16 or later' /root/install.log"
    refute "service non démarré" 'systemctl is-active lotor-server'
    refute "aucun rôle créé" "cd / && runuser -u postgres -- psql -At -c \"SELECT 1 FROM pg_roles WHERE rolname LIKE 'lotor%'\" | grep -q 1"
}

for distro in $DISTROS; do
    echo "=== $distro"
    img=$(image "$distro")
    for scenario in $SCENARIOS; do
        echo "--- $scenario"
        start "$img"
        "scenario_$scenario" || fail "$scenario : arrêt anticipé"
        if [ "${PACKAGE_KEEP:-}" = "$scenario" ]; then
            echo "conteneur conservé : $C"
            trap - EXIT
            exit "$failures"
        fi
    done
done

# Debian 12 ne fournit que PostgreSQL 15 : refus attendu.
if [ -z "${*:-}" ] && [ -z "${PACKAGE_DISTROS:-}" ]; then
    echo "=== debian:12"
    img=$(image debian:12)
    echo "--- old_pg"
    start "$img"
    scenario_old_pg || fail "old_pg : arrêt anticipé"
fi

echo
if [ "$failures" -gt 0 ]; then
    echo "$failures échec(s)" >&2
    exit 1
fi
echo "recette du paquet réussie"
