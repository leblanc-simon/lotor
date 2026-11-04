#!/bin/sh
# Après installation de lotor-server : parcours d'installation de docs/operations.md, sans
# jamais faire échouer dpkg pour une cause que l'administrateur peut corriger ensuite
# (dpkg-reconfigure lotor-server). Le serveur n'est démarré que lorsque ce passage vient
# de le configurer : sur une mise à jour, un démarrage appliquerait des migrations
# irréversibles avant toute sauvegarde.
set -e

[ "$1" = configure ] || exit 0

. /usr/share/debconf/confmodule
db_version 2.0

PREVIOUS_VERSION=${2:-}
ETC=/etc/lotor
ENV_FILE=$ETC/lotor-server.env
CONFIG_FILE=$ETC/config.yaml
PASSWORD_FILE=$ETC/initial-admin-password
TLS_DIR=$ETC/tls
SHARE=/usr/share/lotor-server
PG_MIN=16
BOOTSTRAP_WAIT=60

say() { # message, puis paires VARIABLE valeur : la langue vient de debconf
    message=$1
    shift
    while [ "$#" -ge 2 ]; do
        db_subst "lotor-server/msg_$message" "$1" "$2"
        shift 2
    done
    db_metaget "lotor-server/msg_$message" description
    printf '%s\n' "$RET" >&2
}

get() { db_get "lotor-server/$1"; printf '%s' "$RET"; }

configured() { [ -r "$ENV_FILE" ] && grep -q '^LOTOR_DB_DSN=' "$ENV_FILE"; }

systemd_running() { [ -d /run/systemd/system ]; }

# Configuration publique et fichier des secrets, créés une seule fois.
write_config() {
    [ -e "$CONFIG_FILE" ] && return 0
    case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
    fr*) language=fr ;;
    *) language=en ;;
    esac
    tmp=$(mktemp "$CONFIG_FILE.XXXXXX")
    sed -e "s|@SERVER_NAME@|$(get server_name)|g" -e "s|@LANGUAGE@|$language|g" \
        "$SHARE/config.yaml.in" >"$tmp"
    chmod 0644 "$tmp"
    mv "$tmp" "$CONFIG_FILE"
}

write_secrets() {
    [ -e "$ENV_FILE" ] && return 0
    key_id=$(date +%Y-%m)
    tmp=$(mktemp "$ENV_FILE.XXXXXX")
    {
        printf '# Secrets de lotor-server, lus par systemd (root, 0600). À sauvegarder.\n'
        printf 'LOTOR_SECRETS_KEYS=%s:%s\n' "$key_id" "$(openssl rand -base64 32)"
        printf 'LOTOR_SECRETS_ACTIVE_KEY=%s\n' "$key_id"
    } >"$tmp"
    chmod 0600 "$tmp"
    mv "$tmp" "$ENV_FILE"
    say backup_key FILE "$ENV_FILE"
}

# Ajoute des lignes au fichier des secrets, par remplacement atomique.
append_secrets() {
    tmp=$(mktemp "$ENV_FILE.XXXXXX")
    chmod 0600 "$tmp"
    cat "$ENV_FILE" >"$tmp"
    printf '%s\n' "$@" >>"$tmp"
    mv "$tmp" "$ENV_FILE"
}

remove_bootstrap() {
    tmp=$(mktemp "$ENV_FILE.XXXXXX")
    chmod 0600 "$tmp"
    grep -v '^LOTOR_BOOTSTRAP_ADMIN_' "$ENV_FILE" >"$tmp" || true
    mv "$tmp" "$ENV_FILE"
}

# Le SQL passe par l'entrée standard de psql, jamais par des arguments visibles dans ps ;
# le répertoire courant peut être interdit à postgres.

# Choisit le cluster en marche de plus haute version : « version port ».
local_cluster() {
    command -v pg_lsclusters >/dev/null 2>&1 || return 0
    pg_lsclusters -h 2>/dev/null | awk '$4 == "online" { print $1, $3 }' | sort -n | tail -n 1
}

setup_local_database() {
    cluster=$(local_cluster)
    if [ -z "$cluster" ]; then
        say pg_missing
        return 1
    fi
    version=${cluster%% *}
    port=${cluster##* }
    if [ "${version%%.*}" -lt "$PG_MIN" ]; then
        say pg_too_old VERSION "$version"
        return 1
    fi
    existing=$(printf '%s\n' \
        "SELECT 1 FROM pg_roles WHERE rolname IN ('lotor_owner', 'lotor_app') UNION ALL SELECT 1 FROM pg_database WHERE datname = 'lotor';" |
        (cd / && runuser -u postgres -- psql -X -q -At -p "$port" -d postgres) 2>/dev/null) || {
        say pg_failed
        return 1
    }
    if [ -n "$existing" ]; then
        say pg_exists
        return 1
    fi
    owner_password=$(openssl rand -hex 24)
    app_password=$(openssl rand -hex 24)
    if ! printf '%s\n' \
        "CREATE ROLE lotor_owner LOGIN BYPASSRLS PASSWORD '$owner_password';" \
        "CREATE ROLE lotor_app LOGIN PASSWORD '$app_password' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;" \
        "CREATE DATABASE lotor OWNER lotor_owner;" \
        "REVOKE ALL ON DATABASE lotor FROM PUBLIC;" \
        "GRANT CONNECT ON DATABASE lotor TO lotor_app;" |
        (cd / && runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 -p "$port" -d postgres) >/dev/null 2>&1; then
        # Rien n'existait avant cet essai : ce qui existe maintenant vient de lui.
        printf '%s\n' "DROP DATABASE IF EXISTS lotor;" "DROP ROLE IF EXISTS lotor_app;" "DROP ROLE IF EXISTS lotor_owner;" |
            (cd / && runuser -u postgres -- psql -X -q -p "$port" -d postgres) >/dev/null 2>&1 || true
        say pg_failed
        return 1
    fi
    append_secrets \
        "LOTOR_DB_DSN=postgres://lotor_app:$app_password@127.0.0.1:$port/lotor?sslmode=disable" \
        "LOTOR_MIGRATION_DSN=postgres://lotor_owner:$owner_password@127.0.0.1:$port/lotor?sslmode=disable"
}

setup_remote_database() {
    db_dsn=$(get db_dsn)
    migration_dsn=$(get migration_dsn)
    db_set lotor-server/db_dsn ""
    db_set lotor-server/migration_dsn ""
    if [ -z "$db_dsn" ] || [ -z "$migration_dsn" ]; then
        say dsn_missing
        return 1
    fi
    append_secrets "LOTOR_DB_DSN=$db_dsn" "LOTOR_MIGRATION_DSN=$migration_dsn"
}

# Attend que le serveur tranche le premier compte. Pas /readyz : il répond 503 tant que la
# base de vulnérabilités n'est pas téléchargée, ce qui bloquerait apt plusieurs minutes.
wait_bootstrap() { # depuis
    elapsed=0
    while [ "$elapsed" -lt "$BOOTSTRAP_WAIT" ]; do
        logs=$(journalctl -u lotor-server --since "@$1" -o cat --no-pager 2>/dev/null || true)
        case "$logs" in
        *"premier administrateur créé"*)
            echo created
            return 0
            ;;
        *"bootstrap ignoré"*)
            echo ignored
            return 0
            ;;
        esac
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo timeout
}

site_url() { printf 'https://%s/' "$(get server_name)"; }

# Une note n'est jamais affichée sans terminal (db_input renvoie alors 30) : le mot de passe
# passe par un fichier réservé à root. La variable debconf est vidée dans tous les cas.
show_password() { # e-mail, mot de passe
    db_fset lotor-server/admin_password seen false
    db_subst lotor-server/admin_password URL "$(site_url)"
    db_subst lotor-server/admin_password EMAIL "$1"
    db_subst lotor-server/admin_password PASSWORD "$2"
    rc=0
    db_input critical lotor-server/admin_password || rc=$?
    if [ "$rc" -eq 0 ]; then
        db_go || true
    else
        (umask 077 && printf '%s\n' "$2" >"$PASSWORD_FILE")
        say password_file EMAIL "$1" FILE "$PASSWORD_FILE" URL "$(site_url)"
    fi
    db_subst lotor-server/admin_password PASSWORD ""
    db_reset lotor-server/admin_password
}

# Premier démarrage : compte demandé, service lancé, variables retirées une fois tranché.
first_start() {
    email=$(get admin_email)
    password=""
    if [ -n "$email" ]; then
        password=$(openssl rand -hex 12)
        append_secrets "LOTOR_BOOTSTRAP_ADMIN_EMAIL=$email" "LOTOR_BOOTSTRAP_ADMIN_PASSWORD=$password"
    fi
    if ! systemd_running; then
        say no_systemd
        return 0
    fi
    since=$(date +%s)
    systemctl daemon-reload
    systemctl enable --now lotor-server.service >/dev/null 2>&1 || true
    if [ -z "$email" ]; then
        say no_admin
        say started
        return 0
    fi
    outcome=$(wait_bootstrap "$since")
    case "$outcome" in
    created)
        remove_bootstrap
        show_password "$email" "$password"
        say started
        ;;
    ignored)
        remove_bootstrap
        say started
        ;;
    *)
        say start_failed SECONDS "$BOOTSTRAP_WAIT" FILE "$ENV_FILE"
        ;;
    esac
}

remove_sites() {
    rm -f /etc/nginx/sites-enabled/lotor.conf /etc/nginx/sites-available/lotor.conf
    if [ -e /etc/apache2/sites-enabled/lotor.conf ] && command -v a2dissite >/dev/null 2>&1; then
        a2dissite -q lotor >/dev/null 2>&1 || true
    fi
    rm -f /etc/apache2/sites-enabled/lotor.conf /etc/apache2/sites-available/lotor.conf
}

site_exists() {
    [ -e /etc/nginx/sites-available/lotor.conf ] || [ -e /etc/apache2/sites-available/lotor.conf ]
}

# Certificat autosigné au nom public du site (celui de ssl-cert porterait le nom de la
# machine). Déjà présent pour ce nom : gardé.
selfsigned_certificate() { # nom
    crt=$TLS_DIR/$1.crt
    key=$TLS_DIR/$1.key
    if [ ! -s "$crt" ] || [ ! -s "$key" ]; then
        install -d -m 0755 "$TLS_DIR"
        (umask 077 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -days 825 -subj "/CN=$1" -addext "subjectAltName=DNS:$1" \
            -keyout "$key" -out "$crt" >/dev/null 2>&1)
        chmod 0644 "$crt"
    fi
    CERT=$crt
    KEY=$key
}

render_site() { # gabarit, destination, nom
    tmp=$(mktemp "$2.XXXXXX")
    sed -e "s|@SERVER_NAME@|$3|g" -e "s|@CERT@|$CERT|g" -e "s|@KEY@|$KEY|g" "$1" >"$tmp"
    chmod 0644 "$tmp"
    mv "$tmp" "$2"
}

reload_web() { # service, nom affiché
    systemd_running || return 0
    systemctl reload-or-restart "$1" >/dev/null 2>&1 || say web_reload_failed SERVER "$1"
}

setup_nginx() { # nom
    if ! command -v nginx >/dev/null 2>&1 || [ ! -d /etc/nginx/sites-available ]; then
        say web_missing SERVER nginx
        return 0
    fi
    render_site "$SHARE/nginx.conf.in" /etc/nginx/sites-available/lotor.conf "$1"
    ln -sf ../sites-available/lotor.conf /etc/nginx/sites-enabled/lotor.conf
    if ! nginx -t >/dev/null 2>&1; then
        rm -f /etc/nginx/sites-enabled/lotor.conf /etc/nginx/sites-available/lotor.conf
        say web_failed SERVER nginx
        return 0
    fi
    reload_web nginx
    say site_ready SERVER nginx NAME "$1"
}

setup_apache() { # nom
    if ! command -v a2ensite >/dev/null 2>&1 || [ ! -d /etc/apache2/sites-available ]; then
        say web_missing SERVER apache2
        return 0
    fi
    render_site "$SHARE/apache.conf.in" /etc/apache2/sites-available/lotor.conf "$1"
    a2enmod -q ssl proxy proxy_http headers alias >/dev/null 2>&1 || true
    a2ensite -q lotor >/dev/null 2>&1 || true
    if ! apache2ctl configtest >/dev/null 2>&1; then
        a2dissite -q lotor >/dev/null 2>&1 || true
        rm -f /etc/apache2/sites-available/lotor.conf
        say web_failed SERVER apache2
        return 0
    fi
    reload_web apache2
    say site_ready SERVER apache2 NAME "$1"
}

# Le site n'est écrit que s'il manque, ou à la demande de dpkg-reconfigure : une mise à jour
# ne touche pas aux réglages de l'administrateur.
setup_site() {
    choice=$(get web_server)
    if [ -z "${DEBCONF_RECONFIGURE:-}" ] && site_exists; then
        return 0
    fi
    if [ "$choice" = none ]; then
        [ -n "${DEBCONF_RECONFIGURE:-}" ] && remove_sites
        say no_web
        return 0
    fi
    name=$(get server_name)
    if [ "$(get tls_mode)" = existing ]; then
        CERT=$(get tls_cert)
        KEY=$(get tls_key)
    else
        CERT=""
    fi
    if [ -z "${CERT:-}" ]; then
        selfsigned_certificate "$name"
    fi
    [ -n "${DEBCONF_RECONFIGURE:-}" ] && remove_sites
    case "$choice" in
    nginx) setup_nginx "$name" ;;
    apache2) setup_apache "$name" ;;
    esac
}

public_url_update() {
    [ -n "${DEBCONF_RECONFIGURE:-}" ] || return 0
    [ -w "$CONFIG_FILE" ] || return 0
    sed -i "s|^  public_url: .*|  public_url: $(site_url)|" "$CONFIG_FILE"
}

install -d -m 0755 "$ETC"
write_config
public_url_update
write_secrets
setup_site

if systemd_running; then
    systemctl daemon-reload || true
fi

if configured; then
    # Mise à jour ou réinstallation : pas de démarrage sans sauvegarde.
    if [ -n "$PREVIOUS_VERSION" ] && [ -z "${DEBCONF_RECONFIGURE:-}" ]; then
        if systemd_running && systemctl is-active --quiet lotor-server.service; then
            say upgrade
        else
            say reinstall
        fi
    fi
else
    case "$(get database)" in
    local)
        if setup_local_database; then first_start; fi
        ;;
    remote)
        if setup_remote_database; then first_start; fi
        ;;
    manual)
        say manual FILE "$ENV_FILE"
        ;;
    esac
fi

db_stop
exit 0
