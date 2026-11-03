#!/bin/sh
# Après purge de lotor-server : la configuration publique et le certificat autosigné
# partent. Écart volontaire aux usages Debian (ADR 0053) : la base et le fichier des secrets
# restent, car perdre la clé de chiffrement rendrait les secrets TOTP inutilisables.
set -e

[ "$1" = purge ] || exit 0

ETC=/etc/lotor
rm -f "$ETC/config.yaml" "$ETC/initial-admin-password"
rm -rf "$ETC/tls"

if [ -f /usr/share/debconf/confmodule ]; then
    . /usr/share/debconf/confmodule
    db_version 2.0
    db_subst lotor-server/msg_purge FILE "$ETC/lotor-server.env"
    db_metaget lotor-server/msg_purge description
    printf '%s\n' "$RET" >&2
    db_purge
    db_stop
fi
exit 0
