#!/bin/sh
# Avant désinstallation de lotor-server : arrêt du service et retrait du site web, mais pas
# lors d'une mise à jour. La configuration, les secrets et la base restent en place.
set -e

[ "$1" = remove ] || exit 0

if [ -d /run/systemd/system ]; then
    systemctl disable --now lotor-server.service >/dev/null 2>&1 || true
fi

if [ -e /etc/nginx/sites-available/lotor.conf ]; then
    rm -f /etc/nginx/sites-enabled/lotor.conf /etc/nginx/sites-available/lotor.conf
    if [ -d /run/systemd/system ]; then
        systemctl reload nginx >/dev/null 2>&1 || true
    fi
fi

if [ -e /etc/apache2/sites-available/lotor.conf ]; then
    if command -v a2dissite >/dev/null 2>&1; then
        a2dissite -q lotor >/dev/null 2>&1 || true
    fi
    rm -f /etc/apache2/sites-enabled/lotor.conf /etc/apache2/sites-available/lotor.conf
    if [ -d /run/systemd/system ]; then
        systemctl reload apache2 >/dev/null 2>&1 || true
    fi
fi
