#!/bin/sh
# Avant désinstallation de lotor-repo-agent : arrêt et désactivation de l'unité, mais pas
# lors d'une mise à jour (deb : « upgrade »). La configuration et les credentials de
# /etc/lotor-repo-agent sont conservés jusqu'à la purge du paquet (dpkg ne supprime que
# config.yaml : les *.cred sont à effacer à la main).
set -e

case "$1" in
    remove) ;;
    *) exit 0 ;;
esac

if [ -d /run/systemd/system ]; then
    systemctl disable --now lotor-repo-agent.service >/dev/null 2>&1 || true
fi
