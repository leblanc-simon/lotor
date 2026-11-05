#!/bin/sh
# Après installation de lotor-repo-agent : rechargement de systemd. L'unité n'est ni
# activée ni démarrée : il faut d'abord renseigner le serveur et les forges, et chiffrer
# les secrets. Aucun utilisateur à créer : l'unité tourne sous un compte dynamique.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # Mise à jour : un agent déjà actif repart sur le nouveau binaire.
    systemctl try-restart lotor-repo-agent.service || true
fi
