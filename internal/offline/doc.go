// Package offline écrit et lit les archives d'envoi hors ligne (T23, ADR 0059) : un agent
// d'un réseau isolé écrit son SBOM et son contexte dans un fichier transporté à la main
// jusqu'au serveur, qui l'importe comme un envoi ordinaire.
//
// Une archive est un tar de trois entrées, dans cet ordre : manifest.json (format,
// identifiant public du jeton d'agent émetteur, inscription hors ligne éventuelle,
// contexte, empreinte et taille du SBOM), mac.json (HMAC-SHA256 du manifeste, de clé
// l'empreinte SHA-256 du secret du jeton : le serveur la garde déjà, l'archive ne la
// révèle pas) et sbom.json.gz. Read borne chaque entrée et vérifie l'empreinte du SBOM ;
// l'authenticité se vérifie côté serveur (Verify). L'empreinte d'une archive (Digest,
// SHA-256 du manifeste signé) la dédoublonne à l'import. Sans dépendance : le paquet sert
// aux agents comme au serveur.
package offline
