# Échanges avec Dependency-Track

Requêtes et réponses rejouées par les tests du point compatible et du client des agents
(T19, [ADR 0058](../../docs/adr/0058-point-compatible-dependency-track.md)).

| Fichier | Origine |
| --- | --- |
| `gh-upload-sbom.http` | Requête de l'action GitHub `DependencyTrack/gh-upload-sbom` (branche `master`, `dist/index.js` relu le 4 novembre 2026) : `FormData` d'undici, SBOM en premier (`filename="bom"`, `application/octet-stream`), puis `projectName`, `projectVersion`, `autoCreate`, `projectTags` ; en-tête `X-API-Key`. Reconstituée d'après le code du client (format du multipart d'undici compris), le SBOM étant `testdata/sbom/portail-client.cdx16.json`, puis envoyée telle quelle à un Dependency-Track 5.2.1, qui l'a acceptée (`200`). `$API_KEY` est remplacé par le test. Fins de ligne CRLF (`.gitattributes`). |
| `dt5-upload-response.json` | Réponse d'un `PUT /api/v1/bom` d'un Dependency-Track 5.2.1. |
| `dt5-token-running.json`, `dt5-token-completed.json` | Réponses de `GET /api/v1/event/token/{uuid}` du même serveur, pendant puis après le traitement. |
| `dt4-token-done.json` | Forme de la même réponse en 4.x (sans `status`). |

L'action ne garde aucun chemin de l'adresse du serveur : le test préfixe `/dt` comme le
ferait le mandataire inverse décrit dans `docs/dependency-track.md`.
