// Package agentclient est le client de l'API des agents (/api/v1/agent/*), partagé par
// lotor-host-agent et lotor-repo-agent. Il enveloppe le client généré depuis
// api/openapi.yaml (sous-paquet gen) et n'a rien de propre à une nature d'agent.
//
// Ce qu'il ajoute au client généré :
//
//   - transport : HTTPS, autorité de certification privée (Options.TLS.CAFile), certificat
//     client facultatif pour le mTLS (Options.TLS.ClientCertFile et ClientKeyFile),
//     mandataire explicite ou lu dans l'environnement (HTTPS_PROXY, NO_PROXY), délai par
//     tentative ;
//   - réessais bornés (Retry) : une erreur réseau, 429, 500, 502, 503 et 504 sont
//     réessayés au plus Retry.Attempts fois, avec un délai exponentiel à gigue
//     (Retry.Base, doublé à chaque tentative, plafonné à Retry.Max) ; un en-tête
//     Retry-After est respecté, et s'il dépasse Retry.Max l'appel abandonne aussitôt
//     plutôt que d'attendre au-delà de la politique ;
//   - erreurs : toute réponse hors 2xx devient une *Error qui porte le statut et la clé
//     stable du problème RFC 9457 (Error.Key, par exemple error.ingest.too_large), à
//     tester par IsKey ou HasStatus ;
//   - envoi d'un SBOM (Upload) : corps multipart construit une fois, partie context (JSON)
//     puis partie sbom compressée en gzip (application/gzip), rejoué à l'identique à
//     chaque tentative ; suivi de l'ingestion jusqu'à son état final (Wait) ;
//   - pagination des projets confiés parcourue en entier (Projects) ;
//   - client de Dependency-Track (DTClient, T19, ADR 0057) : PUT /api/v1/bom en JSON (SBOM
//     CycloneDX en base64, clé dans X-Api-Key), suivi par GET /api/v1/event/token/{uuid}
//     (ErrDTFailed sur un statut FAILED), mêmes transport, réessais et bornes.
//
// Le jeton (d'agent ou d'inscription) n'est jamais journalisé ; les journaux des réessais
// ne portent que l'opération, la tentative, le statut et le délai. Les réponses sont
// bornées en taille (maxResponse) avant décodage.
//
// Un envoi réessayé après une réponse perdue peut créer une seconde ingestion : sans effet
// pour une référence de dépôt (même commit et même SBOM : ingestion existante renvoyée) et,
// pour un hôte, une ingestion « inchangée » de plus, qui n'avance que la date de dernière
// analyse.
package agentclient
