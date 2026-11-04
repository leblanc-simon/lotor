# Politiques, notifications et statuts de commit

Ce guide décrit les canaux de notification de lotor, le format du webhook générique et sa
vérification, et la publication du verdict sur les commits. Les règles elles-mêmes sont
décrites dans [`utilisation.md`](utilisation.md#politiques-et-alertes) ; la configuration
de l'instance (SMTP, URL publique, garde réseau) dans
[`operations.md`](operations.md#politiques-et-notifications). Décisions : ADR
[0045](adr/0045-politiques-cel-et-verdicts.md), [0046](adr/0046-notifications.md) et
[0047](adr/0047-statut-de-commit.md).

## Canaux

Un canal appartient à une organisation ; ses administrateurs le créent dans
**Canaux** (`/o/<organisation>/channels`), puis le choisissent dans chaque politique.

| Nature | Ce qu'il faut saisir | Secret (chiffré, jamais réaffiché) |
| --- | --- | --- |
| E-mail | destinataires (20 au plus) | — (serveur SMTP de l'instance) |
| Webhook générique | URL qui reçoit un `POST` JSON | clé HMAC, 16 caractères au moins |
| Matrix | serveur (`https://matrix.example.org`) et identifiant interne du salon (`!abc:example.org`) | jeton d'accès d'un compte invité dans le salon |
| Mattermost | — | URL du webhook entrant |
| Slack | — | URL du webhook entrant |

- À la modification d'un canal, un secret laissé vide est gardé, **sauf** si le serveur
  Matrix ou l'URL du webhook générique change : le secret doit alors être ressaisi, pour
  qu'il ne parte jamais vers une destination choisie par quelqu'un qui ne le connaît pas
  (changement de destination journalisé).
- Le bouton **Envoyer un test** envoie tout de suite un message de test et affiche
  l'issue ; l'essai est journalisé (`channel.tested`).
- Les messages sont rédigés dans la **langue de l'organisation** (paramètres de
  l'organisation), avec un lien vers la page des violations si l'URL publique du serveur
  (`web.public_url`) est configurée.
- Un courriel porte une version texte et une version HTML (gabarit commun aux courriels de
  lotor, ADR 0056) : une carte par violation, étiquette de sévérité, marques KEV et
  « bloquante », bouton vers les violations. Le logo est joint au message (aucune image
  externe n'est chargée) ; le rendu a été vérifié dans Thunderbird, en clair et en sombre.
- Une politique en **envoi immédiat** fait partir ses nouvelles violations dès
  l'évaluation (regroupées, 100 au plus par message) ; en **résumé quotidien**, elles
  partent une fois par jour (`notify.digest_hour`, 7 h UTC par défaut).
- **Sans doublon** : une violation n'est envoyée qu'une fois par canal, tant qu'elle reste
  ouverte ; si elle est résolue puis réapparaît, c'est une nouvelle violation, de nouveau
  envoyée. Une violation résolue avant son envoi n'est pas envoyée. Deux envois simultanés du
  même canal ne partagent jamais une violation (chacun réserve son lot, ADR 0052) ; seul
  un message dont la réponse s'est perdue peut être renvoyé, avec le même
  `X-Lotor-Delivery`.
- **Canal en panne** : l'envoi est réessayé à délai croissant (10 s, 20 s, 40 s… jusqu'à
  30 min, 30 tentatives, soit une dizaine d'heures), puis relancé chaque jour. Les messages
  partent après le rétablissement. La dernière réussite, le dernier échec et sa cause sont
  affichés sur la liste des canaux.
- Un canal **inactif** garde ses envois en attente ; le réactiver les envoie.

## Webhook générique

### Requête

```
POST <URL du canal>
Content-Type: application/json
User-Agent: lotor-server/<version>
X-Lotor-Event: violations.opened | violations.digest | test
X-Lotor-Delivery: 0b7f5c4e-…            (identifiant du message)
X-Lotor-Timestamp: 1793520000            (secondes Unix)
X-Lotor-Signature: sha256=5d41402abc4b2a76b9719d911017c592…
```

```json
{
  "id": "0b7f5c4e-2f6c-5d8a-9a3e-4c1f0b2d7e11",
  "type": "violations.opened",
  "occurred_at": "2026-11-01T08:00:00Z",
  "organization": {"slug": "acme", "name": "Acme"},
  "url": "https://sbom.example.org/o/acme/violations",
  "summary": "lotor : nouvelles violations (Acme)",
  "violations": [
    {
      "id": "0192f3a0-0000-7000-8000-000000000001",
      "policy": {"name": "KEV en production", "blocking": true},
      "subject": "finding",
      "opened_at": "2026-11-01T07:59:58Z",
      "project": {"slug": "api", "name": "API"},
      "ref": "main",
      "vulnerability": {"id": "CVE-2021-44228", "severity": "critical", "kev": true},
      "component": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    },
    {
      "id": "0192f3a0-0000-7000-8000-000000000002",
      "policy": {"name": "Agent muet", "blocking": false},
      "subject": "agent",
      "opened_at": "2026-11-01T02:00:03Z",
      "agent": "srv-web-01"
    }
  ]
}
```

- `type` vaut `violations.opened` (envoi immédiat), `violations.digest` (résumé
  quotidien) ou `test` (bouton « Envoyer un test », `violations` vide).
- `url` est absent si l'URL publique du serveur n'est pas configurée.
- Une réponse **2xx** vaut acceptation ; tout autre statut, une redirection, une erreur
  réseau ou un délai dépassé (30 s par défaut) déclenche un réessai.
- Une tentative répétée après une réponse perdue garde le **même** `X-Lotor-Delivery` et
  le même corps, à un horodatage près : le destinataire peut écarter le doublon.

### Vérifier la signature

`X-Lotor-Signature` vaut `sha256=` suivi de l'hexadécimal de
`HMAC-SHA256(clé, horodatage + "." + corps)`, où `horodatage` est la valeur exacte de
`X-Lotor-Timestamp` et `corps` les octets reçus. Le destinataire :

1. recalcule la signature et la compare **en temps constant** ;
2. refuse un horodatage trop éloigné de son horloge (5 minutes conseillées), ce qui rend
   un message rejoué inutilisable ;
3. peut ignorer un `X-Lotor-Delivery` déjà traité.

En Python :

```python
import hashlib, hmac, time

def verify(secret: bytes, headers, body: bytes) -> bool:
    ts = headers["X-Lotor-Timestamp"]
    if abs(time.time() - int(ts)) > 300:
        return False
    expected = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + expected, headers["X-Lotor-Signature"])
```

En Go :

```go
mac := hmac.New(sha256.New, secret)
mac.Write([]byte(r.Header.Get("X-Lotor-Timestamp") + "."))
mac.Write(body)
ok := hmac.Equal([]byte("sha256="+hex.EncodeToString(mac.Sum(nil))), []byte(r.Header.Get("X-Lotor-Signature")))
```

## Slack, Mattermost et Matrix

- **Slack, Mattermost** : un webhook entrant (Slack : *Incoming Webhooks* d'une
  application ; Mattermost : *Intégrations › Webhooks entrants*). Son URL est le secret du
  canal. Message texte : titre, une ligne par violation (20 au plus, puis « … et N
  autres »), lien.
- **Matrix** : un compte dédié, invité dans le salon, et son jeton d'accès. Le message est
  un `m.notice` ; l'identifiant de transaction est celui du message, si bien qu'une
  tentative répétée n'est pas publiée deux fois.

## Statut de commit (agent dépôt)

Quand `status.enabled` vaut `true` dans la configuration de `lotor-repo-agent`, l'agent
publie le verdict des politiques sur chaque commit qu'il envoie :

1. il suit l'ingestion, puis interroge `GET /api/v1/agent/snapshots/{id}/verdict` ;
2. il publie un statut **en attente** dès que le serveur a un résumé, puis le verdict :
   **succès** (aucune violation d'une politique bloquante sur la référence), **échec**
   (au moins une ; la description nomme les politiques), ou **erreur** (SBOM refusé ;
   « canceled » sur GitLab) ;
3. passé `status.timeout` (15 min), le statut reste « en attente ».

Le statut s'appelle `status.context` (`lotor`) ; sa description est le résumé du serveur,
dans la langue de l'organisation ; son lien mène aux constats du projet (URL publique du
serveur requise). Droits à accorder sur la forge : voir
[`operations.md`](operations.md#statut-de-commit).
