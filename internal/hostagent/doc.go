// Package hostagent porte le pipeline de l'agent serveur (lotor-host-agent) : inventaire
// de l'hôte avec Syft et envoi conditionnel au serveur.
//
// Un cycle (Agent.Cycle) :
//
//  1. inscription au premier démarrage : le jeton d'inscription (fichier en 0600 ou
//     credential systemd « enrollment-token ») est échangé contre un jeton d'agent,
//     gardé dans le répertoire d'état (Store, 0700, fichiers en 0600) ;
//  2. lecture du projet d'hôte confié à l'agent (listAgentProjects) ;
//  3. scan de la racine (SyftScanner) : un parcours construit un index compact de
//     l'arborescence (fsIndex : chemin, type et bit d'exécution, sans ouvrir de fichier),
//     que Syft interroge par indexSource et indexResolver au lieu de sa source
//     « répertoire » (ADR 0055) ; catalogueurs d'un système installé, sans catalogage de
//     fichiers, exclusions par défaut (DefaultExclusions : systèmes de fichiers virtuels,
//     stockages de conteneurs, répertoires de données), montages réseau, de conteneurs et
//     virtuels (lus dans /proc/self/mountinfo) et exclusions configurées ;
//  4. empreinte d'inventaire du SBOM produit, calculée par le même adaptateur et la même
//     fonction que le serveur (sbom/syft.Decode puis sbom.Fingerprint) ;
//  5. empreinte identique à celle du dernier envoi rangé : signal de vie avec compte rendu
//     d'inventaire (le serveur avance la date de dernière analyse, ou réclame le SBOM s'il
//     ne connaît pas cet inventaire) ; sinon envoi du SBOM (Syft JSON, gzip) puis attente
//     de son rangement. L'empreinte n'est retenue qu'une fois le SBOM rangé ;
//  6. si l'inventaire des conteneurs est activé (containers.enabled, désactivé par défaut :
//     sans lui, aucune socket n'est ouverte), découverte des conteneurs en cours par
//     l'API Docker de Docker ou Podman sur socket Unix (SocketEngine), regroupement par
//     identité (Identity : « projet/service » Compose, sinon nom du conteneur ;
//     Workloads), signalement au serveur, qui crée les projets enfants sous l'hôte de
//     l'agent et confirme les inventaires d'images connus (State.Images), puis, pour
//     chaque conteneur à inventorier, export de son image (docker save), scan par Syft
//     depuis l'archive, hors ligne, une fois par image (SyftImageScanner), et envoi de
//     son SBOM sur la référence de son projet enfant (ADR 0041). Un échec sur un
//     conteneur est compté sans faire échouer le cycle.
//
// Agent.Run (mode daemon) fait un cycle à l'échéance de scan.interval et envoie un signal
// de vie toutes les scan.poll_interval ; une demande de scan faite dans l'interface
// (scan_requested) déclenche un cycle aussitôt. Agent.RunOnce (mode oneshot) fait un seul
// cycle, pour un timer systemd.
//
// Rien d'autre ne sort de l'hôte que les SBOM et leur contexte (os-release, noyau,
// architecture, nom d'hôte, durée du scan ; pour un conteneur, moteur, noms, image et
// son empreinte, étiquettes Compose, démarrage). Le paquet ne dépend d'aucun paquet serveur.
package hostagent
