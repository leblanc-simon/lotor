# 0054 — Page de présentation publique sur « / »

- Statut : Accepté
- Date : 2026-11-04
- Lot : hors lot (demande de l'utilisateur)

## Contexte

Jusqu'ici, « / » exigeait une session : un visiteur anonyme était renvoyé vers `/login`, sans
rien apprendre de ce qu'est l'outil. L'utilisateur veut une page de présentation (fonctions,
captures d'écran) servie par l'instance elle-même, sans site séparé ni GitHub Pages, avec un
lien vers la connexion.

## Décision

- **« / » public.** La route sort du groupe `requireAuth` : `identity.root` rend
  `landing/index` quand aucune session n'existe, et passe sinon par `requireAuth` vers
  l'accueil du compte (redirection vers son organisation). Une session de configuration va
  toujours à l'enrôlement du TOTP, un mot de passe temporaire au changement de mot de passe
  (`mustChangePassword`, global).
- **Page statique.** Elle ne lit rien en base ni dans la configuration : aucune information
  sur l'instance (organisations, comptes, volumes) n'est révélée. Seuls le numéro de version
  et le lien vers le code source figurent dans le pied de page, comme sur `/login`.
- **Conventions de l'interface.** Gabarit `html/template` dans la coque habituelle, textes
  dans `landing.*` (français et anglais), feuille `screens/landing.css` sur les tokens,
  aucun script. Les captures sont des fichiers `static/img/screenshots/*.webp` servis avec
  empreinte (type `image/webp` ajouté à `render`) ; elles sont aussi celles du README.
- **Liens externes** : guide de démarrage et mesures sur GitHub, dans la langue de la page.

## Conséquences

- Un visiteur anonyme voit la présentation au lieu d'être redirigé ; la connexion reste à
  `/login`, liée deux fois depuis la page. Les signets vers `/` continuent de fonctionner
  pour un compte connecté.
- Le binaire embarque environ 1,2 Mio de captures. Elles viennent d'une instance de
  démonstration et sont à refaire quand l'interface change notablement.
- Test : `TestLandingForAnonymousVisitors` (rendu dans les deux langues, accessibilité,
  absence de code en ligne, captures servies).
