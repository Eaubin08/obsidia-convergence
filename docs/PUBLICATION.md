# Politique d'import dans ce dépôt PUBLIC

Les dépôts Obsidia d'origine peuvent être privés. Ne pas les cloner et publier directement dans ce dépôt.

## Avant tout push de code

1. Sélectionner uniquement les fichiers et tests nécessaires au chantier.
2. Enregistrer la provenance (dépôt d'origine, branche, commit, SHA256 et état non commité).
3. Contrôler les secrets dans le **contenu et l'historique**, pas seulement dans les noms de fichiers.
4. Écarter les dumps et données confidentielles ; retirer/neutraliser les valeurs sensibles.
5. Vérifier que seuls les fichiers autorisés sont staged via `git diff --cached --name-status` et revue du diff.
6. Publier sur une branche d'import dédiée, non directement sur `main` ; ouvrir une revue avant fusion.

Un `.gitignore` n'est pas une protection suffisante contre une publication involontaire de secrets. Un commit public exposé puis supprimé peut rester accessible dans l'historique : vérifier **avant** le push.

Les archives USB/bundles Git servent à la sauvegarde et au transfert hors dépôt public.
