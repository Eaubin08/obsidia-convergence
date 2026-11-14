# Obsidia Convergence

Espace public de suivi et d'intégration contrôlée des chantiers Obsidia / X-108.

## Objectif

Converger progressivement les contrats de gouvernance KX108 (autorité finale), CREATE / GLOBAL WRITE CLOSURE, Sigma (consultatif), Obsidure (agent de build supervisé) et l'entrée CLI Obsidia, sans réécrire ni écraser les moteurs existants.

## Frontières

- Ne pas importer automatiquement les worktrees en cours ni modifier les dépôts sources.
- Ne pas publier de secrets, fichiers `.env`, tokens, clés, identifiants, dumps ou preuves sensibles.
- Toute intégration doit être explicite, testée et auditable ; HOLD / FAIL-CLOSED en cas d'incertitude.
- KX108 conserve l'autorité finale ; les agents périphériques ne deviennent pas souverains.

## État

Dépôt public initialisé. **Aucun code des chantiers locaux n'est encore importé.** Les exports locaux et bundles Git restent distincts de cette publication.
