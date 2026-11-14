# Plan de convergence Obsidia / X-108

## Architecture cible

```text
Utilisateur
  |
Obsidia CLI existante (entrée unique)
  |-- capacités / tâches supervisées
  |-- Sigma : avis et vérifications non souverains
  |-- Obsidure : proposition et construction supervisées
  |-- modèles locaux : exécution bornée
  |
KX108 : autorité finale, PRE → décision → action bornée → POST → preuve/replay
```

Aucun composant périphérique ne peut accorder une autorisation finale.

## G1 + G2 — Premier vrai build (P0)

Créer une zone de travail isolée, adossée à des instantanés traçables des sources, **sans toucher aux worktrees existants**.

1. Prendre le Decision Store K1 sécurisé comme référence contractuelle ; conserver HMAC, revalidation PRE et refus des votes absents.
2. Examiner les signatures et appelants des pilotes, adaptateurs PRE et cycles gouvernés ; définir une interface commune explicite.
3. Ajouter `WORLD_ACTION_PRE_EXECUTION` comme extension gouvernée ; aucun écrasement du Decision Store entier.
4. Réconcilier les représentations CREATE en conservant la protection des chemins, l'absence initiale de cible et les verrous anti-TOCTOU.
5. Fermer la chaîne de décision avant écriture : aucune création, modification, suppression ou écriture de scellement avant autorisation valide.
6. Exécuter les tests négatifs, les tests de replay, de concurrence et d'interruption ; documenter le verdict.

**Sortie attendue :** un contrat KX108 PRE unique, des consommateurs compatibles, CREATE/WRITE_CLOSURE pilotés par KX108 et des preuves testées.

## Ordre après le socle

- **G3 Sigma :** conserver avis consultatifs, zéro vote/HOLD, champs inconnus et ancrages d'état, sans autorité décisionnelle.
- **G4 Obsidure :** relier F7 / R10 / R12 ; interdire l'APPLY direct hors circuit gouverné.
- **G5 CLI :** garder l'entrée Obsidia existante, raccorder les services ; distinguer erreurs HTTP 401 et indisponibilité réelle.
- **G6 Ragnarok :** ne moderniser qu'après stabilisation ; authentification, requêtes isolées, retrait de toute écriture automatique non gouvernée.

## Invariants de méthode

- Aucun `git reset --hard`, nettoyage, changement de branche ou redémarrage sur les chantiers actifs.
- Ne jamais considérer un SHA valide ou une analyse syntaxique comme une preuve de compatibilité fonctionnelle.
- Toute ambiguïté dans le contrat, les preuves ou la provenance entraîne HOLD / FAIL-CLOSED.
- Les imports dans ce dépôt public sont volontaires et contrôlés ; pas de publication brute des dépôts privés.
