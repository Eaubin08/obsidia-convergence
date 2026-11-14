# Sources nécessaires à la convergence

État : **inventaire préparatoire — sources locales non importées dans ce dépôt**.

Base documentaire : rapport inter-PC communiqué le 14 novembre 2026, annonçant 61 variantes PC1, 32 variantes PC2, 93 variantes, 90 SHA256 binaires uniques, 66 après normalisation EOL et 22 chemins de composants. Ces chiffres sont issus du rapport fourni ; les archives/manifestes complets ne sont pas encore publiés ici.

## Priorité immédiate : G1 + G2

| Origine logique | À récupérer | Contrat à préserver | Statut |
|---|---|---|---|
| PC1 — chantier K1 Guard | `obsidia_kx108_decision_store.py` et tests K1 | HMAC, PRE canonique relu et vérifié, zéro vote → HOLD | À importer après revue |
| PC1 — pilote gouverné | `obsidia_governed_execution_driver_v0.py` et tests | Signature PRE réellement utilisée, preuve et décision | À importer après revue |
| PC1 — CREATE | adaptateurs CREATE, vérification de cible absente et des chemins | `CREATE_TARGET_FROM_SOURCE` sans contournement | À identifier dans le manifeste |
| PC2 — 4A1 Write Closure | `obsidia_kx108_pre_execution_evidence_adapter_v0.py` et tests | Prévention de toute écriture avant décision | À importer après revue |
| PC2 — CREATE / V01 C1 | `obsidia_governed_runtime_cycle_v1.py`, extension du Decision Store et tests | `WORLD_ACTION_PRE_EXECUTION`, raccordement PRE | À importer après revue |
| PC2 — Merkle / 4A1 | tests et fonctions de preuve/scellement | Pas de réécriture automatique du scellement | À identifier dans le manifeste |

**Règle P0 :** jamais de remplacement intégral du Decision Store K1 par la variante PC2. Faire évoluer les contrats et vérifier explicitement chaque appelant.

## Étapes ultérieures

| Ordre | Famille | Sources indispensables |
|---|---|---|
| G3 | Sigma | contrats, sorties consultatives, champs inconnus, ancrages d'état, tests zéro vote/HOLD |
| G4 | Obsidure | modes supervisés F7 R10/R12, chemins APPLY interdits, tests |
| G5 | CLI Obsidia | entrée CLI active, `evaluate/task`, mémoire native, adaptations API/auth 401, tests |
| G6 | Ragnarok | serveur / route / contrôle d'accès / isolation requêtes / tests sans écriture de scellement |

## Provenance exigée pour chaque import

- Origine PC1 ou PC2, dépôt et branche source.
- Commit HEAD, état Git (`git status`) et indication des modifications non commitées.
- Chemin relatif exact, SHA256 du fichier brut et (si pertinent) SHA après normalisation des fins de ligne.
- Version du contrat PRE, appelants affectés et liste des tests associés.
- Rapport de sélection des fichiers autorisés à la publication.

La liste **exhaustive des 22 chemins** doit être chargée depuis la matrice d'origine : elle n'est pas présente dans le texte actuellement fourni et ne doit pas être inventée.

## Exclusions publiques

Ne jamais importer les bundles Git complets, historiques privés bruts, clés HMAC, fichiers d'environnement, identifiants, journaux sensibles, dumps, preuves contenant des données privées ou dépendances lourdes. Le fait qu'un fichier soit techniquement copiable n'autorise pas sa publication.
