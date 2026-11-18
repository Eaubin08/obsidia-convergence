# OBSIDIA CREATOR MODE V0
## MISSION : INTEGRATION NATIVE GOUVERNEE

OBJECTIF
Implémenter un Creator Mode natif dans la CLI Obsidia.
Ce n'est pas un nouveau moteur d'IA, de sécurité,
de gouvernance ou d'exécution.

Creator orchestre les composants existants.

REGLES ABSOLUES
- KX108 reste la seule autorité souveraine.
- Aucune IA locale invoquée avant admission gouvernée.
- Aucun agent ne peut s'auto-autoriser.
- Aucun ALLOW simulé ou codé en dur.
- Aucun contournement du système de tickets.
- Aucun accès en écriture hors du worktree.
- Aucune installation ou activation automatique.
- Aucun téléchargement de modèles ou dépendances.
- Aucune modification des invariants KX108.
- Aucune réparation opportuniste du chantier K1.
- Tout contrat manquant provoque HOLD.

PHASE 1 : INVENTAIRE REEL

Inspecter les fichiers suivants :

scripts/obsidia_cli.py
scripts/obsidia_governed_runtime_cycle_v1.py
scripts/obsidia_kx108_decision_store.py
periphery/world_calls/sovereign_ticket.py
sigma/tooling/governed_bounded_apply.py
sigma/guard.py
sigma/run_pipeline.py

Retrouver :
- Le dispatch CLI
- Les contrats de gouvernance PRE
- Les décisions souveraines vérifiées
- Les tickets et restrictions de périmètre
- Le pipeline TOOLING_BUILD
- Les protections WAL / finality / rollback
- Le registre de capacités existant
- Les routeurs de modèles et agents existants

Ne rien recréer si une brique existe déjà.

PHASE 2 : ENTREE CREATOR

Ajouter Creator dans le dispatch existant
de la CLI Obsidia.

Commandes cibles :
  creator plan
  creator build
  creator status
  creator inspect

Respecter la syntaxe et les conventions
de la CLI actuelle.

PHASE 3 : G0 - GOUVERNANCE AVANT IA

La demande utilisateur arrive d'abord dans
un précontrôle déterministe Obsidia.

Vérifier :
- Intention et périmètre déclarés
- Identité et autorisations applicables
- Capacité demandée
- Ressources nécessaires
- Limites et budget autorisés
- Contrat de décision PRE
- Ticket souverain lorsque requis

HOLD ou BLOCK :
  aucune invocation de modèle local.

Autorisation vérifiée :
  passage au routeur existant.

Si aucun contrat PRE exploitable n'existe :
  HOLD, sans faux adaptateur permissif.

PHASE 4 : CAPABILITY RESOLUTION

Rechercher la capacité dans les composants
et registres existants avant toute création.

Si elle existe :
  préparer sa réutilisation gouvernée.

Si elle manque :
  préparer une proposition de construction.

Ne pas confondre présence d'une capacité
et autorisation de l'exécuter.

PHASE 5 : INTELLIGENCE LOCALE

Réutiliser le routeur de modèles existant.
Connecter le provider Ollama local si compatible.

Point d'entrée Ollama :
  http://127.0.0.1:11434

Ne jamais supposer qu'un modèle est installé.
Inventorier réellement les modèles disponibles.

Les modèles locaux sont non souverains.
Ils produisent des propositions bornées.

PHASE 6 : CONSTRUCTION GOUVERNEE

Raccorder le pipeline TOOLING_BUILD existant.

Chaque écriture, exécution, installation,
suppression ou modification de permissions
doit passer par le contrôle adapté.

Réutiliser :
- apply_proposal_governed
- Les tickets vérifiés
- Les preuves PRE et POST
- Les barrières de persistance existantes
- Les mécanismes de rollback existants

Ne pas reconstruire ces mécanismes.

READY_FOR_COMMIT_REVIEW ne constitue pas
une autorisation d'installation.

PHASE 7 : GOUVERNANCE POST

Produire les éléments vérifiables :
- Intention originale
- Décision PRE et identité de décision
- Modèle et capacités réellement utilisés
- Opérations proposées et exécutées
- Fichiers modifiés et empreintes
- Résultats des tests
- Preuves POST
- Etat des tickets et finality
- Résultat d'intégration ou HOLD/BLOCK

Aucune capacité ne devient active sans
autorisation souveraine correspondante.

PHASE 8 : TESTS OBLIGATOIRES

Créer les tests Creator V0 couvrant :

1. PRE refuse -> aucun appel au modèle
2. PRE HOLD -> aucun effet de bord
3. PRE BLOCK -> aucune génération exécutée
4. Ticket invalide -> refus
5. Ticket expiré ou rejoué -> refus
6. Périmètre dépassé -> refus
7. Champs inconnus -> HOLD
8. Capacité existante -> résolution sans recréation
9. Modèle local indisponible -> HOLD
10. Proposition malformée -> HOLD
11. Echec d'écriture -> état sûr
12. Echec WAL/finality -> aucune fausse réussite
13. READY_FOR_COMMIT_REVIEW -> pas d'installation
14. Réutilisation des mécanismes K1 existants
15. Aucune modification du noyau souverain

Tester avec un faux provider local uniquement
dans les tests, jamais pour accorder l'autorité.

PHASE 9 : RAPPORT

Produire :
CREATOR_MODE_V0_IMPLEMENTATION_REPORT.md

Inclure :
- Inventaire de l'existant réutilisé
- Fichiers créés et modifiés
- Contrats réellement raccordés
- Tests exécutés avec résultats exacts
- Points HOLD / BLOCK
- Limites de l'intégration
- Opérations non réalisées
- Commandes pour reproduire les tests

INTERDIT
Aucun push, merge, activation de plugin,
déploiement, changement de gouvernance
ou installation automatique.

EXECUTION
Commencer par l'inventaire.
Implémenter uniquement les chemins réellement
raccordables et vérifiables.
Si l'intégration souveraine manque, livrer
l'inventaire et les blocages sans la simuler.
