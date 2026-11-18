# KX108 / K1 — ONE PASS COMPLETE CLOSURE

MISSION IMPERATIVE

Fermer techniquement en UNE SEULE EXECUTION tous les chemins
K1 restants qui peuvent etre verifies dans ce depot.

BASE DEMONTREE :
- 100/100 tests K1 PASS
- Test 100 : RECOVERING -> RECOVERED dans un nouveau Python
- WAL authentifie et lifecycle append-only
- PRE KX108 souverain
- Finality et Terminal avec flush
- Nettoyage WAL apres COMMITTED
- Nettoyage WAL apres RECOVERED
- Restauration os.replace suivie du flush cible
- Recuperation apres panne injectee
- FREEZE K1 actuellement HOLD

CECI EST UNE MISSION D'EXECUTION, PAS UN PLAN A REDIGER.

Ne pas terminer apres l'inventaire.
Ne pas terminer apres un premier test.
Ne pas repartir dans une succession de tickets unitaires.
Executer toute la sequence audit -> correction -> tests -> preuves
dans cette meme session.

============================================================
0. PERIMETRE ET INTERDICTIONS
============================================================

Depot courant :
C:\Users\User\.codex\visualizations\2026\11\kx108_zero_vote_guard_fix

Moteur principal :
sigma/tooling/governed_bounded_apply.py

Tests principaux :
tests/cli/test_k1_governed_singlewrite_v1.py

Examiner aussi les tests K1 / KX108 / PRE / WAL connexes.

AUTORITE :
KX108_ONLY.

INTERDICTIONS ABSOLUES :
- Ne jamais contourner KX108.
- Ne jamais produire de fausse preuve PRE.
- Ne jamais inventer une autorisation ou un ticket.
- Ne jamais assouplir la validation HMAC, nonce ou anti-rejeu.
- Ne jamais remplacer une erreur par un PASS artificiel.
- Ne jamais desactiver un test pour obtenir GREEN.
- Ne jamais supprimer ou modifier les preuves de gouvernance.
- Ne jamais lancer d'ACT sur un depot de production.
- Ne jamais modifier des fichiers hors du depot.
- Ne jamais arreter des serveurs ou processus existants.
- Ne jamais utiliser git reset --hard, git clean ou force push.
- Ne pas committer ni pousser.
- Ne pas relancer toute la stack Obsidia.
- Ne pas elargir le contrat autorise WRITE vers CREATE/DELETE.

Les tests physiques doivent utiliser des chemins pytest temporaires.
Conserver les modifications preexistantes, meme non commitees.

============================================================
1. INVENTAIRE EXHAUSTIF DU MOTEUR
============================================================

Lire le moteur reel et tous les tests K1 existants.

Construire la matrice de couverture des branches suivantes :

A. Autorisation PRE KX108
B. Ticket authentique / HMAC / nonce
C. Anti-rejeu et duree de validite
D. Frontieres de chemins, symlinks et junctions
E. Creation du WAL et fsync
F. PREPARED et flush des metadonnees
G. ACT physique et fsync
H. Rollback physique et metadonnees
I. FINALIZING
J. Recu Finality
K. Recu Terminal
L. Publication COMMITTED
M. Suppression WAL apres COMMITTED
N. Recuperation PREPARED
O. Recuperation RECOVERING
P. Recuperation RECOVERED
Q. Recuperation COMMITTED
R. Recuperation ROLLED_BACK
S. WAL persistant sans preuve terminale
T. Recu manquant, invalide, contradictoire ou falsifie
U. Crash entre chaque transition durable
V. Retour de succes apres echec fsync, rename ou unlink
W. Reprise dans un nouveau processus
X. Idempotence et concurrence
Y. Verifications de durabilite et cleanup des repertoires

Pour chaque chemin :
- Trouver la fonction et les lignes reelles.
- Identifier les gardes et transitions.
- Identifier le test existant.
- Verifier les cas positifs et negatifs.
- Declarer PASS / HOLD / BLOCK.
- Ne pas inventer de couverture.

============================================================
2. CORRECTION DE TOUS LES DEFECTS DEMONTRES
============================================================

Corriger directement les defauts reproduits.

Priorites :

P0-1
Auditer les chemins wal_file.unlink() dans
recover_dangling_wal().

Le chemin RECOVERED a deja sa barriere.

Controler la branche COMMITTED et les autres sorties
terminales, sans rendre possible une suppression
non autorisee du WAL.

Un HOLD authentique et intentionnel n'est pas un bug.
Ne pas forcer le nettoyage si les preuves manquent.

P0-2
Verifier la durabilite de toutes les restaurations.

Pour chaque os.replace() ayant un effet physique :
- Fichier synchronise selon le contrat.
- Remplacement execute.
- Repertoire cible synchronise.
- Etat final publie ensuite.

Pour chaque unlink physique gouverne :
- Controle d'autorisation.
- Suppression.
- Barriere de repertoire.
- Aucune annonce de succes avant cette barriere.

P0-3
Verifier que les erreurs d'I/O restent fail-closed.

Aucune exception critique ne doit etre silencieusement
ignoree si elle permet un faux succes.

P0-4
Verifier les etats terminaux et la coherence
WAL / Lifecycle / Finality / Terminal.

Interdire toute publication ou recuperation illegitime.

P0-5
Verifier que la reprise apres erreur ne duplique pas
les transitions append-only.

Ne jamais restaurer les octets apres FINALIZING si le
contrat interdit le rollback a ce stade.

Ne jamais ajouter une nouvelle autorite.

============================================================
3. TESTS DE PREUVE
============================================================

Ajouter les tests necessaires dans les fichiers K1 existants.

Chaque defaut corrige doit avoir :
- Une reproduction RED lorsqu'elle est possible.
- La correction minimale.
- Un PASS apres correction.
- Une injection d'echec.
- Une verification des octets.
- Une verification du WAL.
- Une verification du Lifecycle.
- Une verification de l'absence de succes illegal.

Tester les branches terminales et les reprises.

Verifier les chemins de crash dans un autre processus
Python lorsque cela apporte une preuve supplementaire.

Ne pas appeler cela une simulation de coupure electrique
reelle.

Ne pas modifier les assertions de securite pour
accepter un comportement incorrect.

Si un observateur doit evoluer pour reconnaitre un
nouveau flush legitime, garder les invariants pre-ACT.

============================================================
4. REGRESSION COMPLETE
============================================================

Executer ces neuf modules :

python -B -m pytest -p no:cacheprovider -q sigma/tests/test_kx108_zero_vote_guard_v1.py sigma/tests/test_kx108_pre_phase_gate_v1.py sigma/tests/test_kx108_pre_provenance_red_v1.py tests/cli/test_k1_governed_singlewrite_v1.py tests/cli/test_k1_pre_action_binding_positive_v1.py tests/cli/test_k1_pre_action_binding_red_v1.py tests/test_kx108_k1_ticket_decision_binding.py sigma/tests/test_k1_wal_authority_red_v1.py sigma/tests/test_k1_wal_path_boundary_red_v1.py

Executer aussi les autres tests directement concernes
par les changements, s'ils existent.

Executer :
git diff --check

En cas d'echec :
- Diagnostiquer.
- Corriger dans le perimetre.
- Relancer.
- Continuer dans cette meme session.

Ne pas annoncer GREEN avec un test echoue ou non execute.

============================================================
5. AUDIT DE FERMETURE
============================================================

Produire obligatoirement :

K1_ONE_PASS_CLOSURE/K1_CLOSURE_AUDIT.md
K1_ONE_PASS_CLOSURE/K1_CLOSURE_VERDICT.json

L'audit Markdown doit contenir :

1. Base initiale : 100/100 PASS.
2. Inventaire des branches examinees.
3. Matrice branche -> preuve -> test -> verdict.
4. Liste exacte des corrections.
5. Liste exacte des fichiers modifies.
6. Resultats des tests positifs et negatifs.
7. Etat des invariants KX108.
8. Etat des WAL et des recu de finalite.
9. Limites non testees et preuves absentes.
10. Decision finale.

Schema JSON obligatoire :

{
  "baseline": "100/100 PASS",
  "verdict": "READY_FOR_FREEZE_REVIEW",
  "tests_passed": 0,
  "tests_failed": 0,
  "coverage_matrix_complete": false,
  "kx108_authority_unchanged": true,
  "open_blockers": [],
  "unverified_limits": [],
  "modified_files": []
}

Utiliser :
READY_FOR_FREEZE_REVIEW
uniquement si l'audit des chemins accessibles est termine,
toutes les preuves requises passent,
aucun defaut P0/P1 ouvert n'est masque
et la campagne complete est GREEN.

Sinon :
HOLD ou BLOCK.

La resistance experimentale a une vraie coupure electrique
peut rester une limite explicite ; ne jamais la presenter
comme demontree.

Ne pas effectuer de FREEZE officiel a la place de l'humain.

============================================================
6. EXECUTION
============================================================

COMMENCER MAINTENANT.

Lire, auditer, corriger, tester, documenter.
Ne demander aucune decision intermediaire.
Ne pas creer un plan a executer plus tard.
Ne pas s'arreter avant la regression et le rapport final,
sauf blocage technique ou risque de violation d'invariant.

Sortie finale concise :

K1_ONE_PASS_DONE
TESTS=<nombre reel>
FAILED=<nombre reel>
VERDICT=READY_FOR_FREEZE_REVIEW|HOLD|BLOCK
KX108_AUTHORITY=UNCHANGED|BLOCK
FILES_CHANGED=<liste>
OPEN_BLOCKERS=<liste>
AUDIT=K1_ONE_PASS_CLOSURE/K1_CLOSURE_AUDIT.md