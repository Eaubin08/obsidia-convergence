# OBSIDIA Gouvernance — candidat d'intégration G1 + G2 (V0)

**État : code isolé + tests ciblés PASS ; fusion fonctionnelle G1+G2 : HOLD.**

Ce dossier est un **assemblage candidat**, pas le moteur complet ni un rail
autorisé en production. Il ne modifie ni `imports/`, ni les branches de travail
du portable ou du fixe. Aucun serveur, clé, périphérique ou API n'est lancé.

## Provenance exacte

| Rôle | Machine | Source déjà importée | Référence |
|---|---|---|---|
| K1 canonique, HMAC, PRE/POST, tickets, zéro vote | **Portable `DESKTOP-Q5MD7J7`** (`C:\Users\User`) | `imports/k1-zero-vote-guard/` | `fix/kx108-zero-vote-guard-v1` ; base `d48c3a885fca4d09584f77c353fd725d104aa863` |
| `WORLD_ACTION_PRE_EXECUTION` | **Fixe `DESKTOP-SDOG0EL`** (`C:\Users\Aubin`) | `imports/pc2-governance-g1-g2/v01-c1-world-action/` | `6d0b5c57bfe7` |
| Global Write Closure, adaptateur PRE CREATE, Merkle | Fixe | `imports/pc2-governance-g1-g2/4a1-write-closure/` | `d4ef53766048` |
| CREATE PRE supplémentaire | Fixe | `imports/pc2-governance-g1-g2/x108-create-pre/` | `9461e0968625` |
| CREATE intégration | Fixe | `imports/pc2-governance-g1-g2/x108-create-integration/` | `df6ca2fd2591` |

Le fichier `scripts/obsidia_kx108_decision_store.py` part **exclusivement**
du K1 du **portable** (SHA256 de l'original dans son manifeste :
`930778ab6c8448e6f01b9a5b24dec90325a2b2712e4b9d2326e1e501e68970cc`).
Le fichier V01 C1 du fixe n'a **pas** remplacé K1.

## Changement réel G1

- Ajout additif de `WORLD_ACTION_PRE_EXECUTION`, des champs liés et de
  l'identité `kxworld-...`, dérivés du code V01 C1.
- Les **24 fonctions historiques K1** restent inchangées, sauf
  `_record_bound_fields_for`, étendue à la nouvelle phase (test AST).
- La voie WORLD_ACTION conserve une trace structurellement vérifiée, mais
  **ne pose aucun authentificateur HMAC et n'émet aucun ticket**.
- Même si une dataclass fournie par l'appelant revendique `x108_gate=ALLOW`,
  la réponse reste `EVIDENCE_ONLY` et `execution_authorized=False`.
  La vérification d'authenticité K1 refuse cet enregistrement.
- Un rejeu d'évidence identique réutilise l'enregistrement append-only ;
  une pièce existante altérée entraîne un refus.

**Attention** : `dataclasses.is_dataclass` ne certifie pas une décision
réelle de GuardX108. Les décisions WORLD_ACTION et tout egress restent
**HOLD** tant que la production souveraine et les vérifications canoniques
ne sont pas reliées dans le runtime complet.

## Changement réel G2 (sans ACT)

`scripts/obsidia_create_pre_contract_v0.py` prépare la normalisation :

`CREATE_TARGET_FROM_SOURCE` (intention K1/Jarvis) → `CREATE`
(représentation admise par l'adaptateur PRE 4A1/X108-CREATE, avec
`target_pre_sha256=None`).

Il refuse :

- `UPDATE_TARGET_FROM_SOURCE` lorsque la cible n'existe pas ;
- cible déjà présente, parcours `..`, lecteur Windows, UNC, ADS,
  lien symbolique intermédiaire, parent non-répertoire ;
- SHA256 source absent ou invalide ;
- politique de protection canonique absente, en échec ou défavorable.

La sortie `READY_FOR_CANONICAL_PRE_EVIDENCE` est **une préparation**,
jamais une autorisation. Une vérification d'absence de cible à cet
instant **ne remplace pas** l'anti-TOCTOU au point d'écriture.

## Tests exécutés

```powershell
python -m pytest -q -p no:cacheprovider candidate/g1_g2/tests
```

**44 tests PASS** dans un environnement isolé Linux/Python 3.12 :
tests de refus, non-autorisation, intégrité des champs WORLD_ACTION,
idempotence, préflight CREATE, protection des chemins et conservation des
fonctions K1. Aucun test de production Obsidia n'a été exécuté.

## GATES à fermer avant fusion/activation

| Gate | État | Preuve manquante |
|---|---|---|
| G1 — Conservation des fonctions K1 | PASS statique | Vérifications runtime K1 complètes sur dépôt source |
| G1 — HMAC K1 et tickets | PRÉSERVÉ dans le code | Tests intégrés avec clé et store canonique, sans contournement |
| G1 — WORLD_ACTION | PREUVE SEULE | Producteur réel GuardX108, signature PRE et contrôle egress |
| G2 — CREATE | PRÉFLIGHT SEUL | Point d'écriture réel, anti-TOCTOU, POST, rollback |
| G2 — Global Write Closure | SOURCE PRÉSENTE | Raccordement aux véritables exécuteurs, tests négatifs |
| G2 — Merkle | SOURCE PRÉSENTE | Contrôle qu'aucun chemin de scellement ne réécrit hors gouvernance |
| G1+G2 — Validation bout en bout | HOLD | Runtime complet, dépendances, essais réels en sandbox |

## Fichiers canoniques supplémentaires requis

Les imports GitHub sont **des variantes ciblées**, pas un runtime exécutable.
Pour une fusion G1+G2 effective, il faut encore la base canonique du
portable et le chemin CREATE réel (pas les 133 dépôts). Notamment :

- `scripts/obsidia_batch_execution.py`
- `scripts/obsidia_pre_execution_context.py`
- `scripts/obsidia_test_contract.py`
- `scripts/obsidia_governed_apply_v0.py`
- `sigma/protocols.py`, `sigma/contracts.py`, et vérificateurs KX108
- le code de production qui réalise `CREATE_TARGET_FROM_SOURCE` et son
  point d'écriture atomique
- les tests canoniques associés à CREATE / Write Closure.

Ces chemins sont des **dépendances identifiées dans les imports**, pas la
preuve qu'ils manquent des dépôts locaux. Ils ne sont simplement **pas
encore présents comme base intégrée dans ce dépôt de convergence**.

Suite : isoler la base exécutable minimale du portable, réconcilier
l'ABI PRE (`target_pre_sha256` est présent dans le rapport de l'adaptateur
4A1 mais pas dans les champs directement liés du Decision Store K1),
brancher le vrai GuardX108 + HumanApproval, puis tester les refus et la
reprise sans activer de service.

**Règle : aucun remplacement de K1, aucun APPLY direct, aucune activation
de Ragnarok, aucun WORLD_ACTION egress sans preuve souveraine complète.**
