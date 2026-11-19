# G4B — Relecture canonique des reçus C2 réels (sans APPLY)

## Origine du jalon

La sortie Windows fournie sur `DESKTOP-Q5MD7J7` pour G4 a montré :
`Ran 206 tests`, `OK (skipped=6)`, `OBSIDIA_G4_WINDOWS_PASS`.
KX108 est resté `UNCHANGED`, `RELEASE=HOLD`. L'autre machine est le
**fixe** `DESKTOP-SDOG0EL` et n'est pas sollicitée par ce jalon.

## Progression

`get_runtime().inspect_kx108_c2_actual_receipts(...)` complète l'inspecteur
G4 et relit, par leurs ID canoniques, **de vrais enregistrements** de types :

1. `SealedApplyReceipt` via `load_sealed_apply_receipt` et
   `verify_sealed_apply_receipt` du code canonique existant ;
2. `SealedRollbackEvidence` via `load_sealed_rollback_evidence` et
   `verify_sealed_rollback_evidence` du code canonique existant.

La vérification exige :

| Frontière | Garantie testée |
| --- | --- |
| PRE K1 | Record chargé, HMAC du noyau, enveloppe cohérente, gate PRE ALLOW |
| POST | Hash structurel et lien PRE exact ; pas de preuve d'origine |
| POST → deux reçus | IDs et hashes correspondants aux artefacts rechargés |
| Apply → Rollback | Deux liens exacts ; refus de substitution |
| Ancrages | Batch, child, hash d'autorité, approval et PRE liés sans dérive |
| Cible | Chemin attendu, SHA du contenu avant/après, source et provenance concordants |
| Préimage | Base64 décodé par le vérificateur canonique et SHA recalculé |
| Autorité | Retour **toujours HOLD** ; aucun appel à un exécuteur |

Les 17 tests G4B produisent des fixtures **uniquement dans un dossier de test
jetable**, par les constructeurs canoniques. Ils vérifient les refus de
falsification, rehash, source/target drift, suppression d'artefacts,
reclassement CREATE non autorisé et absence de clé K1. Le stockage final des
fixtures est local et ne concerne aucun dossier Obsidia de l'utilisateur.

## Garde-fous et limites non négociables

- Un reçu C2 dit « scellé » dans le schéma n'est **pas authentifié par MAC** ;
  le hash seul peut être recalculé par un attaquant. Cela reste `HOLD` même
  après une concordance structurelle parfaite.
- Le POST n'est pas authentifié non plus. L'agrément du détenteur de clé
  K1 sur le PRE ne certifie ni le POST ni l'identité de leurs producteurs.
- L'inspection ne certifie pas que l'opération de fichier a effectivement eu
  lieu, ni que le chemin de production non gouverné est universellement fermé.
- Aucune HumanApproval réelle, aucun kernel KX108, aucun runner Obsidure,
  aucune migration/rollback ni aucun connecteur n'ont été activés ici.
- Un vrai test de bout en bout requiert un **worktree isolé et jetable**,
  l'authentification des artefacts de POST/Apply/Rollback et la vérification
  du TOCTOU/crash/replay. Le raccorder sans ces preuves serait prématuré.

## Commande de régression (dev)

```
PYTHONPATH=assembly/g1_g2_runtime_v1:assembly/g1_g2_runtime_v1/scripts \
python -B -m unittest discover \
  -s assembly/g1_g2_runtime_v1/tests/integration -p 'test_*stdlib_v1.py' -q
```

KX108 et la façade runtime sont **inchangés sur le plan de l'autorité**.
`RELEASE=HOLD`, `GLOBAL_WRITE_CLOSURE=HOLD`, `ACTUAL_WRITE_ATTESTED=False`.
