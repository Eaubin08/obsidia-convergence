# G4 — Liaison KX108 PRE/POST et preuves C2 (lecture seule)

## Provenance vérifiée à ce stade

- Portable `DESKTOP-Q5MD7J7` : le journal utilisateur du 19/11/2026 donne
  `OBSIDIA_G3_WINDOWS_PASS`, `Ran 189 tests`, `OK (skipped=6)` au commit
  `efca7cb0669cb9ffe982981d582578c3030b01f9`. Le FIX n'est pas modifié.
- PC fixe `DESKTOP-SDOG0EL` : sources 4A1, X108-CREATE et WORLD_ACTION
  déjà importées séparément dans `imports/pc2-governance-g1-g2`.
- Les tests ci-dessous utilisent des **records synthétiques** et une **clé
  exclusivement synthétique**. Ils ne sont ni des reçus de production, ni
  une attestation du vrai pipeline KX108.

## Ce qui est effectivement implémenté dans le runtime unique

Le point d'entrée `get_runtime().inspect_kx108_pre_post_write_closure(...)`
réutilise les producteurs **canoniques existants** uniquement par leurs
validateurs et chargeurs ; il ne les invoque pas pour générer une décision.

| Frontière | Vérification | Refus |
| --- | --- | --- |
| PRE K1 | record canonique, hash, HMAC, enveloppe cohérente, phase PRE et gate ALLOW | HOLD |
| POST | record canonique, hash structurel, phase POST explicite | HOLD |
| Liaison PRE→POST | ID et hash PRE exacts rechargés ; identifiants batch, child, EAH, approval et test-contract concordants | HOLD |
| C2 | présence des quatre liens scellés (apply et rollback, ID et SHA) | HOLD |
| Appelant | cinq ancrages attendus exacts ; champs supplémentaires refusés | HOLD |
| Écriture | aucun APPLY, aucune décision ni mutation ; `release_authorized=False` partout | HOLD |

Même lorsque toutes les concordances de cette inspection passent, le résultat
reste **`HOLD`** avec des sous-champs de preuve. Les ancrages externes fournis
par l'appelant ne sont pas attestés par ce seul contrôle.

## Limitations explicites : G4 ne clôt pas encore la release

1. **POST n'a pas d'HMAC K1 dans le producteur canonique** : la comparaison du
   hash structurel ne prouve donc pas l'identité de l'émetteur. Une variante
   réécrite avec hash recalculé peut rester structurellement cohérente.
2. Les références `sealed_apply_receipt_*` / `sealed_rollback_evidence_*`
   sont comparées comme champs ; les octets réels des reçus et leur origine
   ne sont pas ici vérifiés.
3. La vérité du `ExecutionEnvelope`, du contexte PRE, de HumanApproval et de
   l'état du système de fichiers au moment de l'écriture exige les vérificateurs
   canoniques et des tests **d'intégration bornés** sur une cible jetable.
4. L'anti-TOCTOU, la fermeture globale 4A1, le rollback post-crash et
   l'intégralité des consommateurs ne sont pas certifiés par les tests G4.
5. Obsidure C278 historique, agent Sigma runtime, API/Ragnarok et release
   demeurent hors de cette clôture.

**Aucun producteur KX108, aucune approbation humaine et aucun exécuteur
réel ne sont appelés dans ce jalon.** Il serait incorrect de présenter le
résultat comme une preuve fonctionnelle complète de la chaîne d'écritures.

## Vérification locale

```
PYTHONPATH=assembly/g1_g2_runtime_v1:assembly/g1_g2_runtime_v1/scripts \
python -B -m unittest discover \
  -s assembly/g1_g2_runtime_v1/tests/integration \
  -p 'test_*stdlib_v1.py' -q
```

G4 ajoute 17 tests : refus de PRE forgé avec hash recalculé, clé HMAC absente,
gate BLOCK, substitution PRE, POST ancien non lié, POST modifié, dérive des
ancrages, liens C2 incomplets, traversée et absence de records. Les tests
post-authentification reconnaissent **explicitement** l'absence de garantie
HMAC sur le POST.

## Prochaine clôture (G4B)

Vérifier, dans un environnement jetable, le cycle canonique
HumanApproval → KX108_PRE authentifié → single-write guarded → reçus C2
authentifiés et reliés → KX108_POST, avec rejets de contournement, reprise
après crash et contrôle de fraîcheur, avant toute décision de release.

`KX108_AUTHORITY=UNCHANGED`, `GLOBAL_WRITE_CLOSURE=HOLD`, `RELEASE=HOLD`.
