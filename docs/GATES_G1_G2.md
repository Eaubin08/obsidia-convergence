# Portes de validation G1 + G2

**Statut initial : HOLD — non exécuté dans ce dépôt.**

## Sécurité KX108

- [ ] K1 HMAC : authentification correcte et échec en cas de falsification, absence ou incompatibilité d'enregistrement.
- [ ] PRE : preuves canoniques rechargées et revalidées avant décision.
- [ ] Zéro vote, vote invalide, champs inconnus et preuve manquante → HOLD/BLOCK.
- [ ] Nonce, ticket, anti-rejeu et identité d'action validés, y compris après redémarrage.
- [ ] Tous les consommateurs utilisent la signature PRE retenue ; aucun chemin alternatif qui la contourne.
- [ ] SIGMA / agent / périphérie : avis non souverain, incapable de produire la décision finale.

## CREATE / Write Closure

- [ ] `CREATE_TARGET_FROM_SOURCE` exige cible absente, chemin autorisé et lien source/cible vérifié.
- [ ] `WORLD_ACTION_PRE_EXECUTION` passe dans le même rail d'autorité KX108.
- [ ] Aucune écriture avant HumanApproval et KX108_PRE lorsque ces gates sont requis.
- [ ] Refus d'écriture sans preuve, avec cible changée, chemin détourné, ou autorisation rejouée.
- [ ] Aucun appel à APPLY direct qui contourne les décisions.
- [ ] Aucun recalcul Merkle ne réécrit automatiquement le scellement sans autorisation.

## Résilience / traçabilité

- [ ] Concurrence, TOCTOU et crash-recovery testés.
- [ ] Chaîne intention → preuve PRE → décision → action bornée → POST → replay auditable.
- [ ] Les tests négatifs démontrent les refus attendus.
- [ ] Les régressions K1 et CREATE des deux provenances passent.
- [ ] Rapport reproductible : commit, manifeste SHA256, versions et commandes de tests.

## Verdict

- **PASS** : toutes les portes requises passent avec preuves et sans régression.
- **HOLD** : preuve absente, contrat inconnu ou test non exécuté.
- **BLOCK** : violation établie d'un invariant ou contournement de l'autorité.

Aucun PASS n'est affirmé au simple motif que la syntaxe Python ou les fichiers source sont valides.
