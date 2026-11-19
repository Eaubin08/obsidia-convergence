# G4E — Rattrapage des exceptions POST après mutation C2

## Portée

- Base : G4D `05a55fb50e4795df4aabdd760c31f08267ab34e9`.
- Machine de validation précédente : portable `DESKTOP-Q5MD7J7`.
- Seul auteur de décision : `KX108_ONLY`; `RELEASE=HOLD`.
- Code concerné : `scripts/obsidia_governed_apply_v0.py` dans l'assemblage
  isolé `assembly/g1_g2_runtime_v1/`.

## Frontières de défaillance traitées

| Phase après mutation mesurée | Défaillance | Sortie imposée |
| --- | --- | --- |
| SealedApplyReceipt | Exception de construction, stockage, chargement ou vérification | Signal `POST_EVIDENCE_UNAVAILABLE` vers D2 |
| Adaptateur de preuve POST | Exception ou retour incomplet/malformé | Signal `POST_EVIDENCE_UNAVAILABLE` vers D2 |
| Kernel KX108 POST | Exception, état non stocké/vérifié ou ID absent | Signal `KX108_POST_STORE_FAILURE` vers D2 |
| Disposition POST | Exception, retour malformé ou incohérence avec le gate | Signal `POST_EVIDENCE_UNAVAILABLE` vers D2 |
| Rollback D2 | Exception ou statut inconnu | `GOVERNED_REMEDIATION_ROLLBACK_FAILED_QUARANTINE` ; revue de commit interdite |

Quand D2 déclare une restauration réussie, l'API publique retourne un statut
de rejet avec rollback ; elle ne fabrique aucune autorisation d'APPLY.
Quand D2 ne confirme pas la restauration, la cible est **considérée
non vérifiée** et requiert une intervention explicite.

## Preuves de développement

- Tests supplémentaires `test_kx108_g4e_post_mutation_exception_stdlib_v1.py` :
  10 scénarios négatifs avec cibles dans `TemporaryDirectory` et simulateurs
  d'écriture/restauration.
- Régression intégrale `unittest test_*stdlib_v1.py` : **254 OK sous Linux**.
- Vérification Windows du lot : **à effectuer** sur le portable, avec
  `candidate/g1_g2/tests`.

## Ce que G4E ne prouve pas

- Résilience après arrêt brutal du processus, coupure électrique ou corruption
  entre l'écriture et le rollback.
- Attestation indépendante du processus producteur, des personnes, du runner
  C278 ou des écritures réellement effectuées.
- Couverture de toutes les fonctions susceptibles d'écrire dans Obsidia.
- Libération du produit ou autorisation de la production.

Conclusion : exception handling testé, **Global Write Closure et RELEASE
sur HOLD**, sans mutation d'aucun dépôt FIX originel.
