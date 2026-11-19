# G4I — Déclaration immuable de résultat et observation à froid du WAL C2

## Provenance

- Parent : `build/g4h-c2-prewrite-intent-optin-v1`.
- Commit parent : `a20a6e2fc3304c35c6f790b50e2abc95527400bb`.
- Machine de validation G4H : **portable** `DESKTOP-Q5MD7J7`, distinct du
  **fixe** `DESKTOP-SDOG0EL`.
- G4H Windows : **286 tests unittest OK (8 ignorés)** ; **54 contrats G1/G2
  PASS (2 ignorés)**.
- La branche G4I ne modifie ni le FIX K1 ni un worktree actif de l'utilisateur.

## Contrat ajouté

Le même runtime expose une **seule méthode de lecture** :

`inspect_c2_wal_outcome_state(wal_dir, intent_id, repo_root)`.

L'inspecteur :

1. Recharge une intention structurée par identité/hash dans un WAL explicite.
2. Refuse les racines relatives, cibles non canoniques et alias reparse.
3. Mesure deux fois le fichier cible dans le contexte d'observation, avec
   empreintes de métadonnées avant/pendant/après la lecture.
4. Distingue `PREIMAGE_OBSERVED`, `POSTIMAGE_OBSERVED`, `UNKNOWN_CONTENT`,
   `TARGET_MISSING` et le cas ambigu `AMBIGUOUS_EQUAL_PRE_POST`.
5. Relit un outcome déclaré, vérifie ses liens et refuse tout écart entre
   SHA actuel, SHA déclaré et type d'issue rapporté.
6. Retourne **toujours** `HOLD`, même lorsque les octets coïncident.

La fonction séparée `report_c2_wal_outcome_testonly(...)`, **non exposée dans
la façade runtime**, peut ajouter exactement un enregistrement WAL par
publication exclusive :

| Issue déclarée | Condition minimale observée | Ce qu'elle ne prouve pas |
|---|---|---|
| `REPORTED_KEEP` | Cible actuelle = hash POST | Décision KX108, origine du processus, mutation historique |
| `REPORTED_ROLLBACK` | Cible actuelle = hash PRE | Qu'un rollback a réellement eu lieu |
| `REPORTED_QUARANTINE` | État mesurable ou cible absente | Qu'une quarantaine ait été physiquement appliquée |

Une issue existe sur disque uniquement après écriture des **métadonnées WAL**.
Le reporter ne modifie jamais la cible. Il ne permet ni report contradictoire
ni remplacement d'une issue existante. La relecture finale est immédiate ;
toute divergence demeure `HOLD`.

## Tests

15 tests supplémentaires, dont : simulation G4H d'un rollback dans un
`TemporaryDirectory`, keep/rollback incohérents, outcome corrompu,
disparition et changement de cible, relecture, refus de rejouement,
symlink Windows (ignoré si le compte ne dispose pas du privilège),
cas A=B ambigu et magasin indisponible.

## HOLD maintenu

Les WAL d'intention/résultat ne sont **pas signés par un producteur
attesté**. Les doubles lectures ne figent pas le disque contre une course
concurrente. Aucune preuve d'APPLY réel, de crash machine, d'une restauration
persistante ou de fermeture globale d'écriture ne découle de G4I.

Il reste à obtenir des preuves de producteur/runner, tester les interruptions
aux frontières réelles et définir un protocole de reprise interprocessus
autorisé explicitement par KX108 avant toute release.

`KX108_AUTHORITY=UNCHANGED` — `RELEASE=HOLD`.
