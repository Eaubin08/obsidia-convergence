# G4H — Raccordement expérimental de l'intention WAL avant C2

## Base vérifiée

- Branche parente : `build/g4g-c2-write-intent-wal-contract-v1`.
- Commit : `7a5ca40291e25d3c96397d206c70a4a39d8e9472`.
- Portable : `DESKTOP-Q5MD7J7` (jamais confondu avec le fixe `DESKTOP-SDOG0EL`).
- G4G Windows : 280 tests `unittest` OK (8 ignorés) ; 54 contrats G1/G2 PASS (2 ignorés).
- La publication G4H ne modifie pas le worktree original K1 ni le runtime souverain.

## Modification contractuelle

Le writer historique `scripts/obsidia_governed_apply_v0.py` accepte un
paramètre **facultatif** `c2_write_intent_dir: Optional[Path] = None`.
Sans ce paramètre, le chemin historique est inchangé.

Lorsqu'un magasin WAL absolu et explicite est fourni dans une **simulation** :

1. Vérifier PRE KX108 authentifié, EAH, approbation, confinement, SHA cible
   et preuve de rollback SRE persistée et relue.
2. Refaire le contrôle final de la cible immédiatement avant l'écriture,
   ainsi que le contrôle de fraîcheur sous verrou pour l'approbation dérivée.
3. Construire une intention bornée à l'identité de l'action et aux SHA PRE,
   SRE et cible attendue ; publier exclusivement dans le WAL puis relire.
4. **Refuser sans mutation** si le magasin est indisponible, si la lecture
   échoue ou si une intention identique existe déjà (replay / possible
   opération orpheline). Dans le cas nominal, le double de mutation peut
   commencer après cette publication.

Le WAL est un **témoin non signé et non souverain**. Sa présence ne transforme
jamais `HOLD` en `ALLOW`, ne donne pas de capacité d'écriture et ne remplace
pas le contrôle KX108.

## Preuves ajoutées

Six tests `unittest` synthétiques : ordre écriture-WAL, replay bloqué,
échec d'écriture WAL, échec de relecture WAL, argument invalide et compatibilité
sans opt-in. Les cibles sont exclusivement des fichiers temporaires ; la
mutation et le rollback sont des doubles de test.

## Limites bloquantes

- Aucune authentification de producteur ou clôture d'outcome n'est raccordée.
- Une intention reste non résolue après retour, même si le rollback de
  simulation s'est terminé ; il n'existe aucune reprise automatique.
- Durabilité après coupure de courant, cohérence multiprocessus, symlinks
  concurrentiels et crash recovery réel **non certifiés**.
- Aucun chemin de release ni d'APPLY réel dans la façade unifiée.

`KX108_AUTHORITY=UNCHANGED` — `RELEASE=HOLD`.
