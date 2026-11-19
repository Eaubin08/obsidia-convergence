# G4F — Observation prudente de la fenêtre C2 interrompue

## Décision

- Base validée Windows : G4E `30e9bb20abb82b35546d1cc4c00d19978d34c319`.
- Entrée unique : `get_runtime().inspect_kx108_c2_crash_window(...)`.
- Lecture seule ; aucun dossier de production ou FIX d'origine modifié.
- `KX108_ONLY`, `RELEASE=HOLD`, `GLOBAL_WRITE_CLOSURE=HOLD`.

## Sources d'observation

1. Record PRE rechargé par identifiant, HMAC K1 vérifié, phase PRE et gate
   ALLOW contrôlés.
2. `SealedRollbackEvidence` C2 rechargée, hash et identité structurels
   recalculés, préimage validée, identifiants EAH/batch/child/PRE/approbation
   comparés avec le PRE signé.
3. Chemin de cible limité au répertoire explicitement choisi ; pas de liens
   symboliques/reparse, pas de parcours `..` ou chemin absolu.
4. SHA256 courant observé deux fois avec métadonnées de fichier stables.

## Sortie (toujours HOLD)

| Observation | Interprétation autorisée | Conséquence |
| --- | --- | --- |
| `PREIMAGE_OBSERVED` | Octets courants identiques à A ; écriture ou restauration historiques non prouvées | Revue requise ; jamais de RELEASE |
| `SOURCE_IMAGE_OBSERVED` | Octets courants identiques à B ; provenance non attestée | Quarantaine recommandée |
| `UNKNOWN_CONTENT` | Octets différents, cible manquante, alias ou changement pendant lecture | Quarantaine recommandée |
| Preuve invalide/inaccessible | Aucune déduction de l'état | HOLD et revue manuelle |

L'absence d'un WAL/intent signé ou d'un reçu POST ne permet pas de conclure
qu'un crash s'est produit. Même une observation répétée n'est pas un verrou
sur un écrivain concurrent. Le hash structurel du SRE n'authentifie pas le
processus qui l'a créé, et le PRE ne remplace pas cette provenance.

## Validation

13 tests synthétiques (temporaires, sans APPLY) et régression totale du
runtime à exécuter sur Windows. Aucun test de crash physique ou de reprise
automatique n'est effectué par G4F.

## Frontière suivante

Pour avancer vers la reprise réelle : journal d'intention persistant,
publication synchrone avant mutation, identité du producteur, arbitrage
concurrent, récupération idempotente vérifiée, tests d'interruption de
processus en environnement jetable. **Aucun de ces actes n'est autorisé par
la réussite de G4F.**
