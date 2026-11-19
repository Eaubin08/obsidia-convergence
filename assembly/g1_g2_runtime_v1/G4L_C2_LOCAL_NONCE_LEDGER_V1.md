# OBSIDIA G4L — Réservation anti-doublon locale et persistante de nonce C2

## Provenance

- Parent : `build/g4k-c2-synthetic-runner-trace-v1`, commit `8ce6804063fac37c7d93ff90b4ab3defead880b8`.
- Portable de validation : `DESKTOP-Q5MD7J7`, compte `C:\Users\User`.
- Fixe : `DESKTOP-SDOG0EL`, compte `C:\Users\Aubin`, **non utilisé**.
- FIX K1 historique : `C:\Users\User\.codex\visualizations\2026\11\kx108_zero_vote_guard_fix`, **inchangé**.

## Ce que fait G4L

Le module `c2_wal_local_nonce_ledger_g4l_v1.py` se situe **hors façade d'exécution** et ne sait traiter que des reçus de scénario synthétique G4K dont les liens WAL et RSA G4J ont été vérifiés.

1. Recharge la signature, le certificat public épinglé par l'appelant, l'intention G4G et l'outcome G4I, la trace synthétique G4K et les octets du runner fixe.
2. Construit une identité de réservation à partir de `machine_id`, de l'empreinte du certificat et du nonce signé. Une même identité de machine ne peut donc pas réutiliser ce nonce pour un autre WAL **tant que le registre local est préservé**.
3. Insère un seul fichier JSON canonique avec ouverture atomique `O_CREAT | O_EXCL`, relecture et `fsync` des données. Un processus concurrent ne peut pas écraser le fichier existant.
4. Toute tentative de réutilisation doit retourner `G4L_LOCAL_REPLAY_DUPLICATE_DENIED` ; un fichier corrompu, incomplet, réencodé ou substitué reste bloquant/quarantainé. Aucun auto-rattrapage.
5. Un outil PowerShell de test signe une fixture entièrement synthétique avec la clé RSA Windows préexistante, puis invoque **deux processus Python distincts** : première réservation, puis tentative de replay refusée. Le dossier temporaire est ensuite supprimé de manière bornée.

## Limites impératives

| Revendication | G4L |
|---|---|
| Une réservation locale exclusive évite deux admissions simultanées du même nonce | **Vérifiée dans des tests** |
| Une seconde tentative dans un nouveau processus est refusée | **Vérifiée dans des tests** |
| Le registre est authentifié, immuable contre administrateur/attaquant local ou scellé matériellement | **Non** |
| L'effacement du répertoire de registre empêche encore le replay | **Non** : un test démontre explicitement l'inverse |
| Reprise cohérente après panne d'alimentation Windows | **Non attestée** |
| Anti-rejeu distribué entre plusieurs PC ou superviseurs | **Non** |
| Identité de producteur C278 réellement attestée | **Non** |
| Approbation d'enrôlement, responsable humain, ticket KX108 | **Non** |
| Droit d'APPLY, de réparation, de rollback ou de release | **Aucun** |

**Décision de sécurité :** `local_nonce_reserved=True` signifie uniquement « une réservation locale observée dans le bac à sable ». Le champ `replay_prevented` reste **toujours False**, indépendamment de la réussite du test. `KX108_ONLY`, `RELEASE=HOLD`.

## Prochaine frontière

Le verrou suivant est un **registre de confiance** (enrôlement et révocation des clés par responsable identifié, preuve de producteur réellement contrôlée, état transactionnel anti-rejeu durable, décision KX108 PRE/HMAC et reprise crash). G4L ne constitue pas cette fermeture.
