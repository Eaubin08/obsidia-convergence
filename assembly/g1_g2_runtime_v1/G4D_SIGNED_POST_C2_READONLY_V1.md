# G4D — POST HMAC K1 joint aux vrais reçus C2 (READ_ONLY)

## Evidence d'entrée

`DESKTOP-Q5MD7J7` est le **portable** et a validé G4C au commit
`cf20d831e99305bcac7737d3ffbdc10d4f4ae2c3` :

- 232 tests `unittest` exécutés, `OK (skipped=6)` ;
- 54 tests de contrats G1/G2 PASS, 2 skipped ;
- `OBSIDIA_G4C_WINDOWS_PASS` ; `RELEASE=HOLD`.

`DESKTOP-SDOG0EL` est le **fixe**. Aucun des deux FIX originaux n'est
modifié par ce lot ; seule la branche d'intégration reçoit l'assemblage.

## Objet G4D

Une **nouvelle méthode de lecture** de la même façade de gouvernance :

`get_runtime().inspect_kx108_c2_signed_post_receipts(...)`

| Étape | Contrôle | Limite explicite |
| --- | --- | --- |
| 1. POST chargé | Record canonique exact depuis un magasin explicitement fourni | Aucun record injecté par l'appelant |
| 2. K1 POST | Hash, HMAC du noyau, cohérence enveloppe, phase POST | Clé K1 absente ou HMAC invalide → HOLD |
| 3. Producteur déclaré | Identité de producteur POST canonique liée par HMAC | HMAC n'atteste pas le processus ni le runner |
| 4. PRE + C2 | Réutilisation des validateurs G4/G4B, références PRE, reçus Apply et Rollback réels | Les reçus restent authentifiés **structurellement seulement** |
| 5. Fraîcheur | Nouvelle lecture et authentification du POST après G4B | Refus si le POST a changé pendant l'inspection |
| 6. Résultat | Toujours `HOLD` | Jamais APPLY, KEEP automatique, ticket ou release |

Les ancrages et chemins « attendus » sont fournis par l'appelant. G4D ne
prouve donc **ni HumanApproval réelle**, ni l'origine de ces attentes. Il ne
lit pas la cible vivante : aucune correspondance de reçu ne devient une
preuve d'effet réel. Il n'enrôle **aucune** identité machine et ne transfère
aucune clé RSA privée. La preuve d'exécution par le producteur C2 (process,
worker, effets, sandbox, timing) demeure à établir séparément.

Les méthodes G4 et G4B historiques restent disponibles pour le replay
structurel. G4D fournit un contrôle **opt-in plus strict** : un POST
historique non signé ne passe pas ce contrôle, même avec un hash recalculé.

## Tests

`tests/integration/test_kx108_g4d_signed_post_readonly_stdlib_v1.py` :
12 tests en dossier temporaire ; POST valide signé par une clé de test,
POST sans HMAC, falsification/re-hash ALLOW, mauvais producteur,
clé indisponible, reçus re-hashés, PRE corrompu, dérive d'ancrage, substitution
du POST entre contrôles, et vérification des entrées des magasins.

**KX108_AUTHORITY = KX108_ONLY ; GLOBAL_WRITE_CLOSURE = HOLD ; RELEASE = HOLD.**
