# G4J — Signature RSA par PC d'un résultat WAL, sans attestation de runner

## Chaîne vérifiée

- Base : `build/g4i-c2-wal-outcome-observation-v1`, commit
  `264cd344091f9e2cda593a91c0afc8777527b7a9`.
- **Portable** : `DESKTOP-Q5MD7J7` (profil Windows `C:\Users\User`).
- **Fixe** : `DESKTOP-SDOG0EL` (profil Windows `C:\Users\Aubin`).
- G4I Windows : **301 tests unittest OK, 9 ignorés** ; **54 contrats G1/G2
  PASS, 2 ignorés**.

## Ce que G4J prouve — et ne prouve pas

G4J introduit un contrat RSA-PKCS1v15/SHA256 *domain-separated* :

`OBSIDIA_G4J_C2_WAL_MACHINE_RSA_V1\0 + JSON_CANONIQUE(payload)`.

Le message lie les SHA256 structuraux **de l'intention et du résultat WAL**,
leur identité, le statut déclaré, le hash des octets observés, un nonce et
des empreintes déclarées de code/trace. Il lie aussi le PC et la SHA256 du
certificat public, avec vérification contre un pin fourni *hors reçu*.

Le vérificateur `c2_wal_machine_rsa_receipt_v1.py` :

1. Recharge et inspecte le WAL et le fichier cible, sans mutation.
2. Exige un outcome lié et actuellement compatible avec les octets observés.
3. Refuse les champs d'autorité inattendus, l'identité d'un autre PC,
   la mutation de reçu, le changement de domaine et le mauvais certificat.
4. Vérifie le certificat RSA3072 (CN de la machine, période, signature),
   puis RSA-SHA256 avec le domaine exact.
5. Retourne **toujours HOLD**, même si la signature correspond.

La signature démontre la **possession de la clé privée** au moment de la
signature, **pas** qu'un runner réel ait effectué l'APPLY/rollback déclaré.
Elle ne vérifie ni l'historique Git signé, ni la vérité du transcript, ni
l'approbation de l'identité par un administrateur. Il n'existe pas encore
de registre durable anti-rejeu ni de révocation indépendante.

## Windows : preuve réelle de compatibilité avec la clé déjà présente

Le script `tools/verify_g4j_wal_machine_rsa_windows_v1.ps1` n'installe aucun
certificat et ne crée aucune clé privée. Il vérifie uniquement **sur le
portable** la clé existante `CN=OBSIDIA-OBSIDURE-DESKTOP-Q5MD7J7`, déjà
vérifiée lors du jalon Obsidure C278. Cette utilisation cryptographique
de démonstration **ne confère aucun rôle de gouvernance à Obsidure**.

Le script crée un dossier temporaire inédit avec des octets synthétiques
et un WAL sans APPLY réel. Python prépare les octets exacts à signer ; la
clé Windows signe **en mémoire**, et un second outil Python vérifie le
certificat, la signature, le WAL et la cible. Le dossier synthétique est
ensuite supprimé ; aucun secret n'est exporté ni publié sur GitHub.

Les outils Python :

- `tools/prepare_g4j_wal_synthetic_fixture_v1.py` : test-only, ne signe pas.
- `tools/verify_g4j_wal_receipt_v1.py` : vérifie le JSON depuis STDIN,
  rejette les clés JSON dupliquées et ne signe jamais.

Les suites de développement apportent **17 tests nouveaux** : RSA synthétique,
falsification, pin, deux machines, changement d'outcome/état cible, faux
nonce/domaine, CLI stdin, doublon JSON et fixture temporaire.

## Suite obligatoire

Un certificat self-signed *enrolled awaiting review* n'est pas une racine
de confiance. Une preuve de producteur nécessitera : une politique de
confiance hors reçu, un runner de référence identifié et borné, un suivi
anti-rejeu/revocation persistant, une chaîne de provenance de l'exécution
et des tests d'interruption réels dans un bac à sable jetable.

`KX108_AUTHORITY=UNCHANGED` — `RELEASE=HOLD` — `NO_REAL_C2_APPLY`.
