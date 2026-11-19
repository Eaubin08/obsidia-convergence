# OBSIDIA G4M — Identité par PC : proposition de rôle, pas admission

## Périmètre et provenance

- Parent : G4L, `build/g4l-c2-local-nonce-ledger-v1`, commit `62a70cc138d3482d4bfd8c090c7108a1f5619165`.
- **Portable** `DESKTOP-Q5MD7J7`, compte Windows `User` : un certificat RSA non exportable préexistant, empreinte publique `5bb3f8688930de497254185292a49b46c2f88b0bb23cf259711e86981932c398`. Enrôlement encore `ENROLLED_AWAITING_REVIEW`.
- **Fixe** `DESKTOP-SDOG0EL`, compte Windows `Aubin` : identité `PLANNED` dans l'exemple ; **aucune création ou utilisation de clé sur le fixe**.
- FIX originel sur portable : `C:\Users\User\.codex\visualizations\2026\11\kx108_zero_vote_guard_fix` ; pas modifié.

## Contrat proposé

Le registre structurel `obsidure_machine_identity_registry_v1.py` existe déjà. G4M le **réutilise** : il n'invente pas un second registre ni une nouvelle autorité.

Le nouvel inspecteur `ObsidiaGovernanceRuntime.inspect_obsidure_machine_role_proposal()` :

1. Recharge le registre complet, exige le schéma, `KX108_ONLY`, une machine unique, des certificats publics non réutilisés et le rôle **consultatif** `OBSIDURE_TEST_EVIDENCE_PRODUCER`.
2. Refuse les machines absentes, `PLANNED`, `REVOKED`, les faux états `APPROVED`, les rôles souverains, les certificats divergents et les identités dupliquées.
3. Pour le portable seulement, compare le certificat public proposé à une signature RSA réelle d'un **scénario synthétique** G4K ; vérifie les hashes de trace/WAL via le rail existant.
4. Rend **uniquement** `G4M_MACHINE_ROLE_PROPOSED_CRYPTO_BOUND_NOT_APPROVED`, `status=HOLD` si les contrats correspondent.

La méthode ne signe aucun certificat, n'approuve aucun responsable, ne délivre aucun ticket et ne déclenche aucun programme.

## Séparation des affirmations

| Propriété | G4M |
|---|---|
| Machine portable et empreinte de certificat concordantes avec une proposition publique | **Oui, contrôlable** |
| Machine fixe préparée comme identité distincte future | **Oui, métadonnée `PLANNED` uniquement** |
| Signature synthétique G4K valide sur WAL | **Oui, vérifiable** |
| Responsable réel identifié, authentifié et habilité | **Non** |
| Attestation indépendante de machine physique ou d'exécution historique C278 | **Non** |
| Approbation d'enrôlement par autorité reconnue | **Non** |
| Registre public GitHub constituant une racine de confiance | **Non** |
| Délégation de pouvoir à Obsidure, autorisation d'APPLY ou de release | **Non** |

Une référence textuelle de revue (`enrollment_review_ref`) ou de responsable (`responsible_refs`) demeure une **déclaration non authentifiée**, même si elle contient un nom ou un identifiant plausible.

## Validation Windows

Un outil de validation crée une fixture temporaire G4K, utilise la clé Windows **préexistante** du portable pour signer uniquement les octets synthétiques, construit un registre **en mémoire** avec les deux identités distinctes et réinterprète sa liaison dans le runtime en lecture seule. Il détruit uniquement sa propre fixture temporaire nommée par GUID.

Les tests négatifs couvrent état révoqué, machine absente, certificat croisé, rôle souverain, doublon, certificat substitué, référence humaine déclarée mais non authentifiée, signature altérée et absence d'API d'activation.

**RELEASE=HOLD** jusqu'à décision humaine explicite sur l'autorité chargée de l'enrôlement, la preuve du responsable, les origines réelles du producteur et du lanceur, le traitement de la révocation et le registre anti-rejeu de confiance.
