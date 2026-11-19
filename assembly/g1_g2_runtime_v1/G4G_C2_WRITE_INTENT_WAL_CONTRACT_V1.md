# G4G — Contrat de journal d'intention C2 isolé

## Position dans la convergence

Base : G4F, commit `3b5de9c8f927c16726360d35c02e9010e8bb4477`.
Validation Windows de G4F : 267 tests OK (7 ignorés), 54 contrats PASS
(2 ignorés), portable `DESKTOP-Q5MD7J7`.

Le but de G4G est de vérifier une brique de *write-ahead intent* avant de
la relier au véritable writer. **Aucune activation d'APPLY**, aucune
restauration réelle, aucun nouveau droit d'écriture métier.

## Contrat testé

1. `build_intent(...)` construit un enregistrement déterministe à partir du
   batch/child, EAH, approval, PRE et identifiant/hash du SealedRollbackEvidence,
   chemin confiné et états attendus A/B. L'identité et le hash sont recalculés.
2. `store_intent(...)` écrit un fichier temporaire, `flush + fsync`, puis
   publie par `os.link` exclusif dans un magasin explicitement choisi.
   Même contenu = idempotent ; contenu différent = refus de réécriture.
3. `build_outcome(...)`/`store_outcome(...)` enregistrent un **résultat
   déclaré**, qui n'est ni preuve de mutation ni autorisation KX108.
4. `inspect_intent(...)` et la méthode du runtime
   `inspect_c2_write_intent_wal(...)` retournent toujours `HOLD`.
   Absence de résultat = `UNRESOLVED_INTENT`, sans reprise automatique.
5. Les chemins du magasin relatifs, symboliques ou jonctions sont rejetés ;
   les fichiers modifiés et les identifiants trompeurs restent non fiables.

## Preuves de développement

- 13 nouveaux tests `unittest` dans un répertoire temporaire.
- Un sous-processus Python est interrompu par `os._exit(17)` après
  publication confirmée : le parent recharge l'intention non résolue.
- Concurrence de publications identiques ; idempotence et conflit.
- Corruption, injection de champs, statut de sortie trompeur, symlink.

## Limites obligatoires

| Point | Verdict |
| --- | --- |
| Survivre à un arrêt de processus **après** publication confirmée | Testé en sandbox |
| Résister aux doublons et écrasements simples | Testé en sandbox |
| Journal branché avant `atomic_replace_with_bytes` canonique | **NON** |
| Crash réel pendant la publication / perte de courant Windows | **NON PROUVÉ** |
| Producteur ou runner C2 authentifié | **NON** |
| Scan global / réveil / reprise automatique idempotente | **NON** |
| Autorisation de production, Global Write Closure ou RELEASE | **HOLD** |

Il faut encore intégrer ce protocole au chemin C2 avec verrouillage,
ordonner durablement **intent avant mutation**, gérer les issues finales et
la synchronisation du répertoire Windows, puis tester des interruptions
avant/après `atomic_replace` dans un dépôt synthétique jetable. Une issue
`REPORTED_KEEP` est une déclaration non authentifiée, jamais un ticket.

**KX108_ONLY demeure le seul organe souverain.**
