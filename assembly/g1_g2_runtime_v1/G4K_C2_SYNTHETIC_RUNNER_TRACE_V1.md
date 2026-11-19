# OBSIDIA G4K — Trace d'un enfant de processus synthétique lié au WAL G4J

## Source et PC

- Parent : `build/g4j-c2-wal-per-machine-rsa-v1` au commit `b478fbcf1235d6020f870742ba3f5260f778f1df`.
- Portable de validation : `DESKTOP-Q5MD7J7`, compte Windows `User`.
- PC fixe distinct : `DESKTOP-SDOG0EL`, compte Windows `Aubin`. Aucun export de cette machine dans cette passe.
- FIX K1 originel : `C:\Users\User\.codex\visualizations\2026\11\kx108_zero_vote_guard_fix`, non modifié.

## Entrée / sortie

1. Un outil extérieur au runtime fabrique **exclusivement** un dossier temporaire inexistant avec intention WAL G4G/G4H et résultat déclaré G4I.
2. Il crée **un seul** script enfant Python constant `runner/g4k_synthetic_child_v1.py`, dont le code est compilé dans l'outil, et lance `sys.executable -I -B` sans shell, dans ce dossier.
3. Il capture le PID retourné, le code de sortie et les octets exacts stdout/stderr. La sortie doit correspondre à un nonce aléatoire de cette passe. Il publie une trace JSON canonique sans écraser de fichier existant et la recharge.
4. Les hachages du script et de la trace entrent dans les champs déjà existants du claim RSA G4J. La clé **existante** du portable signe seulement ce claim synthétique en mémoire ; la clé privée ne quitte pas Windows.
5. Le nouveau point d'entrée **en lecture seule** `ObsidiaGovernanceRuntime.inspect_c2_wal_synthetic_runner_observation` exige un reçu RSA G4J valide, le WAL et son outcome réellement relus, la trace structurée intacte, les octets actuels du script attendu et leur liaison exacte au claim signé.

**Statut d'un scénario valide :** `G4K_SYNTHETIC_SUBPROCESS_TRACE_MATCH_NOT_ATTESTED`, `HOLD`.

## Frontières de preuve

| Proposition | État après G4K |
|---|---|
| Un enfant Python **synthétique** a été lancé lors du test local | Observé par l'outil local, non attesté indépendamment |
| Les octets de trace et de script sont liés à la signature RSA G4J | Vérifiable avec le certificat public fourni et son empreinte attendue |
| Le véritable producteur historique C278 est authentifié | **Non** |
| L'exécution du véritable runner Obsidure est attestée | **Non** |
| L'enrôlement du certificat est approuvé par une autorité de confiance | **Non** |
| La personne responsable et l'approbation humaine sont vérifiées | **Non** |
| Les nonces sont enregistrés dans un registre anti-rejeu de confiance | **Non** |
| Une action C2, un rollback ou une reprise après crash sont autorisés | **Non** |
| Le contrôle souverain KX108 et l'état de release | **Inchangés : KX108_ONLY, HOLD** |

Une signature est une preuve de possession de la clé, pas une preuve de capture non falsifiable du processus. Les PID et la sortie sont des **observations déclarées par le lanceur**. G4K n'active aucune mutation réelle, aucun serveur, aucun connecteur et aucune restauration.

## Vérification attendue

- Régression complète `unittest` dans le worktree isolé.
- Contrats G1/G2 `pytest` dans le même worktree.
- Outil Windows `verify_g4k_synthetic_runner_windows_v1.ps1` : vérifie la machine/HEAD/worktree/certificat, lance un processus jetable fixe, signe les hachages de sa trace, vérifie via Python, puis nettoie **uniquement** ce dossier temporaire exactement nommé.
- Tests négatifs : modification du contenu, trace non canonique, clé/certificat erroné, hash signé substitué, mauvais PC, absence du script ou de la trace, sortie fabriquée, code retour enfant non nul et absence d'anti-rejeu.

`RELEASE=HOLD` tant que le vrai producteur C278 n'a pas été enrôlé et vérifié indépendamment, que l'observation d'exécution n'est pas issue d'un lanceur de confiance et que les preuves de récupération/rejeu ne sont pas closes.
