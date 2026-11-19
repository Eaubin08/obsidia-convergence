# G4C — Fermeture HMAC K1 des consommateurs PRE/POST

## Périmètre vérifié

Base : G4B `470ceff69781abb3cc9b27adc253eb9b622145ec`.
Source de travail : `assembly/g1_g2_runtime_v1`, **pas** le FIX actif de
`DESKTOP-Q5MD7J7`. `DESKTOP-SDOG0EL` reste le PC fixe ; aucun de ses
worktrees n'est touché. Cette branche n'active **aucun** runtime réel.

## Découverte P0

`verify_kx108_decision_record()` ne prouve que l'intégrité du hash. Un
adversaire qui peut fournir un record peut recalculer ce hash ; ce contrôle
ne prouve donc pas l'origine souveraine du record. Dans la base G4B, des
consommateurs au contact de l'écriture utilisaient ce contrôle structurel
seul malgré l'existence de l'authentification HMAC K1 du PRE.

| Frontière | Exigence G4C | Comportement en échec |
| --- | --- | --- |
| `validate_governed_apply_preflight` | PRE HMAC + enveloppe canonique | `PREFLIGHT_HOLD` sans lecture de la source |
| `run_governed_content_apply` | RECHARGER et REVALIDER HMAC PRE à la frontière | refus avant lecture source et écriture |
| `run_and_persist_kx108_post_execution_decision` | PRE HMAC avant appel kernel | `REJECTED`, `kx108_kernel_call_count=0` |
| Producteur POST | HMAC K1 posé **après** une invocation réelle | absence de clé → aucune publication du nouveau POST |
| `classify_post_execution_disposition` | POST HMAC + enveloppe canonique | `MUST_ROLLBACK`, jamais `KEEP_ELIGIBLE` |
| `run_governed_rollback` | PRE et POST HMAC | refus de restauration automatique si non vérifiables |

`TICKET_ELIGIBLE_PRODUCERS` **ne contient pas** le nouveau producteur POST :
un POST signé n'est pas un ticket souverain PRE et n'accorde aucune capacité
d'écriture. Le secret K1 n'est ni embarqué dans GitHub ni remplacé par une
clé par défaut. Les records historiques non signés ne sont **pas promus** :
ils échouent fermé sur ces frontières.

Les modules historiques de replay (`obsidia_governance_decision_replay_v1.py`
et `obsidia_canonical_receipt_replay_v1.py`) restent en analyse **structurelle
seule** pour compatibilité des rapports R8/R12. Leurs résultats ne sont **pas**
une attestation d'origine, un ticket ou une autorisation d'exécution. La
requalification de leur vocabulaire est une amélioration distincte.

## Tests et limites

Tests G4C dans `tests/integration/test_kx108_g4c_k1_auth_consumer_stdlib_v1.py` :
PRE forgé/re-hashé, frontière d'écriture même si preflight ment, POST ALLOW
non signé, POST signé par une clé **synthétique**, clé absente, refus de
rollback, appel kernel POST borné par doubles de test. Ils utilisent seulement
des répertoires temporaires et ne font pas d'APPLY réel.

Les anciens tests CLI basés sur des records historiques non authentifiés
doivent être revus pour refléter les nouveaux refus. Une validation Windows
de l'ensemble `unittest` reste nécessaire. Les replays R8/R12 n'attestent pas
le producteur de reçus C2 ni une isolation réelle du test.

**G1/G2 — FULL_FUNCTIONAL_HOLD**

**KX108_AUTHORITY — KX108_ONLY (inchangée)**

**GLOBAL_WRITE_CLOSURE — HOLD**

**RELEASE — HOLD ; aucune autorisation d'APPLY réel**
