# OBSIDIA Gouvernance — assemblage G1 + G2 (candidat V1)

## Objet

**Un seul produit / un seul point d'entrée logique** : `obsidia_governance_runtime_v1.py`.
Les composants en dessous sont des rails internes gouvernés, pas des moteurs
souverains concurrents. Le modèle distribué multi-runtimes demeure une
architecture **future** d'Obsidia global.

Le candidat assemble des sources effectivement récupérées sur GitHub sans
modifier aucun dépôt source des deux PC. Il **ne démarre pas de service** et
**n'active pas APPLY**. `execution_authorized` reste faux au niveau de la façade.

## Machine / provenance — noms gelés

| Machine | Identité | Source |
|---|---|---|
| **Portable** | `DESKTOP-Q5MD7J7` / `C:\Users\User` | K1 V5, 34 fichiers source, HEAD `d48c3a885fca4d09584f77c353fd725d104aa863` |
| **Fixe** | `DESKTOP-SDOG0EL` / `C:\Users\Aubin` | 4A1 / X108-CREATE / V01 C1 WORLD_ACTION |

Source GitHub : `Eaubin08/obsidia-convergence`, branche amont
`build/g1-g2-contract-merge-v0`, dossiers `imports/pc1-k1-v5-runtime*`
et `imports/pc2-governance-g1-g2`.

La preuve de provenance de **chaque fichier** est `ASSEMBLY_PROVENANCE.json`.
**33/34 fichiers K1 sont bit-à-bit identiques** à leur SHA256 importé.
La seule variante volontaire est `scripts/obsidia_kx108_decision_store.py` :
K1 HMAC et fonctions existantes conservés, extension WORLD_ACTION non autorisante.
Le Merkle 4A1 a également son SHA256 de source exact.

## Un runtime, plusieurs rails

| Rail interne | Source retenue | État dans le candidat | Autorise une mutation ? |
|---|---|---|---|
| Sigma / GuardX108 | Portable K1 | Évaluation directe d'un `DomainAggregate` | **Non** |
| KX108 K1 PRE/POST | Portable K1 V5 | Sources HMAC, tickets, preuve et rollback assemblées | **HOLD** (validation complète requise) |
| UPDATE existant | Portable K1 | `prepare_existing_update` délègue au préparateur canonique | **Non** (PREPARE seulement) |
| CREATE cible absente | Contrat G2 + PC2 CREATE | Protection canonique, absence de cible, chemins/jonctions | **Non** (préflight seulement) |
| WORLD_ACTION | V01 C1 + maintien K1 | Evidence append-only ; même un `ALLOW` construit par l'appelant est inéligible | **Non** |
| Merkle | Fixe 4A1 | Calcul de racine sans écriture du `merkle_seal.json` | **Non** |
| Write Closure | Fixe 4A1 | Variantes disponibles pour comparaison, **pas encore portées en APPLY** | **HOLD** |
| CLI / Obsidure / Ragnarok | Étapes ultérieures | Non raccordés, non démarrés | **Non** |

Le moteur K1 authentifié reste l'autorité. Ni `Sigma ALLOW`, ni une valeur
`x108_gate` transportée dans un message, ni la preuve WORLD_ACTION ne
constituent une permission d'exécution.

## Tests effectivement réalisés

- **26/26 PASS** : suites `unittest` autonomes (11 contrats du runtime,
  15 contrôles des collecteurs de dépendances, de la reprise C2 et des fins de ligne).
- **40 fichiers Python** analysés sans erreur syntaxique.
- Import des classes K1 `GovernedBoundedApply` et du pilote
  `prepare_governed_execution` : **PASS**.
- `pytest` **non disponible dans l'environnement d'assemblage Linux** :
  les tests K1/Windows, le handle V5 et les tests PC2 ne sont **PAS validés ici**.

Commande Windows / PowerShell, à exécuter uniquement après récupération de
la branche de build, sans lancer de service :

```powershell
$env:PYTHONPATH = (Resolve-Path ".\assembly\g1_g2_runtime_v1").Path
py -3 -B -m unittest discover -s .\assembly\g1_g2_runtime_v1\tests\integration -p 'test_unified_runtime_stdlib_v1.py' -v
py -3 -m pytest -q -p no:cacheprovider .\assembly\g1_g2_runtime_v1\tests\cli
```

Les tests `pytest` complémentaires de l'extension et de CREATE se trouvent
dans `tests/integration`. Ils restent à exécuter sur Windows avec `pytest`.

## Blocages contractuels avant release / investisseur

1. **Dépendances du projet non publiées dans les 34 sources** :
   `obsidia_candidate_patch_v1.py`, `obsidia_bounded_mission_v0.py`,
   `obsidia_mission_authority_v0.py`,
   `obsidia_mission_authority_integration_v0.py`, ainsi que
   `sigma/domains/*_agents.py` et `sigma/registry.py`.
   Ce candidat n'est pas une distribution autonome du système complet.
2. **Contrat CREATE** : raccorder le vrai producteur Jarvis et le PRE PC2 à
   K1 HMAC / HumanApproval ; refus des cibles existantes et recontrôle
   anti-TOCTOU au dernier point d'écriture.
3. **4A1 Write Closure** : revue des différences avec `obsidia_build.py`
   et preuve qu'aucune écriture ne contourne le rail canonique.
4. **WORLD_ACTION** : un producteur kernel attesté, vérification de l'identité
   du call et décision KX108 originale sont nécessaires avant tout egress.
   Le mode `EVIDENCE_ONLY` ne doit pas être promu implicitement.
5. **Gates Windows K1** : suite complète PRE/POST, HMAC, anti-rejeu,
   stable-handle V5, rollback, tests négatifs et preuves de fermeture.

**Verdict** : `ASSEMBLY_CANDIDATE_PASS` (structure, contrats locaux) ;
`FULL_FUNCTIONAL_G1_G2_HOLD` (aucun APPLY réel, aucune démo sécurité certifiée).

## Point d'entrée Python (observation, aucune mutation)

```python
from obsidia_governance_runtime_v1 import get_runtime
from sigma.contracts import DomainAggregate

runtime = get_runtime()
print(runtime.capabilities())
result = runtime.evaluate(DomainAggregate(
    domain="tooling_build", market_verdict="ACT",
    confidence=0.95, agent_votes=[]
))
assert result["execution_authorized"] is False
```

Le code doit être appelé avec `assembly/g1_g2_runtime_v1` dans
`PYTHONPATH`. Les sorties observées sont des preuves et des propositions,
pas une autorisation de production.

## Régression Windows étendue du 18 novembre 2026 — fermeture du packaging

Sur `DESKTOP-Q5MD7J7` : **100 PASS, 1 skip, 36 FAIL, 75 ERROR**.
Les traces des FAIL/ERROR observés concernent des imports `sigma.domains`
et d'anciennes références relatives `tests/cli/...` vers une fixture absente,
pas des assertions démontrant une brèche de KX108. **G1/G2 reste HOLD.**

Deux outils non souverains sont disponibles dans `tools/` :

1. `export_k1_missing_deps_portable_v1.py` — sur le **portable seulement**,
   sélectionne douze fichiers K1 attendus (+ deux `__init__.py` facultatifs),
   compare les empreintes et refuse les erreurs de machine, de branche,
   de chemin ou les secrets connus. Sans `--push`, il est en lecture seule.
   Avec `--push`, il publie les sources et leur manifeste dans la branche
   actuelle, sans modifier le worktree source.
2. `verify_windows_g1_g2_v1.ps1` — bloque si les dépendances restent absentes,
   se place temporairement à la **racine de l'assemblage** pour les anciennes
   fixtures `runpy.run_path("tests/cli/...")`, puis lance la suite pytest ;
   il ne démarre aucun serveur et ne modifie aucun FIX.

Depuis `C:\Users\User\obsidia-convergence` et sur une branche propre :

```powershell
git pull --ff-only
py -3 -B .\assembly\g1_g2_runtime_v1\tools\export_k1_missing_deps_portable_v1.py
# Si la vérification confirme les fichiers et leur caractère publiable :
py -3 -B .\assembly\g1_g2_runtime_v1\tools\export_k1_missing_deps_portable_v1.py --push
& .\assembly\g1_g2_runtime_v1\tools\verify_windows_g1_g2_v1.ps1
```

Le script d'export effectue un contrôle limité des secrets courants, **pas**
un audit exhaustif de confidentialité. Le dépôt étant **public**, consulter
la liste des douze fichiers avant `--push`.

### Complément C2 après le premier export (portable `ecaf6729`)

Le premier complément a publié 14 fichiers dans le commit `e36017dbe31beb103a6c2c7727beaa8ce82b2836`.
La nouvelle collecte Windows s'arrête sur :
`ModuleNotFoundError: obsidia_family_wiring_apply_bridge_v0`.
Ce n'est pas encore une assertion métier sur KX108 ; la collecte est bloquée
avant exécution des tests.

Le collecteur V2 `tools/export_k1_c2_bridge_deps_portable_v2.py` cible
le bridge et ses dépendances **statiquement identifiables** dans les
modules G1/G2 seulement ; il n'écrase aucun fichier déjà assemblé et
refuse une collecte excessive.

```powershell
git pull --ff-only
py -3 -B .\assembly\g1_g2_runtime_v1\tools\export_k1_c2_bridge_deps_portable_v2.py
# Vérifier la liste avant publication sur GitHub PUBLIC :
py -3 -B .\assembly\g1_g2_runtime_v1\tools\export_k1_c2_bridge_deps_portable_v2.py --push
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\assembly\g1_g2_runtime_v1\tools\verify_windows_g1_g2_v1.ps1"
```

Le test Windows ne doit être relancé qu'après un `G1G2_C2_BRIDGE_GITHUB_PUSH_PASS=True`.
Le mode `EVIDENCE_ONLY` et le veto `HOLD` sont inchangés.

### Complément C2 Obsidure — dépendance découverte après publication V2

Sur le **portable `DESKTOP-Q5MD7J7`**, la source bridge C2 a été publiée
au commit `ad127294b8a75f27f314b7fe01b23422685f9de6`, SHA256
`c15e7f4c255cd4648e20d4f5677b069dcafd452d29ac2ee4fb5f81e02ca2283c`.
Lors de la collecte Windows suivante, le bridge charge le validateur canonique
`scripts/obsidure_bounded_apply.py`, qui était absent de l'assemblage.
Le sélecteur V2 ne reconnaissait pas les imports `obsidure_*` : c'est une
erreur de fermeture de dépendances, **pas encore une régression fonctionnelle**.

L'outil V3 part du validateur C2 et suit statiquement ses dépendances
`obsidia_*`, `obsidure_*`, `sigma.*`, `periphery.world_calls.*`, avec seuils
stricts (**30 fichiers / 2,5 Mo**), manifestes SHA256 et exclusion des autres
composants. Aucune mutation de la source K1, aucun APPLY de production.

```powershell
cd "$env:USERPROFILE\obsidia-convergence"
git pull --ff-only
py -3 -B .\assembly\g1_g2_runtime_v1\tools\export_k1_obsidure_c2_deps_portable_v3.py
# Après lecture de la liste des fichiers destinés au dépôt PUBLIC :
py -3 -B .\assembly\g1_g2_runtime_v1\tools\export_k1_obsidure_c2_deps_portable_v3.py --push
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\assembly\g1_g2_runtime_v1\tools\verify_windows_g1_g2_v1.ps1"
```

Si le collecteur affiche `STOP=`, **ne pas forcer** la publication. Le
résultat des tests fonctionnels reste `HOLD` jusqu'à un PASS Windows réel.

### Reprise V4 du V3 arrêté avant commit (18/11/2026)

Le V3 a sélectionné `scripts/obsidure_bounded_apply.py`, empreinte SHA256
`4908e421a031752057a7b92c35ab942dafffb2b726f235be3fadb2bd86fca5cf`,
mais son `--push` s'est arrêté sur `git diff --cached --check`. **Aucun push V3
n'a été effectué.** Les deux chemins V3 (source + manifeste) sont restés
indexés localement. Le test Windows lancé ensuite a chargé cette copie locale
et signalé l'absence de `periphery.agents.agent_obsidure` : ce n'est toujours
pas une assertion fonctionnelle KX108.

Le récupérateur `tools/recover_c2_portable_v4.py` est conçu pour **cet état
indexé précis** du portable `DESKTOP-Q5MD7J7` :

1. Vérifie exactement les deux chemins indexés et leurs SHA256, la branche,
   l'URL du dépôt, le HEAD distant, et refuse toute modification annexe.
2. Analyse statiquement les imports Python du validateur Obsidure, y compris
   `periphery.agents.*`, les imports transitifs et les `__init__.py` utiles.
3. Sélectionne uniquement les fichiers Python manquants (50 fichiers/3 Mo
   maximum), sans importer leur code ni modifier le FIX source.
4. En `--push` uniquement, publie la source V3 déjà indexée avec les nouvelles
   dépendances et un second manifeste de provenance. La source K1 est conservée
   **octet par octet** : une anomalie de blancs préexistante ne doit pas être
   corrigée dans le FIX à l'occasion d'un transfert.

**Ne pas relancer V3 ; ne pas effacer ni désindexer ses fichiers.** Depuis la
racine `C:\Users\User\obsidia-convergence` :

```powershell
git pull --ff-only
py -3 -B .\assembly\g1_g2_runtime_v1\tools\recover_c2_portable_v4.py
# Relire la liste des nouveaux fichiers avant de publier sur le dépôt PUBLIC.
py -3 -B .\assembly\g1_g2_runtime_v1\tools\recover_c2_portable_v4.py --push
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\assembly\g1_g2_runtime_v1\tools\verify_windows_g1_g2_v1.ps1"
```

En cas de `STOP=`, ne pas forcer ; garder l'état local et partager la sortie.
`G1G2_C2_RECOVERY_GITHUB_PUSH_PASS=True` ne signifie que **publication des
sources**, pas validation fonctionnelle du runtime. Le vrai verdict G1/G2
reste `HOLD` jusqu'au passage de ses gates Windows et KX108.

#### Évolution de branche du FIX portable — même commit figé

Le portable a été observé sur `feat/gencoin-world-bus-dryrun-v1` avec le **même
HEAD `ecaf6729f1bcdb05bb8896b7c698d1ae90e56de7`** que le FIX K1 à la
collecte précédente. Le seul fichier modifié signalé par `git status -sb -uno`
est `periphery/world_calls/world_action_bus.py` (chantier parallèle).

Le récupérateur V4 reconnaît désormais **uniquement** les branches
`fix/kx108-zero-vote-guard-v1` et `feat/gencoin-world-bus-dryrun-v1`, à
condition que le HEAD reste exactement `ecaf6729` et que la source V3 garde
son SHA256 attendu. Il **exclut** `world_action_bus.py` et bloque toute autre
source sélectionnée qui serait modifiée ou non suivie, sans changer de branche
et sans toucher aux modifications concurrentes.

Après `git pull --ff-only`, réutiliser le même outil V4 en mode de contrôle,
puis en `--push` uniquement après revue de la liste de fichiers.

### Lecture de la régression Windows étendue — 18/11/2026

La commande de diagnostic qui ignorait directement la fixture C2 n'a **pas**
isolé la totalité de ses consommateurs. Plusieurs suites K1 chargent encore
`tests/cli/test_governed_content_apply_c2_v0.py` via `runpy.run_path()`.

Rapport de 7 171 lignes : `113 passed, 1 skipped, 37 failed, 75 errors,
3 subtests passed` (campagne non validante). Les **112 FAIL/ERROR** affichés
se classent exhaustivement ainsi :

| Cause observée | Nombre | Interprétation |
| --- | ---: | --- |
| `ModuleNotFoundError: periphery.agents` | 78 | Validation Obsidure complète requise par C2/K1 |
| `ModuleNotFoundError: sigma.base` | 33 | Base canonique Sigma absente du paquet assemblé |
| Différence CRLF/LF dans un test du collecteur | 1 | Test portable corrigé en écrivant les octets explicitement |

Ce comptage ne révèle **aucune assertion d'autorité KX108 évaluée puis
échouée** parmi ces 112 cas : ils sont bloqués par import ou par un test
de fins de ligne. Il ne prouve pas non plus l'absence de faille une fois
la stack canonique chargée.

**Décision :** arrêter l'extension automatique du paquet public de sources
Obsidure, qui dépasse les seuils bornés. Faire passer et publier les preuves
du socle effectivement autonome séparément ; conserver explicitement les
gates K1/C2 et leurs consommateurs transitifs en `HOLD`, sans les considérer
comme des PASS. Réexaminer ensuite un raccordement contrôlé au runtime
canonique complet, sans fusion par copie brute.

### Premier PASS Windows du socle autonome — 18/11/2026

Sur **le portable `DESKTOP-Q5MD7J7`**, depuis
`C:\Users\User\obsidia-convergence\assembly\g1_g2_runtime_v1` :

```powershell
py -3 -B -m pytest -q -p no:cacheprovider tests/integration
```

Résultat communiqué par l'exécution locale Windows :

```
70 passed, 1 skipped, 3 subtests passed in 0.47s
```

**Verdict borné : `G1_G2_AUTONOMOUS_INTEGRATION_TESTS_PASS`** pour la suite
`tests/integration` effectivement exécutée. Le cas skipped reste à qualifier
avant toute certification complète. Ce PASS ne valide ni la suite K1/C2,
ni le chargement de `sigma.base`/`periphery.agents`, ni l'APPLY production.

**Statut inchangé : `FULL_FUNCTIONAL_G1_G2_HOLD`.**
Les deux fichiers de l'export V3 restés indexés sur le portable ne sont pas
supposés publiés : ne pas les effacer ni réexécuter les collecteurs V3/V4
en `--push` sans une nouvelle revue de portée. Ne pas élargir automatiquement
le dépôt public à l'ensemble des dépendances transitives d'Obsidure.

### G2 — durcissement PRE CREATE des alias de chemins Windows (18/11/2026)

Le prédicat `_is_protected` du rail K1 effectue une comparaison de préfixe
sensible à la casse. Sous Windows, `Proofs/fichier` et `proofs/fichier`
peuvent pointer au même emplacement. Le contrat CREATE a donc été renforcé
**dans le candidat d'intégration uniquement** : double vérification de la
politique canonique (chemin exact + chemin `casefold`), refus des noms de
périphériques Windows, des points/espaces finaux, des alias potentiels 8.3,
des caractères interdits et des racines invalides. Toute ambiguïté mène à
`HOLD_CREATE_PRE`. Aucun `ALLOW`, aucune écriture de cible.

Preuve locale d'assemblage : **30 tests `unittest` autonomes PASS**, dont
4 nouveaux tests ciblés (Linux, Python 3.12), sans pytest ni source canonique
du FIX chargée. La suite Windows complète et les tests K1/C2 restent à
relancer après mise à jour du clone : le nouveau correctif **n'est pas encore
validé sur Windows**.

```powershell
cd "$env:USERPROFILE\obsidia-convergence"
git pull --ff-only
Push-Location .\assembly\g1_g2_runtime_v1
try {
    py -3 -B -m pytest -q -p no:cacheprovider tests/integration
} finally {
    Pop-Location
}
```

Le raccordement canonique Sigma/Obsidure reste un chantier distinct :
`sigma.base` et `periphery.agents` manquent au paquet autonome et la closure
Obsidure dépasse les limites de publication prévues. Ne pas créer de faux
substituts de ces modules et ne pas agrandir le dépôt GitHub public par
copie massive. Il faut définir et valider l'interface d'intégration réelle
avant de lever le `HOLD` complet.

### Windows : confirmation du durcissement CREATE — 18/11/2026

Exécution rapportée sur `DESKTOP-Q5MD7J7` après récupération du commit
`b61dc328b27305f1fede12926070f3f5855d6247` :

```
89 passed, 1 skipped, 17 subtests passed in 0.62s
```

**Verdict : `G1_G2_AUTONOMOUS_INTEGRATION_TESTS_PASS` confirmé sur Windows.**
Les 17 sous-tests couvrent notamment les refus des nouveaux chemins ambigus.
Le skip Windows (création de symlink sans privilège) est préservé et les
tests de jonction simulée restent exercés. La validation intégrale K1/C2 et
l'APPLY réel ne sont **pas** couverts par ce résultat.

### Prochaine frontière : relever les ABI canoniques sans exporter leur code

L'assemblage autonome ne contient pas les véritables modules `sigma.base`
et `periphery.agents`. Un export transitif complet d'Obsidure dépasse la
portée autorisée du dépôt public. Avant de dessiner un raccordement effectif,
`tools/inspect_canonical_k1_abi_portable_v1.py` inspecte **uniquement l'AST**
de six modules K1 sur le portable, à HEAD `ecaf6729...` : noms, paramètres,
imports statiques, tailles et empreintes SHA256. Il refuse les fichiers
modifiés par rapport au commit figé, les liens hors source et les mauvais PC.
Il n'exécute aucun module lu, ne démarre aucun serveur, ne copie aucune
source et ne modifie ni le FIX ni le dépôt d'intégration.

Depuis `C:\Users\User\obsidia-convergence` sur le **portable** :

```powershell
git pull --ff-only
py -3 -B .\assembly\g1_g2_runtime_v1\tools\inspect_canonical_k1_abi_portable_v1.py
```

Résultat attendu de contrôle : `K1_CANONICAL_ABI_READONLY_PASS=True` ou un
`STOP=...` expliquant précisément la pièce bloquante. La sortie contient des
signatures de fonctions et hashes, **pas le contenu des fichiers**. Ne pas
confondre cette inspection avec une validation fonctionnelle ni autoriser
les écritures sur cette base seule.

#### Reprise de l'inspection après déplacement du HEAD du FIX

Sur le portable, l'inspection V1 a retourné `STOP=SOURCE_HEAD_MISMATCH`.
Cela signifie **seulement** que le HEAD courant ne correspond plus à
`ecaf6729f1bcdb05bb8896b7c698d1ae90e56de7` : aucune preuve n'a été
produite que les six modules Sigma/Obsidure auraient changé.

Le garde est désormais précis au fichier : un HEAD plus récent est accepté
**uniquement si chacun des six fichiers** est identique octet pour octet à
son blob dans le commit K1 gelé **et** dans le HEAD courant. Aucun nouveau
HEAD n'est approuvé globalement. Le changement d'une seule source analysée
retourne `STOP=SOURCE_FILE_DIFFERS_FROM_FROZEN_K1_HEAD:<fichier>` ou
`STOP=SOURCE_FILE_DRIFT_FROM_CURRENT_HEAD:<fichier>`. La branche active et
les chantiers parallèles restent intacts, notamment `world_action_bus.py`.

Les contrôles locaux `unittest` sont passés à **35 PASS**, dont un nouveau
test avec un dépôt Git temporaire : avancement du HEAD sans changement des
modules = acceptation ; divergence de code du module = refus. Ce PASS prouve
le fonctionnement du garde, pas les signatures des sources canoniques qui
restent à lire sur le portable.

### ABI canonique : six sources vérifiées sur le portable — 18/11/2026

Le second relevé sur `DESKTOP-Q5MD7J7` a finalement produit :

```
CURRENT_HEAD=6fb69ec45e1aec31e382eee58510fe691ed27e7f
SOURCE_BRANCH=feat/gencoin-world-bus-dryrun-v1
K1_CANONICAL_ABI_READONLY_PASS=True
ALL_SIX_FILES_MATCH_FROZEN_K1_AND_CURRENT_HEAD=True
RELEASE_AUTHORIZATION=False
```

Les **six fichiers** ont la même identité octet par octet dans le FIX K1
gelé (`ecaf6729...`) et le HEAD courant de la branche Gencoin. Leurs SHA256
et **12 points d'entrée pertinents** sont gelés dans
`contracts/K1_CANONICAL_ABI_SNAPSHOT_20261118.json`. La concordance de ce
snapshot avec les six lignes `ABI=` du relevé Windows a été revérifiée :
**6/6 empreintes et 12/12 signatures conformes**.

| Rail | Points d'entrée observés | Décision d'intégration |
|---|---|---|
| Sigma | `BaseAgent.evaluate(state)`, `run_tooling_build_pipeline(state)` | Contrat identifié, implémentation canonique non chargée |
| Sigma registry | `get_sigma_domain(domain)`, `validate_sigma_registry()` | Contrat identifié, tests effectifs HOLD |
| Obsidure | `evaluate_repair_proposal`, `get_last_repair_runtime_evidence` | Capacité à examiner sans APPLY direct |
| Validateur C2 | `load_and_validate_proposal`, `dryrun_bounded` | Signatures identifiées, effets et retours à vérifier |
| Bridge C2 | `build_child_execution_from_obsidure_proposal` | Signature identifiée, raccordement fonctionnel HOLD |

Les méthodes `AgentObsidure.apply_proposal`, `run_bounded_apply` et
`run_obsidure_bounded_apply_pipeline` restent **non activées**. Une signature
AST n'établit ni les effets, ni les valeurs de retour, ni la compatibilité
des dépendances. La prochaine opération utile est un contrat de frontière
*observation/proposition → preuve PRE canonique*, suivi de tests négatifs
contre l'autorisation par avis Sigma ou par simple argument de l'appelant.

**Aucun module privé supplémentaire n'a été publié et `FULL_FUNCTIONAL_G1_G2_HOLD` reste en vigueur.**

### Frontiere Sigma → Gouvernance (candidat borné, sans APPLY)

`ObsidiaGovernanceRuntime.evaluate_tooling_build_advisory(votes)` raccorde
les classes **déjà assemblées** `sigma.contracts.AgentVote`,
`sigma.aggregation.aggregate_tooling_build` et `sigma.guard.GuardX108`.
Il ne crée ni nouvel algorithme souverain ni moteur concurrent.

| Entrée | Contrôle d'admission | Sortie |
|---|---|---|
| 0 vote | Agrégation K1 zéro-vote conservée | `BUILD_BLOCK`, aucune autorisation |
| 1–3 votes, plus de 4 votes, doublons | Quorum/identifiants refusés | `HOLD` |
| 4 votes distincts `tooling_build` consultatifs | Validation des types, domaines, autorité et signaux | Avis + gate observé, **jamais de ticket** |
| Contrat souverain injecté, domaine différent, confiance non finie | Refus de la frontière consultative | `HOLD` |

La sortie ne propage pas `ticket_id`, `decision_id`, `HumanApproval` ni
une enveloppe KX108 directement consommable. Même si le Guard observe
`ALLOW`, `execution_authorized=false` et `action_ticket_issued=false`.
Un vote `AgentVote` transmis par un appelant **n'est pas une preuve de son
origine** : cette étape valide le comportement de la frontière, pas les
agents Sigma canoniques absents (`sigma.base`, `sigma.domains`).

La provenance et les signatures d'Obsidure sont consignées dans
`contracts/K1_CANONICAL_ABI_SNAPSHOT_20261118.json`, mais **aucune méthode
Obsidure n'est importée, exécutée ni promue en APPLY**. Une inspection des
effets/retours du véritable `AgentObsidure` et du validateur C2 reste requise
avant le raccordement proposition → PRE canonique.

Tests autonomes :

```powershell
$env:PYTHONPATH = (Resolve-Path '.\assembly\g1_g2_runtime_v1').Path
py -3 -B -m unittest discover -s .\assembly\g1_g2_runtime_v1\tests\integration -p 'test_*stdlib_v1.py' -q
```

Sur l'environnement d'assemblage Linux : **41 tests unittest PASS** (dont
six nouveaux tests de frontière consultative). Le portable
`DESKTOP-Q5MD7J7` a également exécuté **41/41 PASS sur Windows** après
`git pull --ff-only` jusqu'au commit `bd93f6b`. Le circuit K1/C2 complet
reste à confirmer. **G1/G2 RELEASE HOLD**.

### Obsidure → KX108 PRE : risque de représentation et relevé d'effets

Inspection du pont **déjà publié**
`scripts/obsidia_family_wiring_apply_bridge_v0.py` : sa sortie
`BRIDGE_CHILD_READY` porte l'autorité `NON_SOVEREIGN` et
`write_capability=false`. Cependant, le pont **fixe actuellement**
`operation_type=UPDATE_TARGET_FROM_SOURCE`, même lorsque le fichier cible
est absent (`target_pre_sha256=None`). Cette ambiguïté ne doit jamais être
convertie silencieusement en CREATE : **HOLD contractuel avant KX108 PRE**.
Le pont attribue aussi temporairement `_OBA.PROPOSALS_DIR` globalement ;
l'absence d'effets de bord concurrents n'est pas démontrée. Il n'est **pas
appelé depuis le runtime unifié** à ce stade.

Le nouvel outil `tools/inspect_obsidure_effects_portable_v1.py` prépare la
preuve complémentaire sur le **portable DESKTOP-Q5MD7J7 uniquement**. Il :

- examine par AST **trois fichiers nommés** et leurs fonctions canoniques ;
- refuse les écarts aux SHA256, au commit gelé ou au HEAD courant ;
- émet seulement formes des retours, appels directs et indicateurs d'effets ;
- n'importe ni n'exécute aucun code source du FIX et n'en publie aucun octet ;
- ne certifie **pas** l'absence d'effets indirects (`INDETERMINATE_STATIC_ONLY`).

Depuis `C:\Users\User\obsidia-convergence` sur le **portable** :

```powershell
git pull --ff-only
$rapport = "$env:USERPROFILE\Downloads\OBSIDIA_OBSIDURE_EFFECTS_PORTABLE_20261118.txt"
py -3 -B .\assembly\g1_g2_runtime_v1\tools\inspect_obsidure_effects_portable_v1.py |
    Out-File -FilePath $rapport -Encoding utf8
Get-Content $rapport -Tail 10
```

Le fichier du rapport (sans corps de code) devra être examiné avant tout
raccordement Obsidure → PRE. **46 tests autonomes PASS en assemblage** après
l'ajout de cinq vérifications du relevé AST. Aucun changement de provenance
du FIX, aucune activation C2, aucun APPLY. **RELEASE HOLD.**

**Retour portable 18/11/2026** : après remplacement de `Tee-Object`
(`-Encoding` indisponible sur Windows PowerShell 5.1) par `Out-File`, le
rapport a été obtenu sur `DESKTOP-Q5MD7J7` avec HEAD
`2289e0ca2d36b20f3bbb64b0c8072e4f9833b423` : trois fichiers conformes
aux SHA256 gelés, `K1_OBSIDURE_EFFECTS_READONLY_PASS=True`,
`RUNTIME_BEHAVIOR_PROVEN=False`, `RELEASE_AUTHORIZATION=False`.

| Fonction canonique examinée | Constat AST (non preuve d'absence d'effets) |
|---|---|
| `AgentObsidure.evaluate_repair_proposal` | Appelle `test_repair_proposal`, qui nécessite une revue séparée de ses effets indirects ; met à jour des champs d'état de l'agent |
| `get_last_repair_runtime_evidence` | Forme de retour incluant statut, proposition, décision et `readonly` ; provenance à confirmer |
| `load_and_validate_proposal` / `dryrun_bounded` | Lecture de proposition ; retourne/actualise une `BoundedApplySession` |
| `run_bounded_apply` | Appelle `agent.apply_proposal` : **voie d'écriture à ne pas raccorder** |
| `run_obsidure_bounded_apply_pipeline` | Contient les appels d'APPLY, tests et reçus : **voie non activée** |
| `build_child_execution_from_obsidure_proposal` | Lit source/cible et modifie temporairement `_OBA.PROPOSALS_DIR` ; CREATE/UPDATE ambigu : **HOLD** |

L'analyse sur le portable ne couvre pas les variantes Obsidure des **autres
branches, dépôts ou worktrees**. Le choix d'une source canonique globale
reste ouvert : ne rien remplacer par simple copie d'un fichier tiers.

### Obsidure F7 → façade unique : admission PRE sans autorisation (build isolé)

`ObsidiaGovernanceRuntime.admit_obsidure_bridge(...)` reçoit **un résultat**
du pont C2 déjà identifié `build_child_execution_from_obsidure_proposal`.
Le pont lui-même et les agents F7 **ne sont ni importés ni exécutés** : leur
fermeture de dépendances et les effets indirects restent non démontrés. Un
appelant peut forger ce résultat ; l'admission n'établit donc ni la provenance
authentique de la proposition ni une approbation humaine. La sortie positive
est strictement `OBSIDURE_PRE_ADMISSION_READONLY`, sans droit d'APPLY.

| Rail | Vérification effectuée | Statut / frontière |
|---|---|---|
| Obsidure C2 → enfant | Forme connue du bridge, `NON_SOVEREIGN`, `write_capability=false`, opération `PLANNED`, aucun champ d'autorité injecté | Proposition seulement |
| K1 source → cible | Chemins Windows littéraux et bornés, protections K1, absence de lien/jonction, identité de racine, SHA256 complet réel de la source | Contrôle lecture seule |
| `UPDATE_TARGET_FROM_SOURCE` | Cible réellement existante, pré-image SHA256 complète et intacte | Admission sans mutation |
| `CREATE_TARGET_FROM_SOURCE` | Cible réellement absente, PRE K1 CREATE appelé sans APPLY | Admission sans mutation |
| Ancien pont C2 : UPDATE + cible absente | **Aucune conversion implicite vers CREATE** | `HOLD` |
| Sigma, HumanApproval, KX108 PRE/POST, ticket HMAC | Non invoqués ; une valeur `ALLOW` fournie par un appelant ne confère aucun droit | **Exécution `HOLD`** |

**Décisions de sélection F7** (issues de l'inspection des diffs locaux R10/R12) :

- Conserver les propositions et la validation bornée comme **candidates**,
  sans remplacer l'implémentation K1 de `injected_operations`.
- Ne pas importer `AgentObsidure.apply_proposal`, `run_bounded_apply` ni le
  handoff R12 dans ce build : appels possibles à `shutil.copy2`, `mkdir`,
  écritures JSON et `write_bytes` ; pas de preuve PRE→POST complète.
- `LeanSandbox` R12 référence un `REPO_ROOT` global plutôt que `self._root`
  dans une voie : isolation à corriger séparément avant tout essai d'APPLY.
- Le chemin R12 de reprise renseigne un indicateur de confirmation humaine
  dans le code et le handoff contient `hash-dummy` : aucune valeur de ces
  chemins ne peut servir de preuve d'approbation.

Commande de validation locale, sans serveur ni mutation de cible :

```powershell
cd "$env:USERPROFILE\obsidia-convergence"
$env:PYTHONPATH = (Resolve-Path '.\assembly\g1_g2_runtime_v1').Path
py -3 -B -m unittest discover -s .\assembly\g1_g2_runtime_v1\tests\integration -p 'test_*stdlib_v1.py' -q
```

La fermeture des dépendances F7, les tests Windows, le raccordement de la
véritable sortie C2, les preuves HumanApproval, PRE/POST KX108 et la protection
au point d'écriture restent à traiter. **Un seul runtime, `RELEASE HOLD`.**

### Obsidure F7/R10 : ingestion native RepairRequest → RepairVerdict

**Source de contrat revue** : dépôt `Eaubin08/obsidia-x108-proofs`, branche
`codex/obsidure-f7-r10-isolated`, fichiers :

- `periphery/agents/obsidure_repair_contract.py` : structures sérialisées
  `RepairRequest`, `RepairProposal`, `RepairCandidateFile`, `RepairVerdict`,
  frontière `REPAIR_BOUNDARY`, cibles autorisées et protégées ;
- `scripts/obsidure_repair_r9_adapter_v1.py` : liaison des identifiants
  request/proposal/C278/verdict, hash des artefacts testés, contrôle de base ;
- `scripts/obsidure_governed_patch_prepare_adapter_v1.py` : chemin R9 de
  préparation réutilisé, distinct de toute autorisation ;
- `OBSIDURE_DIFF_G1G2_20261118_231613.zip` (portable) : écarts locaux F7
  R10/R12/R12-F6, **pas une source complète à substituer**.

Le nouvel appel **sur la même façade** est
`ObsidiaGovernanceRuntime.inspect_obsidure_r10_repair(...)`. Ses entrées
sont les dictionnaires sérialisés par les classes F7 existantes, sans
chargement d'agent F7, sans script ajouté à la CLI et sans demande à
Ragnarok.

| Contrat F7 | Contrôle appliqué | Interprétation |
|---|---|---|
| RepairRequest/RepairProposal/C278/RepairVerdict | Autorité `KX108_ONLY`, aucun auto-apply ; identifiants cohérents ; C278 `CONTINUOUS` et verdict `PASS` | **Déclarations inspectées**, origine non attestée |
| RepairCandidateFile | Contenu complet, `change_kind=MODIFY/CREATE`, cible et extension dans le scope F7+K1 | Proposition seulement |
| `tested_artifacts[]` | Identités exactes, SHA256 complet du contenu UTF-8, absence de doublon | Contrôle de substitution |
| MODIFY | Cible existante, absence de reparse, SHA256 de base réel, différence effective | Inspection lecture seule |
| CREATE | Préimage absente, G2 preflight canonique, aucun fichier créé | **Ne convertit pas vers le rail R9 UPDATE** |
| Handoff / HumanApproval / KX108 / R8 replay | Non appelés ; `r9_prepare_executed=false` | **HOLD exécution** |

Cette frontière ne valide **pas** la provenance réelle du sandbox : un appelant
peut encore fabriquer `PASS` et `CONTINUOUS`. Elle ne fabrique jamais de
ticket HMAC, de décision PRE, ni d'approbation humaine. Le contrôle SHA du
fichier cible est un instantané : il devra être refait sous verrou au point
d'écriture. Le R9-B1 historique prépare des fichiers mais ne supporte pas
CREATE sur cible absente ; aucune adaptation implicite n'a été créée.

F7 R12 reste exclu des entrées exécutables : `LeanSandbox` dépend d'une
racine globale dans une voie, le handoff R12 contient un hash factice et
la reprise R12 fabrique un booléen de confirmation humaine. Les capacités
de réparation/replay pourront être reprises **après** tests et attestation
de provenance, sans substitution de source K1.

Tests : `test_obsidure_r10_repair_intake_stdlib_v1.py` couvre l'acceptation
lecture seule, CREATE absent, refus des liens, de l'identité incohérente,
des SHA modifiés, des cibles protégées et d'un résultat synthétique.
Résultat Windows transmis depuis le portable `DESKTOP-Q5MD7J7` :
`Ran 68 tests`, `OK (skipped=3)` sur
`build/g1-g2-obsidure-r10-intake-v1`. Trois cas liés aux privilèges de
symlink Windows ne sont pas validés sur cette machine. Ce passage ne lève
pas le `RELEASE HOLD`.

### Obsidure F7/R12 ↔ preuves canoniques R8 (build isolé, lecture seule)

Le même `ObsidiaGovernanceRuntime` expose désormais
`inspect_obsidure_r12_r8_outcome(...)` ; **aucun deuxième moteur ni CLI**.
Il reçoit l'inspection R10, la préparation R9 sérialisée et l'identifiant
historique `action_evidence_id` d'un reçu R8 déjà persisté. Il appelle
directement les fonctions canoniques :

| Vraie API R8 source | Rôle dans ce rail |
|---|---|
| `load_canonical_receipt_envelope` | Lire le reçu et valider sa structure/hash |
| `replay_action_evidence` | Vérifier l'intégrité historique |
| `replay_governance_decision` | Rejouer seulement la décision historique figée |
| `reconcile_action_evidence` | Confronter historique autorisé et observation persistée |

Provenance : `Eaubin08/obsidia-x108-proofs`, branche
`codex/obsidure-f7-r10-isolated`, chemins `scripts/` des quatre modules
canoniques ainsi que leur dépendance
`obsidia_kx108_policy_identity_v1.py`. Voir
`R12_R8_SOURCE_PROVENANCE_V1.json` pour les identifiants Git et empreintes.
Le code source de `obsidia_canonical_receipt_envelope_v1.py` inclut un
writer canonique, mais **la façade R12 n'appelle que son loader et sa
validation**. Les modules de replay/reconciliation ne sont utilisés que
pour lire des preuves existantes.

Gates et refus :

| Situation | Traitement |
|---|---|
| Identifiant malformé, stores/symlink non sûrs, R10/R9 absents | `HOLD` |
| Lien repair/build/v2 incohérent | `GOVERNANCE_MISMATCH`, `STOP_BLOCKED` |
| Reçu au hash modifié, replay contradictoire | `EVIDENCE_TAMPERED`, `STOP_BLOCKED` |
| Preuve manquante ou `VERIFIED_WITH_LIMITS` | `EVIDENCE_INCOMPLETE`, `ESCALATE` |
| Incertitude post-dispatch | `DISPATCHED_OUTCOME_UNCERTAIN`, `ESCALATE` |
| Preuves canoniques exhaustives et cohérentes | Avis historique seulement, **jamais autorisation** |

Tests isolés Linux : 81 tests `unittest` OK (68 tests antérieurs + 13
nouveaux). Les nouveaux tests exercent les **vrais** modules canoniques
avec des reçus de test jetables ; un reçu incomplet au hash valide est
classé contradictoire, jamais accepté par confort. Les mocks sont
employés seulement pour éprouver la politique de refus des preuves limitées,
pas pour prétendre vérifier un replay R8 positif de production.

Un test supplémentaire réutilise le générateur du test canonique
`tests/test_r8_b3_evidence_only_replay.py` (source F7, copie fixture
`tests/r8_b3_fixture_upstream.py`) dans un répertoire temporaire. Avec
les références descriptives, approbation, décision KX108 et preuve post-état
cohérentes, les trois **vrais** vérificateurs retournent respectivement :
`VERIFIED_WITH_LIMITS`, `MATCH`, `MATCH`. La façade R12 conserve
`EVIDENCE_INCOMPLETE` / `ESCALATE`, notamment parce que Binder n'est
pas persisté séparément et que la version de politique n'est pas liée.
Ces preuves sont **synthétiques pour test**, pas un reçu de production.

**Non validé** : succès réel R8 sur preuve attestée de production,
gates Windows R12, provenance sandbox C278, préparation R9 complète,
HumanApproval, PRE/POST KX108, TOCTOU au point d'écriture.
`FULL_FUNCTIONAL_G1_G2_HOLD` / `RELEASE HOLD` inchangés.

### R8 D3 / V2_APPLY_PATCH : reconstruction du Binder, toujours sans APPLY

La branche isolée `build/g1-g2-r12-r8-apply-patch-binder-v1` valide la
reconstruction du Binder **sur son contrat canonique** `V2_APPLY_PATCH`,
sans confondre ce contrôle avec une décision d'exécuter ou une attestation
d'origine. Le contrôle mobilise le véritable
`run_tooling_build_pipeline(ToolingBuildState(...))`, et les trois replays R8.

Deux dépendances Sigma minimales sont reprises de
`Eaubin08/obsidia-x108-proofs` / `codex/obsidure-f7-r10-isolated` :

| Fichier canonique | SHA256 de la copie de convergence | Usage |
|---|---|---|
| `sigma/base.py` | `6f344dcd0e3e253d0c7d1d50fb42aaa0869c47cafbc39e00e3d3d1e093e9b4b8` | Classe de base des agents Sigma |
| `sigma/utils/indicators.py` | `e0ffe9f20acbc82c1e8cbc6326776f4f852430917a86a9e00340d7c8a6603990` | Import des agents trading existants |

Le module `sigma/protocols.py` conserve inchangé le corps de
`run_tooling_build_pipeline`. Seul le chargement du registre Sigma et du
domaine e-commerce est différé jusqu'à leur utilisation : le replay
`tooling_build` ne doit pas importer `periphery.ecom_attestation` et sa
chaîne de dépendances hors périmètre. Aucune simulation de ce service n'est
ajoutée ; le domaine e-commerce reste à raccorder en intégration globale.

| Preuve isolée (fixture **synthétique**) | R8 intégrité | R8 décision | R8 état | R12 |
|---|---|---|---|---|
| `V2_APPLY_PATCH`, décision Sigma correspondante, Binder reconstruit | `VERIFIED` + `RECONSTRUCTED_MATCH` | `MATCH`, Binder `YES`, politique à couverture bornée | `MATCH` | `EVIDENCE_INCOMPLETE`, `ESCALATE` |
| Dérive de politique simulée | `CONFLICTING` | Non exploitable | Non exploitable | `EVIDENCE_TAMPERED`, `STOP_BLOCKED` |
| Enregistrement KX108 retouché malgré un hash recalculé | Ref KX108 refusée | Non exploitable | Non exploitable | `EVIDENCE_TAMPERED`, `STOP_BLOCKED` |
| Identité R9/Builder différente | Sans replay utile | Sans replay utile | Sans replay utile | `GOVERNANCE_MISMATCH`, `STOP_BLOCKED` |

Test : `tests/integration/test_r12_r8_apply_patch_binder_stdlib_v1.py`
(4 cas). Résultat local Linux : **85 tests, OK**, sans serveur, sans
application de patch et avec seules écritures dans des dossiers de tests
temporaires. Gate Windows portable encore à vérifier. Le `ALLOW` KX108 de
la fixture est une **donnée synthétique**, jamais une décision de production.
L'identité de politique reste `BOUNDED_SOURCE_FINGERPRINT` ; le verdict
R12 ne peut donc pas promouvoir une preuve test en succès de production.

**Interdits maintenus** : provenance synthétique prise pour HumanApproval,
appel `execute`, mutation d'une cible réelle, retry automatique, deuxième
runtime. `RELEASE HOLD` / `FULL_FUNCTIONAL_G1_G2_HOLD`.

### R9 PREPARE canonique → R12 : contrôle de provenance **non attestée**

Dans **le même** `ObsidiaGovernanceRuntime`, le nouveau rail
`inspect_obsidure_r9_preparation(...)` reçoit un résultat R9 déjà préparé
et les objets **typés** Proposal, Manifest, Validation et Handoff.
Il lit, sans créer ni modifier de fichier, les artefacts existants
`v2exec/<v2_exec_id>.json` et `.patch`. Il ne lance **pas**
`adapt_validated_repair_to_r9_prepare`, `pc_v2_apply_patch_prepare`,
`git apply`, KX108, Obsidure APPLY ou de serveur.

Les contrats sources ont été inspectés dans
`Eaubin08/obsidia-x108-proofs` / `codex/obsidure-f7-r10-isolated` :
`obsidure_repair_r9_adapter_v1.py`,
`obsidure_governed_patch_prepare_adapter_v1.py` et
`obsidia_pc_capabilities_v2.py`. Quatre modules canoniques de **données et
validation** ont été recopiés à l'identique, sans leurs adaptateurs à effet :

| Module canonique R9 | Git blob SHA-1 de la source | Fonction retenue |
|---|---|---|
| `obsidure_builder_proposal_v1.py` | `4b47aa603ae38bd32d912e2674f747ed5e583a06` | Proposition et liaison du patch |
| `obsidure_proposal_manifest_v1.py` | `714cde287e88f46e5705f43af2efdbb3a6eab805` | Artefacts et preuves déclarées |
| `obsidure_proposal_validation_v1.py` | `5bdff4246e69f391c366497beabc6c29b0c2ff37` | Replay de validation et obligation de test |
| `obsidure_governance_handoff_v1.py` | `02faadee8f234b3d127c333d02b2c32ab232f2e7` | Handoff et identité de dépôt |

Voir `R9_R12_PREPARE_PROVENANCE_V1.json` pour SHA256 complets et portée
de la copie. Les originaux privés ne sont ni exécutés ni modifiés.

| Liaison contrôlée | Fail-closed |
|---|---|
| R10 Repair IDs → Handoff/R9 | Identité différente : `HOLD` |
| Proposition → Manifest → Validation → Handoff | Identifiant, validation ou obligation de test falsifiés : `HOLD` |
| R9 → patch V2 déjà persisté | SHA, ordre des cibles, scope, préimages ou chemin dangereux : `HOLD` |
| R9 → descripteur V2 déjà persisté | JSON dupliqué, symlink, dérive, EAH, ID enfant ou lignée Builder incohérents : `HOLD` |
| R9 → R12/R8 historique | Préparation manquante : pas de replay ; reçus R8 absents/contradictoires : `HOLD` |

`inspect_obsidure_r9_r12_outcome(...)` dérive les références R9 depuis
les artefacts canoniques inspectés et les transmet à **l'ancien rail R12**.
Il refuse toute élévation d'une concordance historique en permission
d'exécution. Un résultat `R9_PREPARE_BINDING_MATCH_UNATTESTED` signifie
uniquement que **les octets, identifiants et contrats se correspondent** :
ni sandbox C278 réelle, ni `git HEAD` courant, ni HumanApproval, ni
KX108 PRE/POST ne sont attestés.

Tests isolés : `test_obsidure_r9_prepare_provenance_stdlib_v1.py`
exerce les types **réels** et des artefacts V2 **synthétiques** en répertoire
temporaire ; 9 cas, dont ordre multi-fichier non trié, usurpation
d'autorité, substitution de scope, double clé JSON et changement de patch.
Suite intégration locale Linux : **94 tests, OK**. Test Windows portable
à réaliser sur branche isolée ; aucun test de mutation réelle ou de
provenance sandbox n'a été effectué.

**Etat : `R9 PREPARE BINDING VERIFIED / SANDBOX ORIGIN UNATTESTED / RELEASE HOLD`.**

### C278 → sandbox Obsidure → R9 → R12 : observation indépendante

Suite à la validation de 94 tests (89 OK, 5 ignorés sous Windows sur le
portable **`DESKTOP-Q5MD7J7`**, commit `2fb8c35`), la frontière suivante
ajoute deux fonctions au **même** `ObsidiaGovernanceRuntime` :

- `inspect_obsidure_c278_sandbox(...)` : rejoue le vrai validateur
  `validate_proposal_meaning` sur les données RepairRequest/RepairProposal,
  compare le **record C278 complet** à la sortie canonique et relit les octets
  actuels des fichiers `RepairVerdict.tested_artifacts[]` dans la sandbox.
- `inspect_obsidure_c278_r9_r12_outcome(...)` : exige d'abord le contrôle
  C278/sandbox, puis le contrôle R9/PREPARE existant ; **reconstruit en mémoire**
  le diff de chaque candidat `MODIFY` depuis son contenu et sa préimage
  dans le worktree d'exécution, afin de comparer exactement le patch R9.
  Seul ensuite le replay historique R12/R8 est consulté.

| Contrôle ajouté | Refus ou borne |
|---|---|
| Record C278 complet vs validateur canonique | `CONTINUOUS` forgé, champs ou checks changés → `HOLD` |
| Répertoire sandbox historique | Racine différente, chemin ou lien/junction → `HOLD` |
| Fichiers candidats observés | SHA, fichiers, scope ou préimage drift → `HOLD` |
| Tests rapportés dans `RepairVerdict` | Test absent, `FAIL`, returncode non entier ou ordre divergent → `HOLD` |
| Patch R9 reconstruit depuis les fichiers réels | Diff différent ou `CREATE` introduit en UPDATE → `HOLD` |
| Correspondance positive | `C278_SANDBOX_BYTES_MATCH_UNATTESTED` ; jamais autorisation |

La source C278 et son contrat de réparation sont repris depuis
`Eaubin08/obsidia-x108-proofs` / `codex/obsidure-f7-r10-isolated` :
`periphery/language/proposal_meaning_validator.py` et
`periphery/agents/obsidure_repair_contract.py` (seules fins de ligne
normalisées). Le producteur historique
`periphery/agents/obsidure_repair_bridge.py::test_repair_proposal` a été
inspecté **sans exécution** : il écrit les candidats dans
`_EPHEMERAL_REPAIR_SANDBOX_*`, puis renseigne des statuts de test déclarés,
mais **ne signe pas ses verdicts**. Les détails exacts de provenance Git et
SHA sont dans `C278_SANDBOX_OBSERVATION_PROVENANCE_V1.json`.

Les observations ne peuvent donc **pas** attester l'identité du processus
testeur, son isolation effective, la date historique du test, ni le commit
Git réel. Un `PASS` ou `FULL` historique n'est jamais promu en preuve de
production. Les sous-chemins et empreintes restent sujets au TOCTOU entre
observation et éventuelle écriture. L'exécution est toujours bloquée.

Tests locaux Linux : **107 tests, OK** (94 précédents + 13 nouveaux),
dont un raccord synthétique C278 → R10 → R9 → R12 qui reste en HOLD
lorsqu'un reçu R8 manque, ainsi que les refus de modification de sandbox,
de patch incohérent, de faux statut et de tentative de symlink. Les fixtures
sont synthétiques et créées exclusivement dans des répertoires temporaires.

**Bloqueur de la prochaine frontière :** pour prétendre à une provenance
réelle, il faut un producteur de preuve authentifié au moment des tests,
avec enregistrement de l'identité runner, du commit, du digest de sandbox,
du transcript et de la liaison C278/R9, puis une vérification indépendante.
Ce contrat n'existe pas encore dans les sources inspectées. **`RELEASE HOLD`**
et `KX108_ONLY` restent inchangés.

### C278 : contrat de reçu HMAC détaché (vérification seule, provenance HOLD)

Après le **PASS Windows portable `DESKTOP-Q5MD7J7`** sur la branche
`build/g1-g2-c278-r9-r12-sandbox-observation-v1` (commit `85cd5cf` :
**107 tests OK, 6 ignorés**), le chantier suivant formalise la frontière
cryptographique **sans fabriquer de preuve historique**.

L'entrée `ObsidiaGovernanceRuntime.inspect_obsidure_c278_signed_receipt(...)`
réutilise obligatoirement le contrôle C278 + sandbox réel en lecture seule,
puis vérifie une enveloppe détachée `{payload, hmac_sha256}` avec un secret
**Obsidure distinct de la clé HMAC souveraine KX108/K1**. Le code présent
est **uniquement vérificateur** : aucun runner historique, producteur signé,
magasin de clés ni serveur n'a été activé.

| Contrat vérifié | Limite conservée |
|---|---|
| `issuer_id`, `key_id`, schéma et liste exacte des champs | La configuration de l'émetteur est fournie par l'appelant ; aucun certificat de runner |
| HMAC-SHA256 avec séparation de domaine | Authentifie seulement la possession du secret fourni ; jamais la source de ce secret |
| IDs Request / Proposal / Verdict et SHA256 de leurs objets canoniques | Refuse un remplacement de lignée ou de C278, pas une fausse exécution originelle |
| SHA256 des candidats vérifiés contre les fichiers de sandbox présents | La sandbox pourrait avoir été réécrite après les tests historiques |
| `source_git_head`, digest code runner, digest transcript | Champs couverts par le MAC mais **non recoupés** avec un Git HEAD vivant ou un témoin de test indépendant |
| Nonce de 256 bits dans le reçu | **Pas d'antirejeu garanti** sans registre monotone persistant |
| Champ `execution_authorized`, champ supplémentaire ou clé souveraine déguisée | Refus `HOLD` |

Une correspondance retourne **`C278_RECEIPT_HMAC_MATCH_ORIGIN_UNATTESTED`**,
avec `receipt_hmac_verified=True` et **tous les attributs d'attestation,
approbation humaine, release et exécution à `False`**. Un reçu n'est donc
jamais un ticket KX108. Une clé de test synthétique est utilisée **uniquement
dans les fixtures** ; aucune clé réelle n'est écrite dans le dépôt.

Gates de suite avant tout statut `ATTESTED` :

1. Choisir et auditer un **runner Obsidure réel** capable de signer au moment
   de l'exécution, avec identité et stockage de clé autonomes (pas la clé K1).
2. Relier le digest transcript aux tests effectivement lancés, le HEAD Git
   vivant et le code du runner via un témoin indépendant.
3. Implémenter un registre anti-rejeu robuste, contrôler la durée de vie et
   la révocation des clés et vérifier le comportement Windows.
4. Repasser la chaîne entière R10 → C278 → R9 → R12 puis les gates KX108
   PRE/POST et HumanApproval, sans raccourci d'autorité.

**`RELEASE HOLD` / `FULL_FUNCTIONAL_G1_G2_HOLD` maintenus**. Ce jalon
construit le vérificateur et les tests négatifs, **pas** le signer ni une
autorisation d'action. Voir `C278_SIGNED_RECEIPT_PROVENANCE_V1.json`.

### Identité Obsidure **par machine**, préparée pour la gouvernance d'équipe

**Décision d'architecture de l'utilisateur (19/11/2026)** : une identité
cryptographique **distincte pour chaque PC**, et la possibilité de relier
plus tard plusieurs responsables à une machine. Pas de secret HMAC partagé
entre les postes comme source de confiance inter-PC. Un témoin central n'est
pas retenu pour ce premier jalon.

| Machine | Origine réelle | Enrôlement | Rôle proposé |
|---|---|---|---|
| `DESKTOP-Q5MD7J7` | **Portable**, `C:\Users\User` | `PLANNED` | Producteur de preuve Obsidure |
| `DESKTOP-SDOG0EL` | **Fixe**, `C:\Users\Aubin` | `PLANNED` | Producteur de preuve Obsidure |
| Futurs membres de l'équipe | Nouvelle machine, nouvel identifiant et clé distincte | Revue nécessaire | Rôle attribué séparément |

**Deux objets différents, deux contrôles différents :**

1. **Identité technique du poste** : certificat public épinglé, clé privée
   locale non exportable et preuve signée. Le nom `DESKTOP-...` reste une
   identité **déclarée**, pas une attestation matérielle.
2. **Responsabilité humaine** : références de personnes et rôles revus
   séparément ; la présence d'un responsable dans le registre n'est **pas**
   une HumanApproval pour une opération.

Le plan versionné `OBSIDURE_MACHINE_IDENTITY_PLAN_V1.json` énumère uniquement
les deux PC connus. Il ne contient **ni clé privée, ni certificat déjà
enrôlé, ni personne inventée**. Le validateur
`inspect_obsidure_machine_identity_registry(...)` rejette les doublons de
machines et de clés publiques, les rôles souverains, les statuts inconnus,
les preuves de révocation manquantes et les changements de SHA. Il retourne
toujours `MACHINE_REGISTRY_STRUCTURE_VALID_NOT_TRUSTED` même si la structure
est conforme : un dépôt Git public **n'est pas** une racine de confiance.

`tools/enroll_obsidure_machine_identity_windows_v1.ps1` expose deux modes :

- **Par défaut (aucun argument)** : inventaire **lecture seule** du magasin
  `Cert:\CurrentUser\My`, restreint au PC reconnu. Ne crée aucune clé.
- **`-Enroll` (action explicite et persistante)** : crée, si aucune identité
  Obsidure n'existe déjà pour ce poste, un certificat RSA 3072 avec clé
  privée `NonExportable` dans le magasin utilisateur Windows ; n'exporte
  **que la partie publique** vers `Downloads/OBSIDURE_PUBLIC_IDENTITY_<PC>.json`.
  Le dossier et le fichier d'origine du FIX ne sont pas modifiés.

Ce choix emploie les API Windows natives `New-SelfSignedCertificate` et les
certificats utilisateur. Un certificat auto-signé ne prouve pas à lui seul
l'origine matérielle du poste ; `NonExportable` est une politique du stockage
logiciel Windows, **pas** une garantie TPM. Le fichier public produit est une
**proposition à examiner**, pas une identité déjà approuvée.

Références d'API officielles :
https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate
et https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.signdata

**Suite ordonnée :** contrôle Windows lecture seule de l'enrôleur ; enrôlement
explicite du portable après revue ; inscription du certificat public dans une
politique de confiance **ancrée indépendamment de GitHub** ; validation d'une
signature asymétrique sur un reçu émis **au moment réel des tests** ; révision
des rôles/révocations ; ensuite seulement réexamen du parcours C278 → R9 → R12.

Le rail HMAC détaché précédent reste un **prototype de vérification non
autorisé** ; il n'est pas utilisé pour partager un secret entre les machines.
`KX108_ONLY`, `RELEASE HOLD`, aucune signature réelle, aucune HumanApproval
et aucun `APPLY` sont maintenus.

### Portable : preuve locale RSA, puis vérification publique C278 (nouveau rail)

**Observations Windows fournies le 19/11/2026 par le propriétaire du portable** :

| Poste | Vérification réelle | Limite |
|---|---|---|
| `DESKTOP-Q5MD7J7` — portable, `C:\Users\User` | Certificat RSA-3072 créé dans `Cert:\CurrentUser\My`, clé privée non exportée, certificat public comparé au magasin Windows | `ENROLLED_AWAITING_REVIEW`, aucune identité humaine ou matérielle attestée |
| `DESKTOP-Q5MD7J7` | Challenge synthétique signé et vérifié localement ; modification du challenge refusée | Pas un reçu de test C278, pas une provenance du runner |
| `DESKTOP-SDOG0EL` — fixe, `C:\Users\Aubin` | Pas d'enrôlement observé à ce jalon | Ne pas lui attribuer la clé du portable |

Empreinte **publique déclarée et vérifiée sur le portable** :
`5bb3f8688930de497254185292a49b46c2f88b0bb23cf259711e86981932c398`.
Le certificat public complet reste dans
`C:\Users\User\Downloads\OBSIDURE_PUBLIC_IDENTITY_DESKTOP-Q5MD7J7.json`,
**pas dans le dépôt public**. Cette empreinte ne vaut pas validation
d'enrôlement par un responsable indépendant.

`ObsidiaGovernanceRuntime.inspect_obsidure_c278_machine_rsa_receipt(...)`
ajoute un vérificateur **en lecture seule**, distinct du prototype HMAC.
Son contrat exige :

1. Le certificat DER public en base64, son SHA256 attendu et le nom exact de
   machine, chacun fournis par une politique distincte du reçu ; sinon `HOLD`.
2. Un reçu `{payload, signature_base64}` au schéma
   `OBSIDURE_C278_MACHINE_RSA_RECEIPT_V1` et à la liste exacte des champs,
   sans champ d'autorité ni de décision.
3. La concordance des identifiants C278 et des SHA256 avec un **nouveau**
   contrôle de la sandbox observée, jamais une réexécution des tests.
4. La vérification RSA-PKCS1v15/SHA256 sur les octets UTF-8 JSON canoniques
   précédés de `OBSIDIA_OBSIDURE_C278_MACHINE_RSA_V1` puis de l'octet NUL.
   Le nom du certificat, RSA-3072 minimum, usage signature et validité
   temporelle à l'instant du contrôle sont également vérifiés.

La dépendance facultative Python `cryptography` est **nécessaire à ce rail**.
Si absente, la méthode retourne
`HOLD / C278_MACHINE_RSA_VERIFIER_DEPENDENCY_MISSING`.
Les tests cryptographiques synthétiques sont alors ignorés : un `OK`
sur les autres tests ne prouve **pas** cette vérification RSA.

Une concordance retourne seulement
`C278_MACHINE_RSA_SIGNATURE_MATCH_ORIGIN_UNATTESTED` avec
`machine_signature_verified=True`. Restent **False** : enrôlement approuvé,
origine historique des tests, identité responsable, ancrage Git/transcript,
anti-rejeu, HumanApproval, ticket KX108, APPLY et release.
Le code ne signe rien et ne consomme aucune clé privée : les 17 nouveaux
tests utilisent uniquement une clé éphémère synthétique en mémoire.

**Tests Linux de développement : 146 tests OK**. **Windows portable : 146 tests
OK, dont 6 ignorés** (résultat communiqué le 19/11/2026), dépendance
`cryptography` disponible. La série antérieure avait 129 tests OK
(6 ignorés) et le challenge Windows réel signé/refusé correctement.
`RELEASE HOLD` reste maintenu jusqu'à preuve de runner contemporain,
enrôlement contrôlé, politique de révocation et registre anti-rejeu.

### Challenge interopérable Windows/.NET → Python (après 146 tests Windows)

**But de ce jalon** : démontrer que le certificat public utilisé par le rail
C278 Python correspond bien à la clé privée RSA-3072 **déjà présente** dans
`Cert:\CurrentUser\My` sur le portable. Ce n'est toujours pas une preuve
historique du runner C278, ni une validation de l'enrôlement.

Deux outils coopèrent sans toucher aux sources ou aux worktrees du FIX :

1. `tools/verify_obsidure_machine_rsa_interop_windows_v1.ps1` (portable
   uniquement) relit le magasin de certificats existant, exige un
   `-ExpectedPublicSha256` explicite, confronte le certificat au JSON public
   créé lors de l'enrôlement et signe **en mémoire** un défi aléatoire. Il ne
   crée aucun certificat et ne produit aucun fichier.
2. `tools/verify_obsidure_machine_challenge_v1.py` reçoit uniquement des
   octets publics par STDIN. Il utilise le **même validateur de certificat et
   de signature RSA** que `inspect_obsidure_c278_machine_rsa_receipt`, avec
   un domaine cryptographique distinct pour que le challenge ne devienne
   jamais un faux reçu C278.

Une concordance exige certificat SHA256 épinglé, machine attendue, CN exact,
RSA >= 3072 bits, `KeyUsage=digitalSignature`, validité temporelle,
signature PKCS#1 v1.5 / SHA256 et refus d'un défi altéré. Elle rapporte
`MACHINE_RSA_INTEROP_VERIFIED_NOT_C278_PROVENANCE`, avec
`machine_signature_verified=True` mais **aucune admission KX108**.

Ne jamais présenter un `PASS` de ce challenge comme un reçu C278 signé par
le runner historique. Le certificat auto-signé peut être un indice de
continuité de machine, pas une preuve hardware, pas une approbation humaine.

**Développement : 155 tests synthétiques OK (Linux)** ; validation réelle
Windows/.NET → Python de ce jalon **en attente**. Le fixe
`DESKTOP-SDOG0EL` reste non enrôlé. `RELEASE HOLD` et `KX108_ONLY` inchangés.

### C278 : provenance du producteur réel, audit ciblé (étape suivant l'interopérabilité)

**Résultat Windows communiqué le 19/11/2026 :**
`OBSIDURE_WINDOWS_PYTHON_RSA_INTEROP_PASS=True`, refus du challenge altéré
`PASS`, `PRIVATE_KEY_EXPORTED=False`, puis **155 tests OK (6 ignorés)** sur
`DESKTOP-Q5MD7J7`, commit `a95beb8310bdd8b6d1110f199b9bee2a3e60570c`.

Le producteur historique identifié dans `Eaubin08/obsidia-x108-proofs`,
`periphery/agents/obsidure_repair_bridge.py`, commit
`48f0c2fbcfe097c213b2783bc7b4d0fba78e6621`, expose
`test_repair_proposal` et `_run_declared_tests` : le code source du dépôt
GitHub écrit des candidats dans une sandbox, exécute pytest avec un
`PYTHONPATH` préfixé et classe l'isolation `FULL` lorsqu'une arborescence
de package existe. **Cette heuristique n'atteste ni les modules réellement
importés ni la provenance du processus.** Le fichier GitHub peut différer
du FIX courant sur le portable.

`tools/inspect_c278_producer_portable_readonly_v1.py` apporte donc un
diagnostic **borné au seul PC portable** : empreintes SHA256 réelles des
trois fichiers producteurs et contrats, HEAD/branche Git de la source
locale, présence des fonctions et indicateurs AST d'exécution, de sandbox
et de signature directe. **Il n'importe ni n'exécute aucun fichier du FIX,
ne lance aucun test et ne modifie aucun dépôt.** Le résultat
`C278_STATIC_SOURCE_PROFILE_ONLY` ne vaut jamais `TEST_PROCESS_ATTESTED`.

**But précis** : éviter de fabriquer une signature postérieure sur un
ancien verdict `PASS` tout en prétendant qu'elle prouve les tests. Le
prochain raccord producteur devra être examiné contre le SHA réel du FIX,
avec attestation des modules importés, du transcript, du runner et du test
au moment où ils sont observés. Aucun `APPLY` ni release n'est ouvert.

**Développement : 161 tests synthétiques OK (Linux)** ; collecte ciblée
Windows **en attente**. Le script n'exporte pas de source privée, seulement
des empreintes et faits statiques. `RELEASE HOLD` / `KX108_ONLY` inchangés.

### Clôture groupée des preuves du portable — une seule passe

**Contrôle Windows rapporté le 19/11/2026** : sur **le portable**
`DESKTOP-Q5MD7J7`, l'analyse réelle des sources C278 du FIX à la branche
`feat/gencoin-world-bus-dryrun-v1`, HEAD
`c9612ae922f5302a8bd012800d368973d0241d4d`, a réussi.
Les trois SHA vérifiés sont figés dans
`obsidure_c278_source_snapshot_v1.py` ; un changement est un `HOLD`, jamais
une sélection silencieuse d'une autre variante. Seuls les trois fichiers
producteurs sont lus. **Aucun code du FIX n'est importé ou exécuté.**

Pour éviter des boucles de vérification successives sur ce portable, le script
`tools/close_portable_governance_one_pass_windows_v1.ps1` exécute, dans
**un seul passage** :

1. Précontrôle d'identité du portable et du worktree Git isolé propre ;
   instantané de HEAD/statut du FIX, même si déjà volontairement dirty.
2. Intégralité des tests stdlib du runtime G1/G2, puis tests `candidate/g1_g2`
   sous pytest, sans appel à une API ou serveur de production.
3. Signature RSA Windows/Python d'un challenge indépendant avec le certificat
   **déjà** enrôlé sur le portable, exactement épinglé à SHA256
   `5bb3f8688930de497254185292a49b46c2f88b0bb23cf259711e86981932c398`.
4. Signature avec cette clé privée Windows d'un **snapshot des octets source
   C278** identifiés, puis relecture de leurs SHA et revérification RSA Python.
   Une preuve **publique** (certificat + empreintes + signature, aucune clé privée)
   et un rapport sont enregistrés **uniquement dans Downloads**, hors du FIX.

Un rapport `OBSIDIA_PORTABLE_GOVERNANCE_ONE_PASS_*.json` et un journal de tests
du même nom sont produits à la fin. Un échec laisse `HOLD`, sans activation,
et n'exige pas de refaire les étapes déjà prouvées.

**Portée précise du PASS attendu :** preuve locale du code observé et de la
possession de la clé RSA, ainsi que régressions de l'assemblage. Cela ne prouve
toujours **pas** que les tests C278 historiques ont été exécutés par ce poste,
que la sandbox a importé les modules attendus, ni qu'un vrai producteur a
émis un reçu au moment du test. Le reçu conservé n'est donc **pas** une preuve
de runner, de HumanApproval, d'anti-rejeu ou d'autorisation KX108.

**Limites de clôture** : tests symlink Windows éventuellement ignorés faute
de privilèges, chaîne C2 historique complète non certifiée, absence de
signature contemporaine du runner C278 et d'ancrage indépendant des identités
des personnes. Ce sont des étapes d'intégration futures, **pas** une raison de
redemander une série de commandes de collecte sur le portable pour ce jalon.
`KX108_ONLY`, `FULL_FUNCTIONAL_G1_G2_HOLD` et `RELEASE HOLD` maintenus.

**Tests de développement du lot : 173 tests unittest passés sous Linux**, dont
12 négatifs/positifs nouveaux de snapshot RSA. Les tests pytest `candidate`
doivent être revalidés sur Windows lors de l'exécution groupée.
