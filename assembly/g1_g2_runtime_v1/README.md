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

- **11/11 PASS** : suite `unittest` autonome (zéro vote, refus CREATE,
  préparation K1 invalide, WORLD_ACTION forgé, Merkle, execute HOLD).
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
