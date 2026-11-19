# OBSIDIA Gouvernance — G3 / entrée opérateur du runtime unifié

## Positionnement

**Un seul runtime logique :** `ObsidiaGovernanceRuntime`.
`obsidia_governance_cli_v1.py` est un adaptateur d'observation autonome pour
les tests et la démonstration technique. Il n'est **pas** un deuxième moteur,
ne remplace **pas** la CLI canonique Obsidia du PC portable et ne lance aucun
service. Le raccordement dans la CLI canonique devra être prouvé plus tard.

| Commande | Rail interne réel | Retour | Exécution métier |
|---|---|---|---|
| `status` | Runtime unifié | Capacités + HOLD de release | Aucune |
| `sigma-domains` | Registre Sigma analysé en AST | 4 domaines déclarés, chargement non vérifié | Aucune |
| `sigma-tooling --stdin` | Sigma tooling + GuardX108 | Avis, y compris `ALLOW` observé, sans ticket | Aucune |
| `merkle --sha256 ...` | Merkle 4A1 | Calcul en mémoire ; aucun scellement | Aucune |
| `execute --operation ...` | Verrou du runtime | Toujours `HOLD` ; code retour 2 | Aucune |

La CLI JSON refuse les champs inconnus et les tentatives d'injection
`authority_level`, `rule_id`, `human_approval`, `ticket_id` ou
`decision_authority` dans les votes Sigma. Un vote manquant, un quorum non
canonique, un doublon, NaN ou un signal mal typé produit `HOLD`.

**Input unique accepté pour `sigma-tooling --stdin` :**

```json
{"schema":"OBSIDIA_SIGMA_TOOLING_ADVISORY_INPUT_V1","votes":[]}
```

Les votes complets nécessitent quatre identités distinctes, chacune portant
`agent_id`, `domain=tooling_build`, `claim`, `proposed_verdict` et
`confidence`, avec les listes facultatives `unknowns`, `contradictions`,
`risk_flags`. L'entrée est **déclarée par l'appelant**, jamais attestée.

## Limite du registre Sigma

La variante `sigma.registry` importée directement charge
`sigma.domains.ecom_agents`, qui dépend de
`periphery.ecom_attestation` **absent de cette zone d'assemblage**. Importer
ce registre pour une simple sonde de disponibilité produit aujourd'hui une
`ModuleNotFoundError`. La solution G3 **n'ignore pas ce défaut** :
`sigma_registry_descriptor_v1.py` analyse exclusivement l'AST de
`sigma/registry.py` et vérifie les quatre noms de domaines. Résultat :
`SIGMA_DOMAINS_DECLARED_ONLY_NOT_RUNTIME_VERIFIED`.

Cela ne signifie pas qu'un agent bank, trading, ecom ou GPS est exécutable
dans le runtime G3. Le périmètre GPS/défense/aviation reste un seul domaine.

## Éléments et preuve locale

- Base de développement GitHub :
  `build/g1-g2-portable-one-pass-v1`, commit
  `d0579f71cbd52ea84684eee0dccd9cb920dcf6a8`.
- Portable connu : `DESKTOP-Q5MD7J7` / `C:\Users\User`.
- Fixe connu : `DESKTOP-SDOG0EL` / `C:\Users\Aubin`.
- Test de base utilisateur : 173 suites de runtime OK ; 54 PASS / 2 skips
  sur la couche de contrats ; interop RSA Windows / Python PASS ; sources
  C278 live signées ; **aucun verdict de runner historique**.
- Nouvelle suite de développement de l'adaptateur : **189 tests unittest
  PASS sur l'environnement d'assemblage**. Les tests de la CLI doivent
  encore être exécutés sur Windows dans une étape de validation dédiée.

## Gates restantes vers le premier logiciel présentable

1. **KX108 K1 + G2 en réel :** fermer la dépendance PRE/POST HMAC et les
   tests de fermeture des écritures, sans remplacer la sécurité K1 par PC2.
2. **Sigma :** refermer les imports métier manquants, puis vérifier réellement
   l'initialisation de chaque domaine. Les signaux restent consultatifs.
3. **Obsidure :** attester le producteur/runner C278 au moment du test et
   la chaîne R10/R9/R12 ; ne pas promouvoir le snapshot signé en reçu de test.
4. **CLI canonique :** raccorder cet adaptateur dans la vraie CLI Obsidia,
   conserver la mémoire native, les modes `evaluate/task`, puis effectuer
   la régression de l'ensemble.
5. **Ragnarok :** seulement après revue des routes, identités, isolation des
   requêtes et suppression des écritures non gouvernées.

**Freeze contractuel :** `KX108_ONLY` ; `RELEASE HOLD` ; pas d'APPLY ;
pas d'API, de serveur, de connecteur, de Graphiti ou de Workbench démarré.
Un PASS du terminal signifie uniquement que les contrats de lecture seule
fonctionnent sur la version testée.
