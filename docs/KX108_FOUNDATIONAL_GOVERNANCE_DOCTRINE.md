# KX108 — Doctrine fondamentale de gouvernance

**Statut : doctrine normative de conception et de construction.**  
**Autorité décisionnelle : KX108 exclusivement.**  
**Aucune disposition de ce document ne constitue une preuve que toutes les garanties sont déjà réalisées.** Leur réalisation doit être démontrée par des contrats, des tests, des preuves et des audits.

---

## 1. Principe souverain

KX108 est l'unique autorité décisionnelle de l'architecture Obsidia et de tout système raccordé à sa gouvernance.

Les agents, traducteurs, évaluateurs, builders, exécuteurs, interfaces, services, opérateurs et composants périphériques peuvent observer, analyser, proposer, préparer et produire des preuves. Aucun d'eux ne peut s'attribuer l'autorité de décision de KX108 ni transformer une proposition en autorisation.

Cette exclusivité s'applique à tous les acteurs, sans exception :

- agents autonomes ou assistés ;
- services et outils logiciels ;
- scripts, programmes, pipelines et automatisations ;
- systèmes économiques, numériques ou physiques raccordés ;
- administrateurs et opérateurs ;
- fondateur et créateur du système.

**Le fondateur ne possède aucun bypass.** Aucun compte privilégié, mode d'urgence, drapeau caché, intervention manuelle, signature spéciale ou procédure de maintenance ne doit permettre de sortir du cadre de gouvernance. Une intervention humaine peut fournir une intention, une preuve ou une proposition ; elle ne remplace jamais la décision exigée de KX108.

## 2. Exploration ouverte, exécution strictement bornée

Obsidia doit permettre l'exploration d'hypothèses, de domaines inconnus, de méthodes nouvelles et de propositions contradictoires. L'exploration n'est pas une autorisation d'agir.

La séparation est obligatoire :

1. **Explorer** : rechercher, simuler, comparer, formuler et contredire.
2. **Traduire** : convertir l'intention et le contexte en contrats canoniques sans perdre les contraintes, unités, relations, provenance ou inconnues.
3. **Évaluer** : produire des analyses consultatives et expliciter risques, contradictions et preuves manquantes.
4. **Décider** : KX108 applique exclusivement les lois, contrats, politiques et invariants applicables.
5. **Exécuter** : les composants autorisés agissent uniquement dans le périmètre explicite de la décision.
6. **Vérifier et rejouer** : les effets observés, reçus et preuves sont contrôlés et rendus auditables.

L'exploration peut être large dans un environnement sans effet réel. Toute transition vers une écriture, une mutation, une communication externe, une dépense, une publication ou une action physique est une opération gouvernée.

## 3. Aucune sortie du cadre

Toute opération doit être bornée avant son exécution par des contrats explicites couvrant, selon le domaine :

- l'identité de l'acteur et du composant ;
- l'intention et la finalité ;
- les ressources et cibles autorisées ;
- les chemins, objets, données et systèmes concernés ;
- les préconditions et postconditions ;
- les limites quantitatives, temporelles et spatiales ;
- les permissions, délégations et leur portée ;
- les contraintes de sécurité et d'éthique ;
- les preuves requises ;
- les conditions d'arrêt, de refus et de révocation.

Une opération hors périmètre, ambiguë sur un élément critique, insuffisamment prouvée, contraire à une loi, à une exigence éthique ou à un contrat doit être refusée ou placée en **HOLD**. Aucun composant ne peut élargir implicitement le périmètre pour faire réussir l'opération.

Un contrat défectueux ne justifie jamais son contournement. Il faut suspendre l'opération, établir le défaut, corriger le contrat par la procédure gouvernée, puis recommencer l'évaluation. Tant que la correction n'est pas validée, le HOLD demeure.

## 4. Éthique, sécurité et fidélité contractuelle

Les exigences éthiques et de sécurité doivent être traduites en contraintes explicites, testables et auditables dans les contrats applicables. Elles ne peuvent pas rester de simples déclarations, recommandations ou intentions de l'agent.

Aucune performance, commodité, urgence, rentabilité, demande du fondateur ou réussite technique ne justifie de violer une borne éthique, une règle de sécurité ou un contrat.

Lorsqu'une règle est absente, contradictoire, indéterminée ou impossible à vérifier sur un point critique, le système ne doit pas inventer une permission : il doit refuser ou produire HOLD.

## 5. Déterminisme et reproductibilité

Le déterminisme est une exigence d'architecture : une décision doit être explicable à partir de l'état, des entrées, des contrats, des politiques et des versions effectivement utilisés.

Pour chaque transition gouvernée, le système doit préserver autant que nécessaire :

- l'identité et la version des composants ;
- l'état initial et les entrées exactes ;
- les contrats, politiques et invariants applicables ;
- les références et empreintes cryptographiques des preuves ;
- l'ordre des événements et les dépendances ;
- la décision KX108 et sa justification structurée ;
- le périmètre autorisé et les limites de l'autorisation ;
- les opérations exécutées, refusées ou interrompues ;
- l'état final observé et les reçus associés ;
- les informations temporelles, leur source et leur précision connue.

Le rejeu doit permettre de reconstruire et de vérifier la séquence à partir des éléments conservés. Il doit distinguer strictement **rejouer/vérifier une décision passée** et **accorder une nouvelle autorisation** : un replay ne crée jamais une permission nouvelle.

Les affirmations de précision temporelle doivent correspondre à l'instrumentation et à la résolution réellement disponibles. Une précision non mesurée ou non prouvée ne doit jamais être annoncée comme garantie.

## 6. Preuve de bout en bout

La preuve ne s'arrête ni à l'acceptation d'une requête ni à la réponse d'un agent. Elle couvre la chaîne complète, de l'intention à l'effet constaté.

Aucune transition gouvernée ne doit être considérée comme démontrée sur la seule base d'un nom de fonction, d'un statut déclaré, d'un test isolé ou d'un rapport généré par le composant audité lui-même.

Les preuves doivent pouvoir être contrôlées indépendamment, être liées aux sources exactes et permettre de détecter les omissions, divergences, rejouabilités invalides et mutations hors périmètre.

Si une preuve manque, est invalide, incohérente, expirée ou impossible à rattacher à la transition concernée, la décision est HOLD/REFUSE selon le contrat applicable.

## 7. Aucun bypass — y compris fondateur

Sont interdits, quelle que soit leur appellation :

- les chemins d'exécution non soumis à KX108 ;
- les écritures ou mutations avant l'autorisation requise ;
- les modes administrateur qui neutralisent les contrôles ;
- les exceptions permanentes ou temporaires non gouvernées ;
- les validations simulées présentées comme réelles ;
- les permissions implicites ou scopes élargis après décision ;
- les contrôles facultatifs lorsqu'ils sont obligatoires ;
- les chemins alternatifs non audités ;
- les modifications de politiques par un composant qui n'en détient pas l'autorité ;
- les mécanismes de secours qui donnent une autorité concurrente.

Une procédure de maintenance ou de réparation n'est pas une exemption. Elle doit elle-même être définie, bornée, prouvée et gouvernée. En cas d'impossibilité de démontrer que cette procédure respecte le cadre, l'opération reste suspendue.

## 8. KX108 peut être audité et réparé sans transfert d'autorité

L'autorité exclusive de KX108 ne signifie pas que son implémentation est déclarée infaillible ou soustraite à l'audit.

KX108 lui-même doit pouvoir être inspecté, testé, contredit par des preuves, corrigé et soumis à des régressions. Un défaut du kernel impose de suspendre les opérations affectées, d'isoler le défaut et de suivre une procédure de correction contrôlée.

**La réparation de KX108 ne crée jamais une seconde autorité.** Aucun agent, administrateur, fondateur ou outil de maintenance ne peut prendre temporairement sa place ou neutraliser ses invariants. Les corrections doivent préserver l'exclusivité décisionnelle du kernel et être vérifiées par des moyens indépendants adaptés, avec une chaîne de preuves complète.

Si l'autorité, l'intégrité ou le comportement attendu du kernel ne peut pas être établi, le système ne doit pas prétendre être gouverné : HOLD.

## 9. Règles d'architecture pour tous les composants

Tout composant raccordé à Obsidia doit respecter les règles suivantes :

1. **Non-souveraineté** : il ne décide pas à la place de KX108.
2. **Contrat explicite** : ses entrées, sorties, permissions et effets sont définis.
3. **Périmètre fermé** : il ne peut agir au-delà du scope autorisé.
4. **Fail-closed** : toute incertitude critique entraîne refus ou HOLD.
5. **Preuve** : ses opérations gouvernées produisent des éléments vérifiables.
6. **Traçabilité** : provenance, versions et transitions sont conservées.
7. **Rejouabilité** : les séquences sont reconstructibles sans réautorisation implicite.
8. **Absence de bypass** : aucun chemin secondaire ne neutralise les contrôles.
9. **Régression** : toute modification doit démontrer qu'elle ne dégrade pas les invariants.
10. **Retrait sûr** : un composant qui ne peut plus satisfaire ces exigences est isolé ou déconnecté par une procédure gouvernée.

Ces obligations s'appliquent également aux outils de build, aux tests, aux scripts de déploiement, aux connecteurs, aux interfaces et aux outils qui modifient le code.

## 10. Méthode obligatoire de construction et de réparation

Toute construction ou réparation suit une séquence vérifiable :

1. établir le contrat et les invariants concernés ;
2. cartographier les points d'entrée, chemins alternatifs, dépendances et sinks d'effet ;
3. reproduire le défaut par un test négatif RED dans un environnement isolé ;
4. préparer une correction candidate sans mutation prématurée de la production ;
5. vérifier la portée exacte, les préconditions, les preuves et l'autorisation KX108 ;
6. démontrer le refus avant mutation pour tout cas interdit ;
7. démontrer le comportement positif pour les cas autorisés ;
8. exécuter les régressions et audits indépendants ;
9. vérifier l'intégrité des sources, des reçus et du worktree ;
10. conserver les preuves, empreintes, décisions et résultats ;
11. ne permettre une intégration ou une RELEASE qu'après satisfaction de toutes les gates gouvernées.

Un test PASS ne vaut pas autorisation de RELEASE. Un audit terminé ne vaut pas fermeture globale. Une correction candidate ne vaut pas correction intégrée.

## 11. États de sécurité

- **ALLOW / ACT** : uniquement lorsque KX108 a rendu une décision positive valide et que toutes les préconditions sont satisfaites.
- **HOLD** : éléments manquants, doute critique, contradiction, preuve insuffisante ou vérification inachevée.
- **BLOCK / REFUSE** : opération interdite, hors scope, contraire à une règle ou tentative de contournement.
- **RELEASE** : uniquement après satisfaction et preuve de toutes les conditions de livraison applicables.

Aucun état ne peut être déduit d'une simple sortie textuelle d'un agent. Les transitions d'état doivent être établies par les contrats et preuves faisant autorité.

## 12. Critère fondateur de conformité

Un système est conforme à cette doctrine seulement si l'on peut démontrer que :

- toute action réelle passe par l'autorité KX108 ;
- aucun acteur, y compris le fondateur, ne possède de bypass ;
- aucune opération ne sort du contrat et du périmètre accordé ;
- les règles éthiques, de sécurité et les invariants sont effectivement appliqués ;
- les défauts et incertitudes critiques conduisent à HOLD ou REFUSE ;
- les décisions et transitions gouvernées sont traçables, vérifiables et rejouables ;
- les preuves couvrent les effets réels, et pas seulement les intentions ou déclarations ;
- la réparation du système, y compris de KX108, ne transfère jamais son autorité.

**La conformité doit être démontrée par des preuves techniques indépendantes. Elle ne peut pas être auto-déclarée.**

---

## Rappel obligatoire à chaque reprise de build

Avant toute reprise, génération, réparation, intégration, publication ou exécution :

> **KX108 est l'unique autorité. Aucun bypass n'existe, pas même pour le fondateur. L'exploration peut être ouverte ; toute action est strictement bornée. Toute violation éthique, contractuelle, technique ou toute preuve insuffisante entraîne HOLD ou REFUSE. Chaque transition gouvernée doit être prouvable, vérifiable et rejouable. On répare le cadre, on ne le contourne jamais.**

Lire cette doctrine avant de reprendre un chantier ne prouve pas que le runtime l'applique. Chaque chantier doit démontrer son respect par ses propres contrats, tests, contrôles et preuves.

---

**Document normatif de doctrine — distinct des spécifications d'implémentation, des résultats de tests et des autorisations opérationnelles.**
