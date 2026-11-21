# OBSIDIA — Produit 1 : Moteur de gouvernance universelle

## Définition

**Le Produit 1 d’Obsidia est un système de gouvernance déterministe, transversal et auditable, conçu pour encadrer des décisions et des opérations provenant de domaines connus ou inconnus.**

Son objectif est de rendre chaque décision **justifiée, sécurisée, traçable, vérifiable et rejouable**, avant toute exécution autorisée.

La prise en charge d’un domaine inconnu ne signifie pas que le système en maîtrise spontanément toutes les règles métier : il doit pouvoir traduire ce qui est vérifiable vers un contrat canonique, expliciter les inconnues et produire un **HOLD** lorsque les éléments requis manquent.

## Cinq piliers

1. **Traducteur universel de domaines** — Transforme les demandes et opérations en contrats canoniques, sans exiger qu’un domaine soit préprogrammé. Toute ambiguïté critique entraîne un HOLD.
2. **Sigma — Intelligence d’évaluation** — Agrège des analyses consultatives portant sur les preuves, les risques, les contradictions et les inconnues. Aucun agent Sigma ne détient l’autorité finale.
3. **KX108 — Autorité souveraine** — Applique les lois, contrats et invariants de gouvernance ; lui seul détient l’autorité finale de décision.
4. **Obsidure — Ingénierie et action gouvernée** — Prépare, construit, répare et propose des opérations. Une proposition ne vaut jamais autorisation d’exécution.
5. **Preuves, reçus et replay** — Lie les décisions à leurs entrées, contrats, politiques et preuves pour permettre leur audit et leur vérification indépendante. Le replay doit préserver la distinction entre vérifier une décision passée et accorder une autorité nouvelle.

## Principe de traduction vers KX108

**Les domaines parlent la langue canonique du kernel ; le kernel ne change pas de langue pour chaque domaine.**

KX108 reste **agnostique aux domaines métier** : il reçoit des contrats et des preuves conformes à ses interfaces de gouvernance, applique ses lois et invariants, puis exerce seul l’autorité de décision. Un domaine nouveau ne doit pas imposer la modification du noyau ni obtenir une autorité particulière.

Une **frontière de traduction** est nécessaire chaque fois que deux couches ou composants ne partagent pas le même contrat sémantique. Il n'est pas exigé un traducteur entre chaque module : l'adaptation se place aux frontières où elle est réellement nécessaire.

La traduction doit :

- préserver le sens des objets, opérations, relations, contraintes et unités ;
- distinguer les faits attestés, les hypothèses, les contradictions et les inconnues ;
- maintenir la provenance et les références de preuve ;
- produire des contrats canoniques évaluables par Sigma et recevables par KX108, selon leurs interfaces vérifiées ;
- refuser toute traduction ambiguë ou incomplète sur un élément critique (**HOLD**, sans approximation présentée comme preuve) ;
- rester **non souveraine** : traduction, proposition et évaluation ne valent jamais autorisation.

### Articulation des couches

1. **Entrées et domaines** : expriment des intentions, actions et états dans leurs représentations propres, y compris pour un domaine non préprogrammé.
2. **Adaptateurs / traducteurs** : transposent ces représentations vers des contrats canoniques, avec preuves et inconnues explicites.
3. **Sigma** : fournit une évaluation consultative, sans autorité souveraine.
4. **KX108** : décide exclusivement à partir des contrats, politiques et preuves admissibles.
5. **Sorties et exécuteurs, dont Obsidure** : reçoivent seulement des instructions compatibles avec les décisions et autorisations vérifiées ; les résultats retournent vers l'audit, les reçus et le replay.

**Critère de validation P1 :** démontrer que la traduction conserve les invariants et échoue de façon sûre pour un domaine inconnu ou mal spécifié. L'existence d'une fonction nommée `translate_domain` ne suffit pas à prouver cette capacité.

## Proposition commerciale

Permettre à une entreprise, une organisation ou un développeur d’intégrer une **gouvernance vérifiable** à ses systèmes, agents IA et automatisations, sans abandonner le contrôle des décisions.

Le produit est destiné à être utilisable depuis une **CLI** et une **API**. La finance, le commerce, l’industrie ou l’IA sont des domaines d’application possibles, pas des limites imposées à son architecture.

## Principe fondamental

> Obsidia ne demande pas à une intelligence artificielle de décider à la place de l’humain. Il construit une architecture dans laquelle toute proposition, toute décision et toute action doivent respecter des règles explicites, une autorité définie et des preuves vérifiables.

**Positionnement :** infrastructure de gouvernance universelle pour systèmes intelligents et automatisés.

## État du Produit 1 au 21 novembre 2026

**Prototype en cours d’intégration et de validation — RELEASE=HOLD.**

Cette définition présente l’architecture et les objectifs du produit ; elle ne constitue pas une certification de réalisation complète. Les points restant à démontrer comprennent notamment :

- la fermeture des dépendances et des régressions K1/Sigma ;
- la couverture réelle du traducteur de domaines, y compris les domaines inconnus ;
- le raccordement gouverné d’Obsidure ;
- l’intégration CLI/API et la validation de bout en bout ;
- les garanties effectives de traçabilité, de replay et de livraison.

**Invariants de gouvernance :** KX108 conserve l’autorité finale ; Sigma et Obsidure restent non souverains ; aucune publication de cette définition ne vaut autorisation d’ACT ni de RELEASE.

---
Document de définition du Produit 1 — distinct des spécifications techniques, des preuves d’essai et des décisions d’autorisation.
