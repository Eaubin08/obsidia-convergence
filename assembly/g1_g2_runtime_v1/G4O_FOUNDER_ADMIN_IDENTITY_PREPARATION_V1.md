# Obsidia Gouvernance — G4O — identité administrative du fondateur

## Décision conservée

Le **fondateur Etienne** détient initialement l'administration des
**enrôlements d'identités Obsidure**. Le **mode équipe** est déjà préparé
dans G4N ; sa future bascule nécessitera une **proposition signée par le
fondateur, une validation indépendante et un anti-rejeu fiable**.
Une signature du fondateur n'accorde **jamais** une autorité KX108.

## Trois identités différentes

| Objet | Portable `DESKTOP-Q5MD7J7` | Fixe `DESKTOP-SDOG0EL` |
| --- | --- | --- |
| Clé machine Obsidure | RSA3072 non exportable déjà existante | Clé encore à créer explicitement |
| Clé administrateur fondateur | **Distincte**, sujet `OBSIDIA-ADMIN-FOUNDER-ETIENNE`, à créer seulement avec `-Enroll` | Aucune copie automatique |
| Administrateurs équipe | Propositions `PREPARED`, non activées | Même politique partagée, aucun membre fictif enrôlé |

L'identité d'une **personne** ne doit pas se confondre avec l'identité du
**PC** qui produit une preuve ou héberge une session.

## Ajout G4O

1. `enroll_obsidure_founder_admin_windows_g4o_v1.ps1` : **sans paramètre
   `-Enroll`, aucune modification**. Le précontrôle vérifie la machine,
   le commit, la propreté du worktree, l'ancienne clé PC épinglée, et
   contrôle toute identité fondateur déjà présente.
2. `-Enroll` (consentement explicite requis) : clé RSA3072 Windows
   `Microsoft Software Key Storage Provider`, `NonExportable`, dans
   `Cert:\CurrentUser\My`; export du **certificat public uniquement** dans
   `Downloads\OBSIDURE_FOUNDER_PUBLIC_IDENTITY_DESKTOP-Q5MD7J7.json`.
   Aucun fichier de la branche active ou du FIX n'est modifié.
3. Le contrôleur G4N renforcé compare désormais les **clés publiques RSA
   elles-mêmes** (SPKI) : deux certificats DER différents portant la même
   clé RSA doivent être refusés. L'empreinte du seul certificat était
   insuffisante pour prouver cette séparation.
4. Le contrôle refuse un certificat existant non conforme, un doublon,
   une clé PC réutilisée, ou un fichier public existant différent.

## Ce que G4O NE fait PAS

- Ne crée pas automatiquement de clé administrateur.
- Ne marque pas le fondateur comme identité personnelle authentifiée.
- Ne dépose **aucune** clé privée ni certificat utilisateur dans GitHub.
- Ne déclare **pas** le registre GitHub racine de confiance.
- N'active pas le mode équipe, ne crée aucun ticket KX108 et ne signe
  aucun reçu C278 réel.
- N'active aucune production (`RELEASE=HOLD`).

## Passage ultérieur à une identité réelle

L'utilisateur peut choisir explicitement de lancer `-Enroll` sur son
**portable**, après vérification du script et de l'environnement Windows.
La clé resterait dans son magasin Windows ; le certificat public est une
**proposition**. Une étape distincte, dont la racine de confiance devra
être décidée, devra établir et enregistrer l'identité de la personne.

La clé CNG logicielle non exportable limite l'export ordinaire, mais n'est
**pas** une attestation matérielle ni une garantie de résistance à un
poste ou compte utilisateur compromis. Une éventuelle clé matérielle
sera une décision de sécurité ultérieure, sans modifier la séparation
des rôles G4N.

## Vérification

Contrôles isolés de régression, tests du contrat G1/G2 puis **mode
CHECK_ONLY** de l'outil Windows. Aucun `-Enroll` implicite.
