# Attack Scenarios

## Objectif

Ce document définit les comportements que le Mini-SIEM doit détecter à partir des logs SSH et HTTP.

Il fixe les classes utilisées comme `label` dans :

data/interim/parsed_events.csv

Il sert de référence commune entre la partie cybersécurité (définition des comportements) et la partie ML (labels apprenables).

## Classes détectées

| label | gravité | résumé | question |
|---|---|---|---|
| normal | faible | activité légitime, peu d'erreurs | « rien d'anormal » |
| brute_force | moyenne | tentatives d'authentification répétées, aucun succès | « quelqu'un force un accès » |
| web_scan | moyenne | exploration de nombreux chemins, beaucoup de 404 | « quelqu'un cherche une faille » |
| possible_compromise | haute | accès possiblement obtenu ou anomalie | « un accès a peut-être réussi » |

Priorité de détection : `possible_compromise` > `brute_force` = `web_scan` > `normal`.

## Labels autorisés

- normal
- brute_force
- web_scan
- possible_compromise

---

## normal

**Définition**
Activité légitime d'un utilisateur ou d'un client HTTP conforme. Peu d'erreurs, pas de motif répétitif, source cohérente.

**Exemple de log**
```
Jul  9 08:14:22 srv-web sshd[2451]: Accepted password for alice from 192.168.1.24 port 51022 ssh2
192.168.1.24 - - [09/Jul/2026:08:15:03 +0000] "GET /index.html HTTP/1.1" 200 5123
```

**Comportement attendu**
- Taux d'échec d'authentification faible (échecs isolés tolérés).
- Un ou peu d'utilisateurs distincts par IP.
- Peu de `4xx`, ratio de `404` bas.
- Peu de chemins distincts demandés, tous légitimes.
- Pas d'accès à des chemins sensibles.

**Ambiguïtés**
- Quelques échecs isolés (faute de frappe) restent `normal`.
- Un crawler légitime peut générer beaucoup de requêtes : reste `normal` si chemins légitimes et erreurs rares.

---

## brute_force

**Définition**
Tentatives répétées d'authentification depuis une même source, **sans succès confirmé** dans la fenêtre observée. Attaque *en cours* sur l'authentification.

**Exemple de log**
```
Jul  9 12:01:03 srv-web sshd[3320]: Failed password for root from 45.12.88.10 port 40122 ssh2
Jul  9 12:01:05 srv-web sshd[3322]: Failed password for invalid user oracle from 45.12.88.10 port 40126 ssh2
91.44.20.7 - - [09/Jul/2026:12:10:01 +0000] "POST /wp-login.php HTTP/1.1" 401 512
```

**Comportement attendu**
- Nombre d'échecs élevé (`failed_logins`).
- Plusieurs utilisateurs testés (`unique_users_tried`), y compris comptes inexistants.
- Cadence rapide sur une courte fenêtre.
- Côté HTTP : `401` / `403` répétés sur une route d'authentification.
- **Aucune réussite d'authentification** dans la fenêtre.

**Ambiguïtés**
- Dès qu'une réussite suit les échecs de la même source -> bascule en `possible_compromise`.
- Force brute lente/distribuée : peut ressembler à `normal`, à documenter comme limite.
- Cible l'authentification, contrairement à `web_scan` qui explore des chemins.

---

## web_scan

**Définition**
Exploration automatisée de nombreux chemins HTTP à la recherche de ressources ou de failles (reconnaissance). Beaucoup de chemins distincts, forte proportion de `404`, requêtes vers des chemins sensibles, **sans accès réussi confirmé**.

**Exemple de log**
```
91.44.20.7 - - [09/Jul/2026:12:11:40 +0000] "GET /admin HTTP/1.1" 404 320
91.44.20.7 - - [09/Jul/2026:12:11:41 +0000] "GET /.env HTTP/1.1" 404 320
91.44.20.7 - - [09/Jul/2026:12:11:42 +0000] "GET /.git/config HTTP/1.1" 404 320
91.44.20.7 - - [09/Jul/2026:12:11:43 +0000] "GET /wp-login.php HTTP/1.1" 404 320
```

**Comportement attendu**
- Nombre de chemins distincts élevé (`unique_paths`).
- Ratio de `404` élevé (`ratio_404`).
- Plusieurs chemins sensibles sollicités (`sensitive_paths_count`).
- Cadence rapide, une seule source.
- Réponses majoritairement en échec (`404`, `403`) : le scan **ne trouve rien**.

**Ambiguïtés**
- Si un chemin sensible répond `200` (le scan « trouve » quelque chose) -> bascule en `possible_compromise`.
- Un scanner de sécurité autorisé (monitoring interne, pentest) produit le même motif : à exclure des données ou à annoter explicitement.
- Cible des chemins, contrairement à `brute_force` qui cible l'authentification.

---

## possible_compromise

**Définition**
Indices qu'un accès a **peut-être été obtenu**, ou comportement anormal à risque. On ne prouve pas la compromission, on lève une alerte prioritaire.

**Exemple de log**
```
Jul  9 12:03:47 srv-web sshd[3390]: Failed password for admin from 45.12.88.10 port 40890 ssh2
Jul  9 12:03:51 srv-web sshd[3392]: Accepted password for admin from 45.12.88.10 port 40902 ssh2
91.44.20.7 - - [09/Jul/2026:12:12:10 +0000] "GET /.env HTTP/1.1" 200 480
```

**Comportement attendu**
- Réussite d'authentification (`success_logins` >= 1) dans un contexte suspect (échecs préalables, IP inhabituelle).
- Accès réussi (`200`) à un chemin sensible (`/.env`, `/admin`, `/.git/config`).
- Escalade de privilèges (`sudo`, passage à `root`) après une connexion douteuse.

**Ambiguïtés**
- Classe la plus subjective : un faux positif est acceptable si manquer une vraie compromission coûte plus cher.
- Distinction clé côté HTTP : `404` sur `/.env` = reconnaissance (`web_scan`) ; `200` sur `/.env` = succès (`possible_compromise`).
- Distinction clé côté SSH : que des échecs = `brute_force` ; une réussite après échecs = `possible_compromise`.
- Un `200` sur un chemin réellement légitime ne compte pas : la liste des chemins sensibles est définie par projet.

---

## Cas à trancher (décisions d'équipe)

- Force brute qui réussit -> convention : `possible_compromise`.
- Scan qui aboutit (un chemin sensible répond `200`) -> convention : `possible_compromise`.
- Scan pur (beaucoup de `404`, aucun succès) -> `web_scan`.
- Granularité de la source : label par `ip` (v1) ou par `ip` + fenêtre temporelle (v2).
- Liste précise des chemins considérés « sensibles » : à définir et consigner dans `data_contract.md`.

## Validation

La phase est terminée quand l'équipe sait répondre à :

- Qu'est-ce qu'un `brute_force`, un `web_scan`, un `possible_compromise` dans le projet ?
- Qu'est-ce qui distingue `web_scan` de `possible_compromise` (404 vs 200 sur chemin sensible) ?
- Qu'est-ce qui distingue `brute_force` de `possible_compromise` (échec seul vs réussite après échecs) ?
- Quelles valeurs sont autorisées pour `label` ?
- Chaque cas ambigu a-t-il une décision écrite ?
