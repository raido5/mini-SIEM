# Data Contract

## Objectif

Ce document définit le format standard des événements après parsing des logs SSH et HTTP.

Le fichier produit par le parser doit être :

data/interim/parsed_events.csv

## Schéma de parsed_events.csv

| colonne | type | obligatoire | exemple | description |
|---|---|---:|---|---|
| timestamp | datetime | oui | 2026-07-09 12:01:03 | date et heure de l'événement |
| source | string | oui | ssh | source du log : ssh ou http |
| ip | string | oui | 45.12.88.10 | IP à l'origine de l'événement |
| event_type | string | oui | login | type d'événement : login ou request |
| user | string/null | non | root | utilisateur SSH concerné |
| path | string/null | non | /admin | chemin HTTP demandé |
| status | string | oui | failed | état logique : success ou failed |
| status_code | int/null | non | 404 | code HTTP si source=http |
| label | string | oui | brute_force | classe attendue |

## Labels autorisés

- normal
- brute_force
- web_scan

## Règles

- Une ligne = un événement.
- Les logs SSH doivent avoir source = ssh.
- Les logs HTTP doivent avoir source = http.
- Les événements SSH doivent avoir event_type = login.
- Les événements HTTP doivent avoir event_type = request.
- Si une colonne ne s’applique pas, elle vaut null ou vide.