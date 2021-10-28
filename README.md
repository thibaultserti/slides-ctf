# Template reveal-md

[![CC BY-SA 4.0][cc-by-sa-shield]][cc-by-sa]

Cette présentation fait une liste de ressources intéressantes pour débuter dans le monde des CTF et des challenges de cybersécurité.
Elle comprend une liste de sites ainsi que des outils souvent utilisés.

## Installation

Pour lancer le contenu, suivre les instructions présents sur https://github.com/webpro/reveal-md

```console
npm install -g reveal-md
```

## Compilation


Le PDF peut être généré comme suit :

```console
reveal-md slides.md --print slides.pdf --print-size 1920x1080
```

# Développement

Ce dépôt utilise les Github Actions pour générer des releases automatiquement.

Pour cela, sur la branche `main`, tager le commit courant avec `git tag v0.1.1` puis pousser le tag avec `git push --tag`

Cela déclenchera le workflow de CI/CD.

Attention à bien spécifier le nom du fichier markdown dans `.github/workflows/release.yml`

## Auteur

Thibault Ayanides

## Licence

[![CC BY-SA 4.0][cc-by-sa-image]][cc-by-sa]

[cc-by-sa]: http://creativecommons.org/licenses/by-sa/4.0/
[cc-by-sa-image]: https://licensebuttons.net/l/by-sa/4.0/88x31.png
[cc-by-sa-shield]: https://img.shields.io/badge/License-CC%20BY--SA%204.0-lightgrey.svg
