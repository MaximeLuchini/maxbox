# MaxBox - Outil de Test de Pénétration

MaxBox est une boîte à outils de cybersécurité conçue pour faciliter les tests de pénétration. Cette toolbox permet d'exécuter différentes attaques et de générer des rapports détaillés. Elle inclut des fonctionnalités telles que le scan de ports, la recherche de vulnérabilités CVE, l'injection SQL, les attaques bruteforce SSH et FTP.

## Table des Matières
- [Introduction](#introduction)
- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Dépendances](#dépendances)
- [Contributions](#contributions)

## Introduction
MaxBox est un outil puissant pour les pentesters et les chercheurs en sécurité. Il permet d'automatiser et de centraliser plusieurs types d'attaques de sécurité courantes. MaxBox simplifie le processus de test de pénétration en fournissant une interface utilisateur graphique conviviale qui facilite l'exécution et la gestion des attaques.

## Fonctionnalités
- **Scan de Ports avec Nmap**: Scanne les ports ouverts sur une cible spécifiée.
- **Recherche de CVEs**: Identifie les vulnérabilités associées aux services détectés.
- **Injection SQL**: Détecte les failles d'injection SQL dans les formulaires de connexion web.
- **Attaque Bruteforce SSH**: Permet d'exécuter des attaques de bruteforce sur les services SSH et d'accéder à la machine cible.
- **Attaque Bruteforce FTP**: Exécute des attaques de bruteforce sur les services FTP.
- **Génération de Rapports**: Génère des rapports détaillés des attaques en format PDF.
- **Historique des Rapports**: Permet de consulter et de gérer les rapports générés.

## Installation
### Prérequis
- Python 3.10 ou supérieur
- Système d'exploitation Kali Linux

### Étapes d'Installation
#### Installer Python
Assurez-vous d'avoir Python 3.10 ou supérieur installé. Vous pouvez le télécharger depuis le site officiel Python.org.

### Installer les Dépendances
Utilisez pip pour installer les dépendances requises.
```bash
sudo pip install paramiko requests beautifulsoup4 fpdf
```

### Installer Nmap
Suivez les instructions ci-dessous pour installer Nmap sur Kali Linux :
```bash
sudo apt-get update
sudo apt-get install nmap
```
### Installer Hydra
Suivez les instructions ci-dessous pour installer Hydra sur Kali Linux :
```bash
sudo apt-get update
sudo apt-get install hydra
```

### Configuration Supplémentaire
Certaines bibliothèques peuvent nécessiter des configurations supplémentaires. Par exemple, pour utiliser tkinter sur Kali Linux, vous devrez peut-être installer les paquets correspondants :
```bash
sudo apt-get install python3-tk
```

### Fichiers Utilisateurs et Mots de Passe
Pour les attaques bruteforce SSH et FTP, vous pouvez modifier les fichiers contenant les listes d'utilisateurs et de mots de passe. Placez ces fichiers dans le répertoire principal du projet et nommez-les comme suit :
- `user_list.txt` : Liste des utilisateurs
- `pass_list.txt` : Liste des mots de passe

Assurez-vous que ces fichiers contiennent les utilisateurs et mots de passe appropriés pour les attaques.

## Utilisation
### Lancer MaxBox
```bash
sudo python3 main.py
```

### Connexion
Créez un compte utilisateur ou connectez-vous avec des identifiants existants.

### Interface Principale
- **Attaquer**: Entrez l'adresse IP de la cible et sélectionnez le type d'attaque.
- **Historique des Rapports**: Consultez et gérez les rapports générés.
- **Déconnexion**: Déconnectez-vous de l'application.

### Exécution des Attaques
Sélectionnez le type d'attaque à partir de l'interface principale et suivez les instructions. Les résultats seront affichés à l'écran et peuvent être inclus dans un rapport PDF.

### Génération de Rapports
Après avoir exécuté des attaques, cliquez sur le bouton "Générer un rapport" pour créer un rapport PDF détaillé.

## Dépendances
- **Python**: Langage principal utilisé pour développer MaxBox.
- **Nmap**: Utilisé pour le scan de ports.
- **Hydra**: Utilisé pour les attaques bruteforce.
- **Paramiko**: Utilisé pour les connexions SSH.
- **BeautifulSoup**: Utilisé pour le parsing HTML.
- **FPDF**: Utilisé pour générer les rapports PDF.
- **Tkinter**: Utilisé pour créer l'interface utilisateur graphique.
- **Requests**: Utilisé pour les requêtes HTTP.
