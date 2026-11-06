# Gestion de stock — Guide d'utilisation (version 1.2)

Application de gestion de stock et de caisse pour petite boutique. Elle fonctionne entièrement
sur un ordinateur, sans internet, et peut être utilisée depuis un téléphone sur le même Wi-Fi.

## Contenu du dossier

```
gestion_boutique/
├── server.py          Serveur de l'application (Python 3, aucune installation supplémentaire)
├── lancer.sh          Lanceur pour Linux et macOS
├── README.md          Ce guide
├── static/
│   └── index.html     Interface (HTML, CSS, JavaScript)
├── donnees/           Données de la boutique (créé automatiquement)
│   ├── stock.csv      Produits et quantités
│   ├── ventes.csv     Journal des ventes
│   ├── utilisateurs.json  Comptes (mots de passe hachés, jamais en clair)
│   ├── objectif.json  Objectif mensuel
│   ├── parametres.json Nom de la boutique
│   └── photos/        Photos des produits et des reçus
└── sauvegardes/       Copies automatiques des données
```

## Installation

Il faut seulement **Python 3**.

- **Linux (Ubuntu, Mint) :** `python3` est généralement déjà installé. Sinon : `sudo apt install python3`.
- **Windows :** installe Python depuis python.org et coche « Add Python to PATH ».
- **macOS :** Python 3 est disponible sur python.org ou via Homebrew.

## Lancer l'application

Dans le dossier `gestion_boutique` :

```bash
python3 server.py            # ordinateur seulement : http://127.0.0.1:8000
python3 server.py --reseau   # ordinateur et téléphone sur le même Wi-Fi
```

Sous Linux et macOS, tu peux aussi utiliser le lanceur (une seule fois : `chmod +x lancer.sh`) :

```bash
./lancer.sh                  # ou ./lancer.sh --reseau
```

Au premier lancement, l'application demande de créer un mot de passe (8 caractères minimum).

## Accès depuis un téléphone

1. Lance le serveur avec `--reseau`.
2. Note l'adresse affichée, par exemple `http://192.168.1.20:8000`.
3. Ouvre cette adresse dans le navigateur du téléphone (le téléphone doit être sur le même Wi-Fi).
4. Pour les photos, le téléphone propose d'ouvrir la caméra.

Si la page ne s'ouvre pas, vérifie que le téléphone n'est pas en données mobiles, que le Wi-Fi
n'est pas un réseau « invité », et sous Ubuntu : `sudo ufw allow 8000`.

## Utilisation au quotidien

| Rubrique | Ce qu'on y fait |
|---|---|
| **Accueil** | Chiffre d'affaires du jour, ventes de 7 jours, valeur du stock, objectif du mois, dernières ventes. Mis à jour toutes les 5 secondes. |
| **Produits** | Ajouter, rechercher, modifier, supprimer, photo du produit. Cliquer sur un produit pour le vendre. |
| **Ventes** | Ventes d'aujourd'hui, du mois ou de toute la période. Export CSV compatible Excel. |
| **Revenus** | Graphiques des 14 derniers jours et des 12 derniers mois, meilleurs produits. |
| **Ruptures** | Produits épuisés et stocks faibles. Réapprovisionnement en saisissant la quantité reçue. Impression possible. |
| **Paramètres** | Nom de la boutique, changement de mot de passe, informations sur l'application. |

**Vendre :** sélectionne le produit, indique la quantité, puis clique sur « Enregistrer la vente ».
Une facture s'affiche à l'écran avec un bouton Imprimer (elle n'est pas enregistrée en fichier : le journal des ventes fait foi). Tu peux joindre la photo du reçu papier.

## Sauvegardes

- Une sauvegarde est créée **automatiquement à chaque arrêt du serveur** (Ctrl+C ou fermeture du terminal).
- Le bouton **Sauvegarder** crée une copie à la demande.
- Les 30 dernières sauvegardes sont conservées. Les plus anciennes sont supprimées automatiquement.
- **Conseil :** copie régulièrement le dossier `donnees/` sur une clé USB ou un disque externe.

## Comptes, inscription et mot de passe oublié

- **Premier lancement :** la personne qui ouvre l'application crée le compte **propriétaire** (nom, e-mail ou numéro de téléphone, mot de passe). Un **code de récupération** s'affiche une seule fois : il faut le noter.
- **Inscription d'un employé :** sur l'écran de connexion, « Créer un compte ». La demande apparaît dans **Paramètres → Équipe** : le propriétaire la valide ou la refuse. Les employés voient le stock, les ventes et les revenus, mais ne peuvent ni supprimer un produit, ni changer les paramètres, ni gérer l'équipe.
- **Fermer les inscriptions :** case « Autoriser les nouvelles inscriptions » dans Paramètres → Équipe.
- **Mot de passe oublié :** « Mot de passe oublié ? » sur l'écran de connexion, avec l'identifiant et le code de récupération. Un nouveau code est alors remis (l'ancien ne marche plus).
- **Code perdu :** le propriétaire clique sur « Nouveau code » à côté du nom de la personne et le lui transmet.
- **Pourquoi pas d'e-mail ni de SMS ?** L'application fonctionne hors ligne : elle ne peut pas en envoyer. L'envoi de messages demanderait internet et un service d'envoi (SMS payant ou serveur e-mail).
- **Propriétaire qui a tout perdu** (mot de passe et code) : arrête le serveur, supprime `donnees/utilisateurs.json`, relance et recrée le compte propriétaire. Le stock, les ventes et les photos ne sont pas touchés, mais les comptes des employés sont à recréer.
- **Mise à jour depuis une version à mot de passe unique :** au premier lancement, l'ancien mot de passe est demandé une fois pour créer le compte propriétaire.

## Sécurité

- Le mot de passe est haché (PBKDF2-SHA256, sel aléatoire, 200 000 itérations).
- Après 5 mauvaises saisies, la connexion est bloquée 5 minutes.
- Les sessions expirent après 12 heures.
- Les réponses incluent des en-têtes de protection (anti-intégration dans une autre page, politique de contenu).
- **Limite :** le trafic n'est pas chiffré (HTTP). Avec `--reseau`, utilise l'application uniquement
  sur un Wi-Fi de confiance, jamais sur un réseau public. Ne partage pas le dossier `donnees/`.

## Dépannage

| Problème | Solution |
|---|---|
| `Fichier static/index.html introuvable` | Vérifie que `index.html` est dans le sous-dossier `static/`. |
| `Address already in use` | Un autre programme ou un autre serveur utilise le port 8000. Lance avec `--port 8001`. |
| Le téléphone n'affiche pas la page | Voir la section « Accès depuis un téléphone ». |
| Les photos JPG ne s'affichent pas | Elles sont redimensionnées par le navigateur : vérifie que tu utilises une version récente de Chrome, Firefox ou Safari. |
| Les anciennes données n'apparaissent pas | Copie `stock.csv`, `ventes.csv`, `config.json`, `objectif.json` (si présent) et `photos/` dans `donnees/`. |

## Mentions

Application développée pour un usage local. Les données restent sur l'appareil où le serveur fonctionne.
