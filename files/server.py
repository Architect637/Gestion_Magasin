#!/usr/bin/env python3
"""
Gestion de stock - serveur local (version web 1.0).

Architecture :
- server.py : serveur HTTP en Python, bibliothèque standard uniquement (aucune installation).
- static/index.html : interface en HTML, CSS et JavaScript, utilisable sur ordinateur et téléphone.
- donnees/ : stock, ventes, mot de passe haché et photos, stockés localement.

Lancer :
    python3 server.py             accès depuis cet ordinateur seulement (http://127.0.0.1:8000)
    python3 server.py --reseau    accès depuis un téléphone sur le même Wi-Fi

Sécurité : le trafic est en HTTP (non chiffré). Avec --reseau, utilise l'application uniquement
sur un réseau Wi-Fi de confiance.
"""

import argparse
import base64
import calendar
import csv
import hashlib
import hmac
import http.cookies
import io
import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import sys
import threading
import time
import traceback
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse


# ---------- Configuration ----------
BASE = os.path.dirname(os.path.abspath(__file__))
DONNEES = os.path.join(BASE, "donnees")
DOSSIER_STATIQUE = os.path.join(BASE, "static")
FICHIER_STOCK = os.path.join(DONNEES, "stock.csv")
FICHIER_VENTES = os.path.join(DONNEES, "ventes.csv")
FICHIER_CONFIG = os.path.join(DONNEES, "config.json")
FICHIER_OBJECTIF = os.path.join(DONNEES, "objectif.json")
FICHIER_PARAMETRES = os.path.join(DONNEES, "parametres.json")
FICHIER_UTILISATEURS = os.path.join(DONNEES, "utilisateurs.json")
SAUVEGARDES_CONSERVEES = 30
VERSION = "1.2"
DOSSIER_PHOTOS = os.path.join(DONNEES, "photos")
DOSSIER_PHOTOS_PRODUITS = os.path.join(DOSSIER_PHOTOS, "produits")
DOSSIER_PHOTOS_RECUS = os.path.join(DOSSIER_PHOTOS, "recus")
DOSSIER_SAUVEGARDES = os.path.join(BASE, "sauvegardes")

NOM_BOUTIQUE = "Ma Boutique"  # À modifier pour le client
SEUIL_ALERTE = 5
ITERATIONS = 200_000
PRIX_MAX = 100_000_000
LONGUEUR_NOM_MAX = 80
MOT_DE_PASSE_MIN = 8
TAILLE_MAX_CORPS = 14 * 1024 * 1024
TAILLE_MAX_PHOTO = 8 * 1024 * 1024
DUREE_SESSION = timedelta(hours=12)
TENTATIVES_MAX = 5
DUREE_BLOCAGE = 300  # secondes

COLONNES_STOCK = ["nom", "prix", "qte", "photo"]
COLONNES_VENTES = ["id", "date", "heure", "produit", "prix_unitaire", "quantite", "total", "recu"]

# Types de photos acceptés : extension et signature (premiers octets du fichier)
TYPES_PHOTO = {
    "image/jpeg": (".jpg", [b"\xff\xd8\xff"]),
    "image/png": (".png", [b"\x89PNG\r\n\x1a\n"]),
    "image/gif": (".gif", [b"GIF87a", b"GIF89a"]),
    "image/webp": (".webp", []),  # signature vérifiée à part
}

SESSIONS = {}      # jeton -> date d'expiration
TENTATIVES = {}    # adresse IP -> [nombre d'échecs, fin du blocage (timestamp)]
VERROU = threading.RLock()  # protège toutes les lectures et écritures de données


class ErreurClient(Exception):
    """Erreur renvoyée au navigateur avec un code HTTP et un message en français."""

    def __init__(self, statut, message):
        super().__init__(message)
        self.statut = statut
        self.message = message


# ---------- Écriture sûre ----------
def ecrire_atomique(chemin, octets):
    """Écrit un fichier sans jamais le laisser à moitié écrit (fichier temporaire puis remplacement)."""
    os.makedirs(os.path.dirname(os.path.abspath(chemin)), exist_ok=True)
    tmp = chemin + ".tmp"
    with open(tmp, "wb") as f:
        f.write(octets)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, chemin)


def ecrire_texte_atomique(chemin, texte):
    ecrire_atomique(chemin, texte.encode("utf-8"))


def ecrire_csv_atomique(chemin, colonnes, lignes):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=colonnes)
    w.writeheader()
    w.writerows(lignes)
    ecrire_texte_atomique(chemin, buf.getvalue())


# ---------- Utilitaires ----------
def formater(montant):
    return f"{montant:,}".replace(",", " ") + " FCFA"


def nom_sur(texte):
    return "".join(c if c.isalnum() else "_" for c in texte)[:40] or "produit"


def valider_produit(nom, prix_brut, qte_brut):
    """Retourne (nom, prix, qte) validés, ou lève ValueError avec un message en français."""
    nom = str(nom or "").strip()
    if not nom:
        raise ValueError("Le nom du produit est obligatoire.")
    if len(nom) > LONGUEUR_NOM_MAX:
        raise ValueError(f"Le nom ne doit pas dépasser {LONGUEUR_NOM_MAX} caractères.")
    try:
        prix = int(prix_brut)
        qte = int(qte_brut)
    except (TypeError, ValueError):
        raise ValueError("Le prix et la quantité doivent être des nombres entiers.")
    if not 0 <= prix <= PRIX_MAX:
        raise ValueError(f"Le prix doit être compris entre 0 et {formater(PRIX_MAX)}.")
    if qte < 0:
        raise ValueError("La quantité ne peut pas être négative.")
    return nom, prix, qte


def trouver(produits, nom):
    for p in produits:
        if p["nom"] == nom:
            return p
    raise ErreurClient(404, "Produit introuvable.")


# ---------- Mot de passe ----------
def hacher(mot_de_passe, sel):
    return hashlib.pbkdf2_hmac("sha256", mot_de_passe.encode("utf-8"), sel, ITERATIONS).hex()


def charger_config():
    if not os.path.exists(FICHIER_CONFIG):
        return None
    with open(FICHIER_CONFIG, encoding="utf-8") as f:
        return json.load(f)


# ---------- Comptes utilisateurs ----------
REGEX_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
ROUTES_PROPRIETAIRE = {"/api/parametres", "/api/objectif", "/api/sauvegarde", "/api/utilisateurs",
                       "/api/produit/supprimer"}
MAX_EN_ATTENTE = 20
FAUX_SEL = b"\x00" * 16  # sert à garder un temps de réponse identique quand le compte n'existe pas


def charger_utilisateurs():
    if not os.path.exists(FICHIER_UTILISATEURS):
        return []
    with open(FICHIER_UTILISATEURS, encoding="utf-8") as f:
        return json.load(f)


def enregistrer_utilisateurs(utilisateurs):
    ecrire_texte_atomique(FICHIER_UTILISATEURS, json.dumps(utilisateurs, ensure_ascii=False, indent=1))


def normaliser_identifiant(texte):
    """Accepte une adresse e-mail ou un numéro de téléphone et retourne l'identifiant normalisé."""
    texte = str(texte or "").strip()
    if not texte:
        raise ValueError("Indique ton adresse e-mail ou ton numéro de téléphone.")
    if "@" in texte:
        if len(texte) > 120 or not REGEX_EMAIL.match(texte):
            raise ValueError("Adresse e-mail invalide.")
        return texte.lower()
    chiffres = re.sub(r"\D", "", texte)
    if re.search(r"[^\d\s().+\-]", texte) or not 8 <= len(chiffres) <= 15:
        raise ValueError("Numéro de téléphone invalide (8 à 15 chiffres).")
    return ("+" if texte.startswith("+") else "") + chiffres


def normaliser_code(texte):
    return re.sub(r"[^0-9A-F]", "", str(texte or "").upper())


def definir_mot_de_passe(u, mot_de_passe):
    sel = secrets.token_bytes(16)
    u["sel"] = sel.hex()
    u["hash"] = hacher(mot_de_passe, sel)


def definir_code_recuperation(u):
    """Génère un nouveau code (XXXX-XXXX-XXXX), n'en garde que l'empreinte, et retourne le code en clair."""
    brut = secrets.token_hex(6).upper()
    code = "-".join(brut[i:i + 4] for i in range(0, 12, 4))
    sel = secrets.token_bytes(16)
    u["sel_recup"] = sel.hex()
    u["hash_recup"] = hacher(brut, sel)
    return code


def creer_utilisateur(identifiant, nom, mot_de_passe, role, statut):
    u = {"id": secrets.token_hex(6), "identifiant": identifiant, "nom": nom, "role": role,
         "statut": statut, "cree": datetime.now().strftime("%Y-%m-%d %H:%M")}
    definir_mot_de_passe(u, mot_de_passe)
    return u, definir_code_recuperation(u)


def trouver_utilisateur(utilisateurs, identifiant):
    return next((u for u in utilisateurs if u["identifiant"] == identifiant), None)


def mot_de_passe_ok(u, mot_de_passe):
    return hmac.compare_digest(hacher(mot_de_passe, bytes.fromhex(u["sel"])), u["hash"])


def code_ok(u, code):
    return hmac.compare_digest(hacher(normaliser_code(code), bytes.fromhex(u["sel_recup"])), u["hash_recup"])


def verifier_mot_de_passe(mot_de_passe, config):
    calcule = hacher(mot_de_passe, bytes.fromhex(config["sel"]))
    return hmac.compare_digest(calcule, config["hash"])


# ---------- Stock ----------
def charger_stock():
    if not os.path.exists(FICHIER_STOCK):
        return []
    with open(FICHIER_STOCK, newline="", encoding="utf-8") as f:
        return [{"nom": r["nom"], "prix": int(r["prix"]), "qte": int(r["qte"]),
                 "photo": r.get("photo", "")}
                for r in csv.DictReader(f)]


def sauvegarder_stock(produits):
    ecrire_csv_atomique(FICHIER_STOCK, COLONNES_STOCK, produits)


def retirer_stock(produit, quantite):
    if quantite < 1:
        raise ValueError("La quantité doit être au moins 1.")
    if produit["qte"] < quantite:
        raise ValueError(f"Stock insuffisant : il reste {produit['qte']} {produit['nom']}.")
    produit["qte"] -= quantite


# ---------- Ventes ----------
def preparer_ventes():
    """Si ventes.csv a un ancien format, on le met de côté pour ne rien perdre."""
    if not os.path.exists(FICHIER_VENTES):
        return
    with open(FICHIER_VENTES, newline="", encoding="utf-8") as f:
        entete = next(csv.reader(f), [])
    if entete != COLONNES_VENTES:
        os.replace(FICHIER_VENTES, os.path.join(DONNEES, f"ventes_ancien_{datetime.now():%Y%m%d_%H%M%S}.csv"))


_CACHE_VENTES = {"cle": None, "lignes": None}


def invalider_cache_ventes():
    _CACHE_VENTES["cle"] = None
    _CACHE_VENTES["lignes"] = None


def charger_ventes():
    """Lit le journal des ventes. Le résultat est gardé en mémoire tant que le fichier ne change pas."""
    preparer_ventes()
    if not os.path.exists(FICHIER_VENTES):
        invalider_cache_ventes()
        return []
    stat = os.stat(FICHIER_VENTES)
    cle = (stat.st_mtime_ns, stat.st_size)
    if _CACHE_VENTES["cle"] != cle:
        with open(FICHIER_VENTES, newline="", encoding="utf-8") as f:
            _CACHE_VENTES["lignes"] = list(csv.DictReader(f))
        _CACHE_VENTES["cle"] = cle
    return list(_CACHE_VENTES["lignes"])  # copie : l'appelant ne modifie jamais le cache


def ajouter_vente(produit, quantite, recu="", maintenant=None):
    maintenant = maintenant or datetime.now()
    ventes = charger_ventes()
    vid = max((int(v["id"]) for v in ventes), default=0) + 1
    ventes.append({
        "id": str(vid),
        "date": maintenant.strftime("%Y-%m-%d"),
        "heure": maintenant.strftime("%H:%M"),
        "produit": produit["nom"],
        "prix_unitaire": str(produit["prix"]),
        "quantite": str(quantite),
        "total": str(produit["prix"] * quantite),
        "recu": recu,
    })
    ecrire_csv_atomique(FICHIER_VENTES, COLONNES_VENTES, ventes)
    invalider_cache_ventes()
    return vid


def statistiques(ventes, aujourd_hui=None):
    aujourd_hui = aujourd_hui or datetime.now().date()
    cle_jour = aujourd_hui.isoformat()
    cle_debut = (aujourd_hui - timedelta(days=6)).isoformat()
    ca_jour = 0
    ca_semaine = 0
    par_produit = {}
    for v in ventes:
        jour = v["date"]  # AAAA-MM-JJ : l'ordre alphabétique est l'ordre chronologique
        total = int(v["total"])
        if jour == cle_jour:
            ca_jour += total
        if cle_debut <= jour <= cle_jour:
            ca_semaine += total
        par_produit[v["produit"]] = par_produit.get(v["produit"], 0) + int(v["quantite"])
    top = sorted(par_produit.items(), key=lambda x: (-x[1], x[0]))[:5]
    return ca_jour, ca_semaine, top


def texte_facture(produit, quantite, vid, maintenant):
    total = produit["prix"] * quantite
    lignes = [
        nom_boutique(),
        f"Facture n° {vid:05d} du {maintenant:%d/%m/%Y %H:%M}",
        "-" * 44,
        f"{'Produit':<22}{'Qté':>5}{'Total':>17}",
        f"{produit['nom']:<22}{quantite:>5}{formater(total):>17}",
        "-" * 44,
        f"TOTAL : {formater(total)}",
        "",
        "Merci de votre achat !",
    ]
    return "\n".join(lignes) + "\n"


def export_csv(periode):
    maintenant = datetime.now()
    ventes = charger_ventes()
    if periode == "jour":
        cle = maintenant.strftime("%Y-%m-%d")
        lignes = [v for v in ventes if v["date"] == cle]
        nom = f"ventes_{cle}.csv"
    elif periode == "mois":
        cle = maintenant.strftime("%Y-%m")
        lignes = [v for v in ventes if v["date"].startswith(cle)]
        nom = f"ventes_mois_{cle}.csv"
    else:
        raise ErreurClient(400, "Période inconnue.")
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLONNES_VENTES)
    w.writeheader()
    w.writerows(lignes)
    return buf.getvalue().encode("utf-8-sig"), nom  # BOM : Excel lit bien les accents


# ---------- Photos ----------
def photo_valide(octets, type_mime):
    if type_mime == "image/webp":
        return octets[:4] == b"RIFF" and octets[8:12] == b"WEBP"
    return any(octets.startswith(s) for s in TYPES_PHOTO[type_mime][1])


def enregistrer_photo(data_url, dossier, prefixe):
    """
    Décode une image envoyée en data URL, vérifie son type réel et sa taille, puis l'enregistre.
    Retourne le chemin relatif à donnees/ (ex. photos/produits/savon_20261013_093000_123456.jpg).
    """
    if not isinstance(data_url, str) or not data_url.startswith("data:") or ";base64," not in data_url:
        raise ErreurClient(400, "Photo invalide.")
    entete, contenu = data_url.split(",", 1)
    type_mime = entete[5:].split(";")[0]
    if type_mime not in TYPES_PHOTO:
        raise ErreurClient(400, "Format de photo non accepté (JPG, PNG, GIF ou WebP).")
    try:
        octets = base64.b64decode(contenu, validate=True)
    except ValueError:
        raise ErreurClient(400, "Photo corrompue.")
    if len(octets) > TAILLE_MAX_PHOTO:
        raise ErreurClient(400, "Photo trop lourde (8 Mo maximum).")
    if not photo_valide(octets, type_mime):
        raise ErreurClient(400, "Le contenu du fichier ne correspond pas à une image.")
    extension = TYPES_PHOTO[type_mime][0]
    chemin = os.path.join(dossier, f"{prefixe}_{datetime.now():%Y%m%d_%H%M%S_%f}{extension}")
    ecrire_atomique(chemin, octets)
    return os.path.relpath(chemin, DONNEES).replace(os.sep, "/")


# ---------- Objectif, filtrage et revenus ----------
def charger_objectif():
    if not os.path.exists(FICHIER_OBJECTIF):
        return 0
    with open(FICHIER_OBJECTIF, encoding="utf-8") as f:
        return int(json.load(f).get("montant", 0))


def enregistrer_objectif(montant):
    ecrire_texte_atomique(FICHIER_OBJECTIF, json.dumps({"montant": montant}))


def filtrer_ventes(periode):
    ventes = charger_ventes()
    maintenant = datetime.now()
    if periode == "jour":
        cle = maintenant.strftime("%Y-%m-%d")
        return [v for v in ventes if v["date"] == cle]
    if periode == "mois":
        cle = maintenant.strftime("%Y-%m")
        return [v for v in ventes if v["date"].startswith(cle)]
    if periode == "tout":
        return ventes
    raise ErreurClient(400, "Période inconnue.")


def donnees_revenus():
    ventes = charger_ventes()
    aujourd_hui = datetime.now().date()
    par_jour = {}
    par_mois = {}
    par_produit = {}
    for v in ventes:
        total = int(v["total"])
        par_jour[v["date"]] = par_jour.get(v["date"], 0) + total
        mois = v["date"][:7]
        par_mois[mois] = par_mois.get(mois, 0) + total
        pp = par_produit.setdefault(v["produit"], {"produit": v["produit"], "total": 0, "quantite": 0})
        pp["total"] += total
        pp["quantite"] += int(v["quantite"])

    jours = []
    for i in range(13, -1, -1):
        d = (aujourd_hui - timedelta(days=i)).strftime("%Y-%m-%d")
        jours.append({"date": d, "total": par_jour.get(d, 0)})

    mois_liste = []
    annee, mois_courant = aujourd_hui.year, aujourd_hui.month
    for i in range(11, -1, -1):
        annee_i, mois_i = annee, mois_courant - i
        while mois_i <= 0:
            mois_i += 12
            annee_i -= 1
        cle = f"{annee_i:04d}-{mois_i:02d}"
        mois_liste.append({"mois": cle, "total": par_mois.get(cle, 0)})

    top = sorted(par_produit.values(), key=lambda p: (-p["total"], p["produit"]))[:10]
    return {
        "jours": jours,
        "mois": mois_liste,
        "top": top,
        "ca_jour": par_jour.get(aujourd_hui.strftime("%Y-%m-%d"), 0),
        "ca_mois": par_mois.get(aujourd_hui.strftime("%Y-%m"), 0),
    }


# ---------- Analyses ----------
JOURS_FR = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]


def analyser(produits, ventes, aujourd_hui=None):
    """Calcule des indicateurs d'aide à la décision à partir du stock et du journal des ventes."""
    aujourd_hui = aujourd_hui or datetime.now().date()
    cle_mois = aujourd_hui.strftime("%Y-%m")

    ca_mois = 0
    totaux_par_jour = {}     # jour de la semaine -> total sur 90 jours
    ventes_par_heure = {}    # heure -> nombre de ventes
    derniere_vente = {}      # produit -> date de la dernière vente
    quantite_14j = {}        # produit -> quantité vendue sur 14 jours

    for v in ventes:
        try:
            jour = date.fromisoformat(v["date"])
            total = int(v["total"])
            quantite = int(v["quantite"])
            heure = int(v["heure"].split(":")[0])
        except (KeyError, ValueError, AttributeError):
            continue  # ligne illisible : on l'ignore plutôt que de bloquer l'analyse

        if jour.strftime("%Y-%m") == cle_mois:
            ca_mois += total
        ecart = (aujourd_hui - jour).days
        if 0 <= ecart < 90:
            nom_jour = JOURS_FR[jour.weekday()]
            totaux_par_jour[nom_jour] = totaux_par_jour.get(nom_jour, 0) + total
        ventes_par_heure[heure] = ventes_par_heure.get(heure, 0) + 1
        produit = v["produit"]
        if produit not in derniere_vente or jour > derniere_vente[produit]:
            derniere_vente[produit] = jour
        if 0 <= ecart < 14:
            quantite_14j[produit] = quantite_14j.get(produit, 0) + quantite

    jours_ecoules = aujourd_hui.day
    jours_mois = calendar.monthrange(aujourd_hui.year, aujourd_hui.month)[1]
    projection = round(ca_mois * jours_mois / jours_ecoules) if jours_ecoules else 0

    jour_fort = max(totaux_par_jour.items(), key=lambda x: x[1]) if totaux_par_jour else None
    heure_pointe = max(ventes_par_heure.items(), key=lambda x: x[1]) if ventes_par_heure else None

    ruptures_prevues = []
    dormants = []
    for p in produits:
        if p["qte"] <= 0:
            continue  # déjà en rupture : traité dans la rubrique Ruptures
        rythme = quantite_14j.get(p["nom"], 0) / 14
        if rythme > 0:
            jours_restants = p["qte"] / rythme
            if jours_restants < 7:
                ruptures_prevues.append({"nom": p["nom"], "jours": int(jours_restants)})
        else:
            derniere = derniere_vente.get(p["nom"])
            if derniere is None or (aujourd_hui - derniere).days >= 30:
                dormants.append(p["nom"])
    ruptures_prevues.sort(key=lambda x: x["jours"])

    return {
        "ca_mois": ca_mois,
        "projection": projection,
        "jours_ecoules": jours_ecoules,
        "jours_mois": jours_mois,
        "jour_fort": {"jour": jour_fort[0], "total": jour_fort[1]} if jour_fort else None,
        "heure_pointe": {"heure": heure_pointe[0], "nb": heure_pointe[1]} if heure_pointe else None,
        "ruptures_prevues": ruptures_prevues[:10],
        "dormants": sorted(dormants)[:10],
    }


# ---------- Paramètres et rotation des sauvegardes ----------
def charger_parametres():
    if not os.path.exists(FICHIER_PARAMETRES):
        return {}
    with open(FICHIER_PARAMETRES, encoding="utf-8") as f:
        return json.load(f)


def enregistrer_parametres(parametres):
    ecrire_texte_atomique(FICHIER_PARAMETRES, json.dumps(parametres, ensure_ascii=False))


def nom_boutique():
    return charger_parametres().get("nom") or NOM_BOUTIQUE


def rotation_sauvegardes(garder=SAUVEGARDES_CONSERVEES):
    """Supprime les plus anciennes sauvegardes au-delà de `garder`. Ne touche qu'aux dossiers datés."""
    if not os.path.isdir(DOSSIER_SAUVEGARDES):
        return
    dossiers = sorted(
        d for d in os.listdir(DOSSIER_SAUVEGARDES)
        if d[:8].isdigit() and os.path.isdir(os.path.join(DOSSIER_SAUVEGARDES, d))
    )
    for ancien in dossiers[:-garder] if garder > 0 else dossiers:
        shutil.rmtree(os.path.join(DOSSIER_SAUVEGARDES, ancien), ignore_errors=True)


# ---------- Données et sauvegarde ----------
def donnees_complete():
    produits = charger_stock()
    ventes = charger_ventes()
    ca_jour, ca_semaine, top = statistiques(ventes)
    return {
        "boutique": nom_boutique(),
        "version": VERSION,
        "seuil": SEUIL_ALERTE,
        "produits": produits,
        "ventes": list(reversed(ventes))[:5],
        "objectif": charger_objectif(),
        "stats": {
            "ca_jour": ca_jour,
            "ca_semaine": ca_semaine,
            "ca_mois": sum(int(v["total"]) for v in ventes if v["date"].startswith(datetime.now().strftime("%Y-%m"))),
            "valeur": sum(p["prix"] * p["qte"] for p in produits),
            "ruptures": sum(1 for p in produits if p["qte"] == 0),
            "alerte": sum(1 for p in produits if 0 < p["qte"] < SEUIL_ALERTE),
            "top": top,
        },
    }


def copier_lien(source, cible):
    """Une photo ne change jamais une fois écrite : un lien évite de la dupliquer à chaque sauvegarde."""
    try:
        os.link(source, cible)
    except OSError:
        shutil.copy2(source, cible)


def sauvegarder_donnees():
    """Copie stock, ventes, configuration et photos dans un dossier daté. Retourne le dossier ou None."""
    if not os.path.isdir(DONNEES):
        return None
    dossier = os.path.join(DOSSIER_SAUVEGARDES, datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
    os.makedirs(dossier)
    for fichier in (FICHIER_STOCK, FICHIER_VENTES, FICHIER_CONFIG, FICHIER_OBJECTIF, FICHIER_PARAMETRES,
                    FICHIER_UTILISATEURS):
        if os.path.exists(fichier):
            shutil.copy2(fichier, dossier)
    if os.path.isdir(DOSSIER_PHOTOS):
        shutil.copytree(DOSSIER_PHOTOS, os.path.join(dossier, "photos"), copy_function=copier_lien)
    rotation_sauvegardes()
    return dossier


# ---------- Gestionnaire HTTP ----------
class Gestionnaire(BaseHTTPRequestHandler):
    server_version = "GestionStock/1.1"
    protocol_version = "HTTP/1.1"  # connexions persistantes : moins de latence
    timeout = 30  # une connexion inactive est fermée au bout de 30 s

    def log_message(self, format, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))

    # --- Réponses ---
    def envoyer(self, statut, corps, type_contenu, entetes=None, cache="no-store"):
        if isinstance(corps, str):
            corps = corps.encode("utf-8")
        self.send_response(statut)
        self.send_header("Content-Type", type_contenu)
        self.send_header("Content-Length", str(len(corps)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", cache)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data: blob:; "
                         "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                         "connect-src 'self'; frame-src 'none'; object-src 'none'")
        for nom, valeur in (entetes or []):
            self.send_header(nom, valeur)
        self.end_headers()
        self.wfile.write(corps)

    def envoyer_json(self, statut, objet, entetes=None):
        self.envoyer(statut, json.dumps(objet, ensure_ascii=False),
                     "application/json; charset=utf-8", entetes)

    def envoyer_fichier(self, chemin):
        if not os.path.isfile(chemin):
            raise ErreurClient(404, "Page introuvable.")
        type_mime = mimetypes.guess_type(chemin)[0] or "application/octet-stream"
        with open(chemin, "rb") as f:
            self.envoyer(200, f.read(), type_mime)

    def envoyer_photo(self, relatif):
        base = os.path.realpath(DOSSIER_PHOTOS)
        complet = os.path.realpath(os.path.join(DOSSIER_PHOTOS, relatif))
        if not complet.startswith(base + os.sep) or not os.path.isfile(complet):
            raise ErreurClient(404, "Photo introuvable.")
        type_mime = mimetypes.guess_type(complet)[0] or "application/octet-stream"
        with open(complet, "rb") as f:
            # les noms de photos sont uniques (horodatés) : le navigateur peut les garder en cache
            self.envoyer(200, f.read(), type_mime, cache="private, max-age=86400")

    # --- Lecture de la requête ---
    def lire_json(self):
        try:
            longueur = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self.close_connection = True
            raise ErreurClient(400, "Requête invalide.")
        if longueur < 0 or longueur > TAILLE_MAX_CORPS:
            self.close_connection = True  # corps non lu : on ferme pour ne pas fausser la requête suivante
            raise ErreurClient(413, "Données trop volumineuses.")
        brut = self.rfile.read(longueur) if longueur > 0 else b""
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ErreurClient(415, "Type de contenu refusé.")
        try:
            corps = json.loads(brut.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ErreurClient(400, "Requête invalide.")
        if not isinstance(corps, dict):
            raise ErreurClient(400, "Requête invalide.")
        return corps

    # --- Sessions ---
    def jeton(self):
        try:
            cookies = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        morceau = cookies.get("session")
        return morceau.value if morceau else None

    def utilisateur_courant(self):
        """Retourne le compte connecté, ou None si la session est absente, expirée ou le compte inactif."""
        jeton = self.jeton()
        if not jeton:
            return None
        with VERROU:
            session = SESSIONS.get(jeton)
            if session is None:
                return None
            expiration, uid = session
            if datetime.now() > expiration:
                SESSIONS.pop(jeton, None)
                return None
            for u in charger_utilisateurs():
                if u["id"] == uid and u["statut"] == "actif":
                    return u
            SESSIONS.pop(jeton, None)  # compte supprimé ou désactivé
            return None

    def exiger_session(self):
        if self.utilisateur_courant() is None:
            raise ErreurClient(401, "Connexion requise.")

    def exiger_proprietaire(self):
        u = self.utilisateur_courant()
        if u is None:
            raise ErreurClient(401, "Connexion requise.")
        if u["role"] != "proprietaire":
            raise ErreurClient(403, "Réservé au propriétaire de la boutique.")
        return u

    @staticmethod
    def fermer_sessions(uid):
        with VERROU:
            for k in [k for k, (_, u) in SESSIONS.items() if u == uid]:
                del SESSIONS[k]

    def nouvelle_session(self, uid):
        jeton = secrets.token_urlsafe(32)
        with VERROU:
            maintenant = datetime.now()
            for ancien in [k for k, (fin, _) in SESSIONS.items() if fin < maintenant]:
                del SESSIONS[ancien]  # nettoie les sessions expirées
            SESSIONS[jeton] = (maintenant + DUREE_SESSION, uid)
        cookie = (f"session={jeton}; Path=/; HttpOnly; SameSite=Strict; "
                  f"Max-Age={int(DUREE_SESSION.total_seconds())}")
        return [("Set-Cookie", cookie)]

    # --- GET ---
    def do_GET(self):
        try:
            url = urlparse(self.path)
            chemin = unquote(url.path)
            if chemin in ("/", "/index.html"):
                return self.envoyer_fichier(os.path.join(DOSSIER_STATIQUE, "index.html"))
            if chemin == "/favicon.ico":
                self.send_response(204)
                self.send_header("Cache-Control", "max-age=86400")
                self.end_headers()
                return
            if chemin == "/api/statut":
                utilisateurs = charger_utilisateurs()
                return self.envoyer_json(200, {
                    "configure": bool(utilisateurs),
                    "legacy": not utilisateurs and charger_config() is not None,
                    "inscriptions": charger_parametres().get("inscriptions", True),
                })
            if chemin == "/api/donnees":
                moi = self.utilisateur_courant()
                if moi is None:
                    raise ErreurClient(401, "Connexion requise.")
                with VERROU:
                    donnees = donnees_complete()
                    donnees["moi"] = {"nom": moi["nom"], "identifiant": moi["identifiant"], "role": moi["role"]}
                    if moi["role"] == "proprietaire":
                        champs = ("id", "nom", "identifiant", "role", "statut", "cree")
                        donnees["utilisateurs"] = [{k: u[k] for k in champs} for u in charger_utilisateurs()]
                        donnees["inscriptions"] = charger_parametres().get("inscriptions", True)
                    return self.envoyer_json(200, donnees)
            if chemin == "/api/export":
                self.exiger_session()
                periode = parse_qs(url.query).get("periode", [""])[0]
                with VERROU:
                    contenu, nom = export_csv(periode)
                return self.envoyer(200, contenu, "text/csv; charset=utf-8",
                                    [("Content-Disposition", f'attachment; filename="{nom}"')])
            if chemin == "/api/ventes":
                self.exiger_session()
                periode = parse_qs(url.query).get("periode", ["jour"])[0]
                with VERROU:
                    lignes = list(reversed(filtrer_ventes(periode)))
                    return self.envoyer_json(200, {
                        "lignes": lignes[:500],
                        "nb": len(lignes),
                        "total": sum(int(v["total"]) for v in lignes),
                    })
            if chemin == "/api/analyse":
                self.exiger_session()
                with VERROU:
                    return self.envoyer_json(200, analyser(charger_stock(), charger_ventes()))
            if chemin == "/api/revenus":
                self.exiger_session()
                with VERROU:
                    return self.envoyer_json(200, donnees_revenus())
            if chemin.startswith("/photos/"):
                self.exiger_session()
                return self.envoyer_photo(chemin[len("/photos/"):])
            raise ErreurClient(404, "Page introuvable.")
        except ErreurClient as e:
            self.envoyer_json(e.statut, {"erreur": e.message})
        except Exception:
            traceback.print_exc()
            self.envoyer_json(500, {"erreur": "Erreur interne. Consulte la console du serveur."})

    # --- POST : toutes les actions passent par du JSON ---
    def do_POST(self):
        try:
            chemin = urlparse(self.path).path
            corps = self.lire_json()

            if chemin == "/api/setup":
                return self.route_setup(corps)
            if chemin == "/api/login":
                return self.route_login(corps)
            if chemin == "/api/inscription":
                return self.route_inscription(corps)
            if chemin == "/api/recuperation":
                return self.route_recuperation(corps)
            if chemin == "/api/logout":
                return self.route_logout()

            self.exiger_session()
            if chemin in ROUTES_PROPRIETAIRE:
                self.exiger_proprietaire()
            routes = {
                "/api/produit/ajouter": self.route_ajouter,
                "/api/produit/modifier": self.route_modifier,
                "/api/produit/supprimer": self.route_supprimer,
                "/api/produit/photo": self.route_photo_produit,
                "/api/produit/photo/retirer": self.route_retirer_photo,
                "/api/vente": self.route_vente,
                "/api/sauvegarde": self.route_sauvegarde,
                "/api/objectif": self.route_objectif,
                "/api/parametres": self.route_parametres,
                "/api/mot-de-passe": self.route_mot_de_passe,
                "/api/utilisateurs": self.route_utilisateurs,
            }
            action = routes.get(chemin)
            if action is None:
                raise ErreurClient(404, "Action inconnue.")
            return action(corps)

        except ErreurClient as e:
            self.envoyer_json(e.statut, {"erreur": e.message})
        except ValueError as e:
            self.envoyer_json(400, {"erreur": str(e)})
        except Exception:
            traceback.print_exc()
            self.envoyer_json(500, {"erreur": "Erreur interne. Consulte la console du serveur."})

    # --- Authentification et comptes ---
    @staticmethod
    def verifier_longueur(mot):
        if not isinstance(mot, str) or len(mot) < MOT_DE_PASSE_MIN:
            raise ErreurClient(400, f"Le mot de passe doit contenir au moins {MOT_DE_PASSE_MIN} caractères.")

    @staticmethod
    def verifier_nom(nom):
        nom = str(nom or "").strip()
        if not nom or len(nom) > 60:
            raise ErreurClient(400, "Indique ton nom (60 caractères maximum).")
        return nom

    @staticmethod
    def verifier_blocage(ip):
        if time.time() < TENTATIVES.get(ip, [0, 0.0])[1]:
            raise ErreurClient(429, "Trop de tentatives. Réessaie dans quelques minutes.")

    @staticmethod
    def enregistrer_echec(ip):
        echecs = TENTATIVES.get(ip, [0, 0.0])[0] + 1
        TENTATIVES[ip] = [0, time.time() + DUREE_BLOCAGE] if echecs >= TENTATIVES_MAX else [echecs, 0.0]

    def route_setup(self, corps):
        """Création du compte propriétaire (premier lancement ou mise à jour depuis l'ancien mot de passe unique)."""
        ip = self.client_address[0]
        with VERROU:
            if charger_utilisateurs():
                raise ErreurClient(403, "L'application est déjà configurée.")
            ancien = charger_config()
            if ancien is not None:
                self.verifier_blocage(ip)
                if not verifier_mot_de_passe(str(corps.get("ancien", "")), ancien):
                    self.enregistrer_echec(ip)
                    raise ErreurClient(401, "Ancien mot de passe incorrect.")
            identifiant = normaliser_identifiant(corps.get("identifiant"))
            nom = self.verifier_nom(corps.get("nom"))
            mot = corps.get("password", "")
            self.verifier_longueur(mot)
            u, code = creer_utilisateur(identifiant, nom, mot, "proprietaire", "actif")
            enregistrer_utilisateurs([u])
            if ancien is not None:
                os.replace(FICHIER_CONFIG, FICHIER_CONFIG + ".ancien")
                TENTATIVES.pop(ip, None)
            entetes = self.nouvelle_session(u["id"])
        self.envoyer_json(200, {"ok": True, "code": code}, entetes)

    def route_inscription(self, corps):
        identifiant = normaliser_identifiant(corps.get("identifiant"))
        nom = self.verifier_nom(corps.get("nom"))
        mot = corps.get("password", "")
        self.verifier_longueur(mot)
        with VERROU:
            utilisateurs = charger_utilisateurs()
            if not utilisateurs:
                raise ErreurClient(400, "L'application n'est pas encore configurée.")
            if not charger_parametres().get("inscriptions", True):
                raise ErreurClient(403, "Les inscriptions sont fermées. Demande au propriétaire de la boutique.")
            if trouver_utilisateur(utilisateurs, identifiant):
                raise ErreurClient(409, "Ce compte existe déjà. Connecte-toi ou utilise « Mot de passe oublié ».")
            if sum(1 for x in utilisateurs if x["statut"] == "attente") >= MAX_EN_ATTENTE:
                raise ErreurClient(429, "Trop de demandes en attente. Réessaie plus tard.")
            u, code = creer_utilisateur(identifiant, nom, mot, "employe", "attente")
            utilisateurs.append(u)
            enregistrer_utilisateurs(utilisateurs)
        self.envoyer_json(200, {"ok": True, "code": code})

    def route_login(self, corps):
        ip = self.client_address[0]
        mot = corps.get("password", "")
        if not isinstance(mot, str):
            raise ErreurClient(400, "Mot de passe invalide.")
        identifiant = normaliser_identifiant(corps.get("identifiant"))
        with VERROU:
            self.verifier_blocage(ip)
            u = trouver_utilisateur(charger_utilisateurs(), identifiant)
            if u is None:
                hacher(mot, FAUX_SEL)  # même temps de réponse qu'un vrai compte
            if u is None or not mot_de_passe_ok(u, mot):
                self.enregistrer_echec(ip)
                raise ErreurClient(401, "Identifiant ou mot de passe incorrect.")
            if u["statut"] != "actif":
                raise ErreurClient(403, "Ton compte attend la validation du propriétaire de la boutique.")
            TENTATIVES.pop(ip, None)
            entetes = self.nouvelle_session(u["id"])
        self.envoyer_json(200, {"ok": True}, entetes)

    def route_recuperation(self, corps):
        """Mot de passe oublié : on prouve son identité avec le code de récupération remis à l'inscription."""
        ip = self.client_address[0]
        identifiant = normaliser_identifiant(corps.get("identifiant"))
        nouveau = corps.get("nouveau", "")
        self.verifier_longueur(nouveau)
        with VERROU:
            self.verifier_blocage(ip)
            utilisateurs = charger_utilisateurs()
            u = trouver_utilisateur(utilisateurs, identifiant)
            if u is None:
                hacher("x", FAUX_SEL)
            if u is None or not code_ok(u, corps.get("code", "")):
                self.enregistrer_echec(ip)
                raise ErreurClient(401, "Identifiant ou code de récupération incorrect.")
            definir_mot_de_passe(u, nouveau)
            code = definir_code_recuperation(u)  # le code utilisé ne marche plus : on en remet un nouveau
            enregistrer_utilisateurs(utilisateurs)
            self.fermer_sessions(u["id"])
            TENTATIVES.pop(ip, None)
        self.envoyer_json(200, {"ok": True, "code": code})

    def route_utilisateurs(self, corps):
        """Gestion de l'équipe par le propriétaire : valider, refuser, supprimer, nouveau code, inscriptions."""
        action = corps.get("action")
        moi = self.utilisateur_courant()
        with VERROU:
            if action == "inscriptions":
                parametres = charger_parametres()
                parametres["inscriptions"] = bool(corps.get("valeur"))
                enregistrer_parametres(parametres)
                return self.envoyer_json(200, {"ok": True})
            utilisateurs = charger_utilisateurs()
            cible = next((u for u in utilisateurs if u["id"] == corps.get("id")), None)
            if cible is None:
                raise ErreurClient(404, "Utilisateur introuvable.")
            if cible["id"] == moi["id"]:
                raise ErreurClient(400, "Tu ne peux pas modifier ton propre compte ici.")
            code = None
            if action == "approuver":
                cible["statut"] = "actif"
            elif action in ("refuser", "supprimer"):
                utilisateurs.remove(cible)
                self.fermer_sessions(cible["id"])
            elif action == "reinitialiser":
                code = definir_code_recuperation(cible)
            else:
                raise ErreurClient(400, "Action inconnue.")
            enregistrer_utilisateurs(utilisateurs)
        self.envoyer_json(200, {"ok": True, "code": code})

    def route_logout(self):
        jeton = self.jeton()
        with VERROU:
            if jeton:
                SESSIONS.pop(jeton, None)
        self.envoyer_json(200, {"ok": True},
                          [("Set-Cookie", "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")])

    # --- Produits ---
    def route_ajouter(self, corps):
        nom, prix, qte = valider_produit(corps.get("nom"), corps.get("prix"), corps.get("qte"))
        with VERROU:
            produits = charger_stock()
            if any(p["nom"].lower() == nom.lower() for p in produits):
                raise ErreurClient(409, f"Le produit « {nom} » existe déjà.")
            produits.append({"nom": nom, "prix": prix, "qte": qte, "photo": ""})
            sauvegarder_stock(produits)
        self.envoyer_json(200, {"ok": True})

    def route_modifier(self, corps):
        with VERROU:
            produits = charger_stock()
            p = trouver(produits, str(corps.get("nom", "")))
            _, prix, qte = valider_produit(p["nom"], corps.get("prix"), corps.get("qte"))
            p["prix"] = prix
            p["qte"] = qte
            sauvegarder_stock(produits)
        self.envoyer_json(200, {"ok": True})

    def route_supprimer(self, corps):
        with VERROU:
            produits = charger_stock()
            p = trouver(produits, str(corps.get("nom", "")))
            produits.remove(p)
            sauvegarder_stock(produits)
        self.envoyer_json(200, {"ok": True})

    def route_photo_produit(self, corps):
        with VERROU:
            produits = charger_stock()
            p = trouver(produits, str(corps.get("nom", "")))
            p["photo"] = enregistrer_photo(corps.get("data"), DOSSIER_PHOTOS_PRODUITS, nom_sur(p["nom"]))
            sauvegarder_stock(produits)
        self.envoyer_json(200, {"ok": True, "photo": p["photo"]})

    def route_retirer_photo(self, corps):
        with VERROU:
            produits = charger_stock()
            p = trouver(produits, str(corps.get("nom", "")))
            p["photo"] = ""
            sauvegarder_stock(produits)
        self.envoyer_json(200, {"ok": True})

    # --- Ventes ---
    def route_vente(self, corps):
        try:
            quantite = int(corps.get("quantite"))
        except (TypeError, ValueError):
            raise ErreurClient(400, "Quantité invalide.")
        if quantite < 1:
            raise ErreurClient(400, "La quantité doit être au moins 1.")

        with VERROU:
            produits = charger_stock()
            p = trouver(produits, str(corps.get("nom", "")))
            retirer_stock(p, quantite)  # lève ValueError si le stock est insuffisant
            try:
                recu = ""
                maintenant = datetime.now()
                if corps.get("recu"):
                    dossier = os.path.join(DOSSIER_PHOTOS_RECUS, maintenant.strftime("%Y-%m"))
                    recu = enregistrer_photo(corps["recu"], dossier, "recu")
                vid = ajouter_vente(p, quantite, recu, maintenant)
                sauvegarder_stock(produits)
            except Exception:
                p["qte"] += quantite  # annule la décrémentation en mémoire
                raise
            facture = texte_facture(p, quantite, vid, maintenant)
            restant = p["qte"]

        self.envoyer_json(200, {
            "ok": True,
            "facture": facture,
            "vid": vid,
            "nom": p["nom"],
            "restant": restant,
            "alerte": restant < SEUIL_ALERTE,
        })

    # --- Objectif mensuel ---
    def route_objectif(self, corps):
        try:
            montant = int(corps.get("montant"))
        except (TypeError, ValueError):
            raise ErreurClient(400, "Objectif invalide.")
        if not 0 <= montant <= 10 ** 12:
            raise ErreurClient(400, "Objectif hors limites.")
        with VERROU:
            enregistrer_objectif(montant)
        self.envoyer_json(200, {"ok": True})

    # --- Paramètres ---
    def route_parametres(self, corps):
        nom = str(corps.get("nom", "")).strip()
        if not nom or len(nom) > 60:
            raise ErreurClient(400, "Le nom de la boutique doit contenir entre 1 et 60 caractères.")
        with VERROU:
            parametres = charger_parametres()
            parametres["nom"] = nom
            enregistrer_parametres(parametres)
        self.envoyer_json(200, {"ok": True})

    def route_mot_de_passe(self, corps):
        """Changement de son propre mot de passe."""
        ancien = corps.get("ancien", "")
        nouveau = corps.get("nouveau", "")
        if not isinstance(ancien, str) or not isinstance(nouveau, str):
            raise ErreurClient(400, "Requête invalide.")
        moi = self.utilisateur_courant()
        with VERROU:
            utilisateurs = charger_utilisateurs()
            u = next((x for x in utilisateurs if x["id"] == moi["id"]), None)
            if u is None or not mot_de_passe_ok(u, ancien):
                raise ErreurClient(400, "Ancien mot de passe incorrect.")
            self.verifier_longueur(nouveau)
            definir_mot_de_passe(u, nouveau)
            enregistrer_utilisateurs(utilisateurs)
            self.fermer_sessions(u["id"])  # il faut se reconnecter sur tous les appareils
        self.envoyer_json(200, {"ok": True},
                          [("Set-Cookie", "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")])

    # --- Sauvegarde ---
    def route_sauvegarde(self, corps):
        with VERROU:
            dossier = sauvegarder_donnees()
        if dossier is None:
            raise ErreurClient(400, "Aucune donnée à sauvegarder.")
        self.envoyer_json(200, {"dossier": os.path.relpath(dossier, BASE)})


# ---------- Démarrage ----------
def ip_locale():
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # aucun paquet n'est envoyé, sert seulement à connaître l'interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        if s is not None:
            s.close()


def main():
    parser = argparse.ArgumentParser(description="Serveur local de gestion de stock")
    parser.add_argument("--reseau", action="store_true",
                        help="accepter les connexions du réseau local (téléphone sur le même Wi-Fi)")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    if not os.path.isfile(os.path.join(DOSSIER_STATIQUE, "index.html")):
        print("Fichier static/index.html introuvable. Vérifie la structure du dossier.")
        sys.exit(1)
    os.makedirs(DONNEES, exist_ok=True)

    hote = "0.0.0.0" if args.reseau else "127.0.0.1"
    serveur = ThreadingHTTPServer((hote, args.port), Gestionnaire)

    print("Gestion de stock lancée.")
    print(f"  Sur cet ordinateur : http://127.0.0.1:{args.port}")
    if args.reseau:
        print(f"  Sur le téléphone (même Wi-Fi) : http://{ip_locale()}:{args.port}")
        print("  Attention : trafic non chiffré, utilise-le uniquement sur un Wi-Fi de confiance.")
    print("Ctrl+C pour arrêter (une sauvegarde est créée automatiquement).")

    try:
        serveur.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        serveur.server_close()
        with VERROU:
            try:
                dossier = sauvegarder_donnees()
                if dossier:
                    print(f"Sauvegarde créée : {dossier}")
            except OSError as e:
                print(f"Sauvegarde impossible : {e}")


if __name__ == "__main__":
    main()
