# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""French catalog for autocrypt.py — English msgid -> original French text.

Maps the English source strings (the message-ids used in autocrypt.py) back to
their original French wording. Placeholder names match the code exactly.
"""
CATALOG = {
    "gpg: timed out": "gpg: delai depasse (timeout)",
    "gpg: not found": "gpg: introuvable",
    "key generation failed: {err}": "génération de clé échouée : {err}",
    "key generated but not found afterwards": "clé générée mais introuvable ensuite",
    "vault locked: unlock it before migrating the keys.":
        "coffre verrouillé : déverrouille-le avant de migrer les clés.",
    "re-seal of {fpr} failed: {err} — restore the backup.":
        "le re-scellement de {fpr} a échoué : {err} — restaure la sauvegarde.",
    "migration verification failed for {n} key(s) — restore the backup.":
        "vérification de migration échouée pour {n} clé(s) — restaure la sauvegarde.",
    "key export failed: {err}": "export de clé échoué : {err}",
    "peer key rejected (non-conforming structure/UID)":
        "clé de pair refusée (structure/UID non conformes)",
    "key import failed: {err}": "import de clé échoué : {err}",
    "encryption failed: {err}": "chiffrement échoué : {err}",
    "local (sender) key not found": "clé locale (expéditeur) introuvable",
    "missing key for {em}": "clé manquante pour {em}",
    "key for {em} awaiting verification (change detected)":
        "clé de {em} en attente de vérification (changement détecté)",
    "local key not found to encrypt the draft":
        "clé locale introuvable pour chiffrer le brouillon",
    "message not encrypted (not PGP/MIME)": "message non chiffré (pas PGP/MIME)",
    "invalid PGP/MIME structure": "structure PGP/MIME invalide",
    "PGP/MIME control part missing": "partie de contrôle PGP/MIME absente",
    "unexpected PGP/MIME version": "version PGP/MIME inattendue",
    "encrypted part missing": "partie chiffrée absente",
    "empty encrypted part": "partie chiffrée vide",
    "decryption failed": "déchiffrement impossible",
}
