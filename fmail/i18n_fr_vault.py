# -*- coding: utf-8 -*-
# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""French catalog for vault.py (English msgid -> original French text)."""

CATALOG = {
    "gpg: timed out": "gpg: delai depasse (timeout)",
    "gpg: not found": "gpg: introuvable",
    "encryption failed: {err}": "chiffrement échoué : {err}",
    "incorrect master password (or corrupted vault).":
        "mot de passe maître incorrect (ou coffre corrompu).",
    "vault locked.": "coffre verrouillé.",
    "vault unreadable ({path}): {e}": "coffre illisible ({path}) : {e}",
    "cannot write the vault ({path}): {e}": "écriture du coffre impossible ({path}) : {e}",
    "empty master password rejected.": "mot de passe maître vide refusé.",
    "the master password must not contain a line break "
    "(gpg would silently truncate it).":
        "le mot de passe maître ne doit pas contenir de saut de ligne "
        "(gpg le tronquerait silencieusement).",
    "master password too short (>= {n} characters).":
        "mot de passe maître trop court (≥ {n} caractères).",
    "unknown vault KDF: {algo!r}.": "KDF de coffre inconnue : {algo!r}.",
    "invalid vault KDF parameters.": "paramètres KDF du coffre invalides.",
    "vault unreadable (invalid envelope).": "coffre illisible (enveloppe invalide).",
    "vault unreadable (missing lock — truncated/corrupted envelope).":
        "coffre illisible (serrure absente — enveloppe tronquée/corrompue).",
    "vault decrypted but unreadable (JSON): {e}":
        "coffre déchiffré mais illisible (JSON) : {e}",
    "vault decrypted but unexpected format.":
        "coffre déchiffré mais format inattendu.",
    "a vault already exists: {path}": "un coffre existe déjà : {path}",
    "incorrect recovery code.": "code de récupération incorrect.",
    "the vault changed on disk — reload fmail.":
        "le coffre a changé sur le disque — recharge fmail.",
    "invalid contact address: {email!r}": "adresse de contact invalide : {email!r}",
}
