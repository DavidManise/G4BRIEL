# -*- coding: utf-8 -*-
# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""French catalog for fmail.py (English msgid -> original French text)."""

CATALOG = {
    "[encrypted]": "[chiffré]",
    # ── In-app update ──
    "could not check for updates: {e}": "impossible de vérifier les mises à jour : {e}",
    "could not check for updates: empty version.":
        "impossible de vérifier les mises à jour : version vide.",
    "download failed: {e}": "échec du téléchargement : {e}",
    "download failed for {name}: {e}": "échec du téléchargement de {name} : {e}",
    "update manifest invalid (missing files).": "manifeste de mise à jour invalide (fichiers manquants).",
    "checksum mismatch for {name} — update aborted.":
        "empreinte incohérente pour {name} — mise à jour annulée.",
    "cannot write the update ({e}). Check permissions on {dir}.":
        "impossible d'écrire la mise à jour ({e}). Vérifie les permissions de {dir}.",
    # ── Duress password (CLI) ──
    "⚠ DURESS PASSWORD. Entering it at launch will PERMANENTLY DESTROY all "
    "local fmail data (vault, keys, cache, accounts, passwords) behind a fake "
    "network-error screen. It must DIFFER from the master password and the "
    "recovery code. Leave EMPTY to disable.":
        "⚠ MOT DE PASSE DE CONTRAINTE. Le saisir au démarrage DÉTRUIRA DÉFINITIVEMENT "
        "toutes les données locales de fmail (coffre, clés, cache, comptes, mots de passe) "
        "derrière un faux écran d'erreur réseau. Il doit ÊTRE DIFFÉRENT du mot de passe "
        "maître et du code de récupération. Laisser VIDE pour le désactiver.",
    "Duress password (empty = disable): ": "Mot de passe de contrainte (vide = désactiver) : ",
    "✓ duress password disabled.": "✓ mot de passe de contrainte désactivé.",
    "Confirm duress password: ": "Confirmer le mot de passe de contrainte : ",
    "the two entries differ.": "les deux saisies diffèrent.",
    "✓ duress password set. Entering it at launch WIPES everything "
    "(irreversible).":
        "✓ mot de passe de contrainte défini. Le saisir au démarrage EFFACE tout "
        "(irréversible).",
    # ── Account / config ──
    "no password for “{name}” "
    "(vault locked? unlock it, or configure password_file).":
        "mot de passe absent pour « {name} » "
        "(coffre verrouillé ? déverrouille-le, ou configure password_file).",
    "password unreadable for “{name}” ({path}): {e}":
        "mot de passe illisible pour « {name} » ({path}) : {e}",
    "config missing: {path}\n  → create it from accounts.toml.example":
        "config absente : {path}\n  → crée-la depuis accounts.toml.example",
    "invalid config ({path}): {e}": "config invalide ({path}) : {e}",
    "no account in the config ([accounts.<name>] section).":
        "aucun compte dans la config (section [accounts.<nom>]).",
    "account “{name}”: must be an [accounts.{name}] section with keys (not a flat value).":
        "compte « {name} » : doit être une section [accounts.{name}] avec des clés (pas une valeur à plat).",
    "account “{name}”: invalid config ({e}).": "compte « {name} » : config invalide ({e}).",
    "default account “{name}” does not exist.": "compte par défaut « {name} » inexistant.",
    "unknown account: “{name}”. Available: {available}":
        "compte inconnu : « {name} ». Dispo : {available}",
    "[security] lock_timeout must be an integer (seconds).":
        "[security] lock_timeout doit être un entier (secondes).",

    # ── Vault unlock / passwords ──
    "fmail master password: ": "Mot de passe maître fmail : ",
    "unlock cancelled.": "déverrouillage annulé.",
    "incorrect password.": "mot de passe incorrect.",
    "unlock failed (3 tries).": "déverrouillage échoué (3 essais).",
    "Confirm: ": "Confirme : ",
    "the passwords do not match.": "les mots de passe ne correspondent pas.",
    "empty password rejected.": "mot de passe vide refusé.",

    # ── Recovery code ──
    "\n  ┌─ RECOVERY CODE ─────────────────────────────────┐":
        "\n  ┌─ CODE DE RÉCUPÉRATION ─────────────────────────────────┐",
    "  ⚠ WRITE IT DOWN and keep it OFFLINE (paper, password manager).":
        "  ⚠ NOTE-LE et garde-le HORS LIGNE (papier, gestionnaire de mots de passe).",
    "  It lets you recover the vault if you forget the master password.":
        "  Il permet de récupérer le coffre si tu oublies le mot de passe maître.",
    "  If you lose the password AND this code, the vault is PERMANENTLY unusable.\n":
        "  Si tu perds le mot de passe ET ce code, le coffre est DÉFINITIVEMENT inutilisable.\n",

    # ── vault command ──
    "Vault: absent.  (“fmail vault init” to create it.)":
        "Coffre : absent.  (« fmail vault init » pour le créer.)",
    "Vault: {path}": "Coffre : {path}",
    "(none)": "(aucun)",
    "  accounts in the vault: {accounts}": "  comptes dans le coffre : {accounts}",
    "  contacts: {n}": "  contacts : {n}",
    "  master_password active in the config: {active}":
        "  master_password actif dans la config : {active}",
    "no vault. “fmail vault init” first.": "aucun coffre. « fmail vault init » d'abord.",
    "Current master password: ": "Mot de passe maître actuel : ",
    "New master password": "Nouveau mot de passe maître",
    "current password incorrect.": "mot de passe actuel incorrect.",
    "✓ master password changed.": "✓ mot de passe maître changé.",
    "specify the account: fmail vault set-password <account>":
        "précise le compte : fmail vault set-password <compte>",
    "IMAP/SMTP password for “{name}”": "Mot de passe IMAP/SMTP de « {name} »",
    "✓ password for “{name}” saved in the vault.":
        "✓ mot de passe de « {name} » enregistré dans le coffre.",
    "a vault already exists: {path}": "un coffre existe déjà : {path}",
    "Creating the fmail encrypted vault (gpg --symmetric, AES-256, 2 locks).":
        "Création du coffre chiffré fmail (gpg --symmetric, AES-256, 2 serrures).",
    "Choose a master password (≥ {n} characters)":
        "Choisis un mot de passe maître (≥ {n} caractères)",
    "  password not found for “{name}” ({path}) — to re-add later.":
        "  mot de passe introuvable pour « {name} » ({path}) — à ré-ajouter plus tard.",
    "✓ vault created: {path}": "✓ coffre créé : {path}",
    "  {n} account password(s) imported.": "  {n} mot(s) de passe de compte importé(s).",
    "  Enable it by adding to your config (accounts.toml):":
        "  Active-le en ajoutant à ta config (accounts.toml) :",
    "  ⚠ The cleartext ~/secrets/*_mail_password files STILL exist.":
        "  ⚠ Les fichiers ~/secrets/*_mail_password en clair existent ENCORE.",
    "  Once everything works, purge them:  fmail vault purge-secrets":
        "  Une fois que tout marche, purge-les :  fmail vault purge-secrets",
    "no vault.": "aucun coffre.",
    "Recovering the vault via the RECOVERY CODE (forgotten password).":
        "Récupération du coffre via le CODE DE RÉCUPÉRATION (mot de passe oublié).",
    "Recovery code: ": "Code de récupération : ",
    "cancelled.": "annulé.",
    "New master password (≥ {n} characters)":
        "Nouveau mot de passe maître (≥ {n} caractères)",
    "recovery code incorrect.": "code de récupération incorrect.",
    "✓ new master password set (the old one is invalidated).":
        "✓ nouveau mot de passe maître défini (l'ancien est invalidé).",
    "Regenerating the code will invalidate the OLD one. Continue? [y/N] ":
        "Régénérer le code invalidera l'ANCIEN. Continuer ? [y/N] ",
    "Cancelled.": "Annulé.",
    "✓ new recovery code generated (the old one no longer works).":
        "✓ nouveau code de récupération généré (l'ancien ne marche plus).",
    "enable “master_password = true” in [security] first: otherwise, without the "
    "cleartext files or the unlocked vault, fmail could no longer connect.":
        "active d'abord « master_password = true » dans [security] : sinon, sans les "
        "fichiers en clair ni le coffre déverrouillé, fmail ne pourrait plus se connecter.",
    "unreadable ({e})": "illisible ({e})",
    "content ≠ vault or account absent from vault":
        "contenu ≠ coffre ou compte absent du coffre",
    "Files KEPT (not purged, for safety):":
        "Fichiers CONSERVÉS (non purgés, par sécurité) :",
    "   → sync them first:  fmail vault set-password <account>":
        "   → synchronise-les d'abord :  fmail vault set-password <compte>",
    "Nothing safe to purge.": "Rien à purger en sécurité.",
    "CLEARTEXT password files to delete (value identical to the vault):":
        "Fichiers de mot de passe EN CLAIR à supprimer (valeur identique au coffre) :",
    "Confirm permanent deletion? [y/N] ":
        "Confirmer la suppression définitive ? [y/N] ",
    "  deleted {path}": "  supprimé {path}",
    "  failed {path}: {e}": "  échec {path} : {e}",
    "✓ cleartext secrets (identical to the vault) purged — the vault is the source.":
        "✓ secrets en clair (identiques au coffre) purgés — le coffre est la source.",

    # ── add_account_to_config ──
    "account name: letters, digits, hyphen or underscore only.":
        "nom de compte : lettres, chiffres, tiret ou underscore uniquement.",
    "invalid e-mail address: {email!r}": "adresse e-mail invalide : {email!r}",
    "the account “{name}” already exists.": "le compte « {name} » existe déjà.",
    "{label} invalid.": "{label} invalide.",
    "display_name: control characters forbidden.":
        "display_name : caractères de contrôle interdits.",
    "a secret file already exists: {path}. Delete it or choose another account name.":
        "un fichier secret existe déjà : {path}. Supprime-le ou choisis un autre nom de compte.",
    "cannot write the secret ({path}): {e}":
        "écriture du secret impossible ({path}) : {e}",

    # ── IMAP connection / TLS ──
    "⚠ IMAP certificate for {host} REFUSED — interception likely (MITM)":
        "⚠ certificat IMAP de {host} REFUSÉ — interception probable (MITM)",
    "IMAP certificate refused (suspicious intermediary?): {e}":
        "certificat IMAP refusé (intermédiaire suspect ?) : {e}",
    "IMAP connection failed ({email}): {e}":
        "connexion IMAP impossible ({email}) : {e}",
    "IMAP certificate for {host} CHANGED — connection refused (accept the "
    "new certificate in the TUI alert).":
        "certificat IMAP de {host} CHANGÉ — connexion refusée (accepte le "
        "nouveau certificat dans l'alerte TUI).",
    "IMAP folder not found: {folder}": "dossier IMAP introuvable : {folder}",

    # ── Summaries / search ──
    "(?)": "(?)",
    "line break forbidden in the query (injection refused).":
        "saut de ligne interdit dans la requête (injection refusée).",
    "search refused by the server (CHARSET UTF-8?): {e}":
        "recherche refusée par le serveur (CHARSET UTF-8 ?) : {e}",
    "UID {uid}: message too large ({n} B > {max} B) — "
    "download refused (memory protection).":
        "UID {uid} : message trop volumineux ({n} o > {max} o) — "
        "téléchargement refusé (protection mémoire).",
    "UID {uid} not found.": "UID {uid} introuvable.",
    "(no usable text body)": "(pas de corps texte exploitable)",

    # ── State / rendering ──
    "no list remembered for “{name}”. Run first: fmail list":
        "aucune liste mémorisée pour « {name} ». Lance d'abord : fmail list",
    "unknown number: {token}. Re-run “fmail list” (or --uid for a raw UID).":
        "numéro inconnu : {token}. Relance « fmail list » (ou --uid pour un UID brut).",
    "{email} · {folder}  ({n} mails, {unseen} unread)":
        "{email} · {folder}  ({n} mails, {unseen} non lu(s))",
    "  (empty)": "  (vide)",
    "(no subject)": "(sans objet)",
    "  → read: fmail read <n>   reply: fmail reply <n>":
        "  → lire : fmail read <n>   répondre : fmail reply <n>",
    "From": "De",
    "To": "À",
    "Cc": "Cc",
    "Date": "Date",
    "\n-- Raw headers --": "\n-- En-têtes bruts --",

    # ── Address / composition ──
    "line break forbidden in an address (injection refused).":
        "saut de ligne interdit dans une adresse (injection refusée).",
    "invalid address: {addr!r}": "adresse invalide : {addr!r}",
    "%Y-%m-%d at %H:%M": "%d/%m/%Y à %H:%M",
    "On {when}, {name} wrote:": "Le {when}, {name} a écrit :",
    "the sender": "l’expéditeur",
    "attachment not found: {path}": "pièce jointe introuvable : {path}",
    "attachment unreadable ({path}): {e}": "pièce jointe illisible ({path}) : {e}",
    "the subject contains a line break (refused).":
        "le sujet contient un saut de ligne (refusé).",
    "invalid address: {e}": "adresse invalide : {e}",

    # ── Preview / confirm ──
    "─── Message preview ───": "─── Aperçu du message ───",
    "(unnamed)": "(sans nom)",
    "Attachments: ": "Pièces jointes : ",
    "[--dry-run] message NOT sent.": "[--dry-run] message NON envoyé.",
    "Send? [y/N] ": "Envoyer ? [y/N] ",

    # ── TLS pinning / SMTP ──
    "unknown issuer": "émetteur inconnu",
    "⚠ cannot save the TLS pin for {host} "
    "(disk?) — interception detection degraded.":
        "⚠ impossible d'enregistrer l'épinglage TLS de {host} "
        "(disque ?) — détection d'interception dégradée.",
    "⚠ certificate for {host}:{port} CHANGED — possible interception (MITM). "
    "Issuer “{issuer}”. Connection REFUSED until you accept the new "
    "certificate (fingerprint {fpr}…).":
        "⚠ certificat de {host}:{port} CHANGÉ — interception possible (MITM). "
        "Émetteur « {issuer} ». Connexion REFUSÉE tant que tu n'as pas accepté le "
        "nouveau certificat (empreinte {fpr}…).",
    "certificate “{issuer}” memorized ({fpr}…)":
        "certificat « {issuer} » mémorisé ({fpr}…)",
    "certificate recognized (“{issuer}”)": "certificat reconnu (« {issuer} »)",
    "⚠ SERVER CERTIFICATE CHANGED — send REFUSED (possible interception)":
        "⚠ CERTIFICAT DU SERVEUR CHANGÉ — envoi REFUSÉ (interception possible)",
    "connecting to {host}:{port} (SSL/TLS)":
        "connexion {host}:{port} (SSL/TLS)",
    "⚠ SERVER CERTIFICATE REFUSED — interception likely (MITM)":
        "⚠ CERTIFICAT SERVEUR REFUSÉ — interception probable (MITM)",
    "⚠ SMTP certificate for {host} REFUSED — interception likely (MITM)":
        "⚠ certificat SMTP de {host} REFUSÉ — interception probable (MITM)",
    "TLS certificate refused (suspicious intermediary?): {e}":
        "certificat TLS refusé (intermédiaire suspect ?) : {e}",
    "SMTP connection failed: {e}": "échec de connexion SMTP : {e}",
    "SMTP certificate for {host} CHANGED — send refused (accept the "
    "new certificate in the TUI alert).":
        "certificat SMTP de {host} CHANGÉ — envoi refusé (accepte le "
        "nouveau certificat dans l'alerte TUI).",
    "authenticating {email}": "authentification {email}",
    "authenticated": "authentifié",
    "transmitting the message ({n} bytes)":
        "transmission du message ({n} octets)",
    "message accepted by the server": "message accepté par le serveur",
    "SMTP send failed: {e}": "échec de l'envoi SMTP : {e}",

    # ── Sent copy / draft ──
    "no “Sent” folder (copy skipped)": "pas de dossier « Sent » (copie ignorée)",
    "archiving the copy in “{folder}”": "archivage de la copie dans « {folder} »",
    "copy archived": "copie archivée",
    "copy to Sent failed (skipped)": "copie dans Sent impossible (ignorée)",
    "draft save failed: {e}": "sauvegarde du brouillon impossible : {e}",

    # ── finalize_send ──
    "  (copy in Sent)": "  (copie dans Sent)",
    "✓ Sent to {to}": "✓ Envoyé à {to}",

    # ── accounts command ──
    " (default)": " (défaut)",

    # ── read / mark ──
    "[marked as read]": "[marqué comme lu]",
    "unread": "non lu",
    "read": "lu",
    "✓ UID {uid} marked {state}.": "✓ UID {uid} marqué {state}.",

    # ── move / archive / trash ──
    "Move to {dest}:": "Déplacer vers {dest} :",
    "[--dry-run] no move performed.": "[--dry-run] aucun déplacement effectué.",
    "Confirm? [y/N] ": "Confirmer ? [y/N] ",
    "copy to {dest} failed.": "copie vers {dest} échouée.",
    "✓ UID {uid} → {dest}": "✓ UID {uid} → {dest}",
    "no Archive folder detected (configure archive_folder).":
        "aucun dossier Archive détecté (configure archive_folder).",
    "no Trash folder detected (configure trash_folder).":
        "aucun dossier Corbeille détecté (configure trash_folder).",

    # ── forward / compose ──
    "\n\n---------- Forwarded message ----------\n":
        "\n\n---------- Message transféré ----------\n",
    "Subject: ": "Sujet : ",
    "subject entry interrupted.": "saisie du sujet interrompue.",
    "⚠ empty subject.": "⚠ sujet vide.",

    # ── argparse help / descriptions ──
    "Minimalist multi-account CLI mail client.":
        "Client mail CLI minimaliste multi-comptes.",
    "Account to use (default: config).": "Compte à utiliser (défaut : config).",
    "List number (see fmail list) or UID with --uid.":
        "Numéro de liste (cf. fmail list) ou UID avec --uid.",
    "Interpret target as a raw IMAP UID.":
        "Interpréter target comme UID IMAP brut.",
    "IMAP folder (default: the list's).": "Dossier IMAP (défaut : celui de la liste).",
    "Message body (otherwise opens the editor).":
        "Corps du message (sinon ouvre l'éditeur).",
    "Attachment (repeatable).": "Pièce jointe (répétable).",
    "Interpret the body as Markdown → HTML send (+ text fallback).":
        "Interpréter le corps en Markdown → envoi HTML (+ repli texte).",
    "Build without sending.": "Construit sans envoyer.",
    "Send without confirmation.": "Envoyer sans confirmation.",
    "Show the target without moving.": "Montre la cible sans déplacer.",
    "Move without confirmation.": "Déplacer sans confirmation.",
    "List the configured accounts.": "Liste les comptes configurés.",
    "List the IMAP folders.": "Liste les dossiers IMAP.",
    "Encrypted vault (master password).": "Coffre chiffré (mot de passe maître).",
    "account (for set-password).": "compte (pour set-password).",
    "List a folder's mails.": "Liste les mails d'un dossier.",
    "Unread only.": "Uniquement les non-lus.",
    "Full-text search.": "Recherche plein-texte.",
    "Display a full mail.": "Affiche un mail complet.",
    "Show all headers.": "Afficher tous les en-têtes.",
    "Mark as read.": "Marquer comme lu.",
    "Mark read/unread.": "Marque lu/non-lu.",
    "Mark unread (default: read).": "Marquer non-lu (défaut : lu).",
    "Move a mail to a folder.": "Déplace un mail vers un dossier.",
    "Destination folder.": "Dossier destination.",
    "Move to Archive.": "Déplace vers Archive.",
    "Move to Trash.": "Déplace vers la Corbeille.",
    "Reply to a mail.": "Répond à un mail.",
    "Reply to all (To+Cc).": "Répondre à tous (To+Cc).",
    "Forward a mail.": "Transfère un mail.",
    "Recipient(s).": "Destinataire(s).",
    "New message.": "Nouveau message.",
    "Copy(ies).": "Copie(s).",
    "Subject (otherwise prompt).": "Sujet (sinon prompt).",

    # ── main error handlers ──
    "IMAP error (connection interrupted?): {e}":
        "erreur IMAP (connexion interrompue ?) : {e}",
    "network error: {e}": "erreur réseau : {e}",
}
