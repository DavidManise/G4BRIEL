# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""French catalog for fmail_tui.py — English msgid -> original French text.

Maps the English source strings (the message-ids used in fmail_tui.py) back to
their original French wording. Placeholder names match the code exactly.
"""
CATALOG = {
    # ── In-app update (Config menu) ──────────────────────────────────────
    "Update fmail…": "Mettre à jour fmail…",
    "Update fmail": "Mise à jour de fmail",
    " Update fmail": " Mise à jour de fmail",
    "fmail runs from its data/dev directory ({app}) — updating here would\n"
    "overwrite local files. Update it with git, or re-run the installer.":
        "fmail tourne depuis son dossier de données/dev ({app}) — une mise à jour ici\n"
        "écraserait des fichiers locaux. Mets-le à jour via git, ou relance l'installeur.",
    "Checking for updates…": "Vérification des mises à jour…",
    "fmail is up to date (v{v}).": "fmail est à jour (v{v}).",
    "A new version is available:": "Une nouvelle version est disponible :",
    "  installed: v{v}": "  installée : v{v}",
    "  latest:    v{v}": "  dernière :  v{v}",
    "Download and install it now?  [Y/n]": "La télécharger et l'installer maintenant ?  [O/n]",
    "Downloading update…": "Téléchargement de la mise à jour…",
    "✓ Updated to v{v}.": "✓ Mis à jour en v{v}.",
    "Restart fmail to run the new version.": "Redémarre fmail pour lancer la nouvelle version.",
    "Quit fmail now to restart?  [Y/n]": "Quitter fmail maintenant pour redémarrer ?  [O/n]",
    "✓ updated to v{v} — restart fmail to apply.":
        "✓ mis à jour en v{v} — redémarre fmail pour appliquer.",
    # ── Duress decoy (fake connection failure while wiping) ──────────────
    "Connecting to {host}": "Connexion à {host}",
    "authenticating…": "authentification…",
    "connection failed — retrying in 3 s…": "échec de connexion — nouvelle tentative dans 3 s…",
    "Error: could not reach the mail server (connection timed out).":
        "Erreur : impossible de joindre le serveur de messagerie (délai de connexion dépassé).",
    # ── Launch splash ────────────────────────────────────────────────────
    "secure terminal mail": "messagerie sécurisée au terminal",
    # ── First-launch wizard: add an account ──────────────────────────────
    "No mail account configured yet. Run fmail again to use the setup "
    "wizard, or edit ~/freyja-mail/accounts.toml (see accounts.toml.example).":
        "Aucun compte mail configuré pour l'instant. Relance fmail pour utiliser "
        "l'assistant, ou édite ~/freyja-mail/accounts.toml (voir accounts.toml.example).",
    "No mail account is configured yet.": "Aucun compte mail n'est configuré pour l'instant.",
    "Let's add your first account (IMAP/SMTP).": "Ajoutons ton premier compte (IMAP/SMTP).",
    "You can add more later with the “N” key, or edit accounts.toml by hand.":
        "Tu pourras en ajouter d'autres avec la touche « N », ou éditer accounts.toml à la main.",
    " Add a mail account": " Ajouter un compte mail",
    "Add an account now?  [Y/n]   (Esc: skip)": "Ajouter un compte maintenant ?  [O/n]   (Échap : passer)",
    " No account added": " Aucun compte ajouté",
    "No account was added (cancelled or invalid).": "Aucun compte n'a été ajouté (annulé ou invalide).",
    "Try again?  [Y/n]   (Esc: skip)": "Réessayer ?  [O/n]   (Échap : passer)",
    # ── First-launch wizard: cleartext-storage warning ───────────────────
    "⚠ Without a master password, fmail stores your mail UNENCRYPTED.":
        "⚠ Sans mot de passe maître, fmail stocke tes mails EN CLAIR.",
    "Your account passwords (~/secrets) and the local cache — the":
        "Les mots de passe de tes comptes (~/secrets) et le cache local — les",
    "subjects AND full bodies of your messages (~/freyja-mail) — sit in":
        "sujets ET le corps complet de tes messages (~/freyja-mail) — restent en",
    "CLEARTEXT on this machine, readable by anyone who can read your files":
        "CLAIR sur cette machine, lisibles par quiconque peut lire tes fichiers",
    "(another user, a backup, a stolen disk).":
        "(un autre utilisateur, une sauvegarde, un disque volé).",
    "You can enable encryption later at any time with:  fmail vault init":
        "Tu peux activer le chiffrement plus tard à tout moment avec :  fmail vault init",
    " Heads-up: no encryption": " Attention : pas de chiffrement",
    "Encrypt after all?  [Y/n]   (Enter = yes, recommended · n = keep cleartext)":
        "Chiffrer finalement ?  [O/n]   (Entrée = oui, recommandé · n = garder en clair)",
    "fmail starts WITHOUT encryption — mail is cached in cleartext.":
        "fmail démarre SANS chiffrement — les mails sont mis en cache en clair.",
    # ── Uninstall (Config menu) ──────────────────────────────────────────
    "Uninstall fmail…": "Désinstaller fmail…",
    "Uninstall": "Désinstallation",
    "The fmail program directory ({app}) also holds your data or encrypted "
    "vault ({data}).\n\n"
    "To avoid destroying your mail, accounts, vault or keys, fmail will NOT "
    "uninstall itself from here. Remove it by hand if you really want to.":
        "Le dossier du programme fmail ({app}) contient aussi tes données ou ton "
        "coffre chiffré ({data}).\n\n"
        "Pour éviter de détruire tes mails, comptes, coffre ou clés, fmail ne se "
        "désinstallera PAS d'ici. Retire-le à la main si tu y tiens vraiment.",
    "Remove the fmail PROGRAM from this computer?": "Retirer le PROGRAMME fmail de cet ordinateur ?",
    "Will be DELETED:": "Sera SUPPRIMÉ :",
    "  • program: {app}": "  • programme : {app}",
    "  • command: {bin}": "  • commande : {bin}",
    "  • command: (not found / not this install)": "  • commande : (introuvable / autre installation)",
    "Will be KEPT — your data, accounts, encrypted vault and cache:":
        "Sera CONSERVÉ — tes données, comptes, coffre chiffré et cache :",
    "  • {data}": "  • {data}",
    "  • vault: {vault}": "  • coffre : {vault}",
    "(To erase your data too — irreversible — delete those yourself.)":
        "(Pour effacer aussi tes données — irréversible — supprime-les toi-même.)",
    " Uninstall fmail": " Désinstaller fmail",
    "Remove the fmail program?  [y/N] ": "Retirer le programme fmail ?  [o/N] ",
    "fmail has been removed. Your data is kept in {data}.":
        "fmail a été retiré. Tes données sont conservées dans {data}.",
    "Uninstall finished with errors: {err}": "Désinstallation terminée avec des erreurs : {err}",
    "Press a key to quit fmail.": "Appuie sur une touche pour quitter fmail.",
    # ── Human-readable size units ──────────────────────────────────────────
    "B": "o",
    "KB": "Ko",
    "MB": "Mo",
    "GB": "Go",
    "TB": "To",
    "PB": "Po",
    "{n} {unit}": "{n} {unit}",
    "{n:.1f} {unit}": "{n:.1f} {unit}",

    # ── File explorer (pure logic) ─────────────────────────────────────────
    "unreadable: {e}": "illisible : {e}",
    "no match": "aucune correspondance",
    "completion failed": "complétion impossible",
    "{n} matches": "{n} correspondances",

    # ── Fingerprint ────────────────────────────────────────────────────────
    "(unknown)": "(inconnue)",

    # ── Setup / cache ──────────────────────────────────────────────────────
    "master_password enabled but no vault. Run first: fmail vault init":
        "master_password activé mais aucun coffre. Lance d'abord : fmail vault init",
    "⚠ /dev/shm missing: cache decrypted to disk for the session.":
        "⚠ /dev/shm absent : cache déchiffré sur disque le temps de la session.",
    "cache unreadable (rebuilt): ": "cache illisible (reconstruit) : ",

    # ── Button bar ─────────────────────────────────────────────────────────
    "m Menu ▾": "m Menu ▾",
    "↵ Open": "↵ Ouvrir",
    "r Reply": "r Répondre",
    "c Write": "c Écrire",
    "a Archive": "a Archiver",
    "d Del": "d Suppr",
    "n ↻ Check": "n ↻ Vérifier",
    "/ Search": "/ Chercher",
    "? Help": "? Aide",
    "q Quit": "q Quitter",

    # ── Dropdown menu ──────────────────────────────────────────────────────
    "Open mail": "Ouvrir le mail",
    "Reply": "Répondre",
    "Reply to all": "Répondre à tous",
    "Forward": "Transférer",
    "Compose": "Composer",
    "Archive": "Archiver",
    "Move to trash": "Mettre à la corbeille",
    "Move…": "Déplacer…",
    "Mark read / unread": "Marquer lu / non-lu",
    "Search": "Rechercher",
    "Filter unread": "Filtrer non-lus",
    "Check for new mail": "Vérifier les nouveaux mails",
    "🔒 Encryption help (exchange secure mail)":
        "🔒 Aide au chiffrement (échanger des mails sécurisés)",
    "⚙ Configuration ▸": "⚙ Configuration ▸",
    "General help": "Aide générale",
    "Quit fmail": "Quitter fmail",
    "Account signature": "Signature du compte",
    "Switch account": "Changer de compte",
    "Add an account": "Ajouter un compte",
    "‹ Back": "‹ Retour",

    # ── Status / sync ──────────────────────────────────────────────────────
    "Syncing": "Synchronisation",
    "Syncing folder…": "Synchronisation du dossier…",
    "encrypted draft: cannot decrypt (missing key?).":
        "brouillon chiffré : déchiffrement impossible (clé manquante ?).",

    # ── Main rendering ─────────────────────────────────────────────────────
    " ✚ {n} new ": " ✚ {n} nouveau(x) ",
    " ⚠ sync ": " ⚠ sync ",
    "Accounts": "Comptes",
    "{folder} · {total} msg · {unread} unread":
        "{folder} · {total} msg · {unread} non-lus",
    "[unread]": "[non-lus]",
    "(empty)": "(vide)",
    "(no subject)": "(sans objet)",

    # ── Menu drawing ───────────────────────────────────────────────────────
    "Configuration": "Configuration",
    "Menu": "Menu",
    " ↑↓ choose · ↵ confirm · → / ← sub-menu · Esc/m close":
        " ↑↓ choisir · ↵ valider · → / ← sous-menu · Échap/m fermer",

    # ── Reading a mail ─────────────────────────────────────────────────────
    " · sender signature verified ✔": " · signature de l'expéditeur vérifiée ✔",
    " · ⚠ SIGNATURE BY AN EXPIRED KEY": " · ⚠ SIGNATURE PAR UNE CLÉ EXPIRÉE",
    " · ⚠ SIGNATURE BY A REVOKED KEY": " · ⚠ SIGNATURE PAR UNE CLÉ RÉVOQUÉE",
    " · ⚠ signed by a DIFFERENT key than the sender":
        " · ⚠ signé par une AUTRE clé que l'expéditeur",
    " · ⚠ NOT SIGNED — sender NOT authenticated":
        " · ⚠ NON SIGNÉ — expéditeur NON authentifié",
    "Security": "Sécurité",
    "🔒 encrypted": "🔒 chiffré",
    "⚠ encrypted — cannot decrypt": "⚠ chiffré — déchiffrement impossible",
    "Subject": "Sujet",
    "From": "De",
    "To": "À",
    "Cc": "Cc",
    "Date": "Date",
    "🔓 message IN CLEAR (not encrypted)": "🔓 message EN CLAIR (non chiffré)",
    "⚠ Key": "⚠ Clé",
    "this contact's key has CHANGED since the last exchange — \"v\" to verify/accept (otherwise auto-encryption suspended)":
        "la clé de ce contact a CHANGÉ depuis le dernier échange — « v » pour vérifier/accepter (sinon chiffrement auto suspendu)",
    "(cannot decrypt this message — missing key?)":
        "(impossible de déchiffrer ce message — clé manquante ?)",
    "(unnamed)": "(sans nom)",
    "Attachments": "Pièces jointes",
    " Reading · {folder}": " Lecture · {folder}",
    " ↑↓ scroll  r reply  f forward": " ↑↓ défiler  r répondre  f transférer",
    "  s save-att": "  s enregistrer-PJ",
    "  a archive  d trash": "  a archiver  d corbeille",
    "  v verify-key": "  v vérifier-clé",
    "  Esc back": "  Échap retour",

    # ── Attachments: saving ────────────────────────────────────────────────
    "no attachment in this message.": "aucune pièce jointe dans ce message.",
    "→ Save all": "→ Tout enregistrer",
    "Which attachment to save?": "Quelle pièce jointe enregistrer ?",
    "Destination folder": "Dossier de destination",
    "folder not found: {dir}": "dossier introuvable : {dir}",
    "failed to save {fn}: {e}": "échec de l'enregistrement de {fn} : {e}",
    "✓ {n} attachment(s) saved in {dir}":
        "✓ {n} pièce(s) jointe(s) enregistrée(s) dans {dir}",
    "Include the {n} attachment(s) in the forward?":
        "Inclure les {n} pièce(s) jointe(s) au transfert ?",

    # ── Signature ──────────────────────────────────────────────────────────
    "Signature — {name}": "Signature — {name}",
    "^G save · Esc cancel   (the \"-- \" separator is added automatically)":
        "^G enregistrer · Échap annuler   (le séparateur « -- » est ajouté tout seul)",
    "✓ signature saved": "✓ signature enregistrée",
    "cannot write: {e}": "écriture impossible : {e}",

    # ── Reply / forward ────────────────────────────────────────────────────
    "\n\n---------- Forwarded message ----------\n":
        "\n\n---------- Message transféré ----------\n",

    # ── Composer ───────────────────────────────────────────────────────────
    "To    ": "À     ",
    "Cc    ": "Cc    ",
    "Bcc   ": "Cci   ",
    "Subj  ": "Objet ",
    "plain text": "texte brut",
    "Markdown→HTML": "Markdown→HTML",
    "auto: ": "auto: ",
    "Markdown": "Markdown",
    "text": "texte",
    "🔓 a contact's key CHANGED — \"v\" to verify":
        "🔓 clé d'un contact a CHANGÉ — « v » pour vérifier",
    "🔓 cannot encrypt (missing key)": "🔓 chiffrement impossible (clé manquante)",
    "🔓 cleartext · encryptable (^E)": "🔓 clair · chiffrable (^E)",
    "🔓 not encrypted · recipient key missing (^A help)":
        "🔓 non chiffré · clé du destinataire manquante (^A aide)",
    "🔓 cleartext": "🔓 clair",
    " 🔒 ENCRYPTED MESSAGE   (^G send · ^E encryption · ^A help · Esc quit)":
        " 🔒 MESSAGE CHIFFRÉ   (^G envoyer · ^E chiffrement · ^A aide · Échap quitter)",
    " New message  [{flabel}] [{lock}]  (^G send · ^E encrypt · ^F From · ^O attach · ^X att · ^T format · ^A help · Esc quit)":
        " Nouveau message  [{flabel}] [{lock}]  (^G envoyer · ^E chiffrer · ^F De · ^O joindre · ^X PJ · ^T format · ^A aide · Échap quitter)",
    " 🔒 ENCRYPTED MESSAGE — OpenPGP/MIME (RFC 3156) · AES-256 · signed Ed25519  ·  for {n} recipient(s) + you":
        " 🔒 MESSAGE CHIFFRÉ — OpenPGP/MIME (RFC 3156) · AES-256 · signé Ed25519  ·  pour {n} destinataire(s) + vous",
    "  From  : {name} <{email}>  (^F)": "  De    : {name} <{email}>  (^F)",
    "(none)": "(aucune)",
    "  Att   : {att}": "  PJ    : {att}",
    "format: ": "format : ",
    "auto-detect": "auto-détection",
    "encryption: ": "chiffrement : ",
    "auto": "auto",
    "forced": "forcé",
    "disabled": "désactivé",
    "Leave the editor": "Quitter l'éditeur",
    "Back to the mail": "Revenir au mail",
    "Save the draft": "Sauvegarder le brouillon",
    "Discard the message": "Abandonner le message",

    # ── Sending ────────────────────────────────────────────────────────────
    "only one account configured.": "un seul compte configuré.",
    "Send from": "Envoyer depuis",
    "From: ": "De : ",
    "missing recipient.": "destinataire manquant.",
    "key changed for {who} — verify it in the reader (\"v\" key) before encrypting.":
        "clé changée pour {who} — vérifie-la dans le lecteur (touche « v ») avant de chiffrer.",
    "encryption expected but gpg unavailable — send blocked (retry, or ^E to disable).":
        "chiffrement attendu mais gpg indisponible — envoi bloqué (réessaie, ou ^E pour désactiver).",
    "cannot encrypt: key missing for a recipient (^E to send in cleartext).":
        "chiffrement impossible : clé manquante pour un destinataire (^E pour envoyer en clair).",
    "Bcc not supported with encryption (v1): remove the Bcc, or ^E to send in cleartext.":
        "Cci non géré avec le chiffrement (v1) : retire le Cci, ou ^E pour envoyer en clair.",
    "encryption failed: ": "échec du chiffrement : ",
    "From   : ": "De     : ",
    "To     : ": "À      : ",
    "Cc     : ": "Cc     : ",
    "Bcc    : ": "Cci    : ",
    "Subject: ": "Objet  : ",
    "Encr.  : ": "Chiffr.: ",
    "Format : ": "Format : ",
    "Markdown → HTML": "Markdown → HTML",
    "Att    : ": "PJ     : ",
    "Send this message?": "Envoyer ce message ?",
    "✓ Message sent": "✓ Message envoyé",
    " from {email}.": " depuis {email}.",
    "  ⚠ old draft not deleted": "  ⚠ ancien brouillon non supprimé",

    # ── Drafts ─────────────────────────────────────────────────────────────
    "Drafts folder not found.": "dossier Brouillons (Drafts) introuvable.",
    "cannot create encrypted draft: ": "brouillon chiffré impossible : ",
    "✓ draft saved in ": "✓ brouillon enregistré dans ",
    "  ⚠ old draft not deleted (duplicate)":
        "  ⚠ ancien brouillon non supprimé (doublon)",

    # ── Verbose check ──────────────────────────────────────────────────────
    "⟩⟩ MAIL CHECK": "⟩⟩ RELÈVE DU COURRIER",
    "· in progress ·": "· en cours ·",
    "querying the server (SEARCH ALL)…": "interrogation du serveur (SEARCH ALL)…",
    "server ↔ cache diff: {new} new, {deleted} deleted":
        "diff serveur ↔ cache : {new} nouveau(x), {deleted} supprimé(s)",
    "fetching {n} header(s)…": "récupération de {n} en-tête(s)…",
    "{n} header(s) fetched": "{n} en-tête(s) récupéré(s)",
    "reconciling flags ({n} message(s))…":
        "réconciliation des indicateurs ({n} message(s))…",
    "IMAP connection {host}:{port} (SSL/TLS)":
        "connexion IMAP {host}:{port} (SSL/TLS)",
    "selecting folder \"{folder}\"": "sélection du dossier « {folder} »",
    "✓ UP TO DATE — {new} new, {deleted} deleted":
        "✓ À JOUR — {new} nouveau(x), {deleted} supprimé(s)",
    " — OK": " — OK",
    "(Enter, or closes by itself)": "(Entrée, ou se ferme seul)",
    "✗ FAILED: {e}": "✗ ÉCHEC : {e}",
    " — FAILED": " — ÉCHEC",
    "[Enter] close": "[Entrée] fermer",

    # ── Move actions ───────────────────────────────────────────────────────
    "destination folder not found (configure it in accounts.toml).":
        "dossier de destination introuvable (configure-le dans accounts.toml).",
    "{verb} → {dest}?   {info}": "{verb} → {dest} ?   {info}",
    "✓ moved to {dest}": "✓ déplacé vers {dest}",
    "copy to {dest} failed.": "copie vers {dest} échouée.",
    "copied to {dest}, but not purged at source (UID {uid} stays \"deleted\").":
        "copié vers {dest}, mais non purgé en source (UID {uid} reste « supprimé »).",
    "Move to which folder?": "Déplacer vers quel dossier ?",
    "Move": "Déplacer",

    # ── Search & pickers ───────────────────────────────────────────────────
    "Search: ": "Recherche : ",
    "Searching “{q}” on the server…": "Recherche de « {q} » sur le serveur…",
    "server search unavailable — filtering locally (subject/sender).":
        "recherche serveur indisponible — filtrage local (objet/expéditeur).",
    "server search unavailable ({e}) — local filter":
        "recherche serveur indisponible ({e}) — filtre local",
    "Short name (e.g. personal)": "Nom court (ex: perso)",
    "Email address": "Adresse e-mail",
    "IMAP server": "Serveur IMAP",
    "SMTP server": "Serveur SMTP",
    "IMAP server (host, or host:port)": "Serveur IMAP (hôte, ou hôte:port)",
    "SMTP server (host, or host:port — Enter = same as IMAP)":
        "Serveur SMTP (hôte, ou hôte:port — Entrée = même que l'IMAP)",
    "{proto} port — a number, or Enter for the usual {default}":
        "Port {proto} — un nombre, ou Entrée pour la valeur habituelle {default}",
    "Display name (optional)": "Nom affiché (optionnel)",
    "Password (or app password): ": "Mot de passe (ou mot de passe d'application) : ",
    "✓ account \"{name}\" added and selected.":
        "✓ compte « {name} » ajouté et sélectionné.",

    # ── File browser ───────────────────────────────────────────────────────
    "Attach \"{name}\" ({size})?": "Joindre « {name} » ({size}) ?",
    "not a regular file: {name}": "pas un fichier régulier : {name}",
    "unreadable file: {name}": "fichier illisible : {name}",
    "invalid path": "chemin invalide",
    "not a directory: {target}": "pas un dossier : {target}",
    "access denied: {target}": "accès refusé : {target}",
    " Attach a file — {cwd}": " Joindre un fichier — {cwd}",
    " ⏎ open/attach · cd <d> · ls [-a] · ⇥ complete · Esc cancel":
        " ⏎ ouvrir/joindre · cd <d> · ls [-a] · ⇥ compléter · Échap annuler",
    "hidden files ": "cachés ",
    "shown": "affichés",
    "hidden": "masqués",
    "not found: {cmd}": "introuvable : {cmd}",

    # ── Line input / lock ──────────────────────────────────────────────────
    "Enter confirm · Esc cancel": "Entrée valider · Échap annuler",
    "🔒  fmail locked — master password":
        "🔒  fmail verrouillé — mot de passe maître",
    "Enter unlock · Esc quit fmail": "Entrée déverrouiller · Échap quitter fmail",
    "locked — closing fmail.": "verrouillé — fermeture de fmail.",
    "✓ unlocked.": "✓ déverrouillé.",
    "incorrect password.": "mot de passe incorrect.",

    # ── Master password / recovery ─────────────────────────────────────────
    "Choose a master password (≥ {n} characters)":
        "Choisis un mot de passe maître (≥ {n} caractères)",
    "Confirm the master password": "Confirme le mot de passe maître",
    "the two entries differ.": "les deux saisies diffèrent.",
    "Note this RECOVERY CODE and keep it OFFLINE":
        "Note ce CODE DE RÉCUPÉRATION et garde-le HORS LIGNE",
    "(paper, password manager):": "(papier, gestionnaire de mots de passe) :",
    "It lets you recover the vault if you FORGET the master password.":
        "Il permet de récupérer le coffre si tu OUBLIES le mot de passe maître.",
    "⚠ If you lose the password AND this code, the vault will be":
        "⚠ Si tu perds le mot de passe ET ce code, le coffre sera",
    "  PERMANENTLY UNUSABLE (data unrecoverable).":
        "  DÉFINITIVEMENT INUTILISABLE (données irrécupérables).",
    " RECOVERY CODE — WRITE IT DOWN NOW":
        " CODE DE RÉCUPÉRATION — À NOTER MAINTENANT",
    " Have you saved the code somewhere safe?  [y/N] ":
        " As-tu noté le code en lieu sûr ?  [o/N] ",

    # ── Setup wizard ───────────────────────────────────────────────────────
    "Welcome to fmail.": "Bienvenue dans fmail.",
    "Do you want to PROTECT fmail with a master password?":
        "Veux-tu PROTÉGER fmail par un mot de passe maître ?",
    "An encrypted vault (AES-256) will then protect:":
        "Un coffre chiffré (AES-256) protégera alors :",
    "  • your account passwords,": "  • les mots de passe de tes comptes,",
    "  • your address book,": "  • ton carnet d'adresses,",
    "  • the local cache (mail subjects + bodies).":
        "  • le cache local (sujets + corps des mails).",
    "You will have to enter this password each time you open fmail.":
        "Tu devras saisir ce mot de passe à chaque ouverture de fmail.",
    "A recovery code will be given to you (in case you forget the password).":
        "Un code de récupération te sera donné (en cas d'oubli du mot de passe).",
    " fmail configuration (first launch)":
        " Configuration de fmail (premier lancement)",
    "Encrypt fmail in a secure vault?  [Y/n]   (Esc: decide later)":
        "Chiffrer fmail dans un coffre sécurisé ?  [O/n]   (Échap : décider plus tard)",
    "fmail starts without encryption (enable with: fmail vault init).":
        "fmail démarre sans chiffrement (activable : fmail vault init).",
    "configuration deferred (no password set).":
        "configuration reportée (aucun mot de passe défini).",
    "cannot create the vault: ": "création du coffre impossible : ",
    "✓ vault enabled ({n} passwords imported). Check, then \"fmail vault purge-secrets\" to wipe the cleartext passwords.":
        "✓ coffre activé ({n} mdp importés). Vérifie, puis « fmail vault purge-secrets » pour effacer les mdp en clair.",

    # ── TLS certificate change ─────────────────────────────────────────────
    "The TLS certificate of {host}:{port} has CHANGED.":
        "Le certificat TLS de {host}:{port} a CHANGÉ.",
    "Issuer     : ": "Émetteur  : ",
    "Fingerprint: ": "Empreinte : ",
    "⚠ This may be a legitimate rotation (renewal) OR an INTERCEPTION.":
        "⚠ Cela peut être une rotation légitime (renouvellement) OU une INTERCEPTION.",
    "  The connection (login + mails) is REFUSED until you have accepted.":
        "  La connexion (login + mails) est REFUSÉE tant que tu n'as pas accepté.",
    "  Verify the fingerprint with your host / via another channel before accepting.":
        "  Vérifie l'empreinte avec ton hébergeur / par un autre canal avant d'accepter.",
    " ⚠ TLS CERTIFICATE CHANGED — possible interception (MITM)":
        " ⚠ CERTIFICAT TLS CHANGÉ — interception possible (MITM)",
    " Accept this NEW certificate?  [y/N] ":
        " Accepter ce NOUVEAU certificat ?  [o/N] ",
    "certificate of {host} accepted — restart sync (n) or retry the send.":
        "certificat de {host} accepté — relance la synchro (n) ou ré-essaie l'envoi.",
    "certificate of {host} REFUSED — connection blocked.":
        "certificat de {host} REFUSÉ — connexion bloquée.",

    # ── Key change verification ────────────────────────────────────────────
    "The key of {addr} has CHANGED.": "La clé de {addr} a CHANGÉ.",
    "Old fingerprint: ": "Ancienne empreinte : ",
    "New fingerprint: ": "Nouvelle empreinte : ",
    "⚠ Verify the NEW fingerprint with your contact via ANOTHER channel":
        "⚠ Vérifie la NOUVELLE empreinte avec ton contact par un AUTRE canal",
    "  (phone, in person…) BEFORE accepting. If you are not sure,":
        "  (téléphone, en personne…) AVANT d'accepter. Si tu n'es pas sûr·e,",
    "  refuse: encryption to this contact will stay suspended.":
        "  refuse : le chiffrement vers ce contact restera suspendu.",
    " Verifying a key change": " Vérification d'un changement de clé",
    " Accept the NEW key?  [y/N] ": " Accepter la NOUVELLE clé ?  [o/N] ",
    "✓ new key accepted for {addr}.": "✓ nouvelle clé acceptée pour {addr}.",
    "the candidate key changed in the meantime — re-verify.":
        "la clé candidate a changé entre-temps — re-vérifie.",
    "key change NOT accepted (encryption suspended).":
        "changement de clé NON accepté (chiffrement suspendu).",

    # ── Address book ───────────────────────────────────────────────────────
    "address book disabled (security.address_book).":
        "carnet d'adresses désactivé (security.address_book).",
    "address book unavailable: vault locked.":
        "carnet indisponible : coffre verrouillé.",
    " Address book  (Enter write · a add · e edit · d delete · Esc back)":
        " Carnet d'adresses  (Entrée écrire · a ajouter · e éditer · d supprimer · Échap retour)",
    "(empty book — \"a\" to add a contact)":
        "(carnet vide — « a » pour ajouter un contact)",
    "Remove {email} from the book?": "Supprimer {email} du carnet ?",
    "contact removed.": "contact supprimé.",
    "Contact email": "E-mail du contact",
    "invalid email address.": "adresse e-mail invalide.",
    "Name (optional)": "Nom (optionnel)",
    "Notes (optional)": "Notes (optionnel)",
    "✓ contact saved.": "✓ contact enregistré.",

    # ── Popups / transmission ──────────────────────────────────────────────
    "[y] send    [n / Esc] cancel": "[o] envoyer    [n / Échap] annuler",
    "⟩⟩ SECURE TRANSMISSION": "⟩⟩ TRANSMISSION SÉCURISÉE",
    "🔒 OpenPGP/MIME encryption (RFC 3156) — AES-256, signed Ed25519":
        "🔒 chiffrement OpenPGP/MIME (RFC 3156) — AES-256, signé Ed25519",
    "   sealed for {n} recipient(s) + self":
        "   scellé pour {n} destinataire(s) + soi",
    "🔓 message IN CLEAR (not encrypted) — Autocrypt header attached":
        "🔓 message EN CLAIR (non chiffré) — en-tête Autocrypt joint",
    "✓ SENT": "✓ ENVOYÉ",
    "  · copy in Sent": "  · copie dans Sent",
    "⟩⟩ TRANSMISSION — OK": "⟩⟩ TRANSMISSION — OK",
    "✗ FAILED: ": "✗ ÉCHEC : ",
    "⟩⟩ TRANSMISSION — FAILED": "⟩⟩ TRANSMISSION — ÉCHEC",

    # ── Generic widgets ────────────────────────────────────────────────────
    "no items.": "aucun élément.",
    " {title}  (↑↓ + Enter · Esc cancel)": " {title}  (↑↓ + Entrée · Échap annuler)",
    "Error": "Erreur",

    # ── Crypto help ────────────────────────────────────────────────────────
    "fmail encrypts end-to-end with Autocrypt (OpenPGP). No config, no key\n"
    "server: everything settles by itself, through the mails themselves.\n"
    "\n"
    "1.  Your key travels with your mails.\n"
    "    Every message you send (even in clear) carries your public key.\n"
    "\n"
    "2.  The very first exchange goes out IN CLEAR.\n"
    "    Until you have ever received a mail from a contact, fmail doesn't\n"
    "    have their key: it can't encrypt yet.   Indicator: 🔓 (YELLOW header).\n"
    "\n"
    "3.  As soon as you receive a mail from them (from a compatible app),\n"
    "    fmail learns their key AUTOMATICALLY. The next exchanges then\n"
    "    encrypt by themselves: 🔒 GREEN header, green frame when\n"
    "    composing.  → A single round-trip is enough to go encrypted.\n"
    "\n"
    "4.  Force / turn off: ^E key in the composer (auto → forced → off).\n"
    "    In \"forced\", if a key is missing, the send is BLOCKED rather than\n"
    "    going out in clear by surprise.\n"
    "\n"
    "Compatible software (your correspondent can reply encrypted):\n"
    "    • Thunderbird (built-in OpenPGP encryption)\n"
    "    • Thunderbird for Android / K-9 Mail\n"
    "    • Delta Chat\n"
    "    • Mailpile — and fmail, of course 🙂\n"
    "  A correspondent on plain Gmail/Outlook won't encrypt:\n"
    "  the exchange simply stays in clear, with no error or blocking.\n"
    "\n"
    "Verifying a contact's identity:\n"
    "  If a contact's key CHANGES, fmail alerts you (in red) and suspends\n"
    "  automatic encryption. Press \"v\" in the reader to compare their\n"
    "  fingerprint with them (phone, in person…) before accepting.\n"
    "\n"
    "Cues:  🔒 green = encrypted · 🔓 yellow = cleartext · ⚠ red = to verify.\n"
    "Note: the SUBJECT and addresses stay visible (Autocrypt standard);\n"
    "only the BODY and attachments are encrypted.\n":
        "fmail chiffre de bout en bout avec Autocrypt (OpenPGP). Aucune config,\n"
        "aucun serveur de clés : tout se règle tout seul, par les mails eux-mêmes.\n"
        "\n"
        "1.  Ta clé voyage avec tes mails.\n"
        "    Chaque message que tu envoies (même en clair) emporte ta clé publique.\n"
        "\n"
        "2.  Le tout premier échange part EN CLAIR.\n"
        "    Tant que tu n'as jamais reçu de mail d'un contact, fmail n'a pas sa\n"
        "    clé : il ne peut pas encore chiffrer.   Indicateur : 🔓 (en-tête JAUNE).\n"
        "\n"
        "3.  Dès que tu reçois un mail de lui (depuis un logiciel compatible),\n"
        "    fmail apprend sa clé AUTOMATIQUEMENT. Les échanges suivants se\n"
        "    chiffrent alors tout seuls : 🔒 en-tête VERTE, cadre vert à la\n"
        "    composition.  → Un simple aller-retour suffit pour passer en chiffré.\n"
        "\n"
        "4.  Forcer / couper : touche ^E dans le compositeur (auto → forcé → off).\n"
        "    En « forcé », si une clé manque, l'envoi est BLOQUÉ plutôt que de\n"
        "    partir en clair par surprise.\n"
        "\n"
        "Logiciels compatibles (ton correspondant pourra répondre en chiffré) :\n"
        "    • Thunderbird (chiffrement OpenPGP intégré)\n"
        "    • Thunderbird for Android / K-9 Mail\n"
        "    • Delta Chat\n"
        "    • Mailpile — et fmail, évidemment 🙂\n"
        "  Un correspondant sur Gmail/Outlook classique ne chiffrera pas :\n"
        "  l'échange reste simplement en clair, sans erreur ni blocage.\n"
        "\n"
        "Vérifier l'identité d'un contact :\n"
        "  Si la clé d'un contact CHANGE, fmail t'alerte (en rouge) et suspend le\n"
        "  chiffrement automatique. Touche « v » dans le lecteur pour comparer son\n"
        "  empreinte avec lui (téléphone, en personne…) avant d'accepter.\n"
        "\n"
        "Repères :  🔒 vert = chiffré · 🔓 jaune = en clair · ⚠ rouge = à vérifier.\n"
        "À savoir : le SUJET et les adresses restent visibles (standard Autocrypt) ;\n"
        "seuls le CORPS et les pièces jointes sont chiffrés.\n",
    "🔒 Exchanging encrypted mail — how it works":
        "🔒 Échanger des mails chiffrés — comment ça marche",

    # ── General help ───────────────────────────────────────────────────────
    "Navigation (2 columns: Accounts/Folders | Mails | Button bar)\n"
    "  ⇥ (Tab)       switch pane (accounts → mails → bar)\n"
    "  ↑↓ / j k      move in the active pane\n"
    "  ← →           switch accounts ↔ mails (or prev./next button)\n"
    "  Enter         on an ACCOUNT → switch + open its INBOX; on a FOLDER → open it;\n"
    "                on a MAIL → open it (a draft opens in edit mode)\n"
    "  PgUp PgDn     page · Home/End\n"
    "  Esc           clear the search\n\n"
    "Menu\n"
    "  m             open/close the dropdown menu (ALL functions)\n"
    "                → contains the \"⚙ Configuration\" sub-menu\n\n"
    "Actions (shortcuts valid everywhere + buttons at the bottom)\n"
    "  c             compose a new message\n"
    "  r / R / f     reply / reply to all / forward\n"
    "  a             archive        d / Del: trash\n"
    "  M             move to a folder\n"
    "  Space         mark read / unread\n"
    "  / u           search · filter unread\n"
    "  n             check for new mail (silent auto-poll every 5 min)\n"
    "  g             go to the accounts/folders pane\n\n"
    "Configuration (menu m → ⚙, or direct shortcuts)\n"
    "  s             edit the account signature\n"
    "  A             switch account\n"
    "  N             add a new account\n\n"
    "Editing (compose)\n"
    "  Tab           next field   (Shift+Tab: previous)\n"
    "  ^T            format: auto-detect → plain text → Markdown→HTML (default: auto)\n"
    "  ^O            attach a file (browser: cd, ls, ⇥ completes)\n"
    "  ^X            remove the last attachment\n"
    "  ^G            send\n"
    "  Esc           quit: Discard / Save the draft / Back\n\n"
    "  q             quit fmail":
        "Navigation (2 colonnes : Comptes/Dossiers | Mails | Barre de boutons)\n"
        "  ⇥ (Tab)       changer de volet (comptes → mails → barre)\n"
        "  ↑↓ / j k      déplacer dans le volet actif\n"
        "  ← →           passer comptes ↔ mails (ou bouton précéd./suiv.)\n"
        "  Entrée        sur un COMPTE → bascule + ouvre son INBOX ; sur un DOSSIER → l'ouvre ;\n"
        "                sur un MAIL → l'ouvre (un brouillon s'ouvre en édition)\n"
        "  PgUp PgDn     page · Début/Fin\n"
        "  Échap         vider la recherche\n\n"
        "Menu\n"
        "  m             ouvrir/fermer le menu déroulant (TOUTES les fonctions)\n"
        "                → contient le sous-menu « ⚙ Configuration »\n\n"
        "Actions (raccourcis valables partout + boutons en bas)\n"
        "  c             composer un nouveau message\n"
        "  r / R / f     répondre / répondre à tous / transférer\n"
        "  a             archiver        d / Suppr : corbeille\n"
        "  M             déplacer vers un dossier\n"
        "  Espace        marquer lu / non-lu\n"
        "  / u           rechercher · filtrer non-lus\n"
        "  n             vérifier les nouveaux mails (poll auto silencieux toutes les 5 min)\n"
        "  g             aller au volet comptes/dossiers\n\n"
        "Configuration (menu m → ⚙, ou raccourcis directs)\n"
        "  s             éditer la signature du compte\n"
        "  A             changer de compte\n"
        "  N             ajouter un nouveau compte\n\n"
        "Édition (composer)\n"
        "  Tab           champ suivant   (Maj+Tab : précédent)\n"
        "  ^T            format : auto-détection → texte brut → Markdown→HTML (défaut : auto)\n"
        "  ^O            joindre un fichier (explorateur : cd, ls, ⇥ complète)\n"
        "  ^X            retirer la dernière pièce jointe\n"
        "  ^G            envoyer\n"
        "  Échap         quitter : Abandonner / Sauvegarder le brouillon / Revenir\n\n"
        "  q             quitter fmail",
    "Help — fmail {version}": "Aide — fmail {version}",
    " ↑↓ scroll · any key to close": " ↑↓ défiler · une touche pour fermer",
    "cannot start the interface (incompatible terminal?): {e}":
        "interface impossible à démarrer (terminal incompatible ?) : {e}",
}
