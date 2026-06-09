# fmail

A fast, keyboard-driven **terminal email client** — command line **and** full-screen
TUI — with built-in **end-to-end encryption** (OpenPGP/Autocrypt), an **encrypted
vault** for your passwords and address book, and a **local cache** for instant,
offline-friendly browsing of your whole mailbox.

Written in plain Python (standard library only) + the system `gpg`. **No pip
dependencies.** Runs on **Linux and macOS**.

> Status: **0.9.0-beta**. Works daily, but still a beta — back up anything you
> care about and report rough edges.

## Install

```sh
curl -fsSL https://survivologie.org/fmail/install.sh | bash
```

This installs, with **no root**, into your home directory:

- the program in `~/.local/share/fmail/`
- the `fmail` command in `~/.local/bin/`
- your config in `~/freyja-mail/accounts.toml`

Then run `fmail` (full-screen) or `fmail --help` (command line).

Prefer to read before you pipe to a shell? Download `install.sh`, read it, run it.
The installer verifies every file against `SHA256SUMS` before installing.

## Requirements

The installer **checks these and offers to install what's missing** (with your
confirmation; it detects apt/dnf/pacman/zypper/apk/brew and never runs `sudo` without
asking):

- **Python 3.11+** (uses `tomllib`). Check with `python3 --version`.
  - macOS: `brew install python` (or python.org) if the system Python is older.
- **gpg** (GnuPG) — *optional but recommended*: required for the encrypted vault
  and for end-to-end (Autocrypt) encryption. Plain reading/sending works without it.
  - Debian/Ubuntu: `apt install gnupg` · Fedora: `dnf install gnupg2`
  - macOS: `brew install gnupg`

## Configure

Edit `~/freyja-mail/accounts.toml` (a template is created on first install):

```toml
[accounts.me]
email      = "you@example.com"
imap_host  = "imap.example.com"
smtp_host  = "smtp.example.com"
# Password options (pick one):
password_file = "~/secrets/me_mail_password"   # a 0600 file with the password
# …or store it in the encrypted vault:  fmail vault set-password me
```

Optional — protect fmail behind a master password (encrypted vault + cache):

```toml
[security]
master_password = true     # ask for a master password at launch
lock_timeout    = 900       # auto-lock after N seconds idle (0 = never)
address_book    = true      # encrypted contacts
encrypt_cache   = true      # encrypt the local cache at rest
```

Create the vault with `fmail vault init` (shows a one-time recovery code — **write
it down**; losing both the master password and the recovery code makes the vault
unrecoverable).

## Highlights

- **TUI**: two-pane layout (accounts/folders | mails), full-mailbox scrolling from a
  local SQLite cache, background sync, HTML rendering, drafts, attachments.
- **End-to-end encryption** (Autocrypt level 1): opportunistic OpenPGP, keys learned
  from incoming mail, anti-TOFU key-change protection, clear green/yellow/red trust
  markers, in-app encryption help (`Ctrl-A`).
- **Security**: encrypted vault (master password + recovery code, scrypt-hardened),
  TLS certificate pinning with MITM detection (fail-closed), encrypted cache at rest.
- **CLI**: `fmail list|read|reply|forward|compose|move|archive|trash|search|vault …`.

Run fmail and press `m` for the full menu, or `Ctrl-A` for encryption help.

## Uninstall

```sh
curl -fsSL https://survivologie.org/fmail/uninstall.sh | bash
```

Your data and encrypted vault in `~/freyja-mail/` are kept (the uninstaller tells you
how to wipe them if you really want to).

## Notes for macOS

fmail runs on macOS (the `curses` TUI ships with Python). Two things to know:

- Install **gpg** via Homebrew for the vault and encryption.
- macOS has no `/dev/shm`: when the cache is encrypted, its working copy lives in
  `~/freyja-mail` during the session (then re-encrypted and wiped on exit) instead of
  a RAM disk. Functionally identical; slightly weaker "RAM-only" guarantee.

## License

fmail is free software: you can redistribute it and/or modify it under the terms of
the **GNU General Public License v3.0 or later** (GPL-3.0-or-later). See the
[`LICENSE`](LICENSE) file for the full text.

Copyright (C) 2026 David Manise. fmail comes with NO WARRANTY, to the extent
permitted by law.

## Languages

The interface is available in **English** and **French** (`[ui] lang = "en"` / `"fr"`
in `accounts.toml`).
