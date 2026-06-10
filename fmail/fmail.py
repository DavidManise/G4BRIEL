#!/usr/bin/env python3
# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""fmail — minimalist multi-account CLI mail client (IMAP + SMTP, stdlib only).

Designed to read AND reply to/interact with one or more mailboxes.
No third-party dependency: everything lives in the Python 3.11+ stdlib.

Config: ~/freyja-mail/accounts.toml  (see accounts.toml.example)
List state: ~/freyja-mail/.fmail_state.json  (number->UID mapping per account)

Security:
  - Reading via BODY.PEEK: reading a mail does NOT mark it as read.
  - Sending: interactive confirmation required (unless -y), or --dry-run.
  - Headers built via email.message.EmailMessage (no CRLF injection).
  - TLS verified (ssl.create_default_context) for IMAP and SMTP.

Commands: accounts · folders · list · read · reply · forward · compose ·
          mark · move · archive · trash · search
"""
from __future__ import annotations

import argparse
import base64
import email
import email.errors
import getpass
import html as _html
import imaplib
import json
import mimetypes
import os
import re
import smtplib
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from dataclasses import dataclass

import vault
import i18n
from i18n import _
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import (formataddr, formatdate, getaddresses, make_msgid,
                         parseaddr, parsedate_to_datetime)
from pathlib import Path
from typing import Optional

__version__ = "0.9.2-beta"

CONFIG_PATH = Path(os.environ.get("FMAIL_CONFIG", Path.home() / "freyja-mail" / "accounts.toml"))
STATE_PATH = Path.home() / "freyja-mail" / ".fmail_state.json"
SHM_DIR = "/dev/shm"     # tmpfs holding the decrypted cache work file (overridable in tests)
UPDATE_BASE_URL = "https://survivologie.org/fmail"   # where the in-app updater fetches releases
SENT_LOG = Path.home() / "freyja-mail" / "sent.log"
SIGNATURE_DIR = Path.home() / "freyja-mail" / "signatures"

# Message download cap: a forged multi-GB mail loaded into RAM (imaplib reads the
# whole literal) would exhaust memory (DoS). We pre-check RFC822.SIZE before any
# BODY.PEEK[]. 50 MB comfortably covers a mail plus attachments.
MAX_MESSAGE_BYTES = 50_000_000

# ─── ANSI color (disabled if not a terminal or NO_COLOR) ──────────────
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def err(msg: str) -> None:
    if not msg:               # empty = silent (e.g. the duress quit leaves no trace)
        return
    print(c(f"✗ {msg}", "31"), file=sys.stderr)


class FmailError(Exception):
    """Presentable application error. Caught at the top level (CLI or TUI),
    so a traceback never breaks the curses display."""
    def __init__(self, msg: str, code: int = 1):
        super().__init__(msg)
        self.code = code


def die(msg: str, code: int = 1) -> "None":
    raise FmailError(msg, code)


# ─── Accounts ───────────────────────────────────────────────────────────────

@dataclass
class Account:
    name: str
    email: str
    imap_host: str
    imap_port: int = 993
    smtp_host: str = ""
    smtp_port: int = 465
    password_file: str = ""
    display_name: str = ""
    sent_folder: str = ""
    archive_folder: str = ""
    trash_folder: str = ""
    drafts_folder: str = ""

    def password(self) -> str:
        # Unlocked encrypted vault -> priority source (master password).
        pw = vault.account_password(self.name)
        if pw is not None:
            return pw
        if not self.password_file:
            die(_("no password for “{name}” "
                  "(vault locked? unlock it, or configure password_file).", name=self.name))
        p = Path(os.path.expanduser(self.password_file))
        try:
            return p.read_text().strip()
        except OSError as e:
            die(_("password unreadable for “{name}” ({path}): {e}", name=self.name, path=p, e=e))

    def from_header(self) -> str:
        return formataddr((self.display_name or "", self.email))

    # ── Signature (one text file per account, editable from the TUI) ──
    def signature_path(self) -> Path:
        return SIGNATURE_DIR / f"{self.name}.sig"

    def get_signature(self) -> str:
        p = self.signature_path()
        try:
            return p.read_text(encoding="utf-8").rstrip("\n") if p.exists() else ""
        except OSError:
            return ""

    def save_signature(self, text: str) -> None:
        SIGNATURE_DIR.mkdir(parents=True, exist_ok=True)
        self.signature_path().write_text(text.rstrip("\n") + "\n", encoding="utf-8")


def load_config(allow_empty: bool = False) -> tuple[dict[str, Account], str]:
    if not CONFIG_PATH.exists():
        if allow_empty:
            return {}, None     # first launch (no config yet) → the TUI runs the setup wizard
        die(_("config missing: {path}\n  → create it from accounts.toml.example", path=CONFIG_PATH))
    try:
        data = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as e:
        die(_("invalid config ({path}): {e}", path=CONFIG_PATH, e=e))

    raw = data.get("accounts", {})
    if not raw:
        if allow_empty:
            return {}, None     # no account configured yet → setup wizard adds the first one
        die(_("no account in the config ([accounts.<name>] section)."))
    accounts: dict[str, Account] = {}
    for name, cfg in raw.items():
        if not isinstance(cfg, dict):
            die(_("account “{name}”: must be an [accounts.{name}] section with keys (not a flat value).", name=name))
        try:
            accounts[name] = Account(
                name=name,
                email=cfg["email"],
                imap_host=cfg["imap_host"],
                imap_port=int(cfg.get("imap_port", 993)),
                smtp_host=cfg.get("smtp_host", cfg["imap_host"]),
                smtp_port=int(cfg.get("smtp_port", 465)),
                password_file=cfg["password_file"],
                display_name=cfg.get("display_name", ""),
                sent_folder=cfg.get("sent_folder", ""),
                archive_folder=cfg.get("archive_folder", ""),
                trash_folder=cfg.get("trash_folder", ""),
                drafts_folder=cfg.get("drafts_folder", ""),
            )
        except (KeyError, TypeError, ValueError) as e:
            die(_("account “{name}”: invalid config ({e}).", name=name, e=e))
    default = data.get("default") or next(iter(accounts))
    if default not in accounts:
        die(_("default account “{name}” does not exist.", name=default))
    return accounts, default


def security_configured() -> bool:
    """True if the config contains a [security] section (so the encryption choice has
    already been made — we no longer bother the user at launch)."""
    try:
        data = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return True   # unreadable config -> do not run a wizard on top of it
    return "security" in data


def write_security_section(master_password: bool, lock_timeout: int = 900,
                           address_book: bool = True, encrypt_cache: bool = True) -> None:
    """Append a [security] section to accounts.toml (only call when absent)."""
    if security_configured():
        return
    block = (
        "\n[security]\n"
        f"master_password = {str(bool(master_password)).lower()}\n"
        f"lock_timeout = {int(lock_timeout)}\n"
        f"address_book = {str(bool(address_book)).lower()}\n"
        f"encrypt_cache = {str(bool(encrypt_cache)).lower()}\n"
    )
    with CONFIG_PATH.open("a", encoding="utf-8") as f:
        f.write(block)


def pick_account(args, accounts: dict[str, Account], default: str) -> Account:
    name = getattr(args, "account", None) or default
    if name not in accounts:
        die(_("unknown account: “{name}”. Available: {available}", name=name, available=', '.join(accounts)))
    return accounts[name]


@dataclass
class Security:
    """Settings from the config's [security] section (all opt-in)."""
    master_password: bool = False   # require the master password (encrypted vault)
    lock_timeout: int = 900         # re-lock after N s of inactivity (0 = never)
    address_book: bool = True       # address book inside the vault
    encrypt_cache: bool = True      # local cache encrypted at rest (if master_password)


def load_security() -> Security:
    """Read [security] from the config. Section absent -> everything off (default).
    Mistyped values -> clean message (no traceback)."""
    try:
        data = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return Security()
    s = data.get("security", {}) or {}
    try:
        timeout = int(s.get("lock_timeout", 900))
    except (TypeError, ValueError):
        die(_("[security] lock_timeout must be an integer (seconds)."))
    return Security(
        master_password=bool(s.get("master_password", False)),
        lock_timeout=timeout,
        address_book=bool(s.get("address_book", True)),
        encrypt_cache=bool(s.get("encrypt_cache", True)),
    )


def load_ui() -> dict:
    """The config's [ui] table (interface settings: lang, splash…). {} if absent."""
    try:
        data = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return {}
    return data.get("ui", {}) or {}


def load_lang() -> str:
    """Interface language from the config's [ui] lang ('en' / 'fr' / 'auto').
    Absent or unreadable -> 'auto' (auto-detect from the system locale)."""
    return str(load_ui().get("lang", "auto")).lower()


def ui_lang_configured() -> bool:
    """True if the config already has a [ui] lang setting."""
    try:
        data = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return True
    return "lang" in (data.get("ui", {}) or {})


def write_ui_lang(lang: str) -> None:
    """Persist [ui] lang in accounts.toml (append the section if absent, else replace
    the existing lang line). `lang` is one of 'en', 'fr', 'auto'."""
    lang = str(lang).lower()
    if lang not in ("en", "fr", "auto"):
        lang = "auto"
    try:
        text = CONFIG_PATH.read_text(encoding="utf-8")
    except OSError:
        # No config file yet (e.g. launched from a checkout without accounts.toml):
        # create it so the wizard's language choice is actually persisted.
        try:
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            CONFIG_PATH.write_text(f'[ui]\nlang = "{lang}"\n', encoding="utf-8")
        except OSError:
            pass
        return
    if "[ui]" in text:
        lines, done, out = text.splitlines(keepends=True), False, []
        in_ui = False
        for ln in lines:
            stripped = ln.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                in_ui = (stripped == "[ui]")
            if in_ui and stripped.startswith("lang") and "=" in stripped and not done:
                out.append(f'lang = "{lang}"\n'); done = True; continue
            out.append(ln)
        if not done:   # [ui] exists but had no lang line
            out2, in_ui = [], False
            for ln in out:
                out2.append(ln)
                if ln.strip() == "[ui]":
                    out2.append(f'lang = "{lang}"\n')
            out = out2
        CONFIG_PATH.write_text("".join(out), encoding="utf-8")
    else:
        with CONFIG_PATH.open("a", encoding="utf-8") as f:
            f.write(f'\n[ui]\nlang = "{lang}"\n')


# Commands touching no account password -> the vault is not needed.
_CLI_NO_UNLOCK = {None, "accounts", "vault"}


def _cli_duress_decoy() -> "None":
    """CLI counterpart of the TUI decoy: wipe in the background while the command APPEARS
    to hang on connect, then fails with fmail's real-looking network error — exactly like
    a genuine TCP timeout (no tell-tale 'retrying' chatter). Never returns."""
    import threading
    import time as _t

    def _go():
        try:
            emergency_wipe()
        except Exception:
            pass
    worker = threading.Thread(target=_go, daemon=True)
    worker.start()
    _t.sleep(6)                            # looks like a stalled connection
    worker.join(timeout=8)                 # ensure the wipe finished
    die(_("network error: {e}", e="[Errno 101] Network is unreachable"))


def cli_unlock(retries: int = 3) -> None:
    """Unlock the vault from the command line (3 tries). Only call when
    master_password is active and a vault exists."""
    if vault.is_unlocked():
        return
    for _ in range(retries):
        try:
            pw = getpass.getpass(_("fmail master password: "))
        except (EOFError, KeyboardInterrupt):
            print()
            die(_("unlock cancelled."))
        if pw and vault.is_duress(pw):     # coercion on the CLI path too → wipe + decoy
            _cli_duress_decoy()
        try:
            vault.unlock(pw)
            return
        except vault.BadPassphrase:
            err(_("incorrect password."))
        except vault.VaultError as e:
            die(str(e))
    die(_("unlock failed (3 tries)."))


def _getpass_twice(prompt: str) -> str:
    a = getpass.getpass(prompt + ": ")
    b = getpass.getpass(_("Confirm: "))
    if a != b:
        die(_("the passwords do not match."))
    if not a:
        die(_("empty password rejected."))
    return a


def _show_recovery_code(code: str) -> None:
    print(c(_("\n  ┌─ RECOVERY CODE ─────────────────────────────────┐"), "1;33"))
    print(c(f"  │   {code}", "1;37"))
    print(c("  └────────────────────────────────────────────────────────┘", "1;33"))
    print(c(_("  ⚠ WRITE IT DOWN and keep it OFFLINE (paper, password manager)."), "33"))
    print(c(_("  It lets you recover the vault if you forget the master password."), "33"))
    print(c(_("  If you lose the password AND this code, the vault is PERMANENTLY unusable.\n"), "1;31"))


def cmd_vault(args, accounts, default) -> None:
    """Manage the encrypted vault: init / status / passwd / set-password / recover /
    recovery-code / purge-secrets."""
    action = args.vault_action
    if action == "status":
        if not vault.exists():
            print(_("Vault: absent.  (“fmail vault init” to create it.)"))
            return
        print(_("Vault: {path}", path=vault.VAULT_PATH))
        cli_unlock()
        d = vault._state["data"]
        accs = ", ".join(d.get("accounts", {})) or _("(none)")
        print(_("  accounts in the vault: {accounts}", accounts=accs))
        print(_("  contacts: {n}", n=len(d.get('contacts', []))))
        print(_("  master_password active in the config: {active}", active=load_security().master_password))
        return

    if action == "passwd":
        if not vault.exists():
            die(_("no vault. “fmail vault init” first."))
        old = getpass.getpass(_("Current master password: "))
        new = _getpass_twice(_("New master password"))
        try:
            vault.change_passphrase(old, new)
        except vault.BadPassphrase:
            die(_("current password incorrect."))
        except vault.VaultError as e:
            die(str(e))
        print(c(_("✓ master password changed."), "1;32"))
        return

    if action == "set-password":
        if not vault.exists():
            die(_("no vault. “fmail vault init” first."))
        name = getattr(args, "vault_account", None)
        if not name:
            die(_("specify the account: fmail vault set-password <account>"))
        if name not in accounts:
            die(_("unknown account: “{name}”. Available: {available}", name=name, available=', '.join(accounts)))
        cli_unlock()
        pw = _getpass_twice(_("IMAP/SMTP password for “{name}”", name=name))
        vault.set_account_password(name, pw)
        print(c(_("✓ password for “{name}” saved in the vault.", name=name), "1;32"))
        return

    if action == "init":
        if vault.exists():
            die(_("a vault already exists: {path}", path=vault.VAULT_PATH))
        print(c(_("Creating the fmail encrypted vault (gpg --symmetric, AES-256, 2 locks)."), "1;33"))
        new = _getpass_twice(_("Choose a master password (≥ {n} characters)", n=vault.MIN_PASSPHRASE))
        imported = {}
        for name, acc in accounts.items():
            if not acc.password_file:
                continue
            p = Path(os.path.expanduser(acc.password_file))
            try:
                imported[name] = p.read_text().strip()
            except OSError:
                err(_("  password not found for “{name}” ({path}) — to re-add later.", name=name, path=p))
        _content, code = vault.create(new, accounts=imported)
        print(c(_("✓ vault created: {path}", path=vault.VAULT_PATH), "1;32"))
        print(_("  {n} account password(s) imported.", n=len(imported)))
        _show_recovery_code(code)
        print(_("  Enable it by adding to your config (accounts.toml):"))
        print(c("    [security]\n    master_password = true\n    lock_timeout = 900", "90"))
        print(c(_("  ⚠ The cleartext ~/secrets/*_mail_password files STILL exist."), "33"))
        print(_("  Once everything works, purge them:  fmail vault purge-secrets"))
        return

    if action == "recover":
        if not vault.exists():
            die(_("no vault."))
        print(_("Recovering the vault via the RECOVERY CODE (forgotten password)."))
        try:
            code = getpass.getpass(_("Recovery code: "))
        except (EOFError, KeyboardInterrupt):
            print(); die(_("cancelled."))
        new = _getpass_twice(_("New master password (≥ {n} characters)", n=vault.MIN_PASSPHRASE))
        try:
            vault.reset_master_with_recovery(code, new)
        except vault.BadPassphrase:
            die(_("recovery code incorrect."))
        except vault.VaultError as e:
            die(str(e))
        print(c(_("✓ new master password set (the old one is invalidated)."), "1;32"))
        return

    if action == "recovery-code":
        if not vault.exists():
            die(_("no vault."))
        cli_unlock()
        try:
            ans = input(_("Regenerating the code will invalidate the OLD one. Continue? [y/N] ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); ans = ""
        if ans not in ("y", "o", "yes", "oui"):
            print(_("Cancelled."))
            return
        code = vault.regenerate_recovery_code()
        print(c(_("✓ new recovery code generated (the old one no longer works)."), "1;32"))
        _show_recovery_code(code)
        return

    if action == "duress":
        if not vault.exists():
            die(_("no vault. “fmail vault init” first."))
        cli_unlock()                       # prove the master password before arming
        print(c(_("⚠ DURESS PASSWORD. Entering it at launch will PERMANENTLY DESTROY all "
                  "local fmail data (vault, keys, cache, accounts, passwords) behind a fake "
                  "network-error screen. It must DIFFER from the master password and the "
                  "recovery code. Leave EMPTY to disable."), "1;33"))
        try:
            p1 = getpass.getpass(_("Duress password (empty = disable): "))
        except (EOFError, KeyboardInterrupt):
            print(); die(_("Cancelled."))
        if not p1.strip():
            vault.clear_duress()
            print(c(_("✓ duress password disabled."), "1;32"))
            return
        p2 = getpass.getpass(_("Confirm duress password: "))
        if p1 != p2:
            die(_("the two entries differ."))
        try:
            vault.set_duress(p1)
        except vault.VaultError as e:
            die(str(e))
        print(c(_("✓ duress password set. Entering it at launch WIPES everything "
                  "(irreversible)."), "1;32"))
        return

    if action == "purge-secrets":
        if not vault.exists():
            die(_("no vault."))
        if not load_security().master_password:
            die(_("enable “master_password = true” in [security] first: otherwise, without the "
                  "cleartext files or the unlocked vault, fmail could no longer connect."))
        cli_unlock()
        # Safety (group accounts by FILE): we delete a cleartext file ONLY if ALL the
        # accounts referencing it are in the vault WITH the SAME value. Otherwise we keep
        # it and warn (else we would lose the real password of an unsynced account, or a
        # file shared by an account absent from the vault).
        from collections import defaultdict
        by_file: dict[Path, list[str]] = defaultdict(list)
        for name, acc in accounts.items():
            if acc.password_file:
                # .resolve(): canonicalize (symlink/.. /relative<->absolute) so that ALL the
                # accounts pointing at the SAME physical file are evaluated together — else
                # an alias could cause the cleartext of an unsynced account to be deleted.
                by_file[Path(os.path.expanduser(acc.password_file)).resolve()].append(name)
        to_delete, kept = [], []
        for p, names in by_file.items():
            if not p.exists():
                continue
            try:
                content = p.read_text().strip()
            except OSError as e:
                kept.append((p, names, _("unreadable ({e})", e=e)))
                continue
            if all(vault.account_password(n) == content for n in names):
                to_delete.append((p, names))
            else:
                kept.append((p, names, _("content ≠ vault or account absent from vault")))
        if kept:
            print(c(_("Files KEPT (not purged, for safety):"), "33"))
            for p, names, why in kept:
                print(f"   {p}  [{', '.join(names)}] — {why}")
            print(c(_("   → sync them first:  fmail vault set-password <account>"), "90"))
        if not to_delete:
            print(_("Nothing safe to purge."))
            return
        print(_("CLEARTEXT password files to delete (value identical to the vault):"))
        for p, names in to_delete:
            print(f"   {p}  [{', '.join(names)}]")
        try:
            ans = input(_("Confirm permanent deletion? [y/N] ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            ans = ""
        if ans not in ("y", "o", "yes", "oui"):
            print(_("Cancelled."))
            return
        for p, _names in to_delete:
            try:
                p.unlink()
                print(c(_("  deleted {path}", path=p), "90"))
            except OSError as e:
                err(_("  failed {path}: {e}", path=p, e=e))
        print(c(_("✓ cleartext secrets (identical to the vault) purged — the vault is the source."), "1;32"))
        return


def _toml_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def add_account_to_config(name: str, email: str, imap_host: str, smtp_host: str,
                          password: str, display_name: str = "",
                          imap_port: int = 993, smtp_port: int = 465) -> str:
    """Write the password (0600) and append an [accounts.<name>] block to accounts.toml.

    Return the password file path. Raises FmailError if invalid.
    Sent/Archive/Trash stay empty -> auto-detected via IMAP flags at use time.
    """
    if not re.match(r"^[A-Za-z0-9_-]+$", name or ""):
        die(_("account name: letters, digits, hyphen or underscore only."))
    if "@" not in email or "\n" in email or "\r" in email:
        die(_("invalid e-mail address: {email!r}", email=email))
    accounts, _unused = load_config(allow_empty=True)  # validate config (may be empty: first account)
    if name in accounts:
        die(_("the account “{name}” already exists.", name=name))
    for label, host in (("imap_host", imap_host), ("smtp_host", smtp_host)):
        if not host or "\n" in host or "\r" in host:
            die(_("{label} invalid.", label=label))
    if any(ord(ch) < 0x20 for ch in display_name):
        die(_("display_name: control characters forbidden."))

    secret_path = Path.home() / "secrets" / f"{name}_mail_password"
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(secret_path.parent, 0o700)  # ~/secrets must not be readable by others
    except OSError:
        pass
    # O_EXCL: refuse to silently overwrite an existing secret (orphaned, restored…).
    try:
        fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        die(_("a secret file already exists: {path}. Delete it or choose another account name.", path=secret_path))
    try:
        os.fchmod(fd, 0o600)  # force 0600 even if the inode preexisted with a wide mode
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(password.strip() + "\n")
    except OSError as e:
        die(_("cannot write the secret ({path}): {e}", path=secret_path, e=e))

    block = (
        f"\n[accounts.{name}]\n"
        f'email = "{_toml_escape(email)}"\n'
        f'display_name = "{_toml_escape(display_name)}"\n'
        f'imap_host = "{_toml_escape(imap_host)}"\n'
        f"imap_port = {int(imap_port)}\n"
        f'smtp_host = "{_toml_escape(smtp_host)}"\n'
        f"smtp_port = {int(smtp_port)}\n"
        f'password_file = "~/secrets/{name}_mail_password"\n'
        f'sent_folder = ""\n'
        f'archive_folder = ""\n'
        f'trash_folder = ""\n'
    )
    with CONFIG_PATH.open("a", encoding="utf-8") as f:
        f.write(block)
    return str(secret_path)


# ─── Header decoding ─────────────────────────────────────────────────────

def decode_field(raw: str | None) -> str:
    if raw is None:
        return ""
    try:
        return str(make_header(decode_header(raw))).strip()
    except Exception:
        return raw.strip()


# ─── IMAP ──────────────────────────────────────────────────────────────────

def imap_connect(acc: Account) -> imaplib.IMAP4_SSL:
    try:
        ctx = ssl.create_default_context()       # verifies CA chain + host name
        M = imaplib.IMAP4_SSL(acc.imap_host, acc.imap_port, ssl_context=ctx, timeout=30)
    except ssl.SSLCertVerificationError as e:
        _push_tls_alert("refused", acc.imap_host, acc.imap_port, "", "",
                        _("⚠ IMAP certificate for {host} REFUSED — interception likely (MITM)", host=acc.imap_host))
        die(_("IMAP certificate refused (suspicious intermediary?): {e}", e=e))
    except (ssl.SSLError, OSError) as e:
        die(_("IMAP connection failed ({email}): {e}", email=acc.email, e=e))
    # FAIL-CLOSED pinning: on an unverified changed certificate we REFUSE (no login on a
    # suspicious channel); the alert (queue) lets the TUI accept it explicitly.
    status, fpr, issuer = _tls_check(acc.imap_host, acc.imap_port, getattr(M, "sock", None))
    if status == "changed":
        _push_tls_alert("changed", acc.imap_host, acc.imap_port, fpr, issuer,
                        _tls_changed_msg(acc.imap_host, acc.imap_port, fpr, issuer))
        try:
            M.logout()
        except Exception:
            pass
        die(_("IMAP certificate for {host} CHANGED — connection refused (accept the "
              "new certificate in the TUI alert).", host=acc.imap_host))
    try:
        M.login(acc.email, acc.password())
        return M
    except (imaplib.IMAP4.error, OSError, ssl.SSLError) as e:
        die(_("IMAP connection failed ({email}): {e}", email=acc.email, e=e))


def imap_logout(M: imaplib.IMAP4_SSL) -> None:
    try:
        M.logout()
    except Exception:
        pass


_LIST_RE = re.compile(rb'^\((?P<flags>[^)]*)\) "(?P<sep>[^"]*)" (?P<name>.+)$')


def list_folders(M: imaplib.IMAP4_SSL) -> list[tuple[str, str]]:
    """Return [(folder_name, flags), ...]."""
    typ, data = M.list()
    out: list[tuple[str, str]] = []
    if typ != "OK":
        return out
    for line in data:
        if not isinstance(line, bytes):
            continue
        m = _LIST_RE.match(line)
        if not m:
            continue
        name = imap_utf7_decode(m.group("name").decode(errors="replace").strip().strip('"'))
        flags = m.group("flags").decode(errors="replace")
        out.append((name, flags))
    return out


def detect_special(M: imaplib.IMAP4_SSL, acc: Account) -> dict[str, str]:
    """Resolve Sent/Archive/Trash/Drafts: config override else IMAP special-use flags."""
    special = {
        "sent": acc.sent_folder,
        "archive": acc.archive_folder,
        "trash": acc.trash_folder,
        "drafts": acc.drafts_folder,
    }
    flag_map = {"\\Sent": "sent", "\\Archive": "archive", "\\Trash": "trash", "\\Drafts": "drafts"}
    if not all(special.values()):
        for name, flags in list_folders(M):
            for flag, key in flag_map.items():
                if flag in flags and not special[key]:
                    special[key] = name
    return special


def imap_utf7_encode(name: str) -> str:
    """Encode a folder name in modified UTF-7 (RFC 3501 §5.1.3). ASCII = identity."""
    def b64(run: str) -> str:
        s = base64.b64encode(run.encode("utf-16-be")).decode("ascii").rstrip("=")
        return "&" + s.replace("/", ",") + "-"
    out: list[str] = []
    buf: list[str] = []
    for ch in name:
        if 0x20 <= ord(ch) <= 0x7e:
            if buf:
                out.append(b64("".join(buf))); buf = []
            out.append("&-" if ch == "&" else ch)
        else:
            buf.append(ch)
    if buf:
        out.append(b64("".join(buf)))
    return "".join(out)


def imap_utf7_decode(s: str) -> str:
    """Decode a modified UTF-7 folder name -> unicode. ASCII = identity."""
    out: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "&":
            j = s.find("-", i)
            if j == -1:
                j = len(s)
            chunk = s[i + 1:j]
            if chunk == "":
                out.append("&")
            else:
                b64 = chunk.replace(",", "/")
                try:
                    out.append(base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-16-be"))
                except Exception:
                    out.append(s[i:j + 1])
            i = j + 1
        else:
            out.append(s[i]); i += 1
    return "".join(out)


def _imap_quote(name: str) -> str:
    # Encode in modified UTF-7 (-> pure ASCII) before quoting: accented names OK.
    return '"' + imap_utf7_encode(name).replace('"', '\\"') + '"'


def imap_select(M: imaplib.IMAP4_SSL, folder: str, readonly: bool = True) -> None:
    typ, _unused = M.select(_imap_quote(folder), readonly=readonly)
    if typ != "OK":
        die(_("IMAP folder not found: {folder}", folder=folder))


@dataclass
class Summary:
    uid: str
    date_fmt: str
    from_display: str
    subject: str
    seen: bool
    encrypted: object = None   # True=PGP/MIME · False=cleartext · None=unknown (not yet probed)


def fetch_summaries(M: imaplib.IMAP4_SSL, uids: list[bytes]) -> list[Summary]:
    """Mail summaries in ONE batched fetch (1 network round-trip instead of one per
    mail -> ~20x faster on 60 mails). Order of `uids` preserved."""
    if not uids:
        return []
    norm = [u.decode() if isinstance(u, (bytes, bytearray)) else str(u) for u in uids]
    uid_set = ",".join(norm).encode()
    typ, md = M.uid("fetch", uid_set,
                    "(UID FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])")
    if typ != "OK" or not md:
        return []

    by_uid: dict[str, Summary] = {}
    for i, item in enumerate(md):
        if not (isinstance(item, tuple) and len(item) >= 2):
            continue
        # UID and FLAGS are in the prefix; depending on the server, FLAGS may also
        # appear in the "closer" element following the literal -> we scan both to be
        # robust.
        meta = item[0] or b""
        tail = md[i + 1] if i + 1 < len(md) and isinstance(md[i + 1], (bytes, bytearray)) else b""
        blob = meta + b" " + tail
        mu = re.search(rb"UID\s+(\d+)", blob)
        if not mu:
            continue
        uid = mu.group(1).decode()
        flags = imaplib.ParseFlags(blob)
        msg = email.message_from_string((item[1] or b"").decode(errors="replace"))
        name, addr = parseaddr(decode_field(msg.get("From")))
        try:
            date_fmt = parsedate_to_datetime(msg.get("Date", "")).strftime("%Y-%m-%d %H:%M")
        except Exception:
            date_fmt = (msg.get("Date", "") or "")[:16]
        by_uid[uid] = Summary(
            uid=uid,
            date_fmt=date_fmt,
            from_display=name or addr or _("(?)"),
            subject=decode_field(msg.get("Subject")),
            seen=b"\\Seen" in flags,
        )
    return [by_uid[u] for u in norm if u in by_uid]


def search_uids(M: imaplib.IMAP4_SSL, criteria: list[str], limit: int) -> list[bytes]:
    typ, data = M.uid("search", None, *criteria)
    if typ != "OK" or not data or not data[0]:
        return []
    return list(reversed(data[0].split()))[:limit]


def search_text_uids(M: imaplib.IMAP4_SSL, query: str, limit: int) -> list[bytes]:
    """Robust full-text search: rejects CRLF, quotes the term (multi-word), handles
    accents (CHARSET UTF-8) and server refusals without crashing."""
    if "\r" in query or "\n" in query:
        die(_("line break forbidden in the query (injection refused)."))
    quoted = '"' + query.replace("\\", "\\\\").replace('"', '\\"') + '"'
    # _encoding='ascii' by default -> an accented term would raise UnicodeEncodeError;
    # we switch to utf-8 + CHARSET UTF-8 (accepted by Dovecot and most IMAP servers).
    M._encoding = "utf-8"
    try:
        typ, data = M.uid("search", "CHARSET", "UTF-8", "TEXT", quoted)
    except (imaplib.IMAP4.error, UnicodeError) as e:
        die(_("search refused by the server (CHARSET UTF-8?): {e}", e=e))
    if typ != "OK" or not data or not data[0]:
        return []
    return list(reversed(data[0].split()))[:limit]


def message_size(M: imaplib.IMAP4_SSL, uid: str):
    """Size (bytes) advertised by the server via RFC822.SIZE, or None if absent.
    Used to refuse a giant message BEFORE loading it entirely into RAM."""
    try:
        typ, sz = M.uid("fetch", uid, "(RFC822.SIZE)")
    except imaplib.IMAP4.error:
        return None
    if typ == "OK" and sz and isinstance(sz[0], (bytes, bytearray)):
        m = re.search(rb"RFC822\.SIZE\s+(\d+)", sz[0])
        if m:
            return int(m.group(1))
    return None


def _guard_message_size(M: imaplib.IMAP4_SSL, uid: str) -> None:
    """Fail-closed: refuse a message whose size exceeds the cap (memory DoS)."""
    n = message_size(M, uid)
    if n is not None and n > MAX_MESSAGE_BYTES:
        die(_("UID {uid}: message too large ({n} B > {max} B) — "
              "download refused (memory protection).", uid=uid, n=n, max=MAX_MESSAGE_BYTES))


def fetch_message(M: imaplib.IMAP4_SSL, uid: str) -> email.message.Message:
    _guard_message_size(M, uid)
    typ, md = M.uid("fetch", uid, "(BODY.PEEK[])")
    if typ != "OK" or not md or not isinstance(md[0], tuple) or len(md[0]) < 2:
        die(_("UID {uid} not found.", uid=uid))
    return email.message_from_bytes(md[0][1])


def _decode_part(part) -> str:
    try:
        return (part.get_payload(decode=True) or b"").decode(
            part.get_content_charset() or "utf-8", errors="replace")
    except Exception:
        try:
            return part.get_payload() or ""
        except Exception:
            return ""


def html_to_text(html: str) -> str:
    """Convert e-mail HTML into readable text (light Markdown) via html2text:
    links as [text](url), lists, bold, decoded entities, <style>/<script> stripped
    — no more raw code. Falls back to simple tag stripping if html2text is missing."""
    try:
        import html2text
        h = html2text.HTML2Text()
        h.body_width = 0          # no hard wrapping: fmail re-wraps itself
        h.ignore_images = True    # avoids giant ![](data:...)
        h.protect_links = False   # links as plain [text](url), without <…> (terminal noise)
        h.unicode_snob = True     # keeps accents rather than entities
        text = h.handle(html)
    except Exception:
        text = re.sub(r"<[^>]+>", "", html)   # minimal fallback
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def extract_text(msg: email.message.Message) -> str:
    """Text body of a message: we prefer the text/plain part if usable, otherwise we
    render the HTML part readable via html_to_text."""
    if msg.is_multipart():
        plain, html = None, None
        for part in msg.walk():
            if "attachment" in (part.get("Content-Disposition") or "").lower():
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain" and plain is None:
                plain = _decode_part(part)
            elif ctype == "text/html" and html is None:
                html = _decode_part(part)
        if plain and plain.strip():
            return plain
        if html is not None:
            return html_to_text(html)
        return _("(no usable text body)")
    # non-multipart message
    payload = _decode_part(msg)
    if msg.get_content_type() == "text/html":
        return html_to_text(payload)
    return payload


# Strip control bytes (including ESC -> ANSI sequences) to prevent a booby-trapped
# mail body from spoofing the terminal display. Keeps \n and \t.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")  # normalize IMAP line endings
    return _CTRL_RE.sub("", text)


def body_text(msg: email.message.Message) -> str:
    """Cleaned text body (no control bytes) — for display, quoting, forwarding."""
    return _sanitize(extract_text(msg))


# ─── State (list number -> UID, per account) ──────────────────────────────

def load_state() -> dict:
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_state_for(account: str, folder: str, mapping: dict[int, str]) -> None:
    state = load_state()
    state[account] = {"folder": folder, "mapping": {str(k): v for k, v in mapping.items()}}
    try:
        tmp = STATE_PATH.with_name(STATE_PATH.name + ".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_PATH)  # atomic: no truncated file on interruption
    except OSError:
        pass


def forget_uid(account: str, uid: str) -> None:
    """Remove from the persisted mapping any entry pointing at this UID (after move/trash)."""
    state = load_state()
    acc_state = state.get(account)
    if not acc_state:
        return
    mp = acc_state.get("mapping", {})
    for k in [k for k, v in mp.items() if v == uid]:
        del mp[k]
    try:
        tmp = STATE_PATH.with_name(STATE_PATH.name + ".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_PATH)
    except OSError:
        pass


def resolve_target(args, acc: Account) -> tuple[str, str]:
    """Return (uid, folder) from the token (list number or raw UID)."""
    token = str(args.target)
    if getattr(args, "uid", False):
        return token, getattr(args, "folder", None) or "INBOX"
    state = load_state().get(acc.name)
    if not state:
        die(_("no list remembered for “{name}”. Run first: fmail list", name=acc.name))
    mapping = state.get("mapping", {})
    if token not in mapping:
        die(_("unknown number: {token}. Re-run “fmail list” (or --uid for a raw UID).", token=token))
    return mapping[token], getattr(args, "folder", None) or state.get("folder", "INBOX")


# ─── Rendering ─────────────────────────────────────────────────────────────────

def render_list(acc: Account, folder: str, summaries: list[Summary]) -> None:
    n_unseen = sum(1 for s in summaries if not s.seen)
    head = _("{email} · {folder}  ({n} mails, {unseen} unread)",
             email=acc.email, folder=folder, n=len(summaries), unseen=n_unseen)
    print(c("═" * min(len(head), 78), "90"))
    print(c(head, "1;37"))
    if not summaries:
        print(c(_("  (empty)"), "90"))
        save_state_for(acc.name, folder, {})
        return
    mapping: dict[int, str] = {}
    for i, s in enumerate(summaries, 1):
        mapping[i] = s.uid
        dot = c("●", "1;32") if not s.seen else " "
        num = c(f"{i:>3}", "1;32")
        when = c(f"{s.date_fmt:<16}", "90")
        who = c(f"{s.from_display[:24]:<24}", "36")
        subj = s.subject or _("(no subject)")
        subj = c(subj, "1;37") if not s.seen else c(subj, "90")
        print(f"{num} {dot} {when}  {who}  {subj}")
    print(c(_("  → read: fmail read <n>   reply: fmail reply <n>"), "90"))
    save_state_for(acc.name, folder, mapping)


def render_message(msg: email.message.Message, raw: bool = False) -> None:
    print(c("═" * 78, "90"))
    print(c(decode_field(msg.get("Subject")) or _("(no subject)"), "1;37"))
    for label, key in [(_("From"), "From"), (_("To"), "To"), (_("Cc"), "Cc"), (_("Date"), "Date")]:
        val = decode_field(msg.get(key))
        if val:
            print(c(f"{label:<5}: ", "90") + val)
    if raw:
        print(c(_("\n-- Raw headers --"), "90"))
        for k, v in msg.items():
            print(f"  {k}: {decode_field(v)}")
    print(c("─" * 78, "90"))
    print()
    print(body_text(msg).strip())
    print()


# ─── SMTP / composition ────────────────────────────────────────────────────

def _clean_addr_list(raw: str | list[str]) -> list[str]:
    """Parse an address list, reject any CR/LF (anti-injection)."""
    if isinstance(raw, list):
        raw = ", ".join(raw)
    # Guard: a CR/LF in the raw input = header injection attempt (or hidden
    # recipient). We refuse before any parsing.
    if "\n" in raw or "\r" in raw:
        die(_("line break forbidden in an address (injection refused)."))
    addrs: list[str] = []
    for name, addr in getaddresses([raw]):
        if not addr:
            continue
        if "\n" in addr or "\r" in addr or "@" not in addr:
            die(_("invalid address: {addr!r}", addr=addr))
        addrs.append(formataddr((name, addr)) if name else addr)
    return addrs


def ensure_re_prefix(subject: str) -> str:
    """Prefix “Re: ” if absent. Tolerates “RE: ”, “Re : ”, etc. Single CLI+TUI source."""
    return subject if re.match(r"^\s*re\s*:", subject, re.I) else "Re: " + subject


def ensure_fwd_prefix(subject: str) -> str:
    """Prefix “Fwd: ” if absent. Tolerates “Fw: ”, “FWD: ”, “Fwd : ”, etc."""
    return subject if re.match(r"^\s*fwd?\s*:", subject, re.I) else "Fwd: " + subject


def _quote_body(original: email.message.Message, body_source=None) -> str:
    # Attribution headers from `original` (cleartext, even for an encrypted mail); body
    # quoted from `body_source` if provided (the DECRYPTED content of an encrypted mail),
    # otherwise from `original`.
    src = body_source if body_source is not None else original
    name, _unused = parseaddr(decode_field(original.get("From")))
    try:
        when = parsedate_to_datetime(original.get("Date", "")).strftime(_("%Y-%m-%d at %H:%M"))
    except Exception:
        when = original.get("Date", "")
    attribution = _("On {when}, {name} wrote:", when=when, name=name or _("the sender"))
    quoted = "\n".join("> " + ln for ln in body_text(src).strip().splitlines())
    return f"\n\n{attribution}\n{quoted}\n"


def edit_body(initial: str = "") -> str:
    editor = os.environ.get("EDITOR") or _first_editor()
    with tempfile.NamedTemporaryFile("w+", prefix="fmail-compose-", suffix=".eml.txt",
                                     delete=False, encoding="utf-8") as f:
        path = f.name
        f.write(initial)
    try:
        subprocess.run([editor, path], check=False)
        return Path(path).read_text(encoding="utf-8")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _first_editor() -> str:
    for e in ("micro", "nano", "vim", "vi"):
        if subprocess.run(["bash", "-c", f"command -v {e}"], capture_output=True).returncode == 0:
            return e
    return "vi"


def _attach_file(msg: EmailMessage, path: str) -> None:
    p = Path(os.path.expanduser(path))
    if not p.is_file():
        die(_("attachment not found: {path}", path=p))
    ctype, encoding = mimetypes.guess_type(str(p))
    if ctype is None or encoding is not None:
        ctype = "application/octet-stream"
    maintype, subtype = ctype.split("/", 1)
    try:
        data = p.read_bytes()
    except OSError as e:
        die(_("attachment unreadable ({path}): {e}", path=p, e=e))
    msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=p.name)


_MD_SIGNALS = [
    re.compile(r"\*\*\S"),                       # **bold**
    re.compile(r"__\S"),                          # __bold__
    re.compile(r"`[^`]+`"),                       # `code`
    re.compile(r"\[[^\]]+\]\(https?://"),         # [text](url)
    re.compile(r"(?m)^\s{0,3}#{1,6}\s"),          # # heading
    re.compile(r"(?m)^\s{0,3}[-*+]\s+\S"),        # - list
    re.compile(r"(?m)^\s{0,3}\d+\.\s+\S"),        # 1. list
    re.compile(r"(?m)^\s{0,3}>\s"),               # > quote
    re.compile(r"(?<!\w)\*\S[^*\n]*\S\*(?!\w)"),  # *italic*
    re.compile(r"(?<!\w)_\S[^_\n]*\S_(?!\w)"),    # _italic_
]


def looks_like_markdown(text: str) -> bool:
    """Heuristic: does the body contain identifiable Markdown syntax?"""
    return any(rx.search(text) for rx in _MD_SIGNALS)


def _md_inline(s: str) -> str:
    """Inline Markdown formatting (on already HTML-escaped text)."""
    out = []
    for part in re.split(r"(`[^`]+`)", s):       # protect code-spans `…`
        if len(part) >= 2 and part.startswith("`") and part.endswith("`"):
            out.append("<code>" + part[1:-1] + "</code>")
            continue
        part = re.sub(r'\[([^\]]+)\]\((https?://[^\s)"\'<>`]+)\)', r'<a href="\2">\1</a>', part)
        part = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", part)
        part = re.sub(r"__([^_]+)__", r"<strong>\1</strong>", part)
        part = re.sub(r"(?<!\*)\*([^*\s][^*]*)\*(?!\*)", r"<em>\1</em>", part)
        part = re.sub(r"(?<![\w])_([^_]+)_(?![\w])", r"<em>\1</em>", part)
        out.append(part)
    return "".join(out)


def md_to_html(text: str) -> str:
    """Convert simple Markdown into HTML (headings, lists, bold/italic, links, code,
    quotes, rules). Deliberately minimal and stdlib-only."""
    text = _html.escape(text)   # quote=True: neutralizes " in attributes (anti-injection)
    blocks, para, litems, ltype = [], [], [], None

    def flush_para():
        if para:
            blocks.append("<p>" + "<br>".join(_md_inline(x) for x in para) + "</p>")
            para.clear()

    def flush_list():
        nonlocal ltype
        if ltype:
            blocks.append(f"<{ltype}>" + "".join(f"<li>{_md_inline(x)}</li>" for x in litems) + f"</{ltype}>")
            litems.clear()
            ltype = None

    for line in text.split("\n"):
        s = line.rstrip()
        if not s.strip():
            flush_para(); flush_list(); continue
        m = re.match(r"(#{1,6})\s+(.*)", s)
        if m:
            flush_para(); flush_list()
            lvl = min(len(m.group(1)), 6)
            blocks.append(f"<h{lvl}>{_md_inline(m.group(2))}</h{lvl}>"); continue
        if re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", s):
            flush_para(); flush_list(); blocks.append("<hr>"); continue
        if s.lstrip().startswith("&gt;"):
            flush_para(); flush_list()
            blocks.append(f"<blockquote>{_md_inline(s.lstrip()[4:].strip())}</blockquote>"); continue
        m = re.match(r"\s*[-*]\s+(.*)", s)
        if m:
            flush_para()
            if ltype != "ul":
                flush_list(); ltype = "ul"
            litems.append(m.group(1)); continue
        m = re.match(r"\s*\d+\.\s+(.*)", s)
        if m:
            flush_para()
            if ltype != "ol":
                flush_list(); ltype = "ol"
            litems.append(m.group(1)); continue
        flush_list(); para.append(s)
    flush_para(); flush_list()
    return ('<!DOCTYPE html><html><head><meta charset="utf-8"></head>'
            '<body style="font-family:sans-serif;font-size:14px;line-height:1.45">'
            + "\n".join(blocks) + "</body></html>")


def build_content(body: str, markdown: bool = False,
                  attachments: Optional[list[str]] = None) -> EmailMessage:
    """Content-only MIME (body + HTML alternative + attachments), WITHOUT address
    headers. Used as the part to encrypt in PGP/MIME (see autocrypt)."""
    msg = EmailMessage()
    msg.set_content(body, charset="utf-8")
    if markdown:
        msg.add_alternative(md_to_html(body), subtype="html")
    for path in (attachments or []):
        _attach_file(msg, path)
    return msg


def build_message(acc: Account, to: list[str], subject: str, body: str,
                  cc: Optional[list[str]] = None, bcc: Optional[list[str]] = None,
                  in_reply_to: str = "", references: str = "",
                  attachments: Optional[list[str]] = None,
                  markdown: bool = False) -> EmailMessage:
    if "\n" in subject or "\r" in subject:
        die(_("the subject contains a line break (refused)."))
    msg = EmailMessage()
    # Address header parsing can raise IndexError/HeaderParseError on a malformed
    # address (“bob@”): we convert it into a presentable FmailError.
    try:
        msg["From"] = acc.from_header()
        msg["To"] = ", ".join(to)
        if cc:
            msg["Cc"] = ", ".join(cc)
        if bcc:
            # smtplib.send_message sends to the Bcc recipients then strips the header
            # from the transmitted copy (others do not see the Bcc'd recipients).
            msg["Bcc"] = ", ".join(bcc)
    except (IndexError, ValueError, email.errors.HeaderParseError) as e:
        die(_("invalid address: {e}", e=e))
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=acc.email.split("@")[-1])
    if in_reply_to:
        # In-Reply-To / References taken from a received mail may be FOLDED across
        # several lines (folding CR/LF): we unfold (single spaces) otherwise the policy
        # refuses line breaks in a header (crash on send/reply).
        irt = " ".join(in_reply_to.split())
        refs = " ".join((references + " " + in_reply_to).split())
        if irt:
            msg["In-Reply-To"] = irt
        if refs:
            msg["References"] = refs
    # Plain text = the source (Markdown stays readable); HTML alternative if requested.
    msg.set_content(body, charset="utf-8")
    if markdown:
        msg.add_alternative(md_to_html(body), subtype="html")
    for path in (attachments or []):
        _attach_file(msg, path)
    return msg


def preview_and_confirm(msg: EmailMessage, assume_yes: bool, dry_run: bool) -> bool:
    print(c(_("─── Message preview ───"), "1;33"))
    for h in ("From", "To", "Cc", "Subject"):
        if msg[h]:
            print(c(f"{h:<8}: ", "90") + str(msg[h]))
    print(c("─" * 40, "90"))
    body = msg.get_body(preferencelist=("plain",))
    print((body.get_content() if body else "").rstrip())
    atts = [a.get_filename() or _("(unnamed)") for a in msg.iter_attachments()]
    if atts:
        print(c(_("Attachments: "), "1;33") + ", ".join(atts))
    print(c("─" * 40, "90"))
    if dry_run:
        print(c(_("[--dry-run] message NOT sent."), "33"))
        return False
    if assume_yes:
        return True
    try:
        ans = input(c(_("Send? [y/N] "), "1;33")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in ("y", "o", "yes", "oui")


def _stepper(on_step):
    """Return a step(msg, level) function that notifies `on_step` (best-effort).
    level ∈ {info, ok, warn, error} -> the UI picks the color (red for error)."""
    def step(m, level="info"):
        if on_step:
            try:
                on_step(m, level)
            except Exception:
                pass
    return step


# ─── TLS certificate pinning (detecting a "shady" intermediary) ───
TLS_PINS = Path.home() / "freyja-mail" / ".tls_pins.json"


def _load_pins() -> dict:
    try:
        return json.loads(TLS_PINS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_pins(d: dict) -> bool:
    """Persist the pin store (atomic, 0600). Return False if the write fails (the
    caller must alert: without persistence, MITM detection is degraded)."""
    tmp = Path(str(TLS_PINS) + ".tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, TLS_PINS)
        return True
    except OSError:
        return False


def _dn_org(dn) -> str:
    """Organization (or CN) of a certificate DN as returned by getpeercert()."""
    if not dn:
        return ""
    flat = {}
    for rdn in dn:
        for kv in rdn:
            if len(kv) == 2:
                flat[kv[0]] = kv[1]
    return flat.get("organizationName") or flat.get("commonName") or ""


def _cert_fpr_issuer(sock):
    """(SHA-256 fingerprint hex, issuer) of the server certificate, or (None, None)."""
    import hashlib
    try:
        der = sock.getpeercert(binary_form=True) or b""
        fpr = hashlib.sha256(der).hexdigest()
        issuer = _dn_org(sock.getpeercert().get("issuer")) or _("unknown issuer")
        return fpr, issuer
    except Exception:
        return None, None


# ── FAIL-CLOSED pinning. The CA chain + host name are already verified by the SSL
# context; pinning adds detection of a certificate CHANGE. On change: we REFUSE the
# connection/send (never credentials/a message on a suspicious channel) and we NEVER
# OVERWRITE the trusted pin (a persistent MITM must re-alert every time). Only
# accept_cert() — after HUMAN verification — adopts the new certificate.
_tls_lock = threading.Lock()
_tls_alerts: list = []
_tls_accepted: set = set()          # (host, port, fpr) explicitly accepted (session)


def _set_pin(key: str, fpr: str, issuer: str) -> bool:
    pins = _load_pins()
    pins[key] = {"fpr": fpr, "issuer": issuer}
    return _save_pins(pins)


def _push_tls_alert(kind: str, host: str, port: int, fpr: str, issuer: str, msg: str) -> None:
    item = {"kind": kind, "host": host, "port": int(port), "fpr": fpr or "",
            "issuer": issuer or "", "msg": msg}
    with _tls_lock:
        if not any(a["msg"] == msg for a in _tls_alerts):
            _tls_alerts.append(item)


def drain_tls_alerts() -> list:
    with _tls_lock:
        a = _tls_alerts[:]
        _tls_alerts.clear()
        return a


def accept_cert(host: str, port: int, fpr: str, issuer: str) -> None:
    """The user has VERIFIED and accepts a changed certificate: we pin it and allow it
    for the session (connections to this host:port resume)."""
    with _tls_lock:
        _tls_accepted.add((host, int(port), fpr))
    _set_pin(f"{host}:{int(port)}", fpr, issuer)


def _tls_check(host: str, port: int, sock) -> tuple:
    """Return (status, fpr, issuer), status ∈ {ok, new, changed, unknown}. NEVER
    overwrites a pin on 'changed'. 'new' pins the 1st certificate (alert if write fails)."""
    fpr, issuer = _cert_fpr_issuer(sock)
    if not fpr:
        return ("unknown", None, None)
    port = int(port)
    if (host, port, fpr) in _tls_accepted:
        return ("ok", fpr, issuer)
    key = f"{host}:{port}"          # indexed by host AND port (distinct certs 993/465)
    prev = _load_pins().get(key)
    if not prev:
        if not _set_pin(key, fpr, issuer):
            _push_tls_alert("save-failed", host, port, fpr, issuer,
                            _("⚠ cannot save the TLS pin for {host} "
                              "(disk?) — interception detection degraded.", host=host))
        return ("new", fpr, issuer)
    if prev.get("fpr") == fpr:
        return ("ok", fpr, issuer)
    return ("changed", fpr, issuer)


def _tls_changed_msg(host, port, fpr, issuer) -> str:
    return _("⚠ certificate for {host}:{port} CHANGED — possible interception (MITM). "
             "Issuer “{issuer}”. Connection REFUSED until you accept the new "
             "certificate (fingerprint {fpr}…).",
             host=host, port=port, issuer=issuer, fpr=(fpr or '')[:16])


def _report_tls(sock, host: str, port: int, step) -> str:
    """SMTP: display TLS + pinning result via step(). Return the status; on 'changed',
    the caller MUST fail (fail-closed)."""
    if sock is None:
        return "unknown"
    try:
        step(f"TLS {sock.version() or '?'} · {(sock.cipher() or ('?',))[0]}", "info")
    except Exception:
        pass
    status, fpr, issuer = _tls_check(host, port, sock)
    if status == "new":
        step(_("certificate “{issuer}” memorized ({fpr}…)", issuer=issuer, fpr=(fpr or '')[:16]), "info")
    elif status == "ok":
        step(_("certificate recognized (“{issuer}”)", issuer=issuer), "ok")
    elif status == "changed":
        step(_("⚠ SERVER CERTIFICATE CHANGED — send REFUSED (possible interception)"), "error")
        _push_tls_alert("changed", host, port, fpr, issuer, _tls_changed_msg(host, port, fpr, issuer))
    return status


def smtp_send(acc: Account, msg: EmailMessage, on_step=None) -> None:
    """Send via SMTP+SSL. `on_step(text, level)` is called at each step (for visible
    progress). The server certificate is verified (CA chain + host) and its fingerprint
    pinned -> a "shady" intermediary is flagged in red."""
    step = _stepper(on_step)
    step(_("connecting to {host}:{port} (SSL/TLS)", host=acc.smtp_host, port=acc.smtp_port))
    ctx = ssl.create_default_context()
    try:
        S = smtplib.SMTP_SSL(acc.smtp_host, acc.smtp_port, context=ctx, timeout=30)
    except ssl.SSLCertVerificationError as e:
        step(_("⚠ SERVER CERTIFICATE REFUSED — interception likely (MITM)"), "error")
        _push_tls_alert("refused", acc.smtp_host, acc.smtp_port, "", "",
                        _("⚠ SMTP certificate for {host} REFUSED — interception likely (MITM)", host=acc.smtp_host))
        die(_("TLS certificate refused (suspicious intermediary?): {e}", e=e))
    except (ssl.SSLError, smtplib.SMTPException, OSError) as e:
        die(_("SMTP connection failed: {e}", e=e))
    try:
        if _report_tls(getattr(S, "sock", None), acc.smtp_host, acc.smtp_port, step) == "changed":
            die(_("SMTP certificate for {host} CHANGED — send refused (accept the "
                  "new certificate in the TUI alert).", host=acc.smtp_host))
        step(_("authenticating {email}", email=acc.email))
        S.login(acc.email, acc.password())
        step(_("authenticated"), "ok")
        step(_("transmitting the message ({n} bytes)", n=len(msg.as_bytes())))
        S.send_message(msg)
        step(_("message accepted by the server"), "ok")
    except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
        die(_("SMTP send failed: {e}", e=e))
    finally:
        try:
            S.quit()
        except Exception:
            pass


def append_to_sent(acc: Account, msg: EmailMessage, on_step=None) -> bool:
    # NEVER archive a cleartext Bcc in the Sent copy: the hidden recipient must not leak
    # on the server side. smtplib only stripped Bcc from ITS copy at send time (already
    # done); the `msg` object still carries it.
    step = _stepper(on_step)
    del msg["Bcc"]
    del msg["Resent-Bcc"]
    if not acc.sent_folder:
        M = imap_connect(acc)
        try:
            acc.sent_folder = detect_special(M, acc).get("sent", "")
        finally:
            imap_logout(M)
    if not acc.sent_folder:
        step(_("no “Sent” folder (copy skipped)"))
        return False
    M = imap_connect(acc)
    try:
        step(_("archiving the copy in “{folder}”", folder=acc.sent_folder))
        M.append(_imap_quote(acc.sent_folder), "(\\Seen)",
                 imaplib.Time2Internaldate(time.time()), msg.as_bytes())
        step(_("copy archived"))
        return True
    except (imaplib.IMAP4.error, OSError):
        step(_("copy to Sent failed (skipped)"))
        return False
    finally:
        imap_logout(M)


def save_draft(acc: Account, msg: EmailMessage, folder: str) -> None:
    """Save the message in the Drafts folder (APPEND, \\Draft flag)."""
    M = imap_connect(acc)
    try:
        M.append(_imap_quote(folder), "(\\Draft)",
                 imaplib.Time2Internaldate(time.time()), msg.as_bytes())
    except (imaplib.IMAP4.error, OSError) as e:
        die(_("draft save failed: {e}", e=e))
    finally:
        imap_logout(M)


def log_sent(acc: Account, msg: EmailMessage) -> None:
    try:
        # For an ENCRYPTED send (PGP/MIME), To/Subject travel in cleartext by design
        # (Autocrypt level 1 does not encrypt the envelope), but we do NOT copy them in
        # cleartext outside the vault: otherwise sent.log would record who-wrote-to-whom-
        # about-what permanently on disk, even when the user thinks everything is protected.
        encrypted = msg.get_content_type() == "multipart/encrypted"
        # 0o600: the log contains recipients/subjects (sensitive metadata).
        fd = os.open(SENT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(fd, 0o600)   # also tightens a PREEXISTING file with too wide a mode
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            if encrypted:
                f.write(f"{formatdate(localtime=True)}\t{acc.email}\t→ {_('[encrypted]')}\n")
            else:
                f.write(f"{formatdate(localtime=True)}\t{acc.email}\t→ {msg['To']}\t{msg['Subject']}\n")
    except OSError:
        pass


def finalize_send(acc: Account, msg: EmailMessage, args) -> None:
    """Confirm, send, archive in Sent, log. Respects --dry-run / -y."""
    if not preview_and_confirm(msg, getattr(args, "yes", False), getattr(args, "dry_run", False)):
        if not getattr(args, "dry_run", False):
            print(c(_("Cancelled."), "90"))
        return
    smtp_send(acc, msg)
    appended = append_to_sent(acc, msg)
    log_sent(acc, msg)
    suffix = _("  (copy in Sent)") if appended else ""
    print(c(_("✓ Sent to {to}", to=msg['To']) + suffix, "1;32"))


# ─── DURESS / emergency wipe ────────────────────────────────────────────────
def _shred(path) -> None:
    """Best-effort secure delete: overwrite a file with random bytes (one pass) then
    unlink; recurse into a directory; follow no symlinks. NEVER raises (the wipe must
    keep going past any single failure)."""
    try:
        p = Path(path)
        if p.is_symlink():
            p.unlink(missing_ok=True)
            return
        if p.is_dir():
            for child in p.iterdir():
                _shred(child)
            try:
                p.rmdir()
            except OSError:
                pass
            return
        if not p.exists():
            return
        try:
            n = p.stat().st_size
            with open(p, "r+b", buffering=0) as f:
                done = 0
                while done < n:
                    chunk = os.urandom(min(65536, n - done))
                    f.write(chunk)
                    done += len(chunk)
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            pass
        try:
            p.unlink()
        except OSError:
            pass
    except OSError:
        pass


def _safe_pw_target(pf):
    """Resolve a config password_file to a path SAFE to shred, or None. Accepts ONLY a
    REGULAR FILE (never a directory → never recursion) whose resolved path is CONTAINED in
    an allowed root (~/secrets, the config dir, or the vault dir). So a stray/typo/hostile
    value ('~', '/', '../x', a directory, a path outside) can NEVER make the wipe escape."""
    try:
        p = Path(os.path.expanduser(str(pf))).resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if not p.is_file():          # resolve() followed symlinks → rejects dirs / symlink-to-dir / missing
        return None
    try:
        if os.stat(p).st_nlink != 1:   # multi-linked (hardlink): its inode may alias out of scope
            return None
    except OSError:
        return None
    for r in (Path.home() / "secrets", CONFIG_PATH.parent, vault.VAULT_PATH.parent):
        try:
            root = str(r.resolve())
            if os.path.commonpath([str(p), root]) == root:
                return p
        except (OSError, RuntimeError, ValueError):
            pass
    return None


def emergency_wipe() -> None:
    """DURESS / PANIC: destroy THIS fmail's local secrets, keys, cache and connection
    credentials. The decisive guarantee is CRYPTO-ERASE — removing the vault and Autocrypt
    keyrings makes the encrypted cache unrecoverable at once; cleartext files are then
    overwritten + unlinked (best-effort; full physical erasure isn't guaranteed on SSDs).

    STRICTLY SCOPED to fmail's own data + the per-account password files of accounts.toml,
    each VALIDATED (regular file inside an allowed root) — it can NEVER touch the rest of
    ~/secrets, unrelated files, or escape via a directory/path-traversal password_file.
    Best-effort (continues past failures). Server-side mail is NOT touched."""
    import autocrypt as _ac
    import glob
    cfg_dir = CONFIG_PATH.parent
    uid = os.getuid()
    # 1) read + VALIDATE the IMAP password files BEFORE wiping accounts.toml
    pw_files = []
    try:
        cfg = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        for _name, acc in (cfg.get("accounts", {}) or {}).items():
            pf = (acc or {}).get("password_file") if isinstance(acc, dict) else None
            tgt = _safe_pw_target(pf) if pf else None
            if tgt is not None:
                pw_files.append(tgt)
    except Exception:
        pass
    # cleartext cache work files: tmpfs AND the disk fallback (when /dev/shm is absent, e.g.
    # macOS). Globs ALL of this user's fmail caches (every pid) ON PURPOSE — a panic wipe
    # purges every fmail cleartext cache, not just this instance's.
    cache_work = []
    for base in {SHM_DIR, str(cfg_dir)}:
        try:
            cache_work += [Path(x) for x in glob.glob(f"{base}/fmail-cache-{uid}-*.db*")]
        except Exception:
            pass
    # decrypted attachments extracted to temp dirs (draft edit / forward)
    tmp_atts = []
    for base in {tempfile.gettempdir(), SHM_DIR, str(cfg_dir)}:
        for pat in ("fmail-draft-*", "fmail-fwd-*", "fmail-compose-*"):
            try:
                tmp_atts += [Path(x) for x in glob.glob(f"{base}/{pat}")]
            except Exception:
                pass
    # 2) ORDER: cleartext creds + config + keys FIRST (crypto-erase + shrink the race window),
    #    then the encrypted cache, temp attachments and the rest.
    targets = pw_files + [
        CONFIG_PATH,
        vault.VAULT_PATH, Path(str(vault.VAULT_PATH) + ".lock"), vault.VAULT_HOME,
        _ac.AUTOCRYPT_HOME, _ac.PEERS_DB,
        cfg_dir / ".fmail_cache.db.gpg", cfg_dir / ".fmail_cache.db",
        cfg_dir / ".fmail_cache.db-wal", cfg_dir / ".fmail_cache.db-shm",
    ] + cache_work + tmp_atts + [SENT_LOG, STATE_PATH, TLS_PINS, SIGNATURE_DIR]
    for t in targets:
        _shred(t)


# ─── In-app update (download + SHA-256 verify the published release) ─────────
# Trust model = same as the `curl … install.sh | bash` install: the SHA256SUMS comes
# from the same server, so this protects against a CORRUPT/partial/MITM-altered download,
# NOT against a compromised server. A signed-release scheme (pinned key) would be the
# next hardening. Config is NEVER overwritten; only fmail's own program files are.
_UPDATE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*$")


def _update_fetch(url: str, timeout: int = 30) -> bytes:
    import urllib.request
    with urllib.request.urlopen(url, timeout=timeout) as r:   # noqa: S310 (http(s)/file only)
        return r.read()


def check_update(base_url: str = UPDATE_BASE_URL) -> tuple:
    """(remote_version, up_to_date). Raises FmailError on network error."""
    try:
        remote = _update_fetch(base_url.rstrip("/") + "/VERSION").decode("utf-8", "replace").strip()
    except Exception as e:
        raise FmailError(_("could not check for updates: {e}", e=e))
    if not remote:
        raise FmailError(_("could not check for updates: empty version."))
    return remote, (remote == __version__)


def self_update(app_dir, data_dir, base_url: str = UPDATE_BASE_URL) -> str:
    """Download + SHA-256-verify the latest release, then replace fmail's program files in
    app_dir (only known fmail files; config is never overwritten). All-or-nothing: nothing
    is written unless EVERY file verified. Returns the new version. Raises FmailError."""
    import hashlib
    base = base_url.rstrip("/")
    app_dir, data_dir = Path(app_dir), Path(data_dir)
    try:
        sums = _update_fetch(base + "/SHA256SUMS").decode("utf-8", "replace")
    except Exception as e:
        raise FmailError(_("download failed: {e}", e=e))
    # parse "<sha256>  <name>"; accept only safe, known fmail file names
    want = {}
    for line in sums.splitlines():
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            continue
        name = parts[1]
        if not _UPDATE_NAME_RE.fullmatch(name):
            continue                                   # no path traversal / weird names
        if not (name.endswith(".py") or name in ("VERSION", "accounts.toml.example")):
            continue                                   # only fmail's own kinds of files
        want[name] = parts[0].lower()
    if "VERSION" not in want or not any(n.endswith(".py") for n in want):
        raise FmailError(_("update manifest invalid (missing files)."))
    staged = {}
    for name, sha in want.items():
        try:
            blob = _update_fetch(f"{base}/{name}")
        except Exception as e:
            raise FmailError(_("download failed for {name}: {e}", name=name, e=e))
        if hashlib.sha256(blob).hexdigest().lower() != sha:
            raise FmailError(_("checksum mismatch for {name} — update aborted.", name=name))
        staged[name] = blob
    # everything verified → write atomically (config example to data dir, never clobbering accounts.toml)
    app_dir.mkdir(parents=True, exist_ok=True)
    try:
        for name, blob in staged.items():
            dest = (data_dir / name) if name == "accounts.toml.example" else (app_dir / name)
            tmp = dest.with_name(dest.name + ".new")
            with open(tmp, "wb") as f:
                f.write(blob)
            os.replace(tmp, dest)
    except OSError as e:
        raise FmailError(_("cannot write the update ({e}). Check permissions on {dir}.",
                           e=e, dir=app_dir))
    return staged["VERSION"].decode("utf-8", "replace").strip()


# ─── Commands ─────────────────────────────────────────────────────────────

def cmd_accounts(args, accounts, default) -> None:
    for name, acc in accounts.items():
        mark = c(_(" (default)"), "1;32") if name == default else ""
        print(f"{c(name, '1;37')}{mark}  <{acc.email}>  imap={acc.imap_host} smtp={acc.smtp_host}")


def cmd_folders(args, accounts, default) -> None:
    acc = pick_account(args, accounts, default)
    M = imap_connect(acc)
    try:
        for name, flags in list_folders(M):
            tag = c(f"  [{flags}]", "90") if flags else ""
            print(name + tag)
    finally:
        imap_logout(M)


def cmd_list(args, accounts, default) -> None:
    acc = pick_account(args, accounts, default)
    M = imap_connect(acc)
    try:
        imap_select(M, args.folder, readonly=True)
        criteria = ["UNSEEN"] if args.unseen else ["ALL"]
        uids = search_uids(M, criteria, args.limit)
        summaries = fetch_summaries(M, uids)
    finally:
        imap_logout(M)
    render_list(acc, args.folder, summaries)


def cmd_search(args, accounts, default) -> None:
    acc = pick_account(args, accounts, default)
    query = " ".join(args.query)
    M = imap_connect(acc)
    try:
        imap_select(M, args.folder, readonly=True)
        uids = search_text_uids(M, query, args.limit)
        summaries = fetch_summaries(M, uids)
    finally:
        imap_logout(M)
    render_list(acc, args.folder, summaries)


def cmd_read(args, accounts, default) -> None:
    acc = pick_account(args, accounts, default)
    uid, folder = resolve_target(args, acc)
    M = imap_connect(acc)
    try:
        imap_select(M, folder, readonly=not args.mark_read)
        msg = fetch_message(M, uid)
        render_message(msg, raw=args.raw)
        if args.mark_read:
            M.uid("store", uid, "+FLAGS", "(\\Seen)")
            print(c(_("[marked as read]"), "90"))
    finally:
        imap_logout(M)


def cmd_mark(args, accounts, default) -> None:
    acc = pick_account(args, accounts, default)
    uid, folder = resolve_target(args, acc)
    op, flag = ("-FLAGS", "(\\Seen)") if args.unread else ("+FLAGS", "(\\Seen)")
    M = imap_connect(acc)
    try:
        imap_select(M, folder, readonly=False)
        M.uid("store", uid, op, flag)
        state_label = _("unread") if args.unread else _("read")
        print(c(_("✓ UID {uid} marked {state}.", uid=uid, state=state_label), "1;32"))
    finally:
        imap_logout(M)


def _peek_summary(acc: Account, uid: str, folder: str) -> str:
    """From — Subject of the targeted mail, for confirmation before a destructive action."""
    M = imap_connect(acc)
    try:
        imap_select(M, folder, readonly=True)
        typ, md = M.uid("fetch", uid, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])")
        if typ == "OK" and md and isinstance(md[0], tuple):
            m = email.message_from_bytes(md[0][1])
            return f"{decode_field(m.get('From'))} — {decode_field(m.get('Subject')) or _('(no subject)')}"
    except imaplib.IMAP4.error:
        pass
    finally:
        imap_logout(M)
    return ""


def _confirm_move(acc: Account, uid: str, src: str, dest: str, args) -> bool:
    """Display the targeted mail and ask for confirmation (unless -y). Respects --dry-run."""
    print(c(_("Move to {dest}:", dest=dest), "1;33"))
    print(c(f"  UID {uid}  {_peek_summary(acc, uid, src)}", "90"))
    if getattr(args, "dry_run", False):
        print(c(_("[--dry-run] no move performed."), "33"))
        return False
    if getattr(args, "yes", False):
        return True
    try:
        return input(c(_("Confirm? [y/N] "), "1;33")).strip().lower() in ("y", "o", "yes", "oui")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def expunge_uid(M: imaplib.IMAP4_SSL, uid: str) -> bool:
    """Targeted expunge on a single UID (UIDPLUS). Without UIDPLUS, we run a global
    expunge ONLY if this UID is the only one flagged \\Deleted — otherwise we abstain so
    as not to inadvertently purge other deleted messages from the folder.
    Returns True if the message was actually purged from the server, False otherwise
    (abstention) — the caller can then avoid lying to the local cache."""
    if "UIDPLUS" in getattr(M, "capabilities", ()):
        typ, _unused = M.uid("EXPUNGE", uid)
        return typ == "OK"
    try:
        typ, data = M.uid("search", None, "DELETED")
        deleted = set(data[0].split()) if (typ == "OK" and data and data[0]) else set()
    except imaplib.IMAP4.error:
        return False
    if deleted <= {uid.encode() if isinstance(uid, str) else uid}:
        typ, _unused = M.expunge()   # this UID is the only \Deleted: safe purge
        return typ == "OK"
    return False   # abstention: the message stays present (flagged \Deleted)


def _move_uid(acc: Account, uid: str, src: str, dest: str) -> None:
    M = imap_connect(acc)
    try:
        imap_select(M, src, readonly=False)
        # UID MOVE (RFC 6851) if available, else COPY + \Deleted + targeted EXPUNGE.
        typ, _unused = M.uid("move", uid, _imap_quote(dest))
        if typ != "OK":
            typ, _unused = M.uid("copy", uid, _imap_quote(dest))
            if typ != "OK":
                die(_("copy to {dest} failed.", dest=dest))
            M.uid("store", uid, "+FLAGS", "(\\Deleted)")
            expunge_uid(M, uid)
    finally:
        imap_logout(M)
    forget_uid(acc.name, uid)  # the list number pointing at this UID is stale
    print(c(_("✓ UID {uid} → {dest}", uid=uid, dest=dest), "1;32"))


def cmd_move(args, accounts, default) -> None:
    acc = pick_account(args, accounts, default)
    uid, folder = resolve_target(args, acc)
    if not _confirm_move(acc, uid, folder, args.to, args):
        if not getattr(args, "dry_run", False):
            print(c(_("Cancelled."), "90"))
        return
    _move_uid(acc, uid, folder, args.to)


def cmd_archive(args, accounts, default) -> None:
    acc = pick_account(args, accounts, default)
    uid, folder = resolve_target(args, acc)
    M = imap_connect(acc)
    try:
        dest = acc.archive_folder or detect_special(M, acc).get("archive", "")
    finally:
        imap_logout(M)
    if not dest:
        die(_("no Archive folder detected (configure archive_folder)."))
    if not _confirm_move(acc, uid, folder, dest, args):
        if not getattr(args, "dry_run", False):
            print(c(_("Cancelled."), "90"))
        return
    _move_uid(acc, uid, folder, dest)


def cmd_trash(args, accounts, default) -> None:
    acc = pick_account(args, accounts, default)
    uid, folder = resolve_target(args, acc)
    M = imap_connect(acc)
    try:
        dest = acc.trash_folder or detect_special(M, acc).get("trash", "")
    finally:
        imap_logout(M)
    if not dest:
        die(_("no Trash folder detected (configure trash_folder)."))
    if not _confirm_move(acc, uid, folder, dest, args):
        if not getattr(args, "dry_run", False):
            print(c(_("Cancelled."), "90"))
        return
    _move_uid(acc, uid, folder, dest)


def cmd_reply(args, accounts, default) -> None:
    acc = pick_account(args, accounts, default)
    uid, folder = resolve_target(args, acc)
    M = imap_connect(acc)
    try:
        imap_select(M, folder, readonly=True)
        original = fetch_message(M, uid)
    finally:
        imap_logout(M)

    # Recipients: Reply-To else From; --all adds To+Cc minus oneself.
    reply_to = decode_field(original.get("Reply-To")) or decode_field(original.get("From"))
    to = _clean_addr_list(reply_to)
    cc: list[str] = []
    if args.all:
        # Dedup on the normalized bare address (not the formatted string with display name).
        seen = {parseaddr(x)[1].lower() for x in to} | {acc.email.lower()}
        others = decode_field(original.get("To")) + ", " + decode_field(original.get("Cc"))
        for a in _clean_addr_list(others):
            addr = parseaddr(a)[1].lower()
            if addr and addr not in seen:
                seen.add(addr)
                cc.append(a)

    subject = ensure_re_prefix(decode_field(original.get("Subject")) or "")

    quoted = _quote_body(original)
    body = args.body if args.body is not None else edit_body(quoted)

    msg = build_message(
        acc, to, subject, body, cc=cc or None,
        in_reply_to=original.get("Message-ID", ""),
        references=original.get("References", ""),
        attachments=getattr(args, "attach", None),
        markdown=getattr(args, "markdown", False),
    )
    finalize_send(acc, msg, args)


def cmd_forward(args, accounts, default) -> None:
    acc = pick_account(args, accounts, default)
    uid, folder = resolve_target(args, acc)
    M = imap_connect(acc)
    try:
        imap_select(M, folder, readonly=True)
        original = fetch_message(M, uid)
    finally:
        imap_logout(M)

    to = _clean_addr_list(args.to)
    subject = ensure_fwd_prefix(decode_field(original.get("Subject")) or "")
    sep = _("\n\n---------- Forwarded message ----------\n")
    headers = "\n".join(f"{k} : {decode_field(original.get(k))}"
                        for k in ("From", "Date", "Subject", "To") if original.get(k))
    fwd_body = sep + headers + "\n\n" + body_text(original).strip() + "\n"
    body = (args.body or "") + fwd_body if args.body is not None else edit_body(fwd_body)
    msg = build_message(acc, to, subject, body, attachments=getattr(args, "attach", None),
                        markdown=getattr(args, "markdown", False))
    finalize_send(acc, msg, args)


def cmd_compose(args, accounts, default) -> None:
    acc = pick_account(args, accounts, default)
    to = _clean_addr_list(args.to)
    cc = _clean_addr_list(args.cc) if args.cc else None
    if args.subject is not None:
        subject = args.subject
    else:
        try:
            subject = input(_("Subject: ")).strip()
        except (EOFError, KeyboardInterrupt):
            die(_("subject entry interrupted."))
    if not subject:
        print(c(_("⚠ empty subject."), "33"))
    body = args.body if args.body is not None else edit_body("")
    msg = build_message(acc, to, subject, body, cc=cc, attachments=getattr(args, "attach", None),
                        markdown=getattr(args, "markdown", False))
    finalize_send(acc, msg, args)


# ─── Parser ────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fmail", description=_("Minimalist multi-account CLI mail client."))
    p.add_argument("-a", "--account", help=_("Account to use (default: config)."))
    p.add_argument("-V", "--version", action="version", version=f"fmail {__version__}")
    # required=False: `fmail` without a subcommand launches the TUI.
    sub = p.add_subparsers(dest="cmd", required=False)

    def add_target(sp):
        sp.add_argument("target", help=_("List number (see fmail list) or UID with --uid."))
        sp.add_argument("--uid", action="store_true", help=_("Interpret target as a raw IMAP UID."))
        sp.add_argument("-f", "--folder", help=_("IMAP folder (default: the list's)."))

    def add_send_flags(sp):
        sp.add_argument("--body", help=_("Message body (otherwise opens the editor)."))
        sp.add_argument("--attach", action="append", metavar="FILE",
                        help=_("Attachment (repeatable)."))
        sp.add_argument("--markdown", action="store_true",
                        help=_("Interpret the body as Markdown → HTML send (+ text fallback)."))
        sp.add_argument("--dry-run", action="store_true", help=_("Build without sending."))
        sp.add_argument("-y", "--yes", action="store_true", help=_("Send without confirmation."))

    def add_move_flags(sp):
        sp.add_argument("--dry-run", action="store_true", help=_("Show the target without moving."))
        sp.add_argument("-y", "--yes", action="store_true", help=_("Move without confirmation."))

    sp = sub.add_parser("accounts", help=_("List the configured accounts.")); sp.set_defaults(func=cmd_accounts)
    sp = sub.add_parser("folders", help=_("List the IMAP folders.")); sp.set_defaults(func=cmd_folders)

    sp = sub.add_parser("vault", help=_("Encrypted vault (master password)."))
    sp.add_argument("vault_action",
                    choices=["init", "status", "passwd", "set-password", "recover",
                             "recovery-code", "duress", "purge-secrets"],
                    help="init | status | passwd | set-password <account> | recover | "
                         "recovery-code | duress | purge-secrets")
    sp.add_argument("vault_account", nargs="?", help=_("account (for set-password)."))
    sp.set_defaults(func=cmd_vault)

    sp = sub.add_parser("list", help=_("List a folder's mails."))
    sp.add_argument("-f", "--folder", default="INBOX")
    sp.add_argument("-u", "--unseen", action="store_true", help=_("Unread only."))
    sp.add_argument("-n", "--limit", type=int, default=20)
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("search", help=_("Full-text search."))
    sp.add_argument("query", nargs="+")
    sp.add_argument("-f", "--folder", default="INBOX")
    sp.add_argument("-n", "--limit", type=int, default=20)
    sp.set_defaults(func=cmd_search)

    sp = sub.add_parser("read", help=_("Display a full mail."))
    add_target(sp)
    sp.add_argument("--raw", action="store_true", help=_("Show all headers."))
    sp.add_argument("--mark-read", action="store_true", help=_("Mark as read."))
    sp.set_defaults(func=cmd_read)

    sp = sub.add_parser("mark", help=_("Mark read/unread."))
    add_target(sp)
    sp.add_argument("--unread", action="store_true", help=_("Mark unread (default: read)."))
    sp.set_defaults(func=cmd_mark)

    sp = sub.add_parser("move", help=_("Move a mail to a folder."))
    add_target(sp)
    sp.add_argument("--to", required=True, help=_("Destination folder."))
    add_move_flags(sp)
    sp.set_defaults(func=cmd_move)

    sp = sub.add_parser("archive", help=_("Move to Archive."))
    add_target(sp); add_move_flags(sp); sp.set_defaults(func=cmd_archive)
    sp = sub.add_parser("trash", help=_("Move to Trash."))
    add_target(sp); add_move_flags(sp); sp.set_defaults(func=cmd_trash)

    sp = sub.add_parser("reply", help=_("Reply to a mail."))
    add_target(sp)
    sp.add_argument("--all", action="store_true", help=_("Reply to all (To+Cc)."))
    add_send_flags(sp)
    sp.set_defaults(func=cmd_reply)

    sp = sub.add_parser("forward", help=_("Forward a mail."))
    add_target(sp)
    sp.add_argument("--to", required=True, help=_("Recipient(s)."))
    add_send_flags(sp)
    sp.set_defaults(func=cmd_forward)

    sp = sub.add_parser("compose", help=_("New message."))
    sp.add_argument("--to", required=True, help=_("Recipient(s)."))
    sp.add_argument("--cc", help=_("Copy(ies)."))
    sp.add_argument("--subject", help=_("Subject (otherwise prompt)."))
    add_send_flags(sp)
    sp.set_defaults(func=cmd_compose)

    return p


def main() -> int:
    i18n.set_lang(load_lang())   # [ui] lang (or auto-detect) before any message
    args = build_parser().parse_args()
    try:
        sec = load_security()
        cmd = getattr(args, "cmd", None)
        if cmd is None:
            # `fmail` without a subcommand → full-screen interface (curses).
            # Tolerate an unconfigured/empty account list: the TUI runs a first-launch
            # setup wizard (language → add an account → encryption) instead of erroring.
            # Unlocking (lock screen) is handled INSIDE the TUI (curses), not here.
            accounts, default = load_config(allow_empty=True)
            import fmail_tui
            return fmail_tui.run(accounts, default, getattr(args, "account", None), sec)
        accounts, default = load_config()   # CLI commands require a configured account
        # CLI commands touching the accounts → unlock the vault if enabled.
        if sec.master_password and vault.exists() and cmd not in _CLI_NO_UNLOCK:
            cli_unlock()
        try:
            args.func(args, accounts, default)
        except imaplib.IMAP4.error as e:
            die(_("IMAP error (connection interrupted?): {e}", e=e))
        except (OSError, ssl.SSLError) as e:
            die(_("network error: {e}", e=e))
    except FmailError as e:
        err(str(e))
        return e.code
    except vault.VaultError as e:
        # Vault errors (weak/illegal password, vault changed…) → clean message, no traceback.
        err(str(e))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
