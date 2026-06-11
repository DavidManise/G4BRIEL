# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""fmail encrypted vault — master password protecting the secrets.

A single file `~/freyja-mail/vault.gpg` (gpg `--symmetric`, AES-256) encrypted under
the **master password**, containing a JSON document:

    {"version": 1,
     "accounts": {"<name>": "<IMAP/SMTP password>", ...},
     "contacts": [{"name","email","notes","source","added"}, ...]}

Choice: we reuse the system `gpg` (zero new dependency). The passphrase is NEVER
passed in argv (visible in /proc) nor written to disk: it travels through a
dedicated file descriptor (`--passphrase-fd`). Unlocking = decrypting the vault:
a wrong password fails, there is no separate hash.

All functions accept explicit `path`/`home` so they can be tested on temporary
files (never the real vault nor the real mailbox).
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import subprocess
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path

from i18n import _

VAULT_PATH = Path.home() / "freyja-mail" / "vault.gpg"
# GNUPGHOME dedicated to the vault (separate from the Autocrypt keyring and the
# personal ~/.gnupg).
VAULT_HOME = Path.home() / "freyja-mail" / ".gnupg-vault"
GPG_TIMEOUT = 30
SCHEMA_VERSION = 1


class VaultError(Exception):
    pass


class VaultLocked(VaultError):
    """The vault is locked (no unlocked session in memory)."""


class BadPassphrase(VaultError):
    """Incorrect master password (the vault could not be decrypted)."""


def _ensure_home(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)


def _gpg_pw(args: list[str], passphrase: str, stdin: bytes, home: Path) -> tuple[int, bytes, bytes]:
    """gpg with the passphrase supplied via a dedicated FD (never argv, never disk)."""
    _ensure_home(home)
    r, w = os.pipe()
    try:
        os.write(w, (passphrase or "").encode("utf-8"))
    finally:
        os.close(w)
    cmd = ["gpg", "--batch", "--no-tty", "--quiet", "--yes", "--no-options",
           "--disable-dirmngr", "--pinentry-mode", "loopback",
           "--passphrase-fd", str(r), "--homedir", str(home)] + args
    env = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, env=env,
                           pass_fds=(r,), timeout=GPG_TIMEOUT)
    except subprocess.TimeoutExpired:
        return 124, b"", _("gpg: timed out").encode("utf-8")
    except FileNotFoundError:
        return 127, b"", _("gpg: not found").encode("utf-8")
    finally:
        os.close(r)
    return p.returncode, p.stdout, p.stderr


def encrypt_blob(data: bytes, passphrase: str, home: Path = VAULT_HOME,
                 armor: bool = True) -> bytes:
    args = ["--symmetric", "--cipher-algo", "AES256"] + (["--armor"] if armor else [])
    rc, out, err = _gpg_pw(args, passphrase, data, home)
    if rc != 0 or not out:
        raise VaultError(_("encryption failed: {err}", err=err.decode(errors='replace')[-200:]))
    return out


def decrypt_blob(cipher: bytes, passphrase: str, home: Path = VAULT_HOME) -> bytes:
    rc, out, err = _gpg_pw(["--decrypt"], passphrase, cipher, home)
    if rc != 0 or not out:
        raise BadPassphrase(_("incorrect master password (or corrupted vault)."))
    return out


def encrypt_cache(data: bytes) -> bytes:
    """Encrypt bytes (e.g. the SQLite cache) under the session DATA KEY (DEK) —
    stable even if the master password changes. Locked vault -> error."""
    if _state.get("dek") is None:
        raise VaultLocked(_("vault locked."))
    return encrypt_blob(data, _state["dek"], _state["home"], armor=False)


def decrypt_cache(cipher: bytes) -> bytes:
    """Decrypt bytes encrypted by encrypt_cache (with the session DEK)."""
    if _state.get("dek") is None:
        raise VaultLocked(_("vault locked."))
    return decrypt_blob(cipher, _state["dek"], _state["home"])


# ─── Vault file (atomic read/write) ──────────────────────────────────────────
def exists(path: Path = VAULT_PATH) -> bool:
    return Path(path).exists()


def _read_cipher(path: Path) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as e:
        raise VaultError(_("vault unreadable ({path}): {e}", path=path, e=e))


def _write_cipher(cipher: bytes, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    # 0600 right from creation (the ciphertext protects the content, but no metadata leak).
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(cipher)
    except OSError as e:
        raise VaultError(_("cannot write the vault ({path}): {e}", path=path, e=e))
    os.replace(tmp, path)          # atomic replacement


def _normalize(data: dict) -> dict:
    data.setdefault("version", SCHEMA_VERSION)
    data.setdefault("accounts", {})
    data.setdefault("contacts", [])
    return data


MIN_PASSPHRASE = 12


def _check_passphrase(pw: str) -> None:
    if not pw:
        raise VaultError(_("empty master password rejected."))
    if "\n" in pw or "\r" in pw:
        raise VaultError(_("the master password must not contain a line break "
                           "(gpg would silently truncate it)."))
    if len(pw) < MIN_PASSPHRASE:
        raise VaultError(_("master password too short (>= {n} characters).", n=MIN_PASSPHRASE))


# ─── MEMORY-HARD pre-derivation of the "password" slot only (fmt 3) ────────────
# The DEK and the recovery code are high-entropy (256 / 160 bits): their gpg locks
# (S2K) are enough. The weak link is the MASTER password (human entropy): gpg's
# iterated S2K is NOT memory-hard, so GPU-brute-forceable if vault.gpg is stolen.
# We therefore pre-derive the master password via scrypt (memory-hard) BEFORE gpg,
# for this slot only. Versioned by `fmt`: a fmt 2 vault (without `kdf`) stays
# readable with the raw password and is migrated to fmt 3 transparently.
KDF_N, KDF_R, KDF_P = 1 << 17, 8, 1          # scrypt ~ 128 MiB of RAM per attempt (OWASP-recommended)
KDF_MAXMEM = 256 * 1024 * 1024                # 128*n*r (~128 MiB) is the floor OpenSSL refuses
#                                               as-is; ~2x margin. Generous enough to also read
#                                               legacy 2^15/2^16 vaults under this same cap.


def _make_kdf() -> dict:
    """New scrypt parameters (fresh salt) to seal the password slot."""
    return {"algo": "scrypt", "n": KDF_N, "r": KDF_R, "p": KDF_P,
            "salt": base64.b64encode(os.urandom(16)).decode("ascii")}


def _kdf_passphrase(master: str, kdf: dict | None) -> str:
    """EFFECTIVE passphrase of the password slot: scrypt pre-derivation if `kdf` is
    set (fmt >= 3), otherwise the raw password (legacy fmt 2, backward-compatible)."""
    if not kdf:
        return master
    if kdf.get("algo") != "scrypt":
        raise VaultError(_("unknown vault KDF: {algo!r}.", algo=kdf.get('algo')))
    try:
        salt = base64.b64decode(kdf["salt"])
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    except (KeyError, ValueError, TypeError):
        raise VaultError(_("invalid vault KDF parameters."))
    dk = hashlib.scrypt(master.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                        dklen=32, maxmem=KDF_MAXMEM)
    return base64.b64encode(dk).decode("ascii")


# ─── ENVELOPE encryption (2 locks: password + recovery code) ─────────────────
# A random data key (DEK) encrypts the content; the DEK is itself sealed separately
# by the master password AND by the recovery code. Losing BOTH = unrecoverable vault.
# Changing the password does NOT change the DEK (re-sealing only), so an open session
# keeps working and the cache stays valid.
def _gen_dek() -> str:
    return os.urandom(32).hex()


def _gen_recovery_code() -> str:
    """Readable/transcribable code (~160 bits): 8 groups of 4 base32 characters."""
    raw = base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def _norm_recovery(code: str) -> str:
    """Normalize an entered code (uppercase, no dashes/spaces) before gpg use."""
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def _wrap(dek: str, passphrase: str, home: Path) -> str:
    return base64.b64encode(encrypt_blob(dek.encode("ascii"), passphrase, home, armor=False)
                            ).decode("ascii")


def _unwrap(blob_b64: str, passphrase: str, home: Path) -> str:
    return decrypt_blob(base64.b64decode(blob_b64), passphrase, home).decode("ascii")


def _unwrap_password(env: dict, master: str, home: Path) -> str:
    """Unseal the DEK from the "password" slot, applying the envelope's KDF
    (scrypt) if it is present (fmt >= 3)."""
    return _unwrap(env["slots"]["password"], _kdf_passphrase(master, env.get("kdf")), home)


def _read_envelope(path: Path) -> dict:
    raw = _read_cipher(path)
    try:
        env = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise VaultError(_("vault unreadable (invalid envelope)."))
    if not (isinstance(env, dict) and isinstance(env.get("slots"), dict) and env.get("body")):
        raise VaultError(_("vault unreadable (invalid envelope)."))
    # BOTH locks must be present: otherwise a direct access to
    # env["slots"]["recovery"|"password"] would raise a raw KeyError on the recovery /
    # password-change paths (truncated or tampered envelope).
    slots = env["slots"]
    if not slots.get("password") or not slots.get("recovery"):
        raise VaultError(_("vault unreadable (missing lock — truncated/corrupted envelope)."))
    return env


def _decrypt_body(env: dict, dek: str, home: Path) -> dict:
    raw = decrypt_blob(base64.b64decode(env["body"]), dek, home)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise VaultError(_("vault decrypted but unreadable (JSON): {e}", e=e))
    if not isinstance(data, dict):
        raise VaultError(_("vault decrypted but unexpected format."))
    return _normalize(data)


def _body_b64(content: dict, dek: str, home: Path) -> str:
    blob = json.dumps(_normalize(content), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(encrypt_blob(blob, dek, home, armor=False)).decode("ascii")


def read_vault(passphrase: str, path: Path = VAULT_PATH, home: Path = VAULT_HOME) -> dict:
    """Decrypt and parse the vault via the master password. BadPassphrase if wrong."""
    env = _read_envelope(path)
    dek = _unwrap_password(env, passphrase, home)
    return _decrypt_body(env, dek, home)


def write_vault(data: dict, passphrase: str, path: Path = VAULT_PATH,
                home: Path = VAULT_HOME) -> None:
    """Rewrite the BODY (via the DEK obtained from the password), PRESERVING the locks."""
    env = _read_envelope(path)
    dek = _unwrap_password(env, passphrase, home)   # check the password + recover the DEK
    env["body"] = _body_b64(data, dek, home)
    _write_cipher(json.dumps(env).encode("utf-8"), path)


def create(passphrase: str, accounts: dict | None = None, contacts: list | None = None,
           recovery_code: str | None = None, path: Path = VAULT_PATH,
           home: Path = VAULT_HOME) -> tuple[dict, str]:
    """Create a vault (refuses to overwrite). Generates a DEK + a RECOVERY CODE,
    seals the DEK under the password AND under the code. Returns (content, recovery_code)
    — the code must be SHOWN ONCE to the user (never re-stored in cleartext)."""
    if exists(path):
        raise VaultError(_("a vault already exists: {path}", path=path))
    _check_passphrase(passphrase)
    dek = _gen_dek()
    code = recovery_code or _gen_recovery_code()
    content = _normalize({"accounts": dict(accounts or {}), "contacts": list(contacts or [])})
    ensure_home_ = home
    kdf = _make_kdf()   # scrypt on the password slot ONLY (the weak human link)
    env = {"fmt": 3, "kdf": kdf,
           "slots": {"password": _wrap(dek, _kdf_passphrase(passphrase, kdf), ensure_home_),
                     "recovery": _wrap(dek, _norm_recovery(code), ensure_home_)},
           "duress": _duress_make_slot(None),   # random placeholder → presence undetectable
           "body": _body_b64(content, dek, ensure_home_)}
    _write_cipher(json.dumps(env).encode("utf-8"), path)
    return content, code


def change_passphrase(old: str, new: str, path: Path = VAULT_PATH,
                      home: Path = VAULT_HOME) -> None:
    """Change the master password: re-seals the DEK under `new` (the DEK, the body and the
    recovery lock are unchanged). Under an exclusive lock."""
    _check_passphrase(new)
    with _vault_lock(path):
        env = _read_envelope(path)
        if _duress_match(env.get("duress"), new):              # never let the master == duress
            raise VaultError(_("the new master password must DIFFER from the duress password."))
        dek = _unwrap_password(env, old, home)                 # BadPassphrase if old is wrong
        env["fmt"] = 3
        env["kdf"] = _make_kdf()                               # fresh salt on each change
        env["slots"]["password"] = _wrap(dek, _kdf_passphrase(new, env["kdf"]), home)
        _write_cipher(json.dumps(env).encode("utf-8"), path)


def reset_master_with_recovery(recovery_code: str, new_master: str,
                               path: Path = VAULT_PATH, home: Path = VAULT_HOME) -> None:
    """FORGOTTEN master password: via the RECOVERY CODE, re-seals the DEK under a new
    password. Raises BadPassphrase if the code is wrong."""
    _check_passphrase(new_master)
    with _vault_lock(path):
        env = _read_envelope(path)
        if _duress_match(env.get("duress"), new_master):       # never let the master == duress
            raise VaultError(_("the new master password must DIFFER from the duress password."))
        try:
            dek = _unwrap(env["slots"]["recovery"], _norm_recovery(recovery_code), home)
        except BadPassphrase:
            raise BadPassphrase(_("incorrect recovery code."))
        env["fmt"] = 3
        env["kdf"] = _make_kdf()                               # fresh salt
        env["slots"]["password"] = _wrap(dek, _kdf_passphrase(new_master, env["kdf"]), home)
        _write_cipher(json.dumps(env).encode("utf-8"), path)


def regenerate_recovery_code(path: Path = VAULT_PATH, home: Path = VAULT_HOME) -> str:
    """Generate a NEW recovery code (unlocked vault required) and re-seal it.
    Invalidates the old code. Returns the new code (to be shown once)."""
    if _state.get("dek") is None:
        raise VaultLocked(_("vault locked."))
    code = _gen_recovery_code()
    with _vault_lock(path):
        env = _read_envelope(path)
        env["slots"]["recovery"] = _wrap(_state["dek"], _norm_recovery(code), home)
        _write_cipher(json.dumps(env).encode("utf-8"), path)
    return code


# ─── Unlocked session (in memory, current process) ───────────────────────────
# We keep the DEK (not the master password): it is enough to read/write the body and
# the cache, and it survives a password change.
_state: dict = {"data": None, "dek": None, "path": None, "home": None, "last_active": 0.0}


def _kdf_is_weak(kdf) -> bool:
    """True if the password slot has no scrypt pre-derivation (legacy fmt 2) or a weaker
    cost than the current KDF_N (an older vault sealed before a parameter bump)."""
    if not kdf:
        return True
    try:
        return int(kdf.get("n", 0)) < KDF_N
    except (TypeError, ValueError):
        return True


def _upgrade_password_kdf(master: str, dek: str, path: Path, home: Path) -> None:
    """Transparent KDF hardening: re-seals the password slot under a fresh scrypt
    pre-derivation at the CURRENT cost (fmt 2 -> fmt 3, or a weaker fmt 3 -> stronger).
    The DEK, the body and the recovery lock are unchanged. Idempotent and best-effort
    (never blocks unlocking)."""
    with _vault_lock(path):
        env = _read_envelope(path)
        if not _kdf_is_weak(env.get("kdf")):
            return                       # already at full strength (this session or another)
        env["fmt"] = 3
        env["kdf"] = _make_kdf()
        env["slots"]["password"] = _wrap(dek, _kdf_passphrase(master, env["kdf"]), home)
        _write_cipher(json.dumps(env).encode("utf-8"), path)


def unlock(passphrase: str, path: Path = VAULT_PATH, home: Path = VAULT_HOME) -> dict:
    """Unlock the vault for the session (via the master password). BadPassphrase on failure."""
    env = _read_envelope(path)
    dek = _unwrap_password(env, passphrase, home)
    data = _decrypt_body(env, dek, home)
    _state.update(data=data, dek=dek, path=Path(path), home=Path(home), last_active=time.time())
    if _kdf_is_weak(env.get("kdf")):     # legacy fmt 2 or weaker-than-current KDF -> harden in place
        try:
            _upgrade_password_kdf(passphrase, dek, Path(path), Path(home))
        except Exception:
            pass                         # best-effort migration: never blocking
    if not isinstance(env.get("duress"), dict):   # legacy vault -> add placeholder duress slot
        try:
            with _vault_lock(path):
                e2 = _read_envelope(path)
                if not isinstance(e2.get("duress"), dict):
                    e2["duress"] = _duress_make_slot(None)
                    _write_cipher(json.dumps(e2).encode("utf-8"), path)
        except Exception:
            pass
    return data


def unlock_with_recovery(recovery_code: str, path: Path = VAULT_PATH,
                         home: Path = VAULT_HOME) -> dict:
    """Unlock via the RECOVERY CODE (forgotten password). BadPassphrase on failure."""
    env = _read_envelope(path)
    try:
        dek = _unwrap(env["slots"]["recovery"], _norm_recovery(recovery_code), home)
    except BadPassphrase:
        raise BadPassphrase(_("incorrect recovery code."))
    data = _decrypt_body(env, dek, home)
    _state.update(data=data, dek=dek, path=Path(path), home=Path(home), last_active=time.time())
    return data


# ─── DURESS / PANIC password ─────────────────────────────────────────────────
# An OPTIONAL extra password. Entering it at unlock does NOT open the vault: it
# signals the caller to DESTROY all local data (see fmail.emergency_wipe) behind a
# decoy. Only a scrypt VERIFIER (salt+hash) is stored — never the password — so it can
# be checked at the lock screen without opening the vault.
#
# OPSEC: a duress slot is ALWAYS present (a random, never-matching placeholder when no
# duress is configured), so the envelope looks byte-shaped identical whether or not a
# duress password is set — an adversary inspecting vault.gpg cannot tell.
def _duress_norm(pw) -> str:
    return unicodedata.normalize("NFC", pw or "")    # NFC so accented inputs match deterministically


def _duress_make_slot(pw):
    """Build a duress slot. pw=None → a RANDOM (never-matching) placeholder."""
    salt = os.urandom(16)
    verify = (os.urandom(32) if pw is None else
              hashlib.scrypt(_duress_norm(pw).encode("utf-8"), salt=salt, n=KDF_N,
                             r=KDF_R, p=KDF_P, dklen=32, maxmem=KDF_MAXMEM))
    return {"algo": "scrypt", "n": KDF_N, "r": KDF_R, "p": KDF_P,
            "salt": base64.b64encode(salt).decode("ascii"),
            "verify": base64.b64encode(verify).decode("ascii")}


def _duress_match(slot, entered) -> bool:
    """Constant-time check that `entered` matches the slot's verifier. False on a random
    placeholder. Never raises."""
    if not (isinstance(slot, dict) and slot.get("algo") == "scrypt"):
        return False
    try:
        salt = base64.b64decode(slot["salt"])
        verify = base64.b64decode(slot["verify"])
        got = hashlib.scrypt(_duress_norm(entered).encode("utf-8"), salt=salt, n=int(slot["n"]),
                             r=int(slot["r"]), p=int(slot["p"]), dklen=32, maxmem=KDF_MAXMEM)
    except Exception:
        return False
    return hmac.compare_digest(got, verify)


def set_duress(duress_pw: str, path: Path = VAULT_PATH, home: Path = VAULT_HOME) -> None:
    """Define the duress password. Refuses one that opens the vault (i.e. equals the
    master password or the recovery code) — it MUST be distinct."""
    _check_passphrase(duress_pw)
    with _vault_lock(path):
        env = _read_envelope(path)
        collide = False
        try:
            _unwrap_password(env, duress_pw, home); collide = True       # == master ?
        except BadPassphrase:
            pass
        if not collide:
            try:
                _unwrap(env["slots"]["recovery"], _norm_recovery(duress_pw), home); collide = True  # == recovery ?
            except BadPassphrase:
                pass
        if collide:
            raise VaultError(_("the duress password must DIFFER from the master password "
                               "and the recovery code."))
        env["duress"] = _duress_make_slot(duress_pw)
        _write_cipher(json.dumps(env).encode("utf-8"), path)


def clear_duress(path: Path = VAULT_PATH, home: Path = VAULT_HOME) -> None:
    """Disable duress — replaced by a random placeholder (stays indistinguishable)."""
    with _vault_lock(path):
        env = _read_envelope(path)
        env["duress"] = _duress_make_slot(None)
        _write_cipher(json.dumps(env).encode("utf-8"), path)


def is_duress(entered: str, path: Path = VAULT_PATH, home: Path = VAULT_HOME) -> bool:
    """True iff `entered` matches a configured duress password. Never raises; safe at
    the lock screen."""
    try:
        env = _read_envelope(path)
    except VaultError:
        return False
    if not _duress_match(env.get("duress"), entered):
        return False
    # SAFETY (AUTO-01): a duress that collides with the real master password or recovery
    # code — e.g. via Unicode normalization (NFC/NFD) — must NEVER trigger a wipe. The
    # legitimate credential ALWAYS wins: if `entered` actually opens the vault, it is not
    # a duress trigger.
    try:
        _unwrap_password(env, entered, home); return False       # it's the master
    except BadPassphrase:
        pass
    try:
        _unwrap(env["slots"]["recovery"], _norm_recovery(entered), home); return False  # it's the recovery code
    except BadPassphrase:
        pass
    return True


def is_unlocked() -> bool:
    return _state["data"] is not None


def lock() -> None:
    """Lock: wipe secrets and data key from the process memory."""
    _state.update(data=None, dek=None, last_active=0.0)


def touch() -> None:
    """Mark activity (rearm the auto-relock timer)."""
    if is_unlocked():
        _state["last_active"] = time.time()


def idle_expired(timeout: int) -> bool:
    """True if the vault is unlocked but idle for more than `timeout` s
    (timeout <= 0 -> never auto-relock)."""
    if not is_unlocked() or timeout <= 0:
        return False
    return (time.time() - _state["last_active"]) > timeout


def _data() -> dict:
    if _state["data"] is None:
        raise VaultLocked(_("vault locked."))
    return _state["data"]


@contextmanager
def _vault_lock(path: Path):
    """Exclusive inter-process lock (flock) around a read-modify-write of the vault.
    Prevents two fmail instances (or a concurrent `vault passwd`) from silently
    overwriting each other."""
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _locked_mutation(mutate) -> None:
    """Apply `mutate(data)` to the vault under an EXCLUSIVE lock, first RE-READING the
    fresh BODY from disk (decrypted with the session DEK) then rewriting ONLY the body
    (the password/recovery locks are preserved): this way a concurrent password change
    (which does not touch the DEK) is not lost, nor is another write.
    `mutate` may return False ("nothing to write") to avoid contention."""
    if _state["data"] is None or _state.get("dek") is None:
        raise VaultLocked(_("vault locked."))
    path, home, dek = _state["path"], _state["home"], _state["dek"]
    with _vault_lock(path):
        try:
            env = _read_envelope(path)
            fresh = _decrypt_body(env, dek, home)
        except (VaultError, BadPassphrase):
            raise VaultError(_("the vault changed on disk — reload fmail."))
        changed = mutate(fresh)
        if changed is not False:
            env["body"] = _body_b64(fresh, dek, home)
            _write_cipher(json.dumps(env).encode("utf-8"), path)
        _state["data"] = fresh


def _valid_email(em: str) -> bool:
    return ("@" in em and "\n" not in em and "\r" not in em and " " not in em
            and 3 <= len(em) <= 254)


def _clean_field(s: str, maxlen: int) -> str:
    """Strip control characters (CR/LF/NUL...) and bound the length."""
    s = "".join(ch for ch in (s or "") if ch == "\t" or ord(ch) >= 0x20)
    return s[:maxlen]


# ─── Account passwords ───────────────────────────────────────────────────────
def account_password(name: str) -> str | None:
    """An account's password from the unlocked vault, or None (vault locked/absent,
    or account not present in the vault)."""
    if _state["data"] is None:
        return None
    pw = _state["data"].get("accounts", {}).get(name)
    return pw if pw else None


def set_account_password(name: str, password: str) -> None:
    def op(data):
        data.setdefault("accounts", {})[name] = password
    _locked_mutation(op)


# ─── Address book ────────────────────────────────────────────────────────────
def contacts() -> list:
    return list(_data().get("contacts", []))


def get_contact(email: str) -> dict | None:
    em = (email or "").lower()
    for c in _data().get("contacts", []):
        if c.get("email", "").lower() == em:
            return c
    return None


def add_contact(email: str, name: str = "", notes: str = "",
                source: str = "manual", overwrite: bool = True) -> dict | None:
    """Add (or update) a contact, under a lock. Returns the contact."""
    em = (email or "").strip().lower()
    if not _valid_email(em):
        raise VaultError(_("invalid contact address: {email!r}", email=email))
    name = _clean_field(name, 200)
    notes = _clean_field(notes, 2000)
    result = {}

    def op(data):
        lst = data.setdefault("contacts", [])
        for c in lst:
            if c.get("email", "").lower() == em:
                result["c"] = c
                if not overwrite:
                    return False          # contact present + no overwrite -> nothing to write
                if name:
                    c["name"] = name
                if notes:
                    c["notes"] = notes
                return True
        c = {"name": name, "email": em, "notes": notes, "source": source,
             "added": int(time.time())}
        lst.append(c)
        result["c"] = c
        return True

    _locked_mutation(op)
    return result.get("c")


def learn_contact(email: str, name: str = "") -> None:
    """Discreet auto-learning: add the contact if it is absent (NEVER touches an
    existing contact — overwrite=False, so no write if already there)."""
    if not is_unlocked():
        return
    em = (email or "").strip().lower()
    if not _valid_email(em):
        return
    try:
        add_contact(em, name=_clean_field(name, 200), source="learned", overwrite=False)
    except VaultError:
        pass


def remove_contact(email: str) -> bool:
    em = (email or "").lower()
    result = {}

    def op(data):
        lst = data.setdefault("contacts", [])
        new = [c for c in lst if c.get("email", "").lower() != em]
        result["removed"] = len(new) != len(lst)
        data["contacts"] = new
        return result["removed"]          # only writes if something was removed

    _locked_mutation(op)
    return result.get("removed", False)
