# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""Autocrypt (Level 1) for fmail — opportunistic, decentralized E2E encryption.

Principle: every outgoing message carries an `Autocrypt:` header with the sender's
OpenPGP public key. By reading mail, we learn correspondents' keys all by ourselves
(no keyserver, no central authority). Once we have the key of every recipient, we
can encrypt (PGP/MIME).

Implementation choice: we rely on the system `gpg` but in an **ISOLATED keyring**
(dedicated `GNUPGHOME`, 0700) — it never touches the personal ~/.gnupg nor the
web-of-trust, in line with Autocrypt's separate-keystore model. Every function that
touches gpg/the database accepts explicit `home`/`db_path` so it can be tested on
temporary keyrings/databases (never the real mailbox).
"""
from __future__ import annotations

from i18n import _

import base64
import email
import os
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from email.headerregistry import HeaderRegistry
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.policy import default as _policy_default
from email.utils import formatdate, getaddresses, make_msgid, parseaddr
from pathlib import Path

# Isolated Autocrypt keyring + peer-key database (separate from the real ~/.gnupg).
AUTOCRYPT_HOME = Path.home() / "freyja-mail" / ".gnupg-autocrypt"
PEERS_DB = Path.home() / "freyja-mail" / ".autocrypt.db"

VALID_PREFER = ("mutual", "nopreference")

GPG_TIMEOUT = 30          # s: a hung gpg must never freeze the TUI
MAX_KEYDATA = 100_000     # bytes: anti-bomb cap on a peer key (~100 KB)


class AutocryptError(Exception):
    pass


# ─── isolated gpg ────────────────────────────────────────────────────────────
def _gpg(args: list[str], home: Path, stdin: bytes | None = None) -> tuple[int, bytes, bytes]:
    """Run gpg in the `home` keyring. Never interactive (loopback), never network,
    never blocking (timeout). MINIMAL environment (no http_proxy nor inherited
    secrets; C locale for a stable stderr). The `[GNUPG:]` machine status we parse
    is itself locale-independent."""
    env = {"GNUPGHOME": str(home), "PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}
    cmd = ["gpg", "--batch", "--no-tty", "--quiet", "--yes",
           "--no-options",                  # ignore any gpg.conf dropped into the home
           "--no-auto-key-locate", "--no-auto-key-retrieve",
           "--disable-dirmngr",             # 100% local: no network call (WKD/keyserver/dirmngr)
           "--pinentry-mode", "loopback"] + args
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, env=env,
                           timeout=GPG_TIMEOUT)
    except subprocess.TimeoutExpired:
        return 124, b"", _("gpg: timed out").encode()
    except FileNotFoundError:
        return 127, b"", _("gpg: not found").encode()
    return p.returncode, p.stdout, p.stderr


def ensure_home(home: Path = AUTOCRYPT_HOME) -> None:
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)


def _secret_fpr(email: str, home: Path) -> str | None:
    """Fingerprint of the SECRET key for `email`, or None if there is none."""
    rc, out, _ = _gpg(["--list-secret-keys", "--with-colons", f"<{email}>"], home)
    if rc != 0:
        return None
    for line in out.decode(errors="replace").splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    return None


def ensure_key(email: str, name: str = "", home: Path = AUTOCRYPT_HOME) -> str:
    """Guarantee an OpenPGP key (Ed25519/cv25519) for `email`. Idempotent.
    Without a passphrase: the secret lives in the isolated keyring (0700), protected
    by permissions + the ecryptfs home — that's the Autocrypt model."""
    ensure_home(home)
    fpr = _secret_fpr(email, home)
    if fpr:
        return fpr
    uid = f"{name} <{email}>" if name else f"<{email}>"
    rc, _out, err = _gpg(
        ["--passphrase", "", "--quick-generate-key", uid, "default", "default", "never"],
        home,
    )
    if rc != 0:
        raise AutocryptError(_("key generation failed: {err}", err=err.decode(errors='replace')))
    fpr = _secret_fpr(email, home)
    if not fpr:
        raise AutocryptError(_("key generated but not found afterwards"))
    return fpr


def export_pubkey(email: str, home: Path = AUTOCRYPT_HOME) -> bytes:
    """Transferable public key (binary OpenPGP) for `email`."""
    rc, out, err = _gpg(["--export", f"<{email}>"], home)
    if rc != 0 or not out:
        raise AutocryptError(_("key export failed: {err}", err=err.decode(errors='replace')))
    return out


# ─── Autocrypt header ────────────────────────────────────────────────────────
def header_value(email: str, prefer: str = "mutual", home: Path = AUTOCRYPT_HOME) -> str:
    """Value of the `Autocrypt:` header to emit for `email`.

    keydata is split into space-separated blocks: the header thus has folding points,
    and serializing an EmailMessage (modern policy) folds it cleanly instead of
    RE-ENCODING it in RFC2047 — which would corrupt the base64 on the wire and prevent
    third-party MUAs from learning the key (bootstrap). parse_header strips these
    spaces before decoding."""
    if prefer not in VALID_PREFER:
        prefer = "nopreference"
    pub = export_pubkey(email, home)
    b64 = base64.b64encode(pub).decode("ascii")
    # Blocks of 60: the longest word ("keydata="+60 ≈ 72 < 78) fits on one line,
    # so the policy folds it without ever re-encoding it in RFC2047 (verified: ≤64 OK).
    chunked = " ".join(b64[i:i + 60] for i in range(0, len(b64), 60))
    return f"addr={email}; prefer-encrypt={prefer}; keydata={chunked}"


class _AutocryptHeader:
    """Header class for `Autocrypt:` that FOLDS on spaces without EVER re-encoding in
    RFC2047. The modern policy, by contrast, re-encodes any "word" longer than the
    line width (the key, but also the addr= token as soon as an address exceeds
    ~72 chars), which would corrupt keydata on the wire and break key learning by
    third-party MUAs (bootstrap). We touch ONLY this header: the rest of the message
    keeps the default policy (attachments in RFC 2231, accented subject in RFC2047 —
    both correct)."""
    max_count = 1

    @classmethod
    def parse(cls, value, kwds):
        kwds["decoded"] = str(value).replace("\r", "").replace("\n", "")
        kwds["parse_tree"] = None
        kwds["defects"] = []

    def fold(self, *, policy):
        name = self._name
        line, lines = f"{name}:", []
        for w in str(self).split(" "):
            if line != f"{name}:" and len(line) + 1 + len(w) > 76:
                lines.append(line)
                line = " " + w
            else:
                line = (line + " " + w) if line else w
        lines.append(line)
        return policy.linesep.join(lines) + policy.linesep


_AC_REGISTRY = HeaderRegistry()
_AC_REGISTRY.map_to_type("autocrypt", _AutocryptHeader)
# Default policy (correct attachments/subject) BUT with the non-re-encodable Autocrypt header.
_AC_POLICY = _policy_default.clone(header_factory=_AC_REGISTRY)


def attach_autocrypt_header(msg, email: str, prefer: str = "mutual",
                            home: Path = AUTOCRYPT_HOME):
    """Set the `Autocrypt:` header on a CLEARTEXT message without ever having it
    re-encoded in RFC2047 (cf. _AutocryptHeader), even for a long address, while
    PRESERVING the default handling of attachments (RFC 2231) and the subject."""
    msg.policy = _AC_POLICY
    msg["Autocrypt"] = header_value(email, prefer, home)
    return msg


def parse_header(value: str) -> dict | None:
    """Parse an `Autocrypt:` header. Returns {addr, prefer_encrypt, keydata(bytes)}
    or None if invalid. Follows Level 1: addr+keydata mandatory; any unknown
    "critical" attribute (without _ prefix) => header ignored."""
    if not value or len(value) > MAX_KEYDATA * 2:   # size guard before any processing
        return None
    attrs: dict[str, str] = {}
    for part in value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            key = k.strip()
            if key in attrs:        # duplicate attribute → header ignored (L1 spec, anti-smuggling)
                return None
            attrs[key] = v.strip()
    addr = attrs.get("addr")
    keydata = attrs.get("keydata")
    if not addr or not keydata:
        return None
    known = {"addr", "prefer-encrypt", "keydata"}
    for k in attrs:
        if not k.startswith("_") and k not in known:
            return None  # unknown critical attribute → ignore the header
    prefer = attrs.get("prefer-encrypt", "nopreference")
    if prefer not in VALID_PREFER:
        prefer = "nopreference"
    try:
        raw = base64.b64decode("".join(keydata.split()))
    except Exception:
        return None
    if not raw or len(raw) > MAX_KEYDATA:           # empty or base64 bomb → reject
        return None
    return {"addr": addr.lower(), "prefer_encrypt": prefer, "keydata": raw}


def _inspect_key(keydata: bytes, home: Path = AUTOCRYPT_HOME) -> dict | None:
    """Inspect a key WITHOUT importing it. Returns {fpr, uids:[emails], n_pub,
    has_secret} or None. Basis for validating a peer key before import."""
    ensure_home(home)
    rc, out, _ = _gpg(["--show-keys", "--with-colons"], home, stdin=keydata)
    if rc != 0:
        return None
    n_pub = 0
    has_secret = False
    fpr = None
    expires = 0
    uids: list[str] = []
    uids_raw: list[str] = []
    cur_pub = False
    for line in out.decode(errors="replace").splitlines():
        f = line.split(":")
        rec = f[0]
        if rec == "pub":
            n_pub += 1
            cur_pub = True
            if n_pub == 1 and len(f) > 6 and f[6].isdigit():
                expires = int(f[6])            # 0/absent = never expires
        elif rec in ("sec", "ssb"):           # SECRET key packet → forbidden
            has_secret = True
        elif rec == "sub":
            cur_pub = False
        elif rec == "fpr" and cur_pub and fpr is None and len(f) > 9:
            fpr = f[9]                         # 1st fpr after pub = primary key
        elif rec == "uid" and len(f) > 9:
            uids_raw.append(f[9])
            uids.append(parseaddr(f[9])[1].lower())
    if fpr is None:
        return None
    return {"fpr": fpr, "uids": uids, "uids_raw": uids_raw, "n_pub": n_pub,
            "has_secret": has_secret, "expires": expires}


def key_fpr_from_data(keydata: bytes, home: Path = AUTOCRYPT_HOME) -> str | None:
    """(Primary) fingerprint of a public key, without importing it."""
    info = _inspect_key(keydata, home)
    return info["fpr"] if info else None


def validate_peer_key(keydata: bytes, addr: str, home: Path = AUTOCRYPT_HOME) -> str | None:
    """Validate a peer key for `addr`. Requires: bounded size, EXACTLY one public
    primary key, NO secret packet, and at least one UID whose e-mails ALL equal
    `addr`. Returns the primary fingerprint if OK, otherwise None.

    Blocks: poisoning by a third-party UID (a key valid against spoofing addr==From
    but carrying <victim@…> as a UID → we would encrypt to the attacker), multi-key
    flooding (one header = several keys), import of a disguised SECRET key."""
    if not keydata or len(keydata) > MAX_KEYDATA:
        return None
    info = _inspect_key(keydata, home)
    if not info or info["has_secret"] or info["n_pub"] != 1 or not info["fpr"]:
        return None
    addr = addr.lower()
    if not info["uids"] or any(u != addr for u in info["uids"]):
        return None
    # Anti-bypass: a UID whose non-address portion contains an '@'
    # (OpenPGP comment "addr (victim@x)") is rejected — it could fool a possible
    # by-address resolution. A legitimate address has only a single '@'.
    if any(raw.count("@") > 1 for raw in info["uids_raw"]):
        return None
    return info["fpr"]


def import_pubkey(keydata: bytes, addr: str, home: Path = AUTOCRYPT_HOME) -> str:
    """Validate THEN import a peer public key into the isolated keyring. `addr` =
    expected address (== From, checked upstream). Raises AutocryptError if rejected."""
    ensure_home(home)
    fpr = validate_peer_key(keydata, addr, home)
    if not fpr:
        raise AutocryptError(_("peer key rejected (non-conforming structure/UID)"))
    rc, _out, err = _gpg(["--import", "--import-options", "import-clean"],
                         home, stdin=keydata)
    if rc != 0:
        raise AutocryptError(_("key import failed: {err}", err=err.decode(errors='replace')))
    return fpr


# ─── Peer store (keys learned from received headers) ─────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS autocrypt_peers (
    addr            TEXT PRIMARY KEY,     -- correspondent address (lowercase)
    last_seen       TEXT,                 -- date of the last mail seen from this peer (ISO)
    autocrypt_ts    TEXT,                 -- date of the last mail WITH an Autocrypt header
    prefer_encrypt  TEXT NOT NULL DEFAULT 'nopreference',
    fpr             TEXT,                 -- fingerprint of the known key
    keydata         BLOB                  -- transferable public key (binary)
);
"""
# NB: GLOBAL store (per address, not per account) — consistent with the gpg keyring
# shared across accounts. A correspondent's key is the same regardless of which
# fmail account we write to them from.


def _db(db_path: Path = PEERS_DB) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    # Idempotent migrations. Freshness is compared as integer EPOCH (instants), never
    # again as ISO strings; expires = peer key expiration; conflict/prev_fpr = anti-TOFU
    # pinning (a known peer's key changed → to be verified).
    cols = {r[1] for r in conn.execute("PRAGMA table_info(autocrypt_peers)")}
    need_backfill = "ts_epoch" not in cols
    for col, ddl in (("ts_epoch", "INTEGER"), ("expires", "INTEGER DEFAULT 0"),
                     ("conflict", "INTEGER NOT NULL DEFAULT 0"), ("prev_fpr", "TEXT"),
                     ("cand_fpr", "TEXT"), ("cand_keydata", "BLOB")):
        if col not in cols:
            conn.execute(f"ALTER TABLE autocrypt_peers ADD COLUMN {col} {ddl}")
    if need_backfill:
        # Mandatory BACKFILL: without it ts_epoch=NULL would make the freshness rule
        # always true → an attacker mail dated IN THE PAST would overwrite an
        # already-learned key (downgrade). We derive the epoch from autocrypt_ts (ISO),
        # else last_seen; for a row WITH a key but an underivable date, we take "now"
        # (an earlier mail can no longer replace it); a row WITHOUT a key stays neutral (0).
        now = int(time.time())
        for r in conn.execute(
                "SELECT addr, autocrypt_ts, last_seen, fpr FROM autocrypt_peers").fetchall():
            if not r["fpr"]:
                ep = 0
            else:
                ep = _iso_to_epoch(r["autocrypt_ts"]) or _iso_to_epoch(r["last_seen"]) or now
            conn.execute("UPDATE autocrypt_peers SET ts_epoch=? WHERE addr=?", (ep, r["addr"]))
        conn.commit()
    try:
        os.chmod(db_path, 0o600)  # contains public keys + metadata
    except OSError:
        pass
    return conn


def _iso_to_epoch(s) -> int:
    """Integer epoch from an ISO date (naive treated as UTC). 0 if empty/unreadable."""
    if not s:
        return 0
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except (ValueError, TypeError, OverflowError, OSError):
        return 0


def _iso_utc(epoch: int) -> str:
    """Readable ISO UTC (display/debug column) from an integer epoch."""
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return ""


def get_peer(addr: str, db_path: Path = PEERS_DB) -> sqlite3.Row | None:
    with _db(db_path) as conn:
        return conn.execute(
            "SELECT * FROM autocrypt_peers WHERE addr=?", (addr.lower(),)
        ).fetchone()


def update_peer(addr: str, msg_epoch: int, parsed: dict | None,
                db_path: Path = PEERS_DB, home: Path = AUTOCRYPT_HOME) -> None:
    """Update a peer's state on receipt of a mail. `msg_epoch` = message date in UTC
    SECONDS, ALREADY capped to the present by the caller (cf. _msg_date_epoch).
    Autocrypt freshness rule: we overwrite the key only if the message is STRICTLY
    more recent (comparison of INSTANTS, never of strings). `parsed` =
    parse_header(...) or None.

    Security: the key is revalidated here (UID == addr); we create a row ONLY if there
    is a key to remember (anti-growth-DoS); we purge the old key from the keyring on a
    rotation (a single key per peer); no silent downgrade of prefer-encrypt
    (mutual → nopreference)."""
    addr = addr.lower()
    try:
        msg_epoch = int(msg_epoch)
    except (TypeError, ValueError):
        msg_epoch = 0
    msg_epoch = min(msg_epoch, int(time.time()) + 300)   # defense in depth against freezing
    if parsed and not validate_peer_key(parsed["keydata"], addr, home):
        parsed = None       # non-conforming key → ignored (never a silent downgrade)
    with _db(db_path) as conn:
        row = conn.execute(
            "SELECT ts_epoch, fpr, prefer_encrypt, conflict, prev_fpr "
            "FROM autocrypt_peers WHERE addr=?",
            (addr,)).fetchone()
        if not row:
            if parsed:      # record a peer ONLY if it brings a key (anti-DoS)
                fpr = import_pubkey(parsed["keydata"], addr, home)
                exp = (_inspect_key(parsed["keydata"], home) or {}).get("expires", 0)
                conn.execute(
                    "INSERT INTO autocrypt_peers(addr, last_seen, autocrypt_ts, ts_epoch, "
                    "prefer_encrypt, fpr, keydata, expires, conflict) VALUES (?,?,?,?,?,?,?,?,0)",
                    (addr, _iso_utc(msg_epoch), _iso_utc(msg_epoch), msg_epoch,
                     parsed["prefer_encrypt"], fpr, parsed["keydata"], exp))
            return
        conn.execute("UPDATE autocrypt_peers SET last_seen=? WHERE addr=?",
                     (_iso_utc(msg_epoch), addr))
        prev_epoch = row["ts_epoch"]
        has_key = bool(row["fpr"])
        # Freshness: we establish the 1st key of a peer that has none; otherwise we
        # (re)act only on a strictly more recent KNOWN instant — never on an unknown
        # prev_epoch (otherwise an earlier mail would degrade, cf. migration).
        fresh = (not has_key) or (prev_epoch is not None and msg_epoch > prev_epoch)
        if not (parsed and fresh):
            return
        info = _inspect_key(parsed["keydata"], home) or {}
        new_fpr = info.get("fpr")
        exp = info.get("expires", 0)
        old_fpr = row["fpr"]
        prefer = parsed["prefer_encrypt"]
        if row["prefer_encrypt"] == "mutual" and prefer != "mutual":
            prefer = "mutual"                   # anti-downgrade ratchet on prefer-encrypt
        if not old_fpr:
            # No trusted key yet → we adopt directly (1st learning).
            import_pubkey(parsed["keydata"], addr, home)
            conn.execute(
                "UPDATE autocrypt_peers SET autocrypt_ts=?, ts_epoch=?, prefer_encrypt=?, "
                "fpr=?, keydata=?, expires=?, conflict=0, prev_fpr=NULL, "
                "cand_fpr=NULL, cand_keydata=NULL WHERE addr=?",
                (_iso_utc(msg_epoch), msg_epoch, prefer, new_fpr, parsed["keydata"], exp, addr))
        elif old_fpr == new_fpr:
            # Same key → simple refresh (date/prefer/expires). We do NOT touch the
            # conflict flag (an ongoing conflict stays to be acknowledged).
            conn.execute(
                "UPDATE autocrypt_peers SET autocrypt_ts=?, ts_epoch=?, prefer_encrypt=?, "
                "expires=? WHERE addr=?",
                (_iso_utc(msg_epoch), msg_epoch, prefer, exp, addr))
        else:
            # KEY CHANGE of a KNOWN peer → anti-TOFU pinning. We do NOT replace the
            # trusted key (neither in the database nor in the keyring): we remember the
            # CANDIDATE key separately and raise the (sticky) conflict flag. Encryption
            # to this peer is SUSPENDED (recommendation='disable') until clear_conflict(),
            # which — after human verification of the fingerprint — promotes the candidate.
            # Thus a forced ^E during the conflict can NEVER encrypt to an attacker's key.
            conn.execute(
                "UPDATE autocrypt_peers SET ts_epoch=?, conflict=1, prev_fpr=?, "
                "cand_fpr=?, cand_keydata=? WHERE addr=?",
                (msg_epoch, old_fpr, new_fpr, parsed["keydata"], addr))


def have_key(addr: str, db_path: Path = PEERS_DB) -> bool:
    p = get_peer(addr, db_path)
    return bool(p and p["fpr"])


# ─── PGP/MIME encryption / decryption (RFC 3156) ─────────────────────────────
def _emails(addr_headers: list[str]) -> list[str]:
    """Bare addresses (without name) extracted from address lists."""
    return [a.lower() for _n, a in getaddresses([h for h in addr_headers if h]) if a]


def _gpg_encrypt(data: bytes, recipient_fprs: list[str], sender_fpr: str, home: Path) -> bytes:
    """Encrypt+sign `data` (armored) to the FINGERPRINTS `recipient_fprs` (exact keys,
    NEVER resolved by address → no ambiguity nor UID spoofing), signed by
    `sender_fpr`. NB: we target the primary fingerprint WITHOUT "!" (gpg picks the
    encryption subkey) — a "!" on an Ed25519 primary would force the signing key and
    break encryption (rc=2 verified)."""
    args = ["--armor", "--encrypt", "--sign", "--local-user", sender_fpr,
            "--trust-model", "always"]
    for r in dict.fromkeys(recipient_fprs):     # dedupe while keeping order
        args += ["--recipient", r]
    rc, out, err = _gpg(args, home, stdin=data)
    if rc != 0 or not out:
        raise AutocryptError(_("encryption failed: {err}", err=err.decode(errors='replace')))
    return out


def _assemble_encrypted(cipher: bytes, header_pairs, autocrypt_hdr: str | None):
    """Assemble a PGP/MIME envelope (multipart/encrypted, RFC 3156) around the
    armored `cipher`, with the provided cleartext headers (pairs (name, value))."""
    outer = MIMEMultipart("encrypted", protocol="application/pgp-encrypted")
    for h, v in header_pairs:
        if v:
            outer[h] = v
    if autocrypt_hdr:
        outer["Autocrypt"] = autocrypt_hdr
    v = Message()
    v.set_type("application/pgp-encrypted")
    v.set_payload("Version: 1")
    enc = Message()
    enc.set_type("application/octet-stream")
    enc.set_payload(cipher.decode("ascii"))           # armor = 7-bit ASCII
    enc.add_header("Content-Disposition", "inline", filename="encrypted.asc")
    outer.attach(v)
    outer.attach(enc)
    return outer


def build_encrypted(acc, to, subject, body, cc=None,
                    in_reply_to="", references="", attachments=None,
                    markdown=False, prefer="mutual",
                    db_path: Path = PEERS_DB, home: Path = AUTOCRYPT_HOME):
    """Build an encrypted+signed PGP/MIME message (multipart/encrypted), to the To/Cc
    recipients + self (readable Sent copy). Encrypts by FINGERPRINT read from the peer
    store (where the key was validated UID==addr) — NEVER by address, so a same-name
    key injected into the keyring cannot become a recipient. Raises AutocryptError if
    a key is missing (fail-closed: no cleartext fallback here). Bcc is NOT handled
    (cf. _compose_send)."""
    import fmail
    full = fmail.build_message(acc, to, subject, body, cc=cc,
                               in_reply_to=in_reply_to, references=references,
                               attachments=attachments, markdown=markdown)
    inner = fmail.build_content(body, markdown=markdown, attachments=attachments)

    self_fpr = _secret_fpr(acc.email, home)
    if not self_fpr:
        raise AutocryptError(_("local (sender) key not found"))
    fprs = [self_fpr]                                  # self first (readable Sent copy)
    for em in _emails([full.get("To"), full.get("Cc")]):
        peer = get_peer(em, db_path)
        if not (peer and peer["fpr"]):
            raise AutocryptError(_("missing key for {em}", em=em))
        if "conflict" in peer.keys() and peer["conflict"]:
            # Pinning: this peer's key changed and has not been verified → we REFUSE to
            # encrypt (never to a possibly-spoofed candidate key).
            raise AutocryptError(_("key for {em} awaiting verification (change detected)", em=em))
        fprs.append(peer["fpr"])
    cipher = _gpg_encrypt(inner.as_bytes(), fprs, self_fpr, home)

    # Cleartext headers (Autocrypt Level 1 does not encrypt the subject).
    header_pairs = [(h, full[h]) for h in
                    ("From", "To", "Cc", "Subject", "Date", "Message-ID",
                     "In-Reply-To", "References") if full[h]]
    return _assemble_encrypted(cipher, header_pairs, header_value(acc.email, prefer, home))


def build_self_encrypted_draft(acc, inner_bytes: bytes, subject: str,
                               home: Path = AUTOCRYPT_HOME):
    """Encrypt a WHOLE draft (bytes of a complete EmailMessage, address headers
    included) to ONLY the sender's key, to store it encrypted server-side: body,
    attachments AND recipients are protected. The subject stays in cleartext
    (consistent with Level 1) to find the draft in the list. Raises AutocryptError if
    the local key is missing."""
    self_fpr = _secret_fpr(acc.email, home)
    if not self_fpr:
        raise AutocryptError(_("local key not found to encrypt the draft"))
    cipher = _gpg_encrypt(inner_bytes, [self_fpr], self_fpr, home)
    header_pairs = [("From", acc.from_header()),
                    ("Subject", subject),
                    ("Date", formatdate(localtime=True)),
                    ("Message-ID", make_msgid(domain=acc.email.split("@")[-1])),
                    ("X-Fmail-Encrypted-Draft", "1")]
    return _assemble_encrypted(cipher, header_pairs, None)


def is_encrypted(msg) -> bool:
    """True if `msg` is an encrypted PGP/MIME message."""
    return (msg.get_content_type() == "multipart/encrypted"
            and (msg.get_param("protocol") or "").lower() == "application/pgp-encrypted")


def _status_lines(stderr: bytes) -> list[str]:
    """gpg MACHINE status lines (prefix "[GNUPG:] "), stripped of the prefix. We trust
    only these lines (never localized human text)."""
    pre = "[GNUPG:] "
    return [l[len(pre):] for l in stderr.decode(errors="replace").splitlines()
            if l.startswith(pre)]


def decrypt_message(msg, home: Path = AUTOCRYPT_HOME):
    """Decrypt a PGP/MIME message (RFC 3156). Returns (inner_message, info) where
    info = {encrypted, signed, sig_status, signer, sig_fpr, error}; or (None, info).

    A message IS considered decrypted ONLY if gpg emits DECRYPTION_OKAY: without it a
    merely SIGNED message (which traveled IN CLEARTEXT) would be wrongly presented as
    encrypted. The structure is validated (2 parts, control part "Version: 1",
    octet-stream) to reject an injected decoy. The CTE of the encrypted part is decoded
    (base64 common among third-party MUAs)."""
    def fail(e):
        return None, {"encrypted": True, "signed": False, "sig_status": "none",
                      "signer": None, "sig_fpr": None, "error": e}
    if not is_encrypted(msg):
        return fail(_("message not encrypted (not PGP/MIME)"))
    parts = msg.get_payload() if msg.is_multipart() else []
    if len(parts) != 2:                       # RFC 3156: exactly 2 sub-parts
        return fail(_("invalid PGP/MIME structure"))
    vpart, epart = parts[0], parts[1]
    if vpart.get_content_type() != "application/pgp-encrypted":
        return fail(_("PGP/MIME control part missing"))
    vbody = vpart.get_payload(decode=True)
    vtext = (vbody.decode(errors="replace") if isinstance(vbody, (bytes, bytearray))
             else (vpart.get_payload() or ""))
    if "version: 1" not in vtext.lower():
        return fail(_("unexpected PGP/MIME version"))
    if epart.get_content_type() != "application/octet-stream":
        return fail(_("encrypted part missing"))
    data = epart.get_payload(decode=True)     # applies the CTE → raw armor bytes
    if not data:
        return fail(_("empty encrypted part"))
    rc, out, err = _gpg(["--status-fd", "2", "--decrypt"], home, stdin=data)
    lines = _status_lines(err)

    def has(tok):
        return any(l.startswith(tok) for l in lines)

    # Decryption failure = no cleartext OR no DECRYPTION_OKAY (an rc≠0 alone may just
    # signal an unverifiable signature, the signer's key being absent).
    if not out or not has("DECRYPTION_OKAY"):
        return fail(err.decode(errors="replace")[-200:] or _("decryption failed"))

    good, valid = has("GOODSIG"), has("VALIDSIG")
    expired, revoked = has("EXPKEYSIG"), has("REVKEYSIG")
    bad = has("BADSIG") or has("ERRSIG") or has("EXPSIG")
    signer, sig_fpr = None, None
    for l in lines:
        if l.startswith("GOODSIG"):
            p = l.split(None, 2)
            signer = p[2].strip() if len(p) > 2 else None
        elif l.startswith("VALIDSIG"):
            toks = l.split()[1:]
            sig_fpr = toks[-1] if len(toks) >= 10 else (toks[0] if toks else None)
    signed = bool(good and valid and not bad)   # "verified" only if GOODSIG+VALIDSIG
    sig_status = ("good" if signed else "expired" if expired else "revoked" if revoked
                  else "bad" if (bad or valid or good) else "none")
    inner = email.message_from_bytes(out, policy=_policy_default)
    return inner, {"encrypted": True, "signed": signed, "sig_status": sig_status,
                   "signer": signer, "sig_fpr": sig_fpr, "error": None}


# ─── Recommendation algorithm (encrypt by default or not) ────────────────────
def recommendation(recipient_emails: list[str],
                   db_path: Path = PEERS_DB, prefer_self: str = "mutual") -> str:
    """Returns 'disable' (missing/expired key → auto impossible), 'available'
    (possible, OFF by default) or 'encrypt' (ON by default). Simplified Level 1.
    Security: if a recipient's key CHANGED and has not been verified (conflict), we do
    NOT encrypt automatically (the user must force ^E knowingly) — defense against
    silent substitution (TOFU)."""
    if not recipient_emails:
        return "disable"
    now = int(time.time())
    peers = []
    for r in recipient_emails:
        p = get_peer(r.lower(), db_path)
        if not (p and p["fpr"]):
            return "disable"          # at least one recipient without a key
        exp = p["expires"] if "expires" in p.keys() else 0
        if exp and exp < now:
            return "disable"          # expired key → gpg would refuse anyway
        if "conflict" in p.keys() and p["conflict"]:
            # Changed, UNVERIFIED key → we SUSPEND all encryption (auto AND forced) to
            # this peer: 'disable' prevents ^E from targeting a possibly-spoofed
            # candidate key. The only path to encryption is through clear_conflict().
            return "disable"
        peers.append(p)
    if prefer_self == "mutual" and all(p["prefer_encrypt"] == "mutual" for p in peers):
        return "encrypt"
    return "available"


def peer_conflict(addr: str, db_path: Path = PEERS_DB) -> bool:
    """True if this peer's key changed and has not yet been verified/accepted."""
    p = get_peer(addr, db_path)
    return bool(p and "conflict" in p.keys() and p["conflict"])


def clear_conflict(addr: str, db_path: Path = PEERS_DB, home: Path = AUTOCRYPT_HOME,
                   expected_fpr: str | None = None) -> bool:
    """Acknowledge a key change: the user has verified the fingerprint and ACCEPTS the
    new key. We PROMOTE the candidate (import + replacement of the trusted key + purge
    of the old one) then clear the flag. This is the ONLY path that adopts a
    replacement key — never automatic learning.

    If `expected_fpr` is provided, adoption is REFUSED (returns False) when the stored
    candidate differs — defense against the race "the candidate was replaced by a more
    recent attacker mail between display and acknowledgment"."""
    addr = addr.lower()
    with _db(db_path) as conn:
        row = conn.execute(
            "SELECT fpr, cand_fpr, cand_keydata FROM autocrypt_peers WHERE addr=?",
            (addr,)).fetchone()
        if not row:
            return False
        cand = row["cand_keydata"]
        if expected_fpr is not None and row["cand_fpr"] != expected_fpr:
            return False        # the candidate changed since display → we do not adopt
        if cand:
            new_fpr = import_pubkey(cand, addr, home)        # revalidate UID==addr + import
            old_fpr = row["fpr"]
            if old_fpr and old_fpr != new_fpr:
                _gpg(["--delete-keys", old_fpr], home)       # purge the old one from the keyring
            exp = (_inspect_key(cand, home) or {}).get("expires", 0)
            conn.execute(
                "UPDATE autocrypt_peers SET fpr=?, keydata=?, expires=?, conflict=0, "
                "prev_fpr=NULL, cand_fpr=NULL, cand_keydata=NULL WHERE addr=?",
                (new_fpr, cand, exp, addr))
        else:
            conn.execute(
                "UPDATE autocrypt_peers SET conflict=0, prev_fpr=NULL, cand_fpr=NULL, "
                "cand_keydata=NULL WHERE addr=?", (addr,))
        return True
