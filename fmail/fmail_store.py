#!/usr/bin/env python3
# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""fmail_store — local SQLite cache + incremental IMAP sync.

Goal: the TUI reads the mail list from a local database (instant, no cap), and a
background thread regularly resyncs with the server.

Sync principles (per folder):
- UIDVALIDITY safeguard: if the server reindexed the folder, we purge that
  folder's local cache and resync everything;
- new mail: search `UID last_local+1:*` then batched fetch;
- flags (read/unread/…) and deletions: reconciled over a recent window (the last
  N UIDs) each cycle, or over the WHOLE folder in `full` mode ("check now" /
  first open);
- mail bodies: NOT fetched by the sync (on demand, cached on first open via
  set_raw / get_raw).

The server is NEVER modified by this module: readonly SELECT, FETCH, SEARCH.
"""
from __future__ import annotations

import contextlib
import email
import imaplib
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime, parseaddr

import fmail
from fmail import Summary, decode_field, _imap_quote
from i18n import _


SCHEMA = """
CREATE TABLE IF NOT EXISTS folders (
    account       TEXT NOT NULL,
    folder        TEXT NOT NULL,
    uidvalidity   INTEGER,
    uidnext       INTEGER,
    last_sync     REAL,
    PRIMARY KEY (account, folder)
);
CREATE TABLE IF NOT EXISTS messages (
    account       TEXT NOT NULL,
    folder        TEXT NOT NULL,
    uid           INTEGER NOT NULL,
    seen          INTEGER NOT NULL DEFAULT 0,
    answered      INTEGER NOT NULL DEFAULT 0,
    flagged       INTEGER NOT NULL DEFAULT 0,
    date_fmt      TEXT,
    sort_key      INTEGER,          -- epoch (INTERNALDATE) for sorting
    from_display  TEXT,
    from_addr     TEXT,
    subject       TEXT,
    raw           BLOB,             -- full message, NULL until opened
    raw_at        REAL,
    encrypted     INTEGER,          -- 1=PGP/MIME · 0=cleartext · NULL=not probed yet
    PRIMARY KEY (account, folder, uid)
);
CREATE INDEX IF NOT EXISTS idx_msg_sort
    ON messages (account, folder, sort_key DESC, uid DESC);
"""


@dataclass
class SyncStats:
    new: int = 0
    flags: int = 0
    deleted: int = 0
    reset: bool = False


# ════════════════════════════════════════════════════════════════════════════
# Local database
# ════════════════════════════════════════════════════════════════════════════

class Store:
    """Thread-safe SQLite cache (single shared connection + lock).

    WAL enabled for good concurrent read/write performance. All public methods
    take the lock: safe to call from the main thread (reads) and the sync thread
    (writes)."""

    def __init__(self, path):
        self.path = str(path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.executescript(SCHEMA)
            # Migration: "encrypted" column (encryption status for the list padlock).
            cols = {r[1] for r in self._db.execute("PRAGMA table_info(messages)")}
            if "encrypted" not in cols:
                self._db.execute("ALTER TABLE messages ADD COLUMN encrypted INTEGER")
            self._db.commit()
        self._secure()

    def _secure(self):
        """0600 on the database and its WAL/SHM side files: the cache holds
        subjects, senders and mail bodies — as sensitive as passwords."""
        for suffix in ("", "-wal", "-shm"):
            try:
                os.chmod(self.path + suffix, 0o600)
            except OSError:
                pass

    def close(self):
        with self._lock:
            # Fold the WAL into the .db THEN switch to DELETE mode → removes the
            # .db-wal / .db-shm side files (which hold CLEARTEXT mail). Without this,
            # cleartext would remain on disk even after the cache is encrypted.
            try:
                self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._db.execute("PRAGMA journal_mode=DELETE")
            except Exception:
                pass
            try:
                self._db.close()
            except Exception:
                pass

    # ── Folder sync state ────────────────────────────────────────────────
    def folder_state(self, account, folder):
        with self._lock:
            r = self._db.execute(
                "SELECT uidvalidity, uidnext, last_sync FROM folders "
                "WHERE account=? AND folder=?", (account, folder)).fetchone()
            return dict(r) if r else None

    def set_folder_state(self, account, folder, uidvalidity, uidnext, last_sync):
        with self._lock:
            self._db.execute(
                "INSERT INTO folders (account, folder, uidvalidity, uidnext, last_sync) "
                "VALUES (?,?,?,?,?) ON CONFLICT(account, folder) DO UPDATE SET "
                "uidvalidity=excluded.uidvalidity, uidnext=excluded.uidnext, "
                "last_sync=excluded.last_sync",
                (account, folder, uidvalidity, uidnext, last_sync))
            self._db.commit()

    # ── Reading messages (for the TUI) ───────────────────────────────────
    def get_summaries(self, account, folder, search="", only_unseen=False, limit=None, uids=None):
        q = ("SELECT uid, date_fmt, from_display, subject, seen, encrypted FROM messages "
             "WHERE account=? AND folder=?")
        args = [account, folder]
        if only_unseen:
            q += " AND seen=0"
        if uids is not None:
            # Filter by UID: result of a full-text server search (matches the body
            # too, unlike the local LIKE on subject/sender). We INLINE the UIDs —
            # integers validated by int(), so no injection risk — to avoid depending
            # on SQLITE_LIMIT_VARIABLE_NUMBER (999 on SQLite < 3.32; an IN with 2000
            # "?" would crash there).
            if not uids:
                return []
            in_list = ",".join(str(int(u)) for u in uids)
            q += f" AND uid IN ({in_list})"
        elif search:
            # ESCAPE: we treat %/_ as literal characters (otherwise "100%" or
            # "no_reply" would over-match). Escape "\" first.
            esc = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            q += (" AND (subject LIKE ? ESCAPE '\\' OR from_display LIKE ? ESCAPE '\\' "
                  "OR from_addr LIKE ? ESCAPE '\\')")
            pat = f"%{esc}%"
            args += [pat, pat, pat]
        q += " ORDER BY sort_key DESC, uid DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [Summary(uid=str(r["uid"]), date_fmt=r["date_fmt"] or "",
                        from_display=r["from_display"] or "(?)",
                        subject=r["subject"] or "", seen=bool(r["seen"]),
                        encrypted=(None if r["encrypted"] is None else bool(r["encrypted"])))
                for r in rows]

    def counts(self, account, folder):
        with self._lock:
            r = self._db.execute(
                "SELECT COUNT(*) total, COALESCE(SUM(seen=0),0) unseen FROM messages "
                "WHERE account=? AND folder=?", (account, folder)).fetchone()
        return (r["total"], r["unseen"]) if r else (0, 0)

    def max_uid(self, account, folder):
        with self._lock:
            r = self._db.execute(
                "SELECT MAX(uid) m FROM messages WHERE account=? AND folder=?",
                (account, folder)).fetchone()
        return (r["m"] or 0) if r else 0

    def all_uids(self, account, folder):
        with self._lock:
            rows = self._db.execute(
                "SELECT uid FROM messages WHERE account=? AND folder=?",
                (account, folder)).fetchall()
        return [r["uid"] for r in rows]

    def recent_uids(self, account, folder, window):
        with self._lock:
            rows = self._db.execute(
                "SELECT uid FROM messages WHERE account=? AND folder=? "
                "ORDER BY uid DESC LIMIT ?", (account, folder, int(window))).fetchall()
        return [r["uid"] for r in rows]

    # ── Writes (sync thread + TUI actions) ───────────────────────────────
    def upsert_messages(self, account, folder, rows):
        """rows: list of dicts {uid, seen, answered, flagged, date_fmt, sort_key,
        from_display, from_addr, subject, encrypted}. Does NOT overwrite the body (raw)."""
        if not rows:
            return
        with self._lock:
            self._db.executemany(
                "INSERT INTO messages (account, folder, uid, seen, answered, flagged, "
                " date_fmt, sort_key, from_display, from_addr, subject, encrypted) "
                "VALUES (:account,:folder,:uid,:seen,:answered,:flagged,"
                " :date_fmt,:sort_key,:from_display,:from_addr,:subject,:encrypted) "
                "ON CONFLICT(account, folder, uid) DO UPDATE SET "
                " seen=excluded.seen, answered=excluded.answered, flagged=excluded.flagged, "
                " encrypted=excluded.encrypted",
                [{"account": account, "folder": folder, "encrypted": None, **r} for r in rows])
            self._db.commit()

    def set_encrypted(self, account, folder, uid, value):
        """Records a message's encryption status (probed on read / on backfill)."""
        with self._lock:
            self._db.execute(
                "UPDATE messages SET encrypted=? WHERE account=? AND folder=? AND uid=?",
                (1 if value else 0, account, folder, int(uid)))
            self._db.commit()

    def set_encrypted_bulk(self, account, folder, pairs):
        """pairs: list of (uid, encrypted_bool) — bulk backfill of encryption status."""
        if not pairs:
            return
        with self._lock:
            self._db.executemany(
                "UPDATE messages SET encrypted=? WHERE account=? AND folder=? AND uid=?",
                [(1 if e else 0, account, folder, u) for (u, e) in pairs])
            self._db.commit()

    def uids_unprobed(self, account, folder, limit):
        """UIDs whose encryption status has not been determined yet (encrypted IS NULL),
        most recent first — for a bounded padlock backfill."""
        with self._lock:
            rows = self._db.execute(
                "SELECT uid FROM messages WHERE account=? AND folder=? AND encrypted IS NULL "
                "ORDER BY sort_key DESC, uid DESC LIMIT ?",
                (account, folder, int(limit))).fetchall()
        return [r["uid"] for r in rows]

    def update_flags_bulk(self, account, folder, flagrows):
        """flagrows: list of (uid, seen, answered, flagged)."""
        if not flagrows:
            return
        with self._lock:
            self._db.executemany(
                "UPDATE messages SET seen=?, answered=?, flagged=? "
                "WHERE account=? AND folder=? AND uid=?",
                [(s, a, fl, account, folder, u) for (u, s, a, fl) in flagrows])
            self._db.commit()

    def set_flag(self, account, folder, uid, seen=None):
        sets, args = [], []
        if seen is not None:
            sets.append("seen=?"); args.append(1 if seen else 0)
        if not sets:
            return
        args += [account, folder, int(uid)]
        with self._lock:
            self._db.execute(
                f"UPDATE messages SET {', '.join(sets)} "
                "WHERE account=? AND folder=? AND uid=?", args)
            self._db.commit()

    def delete_uids(self, account, folder, uids):
        if not uids:
            return
        with self._lock:
            self._db.executemany(
                "DELETE FROM messages WHERE account=? AND folder=? AND uid=?",
                [(account, folder, int(u)) for u in uids])
            self._db.commit()

    def clear_folder(self, account, folder):
        with self._lock:
            self._db.execute(
                "DELETE FROM messages WHERE account=? AND folder=?", (account, folder))
            self._db.execute(
                "DELETE FROM folders WHERE account=? AND folder=?", (account, folder))
            self._db.commit()

    # ── Mail bodies (on-demand cache) ────────────────────────────────────
    def get_raw(self, account, folder, uid):
        with self._lock:
            r = self._db.execute(
                "SELECT raw FROM messages WHERE account=? AND folder=? AND uid=?",
                (account, folder, int(uid))).fetchone()
        return (r["raw"] if r else None)

    def set_raw(self, account, folder, uid, raw):
        with self._lock:
            self._db.execute(
                "UPDATE messages SET raw=?, raw_at=? WHERE account=? AND folder=? AND uid=?",
                (raw, time.time(), account, folder, int(uid)))
            self._db.commit()


# ════════════════════════════════════════════════════════════════════════════
# Parsing FETCH responses
# ════════════════════════════════════════════════════════════════════════════

_UID_RE = re.compile(rb"UID\s+(\d+)")


def _chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _flags_to_cols(flags):
    return (1 if b"\\Seen" in flags else 0,
            1 if b"\\Answered" in flags else 0,
            1 if b"\\Flagged" in flags else 0)


def _parse_meta_response(md):
    """FETCH response (UID FLAGS INTERNALDATE BODY.PEEK[HEADER...]) →
    list of dicts ready for upsert_messages. Robust to meta/closer ordering."""
    rows = []
    for i, item in enumerate(md):
        if not (isinstance(item, tuple) and len(item) >= 2):
            continue
        meta = item[0] or b""
        tail = md[i + 1] if i + 1 < len(md) and isinstance(md[i + 1], (bytes, bytearray)) else b""
        blob = meta + b" " + (tail or b"")
        mu = _UID_RE.search(blob)
        if not mu:
            continue
        uid = int(mu.group(1))
        seen, answered, flagged = _flags_to_cols(imaplib.ParseFlags(blob))
        # INTERNALDATE → epoch (robust sort, independent of a bogus Date header)
        sort_key = 0
        try:
            tt = imaplib.Internaldate2tuple(blob)
            if tt:
                sort_key = int(time.mktime(tt))
        except Exception:
            pass
        msg = email.message_from_string((item[1] or b"").decode(errors="replace"))
        name, addr = parseaddr(decode_field(msg.get("From")))
        try:
            date_fmt = parsedate_to_datetime(msg.get("Date", "")).strftime("%Y-%m-%d %H:%M")
        except Exception:
            date_fmt = (msg.get("Date", "") or "")[:16]
        if not sort_key:
            # fallback: lacking a usable INTERNALDATE, the UID grows over time
            sort_key = uid
        rows.append({"uid": uid, "seen": seen, "answered": answered, "flagged": flagged,
                     "date_fmt": date_fmt, "sort_key": sort_key,
                     "from_display": name or addr or "(?)", "from_addr": addr,
                     "subject": decode_field(msg.get("Subject")),
                     "encrypted": _ct_encrypted(msg.get("Content-Type"))})
    return rows


def _ct_encrypted(content_type) -> int:
    """1 if the top-level Content-Type is PGP/MIME encrypted (RFC 3156), else 0."""
    ct = (content_type or "").lower()
    return 1 if ("multipart/encrypted" in ct and "application/pgp-encrypted" in ct) else 0


def _parse_flags_response(md):
    """FETCH response (UID FLAGS) → list of (uid, seen, answered, flagged)."""
    out = []
    for i, item in enumerate(md):
        blob = b""
        if isinstance(item, (bytes, bytearray)):
            blob = item
        elif isinstance(item, tuple):
            blob = (item[0] or b"") + b" " + (item[1] if len(item) > 1 and isinstance(item[1], (bytes, bytearray)) else b"")
        mu = _UID_RE.search(blob)
        if not mu:
            continue
        seen, answered, flagged = _flags_to_cols(imaplib.ParseFlags(blob))
        out.append((int(mu.group(1)), seen, answered, flagged))
    return out


def _fetch_meta(M, uids):
    rows = []
    for chunk in _chunks(uids, 500):
        uid_set = ",".join(str(u) for u in chunk).encode()
        typ, md = M.uid("fetch", uid_set,
                        "(UID FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS "
                        "(FROM SUBJECT DATE CONTENT-TYPE)])")
        if typ == "OK" and md:
            rows += _parse_meta_response(md)
    return rows


def _fetch_crypto_flags(M, uids):
    """(uid, encrypted) fetching only the Content-Type — lightweight, to backfill the
    encryption status of already-cached messages (list padlock)."""
    out = []
    for chunk in _chunks(uids, 500):
        uid_set = ",".join(str(u) for u in chunk).encode()
        typ, md = M.uid("fetch", uid_set, "(UID BODY.PEEK[HEADER.FIELDS (CONTENT-TYPE)])")
        if typ != "OK" or not md:
            continue
        for i, item in enumerate(md):
            if not (isinstance(item, tuple) and len(item) >= 2):
                continue
            blob = (item[0] or b"")
            mu = _UID_RE.search(blob)
            if not mu:
                continue
            msg = email.message_from_string((item[1] or b"").decode(errors="replace"))
            out.append((int(mu.group(1)), _ct_encrypted(msg.get("Content-Type"))))
    return out


def _fetch_flags(M, uids):
    out = []
    for chunk in _chunks(uids, 500):
        uid_set = ",".join(str(u) for u in chunk).encode()
        typ, md = M.uid("fetch", uid_set, "(UID FLAGS)")
        if typ == "OK" and md:
            out += _parse_flags_response(md)
    return out


def _untagged_int(M, key):
    try:
        vals = M.untagged_responses.get(key)
        if vals:
            v = vals[0]
            return int(v.decode() if isinstance(v, (bytes, bytearray)) else v)
    except Exception:
        pass
    return 0


# ════════════════════════════════════════════════════════════════════════════
# Incremental sync (read-only on the server side)
# ════════════════════════════════════════════════════════════════════════════

def sync_folder(M, store, account, folder, window=2000, full=False, progress=None,
                flag_guard=None):
    """Sync a folder into the local cache. `M`: live IMAP connection.
    `full=True` → reconcile flags + deletions over the WHOLE folder (slower).
    `progress(phase, done, total)`: optional callback. `flag_guard`: optional context
    manager serializing flag reconciliation with user actions (avoids overwriting a
    just-set \\Seen). Never modifies the server."""
    typ, _resp = M.select(_imap_quote(folder), readonly=True)
    if typ != "OK":
        raise fmail.FmailError(_("folder not found: {folder}", folder=folder))
    uidvalidity = _untagged_int(M, "UIDVALIDITY")
    uidnext = _untagged_int(M, "UIDNEXT")

    stats = SyncStats()
    st = store.folder_state(account, folder)
    if st and st.get("uidvalidity") and uidvalidity and st["uidvalidity"] != uidvalidity:
        store.clear_folder(account, folder)   # server reindexed → start from scratch
        st = None
        stats.reset = True

    if progress:
        progress("search", 0, 0)
    # Reconciliation via a set diff server ↔ cache (1 SEARCH ALL).
    # Interruption-robust: we fetch ALL missing UIDs, not just those above a marker —
    # an interrupted first sync completes on the next pass.
    typ, data = M.uid("search", None, "ALL")
    if typ != "OK":
        # NO/transient response (busy server, Dovecot internal error…): imaplib does
        # NOT raise on NO. Above all, do NOT interpret it as an empty folder, otherwise
        # the diff below would wipe the WHOLE cache (meta + bodies). We give up on this
        # pass; we'll retry on the next cycle.
        store.set_folder_state(account, folder, uidvalidity, uidnext, time.time())
        return stats
    # b" ".join(...): a large result may be split across several untagged
    # "* SEARCH" lines (RFC 3501); the "if p" filter avoids the [None] of empty
    # searches. We aggregate ALL lines, otherwise false deletions.
    server_uids = set(int(u) for u in b" ".join(p for p in data if p).split()) if data else set()
    local_uids = set(store.all_uids(account, folder))

    # 1) Deletions: present locally, absent from the server.
    gone = local_uids - server_uids
    if gone:
        store.delete_uids(account, folder, gone)
        stats.deleted = len(gone)

    # 2) Missing (new mail + backfill), MOST RECENT FIRST → the mailbox is usable
    # within seconds while the backfill continues.
    missing = sorted(server_uids - local_uids, reverse=True)
    if progress:
        progress("diff", len(missing), len(gone))
    if progress and missing:
        progress("new", 0, len(missing))
    fetched = 0
    for chunk in _chunks(missing, 500):
        store.upsert_messages(account, folder, _fetch_meta(M, chunk))
        fetched += len(chunk)
        if progress:
            progress("new", fetched, len(missing))
    stats.new = len(missing)

    # 3) Flags (read/unread…): refresh already-known messages (the missing ones were
    # just fetched with fresh flags). Recent window, or everything if full.
    fresh = set(missing)
    if full:
        scope = [u for u in local_uids if u in server_uids and u not in fresh]
    else:
        recent = set(store.recent_uids(account, folder, window))
        scope = [u for u in recent if u in server_uids and u not in fresh]
    # Flag reconciliation by BATCH, each batch under flag_guard: the server read +
    # cache write of a batch stay atomic with respect to a user action (no overwriting
    # of a just-set \Seen), BUT the lock is released between batches → a user action
    # waits at most one network round-trip (≈ one batch of 500), even during a full
    # reconciliation of a large folder.
    guard = flag_guard if flag_guard is not None else contextlib.nullcontext()
    if progress and scope:
        progress("flags", 0, len(scope))
    nflags = 0
    for chunk in _chunks(scope, 500):
        with guard:
            rows = _fetch_flags(M, chunk)
            store.update_flags_bulk(account, folder, rows)
        nflags += len(rows)
    stats.flags = nflags

    # BOUNDED backfill of the encryption status (list padlock): messages already cached
    # but never probed (encrypted IS NULL). We fetch only the Content-Type (lightweight);
    # a few sync passes are enough to cover everything, without blocking.
    unprobed = store.uids_unprobed(account, folder, 800)
    if unprobed:
        if progress:
            progress("crypto", 0, len(unprobed))
        store.set_encrypted_bulk(account, folder, _fetch_crypto_flags(M, unprobed))

    store.set_folder_state(account, folder, uidvalidity, uidnext, time.time())
    return stats


def consolidate(path):
    """Fold a SQLite database's WAL into its .db and remove -wal/-shm (best-effort).
    Used to make a legacy cache COMPLETE and free of cleartext side files before migration."""
    path = str(path)
    if not os.path.exists(path):
        return
    try:
        con = sqlite3.connect(path)
        try:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            con.execute("PRAGMA journal_mode=DELETE")
            con.commit()
        finally:
            con.close()
    except Exception:
        pass


def fetch_raw(M, folder, uid):
    """Fetch the full message (bytes) via BODY.PEEK (does not alter \\Seen).
    To be stored via Store.set_raw. Selects the folder read-only."""
    M.select(_imap_quote(folder), readonly=True)
    n = fmail.message_size(M, str(uid))
    if n is not None and n > fmail.MAX_MESSAGE_BYTES:
        return None   # message too large: the sync skips it (memory protection)
    typ, md = M.uid("fetch", str(uid), "(BODY.PEEK[])")
    for item in (md or []):
        if isinstance(item, tuple) and len(item) >= 2 and item[1]:
            return bytes(item[1])
    return None
