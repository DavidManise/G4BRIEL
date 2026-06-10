#!/usr/bin/env python3
# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""fmail_tui — full-screen (curses) interface for fmail.

Launched by `fmail` with no sub-command. Keyboard navigation: arrows + Enter,
letter shortcuts, help bar. A single pane (list → full-screen reading), inline
message editor. Reuses the fmail engine (IMAP/SMTP) — only the primitives that
do NOT print (a print() would break the curses screen).

Security: confirmations kept (trash/move/send). Opening a mail marks it read
(\\Seen); Space toggles read/unread. A silent poll checks INBOX every 5 min
(no notification) and shows a "new mail" badge; "n" forces an immediate check.
"""
from __future__ import annotations

import curses
import email
import imaplib
import locale
import os
import re
import shutil
import ssl
import tempfile
import threading
import unicodedata
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path

import autocrypt
import fmail
import fmail_store
import vault
from fmail import FmailError
import i18n
from i18n import _


# ════════════════════════════════════════════════════════════════════════════
# Pure models (no curses) — unit-testable
# ════════════════════════════════════════════════════════════════════════════

class ListModel:
    """Scrollable list with a cursor and a visible window."""
    def __init__(self, items=None, height=10):
        self.items = list(items or [])
        self.height = max(1, height)
        self.cursor = 0
        self.top = 0

    def set_items(self, items):
        self.items = list(items)
        self.cursor = min(self.cursor, max(0, len(self.items) - 1))
        self._clamp()

    def set_height(self, h):
        self.height = max(1, h)
        self._clamp()

    def move(self, delta):
        if not self.items:
            return
        self.cursor = max(0, min(len(self.items) - 1, self.cursor + delta))
        self._clamp()

    def page(self, direction):
        self.move(direction * self.height)

    def home(self):
        self.cursor = 0
        self._clamp()

    def end(self):
        self.cursor = max(0, len(self.items) - 1)
        self._clamp()

    def _clamp(self):
        if self.cursor < self.top:
            self.top = self.cursor
        elif self.cursor >= self.top + self.height:
            self.top = self.cursor - self.height + 1
        self.top = max(0, min(self.top, max(0, len(self.items) - self.height)))

    def current(self):
        return self.items[self.cursor] if self.items else None

    def visible(self):
        return list(enumerate(self.items))[self.top:self.top + self.height]


class LineEditor:
    """Single-line editor (input field)."""
    def __init__(self, text=""):
        self.text = text
        self.cursor = len(text)

    def insert(self, ch):
        self.text = self.text[:self.cursor] + ch + self.text[self.cursor:]
        self.cursor += len(ch)

    def backspace(self):
        if self.cursor > 0:
            self.text = self.text[:self.cursor - 1] + self.text[self.cursor:]
            self.cursor -= 1

    def delete(self):
        if self.cursor < len(self.text):
            self.text = self.text[:self.cursor] + self.text[self.cursor + 1:]

    def left(self):
        self.cursor = max(0, self.cursor - 1)

    def right(self):
        self.cursor = min(len(self.text), self.cursor + 1)

    def home(self):
        self.cursor = 0

    def end(self):
        self.cursor = len(self.text)


class TextEditor:
    """Multi-line editor (message body)."""
    def __init__(self, text=""):
        self.lines = text.split("\n") if text else [""]
        self.row = 0
        self.col = 0

    def insert(self, ch):
        line = self.lines[self.row]
        self.lines[self.row] = line[:self.col] + ch + line[self.col:]
        self.col += len(ch)

    def newline(self):
        line = self.lines[self.row]
        rest = line[self.col:]
        self.lines[self.row] = line[:self.col]
        self.lines.insert(self.row + 1, rest)
        self.row += 1
        self.col = 0

    def backspace(self):
        if self.col > 0:
            line = self.lines[self.row]
            self.lines[self.row] = line[:self.col - 1] + line[self.col:]
            self.col -= 1
        elif self.row > 0:
            prev = self.lines[self.row - 1]
            self.col = len(prev)
            self.lines[self.row - 1] = prev + self.lines[self.row]
            del self.lines[self.row]
            self.row -= 1

    def delete(self):
        line = self.lines[self.row]
        if self.col < len(line):
            self.lines[self.row] = line[:self.col] + line[self.col + 1:]
        elif self.row < len(self.lines) - 1:
            self.lines[self.row] = line + self.lines[self.row + 1]
            del self.lines[self.row + 1]

    def left(self):
        if self.col > 0:
            self.col -= 1
        elif self.row > 0:
            self.row -= 1
            self.col = len(self.lines[self.row])

    def right(self):
        if self.col < len(self.lines[self.row]):
            self.col += 1
        elif self.row < len(self.lines) - 1:
            self.row += 1
            self.col = 0

    def up(self):
        if self.row > 0:
            self.row -= 1
            self.col = min(self.col, len(self.lines[self.row]))

    def down(self):
        if self.row < len(self.lines) - 1:
            self.row += 1
            self.col = min(self.col, len(self.lines[self.row]))

    def home(self):
        self.col = 0

    def end(self):
        self.col = len(self.lines[self.row])

    def text(self):
        return "\n".join(self.lines)


class ComposeState:
    def __init__(self, to="", cc="", bcc="", subject="", body="",
                 attachments=None, in_reply_to="", references="",
                 origin_uid=None, origin_folder=None, fmt="auto", account=None,
                 encrypt=None, was_encrypted=False):
        self.to = LineEditor(to)
        self.cc = LineEditor(cc)
        self.bcc = LineEditor(bcc)
        self.subject = LineEditor(subject)
        self.body = TextEditor(body)
        self.attachments = list(attachments or [])
        self.in_reply_to = in_reply_to
        self.references = references
        self.fmt = fmt   # "auto" (detect) | "plain" (forced plain text) | "markdown" (forced HTML)
        # Sending account (From). None = active account at send time.
        # Lets you reply from a different account than the one the mail arrived on.
        self.account = account
        # Autocrypt encryption: None = auto (per recommendation), True = forced,
        # False = disabled. Toggled with ^E.
        self.encrypt = encrypt
        # True if this draft comes from an ALREADY-encrypted draft: we never let it
        # fall back to cleartext, even if the recommendation changes (auto mode).
        self.was_encrypted = was_encrypted
        # If editing an existing draft: its UID/folder, to replace it (delete the
        # old one) on save or on send.
        self.origin_uid = origin_uid
        self.origin_folder = origin_folder
        self.field = 0  # 0=To 1=Cc 2=Bcc 3=Subject 4=Body

    @property
    def singleline(self):
        return [self.to, self.cc, self.bcc, self.subject]


# ════════════════════════════════════════════════════════════════════════════
# Key detection (get_wch-compatible: str for characters, int for special keys)
# ════════════════════════════════════════════════════════════════════════════

def is_enter(k):
    return k in ("\n", "\r") or k == curses.KEY_ENTER

def is_back(k):
    return k in ("\x7f", "\x08") or k == curses.KEY_BACKSPACE

def is_esc(k):
    return k == "\x1b"

def is_printable(k):
    return isinstance(k, str) and len(k) == 1 and (k.isprintable())


def _disp_width(s):
    """Display width in columns (CJK/emoji characters take 2)."""
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in s)


def _status_num(raw, key):
    """Extract an integer from the IMAP STATUS list (e.g. b'"INBOX" (MESSAGES 3 UNSEEN 1)').

    We first isolate the parenthesised list so we are not fooled by a folder name
    that literally contains "MESSAGES" or "UNSEEN"."""
    try:
        s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        lo, hi = s.rfind("("), s.rfind(")")
        seg = s[lo + 1:hi] if (0 <= lo < hi) else s
        toks = seg.split()
        for i, t in enumerate(toks):
            if t == key and i + 1 < len(toks):
                return int(toks[i + 1].rstrip(")"))
        return 0
    except Exception:
        return 0


# ════════════════════════════════════════════════════════════════════════════
# File explorer — pure logic (testable without curses)
# ════════════════════════════════════════════════════════════════════════════

def _safe_is_dir(p):
    try:
        return p.is_dir()
    except OSError:
        return False


def human_size(n):
    n = float(n)
    for unit in (_("B"), _("KB"), _("MB"), _("GB"), _("TB")):
        if n < 1024:
            return (_("{n} {unit}", n=int(n), unit=unit) if unit == _("B")
                    else _("{n:.1f} {unit}", n=n, unit=unit))
        n /= 1024
    return _("{n:.1f} {unit}", n=n, unit=_("PB"))


def list_dir(path, show_hidden=False):
    """Returns ([('..', True), (name, is_dir), …], error_message). Directories first."""
    try:
        items = list(path.iterdir())
    except OSError as e:
        return [("..", True)], _("unreadable: {e}", e=e)
    if not show_hidden:
        items = [p for p in items if not p.name.startswith(".")]
    items.sort(key=lambda p: (not _safe_is_dir(p), p.name.lower()))
    entries = [("..", True)]
    for p in items:
        d = _safe_is_dir(p)
        entries.append((p.name + ("/" if d else ""), d))
    return entries, ""


def complete_path(text, cwd, show_hidden=False):
    """Completes the last token of `text` (shell-style) against a directory's contents.

    Returns (new_text, message). Handles "cd <prefix>", "~/p", "/abs/p", and a
    simple relative token. Adds a trailing / if the only match is a directory."""
    head, sp, token = text.rpartition(" ")
    # bare "~" (no /) → propose the home directory ready to browse.
    if "/" not in token and token.startswith("~"):
        home = os.path.expanduser(token)
        if os.path.isdir(home):
            return (head + " " if sp else "") + token + "/", ""
        return text, _("no match")
    if "/" in token:
        dpart, _sep, prefix = token.rpartition("/")
        disp_dir = dpart + "/"
        expanded_dir = os.path.expanduser(dpart) if dpart else "/"
        base = Path(expanded_dir) if os.path.isabs(os.path.expanduser(token)) else (cwd / expanded_dir)
    else:
        prefix, disp_dir, base = token, "", cwd
    try:
        names = [p.name for p in base.iterdir()]
    except OSError:
        return text, _("completion failed")
    # Hide dotfiles UNLESS the user explicitly typed a leading dot.
    if not show_hidden and not prefix.startswith("."):
        names = [n for n in names if not n.startswith(".")]
    matches = sorted(n for n in names if n.startswith(prefix))
    if not matches:
        return text, _("no match")
    newtoken = disp_dir + os.path.commonprefix(matches)
    if len(matches) == 1 and _safe_is_dir(base / matches[0]):
        newtoken += "/"
    newtext = (head + " " if sp else "") + newtoken
    return newtext, ("" if len(matches) == 1 else _("{n} matches", n=len(matches)))


# ════════════════════════════════════════════════════════════════════════════
# Curses application
# ════════════════════════════════════════════════════════════════════════════

# Colors (pair id → role)
C_TITLE, C_ACCENT, C_FROM, C_DIM, C_WARN, C_ERR = 1, 2, 3, 4, 5, 6
NET_ERRORS = (FmailError, imaplib.IMAP4.error, OSError, ssl.SSLError)
POLL_INTERVAL_S = 300     # background sync — 5 min
POLL_UI_TICK_MS = 1000    # periodic loop wake-up to repaint the badge

# Control characters forbidden on a display line: a mail subject may contain
# \n/\r (folded header) or \t, which would push a line down or misalign the
# columns in curses. We replace them with a space.
_LINE_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Invisible Unicode formatting characters (category "Cf": bidirectional override
# RLO/LRO/LRI/PDI, LRM/RLM marks, ZWJ/ZWNBSP joiners…). An RLO (U+202E) in an
# attachment name reverses the display and HIDES the real extension
# ("photo‮gpj.exe" shows as "photoexe.jpg") → we strip them both on display AND
# when writing to disk.
_FORMAT_CTRL_RE = re.compile(
    "[\u00ad\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]")

# Launch splash wordmark \u2014 big bold block banner (each cell is width 1).
FMAIL_LOGO = [
    "\u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588   \u2588\u2588   \u2588\u2588\u2588\u2588\u2588   \u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588    ",
    "\u2588\u2588      \u2588\u2588\u2588 \u2588\u2588\u2588  \u2588\u2588   \u2588\u2588    \u2588\u2588    \u2588\u2588    ",
    "\u2588\u2588\u2588\u2588\u2588   \u2588\u2588 \u2588 \u2588\u2588  \u2588\u2588   \u2588\u2588    \u2588\u2588    \u2588\u2588    ",
    "\u2588\u2588      \u2588\u2588   \u2588\u2588  \u2588\u2588\u2588\u2588\u2588\u2588\u2588    \u2588\u2588    \u2588\u2588    ",
    "\u2588\u2588      \u2588\u2588   \u2588\u2588  \u2588\u2588   \u2588\u2588    \u2588\u2588    \u2588\u2588    ",
    "\u2588\u2588      \u2588\u2588   \u2588\u2588  \u2588\u2588   \u2588\u2588  \u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588\u2588\u2588\u2588\u2588",
]


class _IdleLock(BaseException):
    """Raised by _getkey() when the vault must re-lock due to inactivity. Inherits
    from BaseException (like KeyboardInterrupt) so it passes through without being
    swallowed by the `except Exception` of modal loops, all the way to the single
    main_loop handler that re-encrypts the cache then shows the lock."""


def _char_w(c: str) -> int:
    """Display width of a character in terminal cells (0, 1 or 2)."""
    if unicodedata.combining(c) or unicodedata.category(c) in ("Mn", "Me", "Cf"):
        return 0   # combining marks, variation selectors, ZWJ…
    # Only Wide/Fullwidth take 2 cells. Ambiguous (é, │, ●, —) = 1 on a modern
    # UTF-8 terminal, which fmail already assumes everywhere.
    return 2 if unicodedata.east_asian_width(c) in ("W", "F") else 1


def _trunc_w(text: str, maxw: int) -> str:
    """Longest prefix of `text` whose display width fits within `maxw`."""
    if maxw <= 0:
        return ""
    w = 0
    for i, c in enumerate(text):
        cw = _char_w(c)
        if w + cw > maxw:
            return text[:i]
        w += cw
    return text


def _dw(text: str) -> int:
    """Total display width of a string, in terminal cells."""
    return sum(_char_w(c) for c in text)


def _msg_date_iso(msg) -> str:
    """Message date as ISO UTC (for the Autocrypt freshness rule). '' on failure."""
    try:
        dt = parsedate_to_datetime(msg.get("Date"))
        if dt is None:
            return ""
        if dt.tzinfo is None:
            return dt.isoformat()
        from datetime import timezone
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return ""


_DATE_SKEW = 300   # s: clock tolerance; beyond it, a future Date is not probative


def _msg_date_epoch(msg) -> int:
    """Message date as EPOCH (UTC seconds) for Autocrypt freshness, CAPPED at the
    present (+ a small clock tolerance): a Date header forged in the future can no
    longer be assigned a distant epoch (which would FREEZE a peer's key by blocking
    any correction from their real mails). Missing/unreadable Date → now (never '',
    which would be beaten by any date)."""
    import time
    now = int(time.time())
    try:
        dt = parsedate_to_datetime(msg.get("Date"))
        if dt is None:
            return now
        if dt.tzinfo is None:                       # naive → treated as UTC
            from datetime import timezone
            dt = dt.replace(tzinfo=timezone.utc)
        ep = int(dt.timestamp())
    except Exception:
        return now
    return min(ep, now + _DATE_SKEW)


def _date_in_future(msg) -> bool:
    """True if the message Date is clearly in the future (beyond the clock
    tolerance): such a mail is NOT PROBATIVE for learning/changing a key (otherwise
    an attacker would post-date into the future to supplant a legitimate key)."""
    import time
    try:
        dt = parsedate_to_datetime(msg.get("Date"))
        if dt is None:
            return False
        if dt.tzinfo is None:
            from datetime import timezone
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp() > time.time() + _DATE_SKEW
    except Exception:
        return False


def _group_fpr(fpr: str) -> str:
    """Fingerprint formatted in groups of 4 (readable for an eyeball comparison)."""
    fpr = (fpr or "").strip()
    return " ".join(fpr[i:i + 4] for i in range(0, len(fpr), 4)) if fpr else _("(unknown)")


def _wrap_offsets(text: str, maxw: int) -> list[int]:
    """Splits `text` into visual segments of display width <= maxw. Returns the
    start character index of each segment (always [0, …]). Breaks at the character
    (not the word) — enough so nothing overflows the screen."""
    if maxw < 1:
        maxw = 1
    offs = [0]
    w = 0
    for i, c in enumerate(text):
        cw = _char_w(c)
        if w + cw > maxw and i > offs[-1]:
            offs.append(i)
            w = 0
        w += cw
    return offs

# "Dead connection" errors: we drop the pooled connection and reconnect.
# (IMAP4.abort inherits from IMAP4.error; a "plain" IMAP4.error = NO/BAD command,
#  which is NOT a drop → we don't treat it as one.)
DEAD_CONN = (imaplib.IMAP4.abort, OSError, ssl.SSLError, EOFError)


class _ImapLease:
    """Lends a pooled IMAP connection for the duration of a `with`; does NOT close
    it on exit (it stays open for the next action → no re-login). If the block
    raises a drop error, the dead connection is discarded from the pool."""
    def __init__(self, app, acc):
        self.app, self.acc, self.M = app, acc, None

    def __enter__(self):
        self.M = self.app._live_conn(self.acc)
        return self.M

    def __exit__(self, et, ev, tb):
        if et is not None and issubclass(et, DEAD_CONN):
            self.app._drop_conn(self.acc.name)
        return False   # never masks the exception


class App:
    def __init__(self, accounts, default, account=None, sec=None):
        self.accounts = accounts
        # May be empty on first launch (no account configured yet): the setup wizard
        # adds one before anything that needs self.acc runs. self.acc stays None until then.
        self.acc = (accounts.get(account) or accounts.get(default)
                    or (next(iter(accounts.values())) if accounts else None))
        self.sec = sec or fmail.load_security()
        self.folder = "INBOX"
        self.summaries = []
        self.list = ListModel(height=10)
        self.status = ""
        self.search_query = ""
        self.only_unseen = False
        self.folders = []
        self.folders_model = ListModel(height=10)
        self.folder_counts = {}
        self.focus = "mails"   # folders | mails | bar
        self.bar_idx = 0
        self._bar_from = "mails"
        self._special_cache = {}
        # ── Silent poll of new mail (INBOX) ──────────────────────────────
        self.new_count = 0          # new INBOX mails since the last glance
        self.inbox_total = 0
        self.inbox_unseen = 0
        self.poll_error = None      # last poll error (shown discreetly)
        self._inbox_max = 0         # largest UID known in INBOX
        self._poll_baseline = None  # "already seen" UID threshold (None = not set yet)
        self._poll_uidvalidity = None  # observed INBOX UIDVALIDITY (resets baseline if it changes)
        # ── Multi-account badges (collapsible left column) ────────────────
        # acct_status[name] = {"unseen":int, "uidnext":int, "new":bool, "error":bool}
        # fed by _poll_all_status (lightweight STATUS INBOX, all accounts).
        self.acct_status = {}
        # acct_baseline[name] = "already seen" UIDNEXT → ✚ if UIDNEXT has risen since.
        self.acct_baseline = {}
        self._poll_lock = threading.Lock()
        self._poll_stop = threading.Event()
        self._poll_thread = None
        # ── IMAP connection pool (main thread): one per account, kept open and
        # reused. Instant account switching once visited. The sync thread has its
        # OWN connections (imaplib is not thread-safe).
        self._conns = {}
        # ── Local cache + sync: the TUI reads the list from the cache (no cap), a
        # background thread resyncs with IMAP. ────────────────────────────
        # The cache is opened in main() AFTER unlocking the vault (encrypted mode):
        # cf. _open_cache / _close_cache.
        self.store = None
        self._cache_work = None
        self._cache_closed = False            # True when the cache is re-encrypted/erased (re-lock)
        self._raw_key = False                 # _getkey: do not arm the timer (timeout handled by the caller)
        self._sync_wake = threading.Event()   # immediate wake-up (folder open / check now)
        self._dirty = False                   # the cache changed → re-list
        self._synced = set()                  # (account, folder) synced at least once
        self._sync_conns = {}                 # IMAP pool reserved FOR THE SYNC THREAD
        self._full_next = set()               # (account, folder) to reconcile in full mode
        self._sync_cycles = {}                # (account, folder) → incremental passes since the last full
        self._cur_counts = (0, 0)             # (total, unread) of the displayed folder (cache)
        self.search_uids = None               # UIDs of an active server search (None = no search)
        self._flag_lock = threading.Lock()    # serializes flag updates (user action ↔ sync)
        self._sync_lock = threading.Lock()    # serializes sync_folder (worker ↔ "check now")
        self._active = ((self.acc.name if self.acc else None), self.folder)  # active target, read atomically by the sync thread

    # ── Setup ────────────────────────────────────────────────────────────
    def _splash(self):
        """Brief ASCII wordmark at launch. Any key skips it; auto-dismisses after a
        beat. Disabled with [ui] splash = false. Skipped on a too-small terminal."""
        if str(fmail.load_ui().get("splash", True)).lower() in ("false", "0", "no", "off"):
            return
        tagline = f"✉  {_('secure terminal mail')} · v{fmail.__version__}"
        lines = FMAIL_LOGO + ["", tagline]
        h, w = self.stdscr.getmaxyx()
        bw = max(_disp_width(s) for s in lines)
        if h < len(lines) + 2 or w < bw + 2:
            return                              # terminal too small → skip
        self.stdscr.erase()
        top = max(0, (h - len(lines)) // 2)
        for i, s in enumerate(lines):
            x = max(0, (w - _disp_width(s)) // 2)
            attr = (self._cp(C_ACCENT) | curses.A_BOLD) if i < len(FMAIL_LOGO) else self._cp(C_DIM)
            self._put(top + i, x, s, attr)
        self.stdscr.refresh()
        self._wait_key_or_timeout(1300)         # any key skips; otherwise a short beat

    def _mouse_off(self):
        # fmail never uses the mouse (it calls no mousemask). But a terminal — or a
        # previous full-screen app that exited without resetting — can leave mouse
        # tracking ON. curses then doesn't consume those reports, so their raw bytes
        # leak into the key stream: the trailing 'M' of an SGR/X10 report (ESC[<…M,
        # ESC[M) lands squarely on the "Move to folder" command. Turn every
        # mouse-reporting mode OFF at the source so no report is ever emitted:
        #   1000 normal · 1002 button-motion · 1003 any-motion · 1005/1006/1015 ext.
        try:
            os.write(1, b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l")
        except OSError:
            pass

    def main(self, stdscr):
        self.stdscr = stdscr
        curses.curs_set(0)
        stdscr.keypad(True)
        self._mouse_off()             # defuse stray trackpad/mouse signals (see _mouse_off)
        try:
            curses.set_escdelay(25)   # responsive Esc (otherwise ~1 s default latency)
        except (curses.error, AttributeError):
            pass
        self._setup_colors()
        self._splash()            # launch wordmark (skippable, [ui] splash = false to disable)
        # Master lock: decrypt the vault BEFORE any connection (account passwords
        # come from it). Esc on the lock screen = quit.
        if self.sec.master_password:
            if not vault.exists():
                raise FmailError(_("master_password enabled but no vault. "
                                   "Run first: fmail vault init"))
            self._lock_screen()
        elif (not self.accounts) or (not vault.exists() and not fmail.security_configured()):
            # First launch: pick language → add an account if none → offer encryption.
            self._setup_wizard()
            self.sec = fmail.load_security()   # the wizard may have enabled the vault
        # Single chokepoint: never proceed without a usable account. Covers both the
        # user skipping the account step AND the (mis)configured master_password-but-no-
        # account case, where the lock-screen branch above would otherwise fall through
        # to load_folders with self.acc=None (AttributeError, uncaught → raw traceback).
        if self.acc is None:
            raise FmailError(_(
                "No mail account configured yet. Run fmail again to use the setup "
                "wizard, or edit ~/freyja-mail/accounts.toml (see accounts.toml.example)."))
        self._open_cache()      # open/decrypt the cache (after unlocking the vault)
        self.load_folders()
        self.refresh_list()
        self._verbose_check("INBOX", full=False)   # verbose check at startup
        self.list.home()        # focus on the MOST RECENT message (top of list)
        self._start_sync()      # then continuous background sync (5 min + on demand)
        try:
            self.main_loop()
        finally:
            self._poll_stop.set()
            self._sync_wake.set()   # unblock the sync thread so it can exit
            self._interrupt_sync()  # break any in-flight network call → it stops promptly
            t = getattr(self, "_poll_thread", None)
            if t is not None:
                t.join(timeout=5)   # the thread must stop writing the cache before re-encryption
            self._close_all()
            self._close_cache()     # re-encrypt + erase the cleartext cache (encrypted mode)
            # NB: we do NOT close self.store here — the sync thread (daemon) may
            # still be writing (big first sync). The DB is durable (batched commit);
            # the process releases everything cleanly on exit.

    def _setup_colors(self):
        # fmail's palette (green/cyan/yellow/WHITE) is tuned for a DARK background. By
        # default we FORCE a black canvas (window bkgd + black-bg pairs) so it stays
        # readable on ANY terminal — including a light/white one (e.g. macOS Terminal
        # "Basic"), where a transparent bg would make the white title bar invisible and
        # yellow unreadable. Set [ui] background = "terminal" to keep your own bg.
        try:
            curses.start_color()
            curses.use_default_colors()
            mode = str(fmail.load_ui().get("background", "dark")).lower()
            bg = -1 if mode in ("terminal", "default", "transparent") else curses.COLOR_BLACK
            curses.init_pair(C_TITLE, curses.COLOR_WHITE, bg)
            curses.init_pair(C_ACCENT, curses.COLOR_GREEN, bg)
            curses.init_pair(C_FROM, curses.COLOR_CYAN, bg)
            # Green (instead of blue, hard to read on black) for secondary text.
            curses.init_pair(C_DIM, curses.COLOR_GREEN, bg)
            curses.init_pair(C_WARN, curses.COLOR_YELLOW, bg)
            curses.init_pair(C_ERR, curses.COLOR_RED, bg)
            if bg != -1:
                # Paint the whole screen black with white default text (covers cells
                # drawn without an explicit colour, and erase()s, on a light terminal).
                self.stdscr.bkgd(" ", curses.color_pair(C_TITLE))
        except curses.error:
            pass

    def _cp(self, pair):
        try:
            return curses.color_pair(pair)
        except curses.error:
            return 0

    # ── IMAP connection pool ─────────────────────────────────────────────
    def _imap(self, acc=None):
        """Use as `with self._imap() as M:` — pooled and reused connection."""
        return _ImapLease(self, acc or self.acc)

    def _live_conn(self, acc):
        """Live connection for this account: reuses the pooled one (liveness NOOP),
        reconnects transparently if the server has dropped it."""
        M = self._conns.get(acc.name)
        if M is not None:
            try:
                if M.noop()[0] == "OK":
                    return M
            except (imaplib.IMAP4.error, OSError, ssl.SSLError, EOFError):
                pass
            self._drop_conn(acc.name)
        M = fmail.imap_connect(acc)
        self._conns[acc.name] = M
        return M

    def _drop_conn(self, name):
        M = self._conns.pop(name, None)
        if M is not None:
            try:
                M.shutdown()      # close the socket immediately — NO network round-trip
            except Exception:     # (logout() can hang on a slow/busy/dead connection)
                pass

    def _close_all(self):
        for name in list(self._conns):
            self._drop_conn(name)

    def _interrupt_sync(self):
        """Break the sync thread out of any in-flight network call so it stops promptly
        (avoids waiting on a long initial sync at quit). Best-effort, cross-thread."""
        for M in list(getattr(self, "_sync_conns", {}).values()):
            try:
                M.shutdown()             # closes the socket → the in-flight read fails (NET_ERROR)
            except Exception:
                pass

    # ── Local cache: encrypted at rest under the vault (master_password mode) ──
    def _cache_encrypted(self):
        return bool(self.sec.master_password and self.sec.encrypt_cache)

    def _cache_work_path(self):
        # Preferably in RAM (tmpfs, fmail.SHM_DIR) → cleartext never touches the disk.
        # Fallback = config dir (e.g. macOS, no /dev/shm) — same place emergency_wipe globs.
        shm = Path(fmail.SHM_DIR)
        base = shm if shm.is_dir() else fmail.CONFIG_PATH.parent
        return base / f"fmail-cache-{os.getuid()}-{os.getpid()}.db"

    @staticmethod
    def _atomic_write(path, data, mode=0o600):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        finally:
            pass
        os.replace(tmp, path)

    @staticmethod
    def _unlink_db_set(path):
        """Deletes a SQLite file AND its side files (-wal, -shm, .tmp) — they also
        contain cleartext mails."""
        p = str(path)
        for suffix in ("", "-wal", "-shm", ".tmp"):
            try:
                os.unlink(p + suffix)
            except OSError:
                pass

    def _cleanup_stale_work(self):
        """Purges cache work files left by DEAD fmail instances (crash) — never those
        of a LIVE instance (active PID)."""
        import glob
        base = self._cache_work_path().parent
        for f in glob.glob(str(base / f"fmail-cache-{os.getuid()}-*.db")):
            try:
                pid = int(Path(f).stem.rsplit("-", 1)[1])
            except (ValueError, IndexError):
                continue
            if pid == os.getpid():
                continue
            try:
                os.kill(pid, 0)
                continue                 # alive → leave it alone
            except PermissionError:
                continue                 # alive (other user) → leave it alone
            except OSError:
                pass                     # dead PID → residue to purge
            self._unlink_db_set(f)

    def _open_cache(self):
        """Opens the cache. In cleartext (legacy) if master_password/encrypt_cache is
        off. Otherwise: decrypts .fmail_cache.db.gpg to a work file in RAM (tmpfs) —
        cleartext never touches the disk; migrates any legacy cleartext cache."""
        cfgdir = fmail.CONFIG_PATH.parent
        plain = cfgdir / ".fmail_cache.db"
        if not self._cache_encrypted():
            self.store = fmail_store.Store(plain)
            self._cache_closed = False
            return
        self._cache_enc = cfgdir / ".fmail_cache.db.gpg"
        self._cache_plain = plain
        if not Path(fmail.SHM_DIR).is_dir():
            self.status = _("⚠ /dev/shm missing: cache decrypted to disk for the session.")
        self._cleanup_stale_work()        # residue from previous crashes (dead instances)
        work = self._cache_work_path()
        self._cache_work = work
        self._unlink_db_set(work)         # start clean (.db + -wal/-shm side files)
        try:
            if self._cache_enc.exists():
                self._atomic_write(work, vault.decrypt_cache(self._cache_enc.read_bytes()))
            elif plain.exists():
                fmail_store.consolidate(plain)                 # fold the legacy WAL first
                self._atomic_write(work, plain.read_bytes())   # legacy cleartext cache migration
        except Exception as e:
            self.status = _("cache unreadable (rebuilt): ") + str(e)[:50]
            self._unlink_db_set(work)
        self.store = fmail_store.Store(work)
        self._cache_closed = False        # the sync thread can write again

    def _close_cache(self):
        """Closes the cache. In encrypted mode: Store.close() folds the WAL (no more
        cleartext side file), we re-encrypt the work file to .fmail_cache.db.gpg then
        ERASE the cleartext (+ its side files + the legacy cleartext cache). If the
        vault is locked (Esc on re-lock), we write no permanent cleartext — the cache
        delta is lost (rebuilt), never a leak.

        Signals the sync thread to stop, then waits BRIEFLY (bounded) for an in-flight
        sync to finish so it rewrites no cleartext. Never blocks forever: a long initial
        sync holds _sync_lock for seconds, and at quit we must NOT freeze (cf. the
        KeyboardInterrupt-on-quit bug). On timeout we proceed best-effort — the cleartext
        MUST still be re-encrypted + wiped (security); the sync thread is a daemon."""
        self._cache_closed = True             # tell the sync thread to stop (visible at once)
        acquired = self._sync_lock.acquire(timeout=5)
        try:
            store = self.store
            self.store = None
        finally:
            if acquired:
                self._sync_lock.release()
        try:
            if acquired and store is not None:
                store.close()             # checkpoint(TRUNCATE)+DELETE — only when no concurrent writer
        except Exception:
            pass
        work = self._cache_work
        if not work:
            return
        try:
            cipher = vault.encrypt_cache(Path(work).read_bytes())
            self._atomic_write(self._cache_enc, cipher)
            self._unlink_db_set(self._cache_plain)   # migration done → purge the legacy cleartext (+ side files)
        except Exception:
            pass
        finally:
            self._unlink_db_set(work)                # erase the work cleartext (+ side files)

    def _getkey(self):
        # When a vault is active, we guarantee a periodic wake-up of EVERY modal loop
        # (reading, composing, prompts…) so we can test for inactivity and re-lock
        # even if the user left a mail open. _raw_key=True when the caller already
        # manages its own timeout (_wait_key_or_timeout).
        arm = (self.sec.master_password and self.sec.lock_timeout > 0
               and not self._raw_key)
        if arm:
            self.stdscr.timeout(POLL_UI_TICK_MS)
        try:
            k = self.stdscr.get_wch()
        except curses.error:
            k = None
        except KeyboardInterrupt:
            k = "\x1b"
        finally:
            if arm:
                self.stdscr.timeout(-1)
        # Wake-up with no key + unlocked vault idle → re-lock. We raise a
        # BaseException that bubbles up through the modal loops to main_loop.
        if arm and k is None and vault.idle_expired(self.sec.lock_timeout):
            raise _IdleLock()
        # Defence in depth: if a mouse event still arrives (tracking re-enabled by a
        # multiplexer), curses parsed it as KEY_MOUSE — drain and treat it as no key,
        # so its bytes can never reach a command handler.
        if k == curses.KEY_MOUSE:
            try:
                curses.getmouse()
            except curses.error:
                pass
            return None
        return k

    # ── Low-level drawing ─────────────────────────────────────────────────
    def _put(self, y, x, text, attr=0):
        h, w = self.stdscr.getmaxyx()
        if not (0 <= y < h) or x >= w:
            return
        text = _LINE_CTRL_RE.sub(" ", text)   # no \n/\r/\t: a single line
        text = _FORMAT_CTRL_RE.sub("", text)  # bidi override / zero-width (anti-spoofing)
        text = _trunc_w(text, max(0, w - x))  # width truncation (emoji = 2 cells)
        try:
            self.stdscr.addstr(y, x, text, attr)
        except curses.error:
            pass  # bottom-right corner: curses always raises, harmless

    def _pad_row(self, left, tag, width):
        """Pane line: `left` on the left, `tag` flush right within `width` cells
        (emoji width accounted for). Truncates `left` if it overflows."""
        if not tag:
            return _trunc_w(left, width)
        pad = width - _dw(left) - _dw(tag)
        if pad < 1:
            left = _trunc_w(left, max(0, width - _dw(tag) - 1))
            pad = max(1, width - _dw(left) - _dw(tag))
        return left + " " * pad + tag

    def _bar(self, y, text, attr):
        h, w = self.stdscr.getmaxyx()
        self._put(y, 0, text.ljust(w)[:w - 1] if w > 0 else "", attr)

    # ── Data ──────────────────────────────────────────────────────────────
    def refresh_list(self):
        # INSTANT read from the local cache (the whole list, no cap). Syncing with
        # the server happens in the background (sync thread).
        self._relist()
        self._request_sync(self.folder)

    def _relist(self):
        """(Re)reads the list from the local cache while preserving the cursor position."""
        cur = self.list.current()
        keep_uid = cur.uid if cur else None
        # search_uids is only honored when a search is active: so clearing the search
        # (search_query="") is enough, no need to reset it to None everywhere.
        uids = self.search_uids if self.search_query else None
        self.summaries = self.store.get_summaries(
            self.acc.name, self.folder, self.search_query, self.only_unseen, uids=uids)
        self._cur_counts = self.store.counts(self.acc.name, self.folder)
        self.list.set_items(self.summaries)
        if keep_uid is not None:
            for i, s in enumerate(self.summaries):
                if s.uid == keep_uid:
                    self.list.cursor = i
                    self.list._clamp()
                    break


    # Compact button bar (quick reference). "m Menu" opens the full dropdown menu;
    # every shortcut also works directly everywhere.
    BAR = [
        (_("m Menu ▾"), "m"), (_("↵ Open"), "\n"), (_("r Reply"), "r"),
        (_("c Write"), "c"), (_("a Archive"), "a"), (_("d Del"), "d"),
        (_("n ↻ Check"), "n"), (_("/ Search"), "/"), (_("? Help"), "?"),
        (_("q Quit"), "q"),
    ]
    _FOCUS_NEXT = {"folders": "mails", "mails": "bar", "bar": "folders"}
    _FOCUS_PREV = {"folders": "bar", "mails": "folders", "bar": "mails"}

    # Dropdown menu (toggled with "m"). The Configuration sub-menu groups the
    # settings — extensible in the future. Values = action key or sentinel.
    MENU_MAIN = [
        (_("Open mail"), "\n"), (_("Reply"), "r"), (_("Reply to all"), "R"),
        (_("Forward"), "f"), (_("Compose"), "c"), (_("Archive"), "a"),
        (_("Move to trash"), "d"), (_("Move…"), "M"),
        (_("Mark read / unread"), " "), (_("Search"), "/"), (_("Filter unread"), "u"),
        (_("Check for new mail"), "n"),
        (_("⚙ Configuration ▸"), "__config__"),
        (_("General help"), "?"),
        (_("🔒 Encryption help (exchange secure mail)"), "H"),
        (_("Quit fmail"), "q"),
    ]
    MENU_CONFIG = [
        (_("Account signature"), "s"), (_("Switch account"), "A"),
        (_("Add an account"), "N"), (_("Update fmail…"), "__update__"),
        (_("Uninstall fmail…"), "__uninstall__"), (_("‹ Back"), "__back__"),
    ]

    # ── Folders (left pane) ───────────────────────────────────────────────
    def load_folders(self):
        try:
            with self._imap() as M:
                names = [n for n, _ in fmail.list_folders(M)]
                counts = {}
                for n in names:
                    try:
                        typ, data = M.status(fmail._imap_quote(n), "(MESSAGES UNSEEN)")
                        if typ == "OK" and data and data[0]:
                            counts[n] = (_status_num(data[0], "MESSAGES"),
                                         _status_num(data[0], "UNSEEN"))
                    except imaplib.IMAP4.error:
                        pass
            self.folders = names
            self.folder_counts = counts
            self._build_nav()
        except NET_ERRORS as e:
            self.folders = []
            self._build_nav()
            self.error(str(e))

    def _build_nav(self):
        """(Re)builds the left-pane tree: one line per account (collapsed), the active
        account being expanded with its folders indented. Each line is a tuple
        ("acct", name) or ("folder", name). Preserves the selected line."""
        prev = self.folders_model.current()
        rows = []
        for name in self.accounts:                 # config insertion order
            rows.append(("acct", name))
            if name == self.acc.name:
                rows.extend(("folder", f) for f in self.folders)
        self.folders_model.set_items(rows)
        # Repositions the cursor: same line if possible, else current folder, else active account.
        target = (prev if prev in rows
                  else ("folder", self.folder) if ("folder", self.folder) in rows
                  else ("acct", self.acc.name))
        if target in rows:
            self.folders_model.cursor = rows.index(target)
            self.folders_model._clamp()

    # ── Main loop (2 columns + bar) ───────────────────────────────────────
    def main_loop(self):
        curses.curs_set(0)
        while True:
            try:
                if self._main_iter() == "quit":
                    return
            except _IdleLock:
                # Inactivity detected INSIDE a modal sub-loop (reading, compose,
                # prompt…) that propagated the exception: we re-lock cleanly.
                self._do_relock()

    def _do_relock(self):
        """Idle re-lock WITHOUT leaving cleartext: re-encrypt + erase the /dev/shm
        cache BEFORE erasing the DEK (otherwise encrypt_cache would raise VaultLocked
        and the cleartext would remain), blanks the screen, asks for the master
        password, then re-opens the decrypted cache."""
        self._close_cache()                 # re-encrypt + erase the cleartext (DEK still present)
        vault.lock()                        # then only: erase the DEK from RAM
        try:
            self.stdscr.erase()             # does not expose the decrypted content behind the prompt
            self.stdscr.refresh()
        except curses.error:
            pass
        self._lock_screen()                 # blocks on master password entry
        self._open_cache()                  # re-decrypt the cache after unlocking

    def _main_iter(self):
        """One iteration of the main loop. Returns "quit" to exit."""
        # Automatic re-lock after inactivity (vault enabled).
        if self.sec.master_password and vault.idle_expired(self.sec.lock_timeout):
            self._do_relock()
        # TLS alerts raised in the background (IMAP/sync). A CHANGED certificate
        # requires explicit ACCEPTANCE (the connection is refused until verified);
        # the others (rejection, persistence failure) → red modal.
        for _a in fmail.drain_tls_alerts():
            if _a.get("kind") == "changed":
                self._tls_accept_modal(_a)
            else:
                self.error(_a["msg"])
        self.draw_main()
        # Periodic (non-blocking) wake-up to repaint the "new mail" badge fed by the
        # poll thread. _getkey arms this timeout itself when a vault is active (to
        # test for inactivity in all loops).
        self.stdscr.timeout(POLL_UI_TICK_MS)
        k = self._getkey()
        self.stdscr.timeout(-1)
        if k is None or k == curses.KEY_RESIZE:
            if self._dirty:           # the sync thread filled the cache
                self._dirty = False
                self._relist()
            # The "Syncing…" message is transient: we clear it as soon as the sync
            # thread has (re)synced the displayed folder (reappearance in _synced),
            # or if an error occurred (the "⚠ sync" badge then takes over). Cf.
            # _check_now/_open_folder.
            if self.status.startswith(_("Syncing")) and (
                    (self.acc.name, self.folder) in self._synced or self.poll_error):
                self.status = ""
            return
        vault.touch()       # real keyboard activity → re-arm the lock timer
        self.status = ""
        if k == "\t":
            nf = self._FOCUS_NEXT[self.focus]
            if nf == "bar":
                self._bar_from = self.focus
            self.focus = nf
        elif k == curses.KEY_BTAB:
            nf = self._FOCUS_PREV[self.focus]
            if nf == "bar":
                self._bar_from = self.focus
            self.focus = nf
        elif is_enter(k):
            if self._enter() == "quit":
                return "quit"
        elif is_esc(k):
            if self.search_query or self.only_unseen:
                self.search_query = ""
                self.only_unseen = False
                self.refresh_list()
        elif k in (curses.KEY_UP, curses.KEY_DOWN, curses.KEY_LEFT, curses.KEY_RIGHT,
                   curses.KEY_NPAGE, curses.KEY_PPAGE, curses.KEY_HOME, curses.KEY_END,
                   "j", "k"):
            self._nav(k)
        else:
            if self._trigger(k) == "quit":
                return "quit"

    def _nav(self, k):
        if self.focus == "bar":
            if k == curses.KEY_LEFT:
                self.bar_idx = max(0, self.bar_idx - 1)
            elif k == curses.KEY_RIGHT:
                self.bar_idx = min(len(self.BAR) - 1, self.bar_idx + 1)
            elif k == curses.KEY_UP:
                self.focus = self._bar_from
            return
        model = self.folders_model if self.focus == "folders" else self.list
        if k in (curses.KEY_UP, "k"):
            model.move(-1)
        elif k in (curses.KEY_DOWN, "j"):
            model.move(1)
        elif k == curses.KEY_NPAGE:
            model.page(1)
        elif k == curses.KEY_PPAGE:
            model.page(-1)
        elif k == curses.KEY_HOME:
            model.home()
        elif k == curses.KEY_END:
            model.end()
        elif k == curses.KEY_LEFT and self.focus == "mails":
            self.focus = "folders"
        elif k == curses.KEY_RIGHT and self.focus == "folders":
            self.focus = "mails"

    def _enter(self):
        if self.focus == "folders":
            self._activate_nav()
        elif self.focus == "bar":
            return self._trigger(self.BAR[self.bar_idx][1])
        else:
            return self._trigger("\n")

    def _activate_nav(self):
        """Enter in the left tree: on an account → switch (open its INBOX); on a
        folder → open it."""
        row = self.folders_model.current()
        if not row:
            return
        kind, name = row
        if kind == "acct":
            if name != self.acc.name:
                self._switch_account(name)
            else:
                self._open_folder("INBOX")   # already active: (re)open INBOX
            self.focus = "mails"
        else:
            self._open_folder(name)

    def _open_folder(self, f):
        if f and f != self.folder:
            self.folder = f
            self.search_query = ""
            self.only_unseen = False
            self._active = (self.acc.name, self.folder)   # target read by the sync thread
            self.refresh_list()
            self.list.home()      # focus on the MOST RECENT message (top of list)
            if (self.acc.name, f) not in self._synced:
                # cache not yet populated for this folder: signal it (≠ "empty")
                self.status = _("Syncing folder…")
            if self.folder == "INBOX":
                self._ack_new()                  # prominent badge (active account)
                self._ack_account(self.acc.name) # column ✚ badge
        self.focus = "mails"

    def _switch_account(self, name):
        """Switches to account `name`: expands its tree, opens its INBOX."""
        if name not in self.accounts:
            return
        self.acc = self.accounts[name]
        self._special_cache = {}
        self.folder = "INBOX"
        self.search_query = ""
        self.only_unseen = False
        self._active = (self.acc.name, self.folder)
        self.load_folders()      # rebuilds the tree (new account expanded)
        self._reset_poll()       # the prominent badge rebases onto the new account
        self._ack_account(name)  # we look at its INBOX → its ✚ drops
        self.refresh_list()
        self.list.home()         # focus on the MOST RECENT message (top of list)

    def _trigger(self, key):
        """Runs the action bound to a key (direct shortcut or button)."""
        if is_enter(key) or key == "l":
            cur = self.list.current()
            if cur:
                if self._is_drafts():
                    self._edit_draft(cur)        # a draft opens in edit mode
                elif self.reader_loop(cur):
                    self._refresh_all()
            return None
        return self._mail_action(key)

    def _is_drafts(self):
        return bool(self.folder) and self.folder == self._special("drafts")

    def _edit_draft(self, summary):
        """Opens a draft in the editor; on save/send, the old one is replaced."""
        try:
            with self._imap() as M:
                fmail.imap_select(M, self.folder, readonly=True)
                msg = fmail.fetch_message(M, summary.uid)
        except NET_ERRORS as e:
            self.error(str(e))
            return
        # Self-encrypted draft: decrypt it so it can be edited.
        was_enc = bool(autocrypt.is_encrypted(msg) and msg.get("X-Fmail-Encrypted-Draft"))
        if was_enc:
            inner, _info = autocrypt.decrypt_message(msg)
            if inner is None:
                self.error(_("encrypted draft: cannot decrypt (missing key?)."))
                return
            msg = inner
        enc_intent = {"auto": None, "force": True, "off": False}.get(
            (msg.get("X-Fmail-Encrypt") or "").lower(), None)
        cs = ComposeState(
            to=fmail.decode_field(msg.get("To")),
            cc=fmail.decode_field(msg.get("Cc")),
            bcc=(fmail.decode_field(msg.get("Bcc"))
                 or fmail.decode_field(msg.get("X-Fmail-Bcc"))),
            subject=fmail.decode_field(msg.get("Subject")),
            body=fmail.body_text(msg),
            in_reply_to=msg.get("In-Reply-To", ""),
            references=msg.get("References", ""),
            origin_uid=summary.uid, origin_folder=self.folder,
            fmt=(msg.get("X-Fmail-Format") or
                 ("markdown" if msg.get("X-Fmail-Markdown") == "1" else "auto")),
            account=(msg.get("X-Fmail-Account")
                     if msg.get("X-Fmail-Account") in self.accounts else None),
            encrypt=enc_intent,
            was_encrypted=was_enc,
        )
        # draft attachments → a single temporary directory, cleaned up on exit
        tmpdir = None
        for part in msg.walk():
            if "attachment" in (part.get("Content-Disposition") or "").lower():
                try:
                    data = part.get_payload(decode=True) or b""
                    if tmpdir is None:
                        tmpdir = tempfile.mkdtemp(prefix="fmail-draft-")
                    p = self._write_attachment(tmpdir, part.get_filename(), data)
                    cs.attachments.append(str(p))
                except OSError:
                    pass
        try:
            self.compose_loop(cs)
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)
        self._refresh_all()

    def _delete_origin(self, cs):
        """Deletes the original draft (after send/re-save). Returns True if deleted
        (or nothing to delete), False if the failure leaves a duplicate."""
        if not getattr(cs, "origin_uid", None):
            return True
        try:
            with self._imap() as M:
                fmail.imap_select(M, cs.origin_folder, readonly=False)
                M.uid("store", cs.origin_uid, "+FLAGS", "(\\Deleted)")
                fmail.expunge_uid(M, cs.origin_uid)
        except NET_ERRORS:
            return False   # keep origin_uid: old draft still present (duplicate)
        cs.origin_uid = None   # deleted: avoids a double deletion
        return True

    def _mail_action(self, k):
        if k in ("q", "Q"):
            return "quit"
        elif k == "c":
            self.compose_loop(ComposeState(body=self._sig_block()))
        elif k == "s":
            self._edit_signature()
        elif k in ("r", "R", "f"):
            cur = self.list.current()
            if cur:
                # Pre-arm encryption if the mail is encrypted (cached lock): replying
                # from the LIST must be fail-closed like from the reader (otherwise a
                # reply to an encrypted exchange would go out in cleartext).
                # CAUTIOUS FAIL-CLOSED: a still-UNPROBED status (encrypted=None) is
                # treated as encrypted — we only downgrade to cleartext if the mail is
                # CONFIRMED unencrypted.
                self._reply_or_forward(cur.uid, kind=k,
                                       encrypted=(getattr(cur, "encrypted", False) is not False))
        elif k == "a":
            self._action_move_current(self._special("archive"), _("Archive"))
        elif k in ("d", curses.KEY_DC):
            self._action_move_current(self._special("trash"), _("Move to trash"))
        elif k == "m":
            sel = self._open_menu()
            if sel is not None:
                return self._trigger(sel)
        elif k == "M":
            self._move_to_folder_current()
        elif k == " ":
            self._toggle_seen_current()
        elif k == "/":
            self._search_prompt()
        elif k == "u":
            self.only_unseen = not self.only_unseen
            self.search_query = ""
            self.refresh_list()
        elif k == "n":
            self._check_now()
        elif k == "g":
            self.focus = "folders"
        elif k == "A":
            self._account_picker()
        elif k == "N":
            self._new_account_flow()
        elif k == "C":
            self._address_book()
        elif k == "H" or k == "\x01":   # H, or Ctrl-A (consistent with the composer)
            self._crypto_help()
        elif k == "?":
            self.help_box()
        elif k == "__update__":
            return self._update_flow()
        elif k == "__uninstall__":
            return self._uninstall_flow()
        return None

    # ── 2-column rendering ────────────────────────────────────────────────
    def draw_main(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        fw = max(18, min(28, w // 4))
        body_top, body_bot = 1, h - 3
        pane_h = max(1, body_bot - body_top + 1)

        self._bar(0, f" fmail {fmail.__version__} · {self.acc.name}  ({self.acc.email})",
                  self._cp(C_TITLE) | curses.A_BOLD | curses.A_REVERSE)
        # "New mail" badge (high contrast, top-right). Acknowledged by looking at
        # INBOX. Otherwise, a discreet poll-failure indicator.
        with self._poll_lock:
            nc, perr = self.new_count, self.poll_error
        if nc:
            badge = _(" ✚ {n} new ", n=nc)
            self._put(0, max(0, w - _dw(badge) - 1), badge,
                      self._cp(C_ERR) | curses.A_REVERSE | curses.A_BOLD)
        elif perr:
            warn = _(" ⚠ sync ")
            self._put(0, max(0, w - _dw(warn) - 1), warn,
                      self._cp(C_WARN) | curses.A_REVERSE)

        # Left pane: accounts tree (collapsed) / active-account folders (expanded)
        self.folders_model.set_height(max(1, pane_h - 1))
        self._put(body_top, 0, _("Accounts").ljust(fw)[:fw],
                  self._cp(C_TITLE) | curses.A_BOLD | (curses.A_REVERSE if self.focus == "folders" else 0))
        with self._poll_lock:
            status = dict(self.acct_status)   # atomic copy for rendering
        for i, (idx, row) in enumerate(self.folders_model.visible()):
            kind, name = row
            is_sel = (idx == self.folders_model.cursor)
            sel_attr = (self.focus == "folders" and is_sel)
            if kind == "acct":
                active = (name == self.acc.name)
                st = status.get(name, {})
                un, new, err = st.get("unseen", 0), st.get("new", False), st.get("error", False)
                left = ("▾ " if active else "▸ ") + name
                tag = ""
                if un:
                    tag += f" ({un})"
                if new:
                    tag += " ✚"
                if err:
                    tag += " ⚠"
                line = self._pad_row(left, tag, fw)
                if sel_attr:
                    attr = curses.A_REVERSE | curses.A_BOLD
                elif active or un:
                    attr = self._cp(C_TITLE) | curses.A_BOLD
                else:
                    attr = self._cp(C_DIM)
            else:  # active-account folder
                msg, un = self.folder_counts.get(name, (0, 0))
                label = name.replace("INBOX.", "") or "INBOX"
                is_current = (name == self.folder)
                left = ("   ▸ " if is_current else "     ") + label
                line = self._pad_row(left, f"({un})" if un else "", fw)
                if sel_attr:
                    attr = curses.A_REVERSE | curses.A_BOLD
                elif is_current or un:
                    attr = self._cp(C_TITLE) | curses.A_BOLD
                else:
                    attr = self._cp(C_DIM)
            self._put(body_top + 1 + i, 0, line, attr)

        for y in range(body_top, body_bot + 1):
            self._put(y, fw, "│", self._cp(C_DIM))

        # Mail pane
        mx, mw = fw + 2, max(0, w - (fw + 2))
        self.list.set_height(max(1, pane_h - 1))
        total, unread = self._cur_counts          # local cache counts
        fshort = self.folder.replace("INBOX.", "") or "INBOX"
        mtitle = _("{folder} · {total} msg · {unread} unread",
                   folder=fshort, total=total, unread=unread)
        if self.folder == "INBOX":
            with self._poll_lock:
                nc = self.new_count
            if nc:
                mtitle += f" · ✚{nc}"
        if self.search_query:
            mtitle += f"  /{self.search_query}"
        if self.only_unseen:
            mtitle += "  " + _("[unread]")
        self._put(body_top, mx, mtitle[:mw],
                  self._cp(C_TITLE) | curses.A_BOLD | (curses.A_REVERSE if self.focus == "mails" else 0))
        if not self.summaries:
            self._put(body_top + 1, mx, _("(empty)")[:mw], self._cp(C_DIM))
        for i, (idx, s) in enumerate(self.list.visible()):
            dot = "●" if not s.seen else " "
            lk = "🔒" if s.encrypted else "  "   # lock if encrypted (PGP/MIME)
            # date + time (date_fmt = "YYYY-MM-DD HH:MM"); fixed width for alignment
            line = f"{dot}{lk} {s.date_fmt[:16]:<16} {s.from_display[:16]:<16} {s.subject or _('(no subject)')}"
            is_sel = (idx == self.list.cursor)
            if is_sel and self.focus == "mails":
                attr = curses.A_REVERSE | curses.A_BOLD
            elif is_sel:
                attr = self._cp(C_TITLE) | curses.A_BOLD
            else:
                # encrypted → GREEN; otherwise unread → bold white, read → dim green.
                base = (self._cp(C_ACCENT) if s.encrypted
                        else self._cp(C_TITLE) if not s.seen else self._cp(C_DIM))
                attr = base | (curses.A_BOLD if not s.seen else 0)
            self._put(body_top + 1 + i, mx, line[:mw], attr)

        if self.status:
            self._put(h - 2, 0, (" " + self.status)[:w - 1], self._cp(C_WARN))
        self._draw_bar(h, w)
        self.stdscr.refresh()

    def _draw_bar(self, h, w):
        widths = [len(f" {lbl} ") for lbl, _v in self.BAR]
        start = 0
        if self.focus == "bar":
            start = min(getattr(self, "_bar_start", 0), self.bar_idx)
            for _i in range(len(self.BAR)):
                cx, last = 1, start
                for i in range(start, len(self.BAR)):
                    if cx + widths[i] > w - 2:
                        break
                    last, cx = i, cx + widths[i]
                if start <= self.bar_idx <= last:
                    break
                start += 1
            self._bar_start = start
        cx = 1
        if start > 0:
            self._put(h - 1, 0, "‹", self._cp(C_DIM))
        for i in range(start, len(self.BAR)):
            cell = f" {self.BAR[i][0]} "
            focused = (self.focus == "bar" and i == self.bar_idx)
            if cx + len(cell) > w - 2:
                # The focused button must stay visible even truncated (narrow terminal).
                if focused:
                    avail = max(0, w - 2 - cx)
                    if avail:
                        self._put(h - 1, cx, cell[:avail], curses.A_REVERSE | curses.A_BOLD)
                self._put(h - 1, max(cx, w - 2), "›", self._cp(C_DIM))
                break
            attr = (curses.A_REVERSE | curses.A_BOLD) if focused else self._cp(C_DIM)
            self._put(h - 1, cx, cell, attr)
            cx += len(cell)

    # ── Dropdown menu (toggle) ────────────────────────────────────────────
    def _open_menu(self):
        """Full dropdown menu (toggle). Returns the chosen action key or None."""
        path, idx = "main", 0
        curses.curs_set(0)
        while True:
            items = self.MENU_MAIN if path == "main" else self.MENU_CONFIG
            idx = max(0, min(idx, len(items) - 1))
            self._draw_menu(items, idx, path)
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if is_esc(k) or k == "m":
                if path == "config":
                    path, idx = "main", 0
                    continue
                return None
            elif k in (curses.KEY_UP, "k"):
                idx = (idx - 1) % len(items)
            elif k in (curses.KEY_DOWN, "j"):
                idx = (idx + 1) % len(items)
            elif k == curses.KEY_LEFT:
                if path == "config":
                    path, idx = "main", 0
            elif is_enter(k) or k == curses.KEY_RIGHT:
                val = items[idx][1]
                if val == "__config__":
                    path, idx = "config", 0
                elif val == "__back__":
                    path, idx = "main", 0
                else:
                    return val

    def _draw_menu(self, items, idx, path):
        self.draw_main()  # background (panes + bar)
        h, w = self.stdscr.getmaxyx()
        title = _("Configuration") if path == "config" else _("Menu")
        bw = min(max(len(title) + 4, max(len(lbl) for lbl, _v in items) + 4), max(8, w - 2))
        # Scrolling window: shows only what fits (reserves margin + help footer).
        nvis = max(1, min(len(items), h - 3))
        mtop = max(0, min(getattr(self, "_menu_top", 0), len(items) - nvis))
        if idx < mtop:
            mtop = idx
        elif idx >= mtop + nvis:
            mtop = idx - nvis + 1
        self._menu_top = mtop
        bh = nvis + 2
        by = max(0, h - 2 - bh)
        bx = 1
        self._put(by, bx, "┌" + title.center(bw - 2, "─") + "┐",
                  self._cp(C_TITLE) | curses.A_BOLD)
        for j in range(nvis):
            i = mtop + j
            lbl = items[i][0]
            if j == 0 and mtop > 0:
                lbl = "▲ " + lbl
            elif j == nvis - 1 and mtop + nvis < len(items):
                lbl = "▼ " + lbl
            attr = (curses.A_REVERSE | curses.A_BOLD) if i == idx else self._cp(C_TITLE)
            self._put(by + 1 + j, bx, "│", self._cp(C_TITLE))
            self._put(by + 1 + j, bx + 1, (" " + lbl).ljust(bw - 2)[:bw - 2], attr)
            self._put(by + 1 + j, bx + bw - 1, "│", self._cp(C_TITLE))
        self._put(by + bh - 1, bx, "└" + "─" * (bw - 2) + "┘", self._cp(C_TITLE))
        self._put(h - 1, 0, _(" ↑↓ choose · ↵ confirm · → / ← sub-menu · Esc/m close")[:w - 1],
                  self._cp(C_DIM) | curses.A_REVERSE)
        self.stdscr.refresh()

    # ── Reading a mail ────────────────────────────────────────────────────
    def reader_loop(self, summary):
        # Opening a mail marks it read: we select for writing if needed and set
        # \Seen (fetch_message stays BODY.PEEK, so this explicit store is what
        # counts). Immediate local update (list + folder counter) → no need for a
        # full network refresh.
        mark_seen = not summary.seen
        acc = self.acc.name
        raw = self.store.get_raw(acc, self.folder, summary.uid)
        marked = False
        try:
            if raw is not None:
                # Body already cached → instant display. We mark read on the server
                # if needed (best-effort: if offline, we read it anyway).
                msg = email.message_from_bytes(raw)
                if mark_seen:
                    try:
                        with self._imap() as M:
                            fmail.imap_select(M, self.folder, readonly=False)
                            M.uid("store", summary.uid, "+FLAGS", "(\\Seen)")
                        with self._flag_lock:   # don't get overwritten by the worker
                            self.store.set_flag(acc, self.folder, summary.uid, seen=True)
                        summary.seen = True
                        self._dec_unseen(self.folder)
                        marked = True
                    except NET_ERRORS:
                        pass
            else:
                # Not cached: we fetch the message, mark it read, and cache it.
                with self._imap() as M:
                    fmail.imap_select(M, self.folder, readonly=not mark_seen)
                    msg = fmail.fetch_message(M, summary.uid)
                    if mark_seen:
                        try:
                            M.uid("store", summary.uid, "+FLAGS", "(\\Seen)")
                            with self._flag_lock:
                                self.store.set_flag(acc, self.folder, summary.uid, seen=True)
                            summary.seen = True
                            self._dec_unseen(self.folder)
                            marked = True
                        except imaplib.IMAP4.error:
                            pass   # best-effort marking: reading stays possible
                self.store.set_raw(acc, self.folder, summary.uid, msg.as_bytes())
        except NET_ERRORS as e:
            self.error(str(e))
            return False
        if marked:
            self._relist()   # immediate update of the header "N unread" counter

        # ── Autocrypt: learn the sender's key + decrypt if encrypted ──────────
        self._autocrypt_learn(msg)
        _frm_name, frm = parseaddr(fmail.decode_field(msg.get("From")))
        frm = frm.lower()
        if frm:
            self._learn_contact(frm, _frm_name)      # address book: learn the sender
        peer = autocrypt.get_peer(frm) if frm else None
        conflict = bool(peer and "conflict" in peer.keys() and peer["conflict"])
        content_msg, sec_line, encrypted = msg, None, False
        if autocrypt.is_encrypted(msg):
            encrypted = True
            inner, info = autocrypt.decrypt_message(msg)
            if inner is not None:
                content_msg = inner
                if info["signed"] and peer and peer["fpr"] and info.get("sig_fpr") == peer["fpr"]:
                    tag = _(" · sender signature verified ✔")
                elif info.get("sig_status") == "expired":
                    tag = _(" · ⚠ SIGNATURE BY AN EXPIRED KEY")
                elif info.get("sig_status") == "revoked":
                    tag = _(" · ⚠ SIGNATURE BY A REVOKED KEY")
                elif info["signed"]:
                    tag = _(" · ⚠ signed by a DIFFERENT key than the sender")
                else:
                    tag = _(" · ⚠ NOT SIGNED — sender NOT authenticated")
                sec_line = (_("Security"), _("🔒 encrypted") + tag)
            else:
                content_msg = None
                err = info.get("error")
                sec_line = (_("Security"), _("⚠ encrypted — cannot decrypt")
                            + (f" ({err})" if err else ""))
        # Remember the encrypted status (lock in list) + reflect it immediately.
        if summary.encrypted != encrypted:
            summary.encrypted = encrypted
            try:
                self.store.set_encrypted(self.acc.name, self.folder, summary.uid, encrypted)
            except Exception:
                pass

        headers = [
            (_("Subject"), fmail.decode_field(msg.get("Subject")) or _("(no subject)")),
            (_("From"), fmail.decode_field(msg.get("From"))),
            (_("To"), fmail.decode_field(msg.get("To"))),
        ]
        if msg.get("Cc"):
            headers.append((_("Cc"), fmail.decode_field(msg.get("Cc"))))
        headers.append((_("Date"), msg.get("Date", "")))
        if sec_line:
            headers.insert(0, sec_line)
        elif not encrypted:
            headers.insert(0, (_("Security"), _("🔓 message IN CLEAR (not encrypted)")))
        if conflict:
            headers.insert(0, (_("⚠ Key"), _("this contact's key has CHANGED since the last "
                               "exchange — \"v\" to verify/accept (otherwise auto-encryption suspended)")))
        if content_msg is None:
            body = _("(cannot decrypt this message — missing key?)")
            atts = []
        else:
            body = fmail.body_text(content_msg).strip()
            # content_msg: we walk() it spotting the "attachment" parts.
            atts = [part.get_filename() or _("(unnamed)")
                    for part in content_msg.walk()
                    if "attachment" in (part.get("Content-Disposition") or "").lower()]
        has_atts = bool(atts)
        if atts:
            headers.append((_("Attachments"), ", ".join(atts)))

        # Header color keyed on the RESULT of decryption, not just the structure:
        # GREEN = encrypted AND decrypted (trust), RED = encrypted but cannot decrypt
        # (never a false green signal), YELLOW = cleartext.
        dec_ok = encrypted and content_msg is not None
        hcp = (self._cp(C_ACCENT) if dec_ok
               else self._cp(C_ERR) if encrypted
               else self._cp(C_WARN)) | curses.A_BOLD
        top = 0
        cached_w, lines = None, []
        curses.curs_set(0)
        while True:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            if w != cached_w:   # only re-wrap if the width changes (not on every scroll)
                lines = self._wrap_message(headers, body, w - 1, header_attr=hcp)
                cached_w = w
            self._bar(0, _(" Reading · {folder}", folder=self.folder),
                      self._cp(C_TITLE) | curses.A_BOLD | curses.A_REVERSE)
            view_h = h - 2
            top = max(0, min(top, max(0, len(lines) - view_h)))
            for i, segs in enumerate(lines[top:top + view_h]):
                x = 0
                for text, attr in segs:
                    self._put(1 + i, x, text, attr)
                    x += _disp_width(text)
            foot = (_(" ↑↓ scroll  r reply  f forward")
                    + (_("  s save-att") if has_atts else "")
                    + _("  a archive  d trash")
                    + (_("  v verify-key") if conflict else "") + _("  Esc back"))
            self._bar(h - 1, foot, self._cp(C_DIM) | curses.A_REVERSE)
            self.stdscr.refresh()

            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if is_esc(k) or k in ("q", "Q"):
                return False
            elif k in (curses.KEY_DOWN, "j"):
                top += 1
            elif k in (curses.KEY_UP, "k"):
                top = max(0, top - 1)
            elif k == curses.KEY_NPAGE:
                top += (h - 3)
            elif k == curses.KEY_PPAGE:
                top = max(0, top - (h - 3))
            elif k in ("v", "V") and conflict:
                self._verify_key_change(frm)
                conflict = autocrypt.peer_conflict(frm)
                if not conflict:           # accepted → remove the alert and re-wrap
                    headers = [hh for hh in headers if hh[0] != _("⚠ Key")]
                    cached_w = None
            elif k in ("s", "S") and has_atts:
                self._save_attachments(content_msg)
                cached_w = None    # clean repaint after the modal windows
            elif k in ("r", "R", "f"):
                self._reply_or_forward(
                    summary.uid, kind=k, original=msg,
                    body_source=(content_msg if encrypted and content_msg is not None else None),
                    encrypted=encrypted)
            elif k == "a":
                if self._action_move(summary.uid, self._special("archive"), _("Archive")):
                    return True
            elif k in ("d", curses.KEY_DC):
                if self._action_move(summary.uid, self._special("trash"), _("Move to trash")):
                    return True

    def _wrap_message(self, headers, body, width, header_attr=None):
        """Returns visual lines; each line = list of segments (text, attr).
        `header_attr` colors the header block (green=encrypted, yellow=cleartext)."""
        width = max(1, width)
        hattr = header_attr if header_attr is not None else self._cp(C_FROM)
        out = [[(f"{label:<14}: {val}"[:width], hattr)] for label, val in headers]
        out.append([("─" * width, hattr)])
        out.extend(self._render_body(body, width))
        return out

    def _md_spans(self, text, base):
        """Splits a line into segments (text, attr) according to inline Markdown."""
        italic = getattr(curses, "A_ITALIC", curses.A_UNDERLINE)
        pat = re.compile(
            r"(`[^`]+`)"
            r"|(\*\*[^*]+\*\*)"
            r"|(__[^_]+__)"
            r"|(?<![\w*])(\*[^*\s][^*]*\*)(?![\w*])"
            r"|(?<![\w_])(_[^_\s][^_]*_)(?![\w_])"
            r"|(\[[^\]]+\]\(https?://[^\s)]+\))")
        spans, pos = [], 0
        for m in pat.finditer(text):
            if m.start() > pos:
                spans.append((text[pos:m.start()], base))
            tok = m.group(0)
            if tok.startswith("`"):
                spans.append((tok[1:-1], base | self._cp(C_FROM)))
            elif tok.startswith("**") or tok.startswith("__"):
                spans.append((tok[2:-2], base | curses.A_BOLD))
            elif tok.startswith("*") or tok.startswith("_"):
                spans.append((tok[1:-1], base | italic))
            else:
                mm = re.match(r"\[([^\]]+)\]\((https?://[^\s)]+)\)", tok)
                spans.append((mm.group(1), base | curses.A_UNDERLINE | self._cp(C_FROM)))
            pos = m.end()
        if pos < len(text):
            spans.append((text[pos:], base))
        return spans or [("", base)]

    def _render_body(self, body, width):
        """Body → styled visual lines (headings, lists, quotes, bold/italic…)."""
        width = max(1, width)
        out = []
        for raw in body.split("\n"):
            line = raw.rstrip("\r")
            if not line.strip():
                out.append([("", 0)])
                continue
            base, prefix = 0, ""
            mh = re.match(r"^(#{1,6})\s+(.*)", line)
            if mh:
                base = curses.A_BOLD | self._cp(C_TITLE)
                line = mh.group(2)
            elif re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", line):
                out.append([("─" * width, self._cp(C_DIM))])
                continue
            elif re.match(r"^\s*[-*+]\s+\S", line):
                prefix = "• "
                line = re.sub(r"^\s*[-*+]\s+", "", line)
            elif re.match(r"^\s*\d+\.\s+\S", line):
                m = re.match(r"^\s*(\d+)\.\s+", line)
                prefix = m.group(1) + ". "
                line = line[m.end():]
            elif line.lstrip().startswith(">"):
                base = self._cp(C_DIM)
                prefix = "│ "
                line = line.lstrip()[1:].lstrip()
            spans = self._md_spans(line, base)
            if prefix:
                spans = [(prefix, base)] + spans
            out.extend(self._wrap_spans(spans, width))
        return out

    def _wrap_spans(self, spans, width):
        """Breaks a list of segments (text, attr) into visual lines ≤ width (by word)."""
        width = max(1, width)   # guard: avoids an infinite loop if width ≤ 0
        lines, cur, cur_len = [], [], 0
        for text, attr in spans:
            for tok in re.findall(r"\S+|\s+", text):
                tlen = _disp_width(tok)
                if tok.isspace():
                    if cur_len + tlen <= width:
                        cur.append((tok, attr)); cur_len += tlen
                    else:
                        lines.append(cur); cur, cur_len = [], 0
                    continue
                if cur_len + tlen <= width:
                    cur.append((tok, attr)); cur_len += tlen
                else:
                    if cur:
                        lines.append(cur); cur, cur_len = [], 0
                    while _disp_width(tok) > width:
                        lines.append([(tok[:width], attr)]); tok = tok[width:]
                    if tok:
                        cur = [(tok, attr)]; cur_len = _disp_width(tok)
        if cur:
            lines.append(cur)
        return lines or [[("", 0)]]

    # ── Composition ──────────────────────────────────────────────────────
    # ── Received attachments: extraction / saving ────────────────────────────
    @staticmethod
    def _attachment_parts(msg):
        """List of (name, part) of `msg`'s attachments (None → [])."""
        if msg is None:
            return []
        return [(p.get_filename() or "attachment", p) for p in msg.walk()
                if "attachment" in (p.get("Content-Disposition") or "").lower()]

    @staticmethod
    def _safe_filename(name):
        """Safe filename: basename (anti path-traversal) + no ctrl chars."""
        name = os.path.basename(name or "").replace("\x00", "").strip()
        # strip C0/C1 ctrl AND all invisible formatting characters (Cf: bidi
        # override RLO/LRO, isolates, zero-width) that would hide the extension.
        name = "".join(ch for ch in name
                       if ord(ch) >= 0x20 and unicodedata.category(ch) != "Cf")
        return name or "attachment"

    @staticmethod
    def _unique_path(destdir, fname):
        p = Path(destdir) / fname
        if not p.exists():
            return p
        stem, ext = os.path.splitext(fname)
        i = 1
        while (Path(destdir) / f"{stem} ({i}){ext}").exists():
            i += 1
        return Path(destdir) / f"{stem} ({i}){ext}"

    def _write_attachment(self, destdir, fname, data):
        """Writes an attachment safely: sanitized name (basename, anti path-traversal),
        unique path, EXCLUSIVE creation at 0600 — never an overwrite, never readable by
        other users. Returns the written Path. OSError otherwise."""
        p = self._unique_path(destdir, self._safe_filename(fname))
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data or b"")
        return Path(p)

    def _save_attachments(self, content_msg):
        parts = self._attachment_parts(content_msg)
        if not parts:
            self.error(_("no attachment in this message."))
            return
        if len(parts) == 1:
            chosen = parts
        else:
            opts = [(fn, i) for i, (fn, _p) in enumerate(parts)] + [(_("→ Save all"), -1)]
            sel = self.picker(_("Which attachment to save?"), opts)
            if sel is None:
                return
            chosen = parts if sel == -1 else [parts[sel]]
        default = (str(Path.home() / "Downloads") if (Path.home() / "Downloads").is_dir()
                   else str(Path.home()))
        dest = self._line_input(_("Destination folder"), initial=default)
        if dest is None:
            return
        destdir = Path(os.path.expanduser(dest.strip() or default))
        if not destdir.is_dir():
            self.error(_("folder not found: {dir}", dir=destdir))
            return
        saved = 0
        for fn, part in chosen:
            try:
                self._write_attachment(destdir, fn, part.get_payload(decode=True))
                saved += 1
            except OSError as e:
                self.error(_("failed to save {fn}: {e}", fn=fn, e=e))
        if saved:
            self.status = _("✓ {n} attachment(s) saved in {dir}", n=saved, dir=destdir)

    def _reply_or_forward(self, uid, kind, original=None, body_source=None, encrypted=False):
        try:
            if original is None:
                with self._imap() as M:
                    fmail.imap_select(M, self.folder, readonly=True)
                    original = fmail.fetch_message(M, uid)
        except NET_ERRORS as e:
            self.error(str(e))
            return

        # Reply to / forward an ENCRYPTED mail: we quote the DECRYPTED content
        # (body_source) and pre-arm encryption (fail-closed: if a key is missing, the
        # send is blocked rather than leaking an encrypted exchange's content in clear).
        enc = True if encrypted else None
        tmpdir = None
        if kind == "f":
            cs = self._compose_forward(original, body_source=body_source, encrypt=enc)
            # Offer to re-attach the forwarded mail's attachments (Y/n choice).
            parts = self._attachment_parts(body_source if body_source is not None else original)
            if parts and self.confirm(_("Include the {n} attachment(s) in the forward?", n=len(parts))):
                tmpdir = tempfile.mkdtemp(prefix="fmail-fwd-")
                for fn, part in parts:
                    try:
                        p = self._write_attachment(tmpdir, fn, part.get_payload(decode=True))
                        cs.attachments.append(str(p))
                    except OSError:
                        pass
        else:
            cs = self._compose_reply(original, reply_all=(kind == "R"),
                                     body_source=body_source, encrypt=enc)
        try:
            self.compose_loop(cs)
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)

    def _sig_block_for(self, acc):
        """Signature block of a given account (standard "-- " separator)."""
        sig = acc.get_signature()
        return f"\n\n-- \n{sig}\n" if sig else ""

    def _sig_block(self):
        """Signature block pre-filled in the body (active account)."""
        return self._sig_block_for(self.acc)

    def _edit_signature(self):
        new = self._text_editor_modal(
            _("Signature — {name}", name=self.acc.name), self.acc.get_signature(),
            _("^G save · Esc cancel   (the \"-- \" separator is added automatically)"))
        if new is not None:
            try:
                self.acc.save_signature(new)
                self.status = _("✓ signature saved")
            except OSError as e:
                self.error(_("cannot write: {e}", e=e))

    def _text_editor_modal(self, title, initial, hint):
        """Full-screen multi-line editor. Returns the text (^G) or None (Esc)."""
        ed = TextEditor(initial)
        while True:
            curses.curs_set(1)
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self._bar(0, f" {title}", self._cp(C_TITLE) | curses.A_BOLD | curses.A_REVERSE)
            view_h = max(1, h - 2)
            btop = max(0, ed.row - view_h + 1) if ed.row >= view_h else 0
            for i, ln in enumerate(ed.lines[btop:btop + view_h]):
                self._put(1 + i, 0, ln[:w - 1], 0)
            self._bar(h - 1, " " + hint, self._cp(C_DIM) | curses.A_REVERSE)
            self._safe_move(1 + (ed.row - btop), ed.col)
            self.stdscr.refresh()
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if k == "\x07":
                curses.curs_set(0); return ed.text()
            elif is_esc(k):
                curses.curs_set(0); return None
            elif is_enter(k):
                ed.newline()
            elif is_back(k):
                ed.backspace()
            elif k == curses.KEY_DC:
                ed.delete()
            elif k == curses.KEY_LEFT:
                ed.left()
            elif k == curses.KEY_RIGHT:
                ed.right()
            elif k == curses.KEY_UP:
                ed.up()
            elif k == curses.KEY_DOWN:
                ed.down()
            elif k == curses.KEY_HOME:
                ed.home()
            elif k == curses.KEY_END:
                ed.end()
            elif is_printable(k):
                ed.insert(k)

    def _compose_reply(self, original, reply_all, body_source=None, encrypt=None):
        reply_to = fmail.decode_field(original.get("Reply-To")) or fmail.decode_field(original.get("From"))
        to = fmail._clean_addr_list(reply_to)
        cc = []
        if reply_all:
            seen = {parseaddr(x)[1].lower() for x in to} | {self.acc.email.lower()}
            others = fmail.decode_field(original.get("To")) + ", " + fmail.decode_field(original.get("Cc"))
            for a in fmail._clean_addr_list(others):
                ad = parseaddr(a)[1].lower()
                if ad and ad not in seen:
                    seen.add(ad)
                    cc.append(a)
        subject = fmail.ensure_re_prefix(fmail.decode_field(original.get("Subject")) or "")
        cs = ComposeState(
            to=", ".join(to), cc=", ".join(cc), subject=subject,
            body=fmail._quote_body(original, body_source) + self._sig_block(),
            in_reply_to=original.get("Message-ID", ""),
            references=original.get("References", ""),
            # plain text by default: the quoted body (HTML rendered to Markdown by
            # html_to_text) must NOT be auto-detected as Markdown and sent back as
            # reconstructed HTML. The user can switch back to Markdown via ^T.
            fmt="plain",
            encrypt=encrypt,
        )
        # On reply, the recipient/subject are already filled: cursor straight into the
        # BODY (at the top, above the quote). (On forward/compose, we stay on "To"
        # since the recipient must be entered.)
        cs.field = len(cs.singleline)   # body index
        return cs

    def _compose_forward(self, original, body_source=None, encrypt=None):
        subject = fmail.ensure_fwd_prefix(fmail.decode_field(original.get("Subject")) or "")
        sep = _("\n\n---------- Forwarded message ----------\n")
        hdrs = "\n".join(f"{k}: {fmail.decode_field(original.get(k))}"
                         for k in ("From", "Date", "Subject", "To") if original.get(k))
        src = body_source if body_source is not None else original
        body = sep + hdrs + "\n\n" + fmail.body_text(src).strip() + "\n"
        # plain text by default (forwarded body in Markdown via html_to_text → don't
        # send it back as reconstructed HTML). ^T to switch back to Markdown.
        return ComposeState(subject=subject, body=body + self._sig_block(), fmt="plain",
                            encrypt=encrypt)

    def _draw_compose(self, cs):
        LABELS = [_("To    "), _("Cc    "), _("Bcc   "), _("Subj  ")]
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        if cs.fmt == "plain":
            flabel = _("plain text")
        elif cs.fmt == "markdown":
            flabel = _("Markdown→HTML")
        else:
            flabel = _("auto: ") + (_("Markdown") if self._md(cs) else _("text"))
        rcpts = self._compose_recipients(cs)
        rec = autocrypt.recommendation(rcpts) if rcpts else "disable"
        conflict = any(autocrypt.peer_conflict(r) for r in rcpts)
        encrypting = self._encrypt_decision(cs, rec)
        if encrypting:
            lock = _("🔒 encrypted")
        elif conflict:
            # The conflict wins: NEVER let it seem like ^E will encrypt (it's blocked).
            lock = _("🔓 a contact's key CHANGED — \"v\" to verify")
        elif cs.encrypt is True:
            lock = _("🔓 cannot encrypt (missing key)")
        elif rec in ("available", "encrypt"):
            lock = _("🔓 cleartext · encryptable (^E)")
        elif rcpts:
            lock = _("🔓 not encrypted · recipient key missing (^A help)")
        else:
            lock = _("🔓 cleartext")

        # GREEN FRAME when the message will go out ENCRYPTED. Short title at the top
        # (saves space), full tech detail at the BOTTOM of the composer (green bar).
        framed = encrypting
        gcp = self._cp(C_ACCENT) | curses.A_BOLD
        if framed:
            self._bar(0, _(" 🔒 ENCRYPTED MESSAGE   (^G send · ^E encryption · ^A help · Esc quit)"),
                      self._cp(C_ACCENT) | curses.A_BOLD | curses.A_REVERSE)
        else:
            self._bar(0, _(" New message  [{flabel}] [{lock}]  (^G send · ^E encrypt · ^F From · ^O attach · ^X att · ^T format · ^A help · Esc quit)",
                           flabel=flabel, lock=lock),
                      self._cp(C_TITLE) | curses.A_BOLD | curses.A_REVERSE)

        cx = 2 if framed else 0            # horizontal inset of content (after "│")
        base = 1                           # content starts at row 1 (short title → no banner)
        cw = max(1, (w - 2 - cx) if framed else (w - 1))   # usable width (leaves the right edge)
        if framed:
            for r in range(1, h - 1):      # green side borders
                self._put(r, 0, "│", gcp)
                self._put(r, w - 1, "│", gcp)
            # BOTTOM of the composer: full tech detail (full-width green bar).
            self._bar(h - 1, _(" 🔒 ENCRYPTED MESSAGE — OpenPGP/MIME (RFC 3156) · AES-256 · signed "
                               "Ed25519  ·  for {n} recipient(s) + you", n=len(rcpts)),
                      self._cp(C_ACCENT) | curses.A_BOLD | curses.A_REVERSE)

        # "From" line: sending account, editable with ^F.
        facc = self._compose_account(cs)
        self._put(base, cx, _("  From  : {name} <{email}>  (^F)",
                              name=facc.display_name, email=facc.email)[:cw], self._cp(C_DIM))
        n = len(cs.singleline)
        for i, ed in enumerate(cs.singleline):
            marker = "▸" if cs.field == i else " "
            self._put(base + 1 + i, cx, f"{marker} {LABELS[i]}: {ed.text}"[:cw],
                      curses.A_BOLD if cs.field == i else 0)
        att = ", ".join(cs.attachments) if cs.attachments else _("(none)")
        self._put(base + 1 + n, cx, _("  Att   : {att}", att=att)[:cw], self._cp(C_DIM))
        sep_row = base + 2 + n
        if framed:
            self._put(sep_row, cx, "─" * cw, gcp)
        else:
            self._bar(sep_row, "─" * w, self._cp(C_DIM))
        body_top = base + 3 + n
        view_h = max(1, h - body_top - 1)
        maxw = max(1, cw)
        # Visual wrap: each logical body line is split at the usable width (nothing
        # leaves the screen/frame anymore). We keep track of the 1st visual line of
        # each logical line to position the cursor.
        vis, line_vstart = [], []
        for line in cs.body.lines:
            line_vstart.append(len(vis))
            offs = _wrap_offsets(line, maxw)
            for k, s in enumerate(offs):
                e = offs[k + 1] if k + 1 < len(offs) else len(line)
                vis.append(line[s:e])
        cur_line = cs.body.lines[cs.body.row]
        coffs = _wrap_offsets(cur_line, maxw)
        seg = 0
        for k, s in enumerate(coffs):
            if s <= cs.body.col:
                seg = k
            else:
                break
        cur_vrow = line_vstart[cs.body.row] + seg
        cur_vcol = _dw(cur_line[coffs[seg]:cs.body.col])
        vtop = max(0, cur_vrow - view_h + 1)
        for i, seg_text in enumerate(vis[vtop:vtop + view_h]):
            self._put(body_top + i, cx, seg_text, 0)
        self.stdscr.refresh()
        curses.curs_set(1)
        if cs.field < n:
            ed = cs.singleline[cs.field]
            self._safe_move(base + 1 + cs.field, cx + 10 + ed.cursor)  # « ▸ <LABEL 6>: » = 10 col
        else:
            self._safe_move(body_top + (cur_vrow - vtop), cx + cur_vcol)

    def _popup_choice(self, title, options, draw_bg):
        """Small floating choice window, on top of the current screen (the background
        — e.g. the mail — stays visible around it). Returns the chosen value or None."""
        idx, n = 0, len(options)
        while True:
            draw_bg()
            curses.curs_set(0)
            h, w = self.stdscr.getmaxyx()
            bw = min(max(len(title) + 4, max(len(l) for l, _v in options) + 6), max(12, w - 2))
            bh = n + 2
            by = max(0, h - bh - 1)
            bx = max(0, (w - bw) // 2)
            self._put(by, bx, "┌" + title.center(bw - 2, "─") + "┐", self._cp(C_WARN) | curses.A_BOLD)
            for i, (lbl, _v) in enumerate(options):
                sel = (i == idx)
                attr = (curses.A_REVERSE | curses.A_BOLD) if sel else self._cp(C_TITLE)
                self._put(by + 1 + i, bx, "│", self._cp(C_WARN))
                self._put(by + 1 + i, bx + 1, ((" ▸ " if sel else "   ") + lbl).ljust(bw - 2)[:bw - 2], attr)
                self._put(by + 1 + i, bx + bw - 1, "│", self._cp(C_WARN))
            self._put(by + bh - 1, bx, "└" + "─" * (bw - 2) + "┘", self._cp(C_WARN))
            self.stdscr.refresh()
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if is_esc(k):
                return None
            elif k in (curses.KEY_UP, "k"):
                idx = (idx - 1) % n
            elif k in (curses.KEY_DOWN, "j"):
                idx = (idx + 1) % n
            elif is_enter(k):
                return options[idx][1]

    def compose_loop(self, cs):
        while True:
            self._draw_compose(cs)
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if k == "\x07":  # Ctrl-G: send
                if self._compose_send(cs):   # _compose_send already sets the status
                    curses.curs_set(0)
                    return
            elif k == "\x0f":  # Ctrl-O: file browser to attach
                path = self._file_browser()
                if path:
                    cs.attachments.append(path)
                    self._browse_dir = str(Path(path).parent)  # remember the folder
            elif k == "\x18":  # Ctrl-X: remove the last attachment
                if cs.attachments:
                    cs.attachments.pop()
            elif k == "\x14":  # Ctrl-T: cycle auto-detect → plain text → Markdown
                cs.fmt = {"auto": "plain", "plain": "markdown", "markdown": "auto"}[cs.fmt]
                self.status = _("format: ") + {"auto": _("auto-detect"), "plain": _("plain text"),
                                               "markdown": _("Markdown→HTML")}[cs.fmt]
            elif k == "\x06":  # Ctrl-F: choose the sending account (From)
                self._pick_from_account(cs)
            elif k == "\x05":  # Ctrl-E: cycle encryption auto → forced → disabled
                cs.encrypt = {None: True, True: False, False: None}[cs.encrypt]
                self.status = _("encryption: ") + {None: _("auto"), True: _("forced"), False: _("disabled")}[cs.encrypt]
            elif k == "\x01":   # Ctrl-A: "exchange encrypted mail" help
                self._crypto_help()
            elif is_esc(k):
                choice = self._popup_choice(_("Leave the editor"), [
                    (_("Back to the mail"), "back"),
                    (_("Save the draft"), "save"),
                    (_("Discard the message"), "discard"),
                ], lambda: self._draw_compose(cs))
                if choice == "save":
                    if self._save_draft(cs):
                        curses.curs_set(0)
                        return
                elif choice == "discard":
                    curses.curs_set(0)
                    return
                # "back" or Esc → stay in the editor
            elif k == "\t" or (k == curses.KEY_DOWN and cs.field < len(cs.singleline)):
                cs.field = (cs.field + 1) % (len(cs.singleline) + 1)
            elif k == curses.KEY_BTAB or (k == curses.KEY_UP and 0 < cs.field < len(cs.singleline)):
                cs.field = (cs.field - 1) % (len(cs.singleline) + 1)
            else:
                self._compose_edit_key(cs, k)

    def _compose_edit_key(self, cs, k):
        if cs.field < len(cs.singleline):
            ed = cs.singleline[cs.field]
            if is_enter(k):
                cs.field += 1
            elif is_back(k):
                ed.backspace()
            elif k == curses.KEY_DC:
                ed.delete()
            elif k == curses.KEY_LEFT:
                ed.left()
            elif k == curses.KEY_RIGHT:
                ed.right()
            elif k == curses.KEY_HOME:
                ed.home()
            elif k == curses.KEY_END:
                ed.end()
            elif is_printable(k):
                ed.insert(k)
        else:
            body = cs.body
            if is_enter(k):
                body.newline()
            elif is_back(k):
                body.backspace()
            elif k == curses.KEY_DC:
                body.delete()
            elif k == curses.KEY_LEFT:
                body.left()
            elif k == curses.KEY_RIGHT:
                body.right()
            elif k == curses.KEY_UP:
                body.up()
            elif k == curses.KEY_DOWN:
                body.down()
            elif k == curses.KEY_HOME:
                body.home()
            elif k == curses.KEY_END:
                body.end()
            elif is_printable(k):
                body.insert(k)

    def _md(self, cs):
        """Effective Markdown: 'markdown'→yes, 'plain'→no, 'auto'→detect on the body."""
        if cs.fmt == "markdown":
            return True
        if cs.fmt == "plain":
            return False
        return fmail.looks_like_markdown(cs.body.text())

    def _compose_account(self, cs):
        """Effective sending account: the one chosen in the composer (cs.account), else
        the active account. Robust if the key no longer exists (deleted account)."""
        return self.accounts.get(cs.account) or self.acc

    # ── Autocrypt (learning + encryption decision) ───────────────────────────
    def _autocrypt_learn(self, msg):
        """Learns the sender's public key from the Autocrypt header (passive, on read).
        Never breaks reading on error."""
        try:
            frm = parseaddr(fmail.decode_field(msg.get("From")))[1].lower()
            if not frm:
                return
            hdrs = msg.get_all("Autocrypt") or []
            # Spec L1: multiple Autocrypt headers → treat as if there were none (a
            # relay/MITM cannot prepend a second one to impose its key).
            parsed = autocrypt.parse_header(hdrs[0]) if len(hdrs) == 1 else None
            # Security: the header's addr must match From, otherwise we ignore it.
            if parsed and parsed["addr"] != frm:
                parsed = None
            # Mail dated in the future → not probative: we do NOT change the key on its
            # word (anti-supplant/freeze). We still record last_seen (capped epoch).
            if parsed and _date_in_future(msg):
                parsed = None
            autocrypt.update_peer(frm, _msg_date_epoch(msg), parsed)
        except Exception:
            pass

    def _compose_recipients(self, cs):
        """Bare addresses of all recipients (To + Cc + Bcc) of the draft."""
        raw = [cs.to.text, cs.cc.text, cs.bcc.text]
        return [a.lower() for _n, a in getaddresses([t for t in raw if t.strip()]) if a]

    def _encrypt_decision(self, cs, rec):
        """True if the message should go out encrypted, per the toggle (cs.encrypt) and
        the Autocrypt recommendation (`rec` = disable/available/encrypt)."""
        if cs.encrypt is True:
            return rec != "disable"      # forced (impossible if a key is missing)
        if cs.encrypt is False:
            return False                 # explicitly disabled
        return rec == "encrypt"          # auto: encrypt if recommended

    def _pick_from_account(self, cs):
        """"From" picker (^F): choose which account the message goes out from. Updates
        the footer signature if it has not been modified."""
        if len(self.accounts) < 2:
            self.status = _("only one account configured.")
            return
        prev = self._compose_account(cs)
        cur = cs.account or self.acc.name
        opts = [(f"{a.display_name} <{a.email}>" + ("  ✓" if n == cur else ""), n)
                for n, a in self.accounts.items()]
        choice = self._popup_choice(_("Send from"), opts, lambda: self._draw_compose(cs))
        if not choice or choice == cur:
            return
        new = self.accounts[choice]
        self._change_from(cs, prev, new)
        self.status = _("From: ") + new.email

    def _change_from(self, cs, prev, new):
        """Switches the sending account of cs to `new`. Replaces the footer signature
        with `new`'s ONLY if it is intact (never overwrites an edited signature). Pure
        (no curses) → testable."""
        cs.account = new.name
        old_block = self._sig_block_for(prev)
        text = cs.body.text()
        if old_block and text.endswith(old_block):
            cs.body = TextEditor(text[: -len(old_block)] + self._sig_block_for(new))

    def _compose_send(self, cs):
        acc = self._compose_account(cs)
        # Ensures our Autocrypt key (generated on first send). Best-effort: if gpg
        # fails, we don't prevent a cleartext send.
        ac_ok = True
        try:
            autocrypt.ensure_key(acc.email, getattr(acc, "display_name", "") or "")
        except Exception:
            ac_ok = False
        do_encrypt = False
        try:
            to = fmail._clean_addr_list(cs.to.text)
            if not to:
                raise FmailError(_("missing recipient."))
            cc = fmail._clean_addr_list(cs.cc.text) if cs.cc.text.strip() else None
            bcc = fmail._clean_addr_list(cs.bcc.text) if cs.bcc.text.strip() else None
            # recommendation only reads the SQLite store: reliable even if gpg is broken.
            rcpts = self._compose_recipients(cs)
            conflicted = [em for em in rcpts if autocrypt.peer_conflict(em)]
            rec = autocrypt.recommendation(rcpts)
            want_encrypt = self._encrypt_decision(cs, rec)
            # Pinning: if the user FORCES encryption (^E) toward a contact whose key
            # has changed without being verified, we block with a clear message (never
            # toward a candidate key). Encryption stays suspended until verification.
            if cs.encrypt is True and conflicted:
                self.error(_("key changed for {who} — verify it in the reader (\"v\" key) before encrypting.",
                             who=", ".join(conflicted)))
                return False
            if want_encrypt and not ac_ok:
                # Encryption expected but gpg unavailable → NEVER a silent cleartext
                # send (fail-closed also in AUTO mode, not only in forced).
                self.error(_("encryption expected but gpg unavailable — send blocked (retry, or ^E to disable)."))
                return False
            do_encrypt = want_encrypt
            if cs.encrypt is True and not do_encrypt:
                self.error(_("cannot encrypt: key missing for a recipient (^E to send in cleartext)."))
                return False
            if do_encrypt and bcc:
                self.error(_("Bcc not supported with encryption (v1): remove the Bcc, or ^E to send in cleartext."))
                return False
            if do_encrypt:
                try:
                    msg = autocrypt.build_encrypted(
                        acc, to, cs.subject.text, cs.body.text(), cc=cc,
                        in_reply_to=cs.in_reply_to, references=cs.references,
                        attachments=cs.attachments or None, markdown=self._md(cs),
                    )
                except autocrypt.AutocryptError as e:
                    # Never a cleartext send if the user expected encryption.
                    self.error(_("encryption failed: ") + str(e))
                    return False
            else:
                msg = fmail.build_message(
                    acc, to, cs.subject.text, cs.body.text(), cc=cc, bcc=bcc,
                    in_reply_to=cs.in_reply_to, references=cs.references,
                    attachments=cs.attachments or None, markdown=self._md(cs),
                )
                if ac_ok:   # always announce our key (even in clear) → the other learns it
                    try:
                        autocrypt.attach_autocrypt_header(msg, acc.email)
                    except Exception:
                        pass
        except NET_ERRORS as e:
            self.error(str(e))
            return False
        detail = [_("From   : ") + acc.email, _("To     : ") + ", ".join(to)]
        if cc:
            detail.append(_("Cc     : ") + ", ".join(cc))
        if bcc:
            detail.append(_("Bcc    : ") + ", ".join(bcc))
        detail.append(_("Subject: ") + (cs.subject.text or _("(no subject)")))
        detail.append(_("Encr.  : ") + (_("🔒 encrypted") if do_encrypt else _("🔓 cleartext")))
        detail.append(_("Format : ") + (_("Markdown → HTML") if self._md(cs) else _("plain text")))
        if cs.attachments:
            detail.append(_("Att    : ") + ", ".join(Path(a).name for a in cs.attachments))
        if not self._confirm_popup(_("Send this message?"), detail):
            return False
        if not self._send_with_progress(acc, msg):
            return False
        self.status = _("✓ Message sent") + (_(" from {email}.", email=acc.email) if acc is not self.acc else ".")
        for _em in self._compose_recipients(cs):     # address book: learn the recipients
            self._learn_contact(_em)
        if not self._delete_origin(cs):   # draft edited then sent
            self.status += _("  ⚠ old draft not deleted")
        return True

    def _save_draft(self, cs):
        """Saves the draft to Drafts. Lenient: To/Subject may be empty/partial."""
        def lenient(text):
            if not text.strip():
                return []
            try:
                return fmail._clean_addr_list(text)
            except FmailError:
                # incomplete address: keep the text, but WITHOUT CR/LF (otherwise
                # EmailMessage raises ValueError on the header → crash).
                return [text.replace("\r", " ").replace("\n", " ").strip()]
        try:
            folder = self._special("drafts")
            if not folder:
                self.error(_("Drafts folder not found."))
                return False
            acc = self._compose_account(cs)
            # Encryption intent (same logic as on send). If the draft is destined for
            # encryption, we NEVER store it in cleartext on the server side.
            rec = autocrypt.recommendation(self._compose_recipients(cs))
            want_encrypt = self._encrypt_decision(cs, rec)
            bcc = lenient(cs.bcc.text)
            # We do NOT materialize a real Bcc header in a stored draft (it would leak
            # the hidden recipient): we keep it in X-Fmail-Bcc, restored on re-edit.
            # The PRESENCE of a Bcc forces draft encryption (cf. condition below) → the
            # whole inner, X-Fmail-Bcc included, goes into the encrypted blob: never a
            # cleartext Bcc on the server side.
            inner = fmail.build_message(
                acc, lenient(cs.to.text), cs.subject.text, cs.body.text(),
                cc=(lenient(cs.cc.text) or None),
                in_reply_to=cs.in_reply_to, references=cs.references,
                attachments=cs.attachments or None,
            )
            inner["X-Fmail-Encrypt"] = {None: "auto", True: "force", False: "off"}[cs.encrypt]
            if bcc:
                inner["X-Fmail-Bcc"] = ", ".join(bcc)
            if cs.fmt != "auto":   # remember the chosen format for re-edit
                inner["X-Fmail-Format"] = cs.fmt
            if cs.account:         # remember the chosen sending account (restored on re-edit)
                inner["X-Fmail-Account"] = cs.account
            # Fail-closed like on send: whenever encryption is expected, FORCED (^E),
            # or the draft was ALREADY encrypted, we encrypt to SELF (independent of
            # any recipient key); never a cleartext fallback on the server.
            if want_encrypt or cs.encrypt is True or cs.was_encrypted or bcc:
                try:
                    msg = autocrypt.build_self_encrypted_draft(
                        acc, inner.as_bytes(), cs.subject.text)
                except autocrypt.AutocryptError as e:
                    self.error(_("cannot create encrypted draft: ") + str(e))
                    return False
            else:
                msg = inner
            fmail.save_draft(self.acc, msg, folder)
        except NET_ERRORS as e:
            self.error(str(e))
            return False
        replaced = self._delete_origin(cs)   # replaces the old version of the draft
        self._recount_local()
        self.status = _("✓ draft saved in ") + folder.replace("INBOX.", "")
        if not replaced:
            self.status += _("  ⚠ old draft not deleted (duplicate)")
        return True

    # ── Filing actions ────────────────────────────────────────────────────
    def _special(self, kind):
        """Resolves the Sent/Archive/Trash folder (config else IMAP flags, cached)."""
        configured = {"archive": self.acc.archive_folder, "trash": self.acc.trash_folder,
                      "sent": self.acc.sent_folder, "drafts": self.acc.drafts_folder}.get(kind, "")
        if configured:
            return configured
        if kind in self._special_cache:
            return self._special_cache[kind]
        try:
            with self._imap() as M:
                val = fmail.detect_special(M, self.acc).get(kind, "")
        except NET_ERRORS:
            self._special_cache[kind] = ""   # cache the failure: no reconnection on every Enter
            return ""
        self._special_cache[kind] = val
        return val

    def _refresh_all(self):
        """Refreshes the mail list and recounts the folders FROM THE CACHE (no network
        round-trip → no UI freeze after archive/delete)."""
        self.refresh_list()
        self._recount_local()

    def _recount_local(self):
        """Updates folder_counts from the local cache (0 network). We only touch the
        already-synced folders; the others keep their server counter."""
        for n in self.folders:
            if (self.acc.name, n) in self._synced:
                try:
                    self.folder_counts[n] = self.store.counts(self.acc.name, n)
                except Exception:
                    pass

    # ── Sync thread (local cache) + new-mail badge ────────────────────────
    def _start_sync(self):
        self._poll_thread = threading.Thread(target=self._sync_worker, daemon=True)
        self._poll_thread.start()

    def _sync_worker(self):
        """Background thread: syncs the displayed folder with the local cache then
        updates the "new mail" badge, now and then every 5 min (immediately wakeable
        via _sync_wake). DEDICATED IMAP connections — never shared with the main thread
        (imaplib is not thread-safe)."""
        try:
            while not self._poll_stop.is_set():
                self._sync_active_folder()
                self._poll_check()
                self._poll_all_status()
                self._sync_wake.wait(POLL_INTERVAL_S)
                self._sync_wake.clear()
        finally:
            for M in list(self._sync_conns.values()):
                try:
                    M.logout()
                except Exception:
                    pass

    def _request_sync(self, folder=None):
        """Wakes the sync thread for an immediate pass."""
        self._sync_wake.set()

    def _sync_conn(self, accname):
        """IMAP connection of the SYNC THREAD (pool separate from the main thread)."""
        M = self._sync_conns.get(accname)
        if M is not None:
            try:
                if M.noop()[0] == "OK":
                    return M
            except (imaplib.IMAP4.error, OSError, ssl.SSLError, EOFError):
                pass
            try:
                M.logout()
            except Exception:
                pass
            self._sync_conns.pop(accname, None)
        M = fmail.imap_connect(self.accounts[accname])
        self._sync_conns[accname] = M
        return M

    def _sync_active_folder(self):
        """Syncs the currently displayed folder into the local cache. Called from the
        sync thread only (_sync_conns pool)."""
        accname, folder = self._active        # atomic read of the pair (a single attribute)
        key = (accname, folder)
        # periodic full (~30 min): also reconciles the flags of old mails outside the
        # incremental sync's recent window.
        n = self._sync_cycles.get(key, 0)
        if key in self._synced and n >= 6:        # 6 × 5 min ≈ 30 min
            self._full_next.add(key)
        full = key in self._full_next or key not in self._synced
        try:
            M = self._sync_conn(accname)
            with self._sync_lock:   # never two concurrent sync_folder on the Store
                if self._cache_closed or self.store is None:
                    return          # vault re-locked: NEVER rewrite cleartext
                fmail_store.sync_folder(M, self.store, accname, folder, full=full,
                                        progress=lambda *_: setattr(self, "_dirty", True),
                                        flag_guard=self._flag_lock)
        except NET_ERRORS as e:
            with self._poll_lock:
                self.poll_error = str(e)
            self._sync_conns.pop(accname, None)
            return
        self._synced.add(key)
        self._full_next.discard(key)
        self._sync_cycles[key] = 0 if full else n + 1
        self._dirty = True

    def _poll_check(self):
        """Queries INBOX and updates the new-mail counter. Silent: no notification, no
        side effect on the displayed list. Thread-safe."""
        try:
            M = fmail.imap_connect(self.acc)
            try:
                fmail.imap_select(M, "INBOX", readonly=True)
                uidvalidity = fmail_store._untagged_int(M, "UIDVALIDITY")
                typ, data = M.uid("search", None, "ALL")
                uids = [int(u) for u in b" ".join(p for p in data if p).split()] if (typ == "OK" and data) else []
                typ2, ud = M.uid("search", None, "UNSEEN")
                unseen = len(b" ".join(p for p in ud if p).split()) if (typ2 == "OK" and ud) else 0
            finally:
                fmail.imap_logout(M)
        except NET_ERRORS as e:
            with self._poll_lock:
                self.poll_error = str(e)
            return
        maxuid = max(uids) if uids else 0
        with self._poll_lock:
            self.poll_error = None
            if (self._poll_uidvalidity is not None and uidvalidity
                    and uidvalidity != self._poll_uidvalidity):
                self._poll_baseline = None   # INBOX reindexed → the old baseline is meaningless
            self._poll_uidvalidity = uidvalidity or self._poll_uidvalidity
            self._inbox_max = maxuid
            self.inbox_total = len(uids)
            self.inbox_unseen = unseen
            if self._poll_baseline is None:
                # First check: we take the current state as the reference (nothing is
                # "new" at startup).
                self._poll_baseline = maxuid
                self.new_count = 0
            else:
                self.new_count = sum(1 for u in uids if u > self._poll_baseline)

    def _poll_all_status(self):
        """Left-column badges: a lightweight STATUS INBOX (MESSAGES/UNSEEN/UIDNEXT, no
        SELECT or FETCH) for EACH account, over the sync-pool connections. The ✚ lights
        up when UIDNEXT has risen since the last glance (each new message increments
        UIDNEXT, never reused). Sync thread only."""
        for name in list(self.accounts):
            try:
                M = self._sync_conn(name)
                typ, data = M.status(fmail._imap_quote("INBOX"),
                                     "(MESSAGES UNSEEN UIDNEXT)")
            except NET_ERRORS:
                self._sync_conns.pop(name, None)
                with self._poll_lock:
                    st = self.acct_status.setdefault(name, {})
                    st["error"] = True
                continue
            if typ != "OK" or not data or not data[0]:
                continue
            unseen = _status_num(data[0], "UNSEEN")
            uidnext = _status_num(data[0], "UIDNEXT")
            with self._poll_lock:
                base = self.acct_baseline.get(name)
                if base is None:               # first view: nothing is "new"
                    self.acct_baseline[name] = uidnext
                    new = False
                else:
                    new = uidnext > base
                self.acct_status[name] = {"unseen": unseen, "uidnext": uidnext,
                                          "new": new, "error": False}
        self._dirty = True

    def _ack_account(self, name):
        """Acknowledges an account's ✚ (we just looked at its INBOX)."""
        with self._poll_lock:
            st = self.acct_status.get(name)
            if st and st.get("uidnext"):
                self.acct_baseline[name] = st["uidnext"]
                st["new"] = False

    def _ack_new(self):
        """Acknowledges new mail (we just looked at INBOX): the badge drops."""
        with self._poll_lock:
            if self._inbox_max:
                self._poll_baseline = self._inbox_max
            self.new_count = 0

    def _reset_poll(self):
        """Resets the poll (e.g. after an account switch)."""
        with self._poll_lock:
            self._poll_baseline = None
            self._poll_uidvalidity = None
            self._inbox_max = 0
            self.new_count = 0
            self.poll_error = None

    def _check_now(self):
        """"Check now" (key n): verbose + full check of the displayed folder."""
        self._verbose_check(self.folder, full=True)

    def _wait_key_or_timeout(self, ms):
        """Waits for a key, or unblocks on its own after `ms` ms (None on timeout)."""
        self.stdscr.timeout(ms)
        self._raw_key = True          # this timeout wins: _getkey doesn't arm its own
        try:
            return self._getkey()
        finally:
            self._raw_key = False
            self.stdscr.timeout(-1)

    def _verbose_check(self, folder=None, full=True, title=None):
        """Syncs the folder in the FOREGROUND while showing a verbose log (connection,
        TLS+certificate, SEARCH, diff, fetch, flags). Under _sync_lock so it never
        crosses the background sync thread on the Store."""
        import time as _t
        if title is None:
            title = _("⟩⟩ MAIL CHECK")
        folder = folder or self.folder or "INBOX"
        acc = self.acc
        t0 = _t.time()
        log = []

        def step(m, level="info"):
            log.append((f"[{_t.time() - t0:5.2f}s] {m}", self._lvl_attr(level)))
            self._popup_box(title, log, footer=_("· in progress ·"))

        def progress(phase, done, total):
            if phase == "search":
                step(_("querying the server (SEARCH ALL)…"))
            elif phase == "diff":
                step(_("server ↔ cache diff: {new} new, {deleted} deleted", new=done, deleted=total),
                     "ok" if (done or total) else "info")
            elif phase == "new" and total and done == 0:
                step(_("fetching {n} header(s)…", n=total))
            elif phase == "new" and total and done >= total:
                step(_("{n} header(s) fetched", n=done), "ok")
            elif phase == "flags" and total:
                step(_("reconciling flags ({n} message(s))…", n=total))

        try:
            step(_("IMAP connection {host}:{port} (SSL/TLS)", host=acc.imap_host, port=acc.imap_port))
            with self._imap() as M:
                fmail._report_tls(getattr(M, "sock", None), acc.imap_host, acc.imap_port, step)
                step(_("selecting folder \"{folder}\"", folder=folder.replace('INBOX.', '')))
                with self._sync_lock:
                    stats = fmail_store.sync_folder(M, self.store, acc.name, folder,
                                                    full=full, progress=progress,
                                                    flag_guard=self._flag_lock)
            self._synced.add((acc.name, folder))
            self._full_next.discard((acc.name, folder))
            self._sync_cycles[(acc.name, folder)] = 0
            log.append((f"[{_t.time() - t0:5.2f}s] " + _("✓ UP TO DATE — {new} new, {deleted} deleted",
                        new=stats.new, deleted=stats.deleted), self._lvl_attr("ok")))
            self._popup_box(title + _(" — OK"), log, footer=_("(Enter, or closes by itself)"))
            self._wait_key_or_timeout(1500)   # auto-dismiss on success (quick read)
        except NET_ERRORS as e:
            log.append((f"[{_t.time() - t0:5.2f}s] " + _("✗ FAILED: {e}", e=e), self._lvl_attr("error")))
            self._popup_box(title + _(" — FAILED"), log, footer=_("[Enter] close"))
            self._wait_key()
        self._dirty = False
        self._relist()
        if folder == "INBOX" and not self.search_query and not self.only_unseen:
            self._ack_new()

    def _dec_unseen(self, folder):
        """Locally decrements a folder's unread counter (left pane)."""
        msg, un = self.folder_counts.get(folder, (0, 0))
        if un > 0:
            self.folder_counts[folder] = (msg, un - 1)

    def _action_move_current(self, dest, verb):
        if self.list.current():
            if self._action_move(self.list.current().uid, dest, verb):
                self._refresh_all()

    def _action_move(self, uid, dest, verb):
        if not dest:
            self.error(_("destination folder not found (configure it in accounts.toml)."))
            return False
        info = self._peek(uid)
        if not self.confirm(_("{verb} → {dest}?   {info}", verb=verb, dest=dest, info=info)):
            return False
        try:
            self._do_move(uid, self.folder, dest)
        except NET_ERRORS as e:
            self.error(str(e))
            return False
        self.status = _("✓ moved to {dest}", dest=dest)
        return True

    def _do_move(self, uid, src, dest):
        with self._imap() as M:
            fmail.imap_select(M, src, readonly=False)
            typ, _r = M.uid("move", uid, fmail._imap_quote(dest))
            if typ == "OK":
                purged = True
            else:
                typ, _r = M.uid("copy", uid, fmail._imap_quote(dest))
                if typ != "OK":
                    raise FmailError(_("copy to {dest} failed.", dest=dest))
                M.uid("store", uid, "+FLAGS", "(\\Deleted)")
                purged = fmail.expunge_uid(M, uid)  # targeted UIDPLUS; False = abstention
        # The destination received a copy → resync it so it shows up.
        dkey = (self.acc.name, dest)
        self._synced.discard(dkey)
        self._full_next.add(dkey)
        if not purged:
            # Copied to destination but not purged at source (server without UIDPLUS,
            # other \Deleted present): do NOT lie to the cache — the mail is still there.
            raise FmailError(_("copied to {dest}, but not purged at source (UID {uid} stays \"deleted\").",
                               dest=dest, uid=uid))
        fmail.forget_uid(self.acc.name, uid)
        self.store.delete_uids(self.acc.name, src, [uid])   # disappears from the list at once

    def _move_to_folder_current(self):
        cur = self.list.current()
        if not cur:
            return
        dest = self._pick_folder(_("Move to which folder?"))
        if dest and self._action_move(cur.uid, dest, _("Move")):
            self._refresh_all()

    def _toggle_seen_current(self):
        cur = self.list.current()
        if not cur:
            return
        new_seen = not cur.seen
        try:
            with self._imap() as M:
                fmail.imap_select(M, self.folder, readonly=False)
                op = "+FLAGS" if new_seen else "-FLAGS"
                M.uid("store", cur.uid, op, "(\\Seen)")
        except NET_ERRORS as e:
            self.error(str(e))
            return
        # Immediate update of the cache + counters (no need to re-sync)
        cur.seen = new_seen
        with self._flag_lock:   # don't get overwritten by the worker's reconciliation
            self.store.set_flag(self.acc.name, self.folder, cur.uid, seen=new_seen)
        if new_seen:
            self._dec_unseen(self.folder)
        else:
            msg, un = self.folder_counts.get(self.folder, (0, 0))
            self.folder_counts[self.folder] = (msg, un + 1)
        self._relist()

    def _peek(self, uid):
        try:
            with self._imap() as M:
                fmail.imap_select(M, self.folder, readonly=True)
                typ, md = M.uid("fetch", uid, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])")
                if typ == "OK" and md and isinstance(md[0], tuple):
                    m = email.message_from_bytes(md[0][1])
                    return f"{fmail.decode_field(m.get('From'))[:24]} — {fmail.decode_field(m.get('Subject')) or _('(no subject)')}"
        except NET_ERRORS:
            pass
        return ""

    # ── Search & pickers ──────────────────────────────────────────────────
    def _search_prompt(self):
        q = self.prompt(_("Search: "))
        if q is None:
            return
        q = q.strip()
        self.search_query = q
        self.only_unseen = False
        if q:
            # SERVER-SIDE full-text search (matches the body too). It runs synchronously
            # and can take a few seconds (a server without an FTS index scans every body),
            # so: (1) show feedback FIRST — the UI is blocked during the call and would
            # otherwise look frozen; (2) bound it with a short socket timeout — a slow
            # search must fall back to the local filter, never hang. On any error the
            # connection (possibly desynced) is dropped by _ImapLease (OSError ∈ DEAD_CONN).
            self.status = _("Searching “{q}” on the server…", q=q[:40])
            try:
                self.draw_main(); self.stdscr.refresh()
            except curses.error:
                pass
            try:
                with self._imap() as M:
                    fmail.imap_select(M, self.folder, readonly=True)
                    sock = getattr(M, "sock", None)
                    old = sock.gettimeout() if sock else None
                    if sock:
                        sock.settimeout(15)        # bounded: slow search → fallback, never freeze
                    try:
                        uids = fmail.search_text_uids(M, q, 2000)
                    finally:
                        if sock and old is not None:
                            try:
                                sock.settimeout(old)
                            except OSError:
                                pass
                self.search_uids = [u.decode() if isinstance(u, (bytes, bytearray)) else str(u)
                                    for u in uids]
                self.status = ""
            except NET_ERRORS:
                self.search_uids = None   # fallback: local LIKE on subject/sender
                self.status = _("server search unavailable — filtering locally (subject/sender).")
        else:
            self.search_uids = None
        self._relist()

    def _pick_folder(self, title):
        try:
            with self._imap() as M:
                folders = [n for n, _ in fmail.list_folders(M)]
        except NET_ERRORS as e:
            self.error(str(e))
            return None
        return self.picker(title, [(f, f) for f in folders])

    def _account_picker(self):
        choice = self.picker(_("Switch account"),
                             [(f"{n}  <{a.email}>", n) for n, a in self.accounts.items()])
        if choice and choice in self.accounts:
            self._switch_account(choice)

    @staticmethod
    def _split_host_port(value):
        """('host', port|None) — parse an inline 'host:port' (a geek may type it);
        port=None when absent or out of range, so the caller asks for it."""
        value = (value or "").strip()
        m = re.match(r"^(.+):(\d{1,5})$", value)
        if m:
            port = int(m.group(2))
            if 1 <= port <= 65535:
                return m.group(1).strip(), port
        return value, None

    def _ask_port(self, proto, default):
        """Ask for a port. Empty / Esc / 'don't know' → the usual default (never aborts)."""
        v = self.prompt(_("{proto} port — a number, or Enter for the usual {default}",
                          proto=proto, default=default) + ": ")
        if not v or not v.strip():
            return default
        try:
            n = int(v.strip())
            return n if 1 <= n <= 65535 else default
        except ValueError:
            return default

    def _new_account_flow(self, switch=True):
        """Collect a new account and write it to the config. switch=True selects it in
        the running session (key N); switch=False (first-launch wizard, cache not open
        yet) just reloads accounts and points self.acc at it. Returns True if added."""
        fields = [
            (_("Short name (e.g. personal)"), "name"),
            (_("Email address"), "email"),
            (_("IMAP server (host, or host:port)"), "imap_host"),
            (_("SMTP server (host, or host:port — Enter = same as IMAP)"), "smtp_host"),
            (_("Display name (optional)"), "display_name"),
        ]
        data = {}
        for label, key in fields:
            v = self.prompt(label + ": ")
            if v is None:
                return False
            data[key] = v.strip()
        pw = self.prompt(_("Password (or app password): "), secret=True)
        if pw is None:
            return False
        # Ports: accept an inline "host:port"; otherwise ask (Enter = the usual default).
        imap_host, imap_port = self._split_host_port(data["imap_host"])
        if imap_port is None:
            imap_port = self._ask_port("IMAP", 993)
        if data["smtp_host"]:
            smtp_host, smtp_port = self._split_host_port(data["smtp_host"])
        else:
            smtp_host, smtp_port = imap_host, None          # same host as IMAP (but its OWN port)
        if smtp_port is None:
            smtp_port = self._ask_port("SMTP", 465)
        try:
            fmail.add_account_to_config(
                data["name"], data["email"], imap_host, smtp_host, pw,
                display_name=data.get("display_name", ""),
                imap_port=imap_port, smtp_port=smtp_port,
            )
            self.accounts, _cfg = fmail.load_config()
        except NET_ERRORS as e:
            self.error(str(e))       # not persisted → genuinely "not added"
            return False
        # The account IS persisted now. A later connection error must NOT report it as
        # "not added" (that would loop the wizard / mislead the user).
        if switch:
            try:
                self._switch_account(data["name"])
            except NET_ERRORS as e:
                self.error(str(e))
        else:
            # First launch: don't connect/switch yet (cache not open) — just adopt it.
            self.acc = self.accounts.get(data["name"], self.acc)
            self._active = ((self.acc.name if self.acc else None), self.folder)
        self.status = _("✓ account \"{name}\" added and selected.", name=data["name"])
        return True

    def _uninstall_paths(self):
        """(app_dir, wrapper, clash) for the uninstall flow. `clash` is a data/secret
        directory that overlaps app_dir (→ uninstall MUST refuse), or None if safe.
        The vault location is HARDCODED in vault.py (not derived from CONFIG_PATH), so it
        is listed explicitly — otherwise rmtree(app_dir) could destroy the vault/keys."""
        app_dir = Path(__file__).resolve().parent
        bin_dir = os.environ.get("FMAIL_BIN") or str(Path.home() / ".local" / "bin")
        wrapper = Path(os.path.expanduser(bin_dir)) / "fmail"

        def _rp(p):
            try:
                return Path(p).expanduser().resolve()
            except (OSError, RuntimeError, ValueError):
                return None
        protected = set()
        for p in (fmail.CONFIG_PATH.parent, vault.VAULT_PATH.parent, vault.VAULT_HOME,
                  getattr(self, "_cache_enc", None), Path.home() / "secrets"):
            rp = _rp(p) if p else None
            if rp:
                protected.add(rp)
        # Refuse if any protected dir is app_dir, inside it, or an ancestor of it
        # (component-wise via Path.parents, both sides resolved → no string-prefix bug).
        clash = next((d for d in protected
                      if app_dir == d or app_dir in d.parents or d in app_dir.parents), None)
        return app_dir, wrapper, clash

    def _update_flow(self):
        """Check survivologie.org for a newer fmail and install it (SHA-256 verified;
        config never touched). Refuses if fmail runs from its data/dev directory — there,
        update via git / the installer (auto-updating would clobber local files)."""
        app_dir, _wrapper, clash = self._uninstall_paths()
        if clash:
            self._modal_text(_("Update fmail"), _(
                "fmail runs from its data/dev directory ({app}) — updating here would\n"
                "overwrite local files. Update it with git, or re-run the installer.",
                app=app_dir), C_WARN)
            return None
        self.status = _("Checking for updates…")
        self.draw_main(); self.stdscr.refresh()
        try:
            remote, uptodate = fmail.check_update()
        except FmailError as e:
            self.error(str(e)); return None
        if uptodate:
            self._modal_text(_("Update fmail"),
                             _("fmail is up to date (v{v}).", v=fmail.__version__), C_TITLE)
            return None
        if self._wizard_yesno(_(" Update fmail"),
                              [_("A new version is available:"), "",
                               _("  installed: v{v}", v=fmail.__version__),
                               _("  latest:    v{v}", v=remote)],
                              _("Download and install it now?  [Y/n]")) is not True:
            return None
        self.status = _("Downloading update…")
        self.draw_main(); self.stdscr.refresh()
        try:
            newv = fmail.self_update(app_dir, fmail.CONFIG_PATH.parent)
        except FmailError as e:
            self.error(str(e)); return None
        if self._wizard_yesno(_(" Update fmail"),
                              [_("✓ Updated to v{v}.", v=newv), "",
                               _("Restart fmail to run the new version.")],
                              _("Quit fmail now to restart?  [Y/n]")) is True:
            return "quit"
        self.status = _("✓ updated to v{v} — restart fmail to apply.", v=newv)
        return None

    def _uninstall_flow(self):
        """Uninstall fmail: removes the PROGRAM and the `fmail` command, but NEVER your
        data/vault. Refuses if the program shares its folder with the data/vault (e.g. a
        dev checkout / `python3 fmail.py` from ~/freyja-mail) — that would delete mail."""
        app_dir, wrapper, clash = self._uninstall_paths()
        data_dir = fmail.CONFIG_PATH.resolve().parent
        if clash:
            self._modal_text(_("Uninstall"), _(
                "The fmail program directory ({app}) also holds your data or encrypted "
                "vault ({data}).\n\n"
                "To avoid destroying your mail, accounts, vault or keys, fmail will NOT "
                "uninstall itself from here. Remove it by hand if you really want to.",
                app=app_dir, data=clash), C_WARN)
            return None

        # Only remove the wrapper if it actually points at THIS program dir (don't nuke
        # another install's `fmail` command).
        has_cmd = wrapper.exists() or wrapper.is_symlink()
        wrapper_ours = False
        if has_cmd:
            try:
                wrapper_ours = str(app_dir) in wrapper.read_text(errors="replace")
            except OSError:
                wrapper_ours = False
        lines = [
            _("Remove the fmail PROGRAM from this computer?"), "",
            _("Will be DELETED:"),
            _("  • program: {app}", app=app_dir),
            (_("  • command: {bin}", bin=wrapper) if (has_cmd and wrapper_ours)
             else _("  • command: (not found / not this install)")), "",
            _("Will be KEPT — your data, accounts, encrypted vault and cache:"),
            _("  • {data}", data=data_dir),
            _("  • vault: {vault}", vault=vault.VAULT_PATH), "",
            _("(To erase your data too — irreversible — delete those yourself.)"),
        ]
        curses.curs_set(0)
        while True:                      # explicit [y/N], default NO (destructive)
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self._bar(0, _(" Uninstall fmail"),
                      self._cp(C_WARN) | curses.A_BOLD | curses.A_REVERSE)
            for i, ln in enumerate(lines):
                self._put(2 + i, 2, ln[:w - 1], 0)
            self._bar(h - 1, _(" Remove the fmail program?  [y/N] "),
                      self._cp(C_ERR) | curses.A_REVERSE | curses.A_BOLD)
            self.stdscr.refresh()
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if isinstance(k, str) and k.lower() in ("y", "o"):
                break
            return None                  # Esc / n / anything else → cancel
        errors = []
        try:
            if has_cmd and wrapper_ours:
                wrapper.unlink()
        except OSError as e:
            errors.append(str(e))
        try:
            shutil.rmtree(app_dir)       # the running process survives the unlinked files
        except OSError as e:
            errors.append(str(e))
        msg = (_("fmail has been removed. Your data is kept in {data}.", data=data_dir)
               if not errors else
               _("Uninstall finished with errors: {err}", err="; ".join(errors)))
        self._modal_text(_("Uninstall"), msg + "\n\n" + _("Press a key to quit fmail."), C_TITLE)
        return "quit"                    # leave fmail (cache is re-encrypted to the kept data dir)

    # ── File browser (to attach a file) ──────────────────────────────────
    def _confirm_attach(self, p):
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        return self.confirm(_("Attach \"{name}\" ({size})?", name=p.name, size=human_size(size)))

    def _accept_file(self, p):
        """Validates (regular file + readable) then confirms. Otherwise shows the error."""
        if not p.is_file():
            self.error(_("not a regular file: {name}", name=p.name))
            return False
        if not os.access(p, os.R_OK):
            self.error(_("unreadable file: {name}", name=p.name))
            return False
        return self._confirm_attach(p)

    def _file_browser(self, start=None):
        """Browses the file system (cd/ls/Tab + arrows) and returns the chosen
        (confirmed) path or None. Read-only, touches nothing."""
        base = start or getattr(self, "_browse_dir", None) or str(Path.home())
        try:
            cwd = Path(os.path.expanduser(base)).resolve()
            if not cwd.is_dir():
                cwd = Path.home()
        except (OSError, RuntimeError, ValueError):  # RuntimeError = symlink loop
            cwd = Path.home()
        show_hidden = False
        inp = LineEditor("")
        lm = ListModel(height=10)
        entries, status = list_dir(cwd, show_hidden)
        lm.set_items(entries)

        def goto(target):
            nonlocal cwd, entries, status
            expanded = os.path.expanduser(target)
            p = Path(expanded) if os.path.isabs(expanded) else (cwd / expanded)
            try:
                r = p.resolve()
            except (OSError, RuntimeError, ValueError):  # symlink loop, NUL, etc.
                return _("invalid path")
            if not _safe_is_dir(r):
                return _("not a directory: {target}", target=target)
            if not os.access(r, os.R_OK | os.X_OK):
                return _("access denied: {target}", target=target)
            cwd = r
            entries, status = list_dir(cwd, show_hidden)
            lm.set_items(entries)
            lm.cursor = 0
            lm.top = 0
            inp.text = ""
            inp.cursor = 0
            return ""

        def relist():
            nonlocal entries, status
            entries, status = list_dir(cwd, show_hidden)
            lm.set_items(entries)

        while True:
            curses.curs_set(1)  # restored each turn (a modal confirm() resets it to 0)
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self._bar(0, _(" Attach a file — {cwd}", cwd=cwd), self._cp(C_TITLE) | curses.A_BOLD | curses.A_REVERSE)
            lm.set_height(max(1, h - 4))
            for row, (idx, (name, is_dir)) in enumerate(lm.visible(), start=1):
                sel = idx == lm.cursor
                attr = (curses.A_REVERSE | curses.A_BOLD) if sel else (
                    self._cp(C_FROM) if is_dir else self._cp(C_DIM))
                self._bar(row, ("▸ " if sel else "  ") + name, attr)
            if status:
                self._put(h - 3, 0, (" " + status)[:w - 1], self._cp(C_WARN))
            self._bar(h - 2, _(" ⏎ open/attach · cd <d> · ls [-a] · ⇥ complete · Esc cancel"),
                      self._cp(C_DIM) | curses.A_REVERSE)
            self._put(h - 1, 0, (": " + inp.text)[:w - 1])
            self._safe_move(h - 1, min(2 + inp.cursor, w - 1))
            self.stdscr.refresh()

            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            status = ""
            if is_esc(k):
                curses.curs_set(0)
                return None
            elif k == curses.KEY_UP:
                lm.move(-1)
            elif k == curses.KEY_DOWN:
                lm.move(1)
            elif k == curses.KEY_NPAGE:
                lm.page(1)
            elif k == curses.KEY_PPAGE:
                lm.page(-1)
            elif k == "\t":
                inp.text, status = complete_path(inp.text, cwd, show_hidden)
                inp.cursor = len(inp.text)
            elif is_back(k):
                inp.backspace()
            elif k == curses.KEY_LEFT:
                inp.left()
            elif k == curses.KEY_RIGHT:
                inp.right()
            elif k == curses.KEY_HOME:
                inp.home()
            elif k == curses.KEY_END:
                inp.end()
            elif is_enter(k):
                cmd = inp.text.strip()
                if cmd:
                    if cmd == "ls":
                        inp.text = ""; inp.cursor = 0; relist()
                    elif cmd in ("ls -a", "la"):
                        show_hidden = not show_hidden
                        inp.text = ""; inp.cursor = 0; relist()
                        status = _("hidden files ") + (_("shown") if show_hidden else _("hidden"))
                    elif cmd == "cd" or cmd.startswith("cd "):
                        status = goto(cmd[2:].strip() or "~")
                    else:
                        p = Path(os.path.expanduser(cmd))
                        p = p if p.is_absolute() else (cwd / os.path.expanduser(cmd))
                        if _safe_is_dir(p):
                            status = goto(cmd)
                        elif p.exists():
                            if self._accept_file(p):
                                curses.curs_set(0); return str(p)
                            inp.text = ""; inp.cursor = 0
                        else:
                            status = _("not found: {cmd}", cmd=cmd)
                elif entries:
                    name, is_dir = entries[lm.cursor]
                    if name == "..":
                        status = goto("..")
                    elif is_dir:
                        status = goto(name.rstrip("/"))
                    else:
                        p = cwd / name
                        if self._accept_file(p):
                            curses.curs_set(0); return str(p)
            elif is_printable(k):
                inp.insert(k)

    # ── Modal widgets ─────────────────────────────────────────────────────
    def prompt(self, label, secret=False):
        ed = LineEditor("")
        curses.curs_set(1)
        while True:
            h, w = self.stdscr.getmaxyx()
            shown = ("•" * len(ed.text)) if secret else ed.text
            self._bar(h - 1, "", self._cp(C_WARN) | curses.A_REVERSE)
            self._put(h - 1, 0, (label + shown)[:w - 1], self._cp(C_WARN) | curses.A_REVERSE)
            self._safe_move(h - 1, min(len(label) + ed.cursor, w - 1))
            self.stdscr.refresh()
            k = self._getkey()
            if k is None:
                continue
            if is_esc(k):
                curses.curs_set(0)
                return None
            if is_enter(k):
                curses.curs_set(0)
                return ed.text
            elif is_back(k):
                ed.backspace()
            elif k == curses.KEY_DC:
                ed.delete()
            elif k == curses.KEY_LEFT:
                ed.left()
            elif k == curses.KEY_RIGHT:
                ed.right()
            elif k == curses.KEY_HOME:
                ed.home()
            elif k == curses.KEY_END:
                ed.end()
            elif is_printable(k):
                ed.insert(k)

    # ── Single-line input (reused by the lock and the address book) ─────────
    def _line_input(self, title, initial="", hidden=False, hint=None):
        """Single-line input. Returns the text (Enter) or None (Esc).
        hidden=True masks the input (password)."""
        if hint is None:
            hint = _("Enter confirm · Esc cancel")
        ed = LineEditor(initial)
        curses.curs_set(1)
        try:
            while True:
                self.stdscr.erase()
                h, w = self.stdscr.getmaxyx()
                self._bar(0, f" {title}", self._cp(C_TITLE) | curses.A_BOLD | curses.A_REVERSE)
                shown = ("•" * len(ed.text)) if hidden else ed.text
                self._put(2, 2, ("> " + shown)[:w - 1], 0)
                self._bar(h - 1, " " + hint, self._cp(C_DIM) | curses.A_REVERSE)
                self._safe_move(2, min(w - 1, 4 + ed.cursor))
                self.stdscr.refresh()
                k = self._getkey()
                if k is None or k == curses.KEY_RESIZE:
                    continue
                if is_esc(k):
                    return None
                if is_enter(k):
                    return ed.text
                if is_back(k):
                    ed.backspace()
                elif k == curses.KEY_DC:
                    ed.delete()
                elif k == curses.KEY_LEFT:
                    ed.left()
                elif k == curses.KEY_RIGHT:
                    ed.right()
                elif k == curses.KEY_HOME:
                    ed.home()
                elif k == curses.KEY_END:
                    ed.end()
                elif is_printable(k):
                    ed.insert(k)
        finally:
            curses.curs_set(0)

    def _lock_screen(self):
        """Asks for the master password until unlocked. Esc = quit. If the DURESS
        password is entered, triggers the emergency wipe behind a decoy (never returns)."""
        while True:
            pw = self._line_input(_("🔒  fmail locked — master password"), hidden=True,
                                  hint=_("Enter unlock · Esc quit fmail"))
            if pw is None:
                raise FmailError(_("locked — closing fmail."))
            if pw and vault.is_duress(pw):          # coercion → destroy everything, quietly
                self._duress_wipe_decoy()           # wipes + shows a fake network error
                raise FmailError("")                # then quits (data already gone)
            try:
                vault.unlock(pw)
                vault.touch()
                self.status = _("✓ unlocked.")
                return
            except vault.BadPassphrase:
                self.error(_("incorrect password."))
            except vault.VaultError as e:
                raise FmailError(str(e))

    def _duress_decoy_host(self):
        """A realistic IMAP host for the decoy — the active account, else the default
        account read from accounts.toml, else a generic placeholder."""
        if self.acc and getattr(self.acc, "imap_host", None):
            return self.acc.imap_host, getattr(self.acc, "imap_port", 993)
        try:
            cfg = tomllib.loads(fmail.CONFIG_PATH.read_text(encoding="utf-8"))
            accs = cfg.get("accounts", {}) or {}
            name = cfg.get("default") or (next(iter(accs)) if accs else None)
            a = accs.get(name) if name else None
            if isinstance(a, dict) and a.get("imap_host"):
                return a["imap_host"], int(a.get("imap_port", 993))
        except Exception:
            pass
        return "imap.example.com", 993

    def _duress_wipe_decoy(self):
        """Runs emergency_wipe() in the background while showing a screen INDISTINGUISHABLE
        from fmail's real network-failure flow (same '⟩⟩ MAIL CHECK' popup, timestamped
        lines, then '✗ FAILED: … timed out'). The connection appears to hang for a few
        seconds — exactly like a real TCP timeout — which buys time for the wipe to finish.
        (Deliberately NOT fake 'retrying' lines: fmail never retries, so that would betray
        the trap to anyone who knows it.)"""
        import time as _time
        host, port = self._duress_decoy_host()

        def _wipe():
            try:
                fmail.emergency_wipe()
            except Exception:
                pass
        worker = threading.Thread(target=_wipe, daemon=True)
        worker.start()

        title = _("⟩⟩ MAIL CHECK")
        t0 = _time.time()
        log = [(f"[{_time.time() - t0:5.2f}s] "
                + _("IMAP connection {host}:{port} (SSL/TLS)", host=host, port=port),
                self._lvl_attr("info"))]
        try:
            curses.curs_set(0)
            # Static screen, frozen during the "hang" — exactly like the real synchronous
            # _verbose_check while the socket blocks (no spinner, which it never shows).
            self._popup_box(title, log, footer=_("· in progress ·"))
            t_end = _time.time() + 6.0
            while _time.time() < t_end:
                _time.sleep(0.2)
        except curses.error:
            pass
        worker.join(timeout=8)                       # ensure the wipe actually finished
        try:
            log.append((f"[{_time.time() - t0:5.2f}s] "
                        + _("✗ FAILED: {e}", e="[Errno 101] Network is unreachable"),
                        self._lvl_attr("error")))
            self._popup_box(title + _(" — FAILED"), log, footer=_("[Enter] close"))
            self._wait_key()
        except curses.error:
            pass

    # ── First-launch configuration wizard ────────────────────────────────────
    def _wizard_yesno(self, title, lines, prompt):
        """Full info screen + [Y/n] question. Returns True / False / None (Esc)."""
        curses.curs_set(0)
        while True:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self._bar(0, title, self._cp(C_TITLE) | curses.A_BOLD | curses.A_REVERSE)
            for i, ln in enumerate(lines):
                self._put(2 + i, 2, ln[:w - 1], 0)
            self._bar(h - 1, " " + prompt, self._cp(C_WARN) | curses.A_REVERSE | curses.A_BOLD)
            self.stdscr.refresh()
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if is_esc(k):
                return None
            if isinstance(k, str) and k.lower() in ("o", "y"):
                return True
            if isinstance(k, str) and k.lower() == "n":
                return False
            if is_enter(k):
                return True   # default = Yes (the prompt shows [Y/n])

    def _new_master_password(self):
        """Mandatory master password entry (double entry + rules). Returns the
        password, or None if the user gives up (Esc)."""
        while True:
            p1 = self._line_input(_("Choose a master password (≥ {n} characters)", n=vault.MIN_PASSPHRASE),
                                  hidden=True)
            if p1 is None:
                return None
            try:
                vault._check_passphrase(p1)
            except vault.VaultError as e:
                self.error(str(e))
                continue
            p2 = self._line_input(_("Confirm the master password"), hidden=True)
            if p2 is None:
                return None
            if p1 != p2:
                self.error(_("the two entries differ."))
                continue
            return p1

    def _show_recovery_code_screen(self, code):
        """Shows the recovery code ONCE and requires an explicit acknowledgement."""
        lines = [
            _("Note this RECOVERY CODE and keep it OFFLINE"),
            _("(paper, password manager):"), "",
            "    " + code, "",
            _("It lets you recover the vault if you FORGET the master password."),
            "",
            _("⚠ If you lose the password AND this code, the vault will be"),
            _("  PERMANENTLY UNUSABLE (data unrecoverable)."),
        ]
        curses.curs_set(0)
        while True:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self._bar(0, _(" RECOVERY CODE — WRITE IT DOWN NOW"),
                      self._cp(C_WARN) | curses.A_BOLD | curses.A_REVERSE)
            for i, ln in enumerate(lines):
                attr = curses.A_BOLD if ln.strip() == code else 0
                self._put(2 + i, 2, ln[:w - 1], attr)
            self._bar(h - 1, _(" Have you saved the code somewhere safe?  [y/N] "),
                      self._cp(C_WARN) | curses.A_REVERSE | curses.A_BOLD)
            self.stdscr.refresh()
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if isinstance(k, str) and k.lower() in ("o", "y"):
                return

    def _wizard_language(self):
        """First wizard step: choose the interface language. Applied immediately and
        saved to [ui] lang. Skipped if already chosen. Esc keeps auto-detect."""
        if fmail.ui_lang_configured():
            return
        opts = [("English", "en"),
                ("Français", "fr"),
                ("Auto-detect · détection automatique", "auto")]
        sel = self.picker("Language · Langue", opts)
        if sel is None:
            return                      # decide later → auto-detect for now
        i18n.set_lang(sel)              # apply right away (the rest of the wizard follows)
        fmail.write_ui_lang(sel)        # persist in accounts.toml [ui] lang

    def _setup_wizard(self):
        """First launch: choose the language, add a first account if none is configured,
        then offer encryption. Each step runs only if still needed (re-runnable)."""
        self._wizard_language()                     # localize the rest first
        if not self.accounts:
            self._wizard_first_account()            # no account yet → add one
        # Only offer encryption once there's at least one account: enabling
        # master_password with zero account would brick startup (lock screen, then
        # no account to open). With an account, declining still writes [security].
        if self.accounts and not fmail.security_configured():
            self._wizard_encryption()               # offer the encrypted vault

    def _wizard_first_account(self):
        """First launch with no account configured: collect one interactively (loop
        until added, or skipped). Avoids the old 'IMAP error on a placeholder account'."""
        intro = [
            _("No mail account is configured yet."), "",
            _("Let's add your first account (IMAP/SMTP)."),
            _("You can add more later with the “N” key, or edit accounts.toml by hand."),
        ]
        if self._wizard_yesno(_(" Add a mail account"), intro,
                              _("Add an account now?  [Y/n]   (Esc: skip)")) is not True:
            return
        while not self.accounts:
            if self._new_account_flow(switch=False):
                return                              # added → done
            again = self._wizard_yesno(
                _(" No account added"), [_("No account was added (cancelled or invalid).")],
                _("Try again?  [Y/n]   (Esc: skip)"))
            if again is not True:
                return

    def _wizard_encryption(self):
        """Offer the encrypted vault. Declining shows a CLEARTEXT-storage warning and a
        last chance to encrypt. Accepting → mandatory master password + recovery code."""
        welcome = [
            _("Welcome to fmail."), "",
            _("Do you want to PROTECT fmail with a master password?"),
            _("An encrypted vault (AES-256) will then protect:"),
            _("  • your account passwords,"),
            _("  • your address book,"),
            _("  • the local cache (mail subjects + bodies)."), "",
            _("You will have to enter this password each time you open fmail."),
            _("A recovery code will be given to you (in case you forget the password)."),
        ]
        choice = self._wizard_yesno(
            _(" fmail configuration (first launch)"), welcome,
            _("Encrypt fmail in a secure vault?  [Y/n]   (Esc: decide later)"))
        if choice is None:
            return                          # "later" → we'll ask again at the next launch
        if not choice:
            # Be explicit about what "no" means before accepting it.
            warn = [
                _("⚠ Without a master password, fmail stores your mail UNENCRYPTED."),
                _("Your account passwords (~/secrets) and the local cache — the"),
                _("subjects AND full bodies of your messages (~/freyja-mail) — sit in"),
                _("CLEARTEXT on this machine, readable by anyone who can read your files"),
                _("(another user, a backup, a stolen disk)."), "",
                _("You can enable encryption later at any time with:  fmail vault init"),
            ]
            reconsider = self._wizard_yesno(
                _(" Heads-up: no encryption"), warn,
                _("Encrypt after all?  [Y/n]   (Enter = yes, recommended · n = keep cleartext)"))
            if reconsider is None:
                return                      # decide later
            if not reconsider:              # user explicitly accepts cleartext storage
                fmail.write_security_section(master_password=False)
                self.sec = fmail.load_security()
                self.status = _("fmail starts WITHOUT encryption — mail is cached in cleartext.")
                return
            # reconsider is True → fall through and create the master password
        pw = self._new_master_password()    # MANDATORY password to encrypt
        if pw is None:
            self.status = _("configuration deferred (no password set).")
            return
        imported = {}
        for name, acc in self.accounts.items():
            pf = getattr(acc, "password_file", "")
            if pf:
                try:
                    imported[name] = Path(os.path.expanduser(pf)).read_text().strip()
                except OSError:
                    pass
        try:
            _content, code = vault.create(pw, accounts=imported)
            vault.unlock(pw)
        except vault.VaultError as e:
            self.error(_("cannot create the vault: ") + str(e))
            return
        self._show_recovery_code_screen(code)
        fmail.write_security_section(master_password=True)
        self.sec = fmail.load_security()
        self.status = _("✓ vault enabled ({n} passwords imported). Check, then "
                        "\"fmail vault purge-secrets\" to wipe the cleartext passwords.",
                        n=len(imported))

    def _tls_accept_modal(self, a):
        """Server certificate CHANGED: the connection is REFUSED until explicit
        acceptance. Shows the fingerprints and asks for confirmation (default NO)."""
        lines = [
            _("The TLS certificate of {host}:{port} has CHANGED.", host=a['host'], port=a['port']), "",
            _("Issuer     : ") + (a.get("issuer") or "?"),
            _("Fingerprint: ") + _group_fpr(a.get("fpr")), "",
            _("⚠ This may be a legitimate rotation (renewal) OR an INTERCEPTION."),
            _("  The connection (login + mails) is REFUSED until you have accepted."),
            _("  Verify the fingerprint with your host / via another channel before accepting."),
        ]
        curses.curs_set(0)
        while True:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self._bar(0, _(" ⚠ TLS CERTIFICATE CHANGED — possible interception (MITM)"),
                      self._cp(C_ERR) | curses.A_BOLD | curses.A_REVERSE)
            for i, ln in enumerate(lines):
                self._put(2 + i, 2, ln[:w - 1], 0)
            self._bar(h - 1, _(" Accept this NEW certificate?  [y/N] "),
                      self._cp(C_ERR) | curses.A_REVERSE | curses.A_BOLD)
            self.stdscr.refresh()
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if isinstance(k, str) and k.lower() in ("o", "y"):
                fmail.accept_cert(a["host"], a["port"], a["fpr"], a["issuer"])
                self.status = _("certificate of {host} accepted — restart sync (n) or retry the send.",
                                host=a['host'])
                return
            if is_esc(k) or is_enter(k) or (isinstance(k, str) and k.lower() == "n"):
                self.status = _("certificate of {host} REFUSED — connection blocked.", host=a['host'])
                return

    def _verify_key_change(self, addr):
        """INFORMED acknowledgement of a key change: shows both fingerprints, requires
        an out-of-band verification + confirmation, and ties adoption to the shown
        fingerprint (refuses if the candidate changed in the meantime — anti-race)."""
        p = autocrypt.get_peer(addr)
        if not (p and "conflict" in p.keys() and p["conflict"]):
            return
        prev = p["prev_fpr"] if "prev_fpr" in p.keys() else None
        cand = p["cand_fpr"] if "cand_fpr" in p.keys() else None
        lines = [
            _("The key of {addr} has CHANGED.", addr=addr), "",
            _("Old fingerprint: ") + _group_fpr(prev),
            _("New fingerprint: ") + _group_fpr(cand), "",
            _("⚠ Verify the NEW fingerprint with your contact via ANOTHER channel"),
            _("  (phone, in person…) BEFORE accepting. If you are not sure,"),
            _("  refuse: encryption to this contact will stay suspended."),
        ]
        curses.curs_set(0)
        while True:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self._bar(0, _(" Verifying a key change"),
                      self._cp(C_WARN) | curses.A_BOLD | curses.A_REVERSE)
            for i, ln in enumerate(lines):
                self._put(2 + i, 2, ln[:w - 1], 0)
            self._bar(h - 1, _(" Accept the NEW key?  [y/N] "),
                      self._cp(C_WARN) | curses.A_REVERSE | curses.A_BOLD)
            self.stdscr.refresh()
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if isinstance(k, str) and k.lower() in ("o", "y"):
                if autocrypt.clear_conflict(addr, expected_fpr=cand):
                    self.status = _("✓ new key accepted for {addr}.", addr=addr)
                else:
                    self.error(_("the candidate key changed in the meantime — re-verify."))
                return
            if is_esc(k) or is_enter(k) or (isinstance(k, str) and k.lower() == "n"):
                self.status = _("key change NOT accepted (encryption suspended).")
                return

    # ── Address book (in the encrypted vault) ────────────────────────────────
    def _address_book(self):
        if not self.sec.address_book:
            self.error(_("address book disabled (security.address_book)."))
            return
        if not vault.is_unlocked():
            self.error(_("address book unavailable: vault locked."))
            return
        idx = 0
        while True:
            contacts = sorted(vault.contacts(),
                              key=lambda c: (c.get("name") or c.get("email") or "").lower())
            n = len(contacts)
            idx = min(max(0, idx), n - 1) if n else 0
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self._bar(0, _(" Address book  (Enter write · a add · e edit · d delete · Esc back)"),
                      self._cp(C_TITLE) | curses.A_BOLD | curses.A_REVERSE)
            if not contacts:
                self._put(2, 2, _("(empty book — \"a\" to add a contact)"), self._cp(C_DIM))
            view = max(1, h - 2)
            top = max(0, idx - view + 1) if idx >= view else 0
            for row, c in enumerate(contacts[top:top + view]):
                sel = (top + row) == idx
                lock = "🔒" if autocrypt.have_key(c.get("email", "")) else "· "
                line = f" {lock} {(c.get('name') or '—')[:26]:<26} <{c.get('email', '')}>"
                if c.get("notes"):
                    line += f"   — {c['notes']}"
                self._put(1 + row, 0, line[:w - 1],
                          (curses.A_REVERSE | curses.A_BOLD) if sel else 0)
            self.stdscr.refresh()
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if is_esc(k) or k == "q":
                return
            elif k in (curses.KEY_UP, "k"):
                idx = max(0, idx - 1)
            elif k in (curses.KEY_DOWN, "j"):
                idx = min(max(0, n - 1), idx + 1)
            elif k in ("a", "A"):
                self._contact_edit(None)
            elif k in ("e", "E") and contacts:
                self._contact_edit(contacts[idx])
            elif k in ("d", curses.KEY_DC) and contacts:
                c = contacts[idx]
                if self.confirm(_("Remove {email} from the book?", email=c.get('email'))):
                    vault.remove_contact(c["email"])
                    self.status = _("contact removed.")
            elif is_enter(k) and contacts:
                self.compose_loop(ComposeState(to=contacts[idx]["email"], body=self._sig_block()))
                return

    def _contact_edit(self, existing):
        email = self._line_input(_("Contact email"), existing.get("email", "") if existing else "")
        if email is None:
            return
        email = email.strip().lower()
        if not email or "@" not in email:
            self.error(_("invalid email address."))
            return
        name = self._line_input(_("Name (optional)"), existing.get("name", "") if existing else "")
        if name is None:
            return
        notes = self._line_input(_("Notes (optional)"), existing.get("notes", "") if existing else "")
        if notes is None:
            return
        try:
            if existing and existing.get("email", "").lower() != email:
                vault.remove_contact(existing["email"])   # the email changed → remove the old one
            vault.add_contact(email, name=name.strip(), notes=notes.strip(), source="manual")
            self.status = _("✓ contact saved.")
        except vault.VaultError as e:
            self.error(str(e))

    def _learn_contact(self, email, name=""):
        """Discreet auto-learning of a contact (if book active + vault open)."""
        if self.sec.address_book and vault.is_unlocked():
            vault.learn_contact(email, name)

    # ── Framed modal windows (popup) ─────────────────────────────────────────
    def _lvl_attr(self, level):
        """Color of a log line according to its level (red for alerts)."""
        return {
            "info": self._cp(C_ACCENT),
            "ok": self._cp(C_ACCENT) | curses.A_BOLD,
            "warn": self._cp(C_WARN) | curses.A_BOLD,
            "error": self._cp(C_ERR) | curses.A_BOLD,
        }.get(level, self._cp(C_ACCENT))

    def _popup_box(self, title, lines, footer=""):
        """Framed, centered modal window (terminal/phosphor style). Each line can be a
        str (default color) or a (text, attr) pair to color it (e.g. an alert in red).
        Keeps the LAST lines if it overflows."""
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        cp = self._cp(C_ACCENT)
        norm = [(str(t), a) for (t, a) in (ln if isinstance(ln, tuple) else (ln, cp)
                                           for ln in lines)]
        avail = max(16, w - 6)
        norm = [(t[:avail], a) for (t, a) in norm]
        inner = max([len(title) + 4] + [len(t) for t, _ in norm] + [len(footer)] + [28])
        bw = min(inner + 4, w - 2)
        maxrows = max(1, h - 4 - (1 if footer else 0))
        norm = norm[-maxrows:]
        bh = len(norm) + (3 if footer else 2)
        by = max(0, (h - bh) // 2)
        bx = max(0, (w - bw) // 2)
        self._put(by, bx, (f"┌─ {title} ").ljust(bw - 1, "─")[:bw - 1] + "┐",
                  cp | curses.A_BOLD)
        for i, (t, a) in enumerate(norm):
            self._put(by + 1 + i, bx, "│", cp)
            self._put(by + 1 + i, bx + 2, t.ljust(bw - 4)[:bw - 4], a)
            self._put(by + 1 + i, bx + bw - 1, "│", cp)
        if footer:
            self._put(by + bh - 2, bx, "│ " + footer.ljust(bw - 4)[:bw - 4] + " │",
                      cp | curses.A_BOLD)
        self._put(by + bh - 1, bx, "└" + "─" * (bw - 2) + "┘", cp | curses.A_BOLD)
        self.stdscr.refresh()

    def _wait_key(self):
        while True:
            k = self._getkey()
            if k is not None and k != curses.KEY_RESIZE:
                return k

    def _confirm_popup(self, title, lines):
        """Confirmation in a popup (instead of an over-wide bar). True/False."""
        curses.curs_set(0)
        while True:
            self._popup_box(title, lines, footer=_("[y] send    [n / Esc] cancel"))
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if isinstance(k, str) and k.lower() in ("o", "y"):
                return True
            if is_esc(k) or (isinstance(k, str) and k.lower() == "n"):
                return False

    def _send_with_progress(self, acc, msg):
        """Sends while showing a verbose LOG that updates at each step (connection,
        TLS, auth, transmission, Sent copy) — so it doesn't look frozen during network
        latency. Returns True if sent."""
        import time as _t
        t0 = _t.time()
        log = []

        def step(m, level="info"):
            log.append((f"[{_t.time() - t0:5.2f}s] {m}", self._lvl_attr(level)))
            self._popup_box(_("⟩⟩ SECURE TRANSMISSION"), log, footer=_("· in progress ·"))

        try:
            if autocrypt.is_encrypted(msg):
                rcpts = len(getaddresses([msg.get("To", ""), msg.get("Cc", "")]))
                step(_("🔒 OpenPGP/MIME encryption (RFC 3156) — AES-256, signed Ed25519"), "ok")
                step(_("   sealed for {n} recipient(s) + self", n=rcpts), "ok")
            else:
                step(_("🔓 message IN CLEAR (not encrypted) — Autocrypt header attached"), "warn")
            fmail.smtp_send(acc, msg, on_step=step)
            appended = fmail.append_to_sent(acc, msg, on_step=step)
            fmail.log_sent(acc, msg)
            log.append((f"[{_t.time() - t0:5.2f}s] " + _("✓ SENT")
                        + (_("  · copy in Sent") if appended else ""), self._lvl_attr("ok")))
            self._popup_box(_("⟩⟩ TRANSMISSION — OK"), log, footer=_("[Enter] close"))
            self._wait_key()
            return True
        except NET_ERRORS as e:
            log.append(("", self._lvl_attr("info")))
            log.append((_("✗ FAILED: ") + str(e), self._lvl_attr("error")))
            self._popup_box(_("⟩⟩ TRANSMISSION — FAILED"), log, footer=_("[Enter] close"))
            self._wait_key()
            return False

    def confirm(self, question):
        curses.curs_set(0)
        while True:
            h, w = self.stdscr.getmaxyx()
            self._bar(h - 1, f" {question}  [y/N] ", self._cp(C_WARN) | curses.A_REVERSE | curses.A_BOLD)
            self.stdscr.refresh()
            k = self._getkey()
            if k is None:
                continue
            if isinstance(k, str) and k.lower() in ("o", "y"):
                return True
            if is_esc(k) or (isinstance(k, str) and k.lower() in ("n", "\n")) or is_enter(k):
                return False

    def picker(self, title, options):
        if not options:
            self.error(_("no items."))
            return None
        lm = ListModel([lbl for lbl, _v in options], height=10)
        curses.curs_set(0)
        while True:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            lm.set_height(max(1, h - 2))
            self._bar(0, _(" {title}  (↑↓ + Enter · Esc cancel)", title=title),
                      self._cp(C_TITLE) | curses.A_BOLD | curses.A_REVERSE)
            for row, (idx, lbl) in enumerate(lm.visible(), start=1):
                attr = curses.A_REVERSE | curses.A_BOLD if idx == lm.cursor else 0
                self._bar(row, "  " + lbl, attr)
            self.stdscr.refresh()
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if is_esc(k) or k in ("q",):
                return None
            elif k in (curses.KEY_UP, "k"):
                lm.move(-1)
            elif k in (curses.KEY_DOWN, "j"):
                lm.move(1)
            elif k == curses.KEY_NPAGE:
                lm.page(1)
            elif k == curses.KEY_PPAGE:
                lm.page(-1)
            elif is_enter(k):
                return options[lm.cursor][1]

    def error(self, msg):
        self._modal_text(_("Error"), msg, C_ERR)

    def _crypto_help(self):
        """Explains opportunistic encryption (Autocrypt) in plain words, for the user."""
        txt = _(
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
            "only the BODY and attachments are encrypted.\n"
        )
        self._modal_text(_("🔒 Exchanging encrypted mail — how it works"), txt, C_ACCENT)

    def help_box(self):
        text = _(
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
            "  q             quit fmail"
        )
        self._modal_text(_("Help — fmail {version}", version=fmail.__version__), text, C_TITLE)

    def _modal_text(self, title, text, color):
        curses.curs_set(0)
        lines = text.split("\n")
        top = 0
        while True:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self._bar(0, f" {title}", self._cp(color) | curses.A_BOLD | curses.A_REVERSE)
            view_h = h - 2
            top = max(0, min(top, max(0, len(lines) - view_h)))
            for i, ln in enumerate(lines[top:top + view_h]):
                self._put(1 + i, 1, ln[:w - 2])
            self._bar(h - 1, _(" ↑↓ scroll · any key to close"),
                      self._cp(C_DIM) | curses.A_REVERSE)
            self.stdscr.refresh()
            k = self._getkey()
            if k is None or k == curses.KEY_RESIZE:
                continue
            if k in (curses.KEY_DOWN, "j"):
                top += 1
            elif k in (curses.KEY_UP, "k"):
                top = max(0, top - 1)
            elif k == curses.KEY_NPAGE:
                top += (h - 3)
            elif k == curses.KEY_PPAGE:
                top = max(0, top - (h - 3))
            else:
                return

    def _safe_move(self, y, x):
        h, w = self.stdscr.getmaxyx()
        try:
            self.stdscr.move(max(0, min(y, h - 1)), max(0, min(x, w - 1)))
        except curses.error:
            pass


def run(accounts, default, account=None, sec=None):
    """Entry point called by fmail.main() when no sub-command is given."""
    i18n.set_lang(fmail.load_lang())   # honour [ui] lang even if launched directly
    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        pass
    app = App(accounts, default, account, sec)
    try:
        curses.wrapper(app.main)
    except FmailError as e:
        fmail.err(str(e))
        return e.code
    except curses.error as e:
        fmail.err(_("cannot start the interface (incompatible terminal?): {e}", e=e))
        return 1
    return 0
