#!/usr/bin/env python3
# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""Régressions de SÉCURITÉ transverses de fmail (épinglage TLS, pièces jointes,
journal d'envoi, bornes mémoire, signal de confiance). Couvre les 3 bloquants HIGH
du grand audit + les correctifs MEDIUM du re-audit. Tout sur artefacts TEMPORAIRES
— jamais la vraie boîte, le vrai coffre, le vrai magasin d'épingles. Lancer :
`python3 test_security.py`."""
import email.message
import hashlib
import inspect
import os
import stat
import tempfile
import types
from pathlib import Path

import fmail
import fmail_tui


class _FakeSock:
    """Socket TLS factice : getpeercert(binary_form=True) → DER contrôlé."""
    def __init__(self, der, issuer="Test CA"):
        self._der, self._issuer = der, issuer

    def getpeercert(self, binary_form=False):
        if binary_form:
            return self._der
        return {"issuer": ((("organizationName", self._issuer),),)}

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


def test_tls_pinning_fail_closed():
    """HIGH #1 : sur changement de certificat, l'épinglage ne s'écrase JAMAIS et le
    statut 'changed' est renvoyé (l'appelant refuse la connexion, fail-closed)."""
    with tempfile.TemporaryDirectory() as d:
        fmail.TLS_PINS = Path(d) / ".tls_pins.json"
        fmail._tls_accepted.clear()
        s1 = _FakeSock(b"cert-A")
        assert fmail._tls_check("imap.x", 993, s1)[0] == "new"   # 1er vu → épinglé
        assert fmail._tls_check("imap.x", 993, s1)[0] == "ok"    # même → reconnu
        s2 = _FakeSock(b"cert-B-MITM")
        status, fpr, issuer = fmail._tls_check("imap.x", 993, s2)
        assert status == "changed"                                # changé → REFUS
        # le pin de confiance N'A PAS été écrasé (un MITM persistant ré-alerte)
        import json
        pinned = json.loads(fmail.TLS_PINS.read_text())["imap.x:993"]["fpr"]
        assert pinned == hashlib.sha256(b"cert-A").hexdigest()
        assert fmail._tls_check("imap.x", 993, s2)[0] == "changed"
        # acceptation explicite (après vérification humaine) → adopte
        fmail.accept_cert("imap.x", 993, fpr, issuer)
        assert fmail._tls_check("imap.x", 993, s2)[0] == "ok"
        # certificat illisible → 'unknown' (jamais épinglé par erreur)
        assert fmail._tls_check("imap.y", 993, _FakeSock(b""))[0] in ("unknown", "new")


def test_report_tls_arity():
    """Re-audit (completeness) : _report_tls(sock, host, port, step) — l'appel TUI doit
    passer 4 arguments, sinon TypeError plantait le TUI au démarrage."""
    assert list(inspect.signature(fmail._report_tls).parameters) == ["sock", "host", "port", "step"]
    src = Path("fmail_tui.py").read_text(encoding="utf-8")
    assert 'fmail._report_tls(getattr(M, "sock", None), acc.imap_host, acc.imap_port, step)' in src


def test_write_attachment_safe():
    """HIGH #3 + bidi : écriture de PJ sûre (anti-traversée, 0600, anti-écrasement) et
    noms débarrassés des caractères de surcharge bidirectionnelle (usurpation d'extension)."""
    app = fmail_tui.App.__new__(fmail_tui.App)
    with tempfile.TemporaryDirectory() as d:
        dest = Path(d) / "dest"
        dest.mkdir()
        # traversée de chemin neutralisée
        p = app._write_attachment(dest, "../../../../tmp/fmail-pwned", b"x")
        assert p.parent == dest and not Path("/tmp/fmail-pwned").exists()
        # permissions 0600
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
        # anti-écrasement (chemins uniques)
        a = app._write_attachment(dest, "doc.txt", b"1")
        b = app._write_attachment(dest, "doc.txt", b"2")
        assert a != b and a.read_bytes() == b"1" and b.read_bytes() == b"2"
        # surcharge bidi retirée du nom écrit, vraie extension conservée
        q = app._write_attachment(dest, "photo‮gpj.exe", b"z")
        assert "‮" not in q.name and q.name.endswith(".exe")


def test_filename_display_sanitized():
    """bidi : le filtre d'affichage retire les caractères de formatage invisibles (Cf)."""
    for cp in (0x202E, 0x202D, 0x2066, 0x200B, 0x200F, 0x2060, 0xFEFF):
        assert fmail_tui._FORMAT_CTRL_RE.sub("", chr(cp)) == ""
    assert fmail_tui._FORMAT_CTRL_RE.sub("", "rapport éàç.pdf") == "rapport éàç.pdf"


def test_sent_log_masks_encrypted():
    """Re-audit (INFO) : sent.log ne recopie pas To/Sujet en clair pour un envoi chiffré.
    Vérifié dans les DEUX langues (le marqueur chiffré est traduit via _())."""
    import i18n
    for lang, marker in (("en", "[encrypted]"), ("fr", "[chiffré]")):
        i18n.set_lang(lang)
        with tempfile.TemporaryDirectory() as d:
            fmail.SENT_LOG = Path(d) / "sent.log"
            fmail.SENT_LOG.write_text("ancien\n")     # préexistant, mode large
            os.chmod(fmail.SENT_LOG, 0o644)
            acc = types.SimpleNamespace(email="moi@ex.org")
            clear = email.message.EmailMessage()
            clear["To"], clear["Subject"] = "bob@ex.org", "Sujet secret"
            fmail.log_sent(acc, clear)
            enc = email.message.EmailMessage()
            enc["To"], enc["Subject"] = "bob@ex.org", "Sujet secret"
            enc.set_type("multipart/encrypted")
            fmail.log_sent(acc, enc)
            log = fmail.SENT_LOG.read_text()
            assert log.count("bob@ex.org") == 1 and log.count("Sujet secret") == 1
            assert marker in log                      # masqué (marqueur dans la bonne langue)
            assert stat.S_IMODE(os.stat(fmail.SENT_LOG).st_mode) == 0o600
    i18n.set_lang("auto")


def test_message_size_guard():
    """mem-1 : RFC822.SIZE pré-contrôlé ; un message au-delà du plafond est refusé."""
    class FakeM:
        def __init__(self, n):
            self.n = n

        def uid(self, *a):
            if a[2] == "(RFC822.SIZE)":
                return ("OK", [f"1 (UID 5 RFC822.SIZE {self.n})".encode()])
            raise AssertionError("BODY.PEEK[] atteint malgré un message trop gros")

    assert fmail.message_size(FakeM(4567), "5") == 4567
    assert fmail.message_size(FakeM(0), "5") == 0
    fmail._guard_message_size(FakeM(1000), "5")        # sous le plafond : OK
    try:
        fmail._guard_message_size(FakeM(fmail.MAX_MESSAGE_BYTES + 1), "5")
        raise AssertionError("message géant accepté (DoS mémoire)")
    except fmail.FmailError:
        pass


def test_reader_trust_color_gated():
    """med-36 (HIGH) : la couleur de l'en-tête du lecteur est gâchée sur le RÉSULTAT du
    déchiffrement (dec_ok), pas sur la seule structure → pas de faux signal vert."""
    src = Path("fmail_tui.py").read_text(encoding="utf-8")
    assert "dec_ok = encrypted and content_msg is not None" in src
    assert "self._cp(C_ACCENT) if dec_ok" in src and "else self._cp(C_ERR) if encrypted" in src


def test_reply_from_list_prearms():
    """med-21 : répondre/transférer depuis la LISTE propage l'état chiffré (fail-closed,
    y compris un statut non encore sondé = None traité comme chiffré)."""
    src = Path("fmail_tui.py").read_text(encoding="utf-8")
    assert 'encrypted=(getattr(cur, "encrypted", False) is not False)' in src


def test_cache_relock_no_residue():
    """relock-1 : au re-verrouillage, le cache est re-chiffré + effacé (aucun clair
    résiduel) et le thread de synchro ne peut PAS réécrire de clair pendant le verrou."""
    import glob
    import threading
    import vault
    import fmail_store
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        fmail.CONFIG_PATH = d / "accounts.toml"
        fmail.CONFIG_PATH.write_text("[accounts.dm]\nemail='a@b.c'\nimap_host='x'\npassword_file=''\n")
        vault.VAULT_PATH = d / "vault.gpg"
        vault.VAULT_HOME = d / "gh"
        vault.create("MasterPass-Costaud-42", accounts={"dm": "pw"},
                     path=vault.VAULT_PATH, home=vault.VAULT_HOME)
        vault.unlock("MasterPass-Costaud-42", path=vault.VAULT_PATH, home=vault.VAULT_HOME)
        a = fmail_tui.App.__new__(fmail_tui.App)
        a.sec = fmail.Security(master_password=True, encrypt_cache=True)
        a.status = ""
        a._sync_lock = threading.Lock()
        a._poll_lock = threading.Lock()
        a._cache_closed = False
        a._cache_work = None
        a._open_cache()
        assert a._cache_closed is False and a.store is not None
        a.store.set_folder_state("dm", "INBOX", 7, 7, 1.0)
        work = Path(a._cache_work)
        a._close_cache()                          # = ce que fait _do_relock avant vault.lock
        assert a._cache_closed is True and a.store is None
        enc = d / ".fmail_cache.db.gpg"
        clear = [f for f in glob.glob(str(d / ".fmail_cache.db*")) if not f.endswith(".gpg")]
        assert enc.exists() and clear == [] and glob.glob(str(work) + "*") == []
        # la synchro doit refuser d'écrire tant que le cache est fermé
        a._active = ("dm", "INBOX")
        a._synced, a._full_next, a._sync_cycles = set(), set(), {}
        a._sync_conn = lambda n: object()
        called = {"sync": False}
        orig = fmail_store.sync_folder
        fmail_store.sync_folder = lambda *x, **y: called.__setitem__("sync", True)
        try:
            a._sync_active_folder()
        finally:
            fmail_store.sync_folder = orig
        assert called["sync"] is False
        # ré-ouverture → données intactes
        a._open_cache()
        st = a.store.folder_state("dm", "INBOX")
        a._close_cache()
        assert st and st["uidvalidity"] == 7


def test_uninstall_protects_vault():
    """Re-audit HIGH: the in-app uninstall guard must protect the HARDCODED vault dir,
    not only CONFIG_PATH.parent — else rmtree(app_dir) could destroy vault.gpg/keys."""
    import vault
    app = fmail_tui.App.__new__(fmail_tui.App)
    app._cache_enc = None
    app_dir = Path(fmail_tui.__file__).resolve().parent
    save = (fmail.CONFIG_PATH, vault.VAULT_PATH, vault.VAULT_HOME)
    try:
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            # config + GNUPGHOME moved ELSEWHERE, but the vault still sits in app_dir:
            fmail.CONFIG_PATH = d / "accounts.toml"
            vault.VAULT_HOME = d / "gnupghome"
            vault.VAULT_PATH = app_dir / "vault.gpg"     # vault inside the program dir
            _a, _w, clash = app._uninstall_paths()
            assert clash is not None, "uninstall would delete the vault dir (HIGH not fixed)"
            # fully separate layout (nothing overlaps app_dir) → safe (no clash)
            vault.VAULT_PATH = d / "vault.gpg"
            _a, _w, clash2 = app._uninstall_paths()
            assert clash2 is None, f"false-positive clash: {clash2}"
    finally:
        fmail.CONFIG_PATH, vault.VAULT_PATH, vault.VAULT_HOME = save


def test_wizard_cannot_brick():
    """Re-audit HIGH: encryption is only offered WITH an account, and App.main has a
    chokepoint that refuses to proceed (clean FmailError) when self.acc is None."""
    src = Path("fmail_tui.py").read_text(encoding="utf-8")
    assert "if self.accounts and not fmail.security_configured():" in src
    assert "if self.acc is None:" in src and "_open_cache()" in src


def test_emergency_wipe_scope():
    """DURESS wipe: destroys THIS fmail's data + the per-account password files, but
    NEVER the rest of ~/secrets, unrelated files, the program, or accounts.toml.example.
    All on TEMPORARY paths (globals monkeypatched + restored)."""
    import vault
    import autocrypt
    save = {
        "cfg": fmail.CONFIG_PATH, "state": fmail.STATE_PATH, "sent": fmail.SENT_LOG,
        "tls": fmail.TLS_PINS, "sig": fmail.SIGNATURE_DIR, "shm": fmail.SHM_DIR,
        "vp": vault.VAULT_PATH, "vh": vault.VAULT_HOME,
        "ah": autocrypt.AUTOCRYPT_HOME, "pdb": autocrypt.PEERS_DB,
        "home": os.environ.get("HOME"),
    }
    try:
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            os.environ["HOME"] = str(d)     # ~/secrets maps to the TEMP dir (safety + scope)
            data = d / "freyja-mail"; data.mkdir()
            secrets = d / "secrets"; secrets.mkdir()
            (d / "shm").mkdir()
            fmail.CONFIG_PATH = data / "accounts.toml"
            fmail.STATE_PATH = data / ".fmail_state.json"
            fmail.SENT_LOG = data / "sent.log"
            fmail.TLS_PINS = data / ".tls_pins.json"
            fmail.SIGNATURE_DIR = data / "signatures"
            fmail.SHM_DIR = str(d / "shm")
            vault.VAULT_PATH = data / "vault.gpg"; vault.VAULT_HOME = data / ".gnupg-vault"
            autocrypt.AUTOCRYPT_HOME = data / ".gnupg-autocrypt"; autocrypt.PEERS_DB = data / ".autocrypt.db"
            pwf = secrets / "dm_mail_password"; pwf.write_text("imap-secret\n")
            fmail.CONFIG_PATH.write_text(
                f'[accounts.dm]\nemail="a@b.c"\nimap_host="x"\npassword_file="{pwf}"\n')
            # fmail data to be DESTROYED
            vault.VAULT_PATH.write_bytes(b"VAULTCIPHER")
            for dd, f in ((vault.VAULT_HOME, "trustdb.gpg"), (autocrypt.AUTOCRYPT_HOME, "secring")):
                dd.mkdir(); (dd / f).write_bytes(b"key")
            autocrypt.PEERS_DB.write_bytes(b"db")
            (data / ".fmail_cache.db.gpg").write_bytes(b"cache")
            fmail.SENT_LOG.write_text("log"); fmail.STATE_PATH.write_text("{}"); fmail.TLS_PINS.write_text("{}")
            fmail.SIGNATURE_DIR.mkdir(); (fmail.SIGNATURE_DIR / "dm.sig").write_text("sig")
            (data / "drafts").mkdir(); (data / "drafts" / "d1").write_text("draft")
            (data / "notified_uids.txt").write_text("1")
            (d / "shm" / f"fmail-cache-{os.getuid()}-1.db").write_bytes(b"plain")
            # files that MUST SURVIVE (non-fmail secrets, unrelated, program, template)
            survivors = {
                "sudo": secrets / "sudo", "github": secrets / "github",
                "outside": d / "keepme.txt", "program": data / "fmail.py",
                "template": data / "accounts.toml.example",
            }
            for p in survivors.values():
                p.write_text("KEEP")

            fmail.emergency_wipe()

            destroyed = [vault.VAULT_PATH, vault.VAULT_HOME, autocrypt.AUTOCRYPT_HOME,
                         autocrypt.PEERS_DB, data / ".fmail_cache.db.gpg", fmail.SENT_LOG,
                         fmail.STATE_PATH, fmail.TLS_PINS, fmail.SIGNATURE_DIR,
                         fmail.CONFIG_PATH, pwf]
            still = [p for p in destroyed if p.exists()]
            assert not still, f"NOT wiped (leak): {still}"
            gone = [k for k, p in survivors.items() if not p.exists()]
            assert not gone, f"wrongly destroyed (over-wipe): {gone}"
    finally:
        fmail.CONFIG_PATH, fmail.STATE_PATH, fmail.SENT_LOG = save["cfg"], save["state"], save["sent"]
        fmail.TLS_PINS, fmail.SIGNATURE_DIR, fmail.SHM_DIR = save["tls"], save["sig"], save["shm"]
        vault.VAULT_PATH, vault.VAULT_HOME = save["vp"], save["vh"]
        autocrypt.AUTOCRYPT_HOME, autocrypt.PEERS_DB = save["ah"], save["pdb"]
        if save["home"] is not None:
            os.environ["HOME"] = save["home"]


def test_emergency_wipe_no_escape():
    """Red team CRITICAL: a hostile/typo password_file (a DIRECTORY, '~', a path OUTSIDE
    ~/secrets, a symlink pointing out) must NEVER make the wipe escape its scope. And the
    macOS fallback cache (no /dev/shm) MUST be wiped. HOME is redirected to a temp dir so
    even a validation bug could only touch throwaway paths."""
    import vault
    import autocrypt
    save = {k: getattr(fmail, a) for k, a in (("cfg", "CONFIG_PATH"), ("state", "STATE_PATH"),
            ("sent", "SENT_LOG"), ("tls", "TLS_PINS"), ("sig", "SIGNATURE_DIR"), ("shm", "SHM_DIR"))}
    save["vp"], save["vh"] = vault.VAULT_PATH, vault.VAULT_HOME
    save["ah"], save["pdb"] = autocrypt.AUTOCRYPT_HOME, autocrypt.PEERS_DB
    save["home"] = os.environ.get("HOME")
    try:
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            os.environ["HOME"] = str(d)                 # ~ and ~/secrets → temp (SAFE)
            data = d / "freyja-mail"; data.mkdir()
            secrets = d / "secrets"; secrets.mkdir()
            fmail.CONFIG_PATH = data / "accounts.toml"
            fmail.STATE_PATH = data / ".s"; fmail.SENT_LOG = data / "sent.log"
            fmail.TLS_PINS = data / ".tls"; fmail.SIGNATURE_DIR = data / "sig"
            fmail.SHM_DIR = str(d / "noshm")            # absent → macOS-like disk fallback
            vault.VAULT_PATH = data / "vault.gpg"; vault.VAULT_HOME = data / ".gnupg-vault"
            autocrypt.AUTOCRYPT_HOME = data / ".ac"; autocrypt.PEERS_DB = data / ".acdb"
            vault.VAULT_PATH.write_bytes(b"V")
            legit = secrets / "dm_mail_password"; legit.write_text("creds")   # referenced → wiped
            # hostile password_file values + things that MUST survive
            outside_dir = d / "Documents"; outside_dir.mkdir(); (outside_dir / "taxes.pdf").write_text("$$$")
            outside_file = d / "important.txt"; outside_file.write_text("keep")
            keep_sudo = secrets / "sudo"; keep_sudo.write_text("SUDO")        # in ~/secrets but NOT referenced
            sym_target = d / "elsewhere_secret"; sym_target.write_text("x")
            sym = secrets / "link_pw"
            try:
                sym.symlink_to(sym_target)
            except OSError:
                sym = None
            # HARDLINK inside ~/secrets to a file OUTSIDE roots: the shared inode's content
            # must NOT be overwritten (st_nlink>1 → rejected).
            hl_victim = d / "hardlink_victim"; hl_victim.write_text("SHARED-INODE-DATA")
            hl = secrets / "hardlink_pw"
            try:
                os.link(hl_victim, hl)
            except OSError:
                hl = None
            cfg = (f'[accounts.a]\nemail="a@b.c"\nimap_host="x"\npassword_file="{legit}"\n'
                   f'[accounts.b]\nemail="b@b.c"\nimap_host="x"\npassword_file="{outside_dir}"\n'   # a DIR
                   f'[accounts.c]\nemail="c@b.c"\nimap_host="x"\npassword_file="~"\n'                # HOME
                   f'[accounts.e]\nemail="e@b.c"\nimap_host="x"\npassword_file="{outside_file}"\n')  # outside roots
            if sym:
                cfg += f'[accounts.f]\nemail="f@b.c"\nimap_host="x"\npassword_file="{sym}"\n'         # symlink out
            if hl:
                cfg += f'[accounts.g]\nemail="g@b.c"\nimap_host="x"\npassword_file="{hl}"\n'          # hardlink-out
            fmail.CONFIG_PATH.write_text(cfg)
            cwf = data / f"fmail-cache-{os.getuid()}-9999.db"; cwf.write_bytes(b"PLAINTEXT-MAILS")

            fmail.emergency_wipe()

            # destroyed: referenced creds, vault, AND the macOS fallback cache
            assert not legit.exists(), "referenced creds not wiped"
            assert not vault.VAULT_PATH.exists()
            assert not cwf.exists(), "macOS fallback cache survived the wipe (CRITICAL)"
            # NOTHING out of scope touched
            assert outside_dir.exists() and (outside_dir / "taxes.pdf").exists(), "DIR password_file → over-wipe!"
            assert outside_file.exists(), "outside-root password_file wiped"
            assert keep_sudo.exists(), "~/secrets/sudo (unreferenced) wiped"
            assert (d / "important.txt").exists()
            if sym:
                assert sym_target.exists(), "symlink-out target wiped"
            if hl:
                assert hl_victim.read_text() == "SHARED-INODE-DATA", "hardlink-shared inode content destroyed"
    finally:
        for k, a in (("cfg", "CONFIG_PATH"), ("state", "STATE_PATH"), ("sent", "SENT_LOG"),
                     ("tls", "TLS_PINS"), ("sig", "SIGNATURE_DIR"), ("shm", "SHM_DIR")):
            setattr(fmail, a, save[k])
        vault.VAULT_PATH, vault.VAULT_HOME = save["vp"], save["vh"]
        autocrypt.AUTOCRYPT_HOME, autocrypt.PEERS_DB = save["ah"], save["pdb"]
        if save["home"] is not None:
            os.environ["HOME"] = save["home"]


def test_close_cache_no_freeze():
    """Quit/relock bug: _close_cache must NOT block forever when the sync thread holds
    _sync_lock (long initial sync). It waits bounded, then proceeds best-effort and STILL
    wipes the cleartext. Here the lock is held and NEVER released."""
    import glob
    import threading
    import time as _t
    import vault
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        fmail.CONFIG_PATH = d / "accounts.toml"
        fmail.CONFIG_PATH.write_text("[accounts.dm]\nemail='a@b.c'\nimap_host='x'\npassword_file=''\n")
        vault.VAULT_PATH = d / "vault.gpg"; vault.VAULT_HOME = d / "gh"
        vault.create("MasterPass-Costaud-42", accounts={"dm": "pw"},
                     path=vault.VAULT_PATH, home=vault.VAULT_HOME)
        vault.unlock("MasterPass-Costaud-42", path=vault.VAULT_PATH, home=vault.VAULT_HOME)
        a = fmail_tui.App.__new__(fmail_tui.App)
        a.sec = fmail.Security(master_password=True, encrypt_cache=True)
        a.status = ""; a._sync_lock = threading.Lock(); a._cache_closed = False; a._cache_work = None
        a._open_cache()
        a.store.set_folder_state("dm", "INBOX", 7, 7, 1.0)
        work = Path(a._cache_work)
        a._sync_lock.acquire()                       # simulate a stuck/long in-flight sync (never released)
        t0 = _t.time()
        a._close_cache()                             # must return (bounded), not freeze
        elapsed = _t.time() - t0
        assert elapsed < 9, f"_close_cache blocked too long ({elapsed:.0f}s) — freeze not fixed"
        assert a._cache_closed is True
        enc = d / ".fmail_cache.db.gpg"
        clear = [f for f in glob.glob(str(d / ".fmail_cache.db*")) if not f.endswith(".gpg")]
        assert enc.exists() and clear == [] and glob.glob(str(work) + "*") == [], \
            "cleartext not wiped on best-effort close"
        a._sync_lock.release()


def test_self_update():
    """In-app update: SHA-256 verified, all-or-nothing, config NEVER clobbered, hostile
    manifest names ignored. Served from a local file:// 'release' (no network)."""
    import hashlib
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        remote = d / "release"; remote.mkdir()
        app = d / "app"; app.mkdir()
        data = d / "data"; data.mkdir()
        (app / "fmail.py").write_text("# OLD program\n")
        keep_cfg = data / "accounts.toml"; keep_cfg.write_text("[accounts.me]\n")  # must survive
        # build the 'release'
        newpy = "# NEW program v9\n"
        (remote / "fmail.py").write_text(newpy)
        (remote / "VERSION").write_text("9.9.9-beta\n")
        (remote / "accounts.toml.example").write_text("# new template\n")
        def sha(p):
            return hashlib.sha256(p.read_bytes()).hexdigest()
        sums = "".join(f"{sha(remote/n)}  {n}\n" for n in ("fmail.py", "VERSION", "accounts.toml.example"))
        sums += "deadbeef" * 8 + "  ../../etc/evil\n"        # hostile name → must be ignored
        sums += hashlib.sha256(b"x").hexdigest() + "  evil.sh\n"  # non-fmail kind → ignored
        (remote / "SHA256SUMS").write_text(sums)
        base = "file://" + str(remote)

        # check_update: remote differs from our version → not up to date
        ver, uptodate = fmail.check_update(base)
        assert ver == "9.9.9-beta" and uptodate is False
        # self_update installs the new files
        newv = fmail.self_update(app, data, base)
        assert newv == "9.9.9-beta"
        assert (app / "fmail.py").read_text() == newpy           # program replaced
        assert (app / "VERSION").read_text().strip() == "9.9.9-beta"
        assert (data / "accounts.toml.example").read_text() == "# new template\n"
        assert keep_cfg.read_text() == "[accounts.me]\n"         # CONFIG NOT clobbered
        assert not (app / "evil.sh").exists() and not (d / "etc").exists()  # hostile names ignored

        # all-or-nothing: a corrupted manifest entry aborts WITHOUT writing anything
        (app / "fmail.py").write_text("# OLD again\n")
        bad = sums.replace(sha(remote / "fmail.py"), "0" * 64)   # wrong hash for fmail.py
        (remote / "SHA256SUMS").write_text(bad)
        try:
            fmail.self_update(app, data, base)
            raise AssertionError("checksum mismatch not detected")
        except fmail.FmailError:
            pass
        assert (app / "fmail.py").read_text() == "# OLD again\n"  # untouched on failure


def test_update_dev_guard_source():
    """The update flow refuses to self-update from the data/dev dir (reuses the uninstall
    clash guard) and is wired in the Config menu."""
    src = Path("fmail_tui.py").read_text(encoding="utf-8")
    assert '"__update__"' in src and "_update_flow" in src
    body = src.split("def _update_flow", 1)[1][:500]      # the method definition
    assert "_uninstall_paths()" in body and "clash" in body


def test_mouse_reporting_disabled():
    """fmail must never let stray trackpad/mouse signals turn into commands: at startup
    it disables EVERY mouse-tracking mode (…l) and enables NONE (…h), and _getkey drains
    a parsed KEY_MOUSE event to None so its bytes can't reach a command handler."""
    app = fmail_tui.App.__new__(fmail_tui.App)
    captured = {}
    orig = os.write
    os.write = lambda fd, b: (captured.__setitem__("fd", fd), captured.__setitem__("b", b), len(b))[-1]
    try:
        app._mouse_off()
    finally:
        os.write = orig
    b = captured["b"]
    assert captured["fd"] == 1                                  # the controlling terminal
    for mode in (b"1000l", b"1002l", b"1003l", b"1005l", b"1006l", b"1015l"):
        assert mode in b, f"mouse mode {mode!r} not disabled"
    assert b"h" not in b, "must NEVER enable mouse reporting (no …h)"
    # the input chokepoint swallows a parsed mouse event instead of dispatching it,
    # and the disable is actually wired at startup
    src = Path("fmail_tui.py").read_text(encoding="utf-8")
    body = src.split("def _getkey", 1)[1].split("\n    def ", 1)[0]   # the whole _getkey method
    assert "curses.KEY_MOUSE" in body and "curses.getmouse()" in body
    assert "self._mouse_off()" in src.split("def main", 1)[1][:400]


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ✓ {name}")
    print("✅ test_security : toutes les régressions de sécurité passent (artefacts temporaires)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
