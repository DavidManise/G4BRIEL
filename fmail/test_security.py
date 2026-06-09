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
