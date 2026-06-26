#!/usr/bin/env python3
# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests : protection des clés SECRÈTES Autocrypt par la DEK du coffre.

Tout sur trousseaux gpg TEMPORAIRES (jamais le vrai ~/freyja-mail/.gnupg-autocrypt).
Lancer : `python3 test_autocrypt_dek.py`.

Couvre : génération protégée vs sans-passphrase (mode coffre vs sans-coffre),
compat des clés sans-passphrase, fail-closed quand le coffre est verrouillé,
et la migration (re-scellement in-place préservant les empreintes, idempotente,
vérifiée comportementalement).
"""
import os
import sys
import tempfile
from pathlib import Path

import autocrypt as ac
import vault

DEK = "d" * 64          # DEK factice (256 bits hex), comme os.urandom(32).hex()


def _home(d, name):
    h = Path(d) / name
    h.mkdir(parents=True, exist_ok=True)
    os.chmod(h, 0o700)
    return h


def _signs_with_empty(fpr, home):
    """True si la clé signe encore avec une passphrase VIDE (= NON protégée).
    Tue l'agent d'abord pour que le test ne lise pas un cache."""
    ac._kill_agent(home)
    rc, _o, _e = ac._gpg(["--armor", "--detach-sign", "--local-user", fpr],
                         home, stdin=b"probe", passphrase="")
    return rc == 0


def main():
    vault._state["dek"] = None                       # on part coffre verrouillé/absent
    try:
        # 1. session_dek() : None verrouillé, la DEK déverrouillé.
        assert vault.session_dek() is None
        vault._state["dek"] = DEK
        assert vault.session_dek() == DEK
        vault._state["dek"] = None

        with tempfile.TemporaryDirectory() as d:
            # 2. ensure_home écrit gpg-agent.conf TTL=0 (pas de cache de la clé).
            h0 = _home(d, "agentconf")
            ac.ensure_home(h0)
            conf = (h0 / "gpg-agent.conf").read_text()
            assert "default-cache-ttl 0" in conf and "max-cache-ttl 0" in conf, conf

            # 3. SANS coffre (DEK None) → clé SANS passphrase (modèle Autocrypt legacy).
            vault._state["dek"] = None
            hN = _home(d, "novault")
            fN = ac.ensure_key("user@e.org", "User", home=hN)
            assert len(fN) == 40
            assert _signs_with_empty(fN, hN), "sans coffre, la clé doit rester sans passphrase"

            # 4. COMPAT : une clé sans passphrase + DEK fournie sur le FD → marche quand même.
            ct = ac._gpg(["--armor", "--encrypt", "--sign", "--local-user", fN,
                          "--trust-model", "always", "-r", fN],
                         hN, stdin=b"compat", passphrase=DEK)
            assert ct[0] == 0, ct[2]
            ac._kill_agent(hN)
            rc, out, _e = ac._gpg(["--decrypt"], hN, stdin=ct[1], passphrase=DEK)
            assert rc == 0 and out == b"compat"

            # 5. COFFRE déverrouillé → clé générée PROTÉGÉE par la DEK.
            vault._state["dek"] = DEK
            hP = _home(d, "vault")
            fP = ac.ensure_key("alice@e.org", "Alice", home=hP)
            assert not _signs_with_empty(fP, hP), "avec coffre, la clé doit être protégée"
            # …et elle signe/chiffre avec la DEK :
            ct2 = ac._gpg_encrypt(b"top secret", [fP], fP, hP)
            ac._kill_agent(hP)
            vault._state["dek"] = DEK
            rc, out, _e = ac._gpg(["--decrypt"], hP, stdin=ct2, passphrase=DEK)
            assert rc == 0 and out == b"top secret"

            # 6. FAIL-CLOSED : coffre VERROUILLÉ (DEK None) → pas de déchiffrement, pas de signature.
            vault._state["dek"] = None
            ac._kill_agent(hP)
            rc, out, _e = ac._gpg(["--status-fd", "2", "--decrypt"], hP, stdin=ct2,
                                  passphrase=ac._key_passphrase())   # None → pas de FD
            assert rc != 0 and not out, "déchiffrement verrouillé : doit échouer sans clair"
            ac._kill_agent(hP)
            raised = False
            try:
                ac._gpg_encrypt(b"x", [fP], fP, hP)   # _key_passphrase() == None
            except ac.AutocryptError:
                raised = True
            assert raised, "signature verrouillée : doit lever (envoi refusé, jamais en clair)"

            # 7. MIGRATION : un trousseau sans passphrase → protégé, EMPREINTES préservées,
            #    idempotent, vérifié.
            vault._state["dek"] = None
            hM = _home(d, "migrate")
            fM = ac.ensure_key("bob@e.org", "Bob", home=hM)
            assert _signs_with_empty(fM, hM)
            # courrier chiffré AVANT migration (avec la clé sans passphrase) :
            pre = ac._gpg(["--armor", "--encrypt", "--sign", "--local-user", fM,
                           "--trust-model", "always", "-r", fM],
                          hM, stdin=b"vieux courrier", passphrase=None)[1]
            rep = ac.migrate_secret_keys(DEK, home=hM)
            assert rep == {"keys": 1, "resealed": 1}, rep
            assert not _signs_with_empty(fM, hM), "après migration : plus de signature sans passphrase"
            # empreinte préservée → l'ancien courrier se déchiffre avec la DEK :
            ac._kill_agent(hM)
            rc, out, _e = ac._gpg(["--decrypt"], hM, stdin=pre, passphrase=DEK)
            assert rc == 0 and out == b"vieux courrier", "l'empreinte doit être préservée"
            # idempotent : re-run = no-op
            assert ac.migrate_secret_keys(DEK, home=hM) == {"keys": 1, "resealed": 0}
            # migration refusée si la DEK est absente :
            r2 = False
            try:
                ac.migrate_secret_keys("", home=hM)
            except ac.AutocryptError:
                r2 = True
            assert r2, "migration sans DEK : doit lever"

        print("✅ test_autocrypt_dek : protection DEK, compat, fail-closed, migration (trousseaux temporaires)")
        return 0
    finally:
        vault._state["dek"] = None                   # ne pas fuiter l'état entre tests


if __name__ == "__main__":
    sys.exit(main())
