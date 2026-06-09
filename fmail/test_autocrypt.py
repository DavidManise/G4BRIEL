#!/usr/bin/env python3
# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests Autocrypt fmail — sur trousseaux gpg + bases TEMPORAIRES (jamais la vraie
boîte ni le vrai trousseau). Lancer : `python3 test_autocrypt.py`.

Couvre les primitives ET une régression par faille corrigée lors de la revue
adversariale (chiffrement par empreinte, DECRYPTION_OKAY obligatoire, fraîcheur en
epoch, validation de clé importée, anti-RFC2047, brouillon chiffré, Cci hors Sent).
"""
import base64
import email
import sys
import tempfile
import types
from email.mime.multipart import MIMEMultipart
from email.message import Message
from pathlib import Path

import autocrypt as ac


def _acc(addr, name="X"):
    return types.SimpleNamespace(
        from_header=lambda: f"{name} <{addr}>", email=addr, display_name=name)


def _register(addr, src_home, dst_home, db, epoch, prefer="mutual"):
    """Apprend la clé de `addr` (exportée de src_home) dans dst_home + db, comme le
    ferait _autocrypt_learn → update_peer à la réception d'un mail."""
    hv = ac.header_value(addr, prefer=prefer, home=src_home)
    parsed = ac.parse_header(hv)
    ac.update_peer(addr, epoch, parsed, db_path=db, home=dst_home)
    return parsed


def _wrap_octet(cipher_ascii, version="Version: 1", n_octet=1, ctype_ok=True):
    """Fabrique une enveloppe multipart/encrypted arbitraire (pour les tests de
    robustesse de decrypt_message)."""
    outer = MIMEMultipart("encrypted", protocol="application/pgp-encrypted")
    v = Message(); v.set_type("application/pgp-encrypted"); v.set_payload(version)
    outer.attach(v)
    for _ in range(n_octet):
        e = Message()
        e.set_type("application/octet-stream" if ctype_ok else "text/plain")
        e.set_payload(cipher_ascii)
        outer.attach(e)
    return outer


def main():
    with tempfile.TemporaryDirectory() as d:
        hA, hB, hC = Path(d) / "A", Path(d) / "B", Path(d) / "C"
        pdb = Path(d) / "peers.db"
        T = 1_700_000_000          # epoch de référence (instant, pas une chaîne)

        # 1. génération + idempotence + sous-clé de chiffrement
        fA = ac.ensure_key("alice@e.org", "Alice", home=hA)
        assert len(fA) == 40 and ac.ensure_key("alice@e.org", "Alice", home=hA) == fA
        fB = ac.ensure_key("bob@e.org", "Bob", home=hB)
        ac.ensure_key("eve@e.org", "Eve", home=hC)
        rc, out, _ = ac._gpg(["--list-keys", "--with-colons", "<alice@e.org>"], hA)
        assert any(l.startswith("sub:") for l in out.decode().splitlines())
        # Bob et Eve/Carol doivent connaître la clé d'Alice pour VÉRIFIER sa signature.
        alice_pub = ac.export_pubkey("alice@e.org", home=hA)
        ac.import_pubkey(alice_pub, "alice@e.org", home=hB)
        ac.import_pubkey(alice_pub, "alice@e.org", home=hC)

        # 2. en-tête build/parse + import croisé (empreinte identique)
        hv = ac.header_value("bob@e.org", prefer="mutual", home=hB)
        p = ac.parse_header(hv)
        assert p and p["addr"] == "bob@e.org" and p["prefer_encrypt"] == "mutual"
        assert ac.key_fpr_from_data(p["keydata"], home=hA) == fB
        assert ac.import_pubkey(p["keydata"], "bob@e.org", home=hA) == fB

        # 3. validation de clé importée (anti-empoisonnement)
        assert ac.validate_peer_key(p["keydata"], "bob@e.org", home=hA) == fB
        assert ac.validate_peer_key(p["keydata"], "autre@e.org", home=hA) is None  # addr != uid
        #   clé avec UID supplémentaire d'un tiers → refusée (empoisonnement key-UID)
        ac.ensure_key("mallory@evil.org", "Mallory", home=hB)
        ac._gpg(["--quick-add-uid", "<mallory@evil.org>", "Boss <ceo@corp.com>"], hB)
        rc, mpub, _ = ac._gpg(["--export", "<mallory@evil.org>"], hB)
        assert ac.validate_peer_key(mpub, "mallory@evil.org", home=hA) is None, \
            "clé multi-UID (tiers) acceptée → empoisonnement possible"
        #   UID dont l'email == addr MAIS portant un commentaire contenant '@' → refusé
        #   (anti-trick : le commentaire pourrait tromper une résolution par adresse)
        hT = Path(d) / "Trick"
        ac.ensure_home(hT)
        ac._gpg(["--passphrase", "", "--quick-generate-key",
                 "Trickster (backup victim@corp.com) <trickster@e.org>",
                 "default", "default", "never"], hT)
        rc, tpub, _ = ac._gpg(["--export", "<trickster@e.org>"], hT)
        assert tpub and ac.validate_peer_key(tpub, "trickster@e.org", home=hA) is None, \
            "UID à commentaire contenant '@' accepté"
        #   blob multi-clés → refusé
        twokeys = ac.export_pubkey("bob@e.org", home=hB) + ac.export_pubkey("eve@e.org", home=hC)
        assert ac.validate_peer_key(twokeys, "bob@e.org", home=hA) is None
        #   clé SECRÈTE déguisée → refusée
        rc, sec, _ = ac._gpg(["--export-secret-keys", "<bob@e.org>"], hB)
        assert sec and ac.validate_peer_key(sec, "bob@e.org", home=hA) is None
        #   keydata surdimensionné → refusé
        assert ac.validate_peer_key(b"x" * (ac.MAX_KEYDATA + 1), "bob@e.org", home=hA) is None

        # 4. magasin de pairs + fraîcheur EN EPOCH (instants, pas chaînes)
        _register("bob@e.org", hB, hA, pdb, T)
        assert ac.have_key("bob@e.org", db_path=pdb)
        bob_fpr_1 = ac.get_peer("bob@e.org", db_path=pdb)["fpr"]
        assert bob_fpr_1 == fB
        #   un mail PLUS ANCIEN ne doit pas écraser la clé
        old_parsed = ac.parse_header(ac.header_value("bob@e.org", home=hB))
        ac.update_peer("bob@e.org", T - 99999, old_parsed, db_path=pdb, home=hA)
        assert ac.get_peer("bob@e.org", db_path=pdb)["fpr"] == bob_fpr_1, "un vieux mail a écrasé la clé"
        #   un mail de MÊME instant ne remplace pas non plus (strictement plus récent requis)
        ac.update_peer("bob@e.org", T, old_parsed, db_path=pdb, home=hA)
        assert ac.get_peer("bob@e.org", db_path=pdb)["fpr"] == bob_fpr_1
        #   pas de ligne créée pour un From sans clé (anti-DoS de croissance)
        ac.update_peer("spammer@e.org", T, None, db_path=pdb, home=hA)
        assert ac.get_peer("spammer@e.org", db_path=pdb) is None

        # 5. PINNING anti-TOFU (test isolé, db + adresse dédiées pour ne pas polluer bob) :
        #    changement de clé d'un pair connu → la clé de confiance N'est PAS écrasée, la
        #    candidate est stockée à part, le chiffrement est SUSPENDU, et seul clear_conflict
        #    (vérification humaine) adopte la nouvelle clé.
        pdbR = Path(d) / "rot.db"
        hR1, hR2 = Path(d) / "R1", Path(d) / "R2"
        f1 = ac.ensure_key("rot@e.org", "Rot", home=hR1)
        f2 = ac.ensure_key("rot@e.org", "Rot", home=hR2)
        assert f1 != f2
        _register("rot@e.org", hR1, hA, pdbR, T)                 # 1re clé apprise
        assert ac.get_peer("rot@e.org", db_path=pdbR)["fpr"] == f1
        assert ac.recommendation(["rot@e.org"], db_path=pdbR) == "encrypt"
        # changement de clé (mail plus récent) → conflit, clé de confiance INCHANGÉE
        _register("rot@e.org", hR2, hA, pdbR, T + 10)
        pr = ac.get_peer("rot@e.org", db_path=pdbR)
        assert pr["fpr"] == f1, "la clé de confiance a été écrasée pendant un conflit (B1)"
        assert pr["conflict"] and pr["cand_fpr"] == f2 and pr["prev_fpr"] == f1
        assert ac.recommendation(["rot@e.org"], db_path=pdbR) == "disable"  # chiffrement suspendu
        # l'attaquant RENVOIE sa clé (encore plus récent) → conflit COLLANT, toujours disable
        _register("rot@e.org", hR2, hA, pdbR, T + 20)
        assert ac.peer_conflict("rot@e.org", db_path=pdbR)
        assert ac.get_peer("rot@e.org", db_path=pdbR)["fpr"] == f1
        assert ac.recommendation(["rot@e.org"], db_path=pdbR) == "disable"
        # forcer le chiffrement pendant le conflit DOIT échouer (jamais vers la candidate)
        ac.ensure_key("self@e.org", "Self", home=hA)
        try:
            ac.build_encrypted(_acc("self@e.org", "Self"), ["Rot <rot@e.org>"], "S", "secret",
                               db_path=pdbR, home=hA)
            raise AssertionError("build_encrypted a chiffré vers une clé en conflit (B1)")
        except ac.AutocryptError:
            pass
        # vérification humaine → clear_conflict ADOPTE la candidate (f2), purge f1
        ac.clear_conflict("rot@e.org", db_path=pdbR, home=hA)
        pr = ac.get_peer("rot@e.org", db_path=pdbR)
        assert not pr["conflict"] and pr["fpr"] == f2 and not pr["cand_fpr"]
        assert ac.recommendation(["rot@e.org"], db_path=pdbR) == "encrypt"
        rc, out, _ = ac._gpg(["--list-keys", "--with-colons", "<rot@e.org>"], hA)
        kfprs = [l.split(":")[9] for l in out.decode().splitlines() if l.startswith("fpr:")]
        assert f1 not in kfprs and f2 in kfprs, "adoption : ancienne clé non purgée / nouvelle absente"

        # 6. parsing défensif de l'en-tête
        assert ac.parse_header("addr=x@y; danger=1; keydata=AAAA") is None  # attr critique inconnu
        assert ac.parse_header("prefer-encrypt=mutual") is None            # pas d'addr/keydata
        assert ac.parse_header("addr=x@y; keydata=!!!notb64!!!") is None    # base64 invalide
        assert ac.parse_header("addr=a@y; addr=b@y; keydata=AAAA") is None  # attribut DUPLIQUÉ
        big = base64.b64encode(b"x" * (ac.MAX_KEYDATA + 10)).decode()
        assert ac.parse_header(f"addr=x@y; keydata={big}") is None          # bombe base64

        # 7. recommandation
        assert ac.recommendation(["bob@e.org"], db_path=pdb) == "encrypt"
        assert ac.recommendation(["bob@e.org", "inconnu@e.org"], db_path=pdb) == "disable"
        assert ac.recommendation([], db_path=pdb) == "disable"

        # 8. chiffrer → déchiffrer → signer ; tiers exclu ; liaison signature→expéditeur
        outer = ac.build_encrypted(_acc("alice@e.org", "Alice"), ["Bob <bob@e.org>"],
                                   "Sujet en clair", "CORPS-SECRET-42 🤫",
                                   db_path=pdb, home=hA)
        raw = outer.as_bytes()
        assert ac.is_encrypted(outer)
        assert b"CORPS-SECRET-42" not in raw and "🤫".encode() not in raw  # corps absent du transport
        assert b"Sujet en clair" in raw                                    # sujet en clair (Niveau 1)
        inner, info = ac.decrypt_message(email.message_from_bytes(raw), home=hB)
        assert inner and info["signed"] and info["sig_status"] == "good"
        assert info["sig_fpr"] == fA, ("liaison signature→expéditeur", info["sig_fpr"], fA)
        assert "CORPS-SECRET-42" in inner.get_body(preferencelist=("plain",)).get_content()
        assert ac.decrypt_message(email.message_from_bytes(raw), home=hC)[0] is None  # Eve exclue

        # 9. CHIFFREMENT PAR EMPREINTE : une clé homonyme injectée dans le trousseau
        #    ne peut PAS devenir destinataire (régression critiques #1/#2/#42).
        hAtt = Path(d) / "Att"
        f_att = ac.ensure_key("bob@e.org", "Imposteur", home=hAtt)   # même adresse, autre clé
        att_pub = ac.export_pubkey("bob@e.org", home=hAtt)
        ac._gpg(["--import"], hA, stdin=att_pub)                     # poison du trousseau
        rc, o, _ = ac._gpg(["--list-keys", "--with-colons", "<bob@e.org>"], hA)
        assert sum(1 for l in o.decode().splitlines() if l.startswith("pub:")) >= 2
        outer9 = ac.build_encrypted(_acc("alice@e.org", "Alice"), ["Bob <bob@e.org>"],
                                    "S", "POUR-LE-VRAI-BOB", db_path=pdb, home=hA)
        raw9 = outer9.as_bytes()
        assert ac.decrypt_message(email.message_from_bytes(raw9), home=hB)[0] is not None  # vrai Bob OK
        assert ac.decrypt_message(email.message_from_bytes(raw9), home=hAtt)[0] is None, \
            "la clé homonyme injectée a pu déchiffrer → chiffrement par adresse non corrigé"
        ac._gpg(["--delete-keys", f_att], hA)   # nettoie le poison

        # 10. DECRYPTION_OKAY OBLIGATOIRE : un message SEULEMENT signé (qui a voyagé en
        #     clair) ne doit JAMAIS être présenté comme chiffré (régression critique #3).
        rc, signed_only, _ = ac._gpg(
            ["--armor", "--sign", "--local-user", fA], hA, stdin=b"JE-VOYAGE-EN-CLAIR")
        decoy = _wrap_octet(signed_only.decode("ascii"))
        assert b"JE-VOYAGE-EN-CLAIR" not in b""  # (le clair est bien dans l'armor, pas chiffré)
        inner10, info10 = ac.decrypt_message(decoy, home=hB)
        assert inner10 is None, "un message signé-seul a été accepté comme déchiffré"

        # 11. robustesse de structure RFC 3156 : version inattendue / parties multiples
        cipher_ok = email.message_from_bytes(raw).get_payload()[1].get_payload()
        assert ac.decrypt_message(_wrap_octet(cipher_ok, version="Version: 2"), home=hB)[0] is None
        assert ac.decrypt_message(_wrap_octet(cipher_ok, n_octet=2), home=hB)[0] is None  # 3 parties
        assert ac.decrypt_message(_wrap_octet(cipher_ok, ctype_ok=False), home=hB)[0] is None

        # 12. décodage du CTE base64 de la partie chiffrée (interop MUA tiers)
        from email.mime.application import MIMEApplication
        outer12 = MIMEMultipart("encrypted", protocol="application/pgp-encrypted")
        vp = Message(); vp.set_type("application/pgp-encrypted"); vp.set_payload("Version: 1")
        ep = MIMEApplication(cipher_ok.encode("ascii"), _subtype="octet-stream")  # CTE base64 par défaut
        outer12.attach(vp); outer12.attach(ep)
        assert ep.get("Content-Transfer-Encoding", "").lower() == "base64"
        inner12, _ = ac.decrypt_message(outer12, home=hB)
        assert inner12 is not None, "partie chiffrée en base64 (CTE) non décodée"

        # 13. multi-destinataires (To + Cc) : chacun déchiffre avec sa propre clé
        _register("carol@e.org", hC, hA, pdb, T) if False else None
        fCarol = ac.ensure_key("carol@e.org", "Carol", home=hC)
        _register("carol@e.org", hC, hA, pdb, T)
        outer13 = ac.build_encrypted(_acc("alice@e.org", "Alice"), ["Bob <bob@e.org>"],
                                     "S", "POUR-BOB-ET-CAROL", cc=["Carol <carol@e.org>"],
                                     db_path=pdb, home=hA)
        raw13 = outer13.as_bytes()
        for who in (hB, hC):
            iw, _ = ac.decrypt_message(email.message_from_bytes(raw13), home=who)
            assert iw and "POUR-BOB-ET-CAROL" in iw.get_body(preferencelist=("plain",)).get_content()

        # 14. fail-closed : clé manquante → AutocryptError (jamais de repli en clair)
        try:
            ac.build_encrypted(_acc("alice@e.org", "Alice"), ["Inconnu <x@nowhere.org>"],
                               "S", "secret", db_path=pdb, home=hA)
            raise AssertionError("build_encrypted aurait dû lever (clé manquante)")
        except ac.AutocryptError:
            pass

        # 15. ANTI-RFC2047 / bootstrap (régression high #63) + NON-RÉGRESSION PJ : l'en-tête
        #     Autocrypt d'un envoi EN CLAIR survit (adresse LONGUE, Markdown) ET les pièces
        #     jointes à nom NON-ASCII LONG restent intactes (le fix ne doit pas casser le
        #     RFC 2231 des PJ — c'est la régression qu'avait introduite l'approche compat32).
        import fmail
        from email.policy import default as _dflt, compat32 as _c32
        longaddr = "prenom.nom.tres.long.identifiant-2026@sous-domaine.exemple-organisation-tres-longue.org"
        f_long = ac.ensure_key(longaddr, "Long", home=hA)
        pj = Path(d) / "rapport_financier_annéé_2026_éàùç.pdf"
        pj.write_bytes(b"%PDF-1.4 faux\n")

        def _ac_block(wire):   # isole le seul bloc de l'en-tête Autocrypt (avec ses replis)
            out, grab = [], False
            for ln in wire.decode("utf-8", "replace").splitlines():
                if ln[:10].lower().startswith("autocrypt:"):
                    grab = True; out.append(ln); continue
                if grab and ln[:1] in (" ", "\t"):
                    out.append(ln); continue
                if grab:
                    break
            return "\n".join(out)

        for sender, fpr in (("alice@e.org", fA), (longaddr, f_long)):
            m = fmail.build_message(_acc(sender, "S"), ["bob@e.org"], "Coucou", "corps **md**",
                                    markdown=True, attachments=[str(pj)])
            ac.attach_autocrypt_header(m, sender, home=hA)
            wire = m.as_bytes()
            assert "=?utf-8?" not in _ac_block(wire).lower(), f"en-tête Autocrypt ré-encodé RFC2047 ({sender})"
            for pol in (_dflt, _c32):
                mm = email.message_from_bytes(wire, policy=pol)
                rp = ac.parse_header(mm.get("Autocrypt"))
                assert rp and ac.key_fpr_from_data(rp["keydata"], home=hB) == fpr, \
                    f"keydata corrompu sur le fil ({sender}, {pol.__class__.__name__})"
                fns = [p.get_filename() for p in mm.walk()
                       if p.get_content_disposition() == "attachment"]
                assert fns == [pj.name], f"nom de PJ corrompu ({sender}, {pol.__class__.__name__}) : {fns}"

        # 16. brouillon chiffré-vers-soi : corps + destinataires absents du transport,
        #     round-trip de déchiffrement OK (régression high #6/#7/#9).
        draft_inner = fmail.build_message(
            _acc("alice@e.org", "Alice"), ["bob@e.org"], "Brouillon", "TEXTE-BROUILLON-SECRET")
        draft_inner["X-Fmail-Encrypt"] = "force"
        draft_inner["X-Fmail-Bcc"] = "secret-cci@e.org"
        dmsg = ac.build_self_encrypted_draft(_acc("alice@e.org", "Alice"),
                                             draft_inner.as_bytes(), "Brouillon", home=hA)
        drow = dmsg.as_bytes()
        assert dmsg.get("X-Fmail-Encrypted-Draft") == "1" and ac.is_encrypted(dmsg)
        assert b"TEXTE-BROUILLON-SECRET" not in drow and b"secret-cci@e.org" not in drow
        di, _ = ac.decrypt_message(email.message_from_bytes(drow), home=hA)
        assert di and di.get("X-Fmail-Encrypt") == "force"
        assert di.get("X-Fmail-Bcc") == "secret-cci@e.org"
        assert "TEXTE-BROUILLON-SECRET" in di.get_body(preferencelist=("plain",)).get_content()

        # 17. Cci jamais dans la copie Sent (régression high #8) : append_to_sent purge Bcc.
        sm = fmail.build_message(_acc("alice@e.org", "Alice"), ["bob@e.org"],
                                 "S", "corps", bcc=["cci-secret@e.org"])
        assert sm["Bcc"]
        del sm["Bcc"]; del sm["Resent-Bcc"]      # exactement ce que fait append_to_sent
        assert b"cci-secret@e.org" not in sm.as_bytes()

        # 18. MIGRATION ts_epoch : le backfill empêche le DOWNGRADE par mail antidaté
        #     (régression P0). On simule une base au schéma ANCIEN (sans ts_epoch) qui
        #     contient déjà une clé apprise, puis on ouvre via _db (migration+backfill).
        import sqlite3
        pdb2 = Path(d) / "legacy.db"
        bob_kd = ac.parse_header(ac.header_value("bob@e.org", home=hB))["keydata"]
        bob_fpr = ac.key_fpr_from_data(bob_kd, home=hA)
        con = sqlite3.connect(pdb2)
        con.executescript(
            "CREATE TABLE autocrypt_peers(addr TEXT PRIMARY KEY, last_seen TEXT, "
            "autocrypt_ts TEXT, prefer_encrypt TEXT NOT NULL DEFAULT 'nopreference', "
            "fpr TEXT, keydata BLOB);")
        con.execute("INSERT INTO autocrypt_peers(addr,last_seen,autocrypt_ts,prefer_encrypt,fpr,keydata)"
                    " VALUES (?,?,?,?,?,?)",
                    ("bob@e.org", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00",
                     "mutual", bob_fpr, bob_kd))
        con.commit(); con.close()
        attacker = Path(d) / "Att2"
        ac.ensure_key("bob@e.org", "Imposteur", home=attacker)
        att_parsed = ac.parse_header(ac.header_value("bob@e.org", home=attacker))
        #   mail attaquant ANTIDATÉ (2020) : ne doit PAS écraser la clé de 2026
        ac.update_peer("bob@e.org", ac._iso_to_epoch("2020-01-01T00:00:00+00:00"),
                       att_parsed, db_path=pdb2, home=hA)
        assert ac.get_peer("bob@e.org", db_path=pdb2)["fpr"] == bob_fpr, \
            "un mail antidaté a dégradé la clé (backfill ts_epoch défaillant)"

        # 19. Date FUTURE non probante (régression P0 « gel ») — logique fmail_tui.
        import time as _t
        from email.message import EmailMessage as _EM
        from email.utils import formatdate as _fd
        import fmail_tui as ftui
        now = int(_t.time())
        def _mk(epoch):
            mm = _EM(); mm["Date"] = _fd(epoch, usegmt=True); return mm
        assert ftui._date_in_future(_mk(now + 3600)) is True
        assert ftui._date_in_future(_mk(now - 3600)) is False
        assert ftui._msg_date_epoch(_mk(now + 99999)) <= now + ftui._DATE_SKEW + 2  # plafonné
        assert ftui._msg_date_epoch(_mk(now - 3600)) <= now

        # 20. recommendation : une clé EXPIRÉE → 'disable' (le 🔒 ne ment pas).
        import sqlite3 as _sq
        pdb3 = Path(d) / "exp.db"
        ac.update_peer("bob@e.org", T, ac.parse_header(ac.header_value("bob@e.org", home=hB)),
                       db_path=pdb3, home=hA)
        assert ac.recommendation(["bob@e.org"], db_path=pdb3) == "encrypt"
        with _sq.connect(pdb3) as _cc:
            _cc.execute("UPDATE autocrypt_peers SET expires=? WHERE addr=?", (T - 10, "bob@e.org"))
        assert ac.recommendation(["bob@e.org"], db_path=pdb3) == "disable", \
            "clé expirée devrait donner 'disable'"

        # 21. RÉGRESSION : In-Reply-To / References REPLIÉS (CR/LF) repris d'un mail reçu
        #     ne doivent plus faire planter build_message (réponse en clair).
        m_reply = fmail.build_message(
            _acc("alice@e.org", "Alice"), ["bob@e.org"], "Re: coucou", "corps",
            in_reply_to="<id.1@\r\n mail.example.org>",
            references="<a@x>\r\n <b@x>\r\n\t<c@x>")
        assert "\n" not in (m_reply["In-Reply-To"] or "") and "\r" not in (m_reply["In-Reply-To"] or "")
        assert "\n" not in (m_reply["References"] or "") and "\r" not in (m_reply["References"] or "")
        assert m_reply.as_bytes()   # sérialise sans lever

    print("✅ test_autocrypt : tous les tests passent (trousseaux/bases temporaires)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
