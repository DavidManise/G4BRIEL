#!/usr/bin/env python3
# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests du coffre chiffré fmail — sur fichiers/GNUPGHOME TEMPORAIRES uniquement
(jamais le vrai coffre ni la vraie boîte). Lancer : `python3 test_vault.py`."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import vault as v

# These tests exercise the vault LOGIC (sealing, KDF migration, duress), not the raw
# scrypt cost — which is a production constant (vault.KDF_N). Lower it in-process so the
# suite stays fast; the migration test still asserts n >= 1<<14.
v.KDF_N = 1 << 14


def main():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "vault.gpg"
        home = Path(d) / "gnupg"
        MP = "Mot De Passe Maître! éàç 42"

        # 1. création (enveloppe 2-serrures) + code de récupération + refus d'écrasement
        content, RECOV = v.create(MP, accounts={"dm": "imap-pw-dm", "freyja": "imap-pw-fr"},
                                  path=path, home=home)
        assert v.exists(path) and content["accounts"]["dm"] == "imap-pw-dm"
        assert RECOV and "-" in RECOV and len(RECOV.replace("-", "")) >= 24   # code transcriptible
        try:
            v.create(MP, path=path, home=home); raise AssertionError("create a écrasé un coffre existant")
        except v.VaultError:
            pass
        data = v.read_vault(MP, path, home)
        assert data["accounts"]["dm"] == "imap-pw-dm" and data["version"] == 1

        # 2. le clair n'est PAS dans le fichier (enveloppe JSON = serrures + corps chiffrés)
        blob = path.read_bytes()
        assert b"imap-pw-dm" not in blob and "éàç".encode() not in blob
        assert RECOV.encode() not in blob and RECOV.replace("-", "").encode() not in blob
        assert b'"slots"' in blob and b'"password"' in blob and b'"recovery"' in blob and b'"body"' in blob
        assert (os.stat(path).st_mode & 0o777) == 0o600   # 0600

        # 3. mauvais mot de passe → BadPassphrase
        try:
            v.read_vault("mauvais", path, home); raise AssertionError("mauvais mdp accepté")
        except v.BadPassphrase:
            pass

        # 3b. RÉCUPÉRATION : mot de passe oublié → reset via le code ; ancien mdp invalidé
        v.reset_master_with_recovery(RECOV, "Recupere-Maitre-77", path, home)
        assert v.read_vault("Recupere-Maitre-77", path, home)["accounts"]["dm"] == "imap-pw-dm"
        try:
            v.read_vault(MP, path, home); raise AssertionError("ancien mdp encore valide après reset")
        except v.BadPassphrase:
            pass
        for bad in ("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH", "n'importe quoi"):
            try:
                v.reset_master_with_recovery(bad, "X" * 12, path, home)
                raise AssertionError("code de récupération faux accepté")
            except v.BadPassphrase:
                pass
        v.unlock_with_recovery(RECOV, path, home)            # déverrouillage direct par code
        assert v.account_password("dm") == "imap-pw-dm"
        v.lock()
        v.reset_master_with_recovery(RECOV, MP, path, home)  # on remet MP pour la suite

        # 4. changement de mot de passe maître
        v.change_passphrase(MP, "Nouveau-Maître-99", path, home)
        try:
            v.read_vault(MP, path, home); raise AssertionError("ancien mdp encore valide")
        except v.BadPassphrase:
            pass
        assert v.read_vault("Nouveau-Maître-99", path, home)["accounts"]["freyja"] == "imap-pw-fr"
        MP = "Nouveau-Maître-99"

        # 5. session : unlock / account_password / lock
        assert not v.is_unlocked() and v.account_password("dm") is None
        v.unlock(MP, path, home)
        assert v.is_unlocked() and v.account_password("dm") == "imap-pw-dm"
        assert v.account_password("inexistant") is None
        v.set_account_password("lui", "imap-pw-lui")
        assert v.read_vault(MP, path, home)["accounts"]["lui"] == "imap-pw-lui"  # persisté chiffré

        # 5b. régénération du code de récupération (invalide l'ancien)
        NEW_RECOV = v.regenerate_recovery_code(path, home)   # coffre déverrouillé
        assert NEW_RECOV != RECOV
        v.lock()
        try:
            v.reset_master_with_recovery(RECOV, "Zzzzzzzzzzzz", path, home)
            raise AssertionError("ancien code de récupération encore valide après régénération")
        except v.BadPassphrase:
            pass
        v.reset_master_with_recovery(NEW_RECOV, MP, path, home)   # le nouveau code marche
        v.unlock(MP, path, home)

        # 6. re-verrouillage par inactivité
        assert not v.idle_expired(900)
        v._state["last_active"] = time.time() - 1000
        assert v.idle_expired(900) and not v.idle_expired(0)   # 0 = jamais
        v.touch()
        assert not v.idle_expired(900)

        # 7. carnet d'adresses : ajout manuel, auto-apprentissage non destructif, suppression
        v.add_contact("alice@e.org", name="Alice", notes="amie", source="manual")
        assert v.get_contact("ALICE@e.org")["name"] == "Alice"          # casse-insensible
        v.learn_contact("alice@e.org", name="Alice Imposteur")          # NE doit PAS écraser le manuel
        assert v.get_contact("alice@e.org")["name"] == "Alice"
        assert v.get_contact("alice@e.org")["source"] == "manual"
        v.learn_contact("bob@e.org", name="Bob")                        # nouveau → appris
        assert v.get_contact("bob@e.org")["source"] == "learned"
        assert len(v.contacts()) == 2
        try:
            v.add_contact("pas-une-adresse", name="X"); raise AssertionError("adresse invalide acceptée")
        except v.VaultError:
            pass
        assert v.remove_contact("bob@e.org") and not v.remove_contact("bob@e.org")
        assert len(v.contacts()) == 1
        # persistance du carnet (relecture à froid)
        assert any(c["email"] == "alice@e.org" for c in v.read_vault(MP, path, home)["contacts"])

        # 7b. ANTI-PERTE de MAJ concurrente : une écriture « d'une autre instance »
        #     directement sur le disque ne doit PAS être écrasée par notre session
        #     (les mutations relisent le coffre frais sous verrou avant d'écrire).
        d2 = v.read_vault(MP, path, home)
        d2["accounts"]["autre"] = "venu-d-ailleurs"
        v.write_vault(d2, MP, path, home)              # simulate une autre instance
        v.add_contact("zoe@e.org", name="Zoe")          # notre session (état mémoire périmé)
        disk = v.read_vault(MP, path, home)
        assert disk["accounts"].get("autre") == "venu-d-ailleurs", "écriture concurrente perdue"
        assert any(c["email"] == "zoe@e.org" for c in disk["contacts"])

        # 7c. règles du mot de passe maître : longueur min, pas de saut de ligne
        for bad in ("court", "", "ok-mais-avec\nsaut"):
            try:
                v.change_passphrase(MP, bad); raise AssertionError(f"mdp faible accepté: {bad!r}")
            except v.VaultError:
                pass
        # carnet : champs nettoyés (CR/LF retirés) et e-mail invalide refusé
        c = v.add_contact("hervé@e.org", name="Hervé\r\nInjecté", notes="ligne1\nligne2")
        assert "\n" not in c["name"] and "\r" not in c["name"]
        for bad in ("pas-une-adresse", "a b@e.org", "x@e.org\nBcc: y@e.org"):
            try:
                v.add_contact(bad); raise AssertionError(f"e-mail invalide accepté: {bad!r}")
            except v.VaultError:
                pass

        # 8. lock efface tout de la mémoire
        v.lock()
        assert not v.is_unlocked() and v.account_password("dm") is None
        try:
            v.contacts(); raise AssertionError("contacts lisibles coffre verrouillé")
        except v.VaultLocked:
            pass

    _test_kdf_and_migration()
    _test_kdf_strengthen()
    _test_truncated_envelope()
    _test_duress()
    print("✅ test_vault : tous les tests passent (fichiers/GNUPGHOME temporaires)")
    return 0


def _test_duress():
    """Mot de passe de contrainte (durci red team) : set/is/clear + anti-collision
    maître/récup ET maître≠contrainte, slot INDISTINGUABLE (toujours présent), NFC.
    Fichiers TEMPORAIRES."""
    import json
    import unicodedata
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "vault.gpg"
        home = Path(d) / "gnupg"
        MP = "Mot-De-Passe-Maitre-Costaud-42"
        _c, RECOV = v.create(MP, accounts={"dm": "pw"}, path=path, home=home)
        # OPSEC : un slot "duress" existe DÈS la création (placeholder aléatoire) → la
        # présence d'un duress ne fuite pas, et rien ne matche tant qu'il n'est pas défini
        assert "duress" in json.loads(path.read_bytes())
        assert not v.is_duress("nimporte", path, home)
        DURESS = "Contrainte-Panique-2026"
        v.set_duress(DURESS, path, home)
        assert v.is_duress(DURESS, path, home)            # match exact
        assert not v.is_duress("autre", path, home)
        assert not v.is_duress(MP, path, home) and not v.is_duress(RECOV, path, home)
        # la contrainte doit DIFFÉRER du maître et du code de récupération
        for clash in (MP, RECOV):
            try:
                v.set_duress(clash, path, home); raise AssertionError("contrainte == maître/récup acceptée")
            except v.VaultError:
                pass
        # anti-auto-déclenchement : le maître ne peut JAMAIS devenir == la contrainte
        for fn in (lambda: v.change_passphrase(MP, DURESS, path, home),
                   lambda: v.reset_master_with_recovery(RECOV, DURESS, path, home)):
            try:
                fn(); raise AssertionError("maître = contrainte accepté (auto-wipe au bon mdp !)")
            except v.VaultError:
                pass
        # NFC : un duress accentué matche quelle que soit la forme saisie (NFC vs NFD)
        v.set_duress(unicodedata.normalize("NFC", "Pâté-Café-2026"), path, home)
        assert v.is_duress(unicodedata.normalize("NFD", "Pâté-Café-2026"), path, home)
        # le coffre s'ouvre toujours normalement (rien cassé)
        assert v.read_vault(MP, path, home)["accounts"]["dm"] == "pw"
        v.unlock_with_recovery(RECOV, path, home); v.lock()
        # AUTO-01 : même si le vérifieur duress matche le maître (collision NFC simulée
        # en injectant verify = scrypt(NFC(maître))), is_duress(maître) doit rendre FALSE
        # — le vrai identifiant gagne TOUJOURS, jamais d'auto-wipe au bon mot de passe.
        env = json.loads(path.read_bytes())
        env["duress"] = v._duress_make_slot(MP)        # duress == maître (collision)
        v._write_cipher(json.dumps(env).encode("utf-8"), path)
        assert not v.is_duress(MP, path, home), "le MAÎTRE déclenche le wipe (AUTO-01 non corrigé)"
        assert not v.is_duress(RECOV, path, home)
        # désactivation → placeholder ; le slot reste présent (indistinguable) mais ne matche plus
        v.clear_duress(path, home)
        assert "duress" in json.loads(path.read_bytes()) and not v.is_duress(MP, path, home)


def _test_kdf_and_migration():
    """KDF memory-hard (scrypt) du slot mot de passe (fmt 3) + migration transparente
    d'un coffre hérité fmt 2 → fmt 3 au déverrouillage. Fichiers TEMPORAIRES."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "vault.gpg"
        home = Path(d) / "gnupg"
        MP = "Mot-De-Passe-Maitre-Costaud-42"

        # (a) un coffre neuf est en fmt 3 avec une KDF scrypt (sel propre)
        _c, RECOV = v.create(MP, accounts={"dm": "pw-dm"}, path=path, home=home)
        env = json.loads(path.read_bytes().decode("utf-8"))
        assert env["fmt"] == 3 and env["kdf"]["algo"] == "scrypt"
        assert env["kdf"]["salt"] and env["kdf"]["n"] >= 1 << 14
        # le slot mot de passe n'est PAS ouvrable avec le mdp BRUT (la KDF est appliquée) :
        try:
            v._unwrap(env["slots"]["password"], MP, home)
            raise AssertionError("slot password ouvrable sans la KDF (scrypt non appliquée)")
        except v.BadPassphrase:
            pass
        # …mais l'est avec la passphrase dérivée, et read_vault marche
        dek_pw = v._unwrap(env["slots"]["password"], v._kdf_passphrase(MP, env["kdf"]), home)
        assert dek_pw and v.read_vault(MP, path, home)["accounts"]["dm"] == "pw-dm"
        # le slot de récupération reste SANS KDF (code à forte entropie) et scelle la
        # MÊME DEK : les deux serrures ouvrent le même coffre.
        dek_rc = v._unwrap(env["slots"]["recovery"], v._norm_recovery(RECOV), home)
        assert dek_pw == dek_rc

        # (b) changement de mdp → nouveau sel KDF, ancien mdp invalidé
        salt0 = env["kdf"]["salt"]
        v.change_passphrase(MP, "Autre-Mdp-Maitre-Solide-99", path, home)
        env2 = json.loads(path.read_bytes().decode("utf-8"))
        assert env2["fmt"] == 3 and env2["kdf"]["salt"] != salt0   # sel régénéré
        assert v.read_vault("Autre-Mdp-Maitre-Solide-99", path, home)["accounts"]["dm"] == "pw-dm"

        # (c) MIGRATION : forge un coffre hérité fmt 2 (sans KDF, slot sous mdp brut)
        path2 = Path(d) / "legacy.gpg"
        home2 = Path(d) / "gnupg2"
        OLD = "Vieux-Mdp-Maitre-Legacy-2024"
        dek = v._gen_dek()
        code = v._gen_recovery_code()
        content = v._normalize({"accounts": {"x": "secret-x"}, "contacts": []})
        legacy = {"fmt": 2,
                  "slots": {"password": v._wrap(dek, OLD, home2),               # PAS de KDF
                            "recovery": v._wrap(dek, v._norm_recovery(code), home2)},
                  "body": v._body_b64(content, dek, home2)}
        v._write_cipher(json.dumps(legacy).encode("utf-8"), path2)
        assert json.loads(path2.read_bytes().decode("utf-8")).get("kdf") is None
        # déverrouillage avec l'ANCIEN mdp brut → migration transparente vers fmt 3
        assert v.unlock(OLD, path2, home2)["accounts"]["x"] == "secret-x"
        v.lock()
        migr = json.loads(path2.read_bytes().decode("utf-8"))
        assert migr["fmt"] == 3 and migr["kdf"]["algo"] == "scrypt"
        # le MÊME mdp continue de fonctionner après migration (DEK inchangée)
        assert v.read_vault(OLD, path2, home2)["accounts"]["x"] == "secret-x"
        # le slot n'est plus ouvrable avec le mdp brut (désormais dérivé)
        migr_env = json.loads(path2.read_bytes().decode("utf-8"))
        try:
            v._unwrap(migr_env["slots"]["password"], OLD, home2)
            raise AssertionError("après migration, slot encore ouvrable au mdp brut")
        except v.BadPassphrase:
            pass


def _test_kdf_strengthen():
    """Renforcement transparent : un coffre fmt 3 scellé sous une KDF PLUS FAIBLE que
    KDF_N courant est re-scellé au déverrouillage (suite à un bump de paramètres), sans
    toucher la DEK ni le corps. Fichiers TEMPORAIRES."""
    import base64
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "vault.gpg"
        home = Path(d) / "gnupg"
        MP = "Mot-De-Passe-Maitre-A-Renforcer-7"
        v.create(MP, accounts={"k": "v"}, path=path, home=home)   # n = KDF_N (abaissé en test)
        env = json.loads(path.read_bytes().decode("utf-8"))
        dek = v._unwrap_password(env, MP, home)
        # re-scelle le slot mot de passe sous une KDF strictement plus faible (n = KDF_N/2)
        weak = {"algo": "scrypt", "n": v.KDF_N >> 1, "r": v.KDF_R, "p": v.KDF_P,
                "salt": base64.b64encode(os.urandom(16)).decode("ascii")}
        env["kdf"] = weak
        env["slots"]["password"] = v._wrap(dek, v._kdf_passphrase(MP, weak), home)
        v._write_cipher(json.dumps(env).encode("utf-8"), path)
        assert json.loads(path.read_bytes())["kdf"]["n"] == (v.KDF_N >> 1)
        # déverrouillage → renforcement transparent jusqu'à KDF_N, DEK préservée
        assert v.unlock(MP, path=path, home=home)["accounts"]["k"] == "v"
        v.lock()
        after = json.loads(path.read_bytes().decode("utf-8"))
        assert after["kdf"]["n"] >= v.KDF_N, f"KDF non renforcée: {after['kdf']['n']}"
        assert v.read_vault(MP, path, home)["accounts"]["k"] == "v"   # toujours ouvrable


def _test_truncated_envelope():
    """Une enveloppe à laquelle il manque une serrure → VaultError clair (pas de
    KeyError brut), sur les chemins lecture/récupération. Fichiers TEMPORAIRES."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "vault.gpg"
        home = Path(d) / "gnupg"
        MP = "Mot-De-Passe-Maitre-Costaud-42"
        _content, code = v.create(MP, accounts={"dm": "pw"}, path=path, home=home)
        env = json.loads(path.read_bytes().decode("utf-8"))
        # retire la serrure de récupération → enveloppe tronquée
        del env["slots"]["recovery"]
        v._write_cipher(json.dumps(env).encode("utf-8"), path)
        for fn in (lambda: v.read_vault(MP, path, home),
                   lambda: v.unlock(MP, path, home),
                   lambda: v.reset_master_with_recovery(code, "Nouveau-Mdp-Costaud-77", path, home),
                   lambda: v.unlock_with_recovery(code, path, home)):
            try:
                fn(); raise AssertionError("enveloppe tronquée acceptée")
            except v.VaultError:
                pass        # VaultError clair, et surtout PAS un KeyError brut
            except KeyError:
                raise AssertionError("KeyError brut sur enveloppe tronquée (devrait être VaultError)")
        v.lock()


if __name__ == "__main__":
    sys.exit(main())
