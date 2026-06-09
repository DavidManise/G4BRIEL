#!/usr/bin/env python3
# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests of the bilingual layer (EN/FR): translation engine, [ui] lang config
round-trip, and catalog coverage of key strings. Temporary files only. Run:
`python3 test_i18n.py`."""
import sys
import tempfile
from pathlib import Path

import i18n
from i18n import _
import i18n_fr
import fmail


def test_engine():
    i18n.set_lang("en")
    assert _("no vault.") == "no vault."                      # EN: msgid is the source
    assert _("Sent to {to}", to="x@y") == "Sent to x@y"        # interpolation
    assert _("braces {} kept") == "braces {} kept"            # no kwargs -> no format
    i18n.set_lang("fr")
    assert _("no vault.") == "aucun coffre."                   # FR catalog
    assert _("unknown msgid xyz") == "unknown msgid xyz"       # missing -> EN fallback
    assert i18n.set_lang("klingon") == "en"                    # unknown -> en


def test_env_detection(monkeypatch_env=None):
    import os
    old = {k: os.environ.get(k) for k in ("LC_ALL", "LC_MESSAGES", "LANG")}
    try:
        for k in old:
            os.environ.pop(k, None)
        os.environ["LANG"] = "fr_FR.UTF-8"
        assert i18n.set_lang("auto") == "fr"
        os.environ["LANG"] = "en_US.UTF-8"
        assert i18n.set_lang("auto") == "en"
        os.environ["LANG"] = "C"
        assert i18n.set_lang("auto") == "en"
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_catalog_coverage():
    """The FR catalog must cover key user-facing strings (regression guard against a
    msgid being changed in code without updating its translation)."""
    assert len(i18n_fr.CATALOG) > 300
    must_have = [
        "no vault.",
        "[encrypted]",
        "Minimalist multi-account CLI mail client.",
        "unknown account: “{name}”. Available: {available}",
        "incorrect master password (or corrupted vault).",
    ]
    missing = [m for m in must_have if m not in i18n_fr.CATALOG]
    assert not missing, f"missing FR translations: {missing}"
    # placeholders must match between msgid and its French value
    import re
    ph = lambda s: sorted(re.findall(r"\{(\w+)", s))
    bad = [k for k, v in i18n_fr.CATALOG.items() if ph(k) != ph(v)]
    assert not bad, f"placeholder mismatch in: {bad[:5]}"


def test_config_lang_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        cfg = Path(d) / "accounts.toml"
        fmail.CONFIG_PATH = cfg
        base = '[accounts.me]\nemail="me@x.org"\nimap_host="x"\npassword_file=""\n'
        cfg.write_text(base)
        assert fmail.ui_lang_configured() is False and fmail.load_lang() == "auto"
        fmail.write_ui_lang("fr")
        assert fmail.ui_lang_configured() and fmail.load_lang() == "fr"
        fmail.write_ui_lang("en")                       # replace, no duplicate
        assert fmail.load_lang() == "en" and cfg.read_text().count("lang =") == 1
        cfg.write_text(base + "\n[ui]\n")               # [ui] without lang -> insert
        fmail.write_ui_lang("fr")
        assert fmail.load_lang() == "fr" and cfg.read_text().count("[ui]") == 1
        fmail.write_ui_lang("klingon")                  # invalid -> auto
        assert fmail.load_lang() == "auto"
        assert "me" in fmail.load_config()[0]           # config still valid


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ✓ {name}")
    i18n.set_lang("auto")
    print("✅ test_i18n: bilingual engine, env detection, catalog coverage, [ui] lang config")
    return 0


if __name__ == "__main__":
    sys.exit(main())
