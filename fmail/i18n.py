# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""fmail internationalization — minimal, dependency-free.

English source strings ARE the message IDs. A French catalog (i18n_fr.py) overrides
them when the active language is French; any missing translation falls back to the
English source, so a forgotten string degrades gracefully (it never crashes).

Convention used throughout the codebase:

    from i18n import _

    print(_("Sent to {to}", to=addr))      # interpolation: pass keyword args
    self.error(_("no such account."))      # plain string: no args

`_()` only runs str.format() when keyword args are given, so strings that contain
literal braces but take no args are returned untouched.

Language selection (first match wins):
    1. set_lang(code) called explicitly at startup (from [ui] lang in accounts.toml)
    2. environment LC_ALL / LC_MESSAGES / LANG  (a value starting with "fr" -> French)
    3. default: English
"""
from __future__ import annotations

import os

SUPPORTED = ("en", "fr")
_lang = "en"
_catalogs: dict = {}


def _detect_from_env() -> str:
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        if os.environ.get(var, "")[:2].lower() == "fr":
            return "fr"
    return "en"


def _load_catalog(lang: str) -> dict:
    if lang in _catalogs:
        return _catalogs[lang]
    cat: dict = {}
    if lang == "fr":
        try:
            from i18n_fr import CATALOG as cat  # noqa: F401  (assembled at build)
        except Exception:
            cat = {}
    _catalogs[lang] = cat
    return cat


def set_lang(code) -> str:
    """Set the active language: 'en', 'fr', or 'auto' (detect from the environment)."""
    global _lang
    code = (code or "auto").lower()
    if code == "auto":
        code = _detect_from_env()
    _lang = code if code in SUPPORTED else "en"
    _load_catalog(_lang)
    return _lang


def get_lang() -> str:
    return _lang


def _(msgid: str, **kwargs) -> str:
    """Translate `msgid` to the active language; format with kwargs when provided."""
    s = msgid if _lang == "en" else _load_catalog(_lang).get(msgid, msgid)
    return s.format(**kwargs) if kwargs else s


# Initialise from the environment at import time; the app overrides via set_lang().
set_lang("auto")
