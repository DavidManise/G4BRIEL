# Copyright (C) 2026 David Manise
# SPDX-License-Identifier: GPL-3.0-or-later
"""French catalog for fmail — assembled from the per-module catalogs.

Each source module ships its own English->French dictionary in i18n_fr_<module>.py
(produced during translation). This aggregator merges them into a single CATALOG
that i18n.py consumes. Missing per-module files are simply skipped.
"""
CATALOG: dict = {}

for _m in ("fmail", "fmail_tui", "vault", "autocrypt", "fmail_store"):
    try:
        _mod = __import__("i18n_fr_" + _m)
        CATALOG.update(getattr(_mod, "CATALOG", {}))
    except Exception:
        pass
