#!/usr/bin/env bash
# Assemble a clean ./dist tree to upload to https://survivologie.org/fmail/.
#
# SAFETY: this uses an explicit WHITELIST. It never copies your real data
# (vault.gpg, accounts.toml, sent.log, caches, keyrings…) and it aborts if
# anything secret-looking ends up in dist/.
set -euo pipefail
cd "$(dirname "$0")"
OUT="dist"

# --- whitelist: the only files that ship ---------------------------------
APP=(fmail.py fmail_tui.py fmail_store.py vault.py autocrypt.py
     i18n.py i18n_fr.py i18n_fr_fmail.py i18n_fr_fmail_tui.py
     i18n_fr_vault.py i18n_fr_autocrypt.py i18n_fr_fmail_store.py)
OPT=()
DOCS=(README.md LICENSE install.sh uninstall.sh VERSION accounts.toml.example)
TESTS=(test_autocrypt.py test_autocrypt_dek.py test_vault.py test_security.py test_i18n.py)

# --- never-ship guard: secret / personal patterns ------------------------
SECRET_GLOBS=('vault.gpg' 'vault.gpg.lock' 'accounts.toml' 'sent.log' 'check.log'
              'notified_uids.txt' '*.bak-*' '.autocrypt.db' '.tls_pins.json'
              '.fmail_cache.db*' '.gnupg-*' 'config.py' 'inbox.py' 'read.py'
              'check_new.py' 'drafts' 'signatures'
              # byte-compiled artifacts embed the maintainer's absolute home path
              # (co_filename) → must never ship in a public release.
              '__pycache__' '*.pyc')

rm -rf "$OUT"; mkdir -p "$OUT"
copy() { if [ -f "$1" ]; then cp "$1" "$OUT/"; echo "  + $1"; fi; }

echo "Assembling $OUT/ (whitelist only) ..."
for f in "${APP[@]}" "${DOCS[@]}" "${TESTS[@]}" "${OPT[@]}"; do copy "$f"; done
# doc assets (preserve the docs/ path so README's image link resolves)
if [ -f docs/fmail.svg ]; then mkdir -p "$OUT/docs"; cp docs/fmail.svg "$OUT/docs/"; echo "  + docs/fmail.svg"; fi

# abort if any secret slipped in
for pat in "${SECRET_GLOBS[@]}"; do
  for hit in "$OUT"/$pat; do
    [ -e "$hit" ] && { echo "ABORT: secret-looking file in $OUT/: $hit" >&2; exit 1; }
  done
done

# checksums over the files the installer fetches (not README/installers/tests)
( cd "$OUT"
  : > SHA256SUMS
  sumtool() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
  for f in *.py accounts.toml.example VERSION; do
    [ -f "$f" ] || continue
    case "$f" in test_*.py) continue;; esac     # tests are not fetched by the installer
    sumtool "$f"
  done > SHA256SUMS
)
echo "Wrote $OUT/SHA256SUMS"

# --- sign the manifest with the pinned release key (root of trust for the updater) -------
# The signed SHA256SUMS is what fmail >=0.9.3 verifies against its embedded RELEASE_PUBKEY
# before trusting any downloaded file. The secret key lives ONLY here (never shipped).
RELEASE_GNUPGHOME="${FMAIL_RELEASE_GNUPGHOME:-$HOME/secrets/fmail-release}"
if gpg --homedir "$RELEASE_GNUPGHOME" --list-secret-keys >/dev/null 2>&1; then
  rm -f "$OUT/SHA256SUMS.asc"
  gpg --homedir "$RELEASE_GNUPGHOME" --batch --pinentry-mode loopback --passphrase '' \
      --armor --detach-sign -o "$OUT/SHA256SUMS.asc" "$OUT/SHA256SUMS"
  echo "Signed  $OUT/SHA256SUMS.asc  (release key $(gpg --homedir "$RELEASE_GNUPGHOME" \
        --list-keys --with-colons | awk -F: '/^fpr:/{print $10; exit}'))"
else
  echo "WARNING: release key absent from $RELEASE_GNUPGHOME — SHA256SUMS NOT signed." >&2
  echo "         fmail >=0.9.3 will REFUSE this release. Build on the release host." >&2
fi
echo
echo "Next: upload the *contents* of $OUT/ to https://survivologie.org/fmail/"
echo "Users then run:  curl -fsSL https://survivologie.org/fmail/install.sh | bash"
