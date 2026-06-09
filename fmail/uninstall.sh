#!/usr/bin/env bash
# Remove the fmail program and command. Your data/config is KEPT by default.
set -euo pipefail
APP_DIR="${FMAIL_PREFIX:-$HOME/.local/share/fmail}"
BIN_DIR="${FMAIL_BIN:-$HOME/.local/bin}"
DATA_DIR="${FMAIL_DATA:-$HOME/freyja-mail}"

rm -f  "$BIN_DIR/fmail"
rm -rf "$APP_DIR"
echo "Removed the fmail program ($APP_DIR) and the 'fmail' command."
echo
echo "Your accounts, vault and cache in $DATA_DIR were KEPT on purpose."
echo "To erase everything (irreversible — destroys your encrypted vault):"
echo "    rm -rf \"$DATA_DIR\""
