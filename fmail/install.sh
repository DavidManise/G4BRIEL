#!/usr/bin/env bash
# fmail installer — downloads fmail and installs it into your home directory.
#
#   curl -fsSL https://survivologie.org/fmail/install.sh | bash
#
# No root needed. Installs the program under ~/.local, your config under
# ~/freyja-mail, and a `fmail` command in ~/.local/bin.
#
# Environment overrides (advanced / testing):
#   FMAIL_BASE_URL  download base URL   (default https://survivologie.org/fmail)
#   FMAIL_SRC       install from a LOCAL directory instead of downloading
#   FMAIL_PREFIX    program dir         (default ~/.local/share/fmail)
#   FMAIL_BIN       command dir         (default ~/.local/bin)
#   FMAIL_DATA      config/data dir     (default ~/freyja-mail)
set -euo pipefail

FMAIL_BASE_URL="${FMAIL_BASE_URL:-https://survivologie.org/fmail}"
FMAIL_SRC="${FMAIL_SRC:-}"
APP_DIR="${FMAIL_PREFIX:-$HOME/.local/share/fmail}"
BIN_DIR="${FMAIL_BIN:-$HOME/.local/bin}"
DATA_DIR="${FMAIL_DATA:-$HOME/freyja-mail}"
MIN_PY_MINOR=11                          # fmail needs Python 3.11+ (tomllib)

info() { printf '  \033[1;34m>\033[0m %s\n' "$*"; }
ok()   { printf '  \033[1;32mok\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[1;31mx\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Detect a package manager so we can OFFER to install a missing dependency.
PKG=""
for _m in brew apt-get dnf yum pacman zypper apk; do have "$_m" && { PKG="$_m"; break; }; done

pkg_name() {   # map a generic name to this manager's package name
  case "$1:$PKG" in
    gnupg:dnf|gnupg:yum) echo "gnupg2" ;;
    python3:brew)        echo "python" ;;
    *)                   echo "$1" ;;
  esac
}

pkg_install_cmd() {   # echo the install command for generic package $1 (empty if unknown)
  _p="$(pkg_name "$1")"
  case "$PKG" in
    brew)    echo "brew install $_p" ;;
    apt-get) echo "sudo apt-get install -y $_p" ;;
    dnf)     echo "sudo dnf install -y $_p" ;;
    yum)     echo "sudo yum install -y $_p" ;;
    pacman)  echo "sudo pacman -S --noconfirm $_p" ;;
    zypper)  echo "sudo zypper install -y $_p" ;;
    apk)     echo "sudo apk add $_p" ;;
  esac
}

offer_install() {   # <generic-pkg> <human name> — asks first; never runs sudo unattended
  _cmd="$(pkg_install_cmd "$1")"
  [ -n "$_cmd" ] || { warn "couldn't detect a package manager — install $2 yourself."; return 1; }
  printf '  Install %s now? [Y/n]  (runs: %s)  ' "$2" "$_cmd" > /dev/tty 2>/dev/null
  if read -r _ans < /dev/tty 2>/dev/null; then     # needs a real terminal (works under curl|bash)
    case "$_ans" in [nN]*) warn "skipped — install later with:  $_cmd"; return 1 ;; esac
    info "running: $_cmd"
    if sh -c "$_cmd" < /dev/tty > /dev/tty 2>&1; then ok "$2 installed."; return 0; fi
    warn "install failed — run it manually:  $_cmd"; return 1
  fi
  warn "no interactive terminal — install $2 with:  $_cmd"   # never sudo unattended
  return 1
}

printf '\n  fmail installer\n  ===============\n\n'

# 1. Python 3.11+  (required)
find_py() {
  PY=""
  for c in python3 python3.13 python3.12 python3.11 python; do
    command -v "$c" >/dev/null 2>&1 || continue
    v=$("$c" -c 'import sys;print("%d %d"%sys.version_info[:2])' 2>/dev/null) || continue
    major=${v%% *}; minor=${v##* }
    if [ "$major" = 3 ] && [ "$minor" -ge "$MIN_PY_MINOR" ]; then PY="$(command -v "$c")"; return 0; fi
  done
  return 1
}
if ! find_py; then
  warn "Python 3.$MIN_PY_MINOR+ not found (fmail needs it)."
  offer_install python3 "Python 3" && find_py || true
fi
[ -n "$PY" ] || die "Python 3.$MIN_PY_MINOR+ is required.${PKG:+  Install it with:  $(pkg_install_cmd python3)}  Then re-run."
ok "Python: $("$PY" --version 2>&1)  ($PY)"

# 2. gpg — optional, but the encrypted vault and end-to-end encryption need it
if ! have gpg; then
  warn "gpg not found — needed for the encrypted vault and end-to-end (Autocrypt) encryption."
  offer_install gnupg "gpg (GnuPG)"
fi
if have gpg; then
  ok "gpg:    $(gpg --version 2>/dev/null | head -1)"
else
  warn "continuing WITHOUT gpg: reading/sending mail works; the vault and encryption stay OFF."
fi

# 3. download tool
if [ -z "$FMAIL_SRC" ] && ! have curl && ! have wget; then
  die "need 'curl' or 'wget' to download fmail."
fi

# 4. fetch everything into a temp staging dir
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fetch() { # <relpath> <dest>
  if [ -n "$FMAIL_SRC" ]; then
    cp "$FMAIL_SRC/$1" "$2"
  elif have curl; then
    curl -fsSL "$FMAIL_BASE_URL/$1" -o "$2"
  else
    wget -qO "$2" "$FMAIL_BASE_URL/$1"
  fi
}

info "Source: ${FMAIL_SRC:-$FMAIL_BASE_URL}"
fetch "SHA256SUMS" "$TMP/SHA256SUMS" || die "cannot retrieve the file manifest (SHA256SUMS)."
while read -r _sum name; do
  [ -n "${name:-}" ] || continue
  fetch "$name" "$TMP/$name" || die "cannot retrieve $name"
done < "$TMP/SHA256SUMS"

# 5. verify integrity (defends against a tampered/partial download)
if   have sha256sum; then ( cd "$TMP" && sha256sum -c SHA256SUMS >/dev/null ) && ok "checksums verified" || die "CHECKSUM MISMATCH — aborting (corrupt or tampered download)."
elif have shasum;    then ( cd "$TMP" && shasum -a 256 -c SHA256SUMS >/dev/null ) && ok "checksums verified" || die "CHECKSUM MISMATCH — aborting (corrupt or tampered download)."
else warn "no sha256 tool found — skipping integrity check (install one for safety)."; fi

# 6. install the program files
mkdir -p "$APP_DIR" "$BIN_DIR" "$DATA_DIR"
while read -r _sum name; do
  [ -n "${name:-}" ] || continue
  case "$name" in
    accounts.toml.example) cp "$TMP/$name" "$DATA_DIR/accounts.toml.example" ;;
    *.py|VERSION)          install -m 0644 "$TMP/$name" "$APP_DIR/$name" 2>/dev/null || { cp "$TMP/$name" "$APP_DIR/$name"; chmod 0644 "$APP_DIR/$name"; } ;;
    *)                     cp "$TMP/$name" "$APP_DIR/$name" ;;
  esac
done < "$TMP/SHA256SUMS"
ok "program installed -> $APP_DIR"

# 7. config — never clobber an existing accounts.toml
chmod 700 "$DATA_DIR" 2>/dev/null || true
if [ ! -f "$DATA_DIR/accounts.toml" ]; then
  cp "$DATA_DIR/accounts.toml.example" "$DATA_DIR/accounts.toml"
  chmod 600 "$DATA_DIR/accounts.toml" 2>/dev/null || true
  info "created $DATA_DIR/accounts.toml — edit it with your IMAP/SMTP account(s)."
else
  ok "kept your existing $DATA_DIR/accounts.toml"
fi

# 8. the `fmail` command
cat > "$BIN_DIR/fmail" <<EOF
#!/usr/bin/env bash
exec "$PY" "$APP_DIR/fmail.py" "\$@"
EOF
chmod 0755 "$BIN_DIR/fmail"
ok "command installed -> $BIN_DIR/fmail"

# 9. PATH hint
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) warn "$BIN_DIR is not in your PATH. Add this line to your shell profile:"
     warn "    export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

printf '\n'
ok "All set."
printf '  Run:    fmail            (full-screen interface)\n'
printf '          fmail --help     (command line)\n'
printf '  Config: %s/accounts.toml\n\n' "$DATA_DIR"
