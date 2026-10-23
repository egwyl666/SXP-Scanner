#!/usr/bin/env bash
#
# SXP Scanner installer.
#
#   curl -fsSL https://raw.githubusercontent.com/egwyl666/SXP-Scanner/work/fixit1.0/install.sh | sudo bash
#
# or, from a clone:
#
#   sudo ./install.sh
#
set -euo pipefail

REPO="https://github.com/egwyl666/SXP-Scanner.git"
BRANCH="${SXP_BRANCH:-work/fixit1.0}"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
LIBDIR="$PREFIX/lib/sxp-scanner"

echo "==> SXP Scanner installer"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required but was not found in PATH." >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ] && [ ! -w "$BINDIR" ]; then
    echo "Error: writing to $BINDIR needs root. Re-run with sudo." >&2
    exit 1
fi

# If run from inside a checkout, install that; otherwise fetch a fresh copy.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/sxp.py" ]; then
    SRC="$SCRIPT_DIR"
    CLEANUP=""
else
    command -v git >/dev/null 2>&1 || { echo "Error: git is required to fetch the sources." >&2; exit 1; }
    SRC="$(mktemp -d)"
    CLEANUP="$SRC"
    echo "==> Cloning $REPO ($BRANCH)"
    git clone --depth 1 --branch "$BRANCH" "$REPO" "$SRC" >/dev/null 2>&1
fi

echo "==> Installing to $LIBDIR"
install -d "$LIBDIR"
install -m 0644 "$SRC/sxp.py" "$LIBDIR/sxp.py"

echo "==> Creating launcher $BINDIR/sxp"
install -d "$BINDIR"
cat > "$BINDIR/sxp" <<EOF
#!/usr/bin/env bash
# SXP Scanner needs raw sockets; re-exec under sudo unless already root.
if [ "\$(id -u)" -ne 0 ]; then
    exec sudo python3 "$LIBDIR/sxp.py" "\$@"
fi
exec python3 "$LIBDIR/sxp.py" "\$@"
EOF
chmod 0755 "$BINDIR/sxp"

[ -n "$CLEANUP" ] && rm -rf "$CLEANUP"

echo "==> Done. Run it with:"
echo "      sxp"
