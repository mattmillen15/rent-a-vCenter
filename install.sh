#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VMKATZ_BIN="$HOME/.local/bin/vmkatz"

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[0;34m%s\033[0m\n' "$*"; }
die()   { red "[-] $*"; exit 1; }

blue "[*] rent-a-vcenter installer"
echo ""

# ── Python ────────────────────────────────────────────────────────────────────
python3 --version &>/dev/null || die "python3 not found"
PY=$(python3 -c 'import sys; print(sys.version_info >= (3,8))')
[ "$PY" = "True" ] || die "python3.8+ required"

blue "[*] Setting up Python virtual environment..."
python3 -m venv "$SCRIPT_DIR/venv"
source "$SCRIPT_DIR/venv/bin/activate"
pip install -q --upgrade pip
pip install -q -r "$SCRIPT_DIR/requirements.txt"
green "[+] Python dependencies installed"

# ── Rust / cargo ──────────────────────────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
    blue "[*] Rust not found — installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    source "$HOME/.cargo/env"
fi
cargo --version &>/dev/null || die "cargo still not available after rustup install"
green "[+] Rust/cargo: $(cargo --version)"

# ── vmkatz ────────────────────────────────────────────────────────────────────
if command -v vmkatz &>/dev/null; then
    green "[+] vmkatz already in PATH: $(command -v vmkatz)"
else
    blue "[*] Building vmkatz..."
    VMKATZ_TMP=$(mktemp -d)
    git clone -q https://github.com/nikaiw/VMkatz "$VMKATZ_TMP/VMkatz"
    cargo build -q --release --manifest-path "$VMKATZ_TMP/VMkatz/Cargo.toml"
    mkdir -p "$HOME/.local/bin"
    cp "$VMKATZ_TMP/VMkatz/target/release/vmkatz" "$VMKATZ_BIN"
    chmod +x "$VMKATZ_BIN"
    rm -rf "$VMKATZ_TMP"
    green "[+] vmkatz installed to $VMKATZ_BIN"

    # Warn if ~/.local/bin isn't in PATH
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) printf '\n'; red "[!] Add to your shell profile:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
    esac
fi

# ── Launcher wrapper ──────────────────────────────────────────────────────────
LAUNCHER="$HOME/.local/bin/rent-a-vcenter"
mkdir -p "$HOME/.local/bin"
cat > "$LAUNCHER" <<WRAPPER
#!/usr/bin/env bash
source "$SCRIPT_DIR/venv/bin/activate"
exec python3 "$SCRIPT_DIR/rent-a-vcenter.py" "\$@"
WRAPPER
chmod +x "$LAUNCHER"
green "[+] Launcher installed: $LAUNCHER"

# Warn if ~/.local/bin isn't in PATH
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) printf '\n'
       red "[!] ~/.local/bin is not in your PATH — add to your shell profile:"
       red "    export PATH=\"\$HOME/.local/bin:\$PATH\""
       red "    then open a new shell or run: source ~/.bashrc (or ~/.zshrc)" ;;
esac

echo ""
green "[+] Done — run from anywhere:"
echo "    rent-a-vcenter --help"
