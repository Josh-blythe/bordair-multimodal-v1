#!/usr/bin/env bash
# Bordair CLI installer
# Usage: curl -sSL https://bordair.io/install.sh | bash
set -e

echo ""
echo "=== Bordair CLI installer ==="
echo ""

# Check Python
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required but not found."
    echo "Install Python 3.9+ from https://python.org and re-run."
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]; }; then
    echo "ERROR: Python 3.9+ required, found $PY_VER"
    exit 1
fi

echo "[1/3] Python $PY_VER detected"

# Check pip
if ! python3 -m pip --version >/dev/null 2>&1; then
    echo "ERROR: pip is required but not found."
    exit 1
fi

echo "[2/3] Installing bordair via pip..."

# Try pipx first (preferred - isolated install)
if command -v pipx >/dev/null 2>&1; then
    pipx install bordair --force >/dev/null 2>&1 && {
        echo "[3/3] Installed via pipx"
        INSTALLED=1
    } || {
        echo "     pipx install failed, falling back to pip --user"
    }
fi

# Fall back to pip --user
if [ -z "$INSTALLED" ]; then
    python3 -m pip install --user --upgrade bordair >/dev/null 2>&1
    echo "[3/3] Installed via pip --user"

    # Warn if ~/.local/bin isn't on PATH
    USER_BIN="$(python3 -m site --user-base)/bin"
    if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
        echo ""
        echo "NOTE: Add $USER_BIN to your PATH:"
        echo "      echo 'export PATH=\"\$PATH:$USER_BIN\"' >> ~/.bashrc"
        echo "      source ~/.bashrc"
    fi
fi

echo ""
if command -v bordair >/dev/null 2>&1; then
    BORDAIR_VERSION=$(bordair --version 2>/dev/null || echo "installed")
    echo "SUCCESS: $BORDAIR_VERSION"
    echo ""
    echo "Try:"
    echo "  bordair stats"
    echo "  bordair eval --url https://api.openai.com/v1/chat/completions --key \$OPENAI_API_KEY --model gpt-4o-mini --limit 50"
else
    echo "Install completed but 'bordair' not on PATH yet."
    echo "Open a new shell or update PATH as shown above."
fi
echo ""
