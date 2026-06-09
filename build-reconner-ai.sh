#!/usr/bin/env bash
# build-reconner-ai.sh — pull the base, build the reconner-ai Ollama model,
# smoke-test it, and (optionally) point Reconner's settings file at it.
#
# Usage:
#   ./build-reconner-ai.sh                 # default flow
#   ./build-reconner-ai.sh --no-test       # skip the smoke-test prompt
#   ./build-reconner-ai.sh --no-settings   # don't touch ~/.reconner/settings.json
#   BASE=qwen2.5:7b ./build-reconner-ai.sh # override the base model
#
# Re-running is safe — `ollama create` overwrites the tag in place.

set -euo pipefail

MODEL_NAME="${MODEL_NAME:-reconner-ai}"
BASE="${BASE:-qwen2.5-coder:7b-instruct-q4_K_M}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELFILE="${MODELFILE:-$SCRIPT_DIR/Modelfile.reconner-ai}"
SETTINGS="$HOME/.reconner/settings.json"

DO_TEST=1
DO_SETTINGS=1
for arg in "$@"; do
    case "$arg" in
        --no-test)     DO_TEST=0 ;;
        --no-settings) DO_SETTINGS=0 ;;
        -h|--help)
            sed -n '2,12p' "$0"
            exit 0 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

say() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m✓   %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m✗   %s\033[0m\n' "$*" >&2; exit 1; }

# ─── 0. preconditions ────────────────────────────────────────────────────
command -v ollama >/dev/null 2>&1 \
    || die "ollama not installed. Try: curl -fsSL https://ollama.com/install.sh | sh"
ollama list >/dev/null 2>&1 \
    || die "ollama daemon not reachable. Start it with: sudo systemctl start ollama"
[[ -f "$MODELFILE" ]] \
    || die "Modelfile not found at: $MODELFILE"

# ─── 1. pull base ────────────────────────────────────────────────────────
say "Ensuring base model is present: $BASE"
if ollama list | awk '{print $1}' | grep -qx "$BASE"; then
    ok "base already pulled"
else
    ollama pull "$BASE"
    ok "base pulled"
fi

# If the user overrode BASE, rewrite the FROM line on the fly into a temp
# Modelfile so we don't mutate the checked-in one.
BUILD_MODELFILE="$MODELFILE"
if [[ "$BASE" != "qwen2.5-coder:7b-instruct-q4_K_M" ]]; then
    BUILD_MODELFILE="$(mktemp)"
    trap 'rm -f "$BUILD_MODELFILE"' EXIT
    awk -v base="$BASE" '
        BEGIN { replaced = 0 }
        /^FROM[[:space:]]/ && !replaced { print "FROM " base; replaced = 1; next }
        { print }
    ' "$MODELFILE" > "$BUILD_MODELFILE"
    say "Using temporary Modelfile with FROM $BASE"
fi

# ─── 2. build ────────────────────────────────────────────────────────────
say "Building $MODEL_NAME from $BUILD_MODELFILE"
ollama create "$MODEL_NAME" -f "$BUILD_MODELFILE"
ok "$MODEL_NAME built"

# ─── 3. smoke test ───────────────────────────────────────────────────────
if (( DO_TEST )); then
    say "Smoke test (Ctrl-C to skip)"
    ollama run "$MODEL_NAME" "Analyse this fingerprint:
Server: nginx/1.18.0
Set-Cookie: PHPSESSID=abc; XSRF-TOKEN=xyz
Body markers: <meta name='generator' content='WordPress 6.4'>, /wp-json/
Found path: /admin/ (200, 9.8 KB)"
    ok "smoke test returned"
fi

# ─── 4. wire Reconner ────────────────────────────────────────────────────
if (( DO_SETTINGS )); then
    say "Pointing Reconner at $MODEL_NAME (settings: $SETTINGS)"
    mkdir -p "$(dirname "$SETTINGS")"
    python3 - "$SETTINGS" "$MODEL_NAME" <<'PY'
import json, sys, pathlib
path = pathlib.Path(sys.argv[1])
model = sys.argv[2]
data = {}
if path.exists():
    try:
        data = json.loads(path.read_text())
    except Exception:
        data = {}
data['model'] = model
path.write_text(json.dumps(data, indent=2) + '\n')
print(f'wrote model={model!r} to {path}')
PY
    ok "settings updated — Reconner will use $MODEL_NAME on the next AI call"
fi

say "Done."
