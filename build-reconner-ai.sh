#!/usr/bin/env bash
# build-reconner-ai.sh — pull the base, build BOTH Reconner Ollama models
# (reconner-ai for analysis + wizard-ai for the animated Wizard chat),
# smoke-test them, and (optionally) point Reconner's settings file at them.
#
# Usage:
#   ./build-reconner-ai.sh                 # default flow (both models)
#   ./build-reconner-ai.sh --no-test       # skip the smoke-test prompts
#   ./build-reconner-ai.sh --no-settings   # don't touch ~/.reconner/settings.json
#   ./build-reconner-ai.sh --no-wizard     # build only reconner-ai
#   BASE=qwen2.5:7b ./build-reconner-ai.sh # override the base model (both)
#
# Re-running is safe — `ollama create` overwrites the tag in place.

set -euo pipefail

MODEL_NAME="${MODEL_NAME:-reconner-ai}"
WIZARD_NAME="${WIZARD_NAME:-wizard-ai}"
BASE="${BASE:-qwen2.5-coder:7b-instruct-q4_K_M}"
DEFAULT_BASE="qwen2.5-coder:7b-instruct-q4_K_M"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELFILE="${MODELFILE:-$SCRIPT_DIR/Modelfile.reconner-ai}"
WIZARD_MODELFILE="${WIZARD_MODELFILE:-$SCRIPT_DIR/Modelfile.wizard-ai}"
WIZARD_MEMORY_DIR="$HOME/.wizard-ai"
SETTINGS="$HOME/.reconner/settings.json"

DO_TEST=1
DO_SETTINGS=1
DO_WIZARD=1
for arg in "$@"; do
    case "$arg" in
        --no-test)     DO_TEST=0 ;;
        --no-settings) DO_SETTINGS=0 ;;
        --no-wizard)   DO_WIZARD=0 ;;
        -h|--help)
            sed -n '2,13p' "$0"
            exit 0 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

say() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m✓   %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m✗   %s\033[0m\n' "$*" >&2; exit 1; }

# build_model NAME MODELFILE — create the tag, rewriting its FROM line into a
# temp Modelfile when BASE was overridden (so the checked-in file is untouched).
build_model() {
    local name="$1" mf="$2" build_mf="$2"
    if [[ "$BASE" != "$DEFAULT_BASE" ]]; then
        build_mf="$(mktemp)"
        awk -v base="$BASE" '
            BEGIN { replaced = 0 }
            /^FROM[[:space:]]/ && !replaced { print "FROM " base; replaced = 1; next }
            { print }
        ' "$mf" > "$build_mf"
        say "Building $name from $mf (FROM $BASE)"
    else
        say "Building $name from $mf"
    fi
    ollama create "$name" -f "$build_mf"
    [[ "$build_mf" != "$mf" ]] && rm -f "$build_mf"
    ok "$name built"
}

# ─── 0. preconditions ────────────────────────────────────────────────────
command -v ollama >/dev/null 2>&1 \
    || die "ollama not installed. Try: curl -fsSL https://ollama.com/install.sh | sh"
ollama list >/dev/null 2>&1 \
    || die "ollama daemon not reachable. Start it with: sudo systemctl start ollama"
[[ -f "$MODELFILE" ]] \
    || die "Modelfile not found at: $MODELFILE"
(( DO_WIZARD )) && [[ ! -f "$WIZARD_MODELFILE" ]] \
    && die "Wizard Modelfile not found at: $WIZARD_MODELFILE (or pass --no-wizard)"

# ─── 1. pull base ────────────────────────────────────────────────────────
say "Ensuring base model is present: $BASE"
if ollama list | awk '{print $1}' | grep -qx "$BASE"; then
    ok "base already pulled"
else
    ollama pull "$BASE"
    ok "base pulled"
fi

# ─── 2. build models ─────────────────────────────────────────────────────
build_model "$MODEL_NAME" "$MODELFILE"
if (( DO_WIZARD )); then
    build_model "$WIZARD_NAME" "$WIZARD_MODELFILE"
    # Prepare the Wizard's persistent-memory folder (~/.wizard-ai) so the
    # assistant can store/recall conversations on first run.
    mkdir -p "$WIZARD_MEMORY_DIR"
    ok "memory folder ready: $WIZARD_MEMORY_DIR"
fi

# ─── 3. smoke test ───────────────────────────────────────────────────────
if (( DO_TEST )); then
    say "Smoke test: $MODEL_NAME (Ctrl-C to skip)"
    ollama run "$MODEL_NAME" "Analyse this fingerprint:
Server: nginx/1.18.0
Set-Cookie: PHPSESSID=abc; XSRF-TOKEN=xyz
Body markers: <meta name='generator' content='WordPress 6.4'>, /wp-json/
Found path: /admin/ (200, 9.8 KB)"
    ok "$MODEL_NAME smoke test returned"
    if (( DO_WIZARD )); then
        say "Smoke test: $WIZARD_NAME (Ctrl-C to skip)"
        ollama run "$WIZARD_NAME" "Greet me as a wizard, then in one line tell me what to check on a login form served over http."
        ok "$WIZARD_NAME smoke test returned"
    fi
fi

# ─── 4. wire Reconner ────────────────────────────────────────────────────
if (( DO_SETTINGS )); then
    say "Pointing Reconner at $MODEL_NAME / $WIZARD_NAME (settings: $SETTINGS)"
    mkdir -p "$(dirname "$SETTINGS")"
    WIZ="$( (( DO_WIZARD )) && echo "$WIZARD_NAME" || echo '' )"
    python3 - "$SETTINGS" "$MODEL_NAME" "$WIZ" <<'PY'
import json, sys, pathlib
path = pathlib.Path(sys.argv[1])
model = sys.argv[2]
wizard = sys.argv[3] if len(sys.argv) > 3 else ''
data = {}
if path.exists():
    try:
        data = json.loads(path.read_text())
    except Exception:
        data = {}
data['model'] = model
if wizard:
    data['wizard_model'] = wizard
path.write_text(json.dumps(data, indent=2) + '\n')
print(f'wrote model={model!r}' + (f', wizard_model={wizard!r}' if wizard else '')
      + f' to {path}')
PY
    ok "settings updated — Reconner will use $MODEL_NAME (+ $WIZARD_NAME) on the next AI call"
fi

say "Done."
