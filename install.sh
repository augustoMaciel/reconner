#!/usr/bin/env bash
#
# Reconner installer
# ------------------
# - installs system tools (apt) and Python deps (pip --break-system-packages)
# - installs Reconner to ~/.reconner
# - adds a permanent `reconner` alias to your shell rc
# - generates a Chicago95-style window-with-magnifier icon
# - adds a launcher to the applications menu
#
# Usage:  ./install.sh
#
set -u

# Resolve where this script (and reconner.py) live.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
INSTALL_DIR="$HOME/.reconner"
ICONS_DIR="$INSTALL_DIR/reconner-icons"
ICON_PATH="$ICONS_DIR/reconner-ico.png"
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$DESKTOP_DIR/reconner.desktop"

# sudo only when not already root.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

c_info()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
c_ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

# ── 1. System packages (apt) ───────────────────────────────────────────────
# tkinter (GUI), Firefox (the crawler's browser), and the optional CLI probes
# the Tech Scan shells out to. Installed individually so a missing one only
# warns instead of aborting the whole batch.
APT_PKGS="python3 python3-pip python3-tk firefox-esr whatweb nmap wafw00f httpx-toolkit"
c_info "Updating apt and installing system packages…"
$SUDO apt-get update -y || c_warn "apt update failed — continuing"
for pkg in $APT_PKGS; do
    if $SUDO apt-get install -y "$pkg" >/dev/null 2>&1; then
        c_ok "apt: $pkg"
    else
        c_warn "apt: could not install '$pkg' (skipping — it's optional)"
    fi
done

# ── 2. Python packages (pip, externally-managed → --break-system-packages) ──
c_info "Installing Python dependencies with pip --break-system-packages…"
PIP="python3 -m pip"
# Core (required) — abort note if these fail.
$PIP install --break-system-packages --upgrade \
    networkx matplotlib selenium requests urllib3 beautifulsoup4 ollama \
    || c_warn "some core pip packages failed to install"
# Optional fingerprint helpers — best-effort (the app guards their imports).
for p in python-Wappalyzer dnspython python-whois; do
    $PIP install --break-system-packages "$p" >/dev/null 2>&1 \
        && c_ok "pip: $p" || c_warn "pip: optional '$p' not installed"
done

# ── 3. Install Reconner ─────────────────────────────────────────────────────
c_info "Installing Reconner to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -f "$SCRIPT_DIR/reconner.py" "$INSTALL_DIR/reconner.py"
[ -f "$SCRIPT_DIR/requirements.txt" ] && cp -f "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
[ -f "$SCRIPT_DIR/reconner_fingerprints.json" ] && \
    cp -f "$SCRIPT_DIR/reconner_fingerprints.json" "$INSTALL_DIR/"
# Bundled icons folder — the app icon (reconner-ico.png, used by the toolbar
# logo and the menu launcher) and the node-type icons the graph loads as PNGs.
if [ -d "$SCRIPT_DIR/reconner-icons" ]; then
    cp -rf "$SCRIPT_DIR/reconner-icons" "$INSTALL_DIR/"
    c_ok "Copied reconner-icons/"
fi
c_ok "Copied reconner.py"

# ── 4. Launcher icon ────────────────────────────────────────────────────────
# Prefer the bundled reconner-icons/reconner-ico.png; only synthesise one if
# it's absent.
if [ -f "$ICONS_DIR/reconner-ico.png" ]; then
    ICON_PATH="$ICONS_DIR/reconner-ico.png"
    c_ok "Using icon: $ICON_PATH"
else
c_info "Generating icon…"
mkdir -p "$ICONS_DIR"
RECONNER_ICON_OUT="$ICON_PATH" python3 - <<'PYICON' && c_ok "Icon: $ICON_PATH" || c_warn "icon generation failed (matplotlib missing?)"
import os, math
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mp

out = os.environ['RECONNER_ICON_OUT']
fig, ax = plt.subplots(figsize=(2.56, 2.56), dpi=100)
ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.set_aspect('equal'); ax.axis('off')

# Window frame (silver) with a raised 3D bevel — same look as the page icon.
x0, y0, w, h = 0.13, 0.20, 0.72, 0.60
ax.add_patch(mp.Rectangle((x0, y0), w, h, facecolor='#c0c0c0',
                          edgecolor='#000000', lw=2, zorder=2))
ax.plot([x0, x0, x0 + w], [y0, y0 + h, y0 + h], color='#ffffff', lw=2, zorder=3)
ax.plot([x0, x0 + w, x0 + w], [y0, y0, y0 + h], color='#808080', lw=2, zorder=3)

# Blue title bar (page-icon colour) with min/max/close buttons.
b = 0.028
bar_h = h * 0.24
bar_y = y0 + h - b - bar_h
ax.add_patch(mp.Rectangle((x0 + b, bar_y), w - 2 * b, bar_h, facecolor='#4a9eff',
                          edgecolor='#000000', lw=1, zorder=4))
bs = bar_h * 0.58
bx = x0 + w - b - 0.018 - bs
for _ in range(3):
    ax.add_patch(mp.Rectangle((bx, bar_y + (bar_h - bs) / 2), bs, bs,
                              facecolor='#c0c0c0', edgecolor='#000000',
                              lw=0.8, zorder=5))
    bx -= bs + 0.012

# White client area.
cl, cb = x0 + b, y0 + b
cw, ch = w - 2 * b, bar_y - (y0 + b)
ax.add_patch(mp.Rectangle((cl, cb), cw, ch, facecolor='#ffffff',
                          edgecolor='#808080', lw=1, zorder=4))

# Magnifying glass CENTRED on the window; lens diameter ≈ 3/4 of the window
# width, semi-transparent so the window shows through it.
# Centred on the window, then nudged ~10% (≈5px-equivalent) down-right.
cx, cy = x0 + w / 2.0 + 0.10, y0 + h / 2.0 - 0.10
r = 0.75 * w / 2.0
ang = math.radians(-45)                       # handle points down-right
hx1, hy1 = cx + r * math.cos(ang), cy + r * math.sin(ang)
hx2, hy2 = cx + (r + 0.22) * math.cos(ang), cy + (r + 0.22) * math.sin(ang)
ax.plot([hx1, hx2], [hy1, hy2], color='#202020', lw=11,
        solid_capstyle='round', zorder=8)
ax.add_patch(mp.Circle((cx, cy), r, facecolor='#bfe3ff', alpha=0.35,
                       edgecolor='none', zorder=9))
ax.add_patch(mp.Circle((cx, cy), r, fill=False, edgecolor='#202020',
                       lw=7, zorder=10))
ax.plot([cx - r * 0.5, cx - r * 0.1], [cy + r * 0.5, cy + r * 0.15],
        color='#ffffff', lw=3, solid_capstyle='round', zorder=11)

fig.savefig(out, transparent=True, dpi=100)
PYICON
fi

# ── 5. Permanent `reconner` alias (per detected shell) ──────────────────────
ALIAS_CMD="python3 \"$INSTALL_DIR/reconner.py &\""
MARK="# >>> reconner alias >>>"
add_alias() {  # $1 = rc file, $2 = alias line
    local rc="$1" line="$2"
    mkdir -p "$(dirname "$rc")"
    touch "$rc"
    if grep -qF "$MARK" "$rc"; then
        c_info "alias already present in $rc"
    else
        { printf '\n%s\n%s\n# <<< reconner alias <<<\n' "$MARK" "$line"; } >> "$rc"
        c_ok "alias added to $rc"
    fi
}
SHELL_NAME="$(basename "${SHELL:-/bin/bash}")"
case "$SHELL_NAME" in
    zsh)  add_alias "$HOME/.zshrc"  "alias reconner='$ALIAS_CMD'" ;;
    fish) add_alias "$HOME/.config/fish/config.fish" "alias reconner '$ALIAS_CMD'" ;;
    bash|*) add_alias "$HOME/.bashrc" "alias reconner='$ALIAS_CMD'" ;;
esac

# ── 6. Applications-menu launcher ───────────────────────────────────────────
c_info "Creating applications-menu launcher…"
mkdir -p "$DESKTOP_DIR"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Reconner
GenericName=Bug Bounty Recon Tool
Comment=Browser-driven recon: site graph, tech scan, repeater & fuzzer
Exec=python3 "$INSTALL_DIR/reconner.py"
Icon=$ICON_PATH
Terminal=false
Categories=Network;Security;Utility;
Keywords=recon;security;pentest;web;
EOF
chmod +x "$DESKTOP_FILE" 2>/dev/null || true
command -v update-desktop-database >/dev/null 2>&1 \
    && update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1 || true
c_ok "Launcher: $DESKTOP_FILE"

echo
c_ok "Reconner installed."
echo "    • Run from a new terminal:   reconner"
echo "      (or in this one:           $ALIAS_CMD )"
echo "    • Or launch it from the applications menu (search 'Reconner')."
echo "    • Reload your shell to pick up the alias:  source your rc, or open a new terminal."
