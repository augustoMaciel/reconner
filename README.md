# Reconner

**Browser-driven web reconnaissance + intercepting proxy for pentests, bug bounties, and lab/CTF study.**

Reconner drives a real browser to *navigate a target like a user would* — following links, clicking controls, watching the traffic the page actually makes — and lays out what it finds as an interactive **Site Structure tree**: pages, scripts, files, redirects, and **API endpoints**. It also bundles an **OWASP ZAP / Burp-style HTTP/HTTPS intercepting proxy** — open a browser through it, trap requests *and* responses, edit them, and forward or drop. On top of that it adds technology fingerprinting, subdomain discovery, an AI analysis pass, and built-in **Repeater** and **Fuzzer** tools, all in a single Windows-95-styled GUI.

> ⚠️ **Authorized use only.** Reconner actively crawls, probes, intercepts, and (in Aggressive mode) fuzzes targets. Only run it against systems you own or are explicitly authorized to test (your own labs, CTFs, or in-scope bug-bounty programs).

---

## Highlights

- **Intercepting proxy (HTTP + HTTPS)** — a built-in ZAP/Burp-style proxy (default `127.0.0.1:8080`). Flip **Intercept ON** and trap each request and response in a repeater-style 4-box editor: **▶** forward one step, **✕** drop, **Save as Node** to keep a reviewed transaction in the graph. A **History** popup logs every relayed transaction — scope-filtered, searchable, sortable (incl. request/response size), with right-click **Send to Repeater** / **Save as Node** and JSON export. HTTPS is decrypted with an auto-generated CA (per-host certs minted on the fly). Click **Open Browser** to launch your system browser through the proxy (CA auto-trusted), or point any client at the port. Out-of-scope requests are never sent.
- **Intercept-driven full-surface crawl** — start a scan while **Intercept is ON** and Reconner drops *all* safety gates (whitelist, destructive veto, safe-click heuristics) and routes the crawl browser through the proxy — so it exercises **everything** (every control, GET param, POST body, optional feature) and you vet each request in the interceptor before it goes out.
- **User-like crawling** — a real browser (Chrome-first, Firefox fallback via Selenium) renders JavaScript, follows links, and clicks non-destructive controls so SPAs reveal their routes and API calls. The browser presents a normal (non-headless) User-Agent so WAF/CDN bot filters don't blanket-block the crawl.
- **API endpoint discovery** — passively from live XHR/fetch + JS/response-body mining, and actively via spec/well-known probing (and a comprehensive wordlist in Aggressive mode). Real data endpoints are labeled `api`; binary downloads are correctly labeled `file`.
- **Browser & Fuzzing scan types** — pick **Browser** (crawl like a user) or **Fuzzing** (path-wordlist directory/endpoint discovery, no browser) in the Modes dropdown; either intensity (Stealth/Normal/Aggressive) applies. Both build the **same graph**, so a crawl and a fuzz complement each other — fuzzing grafts unlinked dirs (like an `/images/` upload target) onto the crawled map.
- **Web shell tooling** — mark any node as an uploaded **web shell** (file/path + command parameter) and drive it from a built-in **Web Shell terminal**: a bold, cyan-on-black console that sends `?param=<command>` and parses the response (clean output, or a concise error line). Optional URL-encoding on the wire only.
- **POST/parameter recovery + safe auto-probing** — for non-GET endpoints, Reconner recovers the **request body and parameters**: it (1) structurally parses any OpenAPI/Swagger spec it finds (`requestBody`/`parameters`, resolving `$ref`) into a fuzzable body template, (2) submits benign **search/filter** forms during the crawl so the real request body is captured from live traffic, and (3) mines JS **source maps** (`.js.map`) for endpoints and `.post(url, {…})` body shapes. Endpoints whose path is on the **safe-path whitelist** (read/query verbs by default) and not destructive are **auto-probed** — required fields are recovered from the server's validation errors and optional ones (e.g. `orderBy`) from source request-models. Destructive paths (delete/exec/logout/upload/credential ops) are **never auto-sent** — they're seeded as ready-to-edit requests in the Repeater. See [Safe-path whitelist](#safe-path-whitelist).
- **Authenticated scans** — flip on **Auth Scan** and Reconner pauses when it hits a login wall, shows you the exact request it's about to send, and lets you supply the credential (Bearer / Basic / API key / Cookie / Custom header / Form login). It's then reused for every request to that host.
- **Subdomain discovery** — passive (links, traffic, JS) plus certificate-transparency (crt.sh) in Aggressive mode, each subdomain getting its own graph and a full crawl. Discovery is **unbounded** (no cap on how many are found or crawled); the only limiter is the **Max concurrent browsers** setting, which throttles how many crawl at once while the rest queue.
- **Tech fingerprinting** — servers, frameworks, CMSs, CDNs, WAFs, analytics, and more, with optional `whatweb` / `nmap` / `wafw00f` probes.
- **AI analysis** — an optional local **Ollama** model (`reconner-ai`) summarizes a node's security-relevant details.
- **The Wizard** — an animated Office-Assistant-style **Merlin** companion (the wizard-hat button by *Nodes:* in the status bar) that chats in a playful-but-precise *"wizardy"* voice, powered by a second local model (`wizard-ai`). He greets, idles, reacts while you type, thinks, and acts out a writing animation as his answer streams in — and does a trick when you click around the app.
- **Repeater & Fuzzer** — edit and resend any captured request, with a dedicated **Body** box (and a split request/response view) so multipart/JSON bodies are easy to craft; mark `{{FUZZ}}` positions (in the request *or* body) and run wordlists with ffuf-style match/filter.
- **High-fidelity, de-noised map** — failure states are kept distinct from real responses: transport errors (request never landed) and `5xx`/unavailable upstreams are flagged on the node (shown in the inspector), while `401`/`403`/`404` stay as legitimate attack surface. Per-locale duplicate endpoints (`…/en/…`, `…/pt/…`, `…/ar-MA/…`) collapse into one representative node so signal isn't buried in repetition.
- **Export / import** — save a scan (all graphs + data) to JSON and reload it later for offline review.

---

## Requirements

- **Linux** with a desktop (the GUI uses Tk). Built and tested on **Kali**.
- **Python 3** with `tkinter`.
- A **browser + driver**: Google Chrome/Chromium (preferred — enables auth header injection) or Firefox/geckodriver. Selenium Manager fetches the matching driver automatically in most cases.
- **Python packages:** `selenium`, `requests`, `beautifulsoup4`, `cryptography` (HTTPS-interception CA), `Pillow` (tree node icons), `networkx`, `matplotlib`, `ollama` (see `requirements.txt`).
- **Optional CLI tools:** `certutil` (`libnss3-tools`) so the **Open Browser** Firefox profile can trust the proxy CA without sudo; Tech Scan also shells out to `whatweb`, `nmap`, `wafw00f`, `httpx` when present.
- **Optional Python helpers:** `python-Wappalyzer`, `dnspython`, `python-whois`.
- **Optional:** [Ollama](https://ollama.com) for the AI analysis feature.

---

## Installation

### One-shot installer (recommended on Kali)

```bash
git clone <this-repo> reconner && cd reconner
./install.sh
```

The installer:
- installs system packages (`python3-tk`, `firefox-esr`, `whatweb`, `nmap`, `wafw00f`, `httpx-toolkit`) and the Python deps,
- copies Reconner to `~/.reconner/`,
- adds a permanent **`reconner`** shell alias,
- adds a **Reconner** entry to your applications menu.

Open a new terminal (to pick up the alias) and run:

```bash
reconner
```

### Manual install

```bash
sudo apt install -y python3 python3-pip python3-tk firefox-esr
python3 -m pip install --break-system-packages -r requirements.txt
python3 reconner.py
```

For full auth-header injection on browser navigation, also install Chrome/Chromium:

```bash
sudo apt install -y chromium    # or install Google Chrome
```

---

## Optional: AI analysis setup

The **Analyze with AI** buttons and **The Wizard** chat use local Ollama models. To enable them:

```bash
# Install Ollama first: curl -fsSL https://ollama.com/install.sh | sh
./build-reconner-ai.sh
```

This builds **both** models — **`reconner-ai`** (from `Modelfile.reconner-ai`, used for node/fingerprint analysis) and **`wizard-ai`** (from `Modelfile.wizard-ai`, the conversational model behind [The Wizard](#the-wizard)) — tuned to run comfortably on modest hardware, then points Reconner's settings at them. Pass `--no-wizard` to build only `reconner-ai`. You can change either model name / the host any time in **⚙ Settings ▸ AI / Ollama**. If Ollama isn't running, the rest of Reconner works normally — only the AI features are inert.

---

## Running a scan

1. **Launch** Reconner (`reconner`, the apps-menu entry, or `python3 ~/.reconner/reconner.py`).
2. **Enter a target URL** in the toolbar (e.g. `https://example.com`).
3. Pick a **Mode** (see below).
4. Click **SCAN TARGET** (or press Enter in the URL field).

Reconner opens a browser, crawls the target, and streams nodes into the **Site Structure** tree as it finds them. Click any node to inspect it in the **Node Inspector** panel. Click **STOP** to end early.

The main window is laid out as **Site Structure** (tree, left) | **Proxy** (interceptor, right), with the **Node Inspector** spanning the full width below both.

### The toolbar

```
[ RECONNER ]  Target URL: [______________]   Scope: [______________]
[ Tech Scan ] [ Modes ▾ ]  Auth Scan ▭●  [ SCAN TARGET ] [ STOP ]  ▓▓▓░ status   ⚙ Settings
```

**Scope** (next to Target URL) constrains both the crawl and the proxy: `*` is a wildcard and comma/newline separates OR'd patterns (e.g. `https://*.example.com/*`). Empty = no restriction. **Any request that doesn't match the scope is never sent** — by the crawler or the proxy. Press Enter to apply it to a running proxy.

The crawl is **unbounded** — there's no max-pages cap; it follows every in-scope page it finds. Throttle resource use via the **Max concurrent browsers** / **Max fingerprint workers** settings (see [Settings](#settings)).

The **Auth Scan** slide switch (red = off, green = on) toggles authenticated scanning (see below).

### Scan modes

The **Modes ▾** dropdown holds two grouped choices that are **always both active** — an *intensity* and a *type*:

**Intensity** — how hard Reconner hits the target:

| Mode | Footprint | What it adds |
|------|-----------|--------------|
| **Stealth** | Throttled, low-noise | Paces requests to slip under WAF/rate limits; passive tech probes only; **no** active API probing. |
| **Normal** | Balanced (default) | Steady footprint; standard tech probes; **high-signal API probing** (swagger/openapi, `/api` roots, health/actuator, `/.well-known`). |
| **Aggressive** | Maximum coverage | No throttle; every probe incl. `nmap`/WAF fingerprinting, crt.sh subdomain enumeration, and a **comprehensive API path wordlist**. |

**Type** — how Reconner discovers:

| Type | What it does |
|------|--------------|
| **Browser** (default) | The full Selenium crawl — navigate the target like a user, following links and watching live traffic. |
| **Fuzzing** | **No browser.** Runs only the path-wordlist pass (directory/endpoint discovery: `images`, `admin`, `uploads`, `api`, …) under the host root and any live bases — finding things nothing links to, like an `/images/` upload dir. Uses **no whitelist** and is paced by the chosen intensity (throttled in Stealth, full-speed in Normal/Aggressive). |

**The two types build the same graph.** Re-scanning a target you've already mapped **adds to** its graph instead of wiping it, so Browser and Fuzzing complement each other in either order: crawl the site, then switch to Fuzzing to graft the unlinked directories onto the same map (a Fuzzing pass never overwrites a richer browser-crawled node). To start a target over from scratch, use the tree's **Options ▸ Clear** first.

Fuzzing hits are added to the tree so you can inspect, Repeater, or **Set Shell** on them. For targeting one specific position instead, use the manual **Fuzzer** with a `{{FUZZ}}` marker in the URL path.

---

## Authenticated scans

Many API endpoints live behind a login. Tick **Auth Scan** before starting and Reconner handles it **reactively, per host**:

1. When a request hits an **auth wall** (HTTP `401`, a `403` advertising `WWW-Authenticate`, or a visible login form), the scan **pauses** and a popup appears.
2. The popup shows the **exact request it's about to send** (read-only) and updates live as you type.
3. Pick an **authentication type** and fill the fields:
   - **Bearer token** — paste a JWT/access token (`Authorization: Bearer …`)
   - **HTTP Basic** — username + password
   - **Form login** — username + password, typed into the page's login form
   - **API key** — key value (+ optional header name, default `X-API-Key`)
   - **Custom header** — any header name + value
   - **Cookie** — a raw cookie string
4. Click **Apply & retry** — the credential is stored **for that host** and injected into every later request to it (probes, mined endpoints, replays, and — on Chrome — browser navigation). Or choose **Skip host** / **Continue unauthenticated**.

Credentials are **session-only** (never written to disk). Some things are out of scope by design: HMAC-signed (e.g. AWS SigV4) and mTLS endpoints can't be re-authenticated for new requests, and mobile-app-only token gateways require a token you paste in.

> **Why Chrome?** Chrome's DevTools Protocol lets Reconner inject auth headers into top-level browser navigations. Firefox can't, so on Firefox auth still works for the request/probe path and for cookie/form logins — just not header-injection on page loads. Install Chrome for full coverage.

---

## Safe-path whitelist

Reconner auto-probes discovered non-GET endpoints (sending them and recovering their parameters) — but only the ones it can prove are safe. The **safe-path whitelist** (in **⚙ Settings ▸ Performance**) is the allowlist that decides which paths qualify. This replaces the old *Probe POST* checkbox: control is now per-path instead of a global on/off.

How it works when the whitelist is **ON** (the default):

- A discovered non-GET endpoint is **auto-probed** (any method) only when its path matches a whitelist rule **and** is not destructive. Required body fields are recovered from the server's validation errors; optional fields (e.g. `orderBy`, `order`, `filters`) from source request-models.
- The textbox is pre-filled with **default read/query globs** (`*search*`, `*list*`, `*get*`, `*view*`, `*detail*`, `*count*`, `*status*`, …). One glob per line (`*` = wildcard), `#` for comments. Edit freely; **Reset** restores the defaults, **Load list…** appends paths from a file.
- **Destructive paths are always withheld** — `delete`/`remove`/`exec`/`run`/`logout`/`upload`/`install`/credential ops (`password`/`forgot`/`verify`/`token`/`auth`/…), and the `DELETE` method. They're seeded un-sent and surfaced in the inspector (request + response panes show the path and a *"Withheld — …"* note) so you can fire them manually in the Repeater.
- **Override:** to deliberately auto-probe a destructive path, add its **exact path** (no `*`) to the whitelist. A wildcard like `*delete*` never overrides the veto — only a literal path you typed does.
- Auto-probed paths are added to the **live whitelist** as the scan runs (an auditable record, shown in the log).
- **Not gated:** passive GET reads and label-filtered control/navigation clicks happen everywhere regardless — the whitelist governs auto-sent non-GET requests, not browsing.

Turning the whitelist **OFF** (green/red toggle, asks to confirm) lets Reconner auto-probe **every** non-destructive non-GET path it finds, not just the listed ones. Destructive paths stay withheld even then.

---

## The Site Structure tree

Each scan builds a collapsible **tree** of what it found, nested by parent → child. Every row shows an **expand/collapse arrow** (only when the node has children), a **type icon**, and the node's **name**. Node types:

| Type | Meaning |
|------|---------|
| **page** | A browsable HTML page or SPA route |
| **api** (endpoint) | A real data endpoint (JSON/XML/etc.) |
| **file** | A downloadable asset (image, pdf, archive, JS chunk served as a file…) |
| **script** | A JavaScript bundle |
| **redirect** | An endpoint that 3xx-redirects |
| **shell** | A node you've marked as an uploaded **web shell** — drive it from the built-in Web Shell terminal |

Locale-duplicate endpoints (`…/en/…`, `…/pt/…`, …) collapse into one representative node; the inspector's Content tab lists the collapsed locale codes.

Tree controls — dropdowns on **top**, search on the **bottom**:

- **Subdomains ▾** — switch between the entry host's tree and each discovered subdomain's tree.
- **Options ▾** — **Expand all** / **Collapse all**, **Clear**, **Export JSON**, **Export ALL graphs (JSON)**, and **Load scan JSON…** to reopen a saved scan offline.
- **Filter ▾** — show/hide nodes by type (page / file / redirect / script / endpoint / shell).
- **Search** (bottom row) — type to find nodes by URL/title; **◀ / ▶** step through matches (the box tints red when nothing matches).
- **Right-click** — right-click a **row** for its inspector tools (Analyze, Repeater, Fuzzer, Set/Open Shell, Delete Node — Delete is enabled only for nodes you created), or empty space for the Options/Filter menus.

---

## Proxy interceptor

Reconner includes a ZAP/Burp-style intercepting proxy in the **Proxy** panel (top-right), listening on `127.0.0.1:8080` by default (configurable in **⚙ Settings ▸ Proxy**). It relays **HTTP and HTTPS**, decrypting TLS with an auto-generated CA stored in `~/.reconner/ca/` (a per-host leaf cert is minted on demand).

**Toolbar:**

- **Intercept: ON/OFF** — green/red toggle. When ON, each transaction is trapped for review; when OFF the proxy passes everything through transparently.
- **▶** — forward the current item one step (a request → send it and trap its response; a response → deliver it and move to the next item).
- **✕** — drop the current item (the client gets a 502 / the connection closes).
- **Open Browser** — launch your system browser (Firefox preferred, Chromium fallback) through the proxy in a dedicated profile, with the CA trusted, so you can browse and have traffic intercepted. Opens the Target URL if one is set, otherwise a blank page.
- **History** — open the traffic-history popup (see below).
- **Save as Node** (top-right) — add the displayed transaction to the Site Structure graph as a node (parented under its `Referer`). Enabled only once a request has been sent and its response caught.
- **Encode typing** (bottom-right) — three mutually-exclusive checkboxes (**URL-encode** / **Base64-encode** / **Hex-encode typing**) that transform characters as you type them into the request boxes, so you can enter a payload already encoded. The same trio appears in the Repeater and Fuzzer; the Fuzzer also has an **encode-payloads** trio that encodes each wordlist payload before it is sent.

The four editor boxes (**Request Header / Request Body** over **Response Header / Response Body**, with a draggable splitter between headers and bodies) show the trapped request or response as raw HTTP. **Edit anything and forward** — both the request that gets sent and the response that gets delivered are taken from the boxes, so you can e.g. tamper a parameter on the way out or edit a response to bypass a client-side check. Every completed transaction is also added to the Site Structure tree. **Out-of-scope requests are never sent** (see Scope, above). The play/drop/Open-Browser buttons are greyed and blocked while Intercept is OFF.

**Proxy History.** The **History** button opens a popup logging **every transaction the proxy relayed** (trapped or not). A list on the left — columns **# · Method · Code · Req. Size · Resp. Size · URL**, each header **click-sorts** (none → ascending → descending) — sits beside four read-only boxes showing the selected transaction's request headers/body and response headers/body. A **Search** box with ◀ / ▶ steppers walks the matches, scoped to the **main window's Scope** (so the list only shows in-scope traffic). **Right-click** a row for **Send to Repeater** / **Save as Node** (or, on empty space, **Clear All History** / **Export as JSON**); buttons at the bottom **Clear Selected**, **Clear All History**, **Export as JSON**, **Send to Repeater**, and **Save as Node**.

**HTTPS trust.** For HTTPS interception your browser must trust the Reconner CA. The **Open Browser** Firefox profile is configured automatically: it imports the CA with `certutil` when available, otherwise it installs the CA into the system trust store (a one-time `pkexec`/sudo prompt) and enables Firefox's enterprise roots. For your *own* browser, use **Settings ▸ Proxy ▸ Export CA cert…** / **Install into system trust** and import/trust `~/.reconner/ca/reconner-ca.crt`. (Tip: `sudo apt install libnss3-tools` enables the no-sudo per-profile path.)

---

## Inspecting a node

Select a node to open the **Node Inspector** panel: its URL, title, status, content type, GET/POST parameters, request & response headers and bodies, and the requests it made. The **status** is honest about *how* it was determined — a real HTTP code (e.g. `503`), `ERROR — <reason>` when the request never completed, or `NOT SENT — unsafe method` for a `POST`/`PUT`/… observed in traffic but not auto-replayed (open it in the Repeater to send it). From here:

Per-node tools live in the inspector's **Options ▾** menu (also on the graph's right-click menu):

- **Analyze with AI** — summarize the node's security-relevant surface (needs Ollama).
- **Send to Repeater** — open the raw request in an editor, tweak anything, resend it, and **Save as New Node** to add the result to the graph. The request line + headers, the **request body**, and the **response** (status/headers and body) each get their own pane, so crafting a multipart upload or JSON body is straightforward. Switch between **Data In** (the request that fetched the node + its response) and **Data Out** (the requests the node can make).
- **Send to Fuzzer** — mark `{{FUZZ}}` positions in the request **or the body**, load a wordlist, and replay with **ffuf-style match/filter** (`-mc`/`-fc`/`-ms`/`-fs`) and Cluster-bomb / Pitchfork modes. Mark a position **in the URL path** to brute-force and discover hidden endpoints, then **Save Node** the hits.
- **Set Shell / Open Shell** — once you've landed an uploaded web shell, **Set Shell** spawns a new **shell** node as a *child* of the selected node. You give the shell file/path and the command parameter (both required — no default). The path is resolved against the selected node's URL **as a directory**: on a node `http://example.com/images`, entering `shell.jpg` yields `http://example.com/images/shell.jpg` (an absolute path like `/up/s.php` points anywhere on the host). The new node gets the black-terminal shell icon and is auto-selected. **Open Shell** then opens an interactive **Web Shell** terminal (bright-green-on-black, freely resizable): type a command, hit Enter, and Reconner sends `…/shell.jpg?<param>=<command>` and prints the raw response. A **URL Encode Commands** toggle percent-encodes the command on the wire only — you still see what you typed.

---

## The Wizard

Click the **wizard-hat button** next to *Nodes:* in the status bar to summon **The Wizard** — an animated **Merlin** (the classic Office-Assistant character) who chats about your target in a playful *"wizardy"* voice while delivering precise pentest/AppSec guidance. He's powered by the local **`wizard-ai`** model (separate from `reconner-ai`; set under **⚙ Settings ▸ AI / Ollama ▸ Wizard Model**).

Type a question and press **Enter** — his reply streams into a yellow speech balloon. The animation is fully reactive: he **greets** on open, **idles** with little gestures, starts **listening** when you type, **thinks** while the model is silent, acts out a **writing** animation while the answer streams, and plays a **farewell** when you close the window (the close waits for it to finish). Click the wizard — or anything in the app — for a **trick**.

Every chat **starts fresh** (nothing is replayed), but the Wizard keeps two kinds of state in `~/.wizard-ai/`: a raw **chat history** log (`conversation.json`) and a distilled **AI memory** (`memory.md`) — a terse bullet list of durable findings (targets, endpoints, vulnerabilities, what worked/failed) that's refreshed by a background pass when you close a chat. Only the distilled memory is fed back as silent context, so the Wizard recalls earlier discoveries (e.g. a vuln you found in `/pages`) even in a brand-new conversation, without re-printing the whole transcript. **Right-click the wizard** to clear the current chat; **Settings ▸ AI / Ollama** has **Clear chat history** and **Clear AI memory** buttons.

> The Merlin sprites come from the open-source [clippy.js](https://github.com/pi0/clippyjs) assets and are expected at `~/Documents/Projects/Clippy/clippy.js/agents/Merlin/`. The artwork is Microsoft's — keep it to local/personal use. A standalone previewer of all 73 animations is included: `python3 merlin_anim_test.py`.

---

## Tech Scan (fingerprinting)

Click **Tech Scan** (it also runs automatically alongside a target scan) to fingerprint the host: server software and versions, frameworks, CMS, CDN/hosting, WAF, analytics, TLS, DNS/CNAME, and HTTP versions. Aggressive mode adds heavier probes (`nmap` ports, active WAF fingerprinting, common-path discovery, WHOIS). Every discovered subdomain is fingerprinted too (through a bounded **Max fingerprint workers** pool, so even a crt.sh flood of hundreds of hosts doesn't spawn unlimited probe threads), so the export covers every host.

---

## Exporting & reloading scans

From **Options ▾** → **Export ALL graphs (JSON)**, Reconner writes a `reconner_scan_all_<timestamp>.json` containing every graph, node, and fingerprint. Reload it later with **Load scan JSON…** to browse the results offline — no re-scan needed.

---

## Settings

**⚙ Settings** (stored in `~/.reconner/settings.json`), organized into tabs:

- **AI / Ollama** — Ollama host (default `http://localhost:11434`), the analysis **model** (default `reconner-ai`), the **Wizard Model** (default `wizard-ai`, used by [The Wizard](#the-wizard)), temperature, and a **Test Connection** button.
- **Performance** —
  - **Max concurrent browsers** (default `5`) — how many browser crawls run at once: the primary crawl plus up to N−1 concurrent subdomain crawls; the rest queue. This is the only throttle on subdomain crawling (discovery itself is unbounded). Applies live, including mid-scan.
  - **Max fingerprint workers** (default `8`) — bounded pool size for Tech Scan jobs, so unbounded subdomain discovery can't spawn unlimited HTTP/`nmap`/`whatweb` threads. Independent of the browser limit.
  - **Safe-path whitelist** — the [safe-path whitelist](#safe-path-whitelist): on/off toggle and the editable list of paths Reconner may auto-probe (with **Reset** / **Load list…**).
- **Proxy** — the intercepting proxy's listen **port** (default `8080`), the CA certificate path, and **Export CA cert…** / **Install into system trust** buttons (see [Proxy interceptor](#proxy-interceptor)).
- **Interface** — font size.
- Window, browser, and Wizard-popup geometry (position + size) are remembered automatically between sessions.

---

## Troubleshooting

- **"No WebDriver available"** — install Chrome/Chromium or Firefox. Selenium Manager usually fetches the driver; otherwise install `chromium`/`firefox-esr`.
- **Nothing happens on scan / empty tree** — check the target is reachable (try the `www.` host); transient DNS/connection errors are logged in the status area.
- **HTTPS shows `MOZILLA_PKIX_ERROR_MITM_DETECTED` / cert warnings** — the browser doesn't trust the Reconner CA. Use **Open Browser** (it sets this up), or trust `~/.reconner/ca/reconner-ca.crt` via **Settings ▸ Proxy ▸ Install into system trust**; for Firefox also enable `security.enterprise_roots.enabled`. Installing `libnss3-tools` (`certutil`) lets the launched Firefox profile trust it without sudo.
- **Proxy didn't start / "bind failed"** — port `8080` is already in use; change it in **Settings ▸ Proxy**.
- **AI buttons / the Wizard do nothing** — Ollama isn't running or the model name in Settings doesn't exist. Start Ollama and/or run `./build-reconner-ai.sh` (builds both `reconner-ai` and `wizard-ai`).
- **The Wizard won't appear** — the Merlin sprites are missing. They're expected at `~/Documents/Projects/Clippy/clippy.js/agents/Merlin/` (`agent.js` + `map.png`); the popup shows the exact path it looked in. Pillow (`pip install pillow`) is also required.
- **Getting blocked (403 everywhere)** — Reconner already sends a normal (non-headless) User-Agent so the usual headless-browser fingerprint block doesn't apply. If a target still 403s every request it's a stricter WAF/Cloudflare policy — try **Stealth** mode to slow the request rate. (Tech Scan fingerprints often still succeed even when the crawl is blocked.)
- **Auth header not on page loads** — you're on Firefox; install Chrome for CDP header injection (the request/probe path is still authenticated).

---

## Responsible use

Reconner is a security-testing tool. Crawling, probing, fuzzing, and authenticated scanning can generate significant traffic and exercise sensitive functionality. **Always operate within an explicit authorization scope.** You are responsible for how you use it.
