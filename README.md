# Reconner

**Browser-driven web reconnaissance + intercepting proxy for pentests, bug bounties, and lab/CTF study.**

Reconner drives a real browser to *navigate a target like a user would* — following links, clicking controls, watching the traffic the page actually makes — and lays out what it finds as an interactive **Site Structure tree**: pages, scripts, files, redirects, and **API endpoints**. It also bundles an **OWASP ZAP / Burp-style HTTP/HTTPS intercepting proxy** — open a browser through it, trap requests *and* responses, edit them, and forward or drop. On top of that it adds technology fingerprinting, subdomain discovery, an animated AI assistant, built-in **Repeater** and **Fuzzer** tools, and a security toolkit (Encode/Decode, token **Sign**ing, hash **Crack**ing) — all in a single Windows-95-styled GUI.

> ⚠️ **Authorized use only.** Reconner actively crawls, probes, intercepts, and (in Aggressive mode) fuzzes targets, and its toolkit forges tokens and cracks hashes. Only run it against systems you own or are explicitly authorized to test (your own labs, CTFs, or in-scope bug-bounty programs).

---

## Highlights

- **Intercepting proxy (HTTP + HTTPS)** — a built-in ZAP/Burp-style proxy (default `127.0.0.1:8080`). Flip **Intercept ON** and trap each request and response in a repeater-style 4-box editor: **▶** forward one step, **✕** drop, **Save as Node** to keep a reviewed transaction in the graph. A **History** popup logs every relayed transaction — scope-filtered, searchable, sortable (incl. request/response size), with right-click **Send to Repeater** / **Send to Fuzzer** / **Save as Node** and JSON export. HTTPS is decrypted with an auto-generated CA (per-host certs minted on the fly). Click **Open Browser** to launch your system browser through the proxy (CA auto-trusted) — it opens on the currently-selected node's URL. Out-of-scope requests are never sent.
- **User-like crawling** — a real browser (Chrome-first, Firefox fallback via Selenium) renders JavaScript, follows links, and clicks non-destructive controls so SPAs reveal their routes and API calls. The browser presents a normal (non-headless) User-Agent so WAF/CDN bot filters don't blanket-block the crawl. **Proxied manual browsing builds the same hierarchical graph** — each request you make through *Open Browser* becomes a node, nested by its `Referer` exactly like the crawler nests by navigation.
- **API endpoint discovery** — passively from live XHR/fetch + JS/response-body mining, and actively via spec/well-known probing (and a comprehensive wordlist in Aggressive mode). Real data endpoints are labeled `api`; binary downloads are correctly labeled `file`.
- **Browser & Fuzzing scan types** — pick **Browser** (crawl like a user) or **Fuzzing** (path-wordlist directory/endpoint discovery, no browser) in the Modes dropdown; either intensity (Stealth/Normal/Aggressive) applies. Both build the **same graph**, so a crawl and a fuzz complement each other — fuzzing grafts unlinked dirs (like an `/images/` upload target) onto the crawled map.
- **Built-in security tooling** — every Proxy / Repeater / Fuzzer / Node-Inspector **Options ▾** menu carries **Encode / Decode** (Base64 / Hex / URL / Octal workbench), **Sign** (forge JWT, RFC 9421 HTTP Message Signatures, DPoP, SXG, or HMAC-webhook signatures with real crypto — any algorithm, with batch wordlists), **Crack** (drive **hashcat** over captured hashes — any type, any attack mode — plus one-shot **Identify Hash**), and **Show Images** (render images in a response body). Right-click anywhere in a panel to open the same menu.
- **Web shell tooling** — mark any node as an uploaded **web shell** (file/path + command parameter) and drive it from a built-in **Web Shell terminal**: a bold, green-on-black console that sends `?param=<command>` and parses the response. Optional URL-encoding on the wire only.
- **POST/parameter recovery + safe auto-probing** — for non-GET endpoints, Reconner recovers the **request body and parameters**: it parses any OpenAPI/Swagger spec it finds into a fuzzable body template, submits benign **search/filter** forms during the crawl so the real body is captured from live traffic, and mines JS **source maps** for endpoints and body shapes. Endpoints whose path is on the **safe-path whitelist** (read/query verbs by default) and not destructive are **auto-probed**; destructive paths are **never auto-sent** — they're seeded as ready-to-edit requests in the Repeater. See [Safe-path whitelist](#safe-path-whitelist).
- **Authenticated scans** — flip on **Auth Scan** and Reconner pauses when it hits a login wall, shows you the exact request it's about to send, and lets you supply the credential (Bearer / Basic / API key / Cookie / Custom header / Form login). It's then reused for every request to that host.
- **Subdomain discovery** — passive (links, traffic, JS) plus certificate-transparency (crt.sh) in Aggressive mode, each subdomain getting its own graph and a full crawl. Discovery is **unbounded**; the only limiter is the **Max concurrent browsers** setting, which throttles how many crawl at once while the rest queue.
- **Tech fingerprinting** — servers, frameworks, CMSs, CDNs, WAFs, analytics, and more, with optional `whatweb` / `nmap` / `wafw00f` probes; every discovered subdomain is fingerprinted too.
- **The Wizard** — an animated Office-Assistant-style **Merlin** companion (the wizard-hat button by *Nodes:* in the status bar) that chats in a playful-but-precise *"wizardy"* voice, powered by one optional local **Ollama** model (`wizard-ai`). Three **Analyze** buttons (Node / History / Tech, each with a target dropdown for one item or **ALL**) stream a security breakdown into the chat, and a **Test Scheduler** lets the AI propose and track the likeliest-vuln tests per node.
- **Repeater & Fuzzer** — edit and resend any captured request, with a dedicated **Body** box (and a split request/response view) so multipart/JSON bodies are easy to craft; mark `{{FUZZ}}` positions (in the request *or* body) and run wordlists with ffuf-style match/filter.
- **High-fidelity, de-noised map** — transport errors and `5xx`/unavailable upstreams are flagged on the node, while `401`/`403`/`404` stay as legitimate attack surface. Per-locale duplicate endpoints (`…/en/…`, `…/pt/…`) collapse into one representative node.
- **Resizable, remembered popups** — every popup is fully resizable and remembers its size + position between sessions (and edge-tiles like a normal window). **Export / import** saves a scan (all graphs + data) to JSON for offline review.

---

## Requirements

- **Linux** with a desktop (the GUI uses Tk). Built and tested on **Kali**.
- **Python 3** with `tkinter`.
- A **browser + driver**: Google Chrome/Chromium (preferred — enables auth header injection) or Firefox/geckodriver. Selenium Manager fetches the matching driver automatically in most cases.
- **Python packages:** `selenium`, `requests`, `beautifulsoup4`, `cryptography` (HTTPS-interception CA **and** the Sign toolkit), `Pillow` (tree node icons + Show Images), `networkx`, `matplotlib`, `ollama` (see `requirements.txt`).
- **Optional CLI tools:** `certutil` (`libnss3-tools`) so the **Open Browser** Firefox profile can trust the proxy CA without sudo; **`hashcat`** + **`hashid`** for the **Crack** tool (preinstalled on Kali); Tech Scan also shells out to `whatweb`, `nmap`, `wafw00f`, `httpx` when present.
- **Optional Python helpers:** `python-Wappalyzer`, `dnspython`, `python-whois`.
- **Optional:** [Ollama](https://ollama.com) for the Wizard / AI analysis features.

---

## Installation

### One-shot installer (recommended on Kali)

```bash
git clone <this-repo> reconner && cd reconner
./install.sh
```

The installer installs system packages and the Python deps, copies Reconner to `~/.reconner/`, adds a permanent **`reconner`** shell alias, and adds a **Reconner** entry to your applications menu. Open a new terminal (to pick up the alias) and run `reconner`.

### Manual install

```bash
sudo apt install -y python3 python3-pip python3-tk firefox-esr hashcat hashid
python3 -m pip install --break-system-packages -r requirements.txt
python3 reconner.py
```

For full auth-header injection on browser navigation, also install Chrome/Chromium (`sudo apt install -y chromium`).

---

## Optional: AI setup

**The Wizard** — its chat, its **Analyze Node / History / Tech** buttons, and the Test Scheduler — uses one local Ollama model. To enable it:

```bash
# Install Ollama first: curl -fsSL https://ollama.com/install.sh | sh
./build-reconner-ai.sh
```

This builds the single **`wizard-ai`** model (from `Modelfile.wizard-ai`), installs the CWES knowledge base (which silently grounds the model) alongside the Wizard's memory under **`~/.reconner/`**, and points Reconner's settings at it. By default it's built on **Qwen3-Coder 30B** — the strongest free, local coder model — for the best pentest/AppSec reasoning; it's a Mixture-of-Experts model, so only a few experts activate per token and it stays usable even though it exceeds a small GPU (most layers run on CPU/RAM). On a tight box, build a smaller base: `BASE=qwen2.5:14b ./build-reconner-ai.sh` (9 GB) or `BASE=qwen2.5-coder:7b ./build-reconner-ai.sh` (fast). Change the model name / host any time in **⚙ Settings ▸ AI**. If Ollama isn't running, the rest of Reconner works normally — only the AI features are inert.

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

> **Scanning and intercepting are mutually exclusive.** A scan and the proxy's **Intercept** can't run at once (the scanner and interceptor would fight over traffic). While a scan runs the **Intercept** toggle is greyed; while Intercept is ON the **SCAN TARGET** button is greyed (and turning Intercept on mid-scan stops the scan).

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
| **Fuzzing** | **No browser.** Runs the path-wordlist pass (directory/endpoint discovery: `images`, `admin`, `uploads`, `api`, …) under the host root and any live bases, plus subdomain brute-forcing — finding things nothing links to. Paced by the chosen intensity. |

**The two types build the same graph.** Re-scanning a target you've already mapped **adds to** its graph instead of wiping it, so Browser and Fuzzing complement each other in either order (a Fuzzing pass never overwrites a richer browser-crawled node). To start over, use the tree's **Options ▸ Clear** first.

---

## Authenticated scans

Many API endpoints live behind a login. Tick **Auth Scan** before starting and Reconner handles it **reactively, per host**:

1. When a request hits an **auth wall** (HTTP `401`, a `403` advertising `WWW-Authenticate`, or a visible login form), the scan **pauses** and a popup appears.
2. The popup shows the **exact request it's about to send** (read-only) and updates live as you type.
3. Pick an **authentication type** and fill the fields — **Bearer token**, **HTTP Basic**, **Form login**, **API key**, **Custom header**, or **Cookie**.
4. Click **Apply & retry** — the credential is stored **for that host** and injected into every later request to it (probes, mined endpoints, replays, and — on Chrome — browser navigation). Or choose **Skip host** / **Continue unauthenticated**.

Credentials are **session-only** (never written to disk). HMAC-signed (e.g. AWS SigV4) and mTLS endpoints can't be re-authenticated for new requests.

> **Why Chrome?** Chrome's DevTools Protocol lets Reconner inject auth headers into top-level browser navigations. Firefox can't, so on Firefox auth still works for the request/probe path and for cookie/form logins — just not header-injection on page loads.

---

## Safe-path whitelist

Reconner auto-probes discovered non-GET endpoints (sending them and recovering their parameters) — but only the ones it can prove are safe. The **safe-path whitelist** (in **⚙ Settings ▸ Performance**) is the allowlist that decides which paths qualify.

How it works when the whitelist is **ON** (the default):

- A discovered non-GET endpoint is **auto-probed** only when its path matches a whitelist rule **and** is not destructive. Required body fields are recovered from the server's validation errors; optional fields from source request-models.
- The textbox is pre-filled with **default read/query globs** (`*search*`, `*list*`, `*get*`, `*view*`, `*detail*`, `*count*`, `*status*`, …). One glob per line (`*` = wildcard), `#` for comments. **Reset** restores the defaults, **Load list…** appends paths from a file.
- **Destructive paths are always withheld** — `delete`/`remove`/`exec`/`run`/`logout`/`upload`/`install`/credential ops, and the `DELETE` method. They're seeded un-sent and surfaced in the inspector so you can fire them manually in the Repeater.
- **Override:** to deliberately auto-probe a destructive path, add its **exact path** (no `*`) to the whitelist.
- **Not gated:** passive GET reads and label-filtered control/navigation clicks happen everywhere regardless.

Turning the whitelist **OFF** lets Reconner auto-probe **every** non-destructive non-GET path it finds. Destructive paths stay withheld even then.

---

## The Site Structure tree

Each scan builds a collapsible **tree** of what it found, nested by parent → child. Every row shows an **expand/collapse arrow**, a **type icon**, and the node's **name**. Node types: **page**, **api** (endpoint), **file**, **script**, **redirect**, and **shell** (a node you've marked as an uploaded web shell). Locale-duplicate endpoints (`…/en/…`, `…/pt/…`) collapse into one representative node.

Tree controls — dropdowns on **top**, search on the **bottom**:

- **Subdomain ▾** — switch between the entry host's tree and each discovered subdomain's tree (the button shows a fixed "Subdomain" label; the chosen host isn't echoed in it).
- **Options ▾** (top-right) — **Expand all** / **Collapse all**, **Clear**, **Export JSON**, **Export ALL graphs (JSON)**, **Load scan JSON…**, and a **Filter** submenu (show/hide nodes by type: page / file / redirect / script / endpoint / shell).
- **Search** (bottom row) — type to find nodes by URL/title; **◀ / ▶** step through matches (the box tints red when nothing matches).
- **Right-click** — right-click a **row** for its inspector tools (Send to Repeater/Fuzzer, Set/Open Shell, Delete Node — Delete is enabled only for nodes you created, plus the Encode/Decode/Sign/Crack toolkit), or empty space for the Options menu.

All dropdown menus open their submenu on hover and close when the pointer leaves them.

---

## Proxy interceptor

Reconner includes a ZAP/Burp-style intercepting proxy in the **Proxy** panel (top-right), listening on `127.0.0.1:8080` by default (configurable in **⚙ Settings ▸ Proxy**). It relays **HTTP and HTTPS**, decrypting TLS with an auto-generated CA stored in `~/.reconner/ca/`.

**Toolbar:**

- **Intercept: ON/OFF** — green/red toggle. When ON, each transaction is trapped for review; when OFF the proxy passes everything through transparently. (Greyed while a scan is running — see the mutual-exclusion note above.)
- **▶** — forward the current item one step (a request → send it and trap its response; a response → deliver it and move to the next item).
- **✕** — drop the current item.
- **Open Browser** — launch your system browser (Firefox preferred, Chromium fallback) through the proxy in a dedicated profile with the CA trusted. Opens the **selected node's URL** if one is selected, else the Target URL, else a blank page. Every page you visit through it is recorded into the Site Structure graph, nested by `Referer`.
- **History** — open the traffic-history popup (see below).
- **Save as Node** — add the displayed transaction to the graph (parented under its `Referer`).
- **Options ▾** (top-right) — **Encode / Decode**, **Sign**, **Crack**, and **Show Images** over the four boxes (see [Built-in security tooling](#built-in-security-tooling)). Right-click anywhere in the panel opens the same menu.

The four editor boxes (**Request Header / Request Body** over **Response Header / Response Body**, with a draggable splitter) show the trapped request or response as raw HTTP. **Edit anything and forward** — both the request that gets sent and the response that gets delivered are taken from the boxes. **Out-of-scope requests are never sent.** The play/drop/Open-Browser buttons are greyed while Intercept is OFF.

**Proxy History.** The **History** button opens a popup logging **every transaction the proxy relayed** (trapped or not), tagged by source (**P**roxy / **R**epeater / **F**uzzer / **S**can). A list on the left — columns **# · Type · Method · Code · Req. Size · Resp. Size · URL**, each header **click-sorts** — sits beside four read-only boxes showing the selected transaction's request/response. A **Search** box with ◀ / ▶ steppers walks the matches, scoped to the **main window's Scope**. **Right-click** a row for **Send to Repeater** / **Send to Fuzzer** / **Save as Node** (or, on empty space, **Clear All History** / **Export as JSON**); buttons at the bottom **Clear Selected**, **Clear All History**, **Export as JSON**, **Send to Repeater**, **Send to Fuzzer**, and **Save as Node**.

**HTTPS trust.** For HTTPS interception your browser must trust the Reconner CA. The **Open Browser** Firefox profile is configured automatically (imports the CA with `certutil`, else installs into the system trust store and enables enterprise roots). For your *own* browser, use **Settings ▸ Proxy ▸ Export CA cert…** / **Install into system trust** and import/trust `~/.reconner/ca/reconner-ca.crt`.

---

## Built-in security tooling

Every Proxy / Repeater / Fuzzer / Node-Inspector **Options ▾** menu (also reachable by **right-clicking** anywhere in the panel) carries the same toolkit, operating on the current selection / response:

- **Encode / Decode** — a live workbench: paste into the Input box and the Output updates instantly. Switch **direction** (Encode/Decode) and **coding** (Base64 / Hexadecimal / URL / Octal) in the popup; no text needs to be pre-highlighted.
- **Sign** — forge a signed token or signature for authorised testing (alg/key confusion, `alg:none`, weak secrets…). Pick a **method** — **JWT**, **RFC 9421** HTTP Message Signatures, **DPoP**, **SXG**, or **HMAC Webhooks** — and an **algorithm** (every usable one: HS/RS/PS/ES 256-512, ES256K, EdDSA, `none`, hmac/rsa/ecdsa/ed25519 variants, …). Real cryptography (`cryptography` + `hmac`): edit the header/claims/message, generate a keypair (its public PEM/JWK is shown), or paste a PEM public key as the HMAC secret to test RS→HS confusion. **Load Wordlist** signs one token per secret/key so you can paste the whole batch into the Fuzzer. Widgets a method doesn't use are greyed out.
- **Crack** — crack captured hashes. Run **Hashcat** over the hashes (any hash type via the editable `-m`, **Dictionary** or **Brute-force mask** attack, with a wordlist picker — `rockyou.txt.gz` is auto-decompressed), output streamed live; or hit **Identify Hash** on a single hash to detect its type (via `hashid`, shown green when found / red when not).
- **Show Images** — render any images in the current response — the body itself when it's an image, plus any embedded `data:` URIs — in a scrollable viewer.

---

## Inspecting a node

Select a node to open the **Node Inspector** panel: its URL, title, status, content type, GET/POST parameters, request & response headers and bodies, and the requests it made. The **status** is honest about *how* it was determined — a real HTTP code, `ERROR — <reason>` when the request never completed, or `NOT SENT — unsafe method` for a `POST`/`PUT`/… observed but not auto-replayed.

Per-node tools live in the inspector's **Options ▾** menu (also on the graph's right-click menu):

- **Send to Repeater** — open the raw request in an editor, tweak anything, resend it, and **Save as New Node**. The request line + headers, the **request body**, and the **response** each get their own pane. Switch between **Data In** (the request that fetched the node + its response) and **Data Out** (the requests the node can make).
- **Send to Fuzzer** — mark `{{FUZZ}}` positions in the request **or the body**, load a wordlist, and replay with **ffuf-style match/filter** (`-mc`/`-fc`/`-ms`/`-fs`) and Cluster-bomb / Pitchfork modes. Mark a position **in the URL path** to brute-force hidden endpoints, then **Save Node** the hits.
- **Set Shell / Open Shell** — once you've landed an uploaded web shell, **Set Shell** spawns a **shell** node as a *child* of the selected node (you give the shell file/path and the command parameter; the path resolves against the node's URL as a directory). **Open Shell** opens an interactive **Web Shell** terminal (green-on-black, resizable): type a command, hit Enter, and Reconner sends `…/shell.jpg?<param>=<command>` and prints the raw response. A **URL Encode Commands** toggle percent-encodes the command on the wire only.
- **Encode / Decode · Sign · Crack** — the [security toolkit](#built-in-security-tooling), over the node's content / request / response text.

*(For an AI breakdown of a node, open the Wizard and use **Analyze Node**.)*

---

## The Wizard

Click the **wizard-hat button** next to *Nodes:* in the status bar to summon **The Wizard** — an animated **Merlin** (the classic Office-Assistant character) who chats about your target in a playful *"wizardy"* voice while delivering precise pentest/AppSec guidance. He's powered by the local **`wizard-ai`** model (set under **⚙ Settings ▸ AI**), the only AI model Reconner uses.

Under the wizard sit three **Analyze** buttons, each with a target dropdown to its right (pick one item or **ALL**):

- **Analyze Node** — security analysis of a graph node (or every node): likely vuln classes, test cases, payloads.
- **Analyze History** — analysis of intercepted proxy transactions: injectable params, auth/access-control issues, attacks to try.
- **Analyze Tech** — analysis of a host's technology fingerprint (or all hosts): stack risks, misconfigurations, CVEs, next steps.

Results stream into the same chat balloon, so you can ask follow-ups. The CWES knowledge base is folded silently into the Wizard's context to ground his answers.

On the far right, the **Test Scheduler** turns analysis into a checklist. Pick a node from its dropdown, then click the **scrying-orb** button: the Wizard analyses every node + the proxy history + the tech scan and schedules, **per node**, the tests most likely to surface a real vulnerability. Each test is a selectable row (long ones wrap) you can mark **Complete** (green ✓) / **Uncomplete**; the Wizard applauds when a node's tests are all done and lifts a trophy when every node is cleared.

Type a question and press **Enter** — his reply streams into a yellow speech balloon. The animation is fully reactive: he **greets** on open, **idles** with little gestures, starts **listening** when you type, **thinks** while the model is silent, acts out a **writing** animation while the answer streams, and casts a spell when Reconner does something (a Repeater send, a settings change…).

Every chat **starts fresh** (nothing is replayed), but the Wizard keeps two kinds of state under **`~/.reconner/`**: a raw **chat history** log (`conversation.json`) and a distilled **AI memory** (`memory.md`) — a terse bullet list of durable findings that's refreshed by a background pass when you close a chat, and fed back as silent context so the Wizard recalls earlier discoveries in a brand-new conversation. **Right-click the wizard** to clear the current chat; **Settings ▸ AI** has **Clear chat history** and **Clear AI memory** buttons.

> The Merlin sprites come from the open-source [clippy.js](https://github.com/pi0/clippyjs) assets and are expected at `~/Documents/Projects/Clippy/clippy.js/agents/Merlin/`. The artwork is Microsoft's — keep it to local/personal use. A standalone previewer of all 73 animations is included: `python3 merlin_anim_test.py`.

---

## Tech Scan (fingerprinting)

Click **Tech Scan** (it also runs automatically alongside a target scan) to fingerprint the host: server software and versions, frameworks, CMS, CDN/hosting, WAF, analytics, TLS, DNS/CNAME, and HTTP versions. Aggressive mode adds heavier probes (`nmap` ports, active WAF fingerprinting, common-path discovery, WHOIS). Every discovered subdomain is fingerprinted too (through a bounded **Max fingerprint workers** pool). The **Subdomain ▾** selector switches the displayed host.

---

## Exporting & reloading scans

From **Options ▾** → **Export ALL graphs (JSON)**, Reconner writes a `reconner_scan_all_<timestamp>.json` containing every graph, node, and fingerprint. Reload it later with **Load scan JSON…** to browse the results offline — no re-scan needed.

---

## Settings

**⚙ Settings** (stored in `~/.reconner/settings.json`), organized into tabs:

- **AI** — Ollama host (default `http://localhost:11434`), the **AI Model** (default `wizard-ai`, used by [The Wizard](#the-wizard) for chat, all Analyze actions, and the Test Scheduler), temperature, a **Test Connection** button, and **Clear chat history** / **Clear AI memory**.
- **Performance** —
  - **Max concurrent browsers** (default `5`) — how many browser crawls run at once (primary plus up to N−1 subdomain crawls; the rest queue). Applies live, including mid-scan.
  - **Max fingerprint workers** (default `8`) — bounded pool size for Tech Scan jobs.
  - **Safe-path whitelist** — the [safe-path whitelist](#safe-path-whitelist): on/off toggle and the editable list (with **Reset** / **Load list…**).
- **Proxy** — the intercepting proxy's listen **port** (default `8080`), the CA certificate path, and **Export CA cert…** / **Install into system trust** buttons.
- **Interface** — font size.
- **About** — version and dependency status.
- Window, browser, and **every popup's** geometry (position + size) are remembered automatically between sessions (under `~/.reconner/popups.json`).

---

## Troubleshooting

- **"No WebDriver available"** — install Chrome/Chromium or Firefox. Selenium Manager usually fetches the driver; otherwise install `chromium`/`firefox-esr`.
- **Nothing happens on scan / empty tree** — check the target is reachable (try the `www.` host); transient DNS/connection errors are logged in the status area.
- **HTTPS shows cert warnings** — the browser doesn't trust the Reconner CA. Use **Open Browser** (it sets this up), or trust `~/.reconner/ca/reconner-ca.crt` via **Settings ▸ Proxy ▸ Install into system trust**. Installing `libnss3-tools` (`certutil`) lets the launched Firefox profile trust it without sudo.
- **Can't turn on Intercept / SCAN is greyed** — scanning and intercepting are mutually exclusive; stop the scan to intercept, or turn Intercept off to scan.
- **Proxy didn't start / "bind failed"** — port `8080` is already in use; change it in **Settings ▸ Proxy**.
- **Analyze buttons / the Wizard / Test Scheduler do nothing** — Ollama isn't running or the model name in Settings doesn't exist. Start Ollama and/or run `./build-reconner-ai.sh`.
- **The Wizard won't appear** — the Merlin sprites are missing (expected at `~/Documents/Projects/Clippy/clippy.js/agents/Merlin/`); Pillow is also required.
- **Crack does nothing** — install `hashcat` + `hashid` (preinstalled on Kali); the dialog reports if a tool is missing.
- **Getting blocked (403 everywhere)** — Reconner already sends a normal User-Agent. If a target still 403s every request it's a stricter WAF/Cloudflare policy — try **Stealth** mode. (Tech Scan often still succeeds.)
- **Auth header not on page loads** — you're on Firefox; install Chrome for CDP header injection.

---

## Responsible use

Reconner is a security-testing tool. Crawling, probing, fuzzing, authenticated scanning, token forging, and hash cracking can generate significant traffic and exercise sensitive functionality. **Always operate within an explicit authorization scope.** You are responsible for how you use it.
