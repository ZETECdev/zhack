"""English bug-bounty style advisories for every ZHack check.

Each advisory explains, in English:
- what the bug is (description)
- what the company risks if it is not fixed (business_risk)
- how a criminal could exploit it (criminal_example, high-level narrative)
- how to fix it (remediation)
- references (CWE / OWASP / standards)

Scenarios are intentionally narrative: they describe the attacker's steps
without providing ready-to-use exploit code, matching the defensive purpose
of the scanner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple


@dataclass(frozen=True)
class Advisory:
    title: str
    description: str
    business_risk: str
    criminal_example: str
    remediation: str
    references: Tuple[str, ...] = field(default_factory=tuple)


_GENERIC = Advisory(
    title="Security weakness detected",
    description=(
        "The scanner identified a condition that weakens the security posture of the "
        "application. The confirmed impact depends on the deployment, the authentication "
        "model, and the affected asset."
    ),
    business_risk=(
        "If left unfixed, this condition can contribute to data breaches, account "
        "takeover, financial loss, regulatory exposure (e.g. GDPR/CCPA), and reputational "
        "damage, especially when chained with other weaknesses."
    ),
    criminal_example=(
        "A criminal typically: 1) enumerates the application with automated scanners and "
        "finds this condition, 2) confirms it with harmless requests, 3) chains it with "
        "other weaknesses (phishing, injection, session theft) to reach a valuable asset "
        "such as user credentials, funds, or administrative functionality."
    ),
    remediation=(
        "Review the evidence, identify the root cause, apply the check-specific fix, "
        "rotate any potentially exposed credentials, and retest on staging."
    ),
    references=("OWASP Top 10 (2021)", "CWE-1035: OWASP Top Ten"),
)


_ADVISORIES: Dict[str, Advisory] = {
    "https": Advisory(
        title="Site reachable over unencrypted HTTP",
        description=(
            "The application does not force HTTPS: users can reach it over plain HTTP, or "
            "HTTP does not redirect to HTTPS. Traffic, cookies, and credentials then travel "
            "in cleartext and can be modified in transit."
        ),
        business_risk=(
            "Session and credential theft at scale, and for a DEX the worst-case is direct "
            "theft of user funds: an on-path attacker can inject JavaScript into the HTTP "
            "page that replaces the recipient address or requests a malicious signature. "
            "Also damages SEO, browser trust indicators, and compliance posture."
        ),
        criminal_example=(
            "A criminal sets up a rogue Wi-Fi hotspot (or compromises an ISP-level route). "
            "When a victim opens the exchange over HTTP, the attacker strips the upgrade or "
            "injects a script into the page that hooks window.ethereum, so the next swap the "
            "victim confirms sends funds to the attacker's address."
        ),
        remediation=(
            "Redirect all HTTP traffic to HTTPS with a 301, enable HSTS "
            "(max-age>=31536000; includeSubDomains; preload), and serve no content over HTTP."
        ),
        references=("CWE-319: Cleartext Transmission", "OWASP A02:2021 - Cryptographic Failures"),
    ),
    "security_headers": Advisory(
        title="Missing browser security headers",
        description=(
            "Key HTTP response headers (Content-Security-Policy, X-Frame-Options / "
            "frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) "
            "are absent, so the browser cannot apply defense-in-depth policies."
        ),
        business_risk=(
            "Missing CSP makes any small injection immediately exploitable; missing framing "
            "protection allows clickjacking — for a DEX that means an attacker can overlay a "
            "fake UI so victims click 'Confirm' on a transaction they cannot see. The "
            "company risks user fund theft, account takeover, and loss of trust."
        ),
        criminal_example=(
            "A criminal iframes the exchange on a look-alike domain promising an airdrop, "
            "aligns invisible buttons over the real 'Approve' button, and the victim "
            "unknowingly confirms an unlimited token approval to the attacker's contract."
        ),
        remediation=(
            "Deploy a restrictive Content-Security-Policy (start with default-src 'self'), "
            "X-Frame-Options DENY or CSP frame-ancestors, X-Content-Type-Options: nosniff, "
            "Referrer-Policy: strict-origin-when-cross-origin, and a tight Permissions-Policy."
        ),
        references=("CWE-1021: Improper Restriction of Rendered UI Layers", "OWASP A05:2021 - Security Misconfiguration"),
    ),
    "tls": Advisory(
        title="Weak or invalid TLS configuration",
        description=(
            "The TLS certificate or protocol configuration is invalid, expired, or supports "
            "obsolete protocol versions, weakening transport security."
        ),
        business_risk=(
            "Browser warnings train users to click through certificate errors — exactly the "
            "habit a phisher needs. Weak protocols can allow interception or downgrade "
            "attacks, and an expired cert halts the service and erodes brand trust."
        ),
        criminal_example=(
            "A criminal clones the site on a similar domain with an invalid certificate. "
            "Users already accustomed to clicking through the warning on the real site "
            "proceed on the clone and enter their seed phrase or sign a drainer approval."
        ),
        remediation=(
            "Renew/replace the certificate from a trusted CA, automate renewal, disable "
            "TLS < 1.2 and weak cipher suites, and monitor expiry."
        ),
        references=("CWE-295: Improper Certificate Validation", "OWASP A02:2021 - Cryptographic Failures"),
    ),
    "cookies": Advisory(
        title="Insecure cookie attributes",
        description=(
            "Session or preference cookies lack Secure, HttpOnly, or SameSite attributes."
        ),
        business_risk=(
            "A missing HttpOnly flag means any XSS immediately yields the session cookie; "
            "missing Secure lets it leak over HTTP; missing SameSite eases CSRF. Result: "
            "account takeover, fraudulent trades or withdrawals, and support/legal fallout."
        ),
        criminal_example=(
            "A criminal finds a minor reflected XSS, injects a script that reads "
            "document.cookie (HttpOnly missing), exfiltrates the session, and replays it "
            "from their own machine to withdraw to their address."
        ),
        remediation=(
            "Set Secure, HttpOnly, and SameSite=Lax/Strict on all session cookies; scope "
            "Domain/Path narrowly and rotate sessions after login."
        ),
        references=("CWE-1004: Sensitive Cookie Without HttpOnly", "OWASP A05:2021 - Security Misconfiguration"),
    ),
    "cache_control": Advisory(
        title="Sensitive responses are cacheable",
        description=(
            "Authenticated or session-specific responses lack Cache-Control: no-store / "
            "private, so shared caches (proxies, CDNs, browsers) may store them."
        ),
        business_risk=(
            "One user's private data (balances, API keys, personal information) can be "
            "served to another user from a shared cache — a reportable data breach with "
            "regulatory and reputational consequences."
        ),
        criminal_example=(
            "A criminal requests a cacheable authenticated URL right after a victim used it "
            "on a shared proxy (corporate network, university), and receives the victim's "
            "account page with balance and API credentials."
        ),
        remediation=(
            "Send Cache-Control: no-store, private for authenticated content, Vary on "
            "Cookie/Authorization where relevant, and purge any already-cached objects."
        ),
        references=("CWE-525: Use of Web Browser Cache Containing Sensitive Information", "OWASP A05:2021"),
    ),
    "exposed_files": Advisory(
        title="Sensitive files publicly accessible",
        description=(
            "Backup files, .env files, .git repositories, dumps, or configuration archives "
            "are downloadable from the web root."
        ),
        business_risk=(
            "This is frequently a company-ending event for a crypto business: a leaked .env "
            "or hardhat config often contains the deployer private key, RPC credentials, and "
            "database passwords. Full infrastructure and treasury compromise, plus source "
            "code disclosure that accelerates further attacks."
        ),
        criminal_example=(
            "A criminal runs a path wordlist against the domain, downloads /.git and "
            "reconstructs the repository, finds the deployer private key in an old commit or "
            ".env file, imports it, and drains the protocol's treasury and liquidity "
            "contracts within minutes."
        ),
        remediation=(
            "Remove the artifacts from the web root, block dotfiles at the web server "
            "level, rotate every secret they contained (assume compromise), and audit access "
            "logs for prior downloads."
        ),
        references=("CWE-538: Insertion of Sensitive Information into Externally-Accessible File", "OWASP A05:2021"),
    ),
    "info_disclosure": Advisory(
        title="Version banners and verbose error disclosure",
        description=(
            "The server reveals software versions (Server, X-Powered-By) or returns stack "
            "traces/debug output to clients."
        ),
        business_risk=(
            "Attackers get a free vulnerability map: exact versions map directly to public "
            "exploits. Stack traces reveal internal paths, framework details, and sometimes "
            "secrets, reducing the cost of a targeted intrusion."
        ),
        criminal_example=(
            "A criminal reads 'Apache/2.4.49' from a response header, looks up the matching "
            "public exploit (e.g. a path traversal/RCE advisory for that version), and "
            "launches it directly against the server."
        ),
        remediation=(
            "Disable version banners and verbose errors in production, return generic error "
            "pages, and log details server-side only."
        ),
        references=("CWE-200: Exposure of Sensitive Information", "OWASP A05:2021"),
    ),
    "tech": Advisory(
        title="Technology stack fingerprintable",
        description=(
            "Headers, cookies, or markup reveal the frameworks and platforms in use."
        ),
        business_risk=(
            "Fingerprinting shortens the attacker's path from reconnaissance to working "
            "exploit, increasing the likelihood and speed of a successful intrusion."
        ),
        criminal_example=(
            "A criminal fingerprints the framework and version, then tests the shortlist of "
            "known CVEs and framework-specific misconfigurations (debug consoles, default "
            "credentials, known plugin bugs) instead of blind fuzzing."
        ),
        remediation=(
            "Remove unnecessary version markers, keep all components patched, and treat "
            "exposed fingerprints as reconnaissance enablers."
        ),
        references=("CWE-205: Observable Behavioral Discrepancy", "OWASP A05:2021"),
    ),
    "mixed_content": Advisory(
        title="HTTPS page loads insecure HTTP resources",
        description=(
            "The page is served over HTTPS but requests scripts, styles, images, or other "
            "subresources over plain HTTP."
        ),
        business_risk=(
            "An on-path attacker can tamper with the insecure subresource. If it is a "
            "script, the attacker gains full JavaScript execution inside the HTTPS origin — "
            "equivalent to a stored XSS delivered by the network."
        ),
        criminal_example=(
            "A criminal on the victim's network rewrites the HTTP-loaded JavaScript to add a "
            "hook on window.ethereum: the next approval the user signs grants unlimited "
            "spending to the attacker's contract, even though the main page was 'secure'."
        ),
        remediation=(
            "Load every subresource over HTTPS (or same-origin), remove HTTP URLs, and add "
            "CSP upgrade-insecure-requests as a safety net."
        ),
        references=("CWE-319: Cleartext Transmission", "OWASP A02:2021"),
    ),
    "form_security": Advisory(
        title="Sensitive form submitted over insecure channel",
        description=(
            "A login or data form is served over HTTP, or posts its data to an HTTP endpoint."
        ),
        business_risk=(
            "Credentials and personal data can be harvested in transit, leading to account "
            "takeover at scale and breach-notification obligations."
        ),
        criminal_example=(
            "A criminal sniffs an untrusted network and collects the cleartext POST bodies "
            "of the login form, then replays the credentials against the exchange and any "
            "other service where users reused passwords."
        ),
        remediation=(
            "Serve the form page and the form action exclusively over HTTPS and enforce "
            "HSTS."
        ),
        references=("CWE-319: Cleartext Transmission", "OWASP A02:2021"),
    ),
    "dom_xss": Advisory(
        title="DOM-based cross-site scripting data flow",
        description=(
            "User-controlled data (URL fragments, query parameters, storage) reaches a "
            "dangerous DOM sink such as innerHTML, document.write, or eval-like APIs."
        ),
        business_risk=(
            "On a Web3 site, DOM XSS is a wallet drainer delivery mechanism: one crafted "
            "link can execute attacker JavaScript in the victim's session, replace contract "
            "addresses, and request malicious signatures. Direct user fund loss and severe "
            "reputational damage."
        ),
        criminal_example=(
            "A criminal crafts a link with the payload in the URL fragment and posts it in "
            "the project's Discord as 'new pools just launched'. Victims open it, the page's "
            "own script writes the fragment into innerHTML, and the injected code swaps the "
            "router address and silently requests an unlimited approval."
        ),
        remediation=(
            "Replace dangerous sinks with textContent/setter-safe APIs, sanitize with a "
            "vetted library (e.g. DOMPurify), validate URL-derived data, and add a strict CSP."
        ),
        references=("CWE-79: Cross-site Scripting", "OWASP A03:2021 - Injection"),
    ),
    "robots_disclosure": Advisory(
        title="Sensitive paths disclosed via robots.txt",
        description=(
            "robots.txt lists administrative, backup, or debug paths, advertising them to "
            "anyone who reads the file."
        ),
        business_risk=(
            "Attackers get a curated list of interesting endpoints. If any of them lacks "
            "real access control, discovery becomes trivial."
        ),
        criminal_example=(
            "A criminal downloads robots.txt, visits each Disallow entry, finds an "
            "unprotected /admin or /backup route, and proceeds with credential stuffing or "
            "direct exploitation."
        ),
        remediation=(
            "Do not rely on robots.txt for secrecy; enforce authentication/authorization on "
            "every sensitive route and keep the file minimal."
        ),
        references=("CWE-200: Exposure of Sensitive Information", "OWASP A05:2021"),
    ),
    "csrf": Advisory(
        title="State-changing forms without CSRF protection",
        description=(
            "Forms or endpoints that change state lack anti-CSRF tokens and the cookies lack "
            "an effective SameSite policy."
        ),
        business_risk=(
            "An attacker can ride the victim's authenticated session to change settings "
            "(email, withdrawal address, API keys). For a financial platform, a CSRF that "
            "alters the withdrawal destination equals direct theft."
        ),
        criminal_example=(
            "A criminal hosts a page with an auto-submitting form targeting the exchange's "
            "'change withdrawal address' endpoint. A logged-in victim visits the page; the "
            "browser attaches the session cookie; the victim's withdrawal address is "
            "replaced with the attacker's."
        ),
        remediation=(
            "Require per-session anti-CSRF tokens on all state changes, set "
            "SameSite=Lax/Strict cookies, and verify Origin/Referer on sensitive endpoints."
        ),
        references=("CWE-352: Cross-Site Request Forgery", "OWASP A01:2021 - Broken Access Control"),
    ),
    "cdn": Advisory(
        title="CDN/WAF provider identified",
        description=(
            "Response headers reveal the CDN or WAF in front of the application."
        ),
        business_risk=(
            "Knowing the edge provider helps attackers search for an exposed origin server "
            "to bypass WAF rules, rate limits, and DDoS protection."
        ),
        criminal_example=(
            "A criminal identifies the CDN, then hunts the origin IP via DNS history, "
            "certificate transparency, and subdomain scans; once found, they attack the "
            "origin directly, bypassing every edge control."
        ),
        remediation=(
            "Restrict the origin to accept traffic only from the CDN's IP ranges, keep WAF "
            "rules tight, and avoid leaking origin details in headers/DNS."
        ),
        references=("CWE-200: Exposure of Sensitive Information", "OWASP A05:2021"),
    ),
    "dns_sec": Advisory(
        title="Missing email anti-spoofing records (SPF/DMARC)",
        description=(
            "The domain lacks a strict SPF policy and/or a DMARC record, so anyone can send "
            "email that appears to come from the company."
        ),
        business_risk=(
            "For a DEX or wallet company this is catastrophic: convincing phishing email "
            "from 'support@yourdomain' is the #1 way users get their seed phrases and "
            "approvals stolen. Users blame the company even though the email was forged."
        ),
        criminal_example=(
            "A criminal sends 'Urgent: migrate to the new contract' from support@company.com "
            "(no SPF/DMARC to stop them) to the user base, linking to a pixel-perfect clone "
            "that asks users to 'reconnect and approve' — harvesting approvals and seeds."
        ),
        remediation=(
            "Publish SPF with -all for non-senders, DMARC with p=quarantine then p=reject "
            "and reporting (rua), and add DKIM signing."
        ),
        references=("CWE-290: Authentication Bypass by Spoofing", "DMARC.org / RFC 7489"),
    ),
    "sri": Advisory(
        title="Third-party scripts without Subresource Integrity",
        description=(
            "External scripts are loaded from CDNs without integrity/crossorigin attributes, "
            "so the browser cannot detect if the file was modified."
        ),
        business_risk=(
            "One compromised CDN file becomes arbitrary JavaScript execution for every "
            "visitor — the exact pattern behind real supply-chain wallet drains. The company "
            "carries full responsibility for code it served to users."
        ),
        criminal_example=(
            "A criminal compromises or hijacks the CDN asset (or registers an expired S3 "
            "bucket behind it), injects a small hook that rewrites approval transactions to "
            "their contract, and every user of the DEX signs the poisoned transactions."
        ),
        remediation=(
            "Add integrity + crossorigin to every external script, pin versions, and "
            "self-host critical Web3 libraries."
        ),
        references=("CWE-829: Inclusion of Functionality from Untrusted Control Sphere", "OWASP A08:2021 - Software and Data Integrity Failures"),
    ),
    "contract_exposure": Advisory(
        title="Contract addresses / Web3 project configuration exposed",
        description=(
            "Contract addresses, explorer links, or project configuration files "
            "(hardhat/foundry/truffle) are publicly accessible."
        ),
        business_risk=(
            "Attackers can map the protocol's contracts, detect wrong-chain or unverified "
            "deployments, and craft convincing phishing that points users to look-alike "
            "contracts. Leaked project configs sometimes include RPC keys or deployer data."
        ),
        criminal_example=(
            "A criminal extracts the router address from the frontend, deploys a same-named "
            "fake on another chain, buys ads for 'new router migration', and collects "
            "approvals from users who never verified the address against an official registry."
        ),
        remediation=(
            "Publish an official, signed address registry per chain, verify sources on the "
            "explorer, and remove project configuration files from production hosts."
        ),
        references=("CWE-200: Exposure of Sensitive Information", "OWASP A05:2021"),
    ),
    "bucket_exposure": Advisory(
        title="Publicly listable cloud storage bucket",
        description=(
            "A cloud storage bucket referenced by the site allows anonymous listing (and "
            "potentially reading) of its objects."
        ),
        business_risk=(
            "Backups, user data exports, source bundles, or logs in the bucket become public. "
            "This is a data breach with direct regulatory exposure, and buckets under trusted "
            "provider domains are also abused to host convincing phishing."
        ),
        criminal_example=(
            "A criminal spots an S3 URL in the site's JavaScript, lists the bucket, finds a "
            "database backup and a .env with AWS keys, then pivots into the cloud account — "
            "or uploads a malicious 'app update' that the site later serves."
        ),
        remediation=(
            "Disable anonymous access (block public access), enforce least-privilege bucket "
            "policies, enable access logging, audit existing objects, and rotate any secret "
            "found inside."
        ),
        references=("CWE-284: Improper Access Control", "OWASP A05:2021"),
    ),
    "endpoint_exposure": Advisory(
        title="API documentation, admin panels, source maps, or GraphQL exposed",
        description=(
            "Swagger/OpenAPI docs, GraphQL endpoints, JavaScript source maps, or admin "
            "panels are publicly reachable."
        ),
        business_risk=(
            "Attackers receive a complete map of the API surface (including privileged "
            "operations) or the original frontend source with comments and internal logic — "
            "dramatically reducing the effort to find an authorization or validation flaw."
        ),
        criminal_example=(
            "A criminal downloads the source map, reviews the unminified code for API "
            "endpoints and client-side 'admin' flags, then calls the discovered admin API "
            "directly — betting (often correctly) that authorization is only checked in the UI."
        ),
        remediation=(
            "Disable docs/introspection/source maps in production, authenticate admin "
            "routes, and enforce authorization server-side on every endpoint."
        ),
        references=("CWE-200: Exposure of Sensitive Information", "OWASP A05:2021"),
    ),
    "sqli": Advisory(
        title="SQL injection",
        description=(
            "User input reaches SQL queries unsafely: the application returns database errors "
            "when given quote characters, indicating injectable query construction."
        ),
        business_risk=(
            "Full database read/write: user tables, API keys, and in the worst case OS-level "
            "compromise. For a trading platform this means theft of user PII, credentials, "
            "and potentially manipulation of balances or withdrawal records."
        ),
        criminal_example=(
            "A criminal confirms the injection with a quote, enumerates tables via error and "
            "UNION-based extraction (or time-based blind), dumps the users and api_keys "
            "tables, cracks password hashes offline, and uses the API keys to withdraw funds."
        ),
        remediation=(
            "Use parameterized queries/prepared statements everywhere, apply least-privilege "
            "DB accounts, add a WAF rule as a temporary shield, and audit all query builders."
        ),
        references=("CWE-89: SQL Injection", "OWASP A03:2021 - Injection"),
    ),
    "xss": Advisory(
        title="Reflected cross-site scripting",
        description=(
            "Request parameters are reflected into the HTML response without proper "
            "context-aware encoding."
        ),
        business_risk=(
            "One crafted link executes attacker JavaScript in a victim's session: session "
            "theft, UI redressing, and on a DEX, silent replacement of transaction details "
            "before signing. Direct financial loss for users and liability for the platform."
        ),
        criminal_example=(
            "A criminal posts a 'support' link in the community chat containing an encoded "
            "payload. The victim clicks it while connected to the DEX; the injected script "
            "opens a fake swap confirmation that grants the attacker's contract an unlimited "
            "token approval."
        ),
        remediation=(
            "Apply context-aware output encoding, use safe templating, validate input, and "
            "deploy a strict CSP as defense in depth."
        ),
        references=("CWE-79: Cross-site Scripting", "OWASP A03:2021 - Injection"),
    ),
    "open_redirect": Advisory(
        title="Open redirect",
        description=(
            "A redirect endpoint accepts an arbitrary external URL parameter and redirects "
            "the browser to it."
        ),
        business_risk=(
            "Attackers abuse the trusted domain as the first hop of phishing links, "
            "defeating email filters and user suspicion. It can also break OAuth flows "
            "(code/token leakage via redirect_uri manipulation)."
        ),
        criminal_example=(
            "A criminal sends https://yourdomain.com/redirect?url=https://fake-airdrop.io to "
            "the community. The link passes filters because it points to the real domain; "
            "the victim lands on a clone that asks for a 'gasless claim' signature that "
            "drains their wallet."
        ),
        remediation=(
            "Allow only relative/same-origin destinations or an explicit allowlist of "
            "domains, and show an interstitial warning otherwise."
        ),
        references=("CWE-601: URL Redirection to Untrusted Site", "OWASP A01:2021"),
    ),
    "traversal": Advisory(
        title="Path traversal / local file inclusion",
        description=(
            "A file parameter is not normalized, allowing ../ sequences to escape the "
            "intended directory and read arbitrary files."
        ),
        business_risk=(
            "Disclosure of /etc/passwd, application configuration, environment files with "
            "database credentials, TLS keys, or wallet keystore files stored on the server — "
            "a direct path to full compromise."
        ),
        criminal_example=(
            "A criminal requests file=../../../../etc/passwd to confirm the bug, then reads "
            "the app's config and .env to obtain DB credentials and cloud keys, and finally "
            "pulls the server's keystore to steal the hot wallet."
        ),
        remediation=(
            "Resolve and validate paths against an allowlisted base directory, reject ../ "
            "sequences, and run the service with minimal filesystem permissions."
        ),
        references=("CWE-22: Path Traversal", "OWASP A01:2021"),
    ),
    "cors": Advisory(
        title="Overly permissive Cross-Origin Resource Sharing",
        description=(
            "The API reflects arbitrary Origin headers and/or allows credentials, letting "
            "any website read authenticated responses in a victim's browser."
        ),
        business_risk=(
            "Any malicious site visited by a logged-in user can silently read their private "
            "API data (balances, orders, API keys) — an account-level data breach that is "
            "invisible to the victim."
        ),
        criminal_example=(
            "A criminal lures a logged-in user to a 'portfolio tracker' site; the page calls "
            "the exchange API with the victim's cookies (allowed by the permissive CORS), "
            "and ships the account data — including API secrets — to the attacker."
        ),
        remediation=(
            "Allowlist exact trusted origins, never reflect Origin with credentials, and "
            "restrict methods/headers to the minimum."
        ),
        references=("CWE-942: Permissive Cross-domain Policy", "OWASP A05:2021"),
    ),
    "http_methods": Advisory(
        title="Dangerous HTTP methods enabled",
        description=(
            "The server advertises methods such as PUT, DELETE, or TRACE on routes where "
            "they are not needed."
        ),
        business_risk=(
            "Depending on route controls, attackers may upload or delete content, or use "
            "TRACE for cross-site tracing that leaks credentials (including HttpOnly cookies) "
            "through the response."
        ),
        criminal_example=(
            "A criminal probes OPTIONS, finds PUT enabled on an upload route, and writes a "
            "webshell or a malicious .js file into the web root that the application then "
            "serves to users."
        ),
        remediation=(
            "Disable unused methods at the edge and framework level, enforce per-route "
            "authorization, and verify with read-only OPTIONS checks."
        ),
        references=("CWE-749: Exposed Dangerous Method or Function", "OWASP A05:2021"),
    ),
    "rpc_cors": Advisory(
        title="Permissive CORS on JSON-RPC endpoint",
        description=(
            "The blockchain RPC endpoint answers cross-origin browser requests from "
            "arbitrary origins."
        ),
        business_risk=(
            "Third-party sites can consume the node's paid quota through visitors' browsers "
            "(cost/DoS) and read RPC responses cross-origin, potentially exposing "
            "node-specific metadata."
        ),
        criminal_example=(
            "A criminal embeds fetch calls to the company's RPC endpoint in a high-traffic "
            "site; every visitor's browser becomes a free relay, burning the company's RPC "
            "quota and degrading service for real users."
        ),
        remediation=(
            "Restrict allowed origins and methods on the RPC, require authentication/API "
            "keys with per-key quotas, and monitor usage anomalies."
        ),
        references=("CWE-942: Permissive Cross-domain Policy", "OWASP A05:2021"),
    ),
    "rpc_methods": Advisory(
        title="Sensitive JSON-RPC methods publicly reachable",
        description=(
            "The public RPC node answers methods such as eth_accounts, personal_*, admin_*, "
            "or net_* that should never be exposed."
        ),
        business_risk=(
            "If account-management methods are enabled on a node with unlocked keys, an "
            "attacker can sign transactions and steal funds directly. Even read-only "
            "metadata methods leak infrastructure details and burn paid quotas."
        ),
        criminal_example=(
            "A criminal calls eth_accounts on the public RPC, finds an unlocked account, "
            "then uses personal_sign / eth_sendTransaction-style methods to move funds out — "
            "a classic historic attack against misconfigured Ethereum nodes."
        ),
        remediation=(
            "Never expose personal_*/admin_* namespaces publicly, keep no unlocked accounts "
            "on reachable nodes, require auth and rate limits, and audit node logs."
        ),
        references=("CWE-749: Exposed Dangerous Method or Function", "OWASP A05:2021"),
    ),
    "dex_rpc": Advisory(
        title="DEX contract address has no bytecode on the configured chain",
        description=(
            "A router/factory/vault address configured in the frontend has no contract code "
            "on the chain the RPC reports — indicating a wrong chainId, a destroyed contract, "
            "or a spoofed/mistaken address."
        ),
        business_risk=(
            "Users may approve or send funds to an address that is not the intended contract: "
            "transactions fail, funds are lost to an EOA, or an attacker who controls the "
            "same address on another chain collects approvals."
        ),
        criminal_example=(
            "A criminal notices the frontend points to an address with no code on one chain, "
            "deploys their own contract at that address via CREATE2 on another chain where "
            "they control the nonce, and advertises a 'migration' — harvesting approvals from "
            "users who trust the familiar address."
        ),
        remediation=(
            "Verify chainId, bytecode, and verified source for every configured address at "
            "startup; refuse to operate when eth_getCode is empty; maintain a signed address "
            "registry per chain."
        ),
        references=("CWE-345: Insufficient Verification of Data Authenticity", "EIP-155 / chain-specific deployment registries"),
    ),
    "wallet_security": Advisory(
        title="Wallet interaction hygiene weakness",
        description=(
            "The Web3 frontend uses signing, storage, or transport patterns that expose "
            "users to signature phishing, session theft, or data manipulation."
        ),
        business_risk=(
            "Users who connect their wallet can be tricked into signing away funds or have "
            "their sessions stolen. Incidents are publicly attributed to the platform, "
            "destroying user trust and inviting regulatory scrutiny."
        ),
        criminal_example=(
            "A criminal clones or compromises the frontend flow and abuses the weak pattern "
            "(blind signing, replayable signatures, browser-stored secrets) to extract an "
            "authorization or credential, then monetizes it by draining wallets."
        ),
        remediation=(
            "Remove blind-signing methods, adopt SIWE/EIP-712 with verified domains, keep "
            "secrets out of Web Storage, encrypt all transports, and retest with a disposable "
            "wallet."
        ),
        references=("CWE-347: Improper Verification of Cryptographic Signature", "EIP-4361 (SIWE) / EIP-712"),
    ),
    "web3_supply_chain": Advisory(
        title="Vulnerable or unpinned Web3 library from CDN",
        description=(
            "The site loads Web3 libraries (ethers, web3, WalletConnect) that are "
            "end-of-life, outdated, or referenced without a pinned version (mutable URL)."
        ),
        business_risk=(
            "Signing and transaction logic run on this code: a known vulnerability or a "
            "malicious release served through a mutable CDN URL executes for every user — "
            "the classic route to a mass wallet-draining incident attributed to the company."
        ),
        criminal_example=(
            "A criminal either exploits a public PoC against the outdated library version, "
            "or — when the URL is unpinned — compromises the upstream package (or its CDN "
            "account) and ships a drainer that every visitor automatically receives."
        ),
        remediation=(
            "Pin exact audited versions, add SRI hashes, migrate off EOL branches "
            "(ethers v4, web3 0.x, WalletConnect v1), and monitor dependency advisories."
        ),
        references=("CWE-1104: Use of Unmaintained Third Party Components", "OWASP A06:2021 - Vulnerable and Outdated Components"),
    ),
    "seed_harvest": Advisory(
        title="Page harvests wallet seed phrases / private keys",
        description=(
            "The page contains a form (or text) asking users for their seed phrase, "
            "recovery phrase, private key, or keystore password. No legitimate application "
            "ever needs these; this pattern is the defining mechanic of wallet phishing "
            "clones and of critically broken 'web wallet' designs."
        ),
        business_risk=(
            "Every user who submits is instantly drained. If the page impersonates the "
            "company, victims attribute the loss to the brand, regulator complaints follow, "
            "and the reputation damage can end the business. If the company's own site asks "
            "for these, it is a self-inflicted catastrophe."
        ),
        criminal_example=(
            "A criminal registers a look-alike domain and buys search ads for 'wallet "
            "migration'. Victims land on the clone, paste their 12-word seed phrase into "
            "the 'verify your wallet' field, and the page posts it to the attacker, who "
            "sweeps the wallets within minutes using automated bots."
        ),
        remediation=(
            "If it is a clone: take the domain down via the registrar/abuse desk, warn the "
            "community, and add anti-phishing protections. If it is the company's own page: "
            "remove the field immediately and treat every previously submitted secret as "
            "compromised."
        ),
        references=("CWE-522: Insufficiently Protected Credentials", "OWASP A07:2021"),
    ),
}


def _secret_advisory(lowered: str) -> Advisory:
    if "clave privada" in lowered or "semilla" in lowered or "mnemonic" in lowered or "xprv" in lowered or "keystore" in lowered:
        return Advisory(
            title="Wallet private key / seed material exposed",
            description=(
                "Private key material (private key, seed phrase, extended key, or keystore) "
                "is embedded in publicly served code. Anyone who reads the page obtains full, "
                "irreversible control of the wallet."
            ),
            business_risk=(
                "Total loss of all funds controlled by the key — corporate treasury, hot "
                "wallets, or user funds — with no recourse on-chain. Public disclosure of the "
                "incident is effectively an announcement that the company's key management "
                "failed."
            ),
            criminal_example=(
                "Criminals run bots that continuously scan public sites and repositories for "
                "key patterns. Within minutes of deployment, a bot copies the key, sweeps the "
                "balance to a mixer, and monitors future deposits to steal them instantly."
            ),
            remediation=(
                "Treat the wallet as fully compromised: move all funds to a new wallet, "
                "remove the secret from code and history, audit on-chain and access logs, "
                "and adopt HSM/KMS or hardware-wallet key management."
            ),
            references=("CWE-798: Use of Hard-coded Credentials", "OWASP A07:2021 - Identification and Authentication Failures"),
        )
    if "infura" in lowered or "alchemy" in lowered or "quicknode" in lowered or "chainstack" in lowered or "rpc" in lowered or "proveedor web3" in lowered:
        return Advisory(
            title="RPC provider credential exposed",
            description=(
                "An API key or authenticated endpoint for a blockchain infrastructure "
                "provider (Infura, Alchemy, QuickNode, etc.) is embedded in public code."
            ),
            business_risk=(
                "Attackers consume the account's paid quota (direct cost and denial of "
                "service for real users), and the key fingerprints the company's "
                "infrastructure for further attacks."
            ),
            criminal_example=(
                "A criminal extracts the key, resells it or uses it to run their own bots "
                "for free until the quota alarms fire; during congestion they can also "
                "degrade the DEX by exhausting the account's rate limits."
            ),
            remediation=(
                "Rotate the credential, proxy RPC calls through the backend with per-user "
                "quotas, and restrict the key by origin/IP at the provider."
            ),
            references=("CWE-798: Use of Hard-coded Credentials", "OWASP A02:2021"),
        )
    return Advisory(
        title="Secret or credential exposed in public code",
        description=(
            "API keys, tokens, webhooks, or other credentials are embedded in the publicly "
            "served HTML/JavaScript."
        ),
        business_risk=(
            "Depending on the secret: cloud account takeover, payment fraud, spam through "
            "the company's channels, repository compromise, or lateral movement into "
            "internal systems."
        ),
        criminal_example=(
            "A criminal greps the site's JavaScript for key patterns, validates the "
            "credential against the provider's API, and uses it — e.g. an AWS key to spin up "
            "miners and read S3 data, or a Stripe key to issue refunds."
        ),
        remediation=(
            "Revoke and rotate the credential immediately, remove it from code and history, "
            "audit provider logs, and move secrets server-side."
        ),
        references=("CWE-798: Use of Hard-coded Credentials", "OWASP A07:2021"),
    )


def _dex_advisory(lowered: str) -> Advisory:
    if "slippage" in lowered and "extrem" in lowered:
        return Advisory(
            title="Extreme slippage tolerance configured",
            description=(
                "The DEX configuration accepts almost any execution price (slippage "
                "tolerance near 100%), removing meaningful protection against price "
                "manipulation."
            ),
            business_risk=(
                "Users systematically lose money to MEV bots on every swap and publicly "
                "blame the platform; volumes and reputation collapse."
            ),
            criminal_example=(
                "A sandwich bot watches the mempool: it buys the token just before the "
                "victim's swap (pushing the price up), lets the victim buy at the top, and "
                "sells immediately after — extracting the difference risk-free."
            ),
            remediation=(
                "Bound slippage per trade, compute amountOutMin from a fresh quote, and show "
                "the guaranteed minimum to the user before signing."
            ),
            references=("CWE-682: Incorrect Calculation", "MEV / sandwich attack literature"),
        )
    if "slippage" in lowered or "amountout" in lowered:
        return Advisory(
            title="Swap without minimum-output protection (amountOutMin = 0)",
            description=(
                "Swap calls accept any output amount (minimum output set to zero), so the "
                "trade can execute at a catastrophically bad price."
            ),
            business_risk=(
                "Every swap becomes free profit for sandwich/MEV attackers; users suffer "
                "direct, measurable losses attributed to the DEX."
            ),
            criminal_example=(
                "A MEV bot detects a pending swap with amountOutMin=0 in the mempool, "
                "front-runs it with a large buy, lets the victim's trade execute at the "
                "inflated price, and back-runs with a sell — pocketing the slippage."
            ),
            remediation=(
                "Always compute amountOutMin from a recent quote and a bounded slippage "
                "tolerance; reject trades that would execute below it."
            ),
            references=("CWE-682: Incorrect Calculation", "MEV / sandwich attack literature"),
        )
    if "aprobación" in lowered or "approval" in lowered:
        return Advisory(
            title="Unlimited token approval granted to spender",
            description=(
                "The frontend approves the maximum uint256 allowance to the router/spender "
                "instead of the needed amount."
            ),
            business_risk=(
                "If the spender contract is ever compromised, upgraded maliciously, or "
                "substituted in a phishing flow, every user who approved can have their "
                "entire balance of that token drained at any time."
            ),
            criminal_example=(
                "A criminal clones the DEX UI and swaps the spender for their own contract; "
                "users sign the familiar 'infinite approval', and the criminal calls "
                "transferFrom to empty their wallets — no further interaction needed."
            ),
            remediation=(
                "Approve only the required amount (or use Permit2 with short expirations), "
                "allowlist verified spenders, and offer one-click allowance revocation."
            ),
            references=("CWE-732: Incorrect Permission Assignment", "EIP-20 allowance / Permit2 best practices"),
        )
    if "permit" in lowered and "deadline" in lowered or "permit" in lowered and "expir" in lowered:
        return Advisory(
            title="Permit signature without effective expiry",
            description=(
                "EIP-2612 / Permit2 signatures are issued with a zero or maximum deadline, "
                "so a leaked signature remains valid (almost) forever."
            ),
            business_risk=(
                "A single phished signature becomes a permanent authorization: the attacker "
                "can wait months before draining, making incident response nearly impossible."
            ),
            criminal_example=(
                "A criminal harvests permit signatures via a fake 'gasless approval' site, "
                "stores them, and redeems them weeks later when victims have refilled their "
                "wallets — maximizing the haul per signature."
            ),
            remediation=(
                "Use short deadlines, correct nonce/chainId/verifyingContract in the EIP-712 "
                "domain, and invalidate or revoke affected approvals."
            ),
            references=("CWE-613: Insufficient Session Expiration", "EIP-2612 / Permit2"),
        )
    if "deadline" in lowered:
        return Advisory(
            title="Swap transaction without deadline",
            description=(
                "Transactions carry a zero deadline and can be executed long after signing, "
                "at a price and market context the user never intended."
            ),
            business_risk=(
                "Stale user transactions can be executed when it is profitable for someone "
                "else, producing user losses and disputes against the platform."
            ),
            criminal_example=(
                "A criminal (or miner/relayer) holds a signed stale transaction and executes "
                "it after the market moved against the user, capturing the price difference."
            ),
            remediation=(
                "Set short deadlines based on current block time and revert expired "
                "transactions in the contract."
            ),
            references=("CWE-367: Time-of-check Time-of-use Race Condition", "MEV literature"),
        )
    if "spender" in lowered or "router" in lowered and "navegador" in lowered:
        return Advisory(
            title="Router/spender address influenced by browser input",
            description=(
                "The spender or router address can be influenced via URL parameters or "
                "browser storage without cryptographic validation."
            ),
            business_risk=(
                "One crafted link turns the official frontend into a drainer: approvals go "
                "to the attacker's contract under the company's trusted domain."
            ),
            criminal_example=(
                "A criminal shares official-dex.com/?spender=0xATTACKER in the community; "
                "the frontend approves the attacker's contract, and the attacker withdraws "
                "every approved token."
            ),
            remediation=(
                "Use an immutable allowlist of routers per chainId, verify checksum and "
                "deployed bytecode, and never take spender addresses from user input."
            ),
            references=("CWE-20: Improper Input Validation", "EIP-55 address checksum"),
        )
    if "tx.origin" in lowered:
        return Advisory(
            title="tx.origin used for authorization",
            description=(
                "The contract authorizes calls based on tx.origin, which can be spoofed "
                "through an intermediate malicious contract."
            ),
            business_risk=(
                "Privileged functions (admin, withdraw) become callable by anyone who tricks "
                "the owner into touching a malicious contract — full contract takeover."
            ),
            criminal_example=(
                "A criminal deploys a 'rewards' contract and convinces the owner to claim; "
                "the contract calls the target's admin function, which sees tx.origin == "
                "owner and executes the privileged action for the attacker."
            ),
            remediation=(
                "Replace tx.origin with msg.sender and add explicit role-based access "
                "control tests."
            ),
            references=("CWE-477: Use of Obsolete Function (tx.origin)", "SWC-115"),
        )
    if "selfdestruct" in lowered:
        return Advisory(
            title="selfdestruct present in deployed contract code",
            description=(
                "The exposed contract code contains a selfdestruct path; combined with weak "
                "access control or upgradeability, it can destroy the contract or trap funds."
            ),
            business_risk=(
                "Permanent loss of contract availability and potentially all held funds — an "
                "existential, unrecoverable incident for the protocol."
            ),
            criminal_example=(
                "A criminal reaches the unprotected destruction path (or takes over the "
                "proxy admin), destroys the logic contract, and leaves user funds frozen or "
                "routes them through a malicious implementation."
            ),
            remediation=(
                "Remove selfdestruct, audit proxy admin and role boundaries, and protect "
                "upgrades with multisig + timelock."
            ),
            references=("CWE-284: Improper Access Control", "SWC-106"),
        )
    if "delegatecall" in lowered:
        return Advisory(
            title="delegatecall usage in contract",
            description=(
                "The contract executes foreign code in its own storage context via "
                "delegatecall."
            ),
            business_risk=(
                "A controllable or compromised implementation contract can overwrite any "
                "storage slot (owner, balances) and drain the contract."
            ),
            criminal_example=(
                "A criminal points the delegatecall target to their own implementation (via "
                "a broken upgrade flow or uninitialized proxy), overwrites the owner slot, "
                "and calls the withdrawal function."
            ),
            remediation=(
                "Allowlist implementations, initialize proxies correctly, guard upgrades "
                "with multisig + timelock, and validate storage layout on upgrades."
            ),
            references=("CWE-829: Inclusion of Functionality from Untrusted Control Sphere", "SWC-112"),
        )
    if "reentr" in lowered:
        return Advisory(
            title="External call with value without visible reentrancy guard",
            description=(
                "The contract sends ETH via a low-level call while no reentrancy guard is "
                "visible — a heuristic that requires manual state-ordering review."
            ),
            business_risk=(
                "Reentrancy is the bug class behind the largest historic exploits (The DAO): "
                "a pool can be emptied in a single transaction."
            ),
            criminal_example=(
                "A criminal's contract receives ETH and, in its fallback, re-enters the "
                "withdraw function before the balance is updated — repeating until the pool "
                "is drained."
            ),
            remediation=(
                "Apply checks-effects-interactions, add nonReentrant guards, and test "
                "against reentrant tokens (ERC-777 hooks, etc.)."
            ),
            references=("CWE-841: Improper Enforcement of Behavioral Workflow", "SWC-107"),
        )
    if "oracle" in lowered or "reservas" in lowered or "precio" in lowered:
        return Advisory(
            title="Spot-reserve pricing without manipulation resistance",
            description=(
                "Prices or amounts are derived from instantaneous pool reserves with no "
                "oracle/TWAP protection."
            ),
            business_risk=(
                "Flash-loan attackers can move the price within one transaction, trade "
                "against the manipulated value, and extract the pool's value at will."
            ),
            criminal_example=(
                "A criminal takes a flash loan, skews the pool reserves, triggers the "
                "price-dependent operation (swap, borrow, liquidation) at the artificial "
                "price, restores the reserves, and repays the loan — keeping the difference."
            ),
            remediation=(
                "Use a robust oracle or TWAP with deviation limits, add emergency pause, and "
                "simulate flash-loan manipulation in tests."
            ),
            references=("CWE-345: Insufficient Verification of Data Authenticity", "Flash loan attack literature"),
        )
    if "mint" in lowered:
        return Advisory(
            title="Owner-controlled minting",
            description=(
                "The contract lets the owner mint new tokens without a visible cap."
            ),
            business_risk=(
                "A compromised or malicious owner key can inflate supply and dump on the "
                "pool — the classic rug pull; liquidity providers lose everything."
            ),
            criminal_example=(
                "A criminal obtains the owner key (phishing, leaked .env, malicious insider), "
                "mints a huge supply, sells it into the DEX pool in one block, and disappears "
                "with the paired ETH/stablecoins."
            ),
            remediation=(
                "Cap or disable minting after deployment, hold the owner key in a multisig "
                "with timelock, and publish the emission policy."
            ),
            references=("CWE-284: Improper Access Control", "Token rug-pull patterns"),
        )
    if "blacklist" in lowered or "honeypot" in lowered:
        return Advisory(
            title="Transfer blacklist (honeypot pattern)",
            description=(
                "The contract implements blacklisting of addresses, letting the operator "
                "block selected users from transferring or selling."
            ),
            business_risk=(
                "Users can buy but be prevented from selling — the defining honeypot mechanic. "
                "Even if intended for compliance, it centralizes the power to freeze any "
                "holder and will be treated as a scam risk signal."
            ),
            criminal_example=(
                "A malicious deployer lets victims buy freely, blacklists any address that "
                "tries to sell, then dumps the treasury at the top while holders cannot exit."
            ),
            remediation=(
                "Remove blacklisting unless strictly required by regulation; if required, "
                "document it, guard it with multisig + timelock, and emit transparent events."
            ),
            references=("CWE-284: Improper Access Control", "Honeypot token patterns"),
        )
    return _ADVISORIES_GENERIC_DEX


_ADVISORIES_GENERIC_DEX = Advisory(
    title="DEX security weakness",
    description=(
        "A DEX-specific pattern in the frontend or exposed contract code can lead to loss "
        "of funds through manipulation of swaps, approvals, signatures, pricing, or contract "
        "controls."
    ),
    business_risk=(
        "Direct theft or loss of user funds, MEV extraction against users, and protocol "
        "takeover scenarios — all publicly attributable to the platform."
    ),
    criminal_example=(
        "A criminal monitors the protocol's public configuration and transaction intent, "
        "then targets the weakest assumption (minimum output, allowance, signature, oracle, "
        "or admin control) to extract value from users or the protocol."
    ),
    remediation=(
        "Review the specific pattern, validate on a fork with synthetic funds, remediate, "
        "revoke affected approvals, and retest."
    ),
    references=("CWE-1035", "Smart Contract Weakness Classification (SWC)"),
)


def _wallet_advisory(lowered: str) -> Advisory:
    if "eth_sign" in lowered or "ciega" in lowered:
        return Advisory(
            title="Blind signing enabled (eth_sign)",
            description=(
                "The frontend calls eth_sign, which asks the wallet to sign an opaque hash "
                "that cannot be displayed in human-readable form."
            ),
            business_risk=(
                "eth_sign is the most abused drainer primitive: users sign what they believe "
                "is a login/verification and actually authorize a transfer or permit. "
                "Incidents caused by it are blamed on the platform that requested the signature."
            ),
            criminal_example=(
                "A criminal clones the site (or injects a script via any XSS) and pops an "
                "eth_sign 'wallet verification'. MetaMask shows only hex; the victim signs; "
                "the attacker replays the signature as a valid permit/transfer and drains "
                "the wallet."
            ),
            remediation=(
                "Remove eth_sign entirely; use personal_sign or EIP-712 with a verifiable "
                "domain and a human-readable message."
            ),
            references=("CWE-347: Improper Verification of Cryptographic Signature", "MetaMask eth_sign deprecation guidance"),
        )
    if "personal_sign" in lowered or "siwe" in lowered:
        return Advisory(
            title="personal_sign without domain binding (no SIWE/EIP-4361)",
            description=(
                "The login/verification flow signs plain messages without domain, URI, "
                "chainId, nonce, or expiry binding."
            ),
            business_risk=(
                "Signatures are replayable across sites and time: one phished 'verification' "
                "signature can authenticate the attacker as the victim or be confused with "
                "another authorization."
            ),
            criminal_example=(
                "A criminal runs a phishing site that asks for a personal_sign 'verification', "
                "then replays the captured signature to the real backend's login endpoint, "
                "taking over the victim's account and any linked off-chain privileges."
            ),
            remediation=(
                "Adopt SIWE (EIP-4361) messages with domain, URI, chainId, nonce and "
                "expiration, all validated server-side."
            ),
            references=("CWE-294: Authentication Bypass by Capture-replay", "EIP-4361"),
        )
    if "permit" in lowered or "typed data" in lowered:
        return Advisory(
            title="Permit/Permit2 typed-data signing in frontend",
            description=(
                "The frontend builds EIP-712 Permit-style signatures; if spender, amount, "
                "and deadline are not clearly displayed and validated, users can be tricked "
                "into signing approvals."
            ),
            business_risk=(
                "Permit phishing is currently the dominant wallet-draining technique: one "
                "signature equals an off-chain, gasless approval the attacker redeems at will."
            ),
            criminal_example=(
                "A criminal advertises a 'gasless claim' on a pixel-perfect clone; the "
                "EIP-712 payload is actually a Permit2 approval to the attacker's spender "
                "with a far-future deadline. The victim signs; the attacker pulls the tokens "
                "later."
            ),
            remediation=(
                "Display spender/amount/deadline explicitly, enforce short deadlines, "
                "validate the EIP-712 domain, and simulate the effect before signing."
            ),
            references=("CWE-347: Improper Verification of Cryptographic Signature", "EIP-712 / Permit2"),
        )
    if "tokens de sesión" in lowered or ("storage" in lowered and "token" in lowered):
        return Advisory(
            title="Session tokens accessible to JavaScript (Web Storage)",
            description=(
                "Authentication tokens live in localStorage/sessionStorage instead of "
                "HttpOnly cookies."
            ),
            business_risk=(
                "Any XSS becomes full account takeover: stolen tokens grant access to "
                "off-chain services — orders, API keys, withdrawal settings."
            ),
            criminal_example=(
                "A criminal triggers an XSS payload that posts localStorage tokens to their "
                "server, then imports the session and changes the victim's withdrawal "
                "address and API credentials."
            ),
            remediation=(
                "Move tokens to HttpOnly + Secure + SameSite cookies, shorten token TTLs, "
                "and bind sessions to device/IP signals."
            ),
            references=("CWE-922: Insecure Storage of Sensitive Information", "OWASP A07:2021"),
        )
    if "secretos" in lowered or "web storage" in lowered or "storage" in lowered:
        return Advisory(
            title="Wallet secrets stored in Web Storage",
            description=(
                "Private keys, seeds, or secrets are read from or written to "
                "localStorage/sessionStorage, which is readable by any JavaScript on the page."
            ),
            business_risk=(
                "Any XSS, malicious extension, or compromised dependency exfiltrates the "
                "keys — instant, silent, and total wallet takeover of affected users."
            ),
            criminal_example=(
                "A criminal exploits a minor DOM XSS (or ships a compromised npm dependency), "
                "reads localStorage['privateKey'], and broadcasts it to a collector; bots "
                "sweep the funds seconds later."
            ),
            remediation=(
                "Never persist keys/seeds in the browser; rely on external wallets "
                "(EIP-1193) and hardware wallets for high-value operations."
            ),
            references=("CWE-922: Insecure Storage of Sensitive Information", "OWASP A02:2021"),
        )
    if "websocket" in lowered or "ws://" in lowered:
        return Advisory(
            title="Cleartext WebSocket (ws://) in Web3 frontend",
            description=(
                "Market data or transaction payloads travel over an unencrypted WebSocket."
            ),
            business_risk=(
                "A network attacker can feed fake prices/orderbooks or alter the transaction "
                "details shown to the user — the user then signs what the attacker chose."
            ),
            criminal_example=(
                "On a hostile network, a criminal intercepts the ws:// feed and rewrites the "
                "displayed recipient/price; the victim signs a swap that pays the attacker's "
                "address."
            ),
            remediation=(
                "Use wss:// only, and cross-check critical values (recipient, price) against "
                "signed data or on-chain state."
            ),
            references=("CWE-319: Cleartext Transmission", "OWASP A02:2021"),
        )
    if "rpc" in lowered and "claro" in lowered:
        return Advisory(
            title="RPC endpoint served over cleartext HTTP",
            description=(
                "The frontend points its blockchain RPC at an http:// URL instead of https://."
            ),
            business_risk=(
                "An on-path attacker can rewrite RPC responses: fake prices, fake balances, "
                "or a manipulated transaction simulation shown to the user before signing — "
                "leading to losses the platform is blamed for."
            ),
            criminal_example=(
                "On a hostile network, a criminal intercepts the plaintext RPC and serves a "
                "modified eth_call quote that makes the UI show a profit where there is "
                "none; the victim signs, and the real execution takes the loss."
            ),
            remediation=(
                "Serve RPC traffic over HTTPS only, ideally proxied through the backend with "
                "TLS termination."
            ),
            references=("CWE-319: Cleartext Transmission", "OWASP A02:2021"),
        )
    if "automáticamente" in lowered or "auto" in lowered and "conecta" in lowered:
        return Advisory(
            title="Wallet auto-connects on page load",
            description=(
                "The frontend calls eth_requestAccounts as soon as the page loads, without "
                "any user action."
            ),
            business_risk=(
                "It is a hallmark of drainer pages that ask for approvals immediately; for a "
                "legitimate DEX it also degrades privacy (every visit exposes the wallet "
                "address to trackers)."
            ),
            criminal_example=(
                "A victim clicks a phishing ad; the clone connects the wallet instantly and "
                "opens the approval dialog before the user can read the page, riding on "
                "habit and urgency."
            ),
            remediation=(
                "Connect only on explicit user action and request approvals per operation, "
                "never on load."
            ),
            references=("CWE-1188: Insecure Default Initialization", "WalletConnect / dapp best practices"),
        )
    if "portapapeles" in lowered or "clipboard" in lowered:
        return Advisory(
            title="Clipboard writes in a Web3 context",
            description=(
                "The frontend writes to the clipboard; combined with any XSS, copied "
                "addresses can be silently replaced."
            ),
            business_risk=(
                "Address-poisoning losses: users paste attacker look-alike addresses and "
                "irreversibly send funds to them."
            ),
            criminal_example=(
                "A criminal's injected script overwrites the clipboard right after the "
                "victim copies a deposit address; the pasted address belongs to the attacker "
                "and shares the victim's address prefix/suffix, so the user does not notice."
            ),
            remediation=(
                "Always display the full address for visual confirmation, avoid silent "
                "clipboard writes, and warn on look-alike addresses."
            ),
            references=("CWE-200: Exposure of Sensitive Information", "Address poisoning advisories"),
        )
    return _ADVISORIES["wallet_security"]


def _supply_chain_advisory(lowered: str) -> Advisory:
    if "comprometida" in lowered or "solana" in lowered:
        return Advisory(
            title="Compromised @solana/web3.js version in use",
            description=(
                "The site loads @solana/web3.js 1.95.8/1.95.9, the versions published to npm "
                "with malicious code that exfiltrated private keys through injected "
                "providers during the September 2025 supply-chain compromise of the "
                "official package."
            ),
            business_risk=(
                "Any user who connects through this library can have their private key "
                "silently copied to attacker infrastructure — wallets are drained without "
                "any visible misbehavior. A company serving this version is effectively "
                "operating a wallet drainer on behalf of the attacker."
            ),
            criminal_example=(
                "Users simply open the dapp and connect their Phantom wallet; the backdoored "
                "library base64-encodes key material and sends it to a hardcoded collector "
                "endpoint, and the attacker sweeps the wallets at leisure."
            ),
            remediation=(
                "Upgrade to a patched version (>= 1.95.10 or current stable), pin the exact "
                "version, verify package checksums, audit npm install history, and add SRI "
                "if served from a CDN."
            ),
            references=("CWE-1104: Use of Unmaintained Third Party Components", "Solana Foundation / Anza security advisory (Sep 2025)"),
        )
    if "mutable" in lowered or "sin versión" in lowered or "latest" in lowered:
        return Advisory(
            title="Web3 library loaded from a mutable CDN URL",
            description=(
                "The library is referenced via @latest or an unversioned URL, so whatever "
                "is published next is served to users automatically."
            ),
            business_risk=(
                "A single compromised upstream release becomes instant code execution in "
                "every user's browser — a mass wallet-draining event directly attributed to "
                "the company."
            ),
            criminal_example=(
                "A criminal compromises the package maintainer account (or the CDN origin), "
                "publishes a version that hooks window.ethereum approvals, and every visitor "
                "of the DEX loads it without any change on the company's side."
            ),
            remediation=(
                "Pin exact versions, add SRI integrity hashes, and consider self-hosting "
                "critical Web3 libraries."
            ),
            references=("CWE-829: Inclusion of Functionality from Untrusted Control Sphere", "OWASP A08:2021"),
        )
    if "walletconnect v1" in lowered or "web3modal" in lowered:
        return Advisory(
            title="WalletConnect v1 / Web3Modal v1 in use",
            description=(
                "The frontend depends on WalletConnect v1-era libraries whose official relay "
                "was shut down in 2023."
            ),
            business_risk=(
                "Users are pushed toward unofficial bridges that criminals clone for "
                "phishing; connection flows are broken and untrusted."
            ),
            criminal_example=(
                "A criminal operates a fake WalletConnect v1 bridge/clone: victims scanning "
                "the QR connect their wallet to the attacker's relay, which then requests "
                "malicious signatures."
            ),
            remediation=(
                "Migrate to WalletConnect v2 (AppKit/Sign API) and remove all v1 dependencies."
            ),
            references=("CWE-1104: Use of Unmaintained Third Party Components", "WalletConnect v1 sunset notices"),
        )
    return _ADVISORIES["web3_supply_chain"]


def _endpoint_advisory(lowered: str) -> Advisory:
    if "introspección" in lowered or "introspeccion" in lowered:
        return Advisory(
            title="GraphQL introspection enabled in production",
            description=(
                "The GraphQL endpoint answers __schema queries, exposing the full API "
                "schema: types, queries, mutations, and field names."
            ),
            business_risk=(
                "Attackers get a complete map of privileged operations and hidden fields, "
                "turning an authorization mistake in any single resolver into a discovered, "
                "exploitable bug within hours."
            ),
            criminal_example=(
                "A criminal introspects the schema, finds mutations like "
                "setWithdrawalAddress or adminMint, and calls them directly — betting that "
                "authorization is only enforced in the UI, which is a frequent real-world "
                "finding."
            ),
            remediation=(
                "Disable introspection in production, authenticate the endpoint, enforce "
                "field-level authorization, and limit query depth/complexity."
            ),
            references=("CWE-200: Exposure of Sensitive Information", "OWASP API Security Top 10"),
        )
    return _ADVISORIES["endpoint_exposure"]


def advisory_for(check: str, title: str = "") -> Advisory:
    """Devuelve el advisory en inglés para un check/título concreto."""
    lowered = (title or "").lower()
    if check == "dex_rpc" and lowered and "chainid" in lowered:
        return Advisory(
            title="Chain ID mismatch between frontend and RPC",
            description=(
                "The frontend declares a network (chainId) that differs from the chain the "
                "configured RPC actually serves (eth_chainId)."
            ),
            business_risk=(
                "Users would sign swaps and approvals for the wrong network: transactions "
                "fail, funds can be sent to addresses that only exist meaningfully on "
                "another chain, and approvals are granted in a different chain context than "
                "intended — a direct loss vector and a classic misconfiguration in DEX "
                "frontends."
            ),
            criminal_example=(
                "A criminal notices the frontend can be pointed at an RPC of another chain "
                "(or a malicious RPC reporting a different chainId), then promotes a "
                "'migration' link; users approve the router address on the wrong network, "
                "where the attacker controls the equivalent deployment."
            ),
            remediation=(
                "Pin one chainId per environment, verify it against eth_chainId at startup, "
                "and block the UI on any mismatch."
            ),
            references=("CWE-345: Insufficient Verification of Data Authenticity", "EIP-155 / chainId standards"),
        )
    if check == "dex_security" and lowered:
        return _dex_advisory(lowered)
    if check == "wallet_security" and lowered:
        return _wallet_advisory(lowered)
    if check == "secret_scan" and lowered:
        return _secret_advisory(lowered)
    if check == "web3_supply_chain" and lowered:
        return _supply_chain_advisory(lowered)
    if check == "endpoint_exposure" and lowered:
        return _endpoint_advisory(lowered)
    return _ADVISORIES.get(check, _GENERIC)
