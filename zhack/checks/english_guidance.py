from __future__ import annotations


_GENERIC = (
    "An attacker may use this condition to expand the application's attack surface or obtain data, access, or influence that should be protected. The confirmed impact depends on the deployment, authentication model, and affected asset.",
    "High-level scenario: an attacker identifies and confirms the condition, then targets the affected trust boundary. This report intentionally omits live exploitation instructions, transaction payloads, and state-changing actions.",
    "Validate only on an authorized staging environment or local fork with synthetic data. Confirm with read-only requests or static review, preserve evidence, remediate the root cause, rotate or revoke affected credentials, and retest.",
)


_GUIDANCE = {
    "https": (
        "A network attacker may intercept credentials, session cookies, and other traffic when users can remain on HTTP.",
        "High-level scenario: an attacker positioned on the network attempts a downgrade or observes an unencrypted request before the user reaches HTTPS.",
        "Verify the HTTP-to-HTTPS redirect with read-only requests, enable HTTPS everywhere and HSTS, then retest with a non-production account.",
    ),
    "security_headers": (
        "Missing browser security controls can make clickjacking, content injection, data exfiltration, or capability abuse easier when another weakness exists.",
        "High-level scenario: an attacker combines the missing policy with a framing, injection, or cross-origin weakness to affect a user session.",
        "Review response headers in staging, define a restrictive CSP and framing policy, enable the appropriate browser policies, and retest without executing attacker content.",
    ),
    "tls": (
        "Weak or invalid TLS can enable interception, impersonation, browser warnings, or loss of user trust.",
        "High-level scenario: an attacker attempts to negotiate a weak protocol or exploit certificate validation failure to observe or alter traffic.",
        "Check the certificate and protocol configuration with read-only TLS inspection, renew or replace the certificate, disable obsolete protocols, and retest from a clean client.",
    ),
    "cookies": (
        "A missing cookie flag can expose session material to network interception, client-side script access, or cross-site requests.",
        "High-level scenario: an attacker combines a transport, XSS, or CSRF condition with the weak cookie policy to impersonate or influence a user.",
        "Inspect Set-Cookie headers without using real user sessions, set Secure, HttpOnly, and an appropriate SameSite value, revoke affected sessions, and retest.",
    ),
    "cache_control": (
        "A shared cache may store or replay content associated with a session, exposing private data to another user.",
        "High-level scenario: an attacker requests a cacheable authenticated response and checks whether a later unauthenticated or different-user request receives it.",
        "Use synthetic accounts in staging, verify cache behavior with read-only requests, send private/no-store directives for authenticated content, purge affected caches, and retest.",
    ),
    "exposed_files": (
        "Public backups, configuration files, repositories, or dumps may disclose source code, credentials, personal data, or deployment secrets.",
        "High-level scenario: an attacker enumerates predictable public paths and downloads a sensitive artifact if access controls are missing.",
        "Confirm the response without downloading more data than necessary, remove or block the artifact, rotate every secret it contained, review access logs, and retest.",
    ),
    "info_disclosure": (
        "Version banners and stack traces help an attacker fingerprint the stack, select known vulnerabilities, and learn internal paths or logic.",
        "High-level scenario: an attacker uses harmless invalid requests and public headers to improve targeting of a separate exploit.",
        "Reproduce with a non-sensitive invalid request, disable verbose production errors and version disclosure, review logs for leaked data, and retest.",
    ),
    "tech": (
        "Technology fingerprints reduce the effort required to identify framework-specific weaknesses and exposed components.",
        "High-level scenario: an attacker combines public fingerprints with vulnerability intelligence to prioritize targeted probing.",
        "Treat this as reconnaissance evidence, remove unnecessary version details, keep dependencies patched, and verify that security headers do not reveal extra stack data.",
    ),
    "mixed_content": (
        "A network attacker may tamper with HTTP resources loaded by an HTTPS page, potentially influencing user-visible content or script behavior.",
        "High-level scenario: an attacker modifies an insecure resource in transit while the main page remains HTTPS.",
        "Inventory the flagged resources without executing them, migrate them to HTTPS or same-origin hosting, enable upgrade-insecure-requests where appropriate, and retest.",
    ),
    "form_security": (
        "Credentials or other submitted data may be intercepted when a sensitive form or its destination uses HTTP.",
        "High-level scenario: an attacker on the network observes a form submission before it reaches the application.",
        "Use a synthetic account in staging, verify the form action and redirect chain without submitting credentials, force HTTPS on page and endpoint, and retest.",
    ),
    "dom_xss": (
        "A DOM XSS data flow may let an attacker execute script in a victim's browser, access page data, or act with the victim's privileges.",
        "High-level scenario: an attacker supplies controlled URL or browser data that reaches a dangerous DOM sink in a victim's session.",
        "Trace the data flow statically or in a local test page, use safe inert markers only, replace dangerous sinks with context-safe APIs, and retest with a non-production account.",
    ),
    "robots_disclosure": (
        "Sensitive paths listed in robots.txt can make administrative, backup, or debug endpoints easier to discover.",
        "High-level scenario: an attacker reads the public file and prioritizes the disclosed paths for authorized or unauthorized reconnaissance.",
        "Review the listed paths without brute force, remove unnecessary entries, and enforce authentication and server-side access controls on every path.",
    ),
    "csrf": (
        "An attacker may cause an authenticated browser to submit an unintended state-changing request on behalf of a victim.",
        "High-level scenario: a victim visits an attacker-controlled page while authenticated and the application accepts a cross-site state change without a valid anti-CSRF control.",
        "Use a staging account, verify token enforcement with a harmless no-op test, add server-side CSRF protection and SameSite cookies, and retest.",
    ),
    "secret_scan": (
        "Exposed private keys, API credentials, or session tokens may allow direct control of wallets, infrastructure, repositories, or third-party services.",
        "High-level scenario: an attacker copies the exposed credential and uses the provider's normal authentication path; the scanner does not use or validate the secret.",
        "Treat the finding as compromised, revoke and rotate the credential immediately, inspect provider audit logs, remove it from builds and history, and retest.",
    ),
    "endpoint_exposure": (
        "Public API documentation, source maps, admin panels, or GraphQL endpoints can expose privileged operations, internal code, and attack surface.",
        "High-level scenario: an attacker maps the documented endpoints and uses the disclosed schema to focus later authorization or input-validation testing.",
        "Review only the minimum metadata needed, restrict documentation and admin routes, disable unnecessary introspection, and retest with least-privilege access.",
    ),
    "cdn": (
        "A publicly identified CDN or WAF can reveal infrastructure relationships and may help an attacker search for an exposed origin.",
        "High-level scenario: an attacker correlates edge headers with DNS and deployment data to look for origin bypass opportunities.",
        "Treat this as reconnaissance, keep the origin restricted to trusted edges, review WAF rules, and verify origin access from a controlled network.",
    ),
    "dns_sec": (
        "Missing SPF or DMARC makes domain spoofing and convincing phishing against users or partners easier.",
        "High-level scenario: an attacker sends a message that appears to originate from the domain and relies on weak recipient-side validation.",
        "Inspect DNS records, publish SPF and DMARC with a monitored rollout, review legitimate senders, and verify policy enforcement with controlled test mail.",
    ),
    "sri": (
        "A compromised third-party CDN or package may inject script into the application when external resources lack integrity protection.",
        "High-level scenario: an attacker compromises the resource provider or delivery path and the browser accepts the modified resource.",
        "Pin trusted versions, generate SRI hashes, use crossorigin correctly, prefer self-hosting for critical code, and retest after dependency updates.",
    ),
    "contract_exposure": (
        "Public contract addresses and deployment configuration help attackers map the protocol and identify whether users may interact with an unintended contract.",
        "High-level scenario: an attacker compares public addresses across networks and explorers, then targets weak permissions or a substituted frontend address.",
        "Verify each address against an approved chain-specific registry and verified source, protect deployment files, and review upgrade/admin controls.",
    ),
    "sqli": (
        "SQL injection may expose, alter, or destroy application data and can sometimes lead to broader server compromise.",
        "High-level scenario: an attacker sends harmless test input to an authorized staging endpoint and observes whether database errors reveal unsafe query construction.",
        "Reproduce only with the existing safe detection check in staging, preserve the error evidence, replace concatenated queries with parameterized statements, and retest.",
    ),
    "xss": (
        "Reflected XSS may let an attacker execute script in a victim's browser, read accessible data, or perform actions as the victim.",
        "High-level scenario: an attacker supplies a crafted value that is returned without context-appropriate encoding and is interpreted by a victim's browser.",
        "Use inert markers in staging, apply context-aware output encoding and safe templates, review CSP, and retest without targeting real users.",
    ),
    "open_redirect": (
        "An open redirect can make phishing links appear to originate from a trusted domain and may weaken login or OAuth flows.",
        "High-level scenario: an attacker supplies an external destination and uses the trusted URL as the first hop in a social-engineering campaign.",
        "Validate the redirect with a harmless controlled domain, allow only same-origin or explicit destinations, and retest login and OAuth flows.",
    ),
    "traversal": (
        "Path traversal may expose operating-system files, credentials, source code, or service configuration.",
        "High-level scenario: an attacker submits a path value that escapes the intended directory and the server returns a file outside the web root.",
        "Use only the scanner's read-only detection against a local or staging target, normalize and allowlist paths server-side, and rotate any exposed secrets.",
    ),
    "cors": (
        "Overly permissive CORS may let an attacker-controlled origin read authenticated responses in a victim's browser.",
        "High-level scenario: a victim visits an attacker-controlled origin while authenticated and the browser is allowed to expose protected responses cross-origin.",
        "Verify headers with a harmless read-only request, allowlist trusted origins, avoid credentialed wildcard behavior, and retest with a staging account.",
    ),
    "http_methods": (
        "Dangerous HTTP methods may allow unauthorized modification, deletion, upload, or cross-site tracing depending on server and route controls.",
        "High-level scenario: an attacker discovers that a route advertises an unnecessary method and checks authorization in a controlled environment.",
        "Use OPTIONS/read-only verification, disable unused methods at the edge and application, enforce authorization per route, and retest without mutating data.",
    ),
    "rpc_cors": (
        "An exposed RPC endpoint with permissive CORS can let hostile websites consume node resources or read blockchain data through a victim's browser.",
        "High-level scenario: a victim loads an attacker-controlled origin and the browser permits cross-origin RPC requests to the public endpoint.",
        "Verify only OPTIONS/GET behavior, restrict origins and methods, add authentication and rate limits where needed, and monitor provider usage.",
    ),
    "rpc_methods": (
        "A public RPC may expose sensitive node capabilities, consume paid quotas, or reveal unlocked accounts if it is misconfigured.",
        "High-level scenario: an attacker sends read-only JSON-RPC method checks and uses the returned capability information to target the node or account configuration.",
        "Keep validation read-only, disable account-management methods on public nodes, require authentication and rate limits, and review node logs.",
    ),
    "dex_security": (
        "DEX-specific frontend or exposed-contract patterns may let attackers worsen swap execution, drain approved tokens, abuse signatures, exploit upgrade paths, or profit from manipulable pricing.",
        "High-level scenario: an attacker monitors public configuration and transaction intent, then targets weak minimum-output, allowance, signature, oracle, or contract-control assumptions. No live transaction or exploit payload is provided here.",
        "Validate on a fork or staging deployment with synthetic funds, inspect calldata and allowance boundaries without signing production transactions, review verified source and admin/proxy controls, remediate, revoke affected approvals, and retest.",
    ),
    "dex_rpc": (
        "A DEX address without bytecode on the configured network may indicate a wrong chain, spoofed deployment, destroyed contract, or unsafe frontend configuration that can cause failed or misdirected user operations.",
        "High-level scenario: an attacker substitutes or promotes an incorrect chain-specific address and relies on users signing against an unverified configuration.",
        "Confirm chainId and bytecode with read-only RPC calls, compare addresses with an approved deployment registry, block unknown routers in the frontend, and retest with a disposable wallet.",
    ),
    "wallet_security": (
        "Weak signing, storage, or transport hygiene in a Web3 frontend can let attackers steal signatures, sessions, or funds from connected wallets.",
        "High-level scenario: an attacker phishes or injects a signing/storage flow that the wallet or browser cannot present safely to the user, then reuses the captured authorization.",
        "Validate on a staging build with a disposable wallet, remove blind-signing methods, move secrets out of Web Storage, enforce TLS on all transports, and retest.",
    ),
    "web3_supply_chain": (
        "Outdated, end-of-life, or unpinned Web3 libraries can contain known vulnerabilities or be replaced by malicious releases that reach every user of the site.",
        "High-level scenario: an attacker exploits a public vulnerability in the loaded library version, or publishes/compromises a release that the site serves automatically because the version is not pinned and lacks integrity protection.",
        "Pin an audited version, add SRI, migrate away from end-of-life branches, monitor dependency advisories, and retest after upgrades.",
    ),
    "bucket_exposure": (
        "A publicly listable cloud bucket can expose backups, user data, source code, or secrets, and can be abused to host malicious content under a trusted provider URL.",
        "High-level scenario: an attacker enumerates the bucket referenced by the site, downloads sensitive objects, and uses the leaked data to pivot into infrastructure or user accounts.",
        "Confirm exposure with a read-only listing request, disable anonymous access, apply least-privilege policies, audit exposed objects and access logs, rotate any leaked secrets, and retest.",
    ),
    "seed_harvest": (
        "A page asking users for their seed phrase or private key will harvest wallets: no legitimate service ever needs this data, so it indicates a phishing clone or a critical design failure.",
        "High-level scenario: an attacker operates a look-alike page that requests the recovery phrase and immediately drains every submitted wallet.",
        "Never submit anything to such a page; if it impersonates the company, take it down, warn users, and report the domain; if it is the company's own page, remove the field and treat any submitted data as compromised.",
    ),
    "host_header": (
        "Trusting an attacker-controlled Host header can generate poisoned redirects, links, password-reset URLs, or cacheable content under an attacker domain.",
        "High-level scenario: an attacker supplies a crafted Host value and a proxy or application reflects it into a response that is later sent to users or cached.",
        "Confirm only with a read-only marker on staging, allowlist canonical hosts, avoid deriving absolute URLs from request headers, review proxy configuration, and purge affected caches.",
    ),
    "jwt_oauth": (
        "Weak JWT or OAuth browser flows may expose bearer tokens, allow unsigned tokens, or make replay and account impersonation easier.",
        "High-level scenario: an attacker captures a token from a URL or exploits a backend that accepts an unsigned JWT, then presents it through the normal authentication flow.",
        "Review the flow with synthetic accounts, reject alg=none, migrate OAuth implicit flows to Authorization Code with PKCE, avoid tokens in URLs, and revoke exposed tokens before retesting.",
    ),
    "upload_surface": (
        "An unsafe file-upload surface may allow sensitive files to cross trust boundaries or reach executable web locations when server-side validation is weak.",
        "High-level scenario: an attacker or user submits a crafted file to an upload endpoint and relies on missing transport, type, size, storage, or authorization controls.",
        "Review uploads in staging without submitting harmful files, validate content server-side, store outside the webroot, enforce size and authorization limits, and retest with inert fixtures.",
    ),
    "ssrf_hints": (
        "A user-controlled URL or remote-fetch input may allow the server to reach internal services, cloud metadata, or other restricted networks if validation is incomplete.",
        "High-level scenario: an attacker identifies a remote-fetch parameter and attempts to make the backend cross its network trust boundary; this scanner performs no such request.",
        "Use strict host and scheme allowlists, block private/link-local destinations and unsafe redirects, apply egress filtering, and validate the complete server-side data flow.",
    ),
}


def build_english_guidance(check: str, title: str) -> tuple[str, str, str]:
    """Construye contexto en inglés sin incluir instrucciones operativas de explotación."""
    if check == "dex_security":
        lowered = title.lower()
        if "slippage" in lowered or "amountout" in lowered:
            return (
                "A zero or extreme minimum-output setting may let a sandwich or price-manipulation attacker force a victim's swap to execute at a severely unfavorable rate.",
                "High-level scenario: an attacker observes a pending swap and exploits weak output protection through transaction ordering or manipulated liquidity. Validate only in a fork with synthetic tokens.",
                "Review quote-to-minimum-output calculation, simulate the swap on a fork, enforce bounded slippage, and retest without broadcasting a production transaction.",
            )
        if "aprobación" in lowered or "approval" in lowered:
            return (
                "An unlimited token allowance can let a compromised or malicious router/spender transfer the approved token balance from a user's wallet.",
                "High-level scenario: an attacker gains control of the approved spender or substitutes it in the signing flow, then uses the standard allowance mechanism. Do not test this against a funded wallet.",
                "Inspect allowance amount and spender bytecode on a fork, approve only the required amount, revoke existing risky allowances, and retest with a disposable wallet.",
            )
        if "permit" in lowered:
            return (
                "A permit signature with ineffective expiry can remain reusable long enough for theft if it is leaked or presented to an unintended spender.",
                "High-level scenario: an attacker obtains or redirects a signed permit and relies on its long validity. Validate signature domain and expiry without signing a production message.",
                "Use short deadlines, correct nonce/chainId/verifyingContract, explicit spender allowlists, and revoke or invalidate affected approvals before retesting.",
            )
        if "selfdestruct" in lowered:
            return (
                "An accessible selfdestruct path can critically affect contract availability or move funds when authorization or upgrade controls fail.",
                "High-level scenario: an attacker targets the exposed destruction path through a broken admin, proxy, or role boundary. Do not call it on a live contract.",
                "Review access control and proxy admin history on a fork, remove or lock the path, add timelocks/multisig controls, and retest statically.",
            )
        if "oracle" in lowered:
            return (
                "A spot-reserve price without manipulation resistance may let an attacker distort pricing with temporary liquidity or flash-loan conditions.",
                "High-level scenario: an attacker changes pool state around a price-dependent operation and benefits from the temporary price discrepancy. Validate only in a local fork.",
                "Add a robust oracle/TWAP and deviation limits, simulate manipulated liquidity on a fork, and retest the affected invariant.",
            )
        if "mint" in lowered:
            return (
                "Owner-controlled minting lets whoever holds the owner key inflate supply and dump the new tokens on the pool, draining liquidity from holders.",
                "High-level scenario: a compromised or malicious owner key mints a large supply and sells it into the DEX pool in a single sequence. Review on a fork only.",
                "Cap or disable minting after deployment, protect the owner account with multisig and timelock, publish the emission policy, and retest.",
            )
        if "blacklist" in lowered or "honeypot" in lowered:
            return (
                "A transfer blacklist can let the operator block selected users from selling or moving tokens, a classic honeypot pattern.",
                "High-level scenario: users buy freely, then the operator blacklists them and dumps the treasury while victims cannot exit. Review statically, never trade against the contract.",
                "Remove or strictly justify blacklisting, guard it with multisig/timelock, emit transparent events, and retest with a static review.",
            )
    if check == "wallet_security":
        lowered = title.lower()
        if "eth_sign" in lowered or "ciega" in lowered:
            return (
                "Blind signing with eth_sign lets a malicious or compromised frontend make the victim sign an opaque hash that can authorize a transfer or permit, enabling direct theft of funds.",
                "High-level scenario: a phishing clone or an injected script asks the wallet to 'verify' with eth_sign; the wallet shows only raw hex, the victim signs, and the attacker replays the signature to drain approved tokens.",
                "Remove eth_sign from the frontend, use personal_sign or EIP-712 with a verifiable domain and human-readable message, and retest with a disposable wallet.",
            )
        if "personal_sign" in lowered or "siwe" in lowered:
            return (
                "A personal_sign flow without domain binding can be replayed by a malicious site to impersonate the user or confuse the signature with another authorization.",
                "High-level scenario: a phishing site captures a plain 'verify your wallet' personal_sign and replays it against the real backend because no domain, nonce, or chainId binds the message.",
                "Adopt SIWE (EIP-4361) with domain, URI, chainId, nonce, and expiry validated server-side, and retest the login flow.",
            )
        if "permit" in lowered or "typed data" in lowered:
            return (
                "Permit-style typed-data signatures grant token approvals; if the UI does not clearly show spender, amount, and deadline, a look-alike phishing flow can harvest valid approvals and drain wallets.",
                "High-level scenario: a cloned swap page requests a Permit2 signature with an attacker spender and a far-future deadline; once signed, the attacker pulls the tokens at will.",
                "Display spender/amount/deadline explicitly, use short deadlines, validate the EIP-712 domain, simulate before signing, and retest with a disposable wallet.",
            )
        if "web storage" in lowered or "secretos" in lowered or "storage" in lowered:
            return (
                "Keys, seeds, or session tokens in Web Storage are readable by any JavaScript on the page; a single XSS or malicious dependency can exfiltrate them and take over wallets or accounts.",
                "High-level scenario: an attacker exploits any DOM/reflected XSS or a compromised CDN script, reads localStorage, and sends the victim's keys or session token to a collector endpoint.",
                "Never persist secrets in the browser, move sessions to HttpOnly Secure SameSite cookies, audit for XSS and third-party scripts, and retest.",
            )
        if "websocket" in lowered or "ws://" in lowered:
            return (
                "A cleartext WebSocket lets a network attacker read and modify market data or transaction payloads shown to the user before signing.",
                "High-level scenario: on a hostile network, the attacker alters the ws:// feed so the UI displays an attacker-controlled recipient or manipulated price that the victim then signs.",
                "Enforce wss:// everywhere, pin expected data formats, cross-check critical values on-chain, and retest from a clean client.",
            )
        if "portapapeles" in lowered or "clipboard" in lowered:
            return (
                "Clipboard access combined with any XSS lets attackers swap copied addresses for look-alike attacker addresses (address poisoning).",
                "High-level scenario: an injected script overwrites the clipboard after the victim copies a deposit address; the victim pastes the attacker's similar-looking address and funds are lost.",
                "Always show the full address for confirmation, avoid silent clipboard writes, and retest after fixing any XSS.",
            )
    return _GUIDANCE.get(check, _GENERIC)
