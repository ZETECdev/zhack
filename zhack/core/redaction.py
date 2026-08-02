from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PRIVATE_KEY_RE = re.compile(r"\b0x[0-9a-fA-F]{64}\b")
_EXTENDED_KEY_RE = re.compile(r"\b[xyz]prv[1-9A-HJ-NP-Za-km-z]{50,}\b")
_AWS_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_KNOWN_TOKEN_RE = re.compile(
    r"\b(?:sk|rk)_live_[0-9A-Za-z]{12,}\b|"
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{20,}\b|"
    r"\bgithub_pat_[0-9A-Za-z_]{20,}\b|"
    r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b|"
    r"\bAIza[0-9A-Za-z_-]{20,}\b|"
    r"\bSG\.[0-9A-Za-z_-]{15,}\.[0-9A-Za-z_-]{20,}\b|"
    r"\bGOCSPX-[0-9A-Za-z_-]{20,}\b|"
    r"\bkey-[0-9a-fA-F]{24,}\b"
)
_WEBHOOK_RE = re.compile(
    r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_-]{40,}", re.I
)
_PROVIDER_URL_RE = re.compile(
    r"https://(?:[^\s\"']+\.)?(?:infura\.io/v3|alchemy\.com/v2)/[0-9A-Za-z_-]{16,}",
    re.I,
)
_TELEGRAM_RE = re.compile(r"\b[0-9]{8,10}:[0-9A-Za-z_-]{30,}\b")
_TWILIO_RE = re.compile(r"\bSK[0-9a-fA-F]{32}\b")
_SEED_RE = re.compile(r"([\"'])(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\1", re.I)
_PEM_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.I | re.S,
)
_ASSIGNMENT_RE = re.compile(
    r"(?P<name>\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"private[_-]?key|secret[_-]?key|password|passwd|token|mnemonic|seed[_-]?phrase)\b)"
    r"(?P<separator>\s*[:=]\s*)(?P<quote>[\"']?)(?P<value>[^\"'\s,;}]{8,})",
    re.I,
)

_SENSITIVE_QUERY_NAMES = {
    "api_key",
    "apikey",
    "access_token",
    "auth",
    "authorization",
    "code",
    "client_secret",
    "cookie",
    "jwt",
    "password",
    "passwd",
    "secret",
    "session",
    "token",
}


def redact_sensitive(value: str) -> str:
    """Redacta credenciales sin destruir el contexto útil de la evidencia."""
    if not value:
        return value

    redacted = _PEM_RE.sub("<REDACTED_PRIVATE_KEY>", str(value))
    redacted = _JWT_RE.sub("<REDACTED_JWT>", redacted)
    redacted = _AWS_RE.sub("<REDACTED_AWS_KEY>", redacted)
    redacted = _EXTENDED_KEY_RE.sub("<REDACTED_EXTENDED_KEY>", redacted)
    redacted = _KNOWN_TOKEN_RE.sub("<REDACTED_TOKEN>", redacted)
    redacted = _WEBHOOK_RE.sub("<REDACTED_WEBHOOK>", redacted)
    redacted = _PROVIDER_URL_RE.sub("<REDACTED_PROVIDER_URL>", redacted)
    redacted = _TELEGRAM_RE.sub("<REDACTED_BOT_TOKEN>", redacted)
    redacted = _TWILIO_RE.sub("<REDACTED_TWILIO_KEY>", redacted)
    redacted = _SEED_RE.sub("<REDACTED_SEED>", redacted)
    redacted = _PRIVATE_KEY_RE.sub("<REDACTED_HEX_KEY>", redacted)

    def replace_assignment(match: re.Match) -> str:
        quote = match.group("quote")
        return f"{match.group('name')}{match.group('separator')}{quote}<REDACTED>{quote}"

    redacted = _ASSIGNMENT_RE.sub(replace_assignment, redacted)
    return _redact_url_query(redacted)


def _redact_url_query(value: str) -> str:
    """Oculta valores sensibles en URLs presentes como evidencia o destino."""
    url_re = re.compile(r"https?://[^\s<>\"']+", re.I)

    def replace_url(match: re.Match) -> str:
        raw_url = match.group(0).rstrip(".,);]")
        try:
            parts = urlsplit(raw_url)
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            if not pairs:
                return match.group(0)
            safe_pairs = []
            changed = False
            for name, query_value in pairs:
                if name.lower().replace("-", "_") in _SENSITIVE_QUERY_NAMES:
                    query_value = "<REDACTED>"
                    changed = True
                safe_pairs.append((name, query_value))
            if not changed:
                return match.group(0)
            safe_url = urlunsplit(
                (parts.scheme, parts.netloc, parts.path, urlencode(safe_pairs), parts.fragment)
            )
            suffix = match.group(0)[len(raw_url) :]
            return safe_url + suffix
        except ValueError:
            return match.group(0)

    return url_re.sub(replace_url, value)
