from __future__ import annotations

import re
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse

_LINK_RE = re.compile(r'(?:href|src|action)\s*=\s*(["\'])(.*?)\1', re.I)
_FORM_RE = re.compile(r'<form\b[^>]*>', re.I)
_ACTION_RE = re.compile(r'action\s*=\s*(["\'])([^"\']*)\1', re.I)
_METHOD_RE = re.compile(r'method\s*=\s*(["\'])(\w+)\1', re.I)
_INPUT_RE = re.compile(r'<input\b[^>]*>', re.I)
_NAME_RE = re.compile(r'name\s*=\s*(["\'])([^"\']*)\1', re.I)
_BODY_RE = re.compile(r'<body\b[^>]*>(.*?)</body>', re.I | re.S)


def extract_candidate_urls(base_url: str, html: str, limit: int = 15) -> List[str]:
    """Extrae URLs del mismo host (links, scripts, formularios) para el modo profundo."""
    found: List[str] = []
    seen = set()
    base_host = urlparse(base_url).hostname
    for m in _LINK_RE.finditer(html or ""):
        raw = m.group(2).strip()
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        url = urljoin(base_url, raw)
        parsed = urlparse(url)
        if parsed.hostname != base_host or parsed.scheme not in ("http", "https"):
            continue
        if url not in seen:
            seen.add(url)
            found.append(url)
    return found[:limit]


def extract_forms(html: str) -> List[Tuple[str, str, List[str]]]:
    """Extrae formularios: (action, method, lista de nombres de input).

    Retorna lista de (action_url, method, [input_names]).
    """
    forms: List[Tuple[str, str, List[str]]] = []
    if not html:
        return forms
    body_match = _BODY_RE.search(html)
    content = body_match.group(1) if body_match else html
    for fm in _FORM_RE.finditer(content):
        form_tag = fm.group()
        action_m = _ACTION_RE.search(form_tag)
        action = action_m.group(2) if action_m else ""
        method_m = _METHOD_RE.search(form_tag)
        method = method_m.group(2).upper() if method_m else "GET"
        inputs: List[str] = []
        end_pos = fm.end()
        next_form = _FORM_RE.search(content, end_pos)
        form_body_end = next_form.start() if next_form else len(content)
        form_body = content[end_pos:form_body_end]
        for im in _INPUT_RE.finditer(form_body):
            name_m = _NAME_RE.search(im.group())
            if name_m:
                inputs.append(name_m.group(2))
        forms.append((action, method, inputs))
    return forms
