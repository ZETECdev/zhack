from __future__ import annotations

import re
from typing import Iterable, List, Tuple
from urllib.parse import urljoin, urlparse


_DEX_BRAND_RE = re.compile(
    r"\b(?:uniswap|pancakeswap|sushiswap|curve|balancer|1inch|matcha|dydx|"
    r"paraswap|traderjoe|quickswap|raydium|orca|jupiter)\b",
    re.I,
)
_DEX_SWAP_RE = re.compile(
    r"\b(?:swap(?:Exact|Tokens|ETH|Native|In)?|exactInput|exactOutput|"
    r"amountOutMin|amountOutMinimum|minAmountOut|tokenIn|tokenOut)\b",
    re.I,
)
_DEX_MARKET_RE = re.compile(
    r"\b(?:slippage|liquidity|liquidityPool|pair|pool|router|factory|quoter|"
    r"addLiquidity|removeLiquidity|permit2|swap)\b",
    re.I,
)
_FRONTEND_HINT_RE = re.compile(
    r"(?:swap|uniswap|pancake|token|wallet|web3|ethers|viem|chainId|router|rpc)",
    re.I,
)
_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script\s*>", re.I | re.S)
_SCRIPT_SRC_RE = re.compile(
    r"<script\b[^>]+\bsrc\s*=\s*([\"'])(.*?)\1", re.I | re.S
)
_SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s\"']+)")
_RPC_URL_RE = re.compile(
    r"""[\"']((?:https?://|/)[^\"'\\\s]*(?:rpc|infura\.io|alchemy\.com|quicknode\.com|chainstack\.com|helius|drpc|blastapi|tatum)[^\"'\\\s]*)[\"']""",
    re.I,
)
_DEX_ADDRESS_RE = re.compile(
    r"(?P<label>router|factory|quoter|vault|permit2|multicall|pair|pool)"
    r"[A-Za-z0-9_]*\s*[:=]\s*[\"']?(?P<address>0x[0-9a-fA-F]{40})",
    re.I,
)


def is_dex_text(text: str) -> bool:
    """Determina si un texto contiene suficientes señales de una integración DEX."""
    if _DEX_BRAND_RE.search(text):
        return True
    return bool(_DEX_SWAP_RE.search(text) and _DEX_MARKET_RE.search(text))


async def collect_frontend_sources(ctx, html: str, max_files: int = 8) -> List[Tuple[str, str]]:
    """Recoge HTML, scripts y source maps relacionados con una aplicación DEX."""
    sources: List[Tuple[str, str]] = [("HTML principal", html)]
    for match in _SCRIPT_RE.finditer(html):
        if match.group(1).strip():
            sources.append(("script inline", match.group(1)))

    script_urls = _SCRIPT_SRC_RE.findall(html)
    should_fetch = is_dex_text(html) or any(_FRONTEND_HINT_RE.search(src) for src in script_urls)
    if should_fetch:
        seen: set[str] = set()
        for raw_url in script_urls:
            script_url = urljoin(ctx.url, raw_url)
            if script_url in seen or len(seen) >= max_files:
                continue
            seen.add(script_url)
            res = await ctx.fetch("GET", script_url)
            if res.ok and res.body:
                sources.append((script_url, res.text))

    combined = "\n".join(text for _, text in sources)
    if not is_dex_text(combined):
        return sources

    seen_maps: set[str] = set()
    for _, text in list(sources):
        for raw_map in _SOURCE_MAP_RE.findall(text):
            map_url = urljoin(ctx.url, raw_map)
            parsed = urlparse(map_url)
            if parsed.scheme not in ("http", "https") or map_url in seen_maps:
                continue
            seen_maps.add(map_url)
            if len(seen_maps) > 3:
                break
            res = await ctx.fetch("GET", map_url)
            if res.ok and res.body:
                sources.append((map_url, res.text))

    return sources


def extract_rpc_urls(base_url: str, sources: Iterable[Tuple[str, str]]) -> List[str]:
    """Extrae endpoints RPC citados por el frontend DEX."""
    found: List[str] = []
    for _, text in sources:
        for match in _RPC_URL_RE.finditer(text):
            raw = match.group(1)
            url = urljoin(base_url, raw) if raw.startswith("/") else raw
            parsed = urlparse(url)
            if parsed.scheme in ("http", "https") and url not in found:
                found.append(url)
    return found


def extract_dex_addresses(sources: Iterable[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Extrae direcciones etiquetadas como router, factory, vault o similares."""
    found: List[Tuple[str, str]] = []
    for _, text in sources:
        for match in _DEX_ADDRESS_RE.finditer(text):
            item = (match.group("label").lower(), match.group("address").lower())
            if item not in found:
                found.append(item)
    return found
