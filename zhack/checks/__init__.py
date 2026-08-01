from __future__ import annotations

from typing import List

from zhack.checks.base import BaseCheck
from zhack.checks.passive.cdn import CdnDetectCheck
from zhack.checks.passive.cookies import CookieFlagsCheck
from zhack.checks.passive.contract_exposure import ContractExposureCheck
from zhack.checks.passive.csrf import CSRFCheck
from zhack.checks.passive.dns_sec import DnsSecurityCheck
from zhack.checks.passive.endpoint_exposure import EndpointExposureCheck
from zhack.checks.passive.exposed_files import ExposedFilesCheck
from zhack.checks.passive.headers import SecurityHeadersCheck
from zhack.checks.passive.https import HTTPSCheck
from zhack.checks.passive.info_disclosure import InfoDisclosureCheck
from zhack.checks.passive.mixed_content import MixedContentCheck
from zhack.checks.passive.secret_scan import SecretScanCheck
from zhack.checks.passive.sri import SubresourceIntegrityCheck
from zhack.checks.passive.tech import TechFingerprintCheck
from zhack.checks.passive.tls_check import TLSCheck

from zhack.checks.active.cors import CORSCheck
from zhack.checks.active.http_methods import HTTPMethodsCheck
from zhack.checks.active.open_redirect import OpenRedirectCheck
from zhack.checks.active.rpc_cors import RpcCorsCheck
from zhack.checks.active.rpc_methods import RpcMethodsCheck
from zhack.checks.active.sqli import SQLiCheck
from zhack.checks.active.traversal import TraversalCheck
from zhack.checks.active.xss import ReflectedXSSCheck

_ALL_CHECK_CLASSES: List[type] = [
    HTTPSCheck,
    SecurityHeadersCheck,
    TLSCheck,
    CookieFlagsCheck,
    ExposedFilesCheck,
    InfoDisclosureCheck,
    TechFingerprintCheck,
    MixedContentCheck,
    CSRFCheck,
    SecretScanCheck,
    EndpointExposureCheck,
    CdnDetectCheck,
    DnsSecurityCheck,
    SubresourceIntegrityCheck,
    ContractExposureCheck,
    SQLiCheck,
    ReflectedXSSCheck,
    OpenRedirectCheck,
    TraversalCheck,
    CORSCheck,
    HTTPMethodsCheck,
    RpcCorsCheck,
    RpcMethodsCheck,
]


def build_checks(active: bool = False, mass: bool = False) -> List[BaseCheck]:
    """Construye la lista de checks según el modo de escaneo."""
    checks: List[BaseCheck] = []
    for cls in _ALL_CHECK_CLASSES:
        if mass and not cls.mass:
            continue
        if cls.requires_active and not active:
            continue
        checks.append(cls())
    return checks
