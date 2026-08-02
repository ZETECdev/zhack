from __future__ import annotations

import re

from zhack.checks.base import BaseCheck
from zhack.checks.dex_common import collect_frontend_sources, is_dex_text
from zhack.core.models import Severity


_ZERO_OUTPUT_RE = re.compile(
    r"\b(?:amountOutMin|amountOutMinimum|minAmountOut|minOut)\b\s*[:=]\s*"
    r"(?:0n?|0x0+|[\"']0[\"']|BigInt\(\s*0\s*\)|"
    r"(?:ethers(?:\.constants)?|viem)\.Zero|Zero)(?!\w)",
    re.I,
)
_UNLIMITED_APPROVAL_RE = re.compile(
    r"\b(?:approve|safeApprove|forceApprove)\s*\([^;\n]{0,500}?"
    r"(?:MaxUint256|maxUint256|MAX_UINT(?:256)?|2\s*\*\*\s*256\s*-\s*1|0x[fF]{32,})",
    re.I | re.S,
)
_BAD_PERMIT_DEADLINE_RE = re.compile(
    r"\bpermit\b[\s\S]{0,500}?\b(?:deadline|expiry)\b\s*[:=]\s*"
    r"(?:0n?|0x0+|[\"']0[\"']|MaxUint256|maxUint256|MAX_UINT256)",
    re.I,
)
_ZERO_DEADLINE_RE = re.compile(
    r"\b(?:deadline|expiry)\b\s*[:=]\s*(?:0n?|0x0+|[\"']0[\"'])",
    re.I,
)
_EXTREME_SLIPPAGE_RE = re.compile(
    r"\bslippage(?:Tolerance|Bps)?\b\s*[:=]\s*(?:10000|1e[3-9]|999(?:9|99)?)",
    re.I,
)
_USER_CONTROL_RE = re.compile(
    r"(?:location\.(?:search|hash)|new\s+URLSearchParams|"
    r"(?:localStorage|sessionStorage)\s*\.)",
    re.I,
)
_SPENDER_RE = re.compile(r"\b(?:approve|permit|spender|router|permit2)\b", re.I)
_SPENDER_FROM_INPUT_RE = re.compile(
    r"(?:router|spender|routerAddress|factory|vault)\w*\s*[:=]\s*"
    r"(?:new\s+URLSearchParams|location\.(?:search|hash)|searchParams\.get|"
    r"(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|\[))"
    r"|approve\s*\([^;\n)]{0,200}?(?:location\.(?:search|hash)|searchParams\.get|"
    r"(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|\[))",
    re.I,
)
_SOLIDITY_RE = re.compile(r"\b(?:pragma\s+solidity|contract\s+\w+|interface\s+\w+)\b", re.I)
_TX_ORIGIN_RE = re.compile(r"\btx\.origin\b", re.I)
_SELFDESTRUCT_RE = re.compile(r"\bselfdestruct\s*\(", re.I)
_DELEGATECALL_RE = re.compile(r"\.delegatecall\s*\(", re.I)
_VALUE_CALL_RE = re.compile(r"\.call\s*\{[^}]*\bvalue\b", re.I | re.S)
_REENTRANCY_GUARD_RE = re.compile(r"(?:nonReentrant|ReentrancyGuard)", re.I)
_SPOT_ORACLE_RE = re.compile(
    r"(?:getReserves|reserve0|reserve1)[\s\S]{0,500}?"
    r"(?:price|amountOut|quote)",
    re.I,
)
_ORACLE_RE = re.compile(r"(?:twap|oracle|chainlink|observe|consult)", re.I)
_MINT_RE = re.compile(r"\bfunction\s+\w*mint\w*\s*\(", re.I)
_ONLY_OWNER_RE = re.compile(r"\bonlyOwner\b")
_BLACKLIST_RE = re.compile(r"\b(?:isBlacklisted|blacklisted|_blacklist|blacklist)\b", re.I)


class DexSecurityCheck(BaseCheck):
    """Busca patrones de pérdida de fondos en el frontend y fuentes Solidity expuestas."""

    name = "dex_security"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        sources = await collect_frontend_sources(ctx, main.text)
        text = "\n".join(source for _, source in sources)
        if not is_dex_text(text):
            return

        reported: set[str] = set()

        self._report_pattern(
            ctx,
            reported,
            "slippage_cero",
            _ZERO_OUTPUT_RE,
            Severity.HIGH,
            "Swap DEX sin protección de slippage (amountOutMin=0)",
            "La operación puede aceptar cualquier cantidad de tokens de salida. Un atacante puede aprovechar el precio, hacer sandwich y causar una pérdida importante al usuario.",
            "Calcula amountOutMin/amountOutMinimum a partir de una cotización reciente y una tolerancia limitada; no uses cero en producción.",
            text,
        )
        self._report_pattern(
            ctx,
            reported,
            "aprobacion_infinita",
            _UNLIMITED_APPROVAL_RE,
            Severity.HIGH,
            "Aprobación ilimitada de tokens hacia el router DEX",
            "El frontend concede allowance máxima. Si el router, spender o contrato se compromete, puede vaciar todos los tokens aprobados de la wallet.",
            "Aprueba solo la cantidad necesaria, limita el spender a contratos verificados y ofrece revocar allowances. Revisa especialmente Permit2.",
            text,
        )
        self._report_pattern(
            ctx,
            reported,
            "permit_sin_expiracion",
            _BAD_PERMIT_DEADLINE_RE,
            Severity.HIGH,
            "Firma permit de DEX sin expiración efectiva",
            "Una firma EIP-2612/Permit2 con deadline cero o máximo puede reutilizarse durante demasiado tiempo si se filtra o se dirige al spender equivocado.",
            "Usa deadlines cortos, nonce correcto, chainId y verifyingContract esperados; muestra claramente el spender al usuario.",
            text,
        )
        self._report_pattern(
            ctx,
            reported,
            "deadline_cero",
            _ZERO_DEADLINE_RE,
            Severity.MEDIUM,
            "Swap DEX con deadline cero",
            "Una transacción sin expiración temporal puede ejecutarse mucho después de ser firmada, con un precio y contexto distintos.",
            "Usa un deadline corto basado en el tiempo actual y rechaza transacciones caducadas en el contrato.",
            text,
        )
        self._report_pattern(
            ctx,
            reported,
            "slippage_extremo",
            _EXTREME_SLIPPAGE_RE,
            Severity.HIGH,
            "Tolerancia de slippage extrema configurada en el DEX",
            "La configuración permite aceptar prácticamente cualquier precio. Es una señal de posible pérdida por sandwich o manipulación de precio.",
            "Limita la tolerancia por operación, expresa correctamente las unidades (bps o porcentaje) y permite al usuario revisarla antes de firmar.",
            text,
        )

        if "spender_configurable" not in reported and _SPENDER_FROM_INPUT_RE.search(text):
            reported.add("spender_configurable")
            ctx.add(
                self.make(
                    ctx,
                    Severity.HIGH,
                    "Router o spender DEX influido por entrada del navegador",
                    "El código asigna un router/spender o construye una aprobación a partir de datos procedentes de URL, storage o parámetros del navegador. Si no existe una whitelist estricta, puede dirigir fondos a un contrato malicioso.",
                    "Usa una whitelist inmutable de routers por chainId, valida checksum y código desplegado, y nunca tomes el spender desde querystring o localStorage sin validación criptográfica.",
                    evidence=self._evidence(text, _SPENDER_FROM_INPUT_RE),
                )
            )

        if _SOLIDITY_RE.search(text):
            self._report_pattern(
                ctx,
                reported,
                "tx_origin",
                _TX_ORIGIN_RE,
                Severity.HIGH,
                "Contrato DEX usa tx.origin para autorización",
                "tx.origin puede ser manipulado mediante llamadas desde otro contrato y no debe usarse como control de acceso.",
                "Sustituye tx.origin por msg.sender y añade pruebas de autorización y control de acceso por función.",
                text,
            )
            self._report_pattern(
                ctx,
                reported,
                "selfdestruct",
                _SELFDESTRUCT_RE,
                Severity.CRITICAL,
                "Código Solidity expuesto contiene selfdestruct",
                "El contrato contiene una ruta de autodestrucción. Si el control de acceso está roto o el código es actualizable, puede provocar una pérdida crítica de fondos o disponibilidad.",
                "Elimina selfdestruct cuando no sea imprescindible y audita exhaustivamente el control de acceso, timelock y proxy admin.",
                text,
            )
            self._report_pattern(
                ctx,
                reported,
                "delegatecall",
                _DELEGATECALL_RE,
                Severity.HIGH,
                "Contrato DEX usa delegatecall",
                "delegatecall ejecuta código en el almacenamiento del contrato llamador. Un destino controlable o una implementación comprometida puede drenar fondos.",
                "Restringe las implementaciones a una whitelist, protege el proxy admin con multisig y timelock y valida el almacenamiento en upgrades.",
                text,
            )
            if _VALUE_CALL_RE.search(text) and not _REENTRANCY_GUARD_RE.search(text):
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        "Llamada externa con valor sin guardia de reentrancia visible",
                        "La fuente Solidity expuesta realiza una llamada externa con ETH y no muestra ReentrancyGuard/nonReentrant. Es una heurística que requiere revisar el orden de actualizaciones de estado.",
                        "Aplica checks-effects-interactions, nonReentrant cuando proceda y pruebas contra reentrancia y tokens con callbacks.",
                        evidence=self._evidence(text, _VALUE_CALL_RE),
                    )
                )
            if _MINT_RE.search(text) and _ONLY_OWNER_RE.search(text) and "mint_owner" not in reported:
                reported.add("mint_owner")
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        "Función mint controlada por el owner en contrato expuesto",
                        "El contrato permite al owner crear tokens nuevos. Si la clave del owner se compromete (o el deployer es malicioso), puede inflar el suministro y volcarlo sobre la pool, dejando a los holders con tokens sin valor (rug pull clásico).",
                        "Limita o elimina mint tras el despliegue, protege la cuenta owner con multisig + timelock y documenta la política de emisión.",
                        evidence=self._evidence(text, _MINT_RE),
                    )
                )
            self._report_pattern(
                ctx,
                reported,
                "blacklist",
                _BLACKLIST_RE,
                Severity.MEDIUM,
                "Contrato con función de blacklist (patrón de honeypot)",
                "El contrato incluye listas negras de direcciones. Es un patrón habitual de honeypots: los usuarios pueden comprar pero el owner puede impedirles vender o transferir.",
                "Justifica públicamente cualquier lista negra, protégela con multisig/timelock y considera eliminarla si no hay un requisito regulatorio real.",
                text,
            )
            if _SPOT_ORACLE_RE.search(text) and not _ORACLE_RE.search(text):
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        "Precio DEX calculado con reservas spot sin oráculo/TWAP visible",
                        "El código parece derivar precios o cantidades de reservas instantáneas sin una defensa visible contra manipulación. Puede permitir préstamos flash y swaps a precio artificial.",
                        "Usa un oráculo robusto o TWAP, límites de desviación, pausado de emergencia y pruebas de manipulación con flash loans.",
                        evidence=self._evidence(text, _SPOT_ORACLE_RE),
                    )
                )

    def _report_pattern(
        self,
        ctx,
        reported: set[str],
        key: str,
        pattern: re.Pattern,
        severity: Severity,
        title: str,
        description: str,
        remediation: str,
        text: str,
    ) -> None:
        match = pattern.search(text)
        if not match or key in reported:
            return
        reported.add(key)
        ctx.add(
            self.make(
                ctx,
                severity,
                title,
                description,
                remediation,
                evidence=match.group(0),
            )
        )

    @staticmethod
    def _evidence(text: str, pattern: re.Pattern) -> str:
        match = pattern.search(text)
        return match.group(0) if match else "señales DEX relacionadas"
