from __future__ import annotations

import re

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_EXPOSED_PATHS = [
    (
        "/.env",
        b"APP_KEY|DB_PASSWORD|DB_USERNAME|API_KEY|SECRET|TOKEN|PASSWORD",
        Severity.CRITICAL,
        "Archivo .env expuesto",
        "El archivo de configuración con credenciales (.env) es accesible públicamente.",
        "Bloquea el acceso a *.env en el servidor y rota todas las credenciales que contenía.",
    ),
    (
        "/.git/HEAD",
        b"ref:",
        Severity.CRITICAL,
        "Repositorio Git expuesto",
        "El directorio .git es descargable: cualquiera puede bajar el historial completo del código fuente.",
        "Bloquea el acceso a /.git en el servidor web y revoca secretos que existan en el historial.",
    ),
    (
        "/.git/config",
        b"[core]",
        Severity.CRITICAL,
        "Configuración Git expuesta",
        "Se puede leer la configuración del repositorio, incluidas las URLs remotas.",
        "Bloquea el acceso a /.git en el servidor web.",
    ),
    (
        "/wp-config.php.bak",
        b"DB_PASSWORD|DB_USER|define",
        Severity.CRITICAL,
        "Copia de seguridad de wp-config expuesta",
        "Una copia de la configuración de WordPress con credenciales de la base de datos es accesible.",
        "Elimina los backups de configuración y bloquea *.bak / *~ en el servidor.",
    ),
    (
        "/wp-config.php~",
        b"DB_PASSWORD|DB_USER|define",
        Severity.CRITICAL,
        "Copia de seguridad de wp-config expuesta",
        "Una copia de la configuración de WordPress con credenciales de la base de datos es accesible.",
        "Elimina los backups de configuración y bloquea *.bak / *~ en el servidor.",
    ),
    (
        "/config.php.bak",
        b"<?php|password|passwd",
        Severity.CRITICAL,
        "Copia de configuración PHP expuesta",
        "Un backup de configuración PHP es accesible públicamente.",
        "Elimina el archivo y bloquea *.bak en el servidor.",
    ),
    (
        "/backup.zip",
        b"PK\x03\x04",
        Severity.CRITICAL,
        "Archivo de respaldo (backup.zip) descargable",
        "Un zip de respaldo es accesible; puede contener código fuente, credenciales o datos.",
        "Elimina el archivo y saca los backups fuera del webroot.",
    ),
    (
        "/backup.sql",
        b"INSERT INTO|CREATE TABLE|-- MySQL",
        Severity.CRITICAL,
        "Volcado de base de datos expuesto",
        "Un volcado SQL de la base de datos es descargable públicamente.",
        "Elimina el archivo y rota las credenciales si estuvo publicado.",
    ),
    (
        "/db.sql",
        b"INSERT INTO|CREATE TABLE|-- MySQL",
        Severity.CRITICAL,
        "Volcado de base de datos expuesto",
        "Un volcado SQL de la base de datos es descargable públicamente.",
        "Elimina el archivo y rota las credenciales si estuvo publicado.",
    ),
    (
        "/dump.sql",
        b"INSERT INTO|CREATE TABLE|-- MySQL",
        Severity.CRITICAL,
        "Volcado de base de datos expuesto",
        "Un volcado SQL de la base de datos es descargable públicamente.",
        "Elimina el archivo y rota las credenciales si estuvo publicado.",
    ),
    (
        "/phpinfo.php",
        b"phpinfo|PHP Version",
        Severity.HIGH,
        "phpinfo() expuesto",
        "La página phpinfo expone configuración interna, rutas, módulos y variables de entorno del servidor.",
        "Elimina el archivo; nunca publiques información interna del servidor.",
    ),
    (
        "/server-status",
        b"Apache Server Status",
        Severity.MEDIUM,
        "server-status de Apache expuesto",
        "El estado interno del servidor Apache es accesible (módulos, vhosts, actividad).",
        "Restringe /server-status a IPs internas.",
    ),
    (
        "/package.json",
        b'"name"|"dependencies"',
        Severity.LOW,
        "package.json expuesto",
        "Se revela el stack JavaScript y las dependencias; facilita atacar versiones vulnerables conocidas.",
        "Evita servir archivos del proyecto en producción.",
    ),
    (
        "/composer.json",
        b'"require"',
        Severity.LOW,
        "composer.json expuesto",
        "Se revelan las dependencias PHP; facilita atacar versiones vulnerables conocidas.",
        "Evita servir archivos del proyecto en producción.",
    ),
    (
        "/.DS_Store",
        b"Bud1",
        Severity.LOW,
        "Archivo .DS_Store expuesto",
        "Puede revelar la estructura de carpetas del sitio.",
        "Elimínalo o bloquea el acceso a archivos ocultos.",
    ),
    (
        "/.npmrc",
        b"_authToken|registry=|//.*:_auth",
        Severity.HIGH,
        "Configuración de npm expuesta",
        "El archivo .npmrc puede contener tokens de registro privado o credenciales de publicación.",
        "Elimina el archivo del webroot, revoca los tokens y usa un gestor de secretos en CI/CD.",
    ),
    (
        "/.aws/credentials",
        b"aws_access_key_id|aws_secret_access_key",
        Severity.CRITICAL,
        "Credenciales de AWS expuestas",
        "El archivo de credenciales de AWS es accesible públicamente y puede comprometer la cuenta cloud.",
        "Bloquea archivos ocultos, revoca las claves y audita la cuenta de AWS inmediatamente.",
    ),
    (
        "/.svn/entries",
        b"svn|dir|revision",
        Severity.HIGH,
        "Repositorio Subversion expuesto",
        "Se puede leer metadatos del repositorio Subversion y potencialmente reconstruir código fuente.",
        "Bloquea /.svn en el servidor y elimina el directorio del webroot de producción.",
    ),
    (
        "/Dockerfile",
        b"FROM|RUN|COPY|EXPOSE",
        Severity.LOW,
        "Dockerfile expuesto",
        "El Dockerfile revela la imagen base, dependencias y estructura interna del despliegue.",
        "No sirvas archivos de build desde el webroot y revisa que no contengan secretos.",
    ),
    (
        "/docker-compose.yml",
        b"services:|version:|environment:",
        Severity.MEDIUM,
        "Configuración Docker Compose expuesta",
        "La configuración de Compose puede revelar servicios internos, puertos y variables sensibles.",
        "Elimina el archivo del contenido público y rota cualquier secreto que contenga.",
    ),
    (
        "/crossdomain.xml",
        b"cross-domain-policy",
        Severity.LOW,
        "crossdomain.xml presente",
        "Política de Flash obsoleta que puede permitir peticiones cross-domain innecesarias.",
        "Elimina el archivo si no usas Flash.",
    ),
]

_LISTING_PATHS = ["/images/", "/css/", "/js/", "/backups/", "/uploads/"]


def _matches_pattern(pattern: bytes, body: bytes) -> bool:
    """Trata el separador | de las firmas como alternativas literales."""
    lowered = body.lower()
    return any(part.strip().lower() in lowered for part in pattern.split(b"|"))


def _looks_like_html(body: bytes) -> bool:
    """Descarta fallbacks SPA: un archivo sensible real (env/config/sql/zip)
    nunca comienza con una página HTML."""
    head = body[:4096].lstrip(b"\xef\xbb\xbf\x20\x09\x0d\x0a").lower()
    return head.startswith(b"<!doctype") or head.startswith(b"<html")


class ExposedFilesCheck(BaseCheck):
    """Busca archivos sensibles expuestos y listados de directorio."""

    name = "exposed_files"
    mass = True

    async def run(self, ctx) -> None:
        for path, pattern, severity, title, description, remediation in _EXPOSED_PATHS:
            probe_url = ctx.url_for(path)
            res = await ctx.http.fetch("GET", probe_url)
            if res.ok and res.status == 200 and not _looks_like_html(res.body) and _matches_pattern(pattern, res.body):
                ctx.add(
                    self.make(
                        ctx,
                        severity,
                        title,
                        description,
                        remediation,
                        url=probe_url,
                        evidence=res.body[:200].decode("utf-8", errors="replace"),
                    )
                )

        for path in _LISTING_PATHS:
            probe_url = ctx.url_for(path)
            res = await ctx.http.fetch("GET", probe_url)
            if not res.ok:
                continue
            body = res.body.lower()
            if b"index of" in body or b"parent directory" in body:
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        f"Listado de directorio activo ({path})",
                        "El servidor muestra el listado de archivos de un directorio, exponiendo la estructura del sitio.",
                        "Desactiva el autoindex (Options -Indexes en Apache, autoindex off en nginx).",
                        url=probe_url,
                    )
                )

        if not ctx.opts.mass:
            probe_url = ctx.url_for("/.well-known/security.txt")
            res = await ctx.http.fetch("GET", probe_url)
            if not (res.ok and res.status == 200 and b"contact" in res.body.lower()):
                ctx.add(
                    self.make(
                        ctx,
                        Severity.INFO,
                        "No hay security.txt",
                        "La web no publica .well-known/security.txt, que permite a investigadores reportarte vulnerabilidades de forma segura.",
                        "Crea /.well-known/security.txt con una dirección de contacto de seguridad.",
                    )
                )
