"""Servidor local DELIBERADAMENTE VULNERABLE para probar ZHack sin riesgo.

Solo ejecútalo en tu máquina (127.0.0.1). NO lo despliegues en internet.
"""

import argparse

from aiohttp import web


def build_app() -> web.Application:
    app = web.Application()

    async def index(request):
        resp = web.Response(
            text=(
                "<html><head><title>ZHack Test Site</title></head><body>"
                '<h1>Hola</h1>'
                '<a href="/sql?q=1">sql</a> '
                '<a href="/xss?name=test">xss</a> '
                '<a href="/traversal?file=1">traversal</a> '
                '<a href="/redirect?url=/">redirect</a> '
                '<a href="/cors">cors</a> '
                '<a href="/safe">safe</a>'
                '<form method="POST" action="/login"><input name="user"><input name="pass"><button type="submit">Login</button></form>'
                '<script src="/app.js"></script>'
                '<script>const rpcUrl = "/rpc";</script>'
                "</body></html>"
            )
        )
        resp.headers["Server"] = "Apache/2.4.49 (Ubuntu)"
        resp.headers["X-Powered-By"] = "Express/4.18.1"
        resp.set_cookie("session", "abc123")
        resp.set_cookie("prefs", "dark", max_age=3600, secure=True, httponly=True, samesite="lax")
        return resp

    async def safe(request):
        resp = web.Response(
            text="ok",
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            },
        )
        return resp

    async def env_file(request):
        return web.Response(text="APP_KEY=zhack_test_secret_abc123\nDB_PASSWORD=supersecret\nAPI_TOKEN=xyz")

    async def git_head(request):
        return web.Response(text="ref: refs/heads/main\n")

    async def git_config(request):
        return web.Response(
            text='[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/example/example.git'
        )

    async def phpinfo(request):
        return web.Response(text="<h1>PHP Version 5.6.40</h1><h2>phpinfo()</h2>")

    async def backup(request):
        return web.Response(body=b"PK\x03\x04 zhack backup test", headers={"Content-Type": "application/zip"})

    async def sql(request):
        q = request.query.get("q", "")
        if "'" in q or '"' in q:
            return web.Response(
                text="SQLSTATE[42000]: Syntax error: You have an error in your SQL syntax near 'test'' at line 1"
            )
        return web.Response(text="ok")

    async def xss(request):
        name = request.query.get("name", "")
        return web.Response(text=f"<html><body><h1>Hola {name}</h1></body></html>")

    async def redirect(request):
        url = request.query.get("url", "/")
        return web.Response(status=302, headers={"Location": url})

    async def traversal(request):
        f = request.query.get("file", "")
        if "etc/passwd" in f:
            return web.Response(
                text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin"
            )
        return web.Response(text="no")

    async def cors(request):
        origin = request.headers.get("Origin", "")
        resp = web.Response(text="ok")
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    async def listing(request):
        return web.Response(
            text="<html><body><h1>Index of /images/</h1><pre>..\nlogo.png\nbanner.jpg</pre></body></html>"
        )

    async def err500(request):
        return web.Response(
            text='<pre>Traceback (most recent call last):\n  File "/app/app.py", line 42, in index\nValueError: something broke</pre>',
            status=500,
        )

    async def options_handler(request):
        return web.Response(
            text="",
            headers={"Allow": "GET, POST, HEAD, OPTIONS, PUT, DELETE, TRACE, PATCH"},
        )

    async def app_js(request):
        # Secretos de PRUEBA construidos por concatenación para que GitHub
        # push protection no los confunda con claves reales (son ficticios).
        infura = "https://mainnet.infura.io/v3/" + "0123456789abcdef0123456789abcdef"
        aws = "AKIA" + "IOSFODNN7EXAMPLE"
        stripe = "sk_" + "live_51HZaXxExampleTestKey123456"
        return web.Response(
            text=(
                f'window.INFURA = "{infura}";\n'
                f'window.AWS_KEY = "{aws}";\n'
                f'window.STRIPE = "{stripe}";\n'
                "//# sourceMappingURL=/app.js.map\n"
            ),
            headers={"Content-Type": "application/javascript"},
        )

    async def app_js_map(request):
        return web.Response(
            text='{"version":3,"file":"app.js","sources":["src/app.ts"],"names":[],"mappings":"AAAA"}'
        )

    async def swagger(request):
        return web.Response(
            text="<html><head><title>Swagger UI</title></head><body><h1>Swagger UI</h1></body></html>"
        )

    async def rpc_options(request):
        origin = request.headers.get("Origin", "")
        resp = web.Response(text="")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
        return resp

    async def rpc_get(request):
        return web.Response(
            text='{"jsonrpc":"2.0","id":1,"result":"0x1"}',
            headers={"Content-Type": "application/json"},
        )

    app.router.add_get("/", index)
    app.router.add_get("/safe", safe)
    app.router.add_get("/.env", env_file)
    app.router.add_get("/env", env_file)
    app.router.add_get("/.git/HEAD", git_head)
    app.router.add_get("/.git/config", git_config)
    app.router.add_get("/phpinfo.php", phpinfo)
    app.router.add_get("/backup.zip", backup)
    app.router.add_get("/sql", sql)
    app.router.add_get("/xss", xss)
    app.router.add_get("/redirect", redirect)
    app.router.add_get("/traversal", traversal)
    app.router.add_get("/cors", cors)
    app.router.add_get("/images/", listing)
    app.router.add_get("/err", err500)
    app.router.add_get("/app.js", app_js)
    app.router.add_get("/app.js.map", app_js_map)
    app.router.add_get("/swagger-ui.html", swagger)
    app.router.add_get("/rpc", rpc_get)
    app.router.add_route("OPTIONS", "/", options_handler)
    app.router.add_route("OPTIONS", "/safe", options_handler)
    app.router.add_route("OPTIONS", "/rpc", rpc_options)
    return app


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Servidor local deliberadamente vulnerable para probar ZHack"
    )
    parser.add_argument("--port", type=int, default=8070)
    args = parser.parse_args()
    web.run_app(build_app(), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
