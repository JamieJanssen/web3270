#!/usr/bin/env python3
"""Tiny authenticated 3270 web terminal. Requires Linux, aiohttp and c3270."""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import pty
import secrets
import signal
import struct
import sys
import termios
import time
import fcntl
from pathlib import Path

from aiohttp import WSMsgType, web


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("WEB3270_CONFIG", "/etc/web3270/config.json"))
COOKIE = "web3270_session"
SESSION_SECONDS = 8 * 60 * 60


def password_hash(password):
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 400_000)
    return "pbkdf2_sha256$400000$" + salt.hex() + "$" + key.hex()


def verify_password(password, encoded):
    try:
        algorithm, rounds, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or not 100_000 <= int(rounds) <= 2_000_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def sign_session(config):
    expiry = str(int(time.time()) + SESSION_SECONDS)
    signature = hmac.new(bytes.fromhex(config["session_secret"]), expiry.encode(), hashlib.sha256).hexdigest()
    return expiry + "." + signature


def authenticated(request):
    token = request.cookies.get(COOKIE, "")
    try:
        expiry, signature = token.split(".", 1)
        if int(expiry) < time.time() or int(expiry) > time.time() + SESSION_SECONDS:
            return False
        expected = hmac.new(bytes.fromhex(request.app["config"]["session_secret"]), expiry.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)
    except (ValueError, KeyError):
        return False


def same_origin(request):
    # NGINX must forward the external Host and X-Forwarded-Proto headers.
    origin = request.headers.get("Origin", "")
    expected = "https://" + request.headers.get("Host", "")
    return origin == expected


async def index(request):
    html_path = Path(request.app["config"].get("html_path", str(ROOT / "index.html")))
    html = html_path.read_bytes()
    nonce = secrets.token_urlsafe(24)
    # Only our single inline application script gets a one-time CSP nonce.
    html = html.replace(b"<script>", f'<script nonce="{nonce}">'.encode("ascii"))
    response = web.Response(body=html, content_type="text/html", charset="utf-8")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'none'; script-src 'self' https://cdn.jsdelivr.net 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "connect-src 'self' wss:; font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


async def status(request):
    return web.json_response({"authenticated": authenticated(request)}, headers={"Cache-Control": "no-store"})


async def login(request):
    if not same_origin(request):
        raise web.HTTPForbidden()
    try:
        payload = await request.json()
        password = payload["password"]
        if not isinstance(password, str) or len(password) > 1024:
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise web.HTTPBadRequest()
    if not verify_password(password, request.app["config"]["password_hash"]):
        await asyncio.sleep(0.5)
        raise web.HTTPUnauthorized(text="Incorrect password")
    response = web.json_response({"ok": True})
    response.set_cookie(COOKIE, sign_session(request.app["config"]), secure=True,
                        httponly=True, samesite="Strict", path=request.app["config"]["base_path"] + "/",
                        max_age=SESSION_SECONDS)
    return response


async def logout(request):
    if not same_origin(request):
        raise web.HTTPForbidden()
    response = web.json_response({"ok": True})
    response.del_cookie(COOKIE, path=request.app["config"]["base_path"] + "/")
    return response


async def terminal(request):
    if not authenticated(request) or not same_origin(request):
        raise web.HTTPForbidden()
    ws = web.WebSocketResponse(heartbeat=30, max_msg_size=16384)
    await ws.prepare(request)
    cfg = request.app["config"]
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    child = None
    reader_task = None
    try:
        child = await asyncio.create_subprocess_exec(
            "c3270", "-model", "3279-2", f'{cfg["mvs_host"]}:{cfg["mvs_port"]}',
            stdin=slave, stdout=slave, stderr=slave,
            env={**os.environ, "TERM": "xterm"}, start_new_session=True,
        )
        os.close(slave)
        slave = -1
        loop = asyncio.get_running_loop()

        async def relay_output():
            while True:
                try:
                    data = await loop.run_in_executor(None, os.read, master, 4096)
                except OSError:
                    break
                if not data:
                    break
                await ws.send_str(base64.b64encode(data).decode("ascii"))

        reader_task = asyncio.create_task(relay_output())
        async for message in ws:
            if message.type == WSMsgType.TEXT:
                try:
                    data = base64.b64decode(message.data, validate=True)
                    if len(data) > 4096:
                        await ws.close(code=1009)
                        break
                    await loop.run_in_executor(None, os.write, master, data)
                except (ValueError, OSError):
                    break
            elif message.type == WSMsgType.ERROR:
                break
    except FileNotFoundError:
        await ws.send_str(base64.b64encode(b"\r\nc3270 is not installed.\r\n").decode())
    finally:
        if child and child.returncode is None:
            child.terminate()
            try:
                await asyncio.wait_for(child.wait(), timeout=2)
            except asyncio.TimeoutError:
                child.kill()
                await child.wait()
        if reader_task:
            reader_task.cancel()
            await asyncio.gather(reader_task, return_exceptions=True)
        os.close(master)
        if slave != -1:
            os.close(slave)
        await ws.close()
    return ws


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "hash-password":
        import getpass
        print(password_hash(getpass.getpass("New login password: ")))
        return
    if len(sys.argv) == 2 and sys.argv[1] == "generate-secret":
        print(secrets.token_hex(32))
        return
    if len(sys.argv) != 1:
        sys.exit("Usage: server.py [hash-password|generate-secret]")
    cfg = json.loads(CONFIG_PATH.read_text())
    if not cfg.get("password_hash", "").startswith("pbkdf2_sha256$"):
        sys.exit("Configure a password hash first")
    if len(bytes.fromhex(cfg["session_secret"])) < 32:
        sys.exit("Configure a random session secret first")
    if cfg["listen_host"] not in ("127.0.0.1", "::1"):
        sys.exit("For safety, listen_host must be localhost")
    app = web.Application(client_max_size=2048)
    app["config"] = cfg
    app.router.add_get("/", index)
    app.router.add_get("/status", status)
    app.router.add_post("/login", login)
    app.router.add_post("/logout", logout)
    app.router.add_get("/ws", terminal)
    web.run_app(app, host=cfg["listen_host"], port=int(cfg["listen_port"]))


if __name__ == "__main__":
    main()
