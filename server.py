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
REPLAY_LIMIT = 1024 * 1024


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


class PersistentTerminal:
    """One c3270 process shared by successive authenticated browsers."""

    def __init__(self, app):
        self.app = app
        self.client = None
        self.process = None
        self.master = None
        self.reader = None
        self.timer = None
        self.replay = bytearray()
        self.send_lock = asyncio.Lock()

    async def start(self):
        config = self.app["config"]
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        try:
            process = await asyncio.create_subprocess_exec(
                "c3270", "-model", "3279-2", f'{config["mvs_host"]}:{config["mvs_port"]}',
                stdin=slave, stdout=slave, stderr=slave,
                env={**os.environ, "TERM": "xterm"}, start_new_session=True,
            )
        except BaseException:
            os.close(master)
            raise
        finally:
            os.close(slave)
        self.master = master
        self.process = process
        self.replay.clear()
        self.reader = asyncio.create_task(self.read_output())

    async def read_output(self):
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await loop.run_in_executor(None, os.read, self.master, 4096)
            except OSError:
                break
            if not data:
                break
            async with self.send_lock:
                self.replay.extend(data)
                if len(self.replay) > REPLAY_LIMIT:
                    del self.replay[:len(self.replay) - REPLAY_LIMIT]
                client = self.client
                if client and not client.closed:
                    try:
                        await client.send_str(base64.b64encode(data).decode("ascii"))
                    except ConnectionError:
                        pass
        if self.client and not self.client.closed:
            await self.client.close(message=b"MVS connection ended")

    def detach(self, client):
        if self.client is not client:
            return
        self.client = None
        if self.timer:
            self.timer.cancel()
        delay = int(self.app["config"].get("session_timeout_minutes", 60)) * 60
        self.timer = asyncio.get_running_loop().call_later(delay, lambda: asyncio.create_task(self.expire()))

    async def expire(self):
        async with self.app["terminal_lock"]:
            if self.client is None and self.app["terminal_session"] is self:
                await self.stop()
                self.app["terminal_session"] = None

    async def attach(self, client):
        if self.timer:
            self.timer.cancel()
            self.timer = None
        previous = self.client
        # A new browser takes over the single terminal. No second MVS login.
        self.client = client
        if previous and previous is not client and not previous.closed:
            await previous.close(code=4001, message=b"Session opened elsewhere")
        async with self.send_lock:
            if self.replay:
                # Replays the terminal's ANSI updates to reconstruct its last screen.
                for offset in range(0, len(self.replay), 16384):
                    await client.send_str(base64.b64encode(self.replay[offset:offset + 16384]).decode("ascii"))

    async def stop(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None
        client, self.client = self.client, None
        if client and not client.closed:
            await client.close(code=4002, message=b"MVS disconnected")
        process, self.process = self.process, None
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        if self.master is not None:
            os.close(self.master)
            self.master = None
        if self.reader:
            self.reader.cancel()
            await asyncio.gather(self.reader, return_exceptions=True)
            self.reader = None
        self.replay.clear()


async def disconnect(request):
    if not authenticated(request) or not same_origin(request):
        raise web.HTTPForbidden()
    async with request.app["terminal_lock"]:
        session = request.app["terminal_session"]
        if session:
            await session.stop()
            request.app["terminal_session"] = None
    return web.json_response({"ok": True})


async def terminal(request):
    if not authenticated(request) or not same_origin(request):
        raise web.HTTPForbidden()
    ws = web.WebSocketResponse(heartbeat=30, max_msg_size=16384)
    await ws.prepare(request)
    app = request.app
    session = None
    try:
        async with app["terminal_lock"]:
            session = app["terminal_session"]
            if session is None or session.process is None or session.process.returncode is not None:
                if session is not None:
                    await session.stop()
                session = PersistentTerminal(app)
                await session.start()
                app["terminal_session"] = session
            await session.attach(ws)
        loop = asyncio.get_running_loop()
        async for message in ws:
            if message.type == WSMsgType.TEXT:
                try:
                    data = base64.b64decode(message.data, validate=True)
                    if len(data) > 4096:
                        await ws.close(code=1009)
                        break
                    if session.client is ws and session.master is not None:
                        await loop.run_in_executor(None, os.write, session.master, data)
                except (ValueError, OSError):
                    break
            elif message.type == WSMsgType.ERROR:
                break
    except FileNotFoundError:
        await ws.send_str(base64.b64encode(b"\r\nc3270 is not installed.\r\n").decode())
    finally:
        if session:
            session.detach(ws)
        await ws.close()
    return ws


async def shutdown(app):
    session = app["terminal_session"]
    if session:
        await session.stop()


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
    if not 1 <= int(cfg.get("session_timeout_minutes", 60)) <= 1440:
        sys.exit("session_timeout_minutes must be between 1 and 1440")
    app = web.Application(client_max_size=2048)
    app["config"] = cfg
    app["terminal_lock"] = asyncio.Lock()
    app["terminal_session"] = None
    app.on_shutdown.append(shutdown)
    app.router.add_get("/", index)
    app.router.add_get("/status", status)
    app.router.add_post("/login", login)
    app.router.add_post("/logout", logout)
    app.router.add_post("/disconnect", disconnect)
    app.router.add_get("/ws", terminal)
    web.run_app(app, host=cfg["listen_host"], port=int(cfg["listen_port"]))


if __name__ == "__main__":
    main()
