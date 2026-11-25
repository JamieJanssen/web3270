#!/usr/bin/env python3
"""Tiny authenticated 3270 web terminal. Requires Linux, aiohttp and c3270."""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import pty
import re
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
ADMIN_COOKIE = "web3270_admin"
SESSION_SECONDS = 8 * 60 * 60
REPLAY_LIMIT = 1024 * 1024
MAX_TERMINALS = 8


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


def sign_session(config, username):
    expiry = str(int(time.time()) + SESSION_SECONDS)
    message = f"{expiry}.{username}"
    signature = hmac.new(bytes.fromhex(config["session_secret"]), message.encode(), hashlib.sha256).hexdigest()
    return message + "." + signature


def session_username(request, cookie=COOKIE):
    token = request.cookies.get(cookie, "")
    try:
        expiry, username, signature = token.split(".", 2)
        if int(expiry) < time.time() or int(expiry) > time.time() + SESSION_SECONDS:
            return None
        if not re.fullmatch(r"[A-Z0-9_-]{1,16}", username):
            return None
        expected = hmac.new(bytes.fromhex(request.app["config"]["session_secret"]),
                            f"{expiry}.{username}".encode(), hashlib.sha256).hexdigest()
        return username if hmac.compare_digest(signature, expected) else None
    except (ValueError, KeyError):
        return None


def authenticated(request):
    return session_username(request) is not None


def admin_access(request):
    return authenticated(request) and session_username(request, ADMIN_COOKIE) == "ADMIN"


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
    username = session_username(request)
    return web.json_response({"authenticated": username is not None, "username": username}, headers={"Cache-Control": "no-store"})


async def sessions(request):
    if not authenticated(request):
        raise web.HTTPForbidden()
    async with request.app["terminal_lock"]:
        items = [
            {"username": name, "connected": terminal.client is not None and not terminal.client.closed}
            for name, terminal in sorted(request.app["terminal_sessions"].items())
        ]
    return web.json_response({"sessions": items, "current": session_username(request),
                              "can_switch": admin_access(request)}, headers={"Cache-Control": "no-store"})


async def switch_session(request):
    if not same_origin(request) or not admin_access(request):
        raise web.HTTPForbidden()
    try:
        payload = await request.json()
        username = payload["username"]
        if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,16}", username):
            raise ValueError()
        username = username.upper()
    except (ValueError, KeyError, TypeError):
        raise web.HTTPBadRequest()
    async with request.app["terminal_lock"]:
        if username not in request.app["terminal_sessions"]:
            raise web.HTTPNotFound(text="Session no longer exists")
    response = web.json_response({"ok": True, "username": username})
    response.set_cookie(COOKIE, sign_session(request.app["config"], username), secure=True,
                        httponly=True, samesite="Strict", path=request.app["config"]["base_path"] + "/",
                        max_age=SESSION_SECONDS)
    return response


async def login(request):
    if not same_origin(request):
        raise web.HTTPForbidden()
    try:
        payload = await request.json()
        password = payload["password"]
        username = payload.get("username", "Admin")
        if not isinstance(password, str) or len(password) > 1024:
            raise ValueError()
        if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,16}", username):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise web.HTTPBadRequest()
    if not verify_password(password, request.app["config"]["password_hash"]):
        await asyncio.sleep(0.5)
        raise web.HTTPUnauthorized(text="Incorrect password")
    response = web.json_response({"ok": True, "username": username.upper()})
    response.set_cookie(COOKIE, sign_session(request.app["config"], username.upper()), secure=True,
                        httponly=True, samesite="Strict", path=request.app["config"]["base_path"] + "/",
                        max_age=SESSION_SECONDS)
    if username.upper() == "ADMIN":
        response.set_cookie(ADMIN_COOKIE, sign_session(request.app["config"], "ADMIN"), secure=True,
                            httponly=True, samesite="Strict", path=request.app["config"]["base_path"] + "/",
                            max_age=SESSION_SECONDS)
    else:
        response.del_cookie(ADMIN_COOKIE, path=request.app["config"]["base_path"] + "/")
    return response


async def logout(request):
    if not same_origin(request):
        raise web.HTTPForbidden()
    response = web.json_response({"ok": True})
    response.del_cookie(COOKIE, path=request.app["config"]["base_path"] + "/")
    response.del_cookie(ADMIN_COOKIE, path=request.app["config"]["base_path"] + "/")
    return response


class PersistentTerminal:
    """One persistent c3270 process for a particular website username."""

    def __init__(self, app, username):
        self.app = app
        self.username = username
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
                "c3270", "-reconnect", "-model", "3279-2", f'{config["mvs_host"]}:{config["mvs_port"]}',
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
        delay = int(self.app["config"].get("session_timeout_minutes", 240)) * 60
        self.timer = asyncio.get_running_loop().call_later(delay, lambda: asyncio.create_task(self.expire()))

    async def expire(self):
        async with self.app["terminal_lock"]:
            if self.client is None and self.app["terminal_sessions"].get(self.username) is self:
                await self.stop()
                del self.app["terminal_sessions"][self.username]

    async def attach(self, client):
        if self.timer:
            self.timer.cancel()
            self.timer = None
        previous = self.client
        # A browser reconnecting as the same user takes over that user's terminal.
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
    username = session_username(request)
    if username is None or not same_origin(request):
        raise web.HTTPForbidden()
    async with request.app["terminal_lock"]:
        session = request.app["terminal_sessions"].pop(username, None)
        if session:
            await session.stop()
    return web.json_response({"ok": True})


async def terminal(request):
    username = session_username(request)
    if username is None or not same_origin(request):
        raise web.HTTPForbidden()
    ws = web.WebSocketResponse(heartbeat=30, max_msg_size=16384)
    await ws.prepare(request)
    app = request.app
    session = None
    try:
        async with app["terminal_lock"]:
            session = app["terminal_sessions"].get(username)
            new_terminal = False
            if session is None or session.process is None or session.process.returncode is not None:
                if session is not None:
                    await session.stop()
                elif len(app["terminal_sessions"]) >= MAX_TERMINALS:
                    await ws.close(code=1013, message=b"Too many terminal sessions")
                    return ws
                session = PersistentTerminal(app, username)
                await session.start()
                app["terminal_sessions"][username] = session
                new_terminal = True
            if new_terminal:
                # A non-base64 control frame tells the browser to clear once,
                # after the first new terminal screen has finished rendering.
                await ws.send_str("!web3270:new-terminal")
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
    for session in list(app["terminal_sessions"].values()):
        await session.stop()
    app["terminal_sessions"].clear()


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
    if not 1 <= int(cfg.get("session_timeout_minutes", 240)) <= 1440:
        sys.exit("session_timeout_minutes must be between 1 and 1440")
    app = web.Application(client_max_size=2048)
    app["config"] = cfg
    app["terminal_lock"] = asyncio.Lock()
    app["terminal_sessions"] = {}
    app.on_shutdown.append(shutdown)
    app.router.add_get("/", index)
    app.router.add_get("/status", status)
    app.router.add_get("/sessions", sessions)
    app.router.add_post("/switch", switch_session)
    app.router.add_post("/login", login)
    app.router.add_post("/logout", logout)
    app.router.add_post("/disconnect", disconnect)
    app.router.add_get("/ws", terminal)
    web.run_app(app, host=cfg["listen_host"], port=int(cfg["listen_port"]))


if __name__ == "__main__":
    main()
