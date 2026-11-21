# JamieJets web3270

Minimal password-protected 3270 terminal at `https://jamiejets.com/mvs/`.

- `index.html`: one-page login and terminal UI (xterm.js loaded from jsDelivr).
- `server.py`: Python HTTP/WebSocket server, authentication, and a separate `c3270` process per browser session.
- `/etc/web3270/config.json`: **private** settings stored outside the web root and repository.

## Install on Ubuntu

Requires Linux, `c3270`, Python 3.10+, and NGINX with an existing HTTPS server block.

```bash
sudo apt update
sudo apt install -y c3270 python3-venv
sudo mkdir -p /opt/web3270 /etc/web3270
sudo cp index.html server.py requirements.txt /opt/web3270/
sudo cp config.example.json /etc/web3270/config.json
cd /opt/web3270
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python server.py hash-password
.venv/bin/python server.py generate-secret
```

Put the generated hash into `password_hash` and the generated random hex into `session_secret` in `/etc/web3270/config.json` (do not put your plain password in the config). Protect the config:

```bash
sudo chmod 600 /etc/web3270/config.json
```

Create a dedicated account and assign ownership to it:

```bash
sudo useradd --system --home /opt/web3270 --shell /usr/sbin/nologin web3270
sudo chown -R web3270:web3270 /opt/web3270 /etc/web3270
```

Create `/etc/systemd/system/web3270.service`:

```ini
[Unit]
Description=JamieJets web3270
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=web3270
Group=web3270
WorkingDirectory=/opt/web3270
ExecStart=/opt/web3270/.venv/bin/python /opt/web3270/server.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

In the existing `jamiejets.com` **HTTPS** NGINX server block add:

```nginx
location = /mvs { return 301 /mvs/; }

location /mvs/ {
    proxy_pass http://127.0.0.1:3271/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;
    proxy_buffering off;
}
```

Then validate and start:

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl daemon-reload
sudo systemctl enable --now web3270
sudo systemctl status web3270
```

Open `https://jamiejets.com/mvs/`. Each browser connection gets its own c3270 process connecting to `31.184.104.201:13270`. The backend only listens on `127.0.0.1` and does not need its own TLS certificate.

## Notes

- The browser connection is HTTPS/WSS, but **the sample TN3270 connection to the remote MVS host is unencrypted**. Use a trusted network/VPN for that leg if credentials or private data are involved.
- This is a personal-use first version, not a hardened multi-user service. Add a rate limiter in NGINX or Cloudflare and consider IP restrictions/Access before exposing it publicly.
- Static libraries currently load from jsDelivr. For fully self-contained/offline operation, vendor xterm.js locally.
- `config.example.json` is safe to commit; **never commit `/etc/web3270/config.json`**.
