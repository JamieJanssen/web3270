# JamieJets web3270

Minimal 3270 terminal at `https://jamiejets.com/mvs/`, using the existing NGINX HTTPS certificate.

The terminal uses IBM 3270 Model 2 (80 columns × 24 rows). The frontend has a Normal/Stretch display toggle; stretching changes only the visual size, not the terminal geometry.

## Directory layout on Jester

```text
/home/jamie/www/jamiejets.com/
├── public/mvs/index.html      # Public HTML/CSS login and terminal
└── web3270/                   # Backend, outside the public webroot
    ├── server.py
    ├── requirements.txt
    ├── .venv/
    └── config.json            # Private, gitignored configuration
```

## 1. Install

```bash
sudo apt update
sudo apt install -y git python3-venv c3270
```

As the normal `jamie` user (provided they own the site files):

```bash
cd /home/jamie/www/jamiejets.com
git clone https://github.com/JamieJanssen/web3270.git web3270
mkdir -p public/mvs
cp web3270/index.html public/mvs/index.html
cd web3270
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp config.example.json config.json
```

If `web3270/` already exists, inspect it first. Use `git pull` if it is an existing Git clone; do not overwrite or delete existing files blindly.

## 2. Password and secret

```bash
cd /home/jamie/www/jamiejets.com/web3270
.venv/bin/python server.py hash-password
.venv/bin/python server.py generate-secret
nano config.json
```

Paste the generated values into `password_hash` and `session_secret`. Never store the plain password. Confirm `html_path` is `/home/jamie/www/jamiejets.com/public/mvs/index.html` and `base_path` is `/mvs`.

```bash
chmod 600 config.json
```

## 3. systemd

Create `/etc/systemd/system/web3270.service` with `sudo nano`:

```ini
[Unit]
Description=JamieJets web3270
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=jamie
Group=jamie
WorkingDirectory=/home/jamie/www/jamiejets.com/web3270
Environment=WEB3270_CONFIG=/home/jamie/www/jamiejets.com/web3270/config.json
ExecStart=/home/jamie/www/jamiejets.com/web3270/.venv/bin/python /home/jamie/www/jamiejets.com/web3270/server.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now web3270
sudo systemctl status web3270
```

## 4. NGINX

Inside the **existing HTTPS `server {}` block for `jamiejets.com`**, add:

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

The trailing slash in `proxy_pass` is important: it maps `/mvs/ws` to backend `/ws`. The Python server serves the HTML located in your public webroot so it can attach appropriate security headers.

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Browse to `https://jamiejets.com/mvs/`.

## Troubleshooting

```bash
sudo journalctl -u web3270 -n 50 --no-pager
curl -i http://127.0.0.1:3271/status
```

## Security notes

- Python listens only on `127.0.0.1`, not a public port.
- The login cookie is Secure, HttpOnly and SameSite=Strict.
- The browser connection uses HTTPS/WSS, but the sample remote TN3270 connection to `31.184.104.201:13270` is **unencrypted**. Use a VPN or equivalent where credentials/private data are involved.
- This is a personal-use first release, not a hardened multi-user gateway. Add NGINX/Cloudflare rate limiting or access policies before broad exposure.
- The frontend loads xterm.js from jsDelivr; vendor it locally for offline operation.
- Never put `config.json` inside `public/` or commit it to Git.
