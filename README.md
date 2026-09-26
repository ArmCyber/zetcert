# zetcert

zetcert manages the Let's Encrypt certificates of an nginx server, on top of certbot.

- **nginx decides which certificate a site uses.** A server block includes `/etc/nginx/zetcert/<cert>.conf`, and the certificate gets the `server_name`s of every block that includes it.
- **certbot does the ACME work and the renewals**, on its own timer. zetcert decides which certificates exist and which names they hold.
- **zetcert never edits your nginx files.** It writes only its own files in `/etc/nginx/zetcert/`.
- **After changing nginx, run `sudo zetcert sync`.** It shows the changes, issues what is needed, updates the snippets, runs `nginx -t` and reloads nginx.

Every command, setting and file is described in [docs/reference.md](docs/reference.md).

## Requirements

Linux with systemd (Debian and Ubuntu are tested), nginx, certbot (`apt install certbot` or the snap, no plugins needed), openssl, and Node.js 20 or newer.

## Install

```sh
npm install -g zetcert   # with sudo when Node is installed system-wide (apt, NodeSource)
zetcert init             # as your normal user, without sudo: it asks for sudo itself
```

`init` asks for an email, the webroot, the server's public IPs and an optional [alert command](#alerts-and-monitoring), and offers to import the certificates certbot already has. From then on, `sudo zetcert …` works however Node was installed. With nvm or volta, `sudo zetcert` says "command not found" until `init` has run.

## nginx setup

**Include a certificate's snippet in each HTTPS server block.** Blocks that include the same snippet share one certificate. Never include the whole directory (`zetcert/*.conf`).

```nginx
server {
    listen 443 ssl;
    server_name shop.example.com www.shop.example.com;
    include /etc/nginx/zetcert/shop.conf;
}
```

**Port 80: answer Let's Encrypt's checks.** Open `/etc/nginx/sites-available/default` and replace everything in it with this. It serves the validation path for every domain and sends all other HTTP traffic to HTTPS. If you keep your own port-80 server instead, add just the `include` line to it.

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    include /etc/nginx/zetcert/_acme.conf;
    location / { return 301 https://$host$request_uri; }
}
```

**Optional, TLS settings** (Mozilla's "intermediate" profile, as certbot's nginx plugin writes them). Open `/etc/nginx/nginx.conf`:

- delete the `ssl_protocols` and `ssl_prefer_server_ciphers` lines;
- inside the `http {` block, right after the `http {` line, add `include /etc/nginx/zetcert/_tls.conf;`.

After changing nginx's files: `sudo nginx -t`, then `sudo systemctl reload nginx`.

## Daily use

```sh
sudo zetcert status           # certificates, names, expiry, pending changes and problems
sudo zetcert sync --dry-run   # try the changes against Let's Encrypt's staging server
sudo zetcert sync             # apply them: issue, update the snippets, nginx -t, reload
```

**sudo without a password:** run `sudo visudo -f /etc/sudoers.d/zetcert` and add this line with your user name. A file of its own leaves your other sudo rules as they are. It amounts to password-free root for that user, since zetcert can be told to run any command as root.

```
<user> ALL=(root) NOPASSWD: /usr/local/sbin/zetcert
```

A name that fails the pre-checks (its DNS doesn't point here, nginx doesn't serve it the ACME path, or CAA forbids Let's Encrypt) is left out with a warning, and the rest of its certificate is issued. Fix it and run `sync` again.

Names that don't come from nginx, and other options:

```sh
sudo zetcert update shop --exclude old.shop.example.com
sudo zetcert create mail --add mail.example.com --deploy 'systemctl reload postfix dovecot'
```

## Wildcard certificates

A snippet named `wildcard.<domain>.conf` gets a certificate for `<domain>` and `*.<domain>`, validated through a [DNS account](#dns-accounts):

```nginx
server { server_name app.example.net;     include /etc/nginx/zetcert/wildcard.example.net.conf; }
server { server_name api.eu.example.net;  include /etc/nginx/zetcert/wildcard.example.net.conf; }
```

This gives `example.net`, `*.example.net` and `*.eu.example.net`. A new `x.example.net` server block never needs a new certificate.

## DNS accounts

For DNS validation, zetcert creates the `_acme-challenge` TXT records itself, through a DNS account:

```sh
sudo zetcert dns add cf --driver cloudflare   # asks for the API token
sudo zetcert dns add aws --driver route53     # asks for the access key id and secret
sudo zetcert dns test cf app.example.net       # creates and deletes a test record
```

- **Cloudflare:** an API token with **Zone → DNS → Edit**, limited to the zones needed.
- **Route 53:** an access key (or none, to use the instance role) with [this policy](docs/reference.md#route-53-policy).
- **Behind Cloudflare's proxy,** HTTP validation depends on Cloudflare's settings; DNS validation doesn't: `sudo zetcert update <cert> --challenge dns`.

DNS-validated certificates renew through zetcert, so keep it installed.

## Alerts and monitoring

Let's Encrypt no longer sends expiry emails: **without `notify`, nothing tells you when renewals fail.**

`notify` in `/etc/zetcert/config.yml` is a command that gets the alert on stdin: when a certificate isn't renewing or is about to expire, when nginx couldn't be reloaded after a renewal, or when a deploy command failed. For Telegram:

```yaml
notify: curl -sS --fail-with-body --max-time 30 -K /etc/zetcert/telegram.curl --data-urlencode text@-
```

with the token in `/etc/zetcert/telegram.curl` (mode 0600, so it stays out of `ps`):

```
url = "https://api.telegram.org/bot<TOKEN>/sendMessage"
data = "chat_id=<CHAT_ID>"
```

For ntfy: `notify: curl -sS --fail-with-body --max-time 30 -K /etc/zetcert/ntfy.curl --data-binary @-`, with `url = "https://ntfy.sh/<random-topic>"` in that file (topics are public, so pick a random name). By email, if the server can send mail: `notify: mail -s "zetcert alert" you@example.com`. `sudo zetcert notify --test` sends a test alert.

- `sudo zetcert status --check` exits with 0 (healthy), 1 (warning) or 2 (critical), for monitoring.
- `sudo zetcert doctor` checks everything: the install, certbot's timer, nginx, DNS accounts, the certificates and what nginx serves.
- A renewal failed? Fix the cause, then `sudo zetcert sync` renews the certificate.

## Upgrade

```sh
npm install -g zetcert@latest   # with sudo when Node is installed system-wide
sudo zetcert init               # installs the new version
```

`npm update -g` isn't enough: on 0.x it doesn't even cross a minor version. With nvm, if you installed the new version under another Node version, run `zetcert init` without sudo instead.

## Uninstall

```sh
sudo zetcert uninstall     # removes zetcert and its certbot hooks; the config, snippets and certificates stay
npm uninstall -g zetcert   # with sudo when Node is installed system-wide
```

nginx keeps working, and certbot keeps renewing the HTTP-validated certificates and reloading nginx. `uninstall` lists the deploy commands that stop running, and refuses while DNS-validated certificates need zetcert (`--force` goes on; their renewals then fail).

If `sudo zetcert uninstall` says "command not found", `init` never ran: only the npm package is there.

**To remove every trace:**

1. In your nginx config, replace each `include /etc/nginx/zetcert/….conf;` with that file's lines, except the ones pointing into `/etc/nginx/zetcert` or `/var/lib/zetcert` (the `ssl_dhparam` of `_tls.conf`, a placeholder certificate). Keep the ACME `location`: certbot renews through it.
2. `sudo grep -rnE '/etc/nginx/zetcert|/var/lib/zetcert' /etc/nginx --exclude-dir=zetcert` must print nothing.
3. `sudo rm -rf /etc/zetcert /etc/nginx/zetcert /var/lib/zetcert`, then `sudo nginx -t && sudo systemctl reload nginx`.

## Commands

| Command | |
|---|---|
| `status [cert]` | certificates, names, expiry, pending changes and problems; `--check` for monitoring, `--json` |
| `sync [cert…]` | apply nginx changes: issue, update the snippets, `nginx -t`, reload; `--dry-run`, `--no-precheck`, `--strict` |
| `init` | install or upgrade zetcert, create the config, write zetcert's files and hooks |
| `import <name…>`, `import --all` | take over certificates certbot already has |
| `create <cert>` | register a certificate before any nginx include exists |
| `update <cert>` | change a certificate's options (`--add`, `--exclude`, `--challenge`, `--dns`, `--key-type`, `--deploy`) |
| `delete <cert>` | delete a certificate nginx no longer includes |
| `dns add`, `dns list`, `dns test`, `dns remove` | manage DNS accounts |
| `doctor` | full health check |
| `notify --test` | send a test alert |
| `uninstall` | remove zetcert, keep the certificates |

Global options: `-y` (don't ask), `--json`, `-v` (certbot's output and skipped names), `-q`, `--config <path>`, `--no-color`, `--version`.

## License

MIT
