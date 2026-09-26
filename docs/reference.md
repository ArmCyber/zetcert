# zetcert reference

Everything zetcert does, in detail. For an introduction, see the [README](../README.md).

## Commands

Everything runs as root (`sudo zetcert …`), except the first `zetcert init`, which runs itself again with sudo. Before `init` has installed the launcher, other commands started without root say to run `zetcert init` without sudo. `zetcert` without a command is `zetcert status`. Commands other than `init`, `status`, `doctor` and `uninstall` need `init` to have run first.

### Global options

| Option | |
|---|---|
| `-y`, `--yes` | Don't ask: questions are answered yes and prompts take their default. Also applies when stdin is not a terminal. |
| `--json` | Machine-readable output for `status` and `dns list`. |
| `-v`, `--verbose` | Show certbot's output, the `server_name` values skipped silently, and every source of a name. |
| `-q`, `--quiet` | Show only warnings, errors and asked-for results. |
| `--config <path>` | The config file, default `/etc/zetcert/config.yml`. Meant for testing: the certbot hooks always use the default path. |
| `--no-color` | No colours. |
| `-h`, `--help` | Help for zetcert or a command. |
| `--version` | Print the version. |

### `init`

Installs or upgrades the system copy and zetcert's files. Safe to run again.

1. Without root, runs `sudo <node> <bundle> init …` with the same arguments (the real paths of the running Node and bundle). sudo replaces PATH with its `secure_path`, so with Node from nvm, n or volta in a home directory, a plain `sudo zetcert init` finds no zetcert (or no Node); this works however Node was installed.
2. From the system copy, when the npm install recorded in `install.json` has a newer version: copies its bundle over the system copy and runs `init` again from it.
3. Checks that certbot (1.21 or newer), nginx and openssl are installed.
4. Installs the system copy (see [The system copy](#the-system-copy)).
5. Creates `/etc/zetcert/config.yml` if it doesn't exist, asking for the email, the webroot, the public IPs (suggesting the public addresses found on the machine) and an optional notify command; `nginx.config` comes from `nginx -V` (`--conf-path`). With `-y`, the defaults and the found addresses are used.
6. Writes `_tls.conf` (or deletes it, see `tls: off`), `_ffdhe2048.pem` and `_acme.conf`; creates the placeholder certificate if there is none; installs the certbot hooks.
7. When it changed an existing `_tls.conf` or `_acme.conf` (e.g. new defaults after an upgrade): runs `nginx -t` and reloads nginx; if `nginx -t` fails, the previous files are put back.
8. Offers to import the certificates certbot has that zetcert doesn't manage yet.

### `status [cert]`

Lists the certificates: kind, validation, number of names, expiry and state; then, per certificate, its names with where each comes from (file:line of the `server_name`, or `config`), names that aren't included (excluded, covered by a wildcard, outside a wildcard's domain), pending changes, skipped names and problems. Without a certificate name, it starts with a table of all of them.

| Option | |
|---|---|
| `--check` | Also checks the certificate nginx serves for each name, and exits with 0 (healthy), 1 (warning) or 2 (critical). |

States: `ok`, `new`, `pending changes`, `skipped names`, `many names`, `blocked` (the certificate can't be issued as it is, e.g. no names or more than 100), `unused` (no include and not in the config; nothing is planned for it), and the critical ones: `placeholder`, `not renewing`, `expiring`, `wrong certificate served`, `can't check what nginx serves`. Once `init` has run, an outdated `_tls.conf` or `_acme.conf` is listed too.

| `--check` exit code | When |
|---|---|
| 0 | healthy |
| 1 | pending changes (including an outdated `_tls.conf` or `_acme.conf`), names the last sync skipped, more than 25 names, a certificate that can't be issued as it is, errors in the nginx config such as two snippets in one block |
| 2 | renewal failing (less than a quarter of the lifetime left), expiring within 7 days, placeholder in use, nginx serving another certificate, the served-certificate check failing, a missing include file, or the check couldn't run at all (not root, an unknown certificate, a config or nginx config that can't be read) |

Without `--check`: exit 0, or 1 when the nginx config can't be read or has errors. A warning is shown when npm has a newer zetcert than the system copy.

### `sync [cert…]`

Makes certbot and zetcert's files match nginx and the config. See [What sync does](#what-sync-does). With certificate names, only those are issued (placeholder snippets of new includes are still created, because `nginx -t` needs them).

| Option | |
|---|---|
| `--dry-run` | Runs certbot with `--dry-run` (Let's Encrypt's staging server; `reconfigure` becomes `certonly --dry-run`). Nothing is saved or reloaded, except the placeholder snippets of new certificates; the output lists them. |
| `--force` | Re-issues every certificate, even when nothing changed. |
| `--strict` | A name that fails the pre-checks fails its whole certificate instead of being left out; names Let's Encrypt rejects aren't retried without. |
| `--no-reload` | Doesn't reload nginx (the deploy commands still run). |
| `--no-precheck` | Skips the pre-checks. |

Exit codes: 0 done; 2 partly done (a certificate failed, a name was skipped, a certificate without usable names was skipped, certbot kept a certificate it was asked to renew, or a deploy command failed); 1 stopped (an nginx config error, `nginx -t` failing, another sync running, or the question declined).

### `create <cert>` and `update <cert>`

`create` registers a certificate before any nginx include exists: a `certs.<cert>` entry in the config and its snippet (pointing at the placeholder, or at certbot's files if certbot already has a certificate with that name). It refuses a name that already has a config entry or a snippet. `update` changes the options of a certificate zetcert manages. Both edit the config through its YAML document, so comments stay, and the changes take effect at the next `sync`.

| Option | |
|---|---|
| `--add <name>` / `--remove <name>` | Extra names that don't come from nginx (`names`). Repeatable. |
| `--exclude <name>` / `--unexclude <name>` | Ignore a name found in nginx, or one the wildcard rules make (`*.x.D`), or stop ignoring it (`exclude`). Repeatable. |
| `--challenge auto\|http\|dns` | `auto` means DNS if the certificate has a wildcard name, HTTP otherwise. |
| `--dns <account>` | Pin a DNS account. |
| `--key-type ecdsa\|rsa` | The certificate's key type. |
| `--deploy <command>` / `--no-deploy` | Add a command to run after the certificate is renewed (repeatable), or remove them all. |

### `delete <cert>`

Refuses while nginx still includes the certificate, and for a certbot certificate zetcert doesn't manage (use `certbot delete` for that). Otherwise it shows what it will do, asks with No as the default (`-y` skips the question), runs `certbot delete --cert-name <cert>` (showing progress while certbot is busy), and removes the snippet, the config entry and the certificate's state.

| Option | |
|---|---|
| `--force` | Also while nginx includes it: the snippet stays and points at the placeholder (written before certbot deletes its files), so `nginx -t` keeps passing. |
| `--keep-cert` | Keeps the certificate in certbot. |

### `import <name…>` and `import --all`

Takes over certificates certbot already has: writes each snippet pointing at certbot's files, shows how the certificate's names differ from what nginx uses, and moves a deploy hook saved in certbot (`renew_hook`, or `deploy_hook` in newer certbot) into the certificate's `deploy` list. Saved pre- and post-hooks get a warning: zetcert doesn't use them. Nothing is issued: the next `sync` applies zetcert's renewal settings. Exit 2 when some names couldn't be imported.

### `dns add <account> --driver cloudflare|route53`

Asks for the credentials (the token or secret without echo), checks them, lists the zones they can edit, and saves `/etc/zetcert/dns/<account>.yml` (0600). Without a terminal, `--from-stdin` is needed. With `--from-stdin`, the credentials are read from stdin instead: the Cloudflare token on the first line; for Route 53 the access key id and the secret on two lines, or an empty first line for the AWS default chain (environment, instance role). Credentials are never command-line arguments.

- **Cloudflare:** an API token with the permission **Zone → DNS → Edit**, limited to the zones needed.
- **Route 53:** an access key, or none for the AWS default chain, with the policy below.

#### Route 53 policy

Replace `ZONEID` with the hosted zone (one `Resource` per zone, or a list). zetcert can then only change `_acme-challenge` TXT records:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["route53:ListHostedZones", "route53:GetChange"], "Resource": "*" },
    { "Effect": "Allow", "Action": "route53:ListResourceRecordSets", "Resource": "arn:aws:route53:::hostedzone/ZONEID" },
    {
      "Effect": "Allow",
      "Action": "route53:ChangeResourceRecordSets",
      "Resource": "arn:aws:route53:::hostedzone/ZONEID",
      "Condition": {
        "ForAllValues:StringLike": { "route53:ChangeResourceRecordSetsNormalizedRecordNames": ["_acme-challenge.*"] },
        "ForAllValues:StringEquals": { "route53:ChangeResourceRecordSetsRecordTypes": ["TXT"] }
      }
    }
  ]
}
```

### `dns list`

Lists the accounts, their drivers and zones (fetched live; cached zones when an account fails, and `?` as the driver for a file that can't be read, with exit 1). `--json` prints `{ "accounts": [{ "name", "driver", "zones": [...], "error": string | null }] }`.

### `dns test <account> [name]`

Checks the credentials and lists the zones' names. With a name, also creates the TXT record `_acme-challenge.<name>` with a random value in that name's zone, waits until every authoritative nameserver has it, and deletes it.

### `dns remove <account>`

Refuses while a certificate uses the account: pinned with `dns:`, or DNS-validated with names in the account's zones. It also refuses while another account's zones can't be listed, because then it can't tell which account a name belongs to. An account file that can't be read can always be removed.

### `doctor`

A full health check, one line per check: ✓ fine, ! warning, ✗ problem. Exit 1 when there is a problem.

- **The install:** running as root; the system copy's version against the npm copy's (a newer, older or missing npm copy is a warning); `env -i /usr/local/sbin/zetcert --version`; that the launcher, the bundle, Node (and its symlink target), the hook scripts and every directory above them are owned by root and writable only by root.
- **certbot:** installed; `certbot.timer` or `snap.certbot.renew.timer` active; zetcert's hooks installed, unchanged and executable (certbot skips hooks it can't execute); openssl installed.
- **nginx:** `nginx -t`; parse warnings (errors, skipped `server_name`s, missing includes); `ssl_stapling on` anywhere.
- **HTTP validation:** the webroot exists; for every HTTP-validated name, the local ACME check, DNS and CAA (see [Pre-checks](#pre-checks)).
- **DNS accounts:** each account file can be read and its credentials work; each DNS-validated name has an account managing its zone and CAA allows Let's Encrypt with `dns-01`.
- **Certificates:** what `status` flags per certificate: renewal failing, expiring, placeholder in use (failures), pending changes and skipped names (warnings).
- **Certificates nginx serves:** a TLS handshake to each `listen … ssl` address with each name, compared with the certificate file.

### `notify --test`

Sends a test alert through the `notify` command.

### `uninstall`

Removes the system copy (`/usr/local/lib/zetcert`), the launcher and zetcert's certbot hooks, and, in place of zetcert's deploy hook, adds `/etc/letsencrypt/renewal-hooks/deploy/nginx-reload` (a later `init` removes it again), which runs `nginx.test && nginx.reload` (by default `nginx -t && systemctl reload nginx`), so nginx still picks up the certificates certbot keeps renewing. The config, the snippets, `/var/lib/zetcert` and the certificates stay. Refuses while certbot has certificates whose renewal calls zetcert's DNS hooks (`--force` overrides; their renewals will fail). The certificates' `deploy` commands stop running after renewals; uninstall lists them. Asks before acting, with No as the default; `-y` skips the question. Works without a config, with the defaults, e.g. when `init` stopped before writing it. The npm package stays: `npm uninstall -g zetcert`.

### `hook auth|cleanup|deploy|post`

Called by certbot; see [certbot integration](#certbot-integration).

## Config

`/etc/zetcert/config.yml` (0600). Every key is optional; unknown keys are errors, reported with file:line.

| Key | Default | |
|---|---|---|
| `email` | none | Contact for the Let's Encrypt account (`--email`); without it, `--register-unsafely-without-email`. |
| `webroot` | `/var/www/html` | Served on port 80 under `/.well-known/acme-challenge/`. |
| `public_ips` | `[]` | For the DNS pre-check, added to the public addresses found on the machine; needed behind NAT. |
| `key_type` | `ecdsa` | `ecdsa` or `rsa`. |
| `tls` | `{}` | Overrides of `_tls.conf`'s values, or `off`. See [`_tls.conf`](#_tlsconf). |
| `nginx.config` | `/etc/nginx/nginx.conf` | The main nginx config; `init` sets it from `nginx -V`. |
| `nginx.test` | `nginx -t` | |
| `nginx.reload` | `systemctl reload nginx` | |
| `precheck.http_address` | `127.0.0.1:80` | Where the local HTTP pre-check reaches nginx. |
| `dns_propagation_timeout` | `180s` | How long the DNS hook waits for a TXT record; seconds, or `s`/`m`/`h`. |
| `notify` | `""` | A shell command that gets alerts on stdin; empty for none. |
| `certs.<cert>` | | Options of one certificate, only when the defaults aren't enough. |

Per certificate:

| Key | |
|---|---|
| `names` | Extra names that don't come from nginx. |
| `exclude` | Names found in nginx, or made by the wildcard rules, to leave out. A `wildcard.D` certificate can't exclude `D` or `*.D`. An entry that matches nothing gets a warning. |
| `challenge` | `auto` (default), `http` or `dns`. `http` is an error on a certificate with a wildcard name, including every `wildcard.<domain>` certificate. |
| `dns` | The DNS account to use for all its names. |
| `key_type` | Overrides the global `key_type`. |
| `deploy` | Commands to run after the certificate is renewed, e.g. `systemctl reload postfix dovecot`. |

Certificate and DNS account names: `[a-z0-9][a-z0-9.-]*`, at most 64 characters. Names in `names` and `exclude` are lowercased, lose a trailing dot and get IDN converted to punycode, like `server_name`s.

DNS accounts are files in `/etc/zetcert/dns/<account>.yml` (0600): `driver: cloudflare` with `token`, or `driver: route53` with `access_key_id` and `secret_access_key` (both, or neither for the AWS default chain).

## Certificates

A certificate is used by including `/etc/nginx/zetcert/<cert>.conf` in a server block, directly or through nested includes. zetcert manages the certificates included anywhere in nginx, those with a snippet in `/etc/nginx/zetcert/`, and those in the config. Files starting with `_` there are support files, not certificates.

- **Inheritance:** a snippet included in `http {}` applies to every server block with `listen … ssl` (or `quic`) and no `ssl_certificate` of its own.
- **One snippet per server block:** two in one server block (or in `http {}`) is an error with file:line, and `sync` stops.
- **Regular certificate:** the usable `server_name`s of the server blocks that include it, plus `names`, minus `exclude`. A name covered by a wildcard in the same certificate is dropped (`a.foo.example` next to `*.foo.example`). HTTP validation, or DNS when it has a wildcard name or `challenge: dns`.
- **`wildcard.<domain>`:** always `D` and `*.D`. `x.D` is covered; a deeper name `a.x.D` adds `*.x.D` while it is in use; a `*.x.D` `server_name` is kept; a name outside `D` gets a warning and isn't added. Always DNS validation.
- **Limits:** more than 100 names can't be issued; more than 25 gives a warning.
- **Names are ordered** by domain, parents first and `*.x` right after `x`, so the first name — the certificate's subject — is the apex.

How each `server_name` is read:

| Value | Handling |
|---|---|
| `example.com`, `www.example.com` | used: lowercased, trailing dot removed, IDN converted to punycode |
| `*.example.com` | used (a wildcard, so DNS validation) |
| `.example.com` | `example.com` and `*.example.com` |
| `~regex`, `www.example.*` | skipped with a warning and file:line |
| `_`, `""`, `localhost`, IP addresses, names without a dot, names with `$` | skipped silently (listed with `status -v`) |
| anything else that isn't a valid DNS name, e.g. `example.com:8080`, `a_b.example.com` | skipped with a warning and file:line |

## What sync does

1. Takes the lock `/run/zetcert.lock` (a lock left by a sync that is no longer running is taken over) and loads the config.
2. Parses the nginx config from `nginx.config`, following includes. A missing include of `/etc/nginx/zetcert/<cert>.conf` is a new certificate; a missing `_acme.conf` or `_tls.conf` is recreated; any other error (syntax, include cycle, other missing file, two snippets in a block) stops the run.
3. For each new certificate, asks, then writes its snippet: pointing at certbot's files if certbot already has that certificate, otherwise at the placeholder. Also with `--dry-run`.
4. Runs `nginx -t`. If it fails, stops and shows nginx's output: nothing is issued.
5. Builds the wanted names of every certificate. When step 3 wrote files, or `_acme.conf` is outdated (a new `webroot`), and certbot has work: rewrites `_acme.conf`, runs `nginx -t` and reloads nginx, so the pre-checks and Let's Encrypt validate against them. Not with `--dry-run` or `--no-reload`.
6. Pre-checks every name that would be issued. A failing name is left out with a warning (with `--strict`, its certificate fails; a failing `D` or `*.D` always fails a `wildcard.D` certificate, which always contains both). DNS-validated certificates first need an account for every name's zone, or the certificate fails with "no DNS account manages …: run zetcert dns add …" (an account whose zones can't be listed is skipped with a warning, or its cached zones are used). A certificate whose list is then unchanged is left alone; one whose list is empty is skipped with a warning.
7. Compares with what certbot has — names, expiry, staging or production, key type and the saved renewal settings — and shows the plan, one line per certificate (`+ name`, `- name`, `new: …`, `renew: …` for an expired certificate or one certbot hasn't renewed in time, `up to date`), with skipped names, renewal settings to fix, certbot hooks zetcert doesn't know (for a deploy hook, with the `zetcert update <cert> --deploy …` command that keeps it; zetcert runs no pre or post hooks), outdated generated files, the warnings about names (names outside a wildcard's domain, `server_name`s skipped with a warning, more than 25 names), and a warning for a certificate issued 3 or more times in the last 7 days.
8. Asks to go on, unless `-y`.
9. Runs certbot for each changed certificate: `certonly` to issue, `reconfigure` when only its renewal settings differ. When Let's Encrypt rejects some names, retries once without them (not with `--strict`) and records them as skipped; the identifier `x` stands for both `x` and `*.x`. A failed `reconfigure` changes nothing and fails the certificate. When certbot is busy ("Another instance of Certbot is already running"), waits and retries for up to 30 minutes. When certbot keeps a certificate it was asked to renew ("not yet due"), that is reported.
10. Unless `--dry-run`: rewrites the snippets (certbot's files when certbot has the certificate, the placeholder otherwise), `_tls.conf` and `_acme.conf`.
11. Runs `nginx -t`. If it fails, puts the previous files back and doesn't reload. Otherwise reloads nginx (unless `--no-reload` or `--dry-run`). Then runs the `deploy` commands of the certificates that were issued, each stopped after 5 minutes, also when `nginx -t` or the reload failed (the certificates are issued either way); if nginx failed, exits with 1.
12. Saves the state and prints a summary.

When nothing changed, `sync` makes no certbot call and doesn't reload nginx.

## Pre-checks

Free: nothing is sent to Let's Encrypt. Per name, in this order, stopping at the first failure:

- **DNS** (HTTP-validated names): the A/AAAA records exist and every address is one of this server's: `public_ips` plus the public addresses found on the machine. Addresses in Cloudflare's published ranges count as proxied: allowed, with a warning. When no public IPv4 is known, this only warns.
- **nginx** (HTTP-validated names): writes a token file (0644) into `<webroot>/.well-known/acme-challenge/` and requests it at `precheck.http_address` with `Host: <name>`; the request stays on the machine, so this works behind NAT. Like certbot, it creates missing directories (0755, whatever the umask) and removes them afterwards. A redirect fails, with the hint to include `_acme.conf` in that port-80 server; the request is given up after 10 seconds.
- **CAA** (all names): the closest CAA record set, climbing to parent names. For a wildcard, `issuewild` records decide when there are any, otherwise `issue`. One of them must allow `letsencrypt.org`, with a `validationmethods` parameter (if any) including `http-01` or `dns-01`, and an `accounturi` (if any) matching certbot's account for the certificate. An unknown property marked critical fails.

## Files

| Path | Mode | |
|---|---|---|
| `/etc/zetcert/config.yml` | 0600 | settings and per-certificate options |
| `/etc/zetcert/dns/<account>.yml` | 0600 | DNS credentials |
| `/etc/nginx/zetcert/<cert>.conf` | 0644 | a certificate's snippet |
| `/etc/nginx/zetcert/_tls.conf` | 0644 | TLS settings, optionally included once in `http {}` |
| `/etc/nginx/zetcert/_ffdhe2048.pem` | 0644 | DH parameters (the RFC 7919 ffdhe2048 group) |
| `/etc/nginx/zetcert/_acme.conf` | 0644 | ACME `location` for port-80 server blocks |
| `/var/lib/zetcert/state.json` | 0644 | cache: skipped names, issuance history, DNS zones, last alerts; a missing or broken file counts as empty |
| `/var/lib/zetcert/placeholder/` | key 0600 | self-signed placeholder certificate (RSA 2048, CN "zetcert placeholder") |
| `/usr/local/lib/zetcert/` | 0755 | the system copy: `zetcert.cjs`, `node`, `install.json` |
| `/usr/local/sbin/zetcert` | 0755 | the launcher |
| `/etc/letsencrypt/renewal-hooks/deploy/zetcert` | 0755 | runs `zetcert hook deploy` |
| `/etc/letsencrypt/renewal-hooks/post/zetcert` | 0755 | runs `zetcert hook post` |
| `/run/zetcert.lock` | 0644 | held by `sync` (and by `import`, `create`, `update`, `delete`) |

Snippet:

```nginx
# Managed by zetcert — do not edit. Certificate: shop
ssl_certificate     /etc/letsencrypt/live/shop/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/shop/privkey.pem;
```

### `_tls.conf`

certbot's values (Mozilla's "intermediate" profile), with the session cache zone named `zetcert`:

```nginx
# Managed by zetcert — do not edit. Change settings in /etc/zetcert/config.yml (tls).
ssl_session_cache shared:zetcert:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;

ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:…:DHE-RSA-AES256-GCM-SHA384";
ssl_dhparam /etc/nginx/zetcert/_ffdhe2048.pem;
```

Overrides under `tls:` — `protocols`, `ciphers`, `prefer_server_ciphers`, `session_cache`, `session_timeout`, `session_tickets`, `dhparam` (`ffdhe2048`, a file path, or `off`) — replace single values; the second line of the file lists them. With `tls: off`, no `_tls.conf` is written; an existing one stays, with a warning, while nginx still includes it, and is deleted once the include is gone. Changes take effect with `sudo zetcert sync`.

### The system copy

certbot runs zetcert's hooks as root, from a systemd timer, with a minimal PATH, so `init` installs zetcert in a fixed, root-owned place. Everything root runs must be writable only by root: otherwise anything running as another user could change it and get root at the next renewal. It also keeps renewals working when Node versions are switched or removed in nvm.

- `/usr/local/lib/zetcert/zetcert.cjs`: the bundle, copied from the npm install.
- `/usr/local/lib/zetcert/node`: a symlink to the Node binary when root owns it and every directory above it, and only root can write them; otherwise a copy of the binary (e.g. Node from nvm in a home directory). Node from a snap is copied too, because the snap's path changes when it updates.
- `/usr/local/lib/zetcert/install.json`: the version and the path of the npm install's bundle, for upgrades.
- `/usr/local/sbin/zetcert`: sets `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin`, clears `LD_*` variables, and runs the system copy.

## certbot integration

zetcert calls `certbot certonly --non-interactive --agree-tos --cert-name <cert> -d … --key-type <type>` with the validation flags and `--email` (or `--register-unsafely-without-email`) — the full flag set every time, because certbot rewrites a certificate's renewal settings from the flags of its last issuance. It adds `--force-renewal` when the names are unchanged but a new certificate is needed (`sync --force`, a staging certificate, a key type change on certbot before 2.0, or a saved value that must go).

- **HTTP validation:** `--webroot -w <webroot>`.
- **DNS validation:** `--manual --preferred-challenges dns --manual-auth-hook "/usr/local/sbin/zetcert hook auth --cert <cert>" --manual-cleanup-hook "/usr/local/sbin/zetcert hook cleanup --cert <cert>"`. certbot saves these hooks, so its timer calls zetcert on every renewal.
- **Renewal settings:** `sync` compares certbot's saved settings with zetcert's. The validation method, webroot and manual hooks are fixed with `certbot reconfigure` (certbot 2.3 and newer; before, by re-issuing). Values that must go — a hook zetcert doesn't know, an `installer`, manual hooks left from DNS validation — need a new certificate, because `reconfigure` keeps saved values that aren't on its command line. Staging certificates (Let's Encrypt's staging URL or a "(STAGING)" issuer) and key type changes also get a new certificate.
- **`hook deploy`** (after certbot renews a certificate): `nginx.test`, then `nginx.reload`, then the certificate's `deploy` commands, each stopped after 5 minutes. Sends `reload-failed` or `deploy-failed` alerts. When `config.yml` can't be read, it still tests and reloads nginx with the default commands and reports the config error in certbot's log.
- **`hook post`** (after each renewal run): alerts for managed certificates that are failing to renew or about to expire.
- **`hook auth --cert <cert>`:** reads `CERTBOT_IDENTIFIER` (or `CERTBOT_DOMAIN`) and `CERTBOT_VALIDATION`, finds the account (the certificate's pinned one, or the one whose zones contain the name, longest match), creates `_acme-challenge.<identifier>`, prints the record reference on stdout (and nothing else), and waits until every authoritative nameserver has the value. certbot ignores its exit code; the reason of a failure is on stderr.
- **`hook cleanup --cert <cert>`:** deletes the record named in `CERTBOT_AUTH_OUTPUT`, or, when that is empty, the one matching the identifier and value. Failures are only warnings.
- `sync` runs certbot with `ZETCERT_SYNC=1`: the deploy and post hooks then do nothing, because `sync` reloads nginx once and runs the deploy commands itself.

## Alerts

The `notify` command runs as root with `sh -c`, the message on stdin, and is stopped after 60 seconds. Each certificate gets at most one alert per event per day (UTC), with every failure of that event in it; a failed alert is tried again next time.

| Event | When | Sent by |
|---|---|---|
| `renewal-failing` | less than a quarter of the lifetime left (≈22 days for 90-day certificates) | `hook post` |
| `expiring` | less than 7 days left | `hook post` |
| `reload-failed` | after a renewal, `nginx -t` or the reload failed: nginx still serves the old certificate | `hook deploy` |
| `deploy-failed` | one of the certificate's `deploy` commands failed | `hook deploy` |
| `test` | `zetcert notify --test` | you |

Environment: `ZETCERT_EVENT`, `ZETCERT_CERT`, `ZETCERT_EXPIRES` (a date, `2026-11-20`), `ZETCERT_HOST`. The message:

```
[web1] Certificate "shop" is not renewing.
Expires 2026-11-20 (in 21 days). Names: shop.example.com, www.shop.example.com, …
Check: sudo zetcert status shop · certbot log: /var/log/letsencrypt/letsencrypt.log
```

The post hook runs only when certbot tried a renewal in that run: if certbot's timer stops, no alert comes. Monitor `status --check` for that.

## Exit codes

| Code | |
|---|---|
| 0 | done |
| 1 | error, or a question answered no |
| 2 | partly done: `sync` with a failed certificate, skipped names, a skipped certificate, a renewal certbot didn't do, or a failed deploy command; `import` with some names not imported |

- `status --check`: 0 healthy, 1 warning, 2 critical (see [`status`](#status-cert)).
- `doctor`: 0 when no check failed (warnings allowed), 1 otherwise.
- `dns list`: 1 when an account's zones can't be listed or its file can't be read.
- `hook auth`: 1 when the record couldn't be created or didn't show in time; certbot ignores it and answers the challenge anyway.
- `hook cleanup`: always 0; failures are warnings.
- `hook deploy`: 1 when `nginx -t`, the reload or a deploy command failed, or the config can't be read.
- `hook post`: 1 when an alert failed or the config can't be read.

## `status --json`

```json
{
  "initialized": true,
  "certificates": [
    {
      "name": "shop",
      "kind": "regular",
      "validation": "http",
      "keyType": "ecdsa",
      "dnsAccount": null,
      "included": true,
      "inConfig": false,
      "unused": false,
      "names": [{ "name": "shop.example.com", "sources": [{ "type": "nginx", "raw": "shop.example.com", "file": "/etc/nginx/sites-enabled/shop", "line": 18 }] }],
      "dropped": [{ "name": "old.shop.example.com", "reason": "excluded in the config", "sources": [{ "type": "config" }] }],
      "skippedServerNames": [{ "raw": "_", "reason": "catch-all name", "warning": false, "file": "…", "line": 4 }],
      "certificate": { "names": ["shop.example.com"], "notBefore": "…", "notAfter": "…", "issuer": "CN=E7,…", "keyType": "ecdsa", "staging": false },
      "pending": { "action": "none", "reason": null, "add": [], "remove": [], "settings": [], "unknownHooks": [], "snippet": "ok", "blocked": null },
      "problems": [{ "severity": "warning", "code": "pending", "message": "…" }]
    }
  ],
  "problems": [{ "severity": "critical", "message": "…", "file": "…", "line": 3 }],
  "check": 0
}
```

`certificate` is `null` until certbot has one; `check` is there only with `--check`. Name sources are `nginx` (with file and line), `config`, or `wildcard` (`D` and `*.D` of a wildcard certificate). `pending.action` is `issue`, `reconfigure` or `none`; `pending.snippet` is `ok`, `missing`, `placeholder` or `outdated`. Problem codes: `pending`, `blocked`, `skipped`, `too-many-names`, `renewal-failing`, `expiring`, `placeholder`, `unused`, `served` (nginx serves another certificate), `served-unchecked` (the check couldn't be made), and for warnings about names `outside-domain` and `warning`. `pending.reason` is `new`, `names`, `force`, `staging`, `key-type`, `expiry`, `settings` or `unreadable`.
