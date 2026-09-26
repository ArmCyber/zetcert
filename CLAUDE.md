# CLAUDE.md

## Orientation

zetcert is a Linux CLI that manages the Let's Encrypt certificates of one nginx server, on top of certbot. The nginx config decides which certificate a site uses: a server block includes `/etc/nginx/zetcert/<cert>.conf`, and zetcert builds each certificate's names from the server blocks that include its snippet. certbot does the ACME work and the renewals; zetcert decides which certificates exist and which names they hold.

- [docs/reference.md](docs/reference.md) describes every command, setting and file. Keep it in step with the code.
- If a change isn't clearly right, ask the owner. Don't decide alone.

## Structure

```
src/main.ts     entry point, bundled into dist/zetcert.cjs
src/cli/        the commands (program.ts registers them), output, prompts, loading everything (load.ts)
src/config/     config.yml: load, validate, edit with comments kept; DNS account files; name rules
src/nginx/      lexer, parser, include resolver, discovery, snippets, support files, served-certificate check
src/certs/      server_name rules, the certificate model, the planner, health (status --check)
src/certbot/    command builder, runner, reading certbot's certificates and renewal files, output parsing
src/dns/        driver interface, Cloudflare, Route 53, the test-only challtestsrv driver, zone lookup, propagation
src/precheck/   pre-checks: DNS, local HTTP, CAA; public addresses; Cloudflare ranges
src/hooks/      certbot hooks (auth, cleanup, deploy, post) and alerts (notify)
src/system/     test seams (exec, paths), files, lock, state, the system copy, root check
test/unit/      unit tests (vitest), with fakes for certbot and DNS
test/fixtures/  real-world nginx configs
test/e2e/       end-to-end tests in Docker
docs/           reference.md: every command, setting and file
```

Data flow: config + nginx config → discovery (server blocks, snippet includes, names) → model (the names each certificate should hold) → planner (compared with what certbot has) → `status` shows it; `sync` runs the pre-checks, certbot, writes the generated files, `nginx -t`, reloads.

Test seams: every external command goes through `src/system/exec.ts` (`setExec` in tests), and every absolute path through `src/system/paths.ts` (`onDisk`; `setRoot` puts the whole tree in a temporary directory in tests). Other seams for tests: `setIsRoot`, `setLookup` (DNS lookups), `setDriverFactory`, `setPropagationDeps`, `setRootUid`.

## Invariants

- Never edit the user's nginx files. zetcert writes only its own files in `/etc/nginx/zetcert/`.
- `status` is read-only: safe to run on a live server.
- Every external command goes through `src/system/exec.ts`, every absolute path through `src/system/paths.ts`.
- zetcert's config is the only source of certbot's renewal settings: every `certonly` gets the full flag set (`src/certbot/commands.ts`), because certbot rewrites a certificate's renewal settings from the flags of its last issuance.
- The `ZETCERT_SYNC` guard: `sync` runs certbot with `ZETCERT_SYNC=1`, and the directory hooks (`hook deploy`, `hook post`) then do nothing; `sync` reloads nginx itself (before validating when it changed zetcert's files, and at the end) and runs the deploy commands itself.
- Everything root runs is root-owned: the system copy in `/usr/local/lib/zetcert`, the launcher, the hooks. Node is linked only when root owns it and every directory above it; otherwise it is copied.
- User commands have timeouts that kill the whole process group: deploy commands 5 minutes, the notify command 60 seconds, nginx commands 2 minutes. certbot runs hooks without a timeout, so a hanging command would hold certbot's lock and stop all renewals.
- Generated files are written through `FileBatch`, so `sync` can restore them when `nginx -t` fails.
- `hook auth` prints only the record reference on stdout (certbot hands it to `hook cleanup` as `CERTBOT_AUTH_OUTPUT`); every log line goes to stderr.
- DNS drivers add and remove single TXT values and never replace a record set: `_acme-challenge.D` holds the values for both `D` and `*.D`.
- Test-only code (the challtestsrv DNS driver) is behind `ZETCERT_E2E`, which only `scripts/build.js --e2e` sets; esbuild's `minifySyntax` drops it from the published bundle.

## Facts the code relies on

Checked in 2026-09:

- nginx: variables in `ssl_certificate` since 1.15.9 (loaded on every handshake); `ssl_certificate_cache` since 1.27.4; Ubuntu 26.04 ships nginx 1.28.3, Debian 13 nginx 1.26.3.
- Let's Encrypt: 90-day certificates now, 64 days from 2027-02-10, 45 days from 2028-02-16; the `tlsserver` profile gives 45 days and 25 names, `shortlived` about 6 days. OCSP ended 2025-08-06; expiry emails ended 2025-06-04. Rate limits: 50 new certificates per registered domain per 7 days, 5 per identical name set per 7 days, 5 authorization failures per name per hour. Validation comes from several network locations, so don't geo-block port 80 or DNS.
- certbot: latest 5.8.0; ARI since 4.1.0; renews at 1/3 of the lifetime left since 4.0.0 (30 days before); Ubuntu 26.04 and Debian 13 ship 4.0.0; `certbot reconfigure` since 2.3.0; an auth hook is required in non-interactive manual mode.
- Node.js in distro repos: Ubuntu 26.04 22.x, Ubuntu 24.04 18.x, Debian 13 20.x, Debian 12 18.x. The AWS SDK drops Node 20 in January 2027.

Found while building:

- nginx tokenizer (`ngx_conf_read_token`): `#` starts a comment only where a token starts; `}` doesn't end a word; the `{` of `${var}` doesn't open a block; `\" \' \\ \t \r \n` are unescaped, other backslashes kept. `*_by_lua_block` bodies are Lua (lua-nginx-module has its own tokenizer).
- nginx includes: relative paths are relative to the main config's directory; globs are sorted and `*` doesn't match a leading dot; a glob that matches nothing is fine, a missing plain file fails `nginx -t`.
- Let's Encrypt: 100 names per certificate (classic profile); `tlsserver`/`shortlived` allow 25, so zetcert warns above 25.
- certbot renews at 1/3 of the lifetime left (since 4.0) and retries twice a day, so less than 1/4 left means renewal is failing (≈22 days for 90-day certificates).
- Checked on certbot 4.0.0 against Pebble (the Docker lab in `test/e2e`):
  - a key type change with unchanged names renews without `--force-renewal`; unchanged names and settings give "Certificate not yet due for renewal; no action taken." with exit 0;
  - `certbot reconfigure --webroot -w X` updates `webroot_path` and every `webroot_map` entry, and keeps saved values not on its command line (e.g. `renew_hook`), so removing a value needs `certonly --force-renewal`;
  - `certonly` runs the directory post hooks, and the deploy hooks when it renews an existing lineage; the environment (`ZETCERT_SYNC`) reaches them;
  - rejected names come as `Domain:` / `Type:` / `Detail:` lines; a busy certbot says "Another instance of Certbot is already running." (exit 1);
  - `certbot renew` without a terminal first sleeps up to 8 minutes while holding its lock (tests use `--no-random-sleep-on-renew`);
  - account URIs are in `/etc/letsencrypt/accounts/<server>/<id>/regr.json`.
- Let's Encrypt (and Pebble) certificates may have an empty subject: Node's `X509Certificate.subject` is then undefined. Use the DNS names.
- Node ≥ 22 adds `type: 'CAA'` to `dns.resolveCaa` results; Node 20 doesn't.
- certbot's `ssl-dhparams.pem` is the RFC 7919 ffdhe2048 group; only certbot's nginx plugin ships `options-ssl-nginx.conf` (Debian's certbot package doesn't).
- certbot's manual hooks get `CERTBOT_DOMAIN`/`CERTBOT_IDENTIFIER` (the base domain for a wildcard), `CERTBOT_VALIDATION`, and in the cleanup hook `CERTBOT_AUTH_OUTPUT`. certbot ignores the auth hook's exit code and answers the challenge anyway.
- Why not certbot's DNS plugins: the Route 53 plugin has no credentials option (renewals from certbot's timer would use root's default AWS credentials), every plugin is a separate install (the snap also needs `trust-plugin-with-root`), and zetcert's drivers give one credential format, zone detection across accounts and real propagation checks.
- Why a snippet and not a variable in `ssl_certificate`: `set` runs after the TLS handshake; variables make workers read the key on every handshake (it must be root-only); `nginx -t` can't check paths with variables.
- `nginx -s reload` and `systemctl reload nginx` return before nginx has switched over: its old workers can still answer the next handshakes, so the e2e tests wait for the new certificate.
- pebble-challtestsrv: `/set-txt` adds a value, `/clear-txt` clears every value of a name; it doesn't answer NS queries, so the test build checks propagation against challtestsrv itself.
- nginx fails on a glob match that is a directory or a dangling symlink: glob(3) returns every directory entry.
- certbot saves webroot paths with `os.path.abspath` (no trailing slash); the config normalizes them the same way, or the comparison never converges.
- certbot's webroot plugin creates the missing challenge directories with 0755 and removes them afterwards, and leaves existing ones alone; the pre-check does the same, or a strict umask could break certbot's own renewals.
- certbot reports a wildcard's failed authorization under its base identifier: `Domain: x` for `*.x`.
- Cloudflare's zone list includes pending and moved zones unless it asks for `status=active`.
- The AWS SDK prints a Node 20 support warning unless `AWS_SDK_JS_NODE_VERSION_SUPPORT_WARNING_DISABLED=true`; its `requestTimeout` only warns unless `throwOnRequestTimeout` is set.
- certbot 5 (the snap, in CI) reports a failed challenge with `Identifier:` where 4.0 says `Domain:`.
- certbot's renewal files (`/etc/letsencrypt/renewal/<cert>.conf`) are ConfigObj: `[renewalparams]`, `[[webroot_map]]`, comma lists (`a,` is a one-item list). `--deploy-hook` is saved as `renew_hook`, or `deploy_hook` in newer versions.

## Working on the code

- `npm run build`: bundles everything into `dist/zetcert.cjs` (esbuild, Node 20 target, no runtime dependencies).
- `npm test`: unit tests. `npm run lint`, `npm run typecheck`. A task is done when build, lint, typecheck and the tests pass.
- `npm run e2e`: end-to-end tests in Docker (`test/e2e/compose.yml`): Pebble, pebble-challtestsrv and a Debian 13 server with nginx, certbot 4.0, Node 20 and npm from apt. The run builds the test bundle (`node scripts/build.js --e2e`, which sets `ZETCERT_E2E`), packs it, installs it with npm, and runs `test/e2e/1-http`, `2-dns` and `3-commands` in that order (they build on each other). `E2E_KEEP=1` keeps the containers for a look inside (`docker compose -f test/e2e/compose.yml exec server sh`). CI also runs them with `E2E_TARGET=host` against the certbot snap on the runner.
- Libraries are dev dependencies, because they are bundled. `commander` stays on 14.x (15 is ESM-only and needs Node ≥ 22.12), `@types/node` on 20.x so the typecheck rejects newer Node APIs, TypeScript on 6.0 (typescript-eslint doesn't support 7 yet), vitest on 4.x (5 needs Node ≥ 22.12). When updating a bundled library, check its `engines`.
- Never install nginx or certbot on a development machine to try something: use the Docker lab.

### Docs

- The README holds short how-tos: no internals (those go in `docs/reference.md`) and no migration guides.
- Examples in the README, `docs/reference.md` and the code are placeholders: `example.com`/`example.net` names, `203.0.113.x` or `2001:db8::` addresses, generic host and certificate names. Never real domains, hosts, IPs or deployments.

### Releasing

- **The owner releases.** Only the owner publishes to npm and creates or pushes release tags. Never run `npm publish`, `npm version`, `git tag` or push a tag: tell the owner the exact commands instead.
- **The tag matches the npm version:** `v<version>` for the version in `package.json`, e.g. tag `v0.1.0` for version `0.1.0`.
- **A published version is never reused:** a fix after a release is the next patch version (`0.1.0` → `0.1.1`), with its own tag.
- **Steps:**
  1. Set the version in `package.json` and commit it.
  2. The owner runs the manual release check below.
  3. The owner publishes: `npm login`, then `npm publish` (`prepack` builds `dist/`).
  4. The owner tags that commit and pushes the tag: `git tag v<version>`, `git push origin v<version>`.
- **CI never publishes.** It only runs the lint, typecheck, unit and end-to-end jobs; publishing is always the owner's `npm publish`.

Manual release check, on a test server with a public IP, against Let's Encrypt's staging server and real Cloudflare and Route 53 test zones:

- [ ] `npm pack` here; on the server `npm install -g ./zetcert-<version>.tgz` (with `sudo` for Node from apt), then `zetcert init` as a normal user.
- [ ] `sudo zetcert doctor`: no problems.
- [ ] An HTTP name pointing at the server, included in a server block: `sudo zetcert sync --dry-run` passes.
- [ ] `sudo zetcert dns add cf --driver cloudflare` with a token that has only Zone → DNS → Edit: it lists the zones; `sudo zetcert dns test cf <name>` creates, sees and deletes the record.
- [ ] The same with `--driver route53` and the README's policy; and once with no keys on an EC2 instance role if available.
- [ ] A `wildcard.<test zone>` snippet: `sudo zetcert sync --dry-run` passes for each provider.
- [ ] `sudo certbot renew --dry-run --run-deploy-hooks`: the hooks run and nginx reloads.
- [ ] `sudo zetcert notify --test` reaches the phone.
- [ ] `sudo zetcert status --check` exits with 0.

## Commits

- Commit after each finished task.
- The message is one line of at most 10 words, fewer is better, written the way a person would write it.
- Never mention Claude, AI or a session. Add nothing but the message: no `Co-Authored-By` or other trailers.
