import { existsSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { Command, CommanderError } from 'commander';
import { UserError } from '../system/errors';
import { CONFIG_FILE, LAUNCHER, onDisk } from '../system/paths';
import { isRoot } from '../system/root';
import { VERSION } from '../version';
import { deployHook } from '../hooks/deploy';
import { authHook, cleanupHook } from '../hooks/dns';
import { dnsAdd, type DnsAddOptions, dnsList, dnsRemove, dnsTest } from './dns';
import { type CertOptions, create, deleteCert, type DeleteOptions, update } from './certs';
import { doctor } from './doctor';
import { notify } from './notify';
import { uninstall } from './uninstall';
import { postHook } from '../hooks/post';
import { importCerts, type ImportOptions } from './import';
import { init, type InitEnv } from './init';
import { sync, type SyncOptions } from './sync';
import { Output, type Writer } from './output';
import { type Prompter, terminalPrompter } from './prompt';
import { status, type StatusOptions } from './status';

export interface GlobalOptions {
  yes: boolean;
  json: boolean;
  verbose: boolean;
  quiet: boolean;
  config: string;
  color: boolean;
}

export interface Context {
  opts: GlobalOptions;
  out: Output;
  prompt: Prompter;
  /** The config file: `--config`, except for the certbot hooks, which always use the default path. */
  configPath: string;
  /** Whether the config file exists, which means `init` has run. */
  initialized: boolean;
  /** All of stdin, e.g. credentials with --from-stdin. */
  readStdin(): Promise<string>;
}

async function readAll(stream: NodeJS.ReadableStream): Promise<string> {
  let text = '';
  for await (const chunk of stream) text += chunk.toString();
  return text;
}

export interface Io {
  stdout?: Writer;
  stderr?: Writer;
  prompter?: Prompter;
  /** Tests only: the running bundle and Node for init. */
  initEnv?: InitEnv;
  /** Tests only: what stdin holds. */
  stdin?: string;
}

/** Commands that work before `init` has run. */
const WITHOUT_INIT = new Set(['init', 'status', 'doctor', 'uninstall']);
/** Commands called by certbot, which always use the default config path. */
const HOOKS = new Set(['hook']);

type Handler = (ctx: Context, ...args: unknown[]) => Promise<number | void>;

const collect = (value: string, previous: string[] = []) => [...previous, value];

/** The top-level command a subcommand belongs to, e.g. `dns` for `dns add`. */
function topLevel(cmd: Command): Command {
  let current = cmd;
  while (current.parent?.parent) current = current.parent;
  return current;
}

function makeContext(cmd: Command, io: Io): Context {
  const opts = cmd.optsWithGlobals() as GlobalOptions;
  const out = new Output({
    stdout: io.stdout,
    stderr: io.stderr,
    color: opts.color,
    quiet: opts.quiet,
    verbose: opts.verbose,
  });
  const configPath = HOOKS.has(topLevel(cmd).name()) ? CONFIG_FILE : path.resolve(opts.config);
  return {
    opts,
    out,
    prompt: io.prompter ?? terminalPrompter(opts.yes === true),
    configPath,
    initialized: existsSync(onDisk(configPath)),
    readStdin: () => (io.stdin !== undefined ? Promise.resolve(io.stdin) : readAll(process.stdin)),
  };
}

export function buildProgram(io: Io, setExitCode: (code: number) => void): Command {
  const program = new Command('zetcert')
    .description("Manages the Let's Encrypt certificates of an nginx server, on top of certbot.")
    .version(VERSION, '--version', 'print the version')
    .helpOption('-h, --help', 'show help')
    .option('-y, --yes', "don't ask (also when stdin is not a terminal)")
    .option('--json', 'machine-readable output for status and dns list')
    .option('-v, --verbose', "show certbot's output and skipped names")
    .option('-q, --quiet', 'show only warnings and errors')
    .option('--config <path>', 'config file, for testing (the certbot hooks always use the default)', CONFIG_FILE)
    .option('--no-color', 'no colours')
    .exitOverride()
    .configureOutput({
      writeOut: (text) => (io.stdout ?? process.stdout).write(text),
      writeErr: (text) => (io.stderr ?? process.stderr).write(text),
    });

  program.hook('preAction', (_program, actionCommand) => {
    const name = topLevel(actionCommand).name();
    // The first `init` may start without sudo: it re-runs itself as root.
    if (name !== 'init' && !isRoot()) {
      // For monitoring, a check that can't run is critical.
      const checking = name === 'status' && actionCommand.opts().check === true;
      // Before init there's no launcher, and with Node from nvm sudo wouldn't find zetcert at all.
      const message = existsSync(onDisk(LAUNCHER))
        ? 'zetcert must run as root: sudo zetcert …'
        : "zetcert isn't set up yet: run zetcert init as your normal user, without sudo (it asks for sudo itself)";
      throw new UserError(message, checking ? 2 : 1);
    }
    if (!WITHOUT_INIT.has(name) && !makeContext(actionCommand, io).initialized) {
      throw new UserError('run zetcert init first');
    }
  });

  const action =
    (handler: Handler) =>
    async (...args: unknown[]): Promise<void> => {
      const cmd = args[args.length - 1] as Command;
      const code = await handler(makeContext(cmd, io), ...args.slice(0, -1));
      setExitCode(code ?? 0);
    };

  program
    .command('init')
    .description("install or upgrade the system copy, create the config and zetcert's files")
    .action(
      action((ctx) =>
        init(
          ctx,
          io.initEnv ?? {
            bundle: realpathSync(process.argv[1] as string),
            node: realpathSync(process.execPath),
            argv: process.argv.slice(2),
          },
        ),
      ),
    );

  program
    .command('status [cert]', { isDefault: true })
    .description('list certificates, their names, expiry, pending changes and problems')
    .option('--check', 'exit code for monitoring: 0 healthy, 1 warning, 2 critical')
    .action(action((ctx, cert, options) => status(ctx, cert as string | undefined, options as StatusOptions)));

  program
    .command('sync [certs...]')
    .description('issue what nginx needs, update the snippets, run nginx -t and reload nginx')
    .option('--dry-run', "test against Let's Encrypt's staging server; nothing is saved but new snippets")
    .option('--force', 're-issue even when nothing changed')
    .option('--strict', 'a name that fails the pre-checks fails its whole certificate')
    .option('--no-reload', "don't reload nginx")
    .option('--no-precheck', 'skip the pre-checks')
    .action(action((ctx, certs, options) => sync(ctx, certs as string[], options as SyncOptions)));

  const certOptions = (cmd: Command) =>
    cmd
      .option('--add <name>', "an extra name that doesn't come from nginx (repeatable)", collect)
      .option('--remove <name>', 'remove an extra name (repeatable)', collect)
      .option('--exclude <name>', 'ignore a name found in nginx (repeatable)', collect)
      .option('--unexclude <name>', 'stop ignoring a name (repeatable)', collect)
      .option('--challenge <challenge>', 'auto (DNS if there is a wildcard, else HTTP), http or dns')
      .option('--dns <account>', 'pin a DNS account')
      .option('--key-type <type>', 'ecdsa or rsa')
      .option('--deploy <command>', 'a command to run after the certificate is renewed (repeatable)', collect)
      .option('--no-deploy', 'remove the deploy commands');
  certOptions(program.command('create <cert>').description('register a certificate before any nginx include exists')).action(
    action((ctx, cert, options) => create(ctx, cert as string, options as CertOptions)),
  );
  certOptions(program.command('update <cert>').description("change a certificate's options")).action(
    action((ctx, cert, options) => update(ctx, cert as string, options as CertOptions)),
  );

  program
    .command('delete <cert>')
    .description('delete a certificate nginx no longer includes (certbot delete, snippet and config entry)')
    .option('--force', 'also while nginx includes it: the snippet then points at the placeholder')
    .option('--keep-cert', 'keep the certificate in certbot')
    .action(action((ctx, cert, options) => deleteCert(ctx, cert as string, options as DeleteOptions)));

  program
    .command('import [names...]')
    .description('take over certificates certbot already has')
    .option('--all', "import all of certbot's certificates")
    .action(action((ctx, names, options) => importCerts(ctx, names as string[], options as ImportOptions)));

  const dns = program.command('dns').description('DNS accounts for DNS validation');
  dns
    .command('add <account>')
    .description('add a DNS account; the credentials are asked for, or read with --from-stdin')
    .requiredOption('--driver <driver>', 'cloudflare or route53')
    .option('--from-stdin', 'read the credentials from stdin: the token, or the access key id and secret on two lines')
    .action(action((ctx, account, options) => dnsAdd(ctx, account as string, options as DnsAddOptions)));
  dns
    .command('list')
    .description('list the accounts, their drivers and zones')
    .action(action((ctx) => dnsList(ctx)));
  dns
    .command('test <account> [name]')
    .description("check the credentials; with a name, also create and delete a test TXT record in its zone")
    .action(action((ctx, account, name) => dnsTest(ctx, account as string, name as string | undefined)));
  dns
    .command('remove <account>')
    .description('remove an account no certificate uses')
    .action(action((ctx, account) => dnsRemove(ctx, account as string)));

  program
    .command('doctor')
    .description('full health check: the install, certbot, nginx, HTTP and DNS validation, served certificates')
    .action(action((ctx) => doctor(ctx)));

  program
    .command('notify')
    .description('send a test alert through the notify command')
    .option('--test', 'send a test alert')
    .action(action((ctx, options) => notify(ctx, options as { test?: boolean })));

  program
    .command('uninstall')
    .description('remove the system copy, the launcher and the certbot hooks; keep the config, snippets and certificates')
    .option('--force', 'also while DNS-validated certificates exist (their renewals need zetcert)')
    .action(action((ctx, options) => uninstall(ctx, options as { force?: boolean })));

  const hook = program.command('hook').description('internal: called by certbot');
  hook
    .command('auth')
    .description('certbot manual auth hook: create the DNS TXT record and wait until it is visible')
    .requiredOption('--cert <cert>', 'the certificate')
    .action(action((ctx, options) => authHook(ctx, (options as { cert: string }).cert)));
  hook
    .command('cleanup')
    .description('certbot manual cleanup hook: delete the DNS TXT record')
    .requiredOption('--cert <cert>', 'the certificate')
    .action(action((ctx, options) => cleanupHook(ctx, (options as { cert: string }).cert)));
  hook
    .command('deploy')
    .description('after certbot renews a certificate: nginx -t, reload, deploy commands')
    .action(action((ctx) => deployHook(ctx)));
  hook
    .command('post')
    .description('after each certbot renewal run: check the certificates and alert')
    .action(action((ctx) => postHook(ctx)));

  return program;
}

/** Runs the CLI with the arguments after `zetcert` and returns the exit code. */
export async function run(argv: string[], io: Io = {}): Promise<number> {
  let exitCode = 0;
  const program = buildProgram(io, (code) => {
    exitCode = code;
  });
  try {
    await program.parseAsync(argv, { from: 'user' });
    return exitCode;
  } catch (err) {
    // Help and --version end with exit code 0; commander has already printed its own errors.
    if (err instanceof CommanderError) return err.exitCode === 0 ? 0 : 1;
    const out = new Output({ stdout: io.stdout, stderr: io.stderr, color: !argv.includes('--no-color') });
    const verbose = argv.includes('-v') || argv.includes('--verbose');
    if (err instanceof UserError) {
      out.error(err.message);
      return err.exitCode;
    }
    out.error(err instanceof Error ? (verbose ? (err.stack ?? err.message) : err.message) : String(err));
    return 1;
  }
}
