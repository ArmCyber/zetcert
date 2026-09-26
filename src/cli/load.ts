// Loads everything the commands look at: the config, the nginx config, what certbot has and the
// state, and builds the certificate model from them.
import { type CertbotCert, type CertbotVersion, certbotVersion, readCertbotCerts } from '../certbot/reader';
import { buildModel, type CertModel } from '../certs/model';
import { planCert, type CertPlan } from '../certs/planner';
import { type LoadedConfig, loadConfig } from '../config/config';
import { type Discovery, discover } from '../nginx/discovery';
import { loadNginxConfig, type NginxConfig } from '../nginx/include';
import { existingSnippets, snippetPath } from '../nginx/snippets';
import { readText } from '../system/fs';
import { loadState, type State } from '../system/state';

export interface Loaded {
  config: LoadedConfig;
  nginx: NginxConfig;
  discovery: Discovery;
  models: CertModel[];
  certbot: Map<string, CertbotCert>;
  certbotVersion?: CertbotVersion;
  state: State;
}

/** Throws a UserError or ParseError when the config or the nginx config can't be read. */
export async function loadAll(configPath: string): Promise<Loaded> {
  const config = loadConfig(configPath);
  const nginx = loadNginxConfig(config.config.nginx.config);
  const discovery = discover(nginx);
  const models = buildModel({ config: config.config, discovery, snippets: existingSnippets() });
  const certbot = new Map(readCertbotCerts().map((c) => [c.name, c]));
  return { config, nginx, discovery, models, certbot, certbotVersion: await certbotVersion(), state: loadState() };
}

export function readSnippet(cert: string): string | undefined {
  return readText(snippetPath(cert));
}

export function planAll(loaded: Loaded, force = false): Map<string, CertPlan> {
  return new Map(
    loaded.models.map((model) => [
      model.cert,
      planCert({
        model,
        actual: loaded.certbot.get(model.cert),
        snippet: readSnippet(model.cert),
        webroot: loaded.config.config.webroot,
        certbotVersion: loaded.certbotVersion,
        force,
      }),
    ]),
  );
}
