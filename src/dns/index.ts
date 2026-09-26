import type { DnsAccount } from '../config/dns-accounts';
import { ChalltestsrvDriver } from './challtestsrv';
import { CloudflareDriver } from './cloudflare';
import type { DnsDriver } from './driver';
import type { Nameserver } from './propagation';
import { Route53Driver } from './route53';

let fake: ((account: DnsAccount) => DnsDriver) | undefined;

/** Replaces the drivers. Tests only; `undefined` restores the real ones. */
export function setDriverFactory(factory: ((account: DnsAccount) => DnsDriver) | undefined): void {
  fake = factory;
}

export function driverFor(account: DnsAccount): DnsDriver {
  if (fake) return fake(account);
  if (ZETCERT_E2E && account.driver === 'challtestsrv') {
    return new ChalltestsrvDriver(account.url ?? '', account.zones ?? []);
  }
  if (account.driver === 'cloudflare') return new CloudflareDriver(account.token ?? '');
  return new Route53Driver({ accessKeyId: account.access_key_id, secretAccessKey: account.secret_access_key });
}

/**
 * Nameservers to check propagation on instead of the zone's NS records: the test build asks
 * challtestsrv, which doesn't answer NS queries.
 */
export function propagationServers(account: DnsAccount): Nameserver[] | undefined {
  if (ZETCERT_E2E && account.driver === 'challtestsrv' && account.dns) {
    return [{ name: 'challtestsrv', addresses: [account.dns] }];
  }
  return undefined;
}
