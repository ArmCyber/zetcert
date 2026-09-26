// Test-only driver for the end-to-end tests: TXT records go to pebble-challtestsrv's management
// API. Only in the test build (ZETCERT_E2E), never in the published bundle.
import { type DnsDriver, DriverError, type RecordRef, type Zone } from './driver';

export class ChalltestsrvDriver implements DnsDriver {
  constructor(
    private readonly url: string,
    private readonly zoneNames: string[],
  ) {}

  private async post(path: string, body: unknown): Promise<void> {
    const r = await fetch(`${this.url}${path}`, { method: 'POST', body: JSON.stringify(body), signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new DriverError(`challtestsrv ${path}: HTTP ${r.status}`);
  }

  async verify(): Promise<void> {
    await this.post('/clear-txt', { host: '_zetcert-verify.test.' });
  }

  async zones(): Promise<Zone[]> {
    return this.zoneNames.map((name) => ({ id: name, name }));
  }

  async createTxt(_zone: Zone, name: string, value: string): Promise<RecordRef> {
    await this.post('/set-txt', { host: `${name}.`, value });
    return { name, value };
  }

  /** challtestsrv can only clear every value of a name. */
  async deleteTxt(_zone: Zone, ref: RecordRef): Promise<void> {
    await this.post('/clear-txt', { host: `${ref.name}.` });
  }
}
