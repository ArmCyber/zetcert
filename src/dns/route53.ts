// Route 53: keys from the account file, or the AWS default chain (environment, instance role)
// when they're left out. Public hosted zones only. Minimum permissions: route53:ListHostedZones and
// route53:GetChange; route53:ListResourceRecordSets and route53:ChangeResourceRecordSets on the
// hosted zones needed.
import {
  type Change,
  ChangeResourceRecordSetsCommand,
  GetChangeCommand,
  ListHostedZonesCommand,
  ListResourceRecordSetsCommand,
  type ResourceRecordSet,
  Route53Client,
} from '@aws-sdk/client-route-53';
import { type DnsDriver, DriverError, type RecordRef, type Zone } from './driver';

export interface Route53Options {
  accessKeyId?: string;
  secretAccessKey?: string;
  /** Tests only: a mock of the API. */
  endpoint?: string;
  pollMs?: number;
  syncTimeoutMs?: number;
}

const fqdn = (name: string) => `${name.toLowerCase().replace(/\.$/, '')}.`;

export class Route53Driver implements DnsDriver {
  private readonly client: Route53Client;
  private readonly pollMs: number;
  private readonly syncTimeoutMs: number;

  constructor(options: Route53Options = {}) {
    // The SDK warns on every run under Node 20; its end of support is tracked in CLAUDE.md.
    process.env.AWS_SDK_JS_NODE_VERSION_SUPPORT_WARNING_DISABLED ??= 'true';
    this.client = new Route53Client({
      region: 'us-east-1',
      maxAttempts: 5,
      // No hanging request while sync holds its lock or certbot waits for the hook.
      requestHandler: { connectionTimeout: 10_000, requestTimeout: 30_000, throwOnRequestTimeout: true },
      ...(options.accessKeyId && options.secretAccessKey
        ? { credentials: { accessKeyId: options.accessKeyId, secretAccessKey: options.secretAccessKey } }
        : {}),
      ...(options.endpoint ? { endpoint: options.endpoint } : {}),
    });
    this.pollMs = options.pollMs ?? 5000;
    this.syncTimeoutMs = options.syncTimeoutMs ?? 180_000;
  }

  private async call<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (err) {
      const e = err as Error;
      throw new DriverError(`Route 53: ${e.name && e.name !== 'Error' ? `${e.name}: ` : ''}${e.message}`);
    }
  }

  async verify(): Promise<void> {
    const command = new ListHostedZonesCommand({ MaxItems: 1 });
    await this.call(() => this.client.send(command));
  }

  async zones(): Promise<Zone[]> {
    const zones: Zone[] = [];
    let marker: string | undefined;
    do {
      const command = new ListHostedZonesCommand({ Marker: marker, MaxItems: 100 });
      const r = await this.call(() => this.client.send(command));
      for (const z of r.HostedZones ?? []) {
        if (z.Config?.PrivateZone || !z.Id || !z.Name) continue;
        zones.push({ id: z.Id.replace(/^\/hostedzone\//, ''), name: z.Name.replace(/\.$/, '').toLowerCase() });
      }
      marker = r.IsTruncated ? r.NextMarker : undefined;
    } while (marker);
    return zones;
  }

  /** The TXT record set at exactly `name`, if there is one. */
  private async recordSet(zone: Zone, name: string): Promise<ResourceRecordSet | undefined> {
    const command = new ListResourceRecordSetsCommand({
      HostedZoneId: zone.id,
      StartRecordName: name,
      StartRecordType: 'TXT',
      MaxItems: 1,
    });
    const r = await this.call(() => this.client.send(command));
    const set = r.ResourceRecordSets?.[0];
    return set && set.Type === 'TXT' && set.Name && fqdn(set.Name) === fqdn(name) ? set : undefined;
  }

  private async change(zone: Zone, change: Change): Promise<string | undefined> {
    const command = new ChangeResourceRecordSetsCommand({
      HostedZoneId: zone.id,
      ChangeBatch: { Comment: 'zetcert', Changes: [change] },
    });
    const r = await this.call(() => this.client.send(command));
    return r.ChangeInfo?.Id;
  }

  private async waitInSync(id: string | undefined): Promise<void> {
    if (!id) return;
    const deadline = Date.now() + this.syncTimeoutMs;
    for (;;) {
      const command = new GetChangeCommand({ Id: id });
      const r = await this.call(() => this.client.send(command));
      if (r.ChangeInfo?.Status === 'INSYNC') return;
      if (Date.now() > deadline) throw new DriverError(`Route 53: change ${id} not in sync after ${this.syncTimeoutMs / 1000}s`);
      await new Promise((resolve) => setTimeout(resolve, this.pollMs));
    }
  }

  async createTxt(zone: Zone, name: string, value: string): Promise<RecordRef> {
    const set = await this.recordSet(zone, name);
    const quoted = `"${value}"`;
    const values = (set?.ResourceRecords ?? []).map((r) => r.Value ?? '');
    if (!values.includes(quoted)) {
      const id = await this.change(zone, {
        Action: 'UPSERT',
        ResourceRecordSet: {
          Name: name,
          Type: 'TXT',
          TTL: set?.TTL ?? 60,
          ResourceRecords: [...values, quoted].map((Value) => ({ Value })),
        },
      });
      await this.waitInSync(id);
    }
    return { name, value };
  }

  async deleteTxt(zone: Zone, ref: RecordRef): Promise<void> {
    const set = await this.recordSet(zone, ref.name);
    const quoted = `"${ref.value}"`;
    const values = (set?.ResourceRecords ?? []).map((r) => r.Value ?? '');
    if (!set || !values.includes(quoted)) return;
    const rest = values.filter((v) => v !== quoted);
    // DELETE needs the exact record set; with other values left, write them back instead.
    await this.change(
      zone,
      rest.length === 0
        ? { Action: 'DELETE', ResourceRecordSet: set }
        : { Action: 'UPSERT', ResourceRecordSet: { ...set, ResourceRecords: rest.map((Value) => ({ Value })) } },
    );
  }
}
