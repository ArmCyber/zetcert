import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Route53Driver } from '../../../src/dns/route53';

/** A mock of Route 53's REST-XML API. */
interface RecordSet {
  name: string;
  ttl: number;
  values: string[];
}
let sets: Map<string, RecordSet>;
let changes: string[];
let authKeys: string[];
let ttls: number[];
let server: http.Server;
let endpoint = '';
const NS = 'https://route53.amazonaws.com/doc/2013-04-01/';

const zonesXml = (page: number) => {
  const all = [
    ['/hostedzone/Z1', 'client.example.', false],
    ['/hostedzone/Z2', 'internal.client.example.', true],
    ['/hostedzone/Z3', 'Example.org.', false],
  ] as const;
  const slice = page === 1 ? all.slice(0, 2) : all.slice(2);
  return `<?xml version="1.0" encoding="UTF-8"?>
<ListHostedZonesResponse xmlns="${NS}"><HostedZones>${slice
    .map(([id, name, priv]) => `<HostedZone><Id>${id}</Id><Name>${name}</Name><CallerReference>x</CallerReference><Config><PrivateZone>${priv}</PrivateZone></Config><ResourceRecordSetCount>2</ResourceRecordSetCount></HostedZone>`)
    .join('')}</HostedZones><IsTruncated>${page === 1}</IsTruncated>${page === 1 ? '<NextMarker>page2</NextMarker>' : ''}<MaxItems>100</MaxItems></ListHostedZonesResponse>`;
};

beforeAll(async () => {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString()));
    req.on('end', () => {
      authKeys.push(/Credential=([^/]+)\//.exec(req.headers.authorization ?? '')?.[1] ?? '');
      const url = new URL(req.url ?? '/', 'http://x');
      const xml = (text: string) => res.writeHead(200, { 'Content-Type': 'text/xml' }).end(text);
      if (url.pathname === '/2013-04-01/hostedzone') {
        xml(zonesXml(url.searchParams.get('marker') === 'page2' ? 2 : 1));
      } else if (url.pathname.endsWith('/rrset') && req.method === 'GET') {
        const name = url.searchParams.get('name') ?? '';
        const key = name.replace(/\.?$/, '.');
        const set = sets.get(key);
        xml(
          `<ListResourceRecordSetsResponse xmlns="${NS}"><ResourceRecordSets>${
            set
              ? `<ResourceRecordSet><Name>${key}</Name><Type>TXT</Type><TTL>${set.ttl}</TTL><ResourceRecords>${set.values
                  .map((v) => `<ResourceRecord><Value>${v.replace(/"/g, '&quot;')}</Value></ResourceRecord>`)
                  .join('')}</ResourceRecords></ResourceRecordSet>`
              : `<ResourceRecordSet><Name>zzz.client.example.</Name><Type>A</Type><TTL>300</TTL><ResourceRecords><ResourceRecord><Value>198.51.100.4</Value></ResourceRecord></ResourceRecords></ResourceRecordSet>`
          }</ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResponse>`,
        );
      } else if (url.pathname.endsWith('/rrset') && req.method === 'POST') {
        const action = /<Action>(\w+)<\/Action>/.exec(body)?.[1] ?? '';
        const name = (/<Name>([^<]+)<\/Name>/.exec(body)?.[1] ?? '').replace(/\.?$/, '.');
        const ttl = Number(/<TTL>(\d+)<\/TTL>/.exec(body)?.[1] ?? 0);
        const values = [...body.matchAll(/<Value>([^<]*)<\/Value>/g)].map((m) => (m[1] ?? '').replace(/&quot;/g, '"'));
        changes.push(`${action} ${name} ${values.join(' ')}`);
        ttls.push(ttl);
        if (action === 'DELETE') sets.delete(name);
        else sets.set(name, { name, ttl, values });
        xml(`<ChangeResourceRecordSetsResponse xmlns="${NS}"><ChangeInfo><Id>/change/C${changes.length}</Id><Status>PENDING</Status><SubmittedAt>2026-09-26T00:00:00Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>`);
      } else if (url.pathname.startsWith('/2013-04-01/change/')) {
        xml(`<GetChangeResponse xmlns="${NS}"><ChangeInfo><Id>${url.pathname.slice('/2013-04-01'.length)}</Id><Status>INSYNC</Status><SubmittedAt>2026-09-26T00:00:00Z</SubmittedAt></ChangeInfo></GetChangeResponse>`);
      } else {
        res.writeHead(404).end();
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => server.close());
beforeEach(() => {
  sets = new Map();
  changes = [];
  authKeys = [];
  ttls = [];
});

describe('Route 53 record sets', () => {
  it('keeps the TTL and other values, and deletes the exact set it read', async () => {
    const d = new Route53Driver({ accessKeyId: 'AKIDTEST', secretAccessKey: 'secret', endpoint, pollMs: 1 });
    const zone = { id: 'Z1', name: 'client.example' };
    sets.set('_acme-challenge.client.example.', { name: '_acme-challenge.client.example.', ttl: 300, values: ['"someone-else"'] });
    await d.createTxt(zone, '_acme-challenge.client.example', 'mine');
    expect(changes).toEqual(['UPSERT _acme-challenge.client.example. "someone-else" "mine"']);
    await d.deleteTxt(zone, { name: '_acme-challenge.client.example', value: 'mine' });
    await d.deleteTxt(zone, { name: '_acme-challenge.client.example', value: 'someone-else' });
    expect(changes.slice(1)).toEqual(['UPSERT _acme-challenge.client.example. "someone-else"', 'DELETE _acme-challenge.client.example. "someone-else"']);
    expect(ttls).toEqual([300, 300, 300]);
  });
});

describe('Route 53 driver', () => {
  const driver = () => new Route53Driver({ accessKeyId: 'AKIDTEST', secretAccessKey: 'secret', endpoint, pollMs: 1 });
  const zone = { id: 'Z1', name: 'client.example' };

  it('lists public hosted zones across pages, signed with the account keys', async () => {
    await driver().verify();
    expect(await driver().zones()).toEqual([
      { id: 'Z1', name: 'client.example' },
      { id: 'Z3', name: 'example.org' },
    ]);
    expect(authKeys.every((k) => k === 'AKIDTEST')).toBe(true);
  });

  it('uses the AWS default chain without keys', async () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIDFROMENV';
    process.env.AWS_SECRET_ACCESS_KEY = 'secret';
    try {
      await new Route53Driver({ endpoint }).verify();
      expect(authKeys).toEqual(['AKIDFROMENV']);
    } finally {
      delete process.env.AWS_ACCESS_KEY_ID;
      delete process.env.AWS_SECRET_ACCESS_KEY;
    }
  });

  it('adds and removes single values of a record set', async () => {
    const d = driver();
    const a = await d.createTxt(zone, '_acme-challenge.client.example', 'value-a');
    await d.createTxt(zone, '_acme-challenge.client.example', 'value-b');
    await d.createTxt(zone, '_acme-challenge.client.example', 'value-b');
    expect(sets.get('_acme-challenge.client.example.')?.values).toEqual(['"value-a"', '"value-b"']);
    await d.deleteTxt(zone, a);
    expect(sets.get('_acme-challenge.client.example.')?.values).toEqual(['"value-b"']);
    await d.deleteTxt(zone, { name: '_acme-challenge.client.example', value: 'value-b' });
    await d.deleteTxt(zone, { name: '_acme-challenge.client.example', value: 'value-b' });
    expect(changes).toEqual([
      'UPSERT _acme-challenge.client.example. "value-a"',
      'UPSERT _acme-challenge.client.example. "value-a" "value-b"',
      'UPSERT _acme-challenge.client.example. "value-b"',
      'DELETE _acme-challenge.client.example. "value-b"',
    ]);
  });
});
