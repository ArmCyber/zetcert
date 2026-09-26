import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { CloudflareDriver } from '../../../src/dns/cloudflare';

interface CfRecord {
  id: string;
  type: string;
  name: string;
  content: string;
}

/** A mock of the Cloudflare v4 API: 3 zones on 2 pages, TXT records per zone. */
const zones = [
  { id: 'z1', name: 'client.example' },
  { id: 'z2', name: 'Example.org' },
  { id: 'z3', name: 'eu.client.example' },
];
let records: Record<string, CfRecord[]> = {};
let nextId = 1;
let duplicateCode = 81058;
let server: http.Server;
let api = '';

function reply(res: http.ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(body));
}

beforeAll(async () => {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString()));
    req.on('end', () => {
      if (req.headers.authorization !== 'Bearer good-token') {
        reply(res, 403, { success: false, errors: [{ code: 9109, message: 'Invalid access token' }], result: null });
        return;
      }
      const url = new URL(req.url ?? '/', 'http://x');
      const parts = url.pathname.split('/').filter(Boolean);
      if (req.method === 'GET' && url.pathname === '/zones') {
        const page = Number(url.searchParams.get('page') ?? 1);
        const perPage = Math.min(Number(url.searchParams.get('per_page') ?? 20), 2);
        const slice = zones.slice((page - 1) * perPage, page * perPage);
        reply(res, 200, { success: true, result: slice, result_info: { page, total_pages: Math.ceil(zones.length / perPage) } });
        return;
      }
      const zone = parts[1] ?? '';
      const list = (records[zone] ??= []);
      if (req.method === 'POST' && parts[2] === 'dns_records') {
        const rec = JSON.parse(body) as CfRecord;
        if (list.some((r) => r.name === rec.name && (r.content === rec.content || r.content === `"${rec.content}"`))) {
          reply(res, 400, { success: false, errors: [{ code: duplicateCode, message: 'An identical record already exists.' }], result: null });
          return;
        }
        const created = { ...rec, id: `r${nextId++}` };
        list.push(created);
        reply(res, 200, { success: true, result: created });
      } else if (req.method === 'GET' && parts[2] === 'dns_records') {
        const name = url.searchParams.get('name');
        reply(res, 200, { success: true, result: list.filter((r) => r.name === name && r.type === 'TXT') });
      } else if (req.method === 'DELETE' && parts[2] === 'dns_records') {
        const i = list.findIndex((r) => r.id === parts[3]);
        if (i < 0) {
          reply(res, 404, { success: false, errors: [{ code: 81044, message: 'Record does not exist.' }], result: null });
          return;
        }
        list.splice(i, 1);
        reply(res, 200, { success: true, result: { id: parts[3] } });
      } else {
        reply(res, 404, { success: false, errors: [{ code: 7003, message: 'No route' }], result: null });
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  api = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => server.close());
beforeEach(() => {
  records = {};
});

describe('Cloudflare driver', () => {
  const driver = () => new CloudflareDriver('good-token', api);
  const zone = { id: 'z1', name: 'client.example' };

  it('verifies the token and lists every zone, across pages', async () => {
    await driver().verify();
    expect(await driver().zones()).toEqual([
      { id: 'z1', name: 'client.example' },
      { id: 'z2', name: 'example.org' },
      { id: 'z3', name: 'eu.client.example' },
    ]);
  });

  it('reports a bad token', async () => {
    await expect(new CloudflareDriver('bad', api).verify()).rejects.toThrow('Cloudflare API: Invalid access token (9109)');
  });

  it('adds and removes single TXT values, keeping the others', async () => {
    const d = driver();
    const a = await d.createTxt(zone, '_acme-challenge.client.example', 'value-a');
    const b = await d.createTxt(zone, '_acme-challenge.client.example', 'value-b');
    expect(records.z1?.map((r) => r.content)).toEqual(['value-a', 'value-b']);
    await d.deleteTxt(zone, a);
    expect(records.z1?.map((r) => r.content)).toEqual(['value-b']);
    // Without an id, it is found by name and value; a second delete is fine.
    await d.deleteTxt(zone, { name: b.name, value: b.value });
    await d.deleteTxt(zone, b);
    expect(records.z1).toEqual([]);
  });

  it('finds a record Cloudflare stored with quotes, also with the 81057 code', async () => {
    duplicateCode = 81057;
    records.z1 = [{ id: 'q1', type: 'TXT', name: '_acme-challenge.client.example', content: '"quoted"' }];
    const ref = await driver().createTxt(zone, '_acme-challenge.client.example', 'quoted');
    expect(ref.id).toBe('q1');
    await driver().deleteTxt(zone, { name: '_acme-challenge.client.example', value: 'quoted' });
    expect(records.z1).toEqual([]);
    duplicateCode = 81058;
  });

  it('accepts a value that already exists', async () => {
    const d = driver();
    const first = await d.createTxt(zone, '_acme-challenge.client.example', 'same');
    const second = await d.createTxt(zone, '_acme-challenge.client.example', 'same');
    expect(second.id).toBe(first.id);
  });
});
