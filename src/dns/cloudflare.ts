// Cloudflare: the v4 API with an API token. Minimum permission: Zone → DNS → Edit, limited to
// the zones needed.
import { type DnsDriver, DriverError, type RecordRef, type Zone } from './driver';

export const CLOUDFLARE_API = 'https://api.cloudflare.com/client/v4';

interface ApiResponse<T> {
  success: boolean;
  errors?: { code: number; message: string }[];
  result: T;
  result_info?: { page: number; total_pages: number };
}

export class CloudflareDriver implements DnsDriver {
  constructor(
    private readonly token: string,
    private readonly api = CLOUDFLARE_API,
  ) {}

  private async call<T>(method: string, path: string, body?: unknown): Promise<ApiResponse<T>> {
    let response: Response;
    try {
      response = await fetch(`${this.api}${path}`, {
        method,
        headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      throw new DriverError(`Cloudflare API: ${(err as Error).message}`);
    }
    let json: ApiResponse<T>;
    try {
      json = (await response.json()) as ApiResponse<T>;
    } catch {
      throw new DriverError(`Cloudflare API: HTTP ${response.status} without a JSON answer`);
    }
    if (!response.ok || !json.success) {
      const errors = (json.errors ?? []).map((e) => `${e.message} (${e.code})`).join('; ');
      const error = new DriverError(`Cloudflare API: ${errors || `HTTP ${response.status}`}`);
      (error as DriverError & { codes?: number[] }).codes = (json.errors ?? []).map((e) => e.code);
      throw error;
    }
    return json;
  }

  async verify(): Promise<void> {
    await this.call('GET', '/zones?per_page=5');
  }

  async zones(): Promise<Zone[]> {
    const zones: Zone[] = [];
    for (let page = 1; ; page++) {
      // Only active zones are authoritative; a pending or moved one would take the record in vain.
      const r = await this.call<{ id: string; name: string }[]>('GET', `/zones?status=active&per_page=50&page=${page}`);
      zones.push(...r.result.map((z) => ({ id: z.id, name: z.name.toLowerCase() })));
      if (!r.result_info || r.result_info.page >= r.result_info.total_pages) return zones;
    }
  }

  private async find(zone: Zone, name: string, value: string): Promise<string | undefined> {
    const query = new URLSearchParams({ type: 'TXT', name, per_page: '100' });
    const r = await this.call<{ id: string; content: string }[]>('GET', `/zones/${zone.id}/dns_records?${query}`);
    return r.result.find((rec) => rec.content === value || rec.content === `"${value}"`)?.id;
  }

  async createTxt(zone: Zone, name: string, value: string): Promise<RecordRef> {
    try {
      const r = await this.call<{ id: string }>('POST', `/zones/${zone.id}/dns_records`, { type: 'TXT', name, content: value, ttl: 60 });
      return { name, value, id: r.result.id };
    } catch (err) {
      // 81057/81058: the record already exists, e.g. from an earlier try.
      const codes = (err as { codes?: number[] }).codes ?? [];
      if (!codes.includes(81057) && !codes.includes(81058)) throw err;
      const id = await this.find(zone, name, value);
      if (!id) throw err;
      return { name, value, id };
    }
  }

  async deleteTxt(zone: Zone, ref: RecordRef): Promise<void> {
    const id = ref.id ?? (await this.find(zone, ref.name, ref.value));
    if (!id) return;
    try {
      await this.call('DELETE', `/zones/${zone.id}/dns_records/${id}`);
    } catch (err) {
      // 81044: the record is already gone.
      if (!((err as { codes?: number[] }).codes ?? []).includes(81044)) throw err;
    }
  }
}
