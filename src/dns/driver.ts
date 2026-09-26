// DNS drivers: one file per provider. A driver adds and removes single TXT values and never
// replaces a record set: one name holds several values (`_acme-challenge.example.net` is used for
// both example.net and *.example.net).

export interface Zone {
  id: string;
  /** Without a trailing dot, e.g. example.net. */
  name: string;
}

/** Identifies one TXT value; drivers add what they need, e.g. Cloudflare's record id. */
export interface RecordRef {
  name: string;
  value: string;
  id?: string;
}

export interface DnsDriver {
  /** The credentials work. */
  verify(): Promise<void>;
  /** The public zones this account can edit. */
  zones(): Promise<Zone[]>;
  createTxt(zone: Zone, name: string, value: string): Promise<RecordRef>;
  deleteTxt(zone: Zone, ref: RecordRef): Promise<void>;
}

export class DriverError extends Error {}
