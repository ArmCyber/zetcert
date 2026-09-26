// Builds X.509 certificates for tests, with any names, dates, key type and issuer.
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';

function length(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag: number, ...content: Buffer[]) => {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), length(body.length), body]);
};
const seq = (...c: Buffer[]) => tlv(0x30, ...c);
const set = (...c: Buffer[]) => tlv(0x31, ...c);
const integer = (b: Buffer) => tlv(0x02, (b[0] as number) & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b);
function oid(dotted: string): Buffer {
  const [a = 0, b = 0, ...rest] = dotted.split('.').map(Number);
  const bytes = [40 * a + b];
  for (const part of rest) {
    const enc = [part & 0x7f];
    for (let v = part >> 7; v > 0; v >>= 7) enc.unshift(0x80 | (v & 0x7f));
    bytes.push(...enc);
  }
  return tlv(0x06, Buffer.from(bytes));
}
function time(d: Date): Buffer {
  const p = (n: number) => String(n).padStart(2, '0');
  const rest = `${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  const year = d.getUTCFullYear();
  return year < 2050 ? tlv(0x17, Buffer.from(String(year).slice(2) + rest)) : tlv(0x18, Buffer.from(`${year}${rest}`));
}
const cn = (name: string) => seq(set(seq(oid('2.5.4.3'), tlv(0x0c, Buffer.from(name)))));

export interface TestCert {
  pem: string;
  key: string;
}

const DAY = 86_400_000;

export function makeCert(options: {
  names: string[];
  notBefore?: Date;
  notAfter?: Date;
  /** Days of validity when notAfter isn't given. */
  days?: number;
  issuer?: string;
  /** The subject CN; '' for an empty subject, as in Let's Encrypt's newer certificates. */
  subject?: string;
  keyType?: 'ecdsa' | 'rsa';
}): TestCert {
  const notBefore = options.notBefore ?? new Date(Date.now() - DAY);
  const notAfter = options.notAfter ?? new Date(notBefore.getTime() + (options.days ?? 90) * DAY);
  const rsa = options.keyType === 'rsa';
  const { publicKey, privateKey } = rsa
    ? generateKeyPairSync('rsa', { modulusLength: 2048 })
    : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const algorithm = rsa ? seq(oid('1.2.840.113549.1.1.11'), tlv(0x05)) : seq(oid('1.2.840.10045.4.3.2'));
  const serial = randomBytes(8);
  // Positive and minimal in DER: the first byte is 0x01–0x7f.
  serial[0] = ((serial[0] as number) & 0x7f) | 0x01;
  const san = seq(...options.names.map((n) => tlv(0x82, Buffer.from(n))));
  const tbs = seq(
    tlv(0xa0, integer(Buffer.from([2]))),
    integer(serial),
    algorithm,
    cn(options.issuer ?? 'Test CA'),
    seq(time(notBefore), time(notAfter)),
    options.subject === '' ? seq() : cn(options.subject ?? options.names[0] ?? 'test'),
    publicKey.export({ type: 'spki', format: 'der' }),
    tlv(0xa3, seq(seq(oid('2.5.29.17'), tlv(0x04, san)))),
  );
  const der = seq(tbs, algorithm, tlv(0x03, Buffer.concat([Buffer.from([0]), sign('sha256', tbs, privateKey)])));
  const body = der.toString('base64').match(/.{1,64}/g)?.join('\n') ?? '';
  return {
    pem: `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`,
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

/** Writes a certbot lineage: live/<cert>/{cert,fullchain,privkey}.pem and renewal/<cert>.conf. */
export function writeCertbotCert(
  write: (path: string, content: string) => void,
  cert: string,
  pem: TestCert,
  renewalParams: string,
): void {
  write(`/etc/letsencrypt/live/${cert}/cert.pem`, pem.pem);
  write(`/etc/letsencrypt/live/${cert}/fullchain.pem`, pem.pem);
  write(`/etc/letsencrypt/live/${cert}/privkey.pem`, pem.key);
  write(
    `/etc/letsencrypt/renewal/${cert}.conf`,
    `# renew_before_expiry = 30 days
version = 4.0.0
archive_dir = /etc/letsencrypt/archive/${cert}
cert = /etc/letsencrypt/live/${cert}/cert.pem
privkey = /etc/letsencrypt/live/${cert}/privkey.pem
chain = /etc/letsencrypt/live/${cert}/chain.pem
fullchain = /etc/letsencrypt/live/${cert}/fullchain.pem

# Options used in the renewal process
[renewalparams]
${renewalParams}
`,
  );
}
