import { createDiffieHellman } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { acmeConfContent, FFDHE2048_PEM, tlsConfContent, tlsFilePlan } from '../../../src/nginx/support';


describe('_tls.conf', () => {
  it('holds certbot\'s values by default, exactly as in the spec', () => {
    expect(tlsConfContent({})).toBe(`# Managed by zetcert — do not edit. Change settings in /etc/zetcert/config.yml (tls).
ssl_session_cache shared:zetcert:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;

ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
ssl_dhparam /etc/nginx/zetcert/_ffdhe2048.pem;
`);
  });

  it('applies overrides and lists them at the top', () => {
    const text = tlsConfContent({ protocols: 'TLSv1.3', session_timeout: '4h', dhparam: '/etc/ssl/dh.pem' });
    expect(text.split('\n').slice(0, 2)).toEqual([
      '# Managed by zetcert — do not edit. Change settings in /etc/zetcert/config.yml (tls).',
      "# From the config: protocols, session_timeout, dhparam. The rest are zetcert's defaults.",
    ]);
    expect(text).toContain('ssl_protocols TLSv1.3;');
    expect(text).toContain('ssl_session_timeout 4h;');
    expect(text).toContain('ssl_dhparam /etc/ssl/dh.pem;');
    expect(tlsConfContent({ dhparam: 'off' })).not.toContain('ssl_dhparam');
  });

  it('with tls: off, stays while nginx includes it and goes once the include is gone', () => {
    expect(tlsFilePlan('off', [])).toEqual({ action: 'remove' });
    expect(tlsFilePlan('off', undefined)).toMatchObject({ action: 'keep' });
    const kept = tlsFilePlan('off', [{ path: '/etc/nginx/zetcert/_tls.conf', file: '/etc/nginx/nginx.conf', line: 30 }]);
    expect(kept).toMatchObject({ action: 'keep', warning: expect.stringContaining('/etc/nginx/nginx.conf:30 still includes') });
    expect(tlsFilePlan({}, [])).toMatchObject({ action: 'write' });
  });
});

describe('_ffdhe2048.pem', () => {
  it('holds the RFC 7919 ffdhe2048 group', () => {
    const der = Buffer.from(FFDHE2048_PEM.replace(/-----[^-]+-----|\s/g, ''), 'base64');
    // SEQUENCE { INTEGER p (257 bytes with the leading zero), INTEGER g }
    const p = der.subarray(8, 8 + 257).subarray(1);
    const g = der.subarray(der.length - 1);
    const rfc7919 =
      'FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF';
    expect(p.toString('hex').toUpperCase()).toBe(rfc7919);
    expect(g[0]).toBe(2);
    expect(() => createDiffieHellman(p, g)).not.toThrow();
  });
});

describe('_acme.conf', () => {
  it('serves the ACME path from the webroot', () => {
    expect(acmeConfContent('/var/www/html')).toContain(`location ^~ /.well-known/acme-challenge/ {
    root /var/www/html;
    default_type text/plain;
    try_files $uri =404;
}`);
  });
});
