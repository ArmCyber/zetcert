import { describe, expect, it } from 'vitest';
import { isWithin, normalizeCertName, normalizeDnsName, parentOf } from '../../../src/certs/names';

describe('normalizeDnsName', () => {
  it('lowercases, drops a trailing dot and converts IDN to punycode', () => {
    expect(normalizeDnsName('WWW.Example.COM.')).toBe('www.example.com');
    expect(normalizeDnsName('bücher.example')).toBe('xn--bcher-kva.example');
    expect(normalizeDnsName('*.Bücher.Example')).toBe('*.xn--bcher-kva.example');
  });

  it('rejects what is not a DNS name', () => {
    for (const bad of ['example.com:8080', 'a_b.example.com', '-a.example', 'a-.example', 'a..com', '*.*.a.example', 'www.a.*', '*a.example', '', '.']) {
      expect(normalizeDnsName(bad), bad).toBeUndefined();
    }
    expect(normalizeDnsName(`${'a'.repeat(64)}.com`)).toBeUndefined();
  });

  it('requires a dot and no IP address for certificate names', () => {
    expect(normalizeCertName('localhost')).toBeUndefined();
    expect(normalizeCertName('10.0.0.1')).toBeUndefined();
    expect(normalizeCertName('a.example')).toBe('a.example');
  });

  it('has helpers for parents and domains', () => {
    expect(parentOf('a.b.example')).toBe('b.example');
    expect(parentOf('*.b.example')).toBe('b.example');
    expect(isWithin('b.example', 'b.example')).toBe(true);
    expect(isWithin('a.b.example', 'b.example')).toBe(true);
    expect(isWithin('ab.example', 'b.example')).toBe(false);
  });
});
