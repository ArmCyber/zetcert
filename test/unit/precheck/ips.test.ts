import { describe, expect, it } from 'vitest';
import { isPublicIp } from '../../../src/precheck/ips';

describe('isPublicIp', () => {
  it.each(['1.1.1.1', '8.8.8.8', '2001:4860:4860::8888', '2606:4700::1111'])('%s is public', (ip) => {
    expect(isPublicIp(ip)).toBe(true);
  });
  it.each(['10.0.0.1', '172.20.1.1', '192.168.1.10', '100.64.0.1', '127.0.0.1', '169.254.1.1', '::1', 'fe80::1', 'fd00::1', 'x'])(
    '%s is not',
    (ip) => {
      expect(isPublicIp(ip)).toBe(false);
    },
  );
});
