// This machine's public addresses: pre-checks combine them with `public_ips` from the config.
import { BlockList, isIP } from 'node:net';
import { networkInterfaces } from 'node:os';

const notPublic = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 3],
] as const) {
  notPublic.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [
  ['::', 127],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001:db8::', 32],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  notPublic.addSubnet(net, prefix, 'ipv6');
}

export function isPublicIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 0) return false;
  return !notPublic.check(ip, family === 4 ? 'ipv4' : 'ipv6');
}

/** Public addresses on this machine's interfaces. */
export function localPublicIps(): string[] {
  const found = new Set<string>();
  for (const addresses of Object.values(networkInterfaces())) {
    for (const a of addresses ?? []) {
      const ip = a.address.split('%')[0] as string;
      if (!a.internal && isPublicIp(ip)) found.add(ip);
    }
  }
  return [...found];
}
