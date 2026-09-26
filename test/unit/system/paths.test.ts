import { afterEach, describe, expect, it } from 'vitest';
import { CONFIG_FILE, onDisk, resetRoot, setRoot } from '../../../src/system/paths';

describe('onDisk', () => {
  afterEach(resetRoot);

  it('keeps paths as they are by default', () => {
    expect(onDisk(CONFIG_FILE)).toBe('/etc/zetcert/config.yml');
  });

  it('puts paths under the root set by tests', () => {
    setRoot('/tmp/tree');
    expect(onDisk(CONFIG_FILE)).toBe('/tmp/tree/etc/zetcert/config.yml');
  });

  it('refuses relative paths', () => {
    expect(() => onDisk('etc/zetcert')).toThrow('not an absolute path');
  });
});
