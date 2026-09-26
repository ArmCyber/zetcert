import { describe, expect, it } from 'vitest';
import { terminalPrompter } from '../../../src/cli/prompt';

describe('terminal prompter', () => {
  it('asks nothing with -y or without a terminal: yes, the default, and no secrets', async () => {
    for (const prompter of [terminalPrompter(true), terminalPrompter(false)]) {
      // stdin is not a terminal under the test runner.
      expect(prompter.interactive).toBe(false);
      expect(await prompter.confirm('Go on?')).toBe(true);
      expect(await prompter.confirm('Delete?', true)).toBe(true);
      expect(await prompter.ask('Webroot:', '/var/www/html')).toBe('/var/www/html');
      await expect(prompter.secret('Token:')).rejects.toThrow('pass them on stdin with --from-stdin');
    }
  });
});
