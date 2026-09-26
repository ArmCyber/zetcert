import { run } from './cli/program';

void run(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
});
