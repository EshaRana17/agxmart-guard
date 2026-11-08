import { loadPolicy } from './policy.js';
import { DecisionLog } from './log.js';
import { runProxy } from './proxy.js';

const USAGE = 'usage: agenticmart-guard --policy policy.json --log guard.jsonl -- <server command...>\n';

function refuse(message) {
  process.stderr.write(`agenticmart-guard: ${message}\nNo server was started.\n`);
  process.exit(2);
}

export function main(argv) {
  const sep = argv.indexOf('--');
  const flags = sep === -1 ? argv : argv.slice(0, sep);
  const command = sep === -1 ? [] : argv.slice(sep + 1);
  if (flags.includes('--help') || flags.includes('-h')) {
    process.stdout.write(USAGE);
    return;
  }
  let policyPath;
  let logPath;
  for (let i = 0; i < flags.length; i += 1) {
    if (flags[i] === '--policy') policyPath = flags[(i += 1)];
    else if (flags[i] === '--log') logPath = flags[(i += 1)];
    else refuse(`unknown argument ${flags[i]}\n${USAGE}`);
  }
  if (!policyPath || !logPath || command.length === 0) refuse(`--policy, --log and a server command are required\n${USAGE}`);

  let policy;
  try {
    policy = loadPolicy(policyPath);
  } catch (e) {
    refuse(`invalid policy file ${policyPath}: ${e.message}`);
  }
  let log;
  try {
    log = new DecisionLog(logPath);
  } catch (e) {
    refuse(`cannot open log file ${logPath}: ${e.message}`);
  }
  runProxy({ policy, log, command });
}
