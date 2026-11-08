import fs from 'node:fs';

const SECRET_KEY = /pass(word|wd|phrase)?|secret|token|api[-_]?key|auth|credential|private[-_]?key|access[-_]?key|cookie|session|bearer|signature/i;

export function redact(value, key = '') {
  if (key && SECRET_KEY.test(key)) return '[REDACTED]';
  if (Array.isArray(value)) return value.map((v) => redact(v));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      Object.defineProperty(out, k, { value: redact(v, k), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return value;
}

export class DecisionLog {
  constructor(file) {
    this.fd = fs.openSync(file, 'a');
  }

  write(entry) {
    const { tool = null, event, decision, reason, rule = null, requestId = null } = entry;
    const args = entry.arguments === undefined ? null : redact(entry.arguments);
    const row = { timestamp: new Date().toISOString(), event, tool, arguments: args, decision, reason, rule, requestId };
    fs.writeSync(this.fd, `${JSON.stringify(row)}\n`);
  }
}
