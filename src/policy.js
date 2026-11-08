import fs from 'node:fs';

const TOP_KEYS = new Set(['allowTools', 'denyTools', 'denyArgPatterns', 'limits', 'onToolListChange', 'expectedTools']);
const LIMIT_KEYS = new Set(['maxCallsPerMinute', 'maxIdenticalCalls', 'maxTotalCalls']);

function isPlain(v) { return typeof v === 'object' && v !== null && !Array.isArray(v); }
function strings(v) { return Array.isArray(v) && v.every((s) => typeof s === 'string'); }

// Unknown keys are errors: a typo such as "denyTool" must not silently turn a rule off.
export function parsePolicy(text) {
  let raw;
  try { raw = JSON.parse(text); } catch (e) { throw new Error(`not valid JSON: ${e.message}`); }
  if (!isPlain(raw)) throw new Error('policy must be a JSON object');
  for (const k of Object.keys(raw)) if (!TOP_KEYS.has(k)) throw new Error(`unknown policy key "${k}"`);

  const allowTools = raw.allowTools ?? null;
  if (allowTools !== null && !strings(allowTools)) throw new Error('allowTools must be null or an array of strings');

  const denyTools = raw.denyTools ?? [];
  if (!strings(denyTools)) throw new Error('denyTools must be an array of strings');

  const patterns = raw.denyArgPatterns ?? [];
  if (!Array.isArray(patterns)) throw new Error('denyArgPatterns must be an array');
  const denyArgPatterns = patterns.map((p, i) => {
    if (!isPlain(p) || typeof p.tool !== 'string' || typeof p.pattern !== 'string') {
      throw new Error(`denyArgPatterns[${i}] needs string "tool" and "pattern"`);
    }
    for (const k of Object.keys(p)) if (k !== 'tool' && k !== 'pattern') throw new Error(`denyArgPatterns[${i}] has unknown key "${k}"`);
    let regex;
    try { regex = new RegExp(p.pattern, 'i'); } catch (e) { throw new Error(`denyArgPatterns[${i}] bad regex: ${e.message}`); }
    return { tool: p.tool, pattern: p.pattern, regex };
  });

  const limits = raw.limits ?? {};
  if (!isPlain(limits)) throw new Error('limits must be an object');
  for (const [k, v] of Object.entries(limits)) {
    if (!LIMIT_KEYS.has(k)) throw new Error(`unknown limit "${k}"`);
    if (v !== null && (!Number.isInteger(v) || v < 1)) throw new Error(`${k} must be a positive integer or null`);
  }

  const onToolListChange = raw.onToolListChange ?? 'block';
  if (onToolListChange !== 'block' && onToolListChange !== 'log') throw new Error('onToolListChange must be "block" or "log"');

  const expectedTools = raw.expectedTools ?? null;
  if (expectedTools !== null) {
    if (!isPlain(expectedTools)) throw new Error('expectedTools must be an object of name to sha256');
    for (const [k, v] of Object.entries(expectedTools)) {
      if (typeof v !== 'string' || !/^[a-f0-9]{64}$/i.test(v)) throw new Error(`expectedTools["${k}"] is not a sha256 hex string`);
    }
  }

  return { allowTools, denyTools, denyArgPatterns, limits, onToolListChange, expectedTools };
}

export function loadPolicy(file) {
  return parsePolicy(fs.readFileSync(file, 'utf8'));
}
