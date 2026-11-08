import crypto from 'node:crypto';

export function sha256(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

// Stable form, so {"a":1,"b":2} and {"b":2,"a":1} count as the same call.
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function strings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => strings(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => strings(v, out));
  return out;
}

export class Engine {
  constructor(policy, now = () => Date.now()) {
    this.policy = policy;
    this.now = now;
    this.flagged = new Map();
    this.minute = [];
    this.identical = new Map();
    this.total = 0;
  }

  isListed(name) {
    const p = this.policy;
    if (p.denyTools.includes(name)) return { rule: 'denyTools', reason: `tool "${name}" is on the deny list` };
    if (p.allowTools !== null && !p.allowTools.includes(name)) return { rule: 'allowTools', reason: `tool "${name}" is not on the allow list` };
    return null;
  }

  // Returns null to allow, or {rule, reason}. Only forwarded calls count toward limits.
  checkCall(name, args) {
    const p = this.policy;
    if (typeof name !== 'string') return { rule: 'invalidRequest', reason: 'tools/call without a string tool name' };
    const listed = this.isListed(name);
    if (listed) return listed;

    if (p.onToolListChange === 'block') {
      if (this.flagged.has(name)) return this.flagged.get(name);
      if (p.expectedTools && !Object.hasOwn(p.expectedTools, name)) {
        return { rule: 'unexpectedTool', reason: `tool "${name}" is not in expectedTools` };
      }
    }

    const texts = [canonical(args ?? {}), ...strings(args ?? {})];
    for (const d of p.denyArgPatterns) {
      if ((d.tool === '*' || d.tool === name) && texts.some((t) => d.regex.test(t))) {
        return { rule: 'denyArgPatterns', reason: `arguments match denied pattern ${d.pattern}` };
      }
    }

    const { maxTotalCalls, maxCallsPerMinute, maxIdenticalCalls } = p.limits;
    if (maxTotalCalls && this.total >= maxTotalCalls) {
      return { rule: 'maxTotalCalls', reason: `total call limit of ${maxTotalCalls} reached` };
    }
    const t = this.now();
    this.minute = this.minute.filter((x) => t - x < 60000);
    if (maxCallsPerMinute && this.minute.length >= maxCallsPerMinute) {
      return { rule: 'maxCallsPerMinute', reason: `rate limit of ${maxCallsPerMinute} calls per minute reached` };
    }
    const key = `${name}\n${canonical(args ?? {})}`;
    const seen = this.identical.get(key) ?? 0;
    if (maxIdenticalCalls && seen >= maxIdenticalCalls) {
      return { rule: 'maxIdenticalCalls', reason: `same tool and arguments already called ${seen} times, limit is ${maxIdenticalCalls}` };
    }

    this.total += 1;
    this.minute.push(t);
    this.identical.set(key, seen + 1);
    return null;
  }

  // Returns {tools, decisions}. tools is what the client is allowed to see.
  filterTools(tools) {
    const p = this.policy;
    const kept = [];
    const decisions = [];
    for (const tool of tools) {
      const name = tool?.name;
      if (typeof name !== 'string') {
        decisions.push({ tool: null, decision: 'block', rule: 'invalidRequest', reason: 'tools/list entry without a string name was hidden' });
        continue;
      }
      const listed = this.isListed(name);
      if (listed) {
        decisions.push({ tool: name, decision: 'block', ...listed, reason: `hidden from tools/list: ${listed.reason}` });
        continue;
      }
      let flag = null;
      if (p.expectedTools) {
        const hash = sha256(typeof tool.description === 'string' ? tool.description : '');
        if (!Object.hasOwn(p.expectedTools, name)) {
          flag = { rule: 'unexpectedTool', reason: `tool "${name}" is not in expectedTools` };
        } else if (p.expectedTools[name].toLowerCase() !== hash) {
          flag = { rule: 'toolChanged', reason: `description hash of "${name}" differs from expectedTools (now ${hash})` };
        }
      }
      if (flag && p.onToolListChange === 'block') {
        this.flagged.set(name, flag);
        decisions.push({ tool: name, decision: 'block', rule: flag.rule, reason: `hidden from tools/list: ${flag.reason}` });
        continue;
      }
      this.flagged.delete(name);
      if (flag) decisions.push({ tool: name, decision: 'log', rule: flag.rule, reason: flag.reason });
      kept.push(tool);
    }
    return { tools: kept, decisions };
  }
}
