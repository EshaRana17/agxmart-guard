import { StringDecoder } from 'node:string_decoder';
import { Engine } from './engine.js';
import { startServer, killTree } from './spawn.js';

const MAX_LINE = 64 * 1024 * 1024;

export function lineSplitter(onLine, onOverflow) {
  const decoder = new StringDecoder('utf8');
  let buf = '';
  return (chunk) => {
    buf += decoder.write(chunk);
    let at;
    while ((at = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, at).replace(/\r$/, '');
      buf = buf.slice(at + 1);
      if (line.trim()) onLine(line);
    }
    if (buf.length > MAX_LINE) onOverflow();
  };
}

function blockedResult(id, reason) {
  return {
    jsonrpc: '2.0',
    id,
    result: {
      resultType: 'complete',
      content: [{ type: 'text', text: `Blocked by agxmart-guard policy: ${reason}` }],
      isError: true,
    },
  };
}

function rpcError(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

export function runProxy({ policy, log, command }) {
  const engine = new Engine(policy);
  const pendingLists = new Set();
  const [cmd, ...cmdArgs] = command;
  let finishing = false;

  const toClient = (obj) => process.stdout.write(`${JSON.stringify(obj)}\n`);

  function finish(code) {
    if (finishing) return;
    finishing = true;
    process.stdout.write('', () => process.exit(code));
  }

  const child = startServer(cmd, cmdArgs, ['pipe', 'pipe', 'inherit']);

  // If the audit log cannot be written, stop rather than pass traffic unrecorded.
  function record(entry) {
    try {
      log.write(entry);
    } catch (e) {
      process.stderr.write(`agxmart-guard: cannot write log, stopping: ${e.message}\n`);
      killTree(child);
      finish(2);
      throw e;
    }
  }

  record({ event: 'lifecycle', decision: 'log', reason: `started server command ${cmd}`, rule: 'start' });

  child.on('error', (e) => {
    record({ event: 'lifecycle', decision: 'log', reason: `server failed to start: ${e.message}`, rule: 'spawnError' });
    process.stderr.write(`agxmart-guard: could not start server: ${e.message}\n`);
    finish(1);
  });
  child.on('close', (code, signal) => {
    if (finishing) return;
    record({ event: 'lifecycle', decision: 'log', reason: `server exited with ${signal ?? code}`, rule: 'exit' });
    finish(code ?? 1);
  });
  child.stdin.on('error', () => { /* server gone, the close handler reports it */ });

  const toServer = (obj) => {
    if (child.stdin.writable) child.stdin.write(`${JSON.stringify(obj)}\n`);
  };

  function block(id, tool, args, verdict) {
    record({ event: 'tools/call', tool, arguments: args, decision: 'block', reason: verdict.reason, rule: verdict.rule, requestId: id ?? null });
    if (id !== undefined) toClient(blockedResult(id, verdict.reason));
  }

  function handleCall(msg) {
    const name = msg.params?.name;
    const args = msg.params?.arguments;
    let verdict;
    try {
      verdict = engine.checkCall(name, args);
    } catch (e) {
      verdict = { rule: 'internalError', reason: `guard could not evaluate this call: ${e.message}` };
    }
    if (verdict) return block(msg.id, typeof name === 'string' ? name : null, verdict.rule === 'internalError' ? undefined : args, verdict);
    record({ event: 'tools/call', tool: name, arguments: args, decision: 'allow', reason: 'passed all policy rules', requestId: msg.id ?? null });
    return toServer(msg);
  }

  // Client lines are forwarded re-serialized, never raw, so the server parses
  // exactly the message that was evaluated (for example with duplicate keys).
  function onClientLine(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      record({ event: 'protocol', decision: 'block', reason: 'client sent a line that is not valid JSON', rule: 'parseError' });
      return toClient(rpcError(null, -32700, 'Parse error'));
    }
    if (Array.isArray(msg)) {
      record({ event: 'protocol', decision: 'block', reason: 'JSON-RPC batches are not forwarded', rule: 'batch' });
      return toClient(rpcError(null, -32600, 'JSON-RPC batches are not supported by this proxy'));
    }
    if (msg === null || typeof msg !== 'object') {
      record({ event: 'protocol', decision: 'block', reason: 'client sent a non-object message', rule: 'parseError' });
      return toClient(rpcError(null, -32600, 'Invalid Request'));
    }
    if (msg.method === 'tools/call') return handleCall(msg);
    if (msg.method === 'tools/list' && msg.id !== undefined) pendingLists.add(JSON.stringify(msg.id));
    return toServer(msg);
  }

  function onServerLine(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      process.stderr.write('agxmart-guard: dropped a non-JSON line from server stdout\n');
      return undefined;
    }
    if (Array.isArray(msg)) {
      process.stderr.write('agxmart-guard: dropped a batch from server stdout\n');
      return undefined;
    }
    if (msg?.method === 'notifications/tools/list_changed') {
      record({ event: 'tools/list_changed', decision: 'log', reason: 'server announced that its tool list changed', rule: 'listChanged' });
    }
    const key = msg?.id === undefined || msg.method ? null : JSON.stringify(msg.id);
    if (key !== null && pendingLists.delete(key) && Array.isArray(msg.result?.tools)) {
      const before = msg.result.tools.length;
      const { tools, decisions } = engine.filterTools(msg.result.tools);
      for (const d of decisions) record({ event: 'tools/list', requestId: msg.id, ...d });
      record({ event: 'tools/list', decision: 'allow', reason: `returned ${tools.length} of ${before} tools to the client`, requestId: msg.id });
      return toClient({ ...msg, result: { ...msg.result, tools } });
    }
    process.stdout.write(`${line}\n`);
    return undefined;
  }

  const overflow = (side) => () => {
    process.stderr.write(`agxmart-guard: ${side} sent an oversized line, stopping\n`);
    try {
      record({ event: 'protocol', decision: 'block', reason: `${side} sent an oversized line`, rule: 'parseError' });
    } finally {
      killTree(child);
      finish(2);
    }
  };

  child.stdout.on('data', lineSplitter(onServerLine, overflow('server')));
  process.stdin.on('data', lineSplitter(onClientLine, overflow('client')));
  process.stdin.on('end', () => {
    child.stdin.end();
    setTimeout(() => { killTree(child); finish(0); }, 3000).unref();
  });
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => { killTree(child); finish(1); });
  }
}
