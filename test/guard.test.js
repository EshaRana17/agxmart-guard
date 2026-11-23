import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(here, '..', 'bin', 'agxmart-guard.js');
const FAKE = path.join(here, 'fixtures', 'fake-server.fixture');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

function tmpdir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'guard-test-')); }

class Session {
  constructor(policy, env = {}, serverCommand = [process.execPath, FAKE]) {
    this.dir = tmpdir();
    this.policyFile = path.join(this.dir, 'policy.json');
    this.logFile = path.join(this.dir, 'guard.jsonl');
    this.callsFile = path.join(this.dir, 'calls.jsonl');
    fs.writeFileSync(this.policyFile, typeof policy === 'string' ? policy : JSON.stringify(policy));
    this.proc = spawn(process.execPath, [BIN, '--policy', this.policyFile, '--log', this.logFile, '--', ...serverCommand], {
      env: { ...process.env, FAKE_CALLS: this.callsFile, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.buf = '';
    this.msgs = [];
    this.waiters = [];
    this.stderr = '';
    this.proc.stdin.on('error', () => {});
    this.proc.stdout.on('data', (d) => {
      this.buf += d;
      let at;
      while ((at = this.buf.indexOf('\n')) !== -1) {
        const line = this.buf.slice(0, at);
        this.buf = this.buf.slice(at + 1);
        this.msgs.push(JSON.parse(line));
        this.flush();
      }
    });
    this.proc.stderr.on('data', (d) => { this.stderr += d; });
    this.exited = new Promise((res) => this.proc.on('close', (code) => res(code)));
  }

  flush() {
    this.waiters = this.waiters.filter((w) => {
      const i = this.msgs.findIndex(w.match);
      if (i === -1) return true;
      clearTimeout(w.timer);
      w.resolve(this.msgs.splice(i, 1)[0]);
      return false;
    });
  }

  wait(match) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timeout; stderr: ${this.stderr}`)), 8000);
      this.waiters.push({ match, resolve, reject, timer });
      this.flush();
    });
  }

  send(obj) { this.proc.stdin.write(`${typeof obj === 'string' ? obj : JSON.stringify(obj)}\n`); }

  request(id, method, params) {
    this.send({ jsonrpc: '2.0', id, method, params });
    return this.wait((m) => m.id === id);
  }

  call(id, name, args = {}, extra = {}) { return this.request(id, 'tools/call', { name, arguments: args, ...extra }); }

  serverCalls() {
    if (!fs.existsSync(this.callsFile)) return [];
    return fs.readFileSync(this.callsFile, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((m) => m.method === 'tools/call');
  }

  log() { return fs.readFileSync(this.logFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l)); }

  async close() {
    this.proc.stdin.end();
    return this.exited;
  }
}

function isBlocked(res, text) {
  assert.equal(res.result.isError, true);
  assert.equal(res.error, undefined);
  assert.equal(res.result.content[0].type, 'text');
  assert.match(res.result.content[0].text, /Blocked by agxmart-guard/);
  if (text) assert.match(res.result.content[0].text, text);
}

test('legacy handshake and an allowed call pass through to the server', async () => {
  const s = new Session({});
  const init = await s.request(1, 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '1' } });
  assert.equal(init.result.serverInfo.name, 'fake-server');
  s.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  const res = await s.call(2, 'read_file', { path: 'a.txt' });
  assert.equal(res.result.content[0].text, 'ok:read_file');
  assert.equal(s.serverCalls().length, 1);
  assert.equal(await s.close(), 0);
});

test('stateless _meta from the client is passed through unchanged', async () => {
  const s = new Session({});
  const meta = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 'c', version: '1' } };
  const res = await s.call(1, 'read_file', {}, { _meta: meta });
  assert.deepEqual(res.result.echoMeta, meta);
  await s.close();
});

test('denyTools returns a readable result and never reaches the server', async () => {
  const s = new Session({ denyTools: ['delete_all'] });
  isBlocked(await s.call(1, 'delete_all'), /deny list/);
  assert.equal(s.serverCalls().length, 0);
  await s.close();
});

test('allowTools blocks anything not listed', async () => {
  const s = new Session({ allowTools: ['read_file'] });
  assert.equal((await s.call(1, 'read_file')).result.isError, undefined);
  isBlocked(await s.call(2, 'write_file'), /allow list/);
  assert.equal(s.serverCalls().length, 1);
  await s.close();
});

test('empty allowTools blocks every tool', async () => {
  const s = new Session({ allowTools: [] });
  isBlocked(await s.call(1, 'read_file'));
  await s.close();
});

test('denyArgPatterns matches nested strings, scoped by tool', async () => {
  const s = new Session({ denyArgPatterns: [{ tool: 'read_file', pattern: '\\.ssh[\\\\/]' }, { tool: '*', pattern: 'rm -rf' }] });
  isBlocked(await s.call(1, 'read_file', { opts: { paths: ['C:\\Users\\e\\.ssh\\id'] } }));
  assert.equal((await s.call(2, 'write_file', { p: '.ssh/x' })).result.isError, undefined);
  isBlocked(await s.call(3, 'write_file', { cmd: 'RM -RF /' }));
  assert.equal(s.serverCalls().length, 1);
  await s.close();
});

test('maxIdenticalCalls breaks a loop regardless of key order', async () => {
  const s = new Session({ limits: { maxIdenticalCalls: 2 } });
  await s.call(1, 'read_file', { a: 1, b: 2 });
  await s.call(2, 'read_file', { b: 2, a: 1 });
  isBlocked(await s.call(3, 'read_file', { a: 1, b: 2 }), /already called 2 times/);
  assert.equal((await s.call(4, 'read_file', { a: 2 })).result.isError, undefined);
  assert.equal(s.serverCalls().length, 3);
  await s.close();
});

test('maxCallsPerMinute limits the rate', async () => {
  const s = new Session({ limits: { maxCallsPerMinute: 2 } });
  await s.call(1, 'read_file', { n: 1 });
  await s.call(2, 'read_file', { n: 2 });
  isBlocked(await s.call(3, 'read_file', { n: 3 }), /per minute/);
  await s.close();
});

test('maxTotalCalls caps the run', async () => {
  const s = new Session({ limits: { maxTotalCalls: 1 } });
  await s.call(1, 'read_file', { n: 1 });
  isBlocked(await s.call(2, 'read_file', { n: 2 }), /total call limit/);
  await s.close();
});

test('tools/list hides denied tools', async () => {
  const s = new Session({ denyTools: ['delete_all'] });
  const res = await s.request(1, 'tools/list', {});
  assert.deepEqual(res.result.tools.map((t) => t.name), ['read_file', 'write_file']);
  await s.close();
});

const expected = { read_file: sha('Read a file'), write_file: sha('Write a file'), delete_all: sha('Delete everything') };

test('matching expectedTools leaves the list alone', async () => {
  const s = new Session({ expectedTools: expected });
  const res = await s.request(1, 'tools/list', {});
  assert.equal(res.result.tools.length, 3);
  await s.close();
});

test('onToolListChange block hides a tool whose description changed and blocks calls to it', async () => {
  const s = new Session({ onToolListChange: 'block', expectedTools: expected }, { FAKE_RUG: 'second' });
  assert.equal((await s.request(1, 'tools/list', {})).result.tools.length, 3);
  assert.equal((await s.call(2, 'write_file')).result.isError, undefined);
  const res = await s.request(3, 'tools/list', {});
  assert.deepEqual(res.result.tools.map((t) => t.name), ['read_file', 'delete_all']);
  isBlocked(await s.call(4, 'write_file'), /differs from expectedTools/);
  assert.equal(s.serverCalls().length, 1);
  await s.close();
  assert.ok(s.log().some((e) => e.rule === 'toolChanged' && e.event === 'tools/list' && e.decision === 'block'));
});

test('onToolListChange log keeps the tool and records the change', async () => {
  const s = new Session({ onToolListChange: 'log', expectedTools: expected }, { FAKE_RUG: 'always' });
  assert.equal((await s.request(1, 'tools/list', {})).result.tools.length, 3);
  assert.equal((await s.call(2, 'write_file')).result.isError, undefined);
  await s.close();
  assert.ok(s.log().some((e) => e.rule === 'toolChanged' && e.decision === 'log' && e.tool === 'write_file'));
});

test('a tool missing from expectedTools is hidden and blocked in block mode', async () => {
  const s = new Session({ expectedTools: expected }, { FAKE_EXTRA: 'surprise' });
  const res = await s.request(1, 'tools/list', {});
  assert.equal(res.result.tools.find((t) => t.name === 'surprise'), undefined);
  isBlocked(await s.call(2, 'surprise'), /not in expectedTools/);
  await s.close();
});

test('an unlisted tool is blocked even before any tools/list', async () => {
  const s = new Session({ expectedTools: expected });
  isBlocked(await s.call(1, 'never_listed'), /not in expectedTools/);
  await s.close();
});

test('pagination cursors pass through and each page is filtered', async () => {
  const s = new Session({ denyTools: ['delete_all'] }, { FAKE_PAGED: '1' });
  const p1 = await s.request(1, 'tools/list', {});
  assert.equal(p1.result.nextCursor, 'p2');
  const p2 = await s.request(2, 'tools/list', { cursor: 'p2' });
  assert.deepEqual(p2.result.tools.map((t) => t.name), ['write_file']);
  await s.close();
});

for (const [label, text] of [
  ['bad JSON', '{not json'],
  ['unknown key', '{"denyTool":["x"]}'],
  ['bad regex', '{"denyArgPatterns":[{"tool":"*","pattern":"("}]}'],
  ['bad limit', '{"limits":{"maxTotalCalls":-1}}'],
  ['bad onToolListChange', '{"onToolListChange":"ignore"}'],
  ['bad hash', '{"expectedTools":{"a":"abc"}}'],
]) {
  test(`invalid policy fails closed: ${label}`, async () => {
    const s = new Session(text);
    assert.equal(await s.exited, 2);
    assert.match(s.stderr, /invalid policy/);
    assert.equal(fs.existsSync(s.callsFile), false);
  });
}

test('every decision is logged with the required fields and secrets are redacted', async () => {
  const s = new Session({ denyTools: ['delete_all'] });
  await s.call(1, 'read_file', { path: 'a', apiKey: 'sk-AAA', nested: { Authorization: 'Bearer BBB', ok: 1 }, list: [{ password: 'CCC' }] });
  await s.call(2, 'delete_all', { token: 'DDD' });
  await s.close();
  const raw = fs.readFileSync(s.logFile, 'utf8');
  for (const secret of ['sk-AAA', 'BBB', 'CCC', 'DDD']) assert.equal(raw.includes(secret), false);
  const calls = s.log().filter((e) => e.event === 'tools/call');
  assert.equal(calls.length, 2);
  assert.equal(calls[0].decision, 'allow');
  assert.equal(calls[1].decision, 'block');
  assert.equal(calls[1].rule, 'denyTools');
  for (const e of calls) for (const k of ['timestamp', 'tool', 'arguments', 'decision', 'reason']) assert.ok(k in e, k);
  assert.equal(calls[0].arguments.path, 'a');
  assert.equal(calls[0].arguments.nested.ok, 1);
  assert.equal(calls[0].arguments.nested.Authorization, '[REDACTED]');
});

test('a malformed client line gets a parse error and is not forwarded', async () => {
  const s = new Session({});
  s.send('{"method":"tools/call"');
  const res = await s.wait((m) => m.error?.code === -32700);
  assert.equal(res.id, null);
  assert.equal(s.serverCalls().length, 0);
  await s.close();
});

test('a batch cannot smuggle a call past the policy', async () => {
  const s = new Session({ denyTools: ['delete_all'] });
  s.send([{ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'delete_all' } }]);
  const res = await s.wait((m) => m.error?.code === -32600);
  assert.equal(res.id, null);
  assert.equal(s.serverCalls().length, 0);
  await s.close();
});

test('duplicate JSON keys are normalized before forwarding', async () => {
  const s = new Session({ denyTools: ['delete_all'] });
  s.send('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all","name":"read_file"}}');
  await s.wait((m) => m.id === 1);
  const calls = s.serverCalls();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].params.name, 'read_file');
  await s.close();
});

test('a tools/call notification is evaluated too and dropped when blocked', async () => {
  const s = new Session({ denyTools: ['delete_all'] });
  s.send({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'delete_all' } });
  await s.call(1, 'read_file');
  assert.equal(s.serverCalls().length, 1);
  await s.close();
  assert.ok(s.log().some((e) => e.tool === 'delete_all' && e.decision === 'block' && e.requestId === null));
});

test('non-string tool names are blocked', async () => {
  const s = new Session({});
  isBlocked(await s.request(1, 'tools/call', { name: 42 }));
  assert.equal(s.serverCalls().length, 0);
  await s.close();
});

test('non-JSON server stdout is dropped and does not reach the client', async () => {
  const s = new Session({}, { FAKE_BANNER: '1' });
  await s.call(1, 'read_file');
  assert.equal(s.msgs.length, 0);
  assert.match(s.stderr, /dropped a non-JSON line/);
  await s.close();
});

test('proxy exits with the server exit code', async () => {
  const s = new Session({}, { FAKE_EXIT: '7' });
  assert.equal(await s.exited, 7);
  assert.ok(s.log().some((e) => e.rule === 'exit'));
});

test('a server that cannot start is reported', async () => {
  const s = new Session({}, {}, ['agxmart-no-such-binary-xyz']);
  assert.equal(await s.exited, 1);
  assert.match(s.stderr, /could not start server/);
});

test('a log path that cannot be opened fails closed', async () => {
  const dir = tmpdir();
  const policy = path.join(dir, 'p.json');
  fs.writeFileSync(policy, '{}');
  const proc = spawn(process.execPath, [BIN, '--policy', policy, '--log', path.join(dir, 'missing', 'x.jsonl'), '--', process.execPath, FAKE], { stdio: ['ignore', 'pipe', 'pipe'] });
  const code = await new Promise((res) => proc.on('close', res));
  assert.equal(code, 2);
});

test('a missing server command is refused', async () => {
  const dir = tmpdir();
  const policy = path.join(dir, 'p.json');
  fs.writeFileSync(policy, '{}');
  const proc = spawn(process.execPath, [BIN, '--policy', policy, '--log', path.join(dir, 'x.jsonl')], { stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(await new Promise((res) => proc.on('close', res)), 2);
});

test('Windows .cmd servers launch with arguments intact', { skip: process.platform !== 'win32' }, async () => {
  const dir = tmpdir();
  const argsFile = path.join(dir, 'args.json');
  const shim = path.join(dir, 'server.cmd');
  fs.writeFileSync(shim, `@echo off\r\n"${process.execPath}" "${FAKE}" %*\r\n`);
  const tricky = ['a b', 'x&y', 'q"r'];
  const s = new Session({}, { FAKE_ARGS_FILE: argsFile }, [shim, ...tricky]);
  await s.call(1, 'read_file');
  assert.deepEqual(JSON.parse(fs.readFileSync(argsFile, 'utf8')), tricky);
  await s.close();
});
