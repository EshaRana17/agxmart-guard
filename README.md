# agxmart-guard

agxmart-guard is a stdio MCP proxy that sits between a client and one server, applies a tool policy to the traffic passing through it, and logs every decision as JSONL.

It has no runtime dependencies and needs Node 20 or newer.

## Install

```sh
npx github:EshaRana17/agxmart-guard --policy policy.json --log guard.jsonl -- <server command...>
```

## Usage

Point your MCP client at the guard instead of the server:

```sh
agxmart-guard --policy policy.json --log guard.jsonl -- npx -y some-mcp-server
```

Policy file (every field is optional, and `allowTools` of `null` means no allow list):

```json
{
  "allowTools": ["read_file", "write_file"],
  "denyTools": ["delete_all"],
  "denyArgPatterns": [{ "tool": "*", "pattern": "\\.ssh" }],
  "limits": { "maxCallsPerMinute": 60, "maxIdenticalCalls": 5, "maxTotalCalls": 1000 },
  "onToolListChange": "block",
  "expectedTools": { "read_file": "<sha256 of the description>" }
}
```

- A blocked `tools/call` gets a normal JSON-RPC result with `isError: true` and a reason the client can read. It does not reach the server.
- `tools/list` responses are filtered so denied tools are hidden.
- If a description hash differs from `expectedTools`, or a tool is not listed there, `onToolListChange` decides what happens: `block` hides the tool and refuses calls to it, `log` keeps it and records the change. Omitting it means `block`.
- `maxIdenticalCalls` is the loop breaker: it counts the same tool with the same arguments for the life of the guard process.
- Patterns are case-insensitive and tested against each string value and the whole argument object.
- Only calls that were forwarded count toward limits.
- An invalid policy, including an unknown key, stops the guard before the server starts (exit code 2). If the log cannot be written, the guard stops rather than passing unlogged traffic.
- Arguments under keys that look like secrets (`password`, `token`, `api_key`, `authorization` and similar) are written to the log as `[REDACTED]`.
- It passes `_meta` through unchanged, so both the 2025-era `initialize` flow and stateless MCP 2026-07-28 requests work.

Real output from a test run with a small fake server, with a policy from `agxmart-baseline to-policy` plus a deny rule, an argument pattern and `maxIdenticalCalls` of 2. Blocked responses from the guard:

```json
{"jsonrpc":"2.0","id":5,"result":{"resultType":"complete","content":[{"type":"text","text":"Blocked by agxmart-guard policy: same tool and arguments already called 2 times, limit is 2"}],"isError":true}}
{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","content":[{"type":"text","text":"Blocked by agxmart-guard policy: tool \"delete_all\" is on the deny list"}],"isError":true}}
```

Lines from `guard.jsonl`:

```json
{"timestamp":"2026-11-08T11:25:40.754Z","event":"tools/call","tool":"read_file","arguments":{"path":"notes.txt"},"decision":"allow","reason":"passed all policy rules","rule":null,"requestId":3}
{"timestamp":"2026-11-08T11:25:41.132Z","event":"tools/call","tool":"read_file","arguments":{"path":"/home/me/.ssh/id_rsa","api_key":"[REDACTED]"},"decision":"block","reason":"arguments match denied pattern \\.ssh","rule":"denyArgPatterns","requestId":6}
```

Turn a log into a report with [agxmart-replay](https://github.com/EshaRana17/agxmart-replay).

## Limits

- It works only for traffic going through it. A client or agent that talks to the server another way is not affected.
- It cannot see what a server does internally. An allowed call can still read files, reach the network or do anything else the server's code does.
- It is not a sandbox. The server runs with your normal permissions.
- Deny patterns match text. Encoded, split or paraphrased values will not match, so treat them as one signal.
- Hashes are compared only when a `tools/list` response passes through the guard, and they cover descriptions only, not input schemas.
- Tool results and server-initiated requests are forwarded without inspection.
- Redaction goes by key name. A secret under an ordinary key such as `note` is logged as is.
- JSON-RPC batches are rejected. Client messages are forwarded re-serialized, so integers too large for a JavaScript number lose precision.
- Counters live in memory and reset when the process restarts.
- A retry of a call after an input request counts as an identical call.
- A very slow regular expression in your policy can stall the proxy.
- Only stdio is supported, not Streamable HTTP.

## Tests

```sh
node --test
```

34 tests, all passing on Node 24.14.0 on Windows 10. They start the real proxy process and a fake MCP server from `test/fixtures`.

## License

MIT

Developed by [buildwithesha.web.app](https://buildwithesha.web.app/) for [AGXMart](https://agxmart.com)
