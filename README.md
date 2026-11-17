# Bull Family — MCP client signs server-substituted API requests (PoC)

**Finding:** the local Bull MCP wrapper (`bull-mcp.mjs`, function `bull()`) verifies
the *shape* of a signature request from the remote MCP server — 4-line format,
fresh timestamp, own address, 64-hex body hash, and the method+path *pattern*
against `SIGN_OK` — but never verifies that the **body hash** or the **dynamic
path segments** (quoteId / rfqId) match the tool call the agent actually made.
A compromised or malicious MCP server can therefore get the agent to sign an
API request for a different quote / RFQ / body than the agent intended.

**Affected file:** `bull-mcp.mjs` as served at
https://www.bull.family/mcp/bull-mcp.mjs (vendored here as
`bull-mcp-live2.mjs`, sha256
`27d999bfc5e922232a30da18d1bedecd5f0202899a7a9dbc4a43ec209be292db`,
fetched 17 Nov 2026). The gap is in `bull()` (the `signature_required` branch):
it checks `SIGN_OK[name]` against the method and the path *regex*
(e.g. `/^\/api\/v1\/quotes\/[\w-]+\/accept$/` matches ANY quoteId) and checks
that line 4 looks like a hash — it never recomputes the hash from the intended
body and never compares the quoteId in the path with `args.quoteId`.

**Impact:** the signed message authorizes one Bull API request
(`Bull API\nMETHOD /path\ntimestamp\n<body hash>`). The server can substitute
the quote being accepted, the RFQ being quoted, or the body of any signed call
(`bull_accept_quote`, `bull_send_quote`, `bull_counter_quote`,
`bull_revise_quote`, `bull_reject_quote`, `bull_create_rfq`, …). The signature
itself moves no funds — the fund-moving steps re-verify on-chain data — but the
agent ends up committed to API actions it never chose (wrong quote accepted,
mispriced quote sent, good quote rejected). Combined with the separate
`bull_open_deal` sell-side gap (it verifies only buyer/feeBps/payAmount from
the chain, not sellToken/sellAmount), a substituted accept can lead the agent
to fund the wrong deal.

## Reproduce (no real funds, no live server, throwaway key)

```bash
npm i viem
node drive.mjs
```

`drive.mjs` generates a throwaway agent key, starts `mock-server.mjs` (a
malicious MCP server on localhost:8099), runs the real vendored
`bull-mcp-live2.mjs` against it (`BULL_URL=http://localhost:8099`), and asks
it to accept quote `QUOTE-INTENDED-BY-AGENT`. The mock server answers with a
`signature_required` for a **different** quote (`QUOTE-ATTACKER-999`) and an
attacker-chosen body hash (`ab…ab`).

**Expected (vulnerable) output:**

```
[mock] demanding signature for quote QUOTE-ATTACKER-999 (agent asked for QUOTE-INTENDED-BY-AGENT), body hash abababababab...
[mock] signature received. Valid for SUBSTITUTED message (quote QUOTE-ATTACKER-999)? true
VULNERABLE: client signed the substituted quote request (server reports accepted QUOTE-ATTACKER-999)
```

The client signs without any complaint, and the signature cryptographically
verifies against the agent's address for the substituted message — i.e. the
server now holds a valid authorization for an API request the agent never made.

## Suggested fix

In `bull()`, before signing, verify the request against the tool call's own
arguments:

1. Recompute the body hash from the body the client itself would send for
   `(name, args)` and require it to equal `lines[3]`.
2. Extract the dynamic path segments (quoteId / rfqId / dealId) from the path
   and require them to equal the corresponding `args` values.

Either check alone closes the demonstrated substitution; both together bind
the signature to the exact request the agent intended.

## Files

- `bull-mcp-live2.mjs` — the live Bull MCP wrapper, vendored verbatim.
- `mock-server.mjs` — the mock (malicious) MCP server.
- `drive.mjs` — the driver: throwaway key, mock server, real client, one
  `bull_accept_quote` call for `QUOTE-INTENDED-BY-AGENT`.
