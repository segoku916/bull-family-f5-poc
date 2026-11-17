// Bull MCP (local): lets an AI agent trade OTC on Bull with its OWN wallet key. The key never leaves this process.
// It signs every Bull API request for you and can send the escrow transactions (open deal, pay, deposit).
//
// Setup:   npm i viem      (Node 18+)
// Run:     BULL_AGENT_KEY=0x... node bull-mcp.mjs
// Claude Desktop / Cursor config:
//   { "mcpServers": { "bull": { "command": "node", "args": ["/path/to/bull-mcp.mjs"], "env": { "BULL_AGENT_KEY": "0x..." } } } }
// Use a dedicated wallet that holds only what you want to trade. The escrow contract is not audited yet.
import { createPublicClient, createWalletClient, defineChain, erc20Abi, formatEther, http, parseAbi, parseEther, parseEventLogs, parseUnits } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const DEFAULT_BASE = "https://www.bull.family";
const BASE = (process.env.BULL_URL || DEFAULT_BASE).replace(/\/$/, "");
if (BASE !== DEFAULT_BASE) console.error(`Bull MCP WARNING: BULL_URL points to ${BASE}, not ${DEFAULT_BASE}. Only continue if you run this server yourself.`);

// Safety: the API server is not trusted with your wallet. Transactions it returns may only go to Bull's contracts (or approve them),
// and no single transaction may send more ETH than BULL_MAX_ETH (default 1). Signatures are only given for what the tool call needs.
const ESCROWS = ["0xd961ca37e339e14e0d3478383a252e218fe7aa4a"]; // current escrow only
const AGREEMENT = "0x84c6d5daf99bc65ed3a1d26ca88ffa834d143999";
const BULL_CONTRACTS = [...ESCROWS, AGREEMENT];
const MAX_WEI = BigInt(Math.round(Number(process.env.BULL_MAX_ETH || "1") * 1e18));
const low = (x) => String(x || "").toLowerCase();

// What each tool may ask you to sign: the HTTP method and path of the request it stands for. Anything else is refused.
const SIGN_OK = {
  bull_create_rfq: ["POST", /^\/api\/v1\/rfqs$/], bull_settle: ["POST", /^\/api\/v1\/settle$/], bull_settle_steps: ["GET", /^\/api\/v1\/settle\/\d+$/],
  bull_vesting_lock: ["POST", /^\/api\/v1\/vesting$/], bull_vesting_status: ["GET", /^\/api\/v1\/vesting\/\d+$/],
  bull_agreement_create: ["POST", /^\/api\/v1\/agreements$/], bull_agreement_status: ["GET", /^\/api\/v1\/agreements\/\d+$/], bull_agreement_feed: ["GET", /^\/api\/v1\/agreements/],
  bull_agreement_watch: ["POST", /^\/api\/v1\/agreements\/watch$/], bull_agent_reputation: ["GET", /^\/api\/v1\/agents\/0x[0-9a-fA-F]{40}$/],
  bull_agreement_from_template: ["POST", /^\/api\/v1\/templates$/], bull_get_quotes: ["GET", /^\/api\/v1\/rfqs\/[\w-]+\/quotes$/], bull_send_quote: ["POST", /^\/api\/v1\/rfqs\/[\w-]+\/quotes$/],
  bull_counter_quote: ["POST", /^\/api\/v1\/quotes\/[\w-]+\/counter$/], bull_revise_quote: ["POST", /^\/api\/v1\/quotes\/[\w-]+\/revise$/], bull_accept_quote: ["POST", /^\/api\/v1\/quotes\/[\w-]+\/accept$/],
  bull_attach_deal: ["POST", /^\/api\/v1\/quotes\/[\w-]+\/deal$/], bull_quote_status: ["GET", /^\/api\/v1\/quotes\/[\w-]+$/], bull_deposit_plan: ["GET", /^\/api\/v1\/quotes\/[\w-]+\/permit$/],
  bull_deposit: ["POST", /^\/api\/v1\/quotes\/[\w-]+\/deposit$/], bull_consent_plan: ["GET", /^\/api\/v1\/quotes\/[\w-]+\/consent$/], bull_consent: ["POST", /^\/api\/v1\/quotes\/[\w-]+\/consent$/], bull_reject_quote: ["POST", /^\/api\/v1\/quotes\/[\w-]+\/reject$/],
};
const KEY = process.env.BULL_AGENT_KEY || "";
if (!/^0x[0-9a-fA-F]{64}$/.test(KEY)) { console.error("Set BULL_AGENT_KEY to a 0x... private key (64 hex characters)."); process.exit(1); }
const account = privateKeyToAccount(KEY);
const AUTH = new Set(["address", "timestamp", "signature"]);

let chainInfo = null;
async function chainClients() {
  if (!chainInfo) {
    const info = await (await fetch(BASE + "/api/v1")).json();
    const chain = defineChain({
      id: info.chain.id, name: info.chain.name, nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: { default: { http: [process.env.BULL_RPC || "https://rpc.mainnet.chain.robinhood.com"] } },
    });
    chainInfo = { chain, pub: createPublicClient({ chain, transport: http() }), wal: createWalletClient({ account, chain, transport: http() }), info };
  }
  return chainInfo;
}

// ---- remote Bull MCP (signing handled here) ----
let rid = 0;
async function remote(method, params) {
  const r = await fetch(BASE + "/api/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: ++rid, method, params }) });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}
const parse = (res) => { try { return JSON.parse(res.content[0].text); } catch { return { raw: res }; } };

// Calls a Bull tool; if the server asks for a signature, signs it with the agent key and calls again.
async function bull(name, args = {}) {
  const a = { ...args, address: account.address };
  let res = await remote("tools/call", { name, arguments: a });
  let out = parse(res);
  if (out.status === "signature_required") {
    // Only sign a Bull API request: "Bull API\nMETHOD /api/v1/...\n<timestamp>\n<body hash>", fresh, from our own address.
    const lines = String(out.message || "").split("\n");
    const fresh = Math.abs(Date.now() - Number(lines[2])) < 5 * 60 * 1000;
    if (lines.length !== 4 || lines[0] !== "Bull API" || !/^(GET|POST) \/api\/v1\//.test(lines[1]) || !fresh || lines[2] !== String(out.timestamp) || low(out.address) !== low(account.address) || !/^[0-9a-f]{64}$|^0x[0-9a-f]{64}$/i.test(lines[3]))
      throw new Error("Refusing to sign: the server asked for a message that is not a fresh Bull API request.");
    const [method, path] = String(lines[1]).split(" ");
    const rule = SIGN_OK[name];
    if (!rule || rule[0] !== method || !rule[1].test(path.split("?")[0])) throw new Error(`Refusing to sign ${method} ${path} for the tool ${name}: that is not what this tool does.`);
    const signature = await account.signMessage({ message: out.message });
    res = await remote("tools/call", { name, arguments: { ...a, timestamp: out.timestamp, signature } });
    out = parse(res);
  }
  return { ok: !res.isError, data: out };
}

// ---- local tools (these use the wallet) ----
const ZERO = "0x0000000000000000000000000000000000000000";
const USDG = "0x5fc5360d0400a0fd4f2af552add042d716f1d168";
const DEALS_ABI = parseAbi(["function deals(uint256) view returns (address buyer,address seller,address sellToken,uint256 sellAmount,address payToken,uint256 payAmount,uint64 deadline,bool buyerFunded,bool sellerFunded,uint8 status,address sellerPayout,address buyerReceive,uint16 feeBps)"]);
// The deal as the chain knows it (never as the server describes it).
async function chainDeal(id) {
  const { pub } = await chainClients();
  const r = await pub.readContract({ address: ESCROWS[0], abi: DEALS_ABI, functionName: "deals", args: [BigInt(id)] });
  return { buyer: r[0], seller: r[1], sellToken: r[2], sellAmount: r[3], payToken: r[4], payAmount: r[5], buyerFunded: r[7], sellerFunded: r[8], status: Number(r[9]) };
}

// o.token / o.maxApprove: the only approval this step may make (taken from the chain), o.maxWei: ETH this step may send.
function guard(tx, o = {}) {
  const to = low(tx?.to), data = String(tx?.data || "0x"), value = BigInt(tx?.value || "0");
  const maxWei = o.maxWei ?? 0n;
  if (value > maxWei || value > MAX_WEI) throw new Error(`Refusing to send ${value} wei: more than the ${maxWei} this step needs.`);
  if (data.startsWith("0x095ea7b3")) {
    const spender = "0x" + data.slice(34, 74).toLowerCase();
    const amt = BigInt("0x" + data.slice(74, 138));
    if (!o.token || to !== low(o.token)) throw new Error(`Refusing to approve ${to}: not the token of this deal.`);
    if (!BULL_CONTRACTS.includes(spender)) throw new Error(`Refusing to approve ${spender}: not a Bull contract.`);
    if (o.maxApprove === undefined || amt > o.maxApprove) throw new Error(`Refusing to approve ${amt}: more than the ${o.maxApprove ?? 0n} this deal needs.`);
    return;
  }
  if (BULL_CONTRACTS.includes(to)) return;
  throw new Error(`Refusing to send a transaction to ${to}: not a Bull contract.`);
}

async function send(tx, o) {
  guard(tx, o);
  const { wal, pub } = await chainClients();
  const hash = await wal.sendTransaction({ to: tx.to, data: tx.data, value: BigInt(tx.value || "0") });
  const rc = await pub.waitForTransactionReceipt({ hash });
  if (rc.status !== "success") throw new Error("Transaction failed: " + hash);
  return rc;
}

const LOCAL = [
  {
    name: "bull_whoami",
    description: "Your agent wallet address and ETH balance on the Bull chain.",
    inputSchema: { type: "object", properties: {} },
    run: async () => { const { pub, info } = await chainClients(); return { address: account.address, chain: info.chain.name, eth: formatEther(await pub.getBalance({ address: account.address })) }; },
  },
  {
    name: "bull_open_deal",
    description: "BUYER, one step: accept the quote, open the escrow deal onchain, and pay your side into escrow. Needs ETH for the price plus gas. After this the seller deposits and the swap settles.",
    inputSchema: { type: "object", properties: { quoteId: { type: "string" }, payAsset: { type: "string", description: "\"base\" (ETH, default) or \"alt\" (stablecoin)." } }, required: ["quoteId"] },
    run: async (a) => {
      const { chain } = await chainClients();
      const acc = await bull("bull_accept_quote", { quoteId: a.quoteId, ...(a.payAsset ? { payAsset: a.payAsset } : {}) });
      if (!acc.ok) return acc.data;
      const rc = await send(acc.data.transaction, { maxWei: 0n });
      const ev = parseEventLogs({ abi: parseAbi(["event DealCreated(uint256 indexed id,address indexed buyer,address indexed seller,uint16 feeBps)"]), logs: rc.logs })[0];
      const dealId = ev.args.id.toString();
      const cd = await chainDeal(dealId);
      if (low(cd.buyer) !== low(account.address)) throw new Error("The deal on chain does not name your wallet as buyer. Do not fund it.");
      if (Number(ev.args.feeBps) > 250 || low(ev.args.buyer) !== low(account.address)) throw new Error("The deal on chain has a fee above 2.5% or another buyer. Do not fund it.");
      if (cd.payAmount > MAX_WEI && low(cd.payToken) === ZERO) throw new Error(`The deal costs more than BULL_MAX_ETH (${MAX_WEI} wei). Raise BULL_MAX_ETH to continue.`);
      const att = await bull("bull_attach_deal", { quoteId: a.quoteId, dealId });
      if (!att.ok) return att.data;
      const txs = [rc.transactionHash];
      for (const step of att.data.steps) txs.push((await send(step, { maxWei: low(cd.payToken) === ZERO ? cd.payAmount : 0n, token: cd.payToken, maxApprove: cd.payAmount })).transactionHash);
      return { status: "paid_into_escrow", dealId, feeBps: Number(ev.args.feeBps), transactions: txs.map((h) => `${chain.blockExplorers?.default?.url || ""}/tx/${h}`), next: "Wait for the seller to deposit. Check bull_get_deal." };
    },
  },
  {
    name: "bull_sign_terms",
    description: "SELLER, one step: after the buyer accepted your quote, sign the exact deal terms (EIP-712, free, moves nothing) so the buyer can open the escrow. Checks the terms against your quote first.",
    inputSchema: { type: "object", properties: { quoteId: { type: "string" }, buyer: { type: "string", description: "The buyer wallet you agreed with." }, tokens: { type: "string", description: "Token amount you agreed to sell, e.g. \"1000\"." }, payAsset: { type: "string", enum: ["eth", "usdg"] }, payAmount: { type: "string", description: "Total price you agreed, in ETH or USDG." }, payout: { type: "string", description: "Only if your quote named a different payout wallet." } }, required: ["quoteId", "buyer", "tokens", "payAsset", "payAmount"] },
    run: async (a) => {
      const plan = await bull("bull_consent_plan", { quoteId: a.quoteId });
      if (!plan.ok) return plan.data;
      const t = plan.data.typedData;
      // Everything is checked against what YOU pass in, never against server data.
      const { pub } = await chainClients();
      const m = t?.message || {};
      if (t?.primaryType !== "Consent" || t.domain?.name !== "BullEscrow" || String(t.domain?.version) !== "3" || Number(t.domain?.chainId) !== 4663 || !ESCROWS.includes(low(t.domain?.verifyingContract))) throw new Error("Refusing to sign: not a Bull escrow consent.");
      if (JSON.stringify((t.types?.Consent || []).map((f) => f.name + ":" + f.type)) !== JSON.stringify(["buyer:address", "seller:address", "sellerPayout:address", "buyerReceive:address", "sellToken:address", "sellAmount:uint256", "payToken:address", "payAmount:uint256", "deadline:uint64", "validUntil:uint64"])) throw new Error("Refusing to sign: unexpected typed-data layout.");
      if (low(m.seller) !== low(account.address)) throw new Error("Refusing to sign: the seller is not your wallet.");
      if (low(m.buyer) !== low(a.buyer)) throw new Error("Refusing to sign: the buyer is not the one you agreed with.");
      if (low(m.sellerPayout) !== low(a.payout || account.address) && low(m.sellerPayout) !== ZERO) throw new Error("Refusing to sign: the payout wallet is not yours.");
      if (low(m.buyerReceive) !== ZERO) throw new Error("Refusing to sign: the tokens would go to another wallet than the buyer.");
      const dec = Number(await pub.readContract({ address: m.sellToken, abi: parseAbi(["function decimals() view returns (uint8)"]), functionName: "decimals" }));
      if (BigInt(m.sellAmount) !== parseUnits(String(a.tokens), dec)) throw new Error("Refusing to sign: the token amount is not the one you agreed.");
      if (a.payAsset === "eth") { if (low(m.payToken) !== ZERO || BigInt(m.payAmount) !== parseEther(String(a.payAmount))) throw new Error("Refusing to sign: the price is not the one you agreed."); }
      else if (a.payAsset === "usdg") { if (low(m.payToken) !== USDG || BigInt(m.payAmount) !== parseUnits(String(a.payAmount), 6)) throw new Error("Refusing to sign: the payment asset or amount is not the one you agreed."); }
      else throw new Error("payAsset must be eth or usdg.");
      const left = Number(m.deadline) - Math.floor(Date.now() / 1000);
      if (!(left > 3600 && left <= 8 * 86400) || Number(m.validUntil) < Date.now() / 1000) throw new Error("Refusing to sign: unreasonable deadline or expired consent.");
      const signature = await account.signTypedData({ domain: t.domain, types: t.types, primaryType: "Consent", message: Object.fromEntries(Object.entries(m).map(([k, v]) => [k, /^\d+$/.test(String(v)) ? BigInt(v) : v])) });
      const r = await bull("bull_consent", { quoteId: a.quoteId, signature });
      return r.ok ? { status: "terms_signed", next: "The buyer can open the escrow now.", ...r.data } : r.data;
    },
  },
  {
    name: "bull_fund_tokens",
    description: "SELLER, one step: deposit your tokens into escrow once the buyer has paid. Uses the gasless permit when the token supports it, otherwise approve + deposit (needs a little ETH for gas). The swap settles in that transaction.",
    inputSchema: { type: "object", properties: { quoteId: { type: "string" } }, required: ["quoteId"] },
    run: async (a) => {
      const plan = await bull("bull_deposit_plan", { quoteId: a.quoteId });
      if (!plan.ok) return plan.data;
      const d = plan.data;
      const qs = await bull("bull_quote_status", { quoteId: a.quoteId });
      const cd = await chainDeal(String(qs.data?.dealId ?? qs.data?.deal?.id ?? ""));
      if (low(cd.seller) !== low(account.address) || !cd.buyerFunded || cd.sellerFunded || cd.status !== 1) throw new Error("The deal on chain is not one you can fund as the seller right now.");
      if (d.permit) {
        const m = d.permit.message;
        if (low(m.owner) !== low(account.address) || !ESCROWS.includes(low(m.spender)) || BigInt(m.value) !== cd.sellAmount || low(d.permit.domain?.verifyingContract) !== low(cd.sellToken) || Number(m.deadline) > Date.now() / 1000 + 86400 || Number(m.deadline) < Date.now() / 1000)
          throw new Error("Refusing to sign the permit: the owner, spender, amount or deadline is not what a Bull deposit needs.");
        const sig = await account.signTypedData({ domain: d.permit.domain, types: d.permit.types, primaryType: d.permit.primaryType, message: { owner: m.owner, spender: m.spender, value: BigInt(m.value), nonce: BigInt(m.nonce), deadline: BigInt(m.deadline) } });
        const r = "0x" + sig.slice(2, 66), s = "0x" + sig.slice(66, 130);
        let v = parseInt(sig.slice(130, 132), 16); if (v < 27) v += 27;
        // The seller also signs the escrow's Fund message for exactly this deal, so a relayer cannot reuse the permit anywhere else.
        const f = d.fund;
        if (!f || f.domain?.name !== "BullEscrow" || String(f.domain?.version) !== "3" || Number(f.domain?.chainId) !== 4663 || !ESCROWS.includes(low(f.domain?.verifyingContract)) || f.primaryType !== "Fund"
          || String(f.message.id) !== String(qs.data?.dealId) || low(f.message.seller) !== low(account.address) || low(f.message.sellToken) !== low(cd.sellToken) || BigInt(f.message.sellAmount) !== cd.sellAmount || String(f.message.permitDeadline) !== String(m.deadline))
          throw new Error("Refusing to sign the fund message: it is not for this deal.");
        const fundSig = await account.signTypedData({ domain: f.domain, types: f.types, primaryType: "Fund", message: { id: BigInt(f.message.id), seller: f.message.seller, sellToken: f.message.sellToken, sellAmount: BigInt(f.message.sellAmount), permitDeadline: BigInt(f.message.permitDeadline) } });
        const dep = await bull("bull_deposit", { quoteId: a.quoteId, permitDeadline: m.deadline, v, r, s, fundSig });
        return dep.ok ? { status: "deposited_gasless", ...dep.data } : dep.data;
      }
      const txs = [];
      for (const step of d.direct) txs.push((await send(step, { token: cd.sellToken, maxApprove: cd.sellAmount })).transactionHash);
      return { status: "deposited", transactions: txs };
    },
  },
];

// ---- MCP over stdio ----
async function tools() {
  const r = await remote("tools/list", {});
  const proxied = r.tools
    .map((t) => ({ ...t, description: t.description.replace(/ Signed call:.*$/, ""), inputSchema: { ...t.inputSchema, properties: Object.fromEntries(Object.entries(t.inputSchema.properties).filter(([k]) => !AUTH.has(k))), required: (t.inputSchema.required || []).filter((k) => !AUTH.has(k)) } }));
  return [...LOCAL.map(({ run, ...t }) => t), ...proxied];
}

async function handle(m) {
  switch (m.method) {
    case "initialize":
      return { protocolVersion: m.params?.protocolVersion || "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "bull-otc-local", version: "1.0.0" }, instructions: `Bull OTC with your own wallet ${account.address}. Start with bull_info and bull_whoami.` };
    case "ping": return {};
    case "tools/list": return { tools: await tools() };
    case "tools/call": {
      const { name, arguments: args = {} } = m.params;
      const local = LOCAL.find((t) => t.name === name);
      try {
        if (local) return { content: [{ type: "text", text: JSON.stringify(await local.run(args), null, 2) }] };
        const out = await bull(name, args);
        return { content: [{ type: "text", text: JSON.stringify(out.data, null, 2) }], ...(out.ok ? {} : { isError: true }) };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ error: String(e.message || e).slice(0, 400) }) }], isError: true };
      }
    }
    default: throw Object.assign(new Error("Method not found: " + m.method), { code: -32601 });
  }
}

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line) continue;
    let m; try { m = JSON.parse(line); } catch { continue; }
    if (m.id === undefined) continue; // notifications need no reply
    handle(m).then((result) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }) + "\n"))
      .catch((e) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: e.code || -32603, message: e.message } }) + "\n"));
  }
});
console.error(`Bull MCP ready for ${account.address}`);
