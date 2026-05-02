# HiveDrops

> **Layer C — Reference Primitive.** This is a public reference implementation. The wire format (see `SPEC.md` where present) is normative; this code is illustrative. Production-grade implementations of these specs run on the closed-source Hive Civilization platform with HSM-backed key custody, immutable transparency-log audit, multi-region sovereign federation, and SOC 2 / ISO 27001 / FedRAMP-track controls. Fork freely; conform to the spec.

> ## ⏸️ Settlement Status: Anchor Contract Pending
>
> **HiveDrops is a reference implementation of USPTO 64/055,601 Claim C13 (Merkle-Rolled Metering with Threshold Settlement).** The cryptographic primitives — Ed25519 event signing, insertion-ordered Merkle accumulator, threshold logic, challenge protocol — are real and tested (69/69).
>
> **However, the Base L2 anchor contract is not yet deployed.** The `stubAnchorFn` in this repo is exactly that: a stub. Until the production anchor contract is live, this library is **specification-grade**, not settlement-grade.
>
> When the anchor contract ships, it will be added to the production [hive-mcp-attest](https://github.com/srotzin/hive-mcp-attest) umbrella as the `attest_drops_*` tool family. No new MCP server, no new Render head — just additional tools mounted on the existing perimeter.
>
> **Use today:** wire-format reference, audit by review, fork freely.
> **Do not use today:** as a live settlement rail.



**Merkle-Rolled Metering for Usage-Based Settlement on Agent Infrastructure**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue.svg)](https://typescriptlang.org)
[![Tests](https://img.shields.io/badge/tests-69%20passing-brightgreen.svg)](tests/)

Reference implementation of the C13 patent claim: *"Merkle-Rolled Metering with Threshold Settlement and Optional L2 Precompile Embodiment"* — reduced to practice in TypeScript.

---

## The Problem

Agent infrastructure generates thousands of microtransactions per minute. Three settlement approaches exist, all with fatal flaws:

| Approach | Cost | Trust | Auditability |
|----------|------|-------|-------------|
| Per-event on-chain | $5k+/day at scale | None needed | Full |
| Off-chain aggregation | Near-zero | Requires trusting operator | None |
| **HiveDrops** | $10–70/day | No trust needed | Cryptographic |

---

## The HiveDrops Solution

Instead of settling every microtransaction on-chain, or trusting an off-chain aggregator:

1. **Batch** usage events into an insertion-ordered Merkle accumulator.
2. **Anchor** the Merkle root to L2 every N seconds OR every M USDC accumulated (whichever comes first).
3. **Challenge** any anchor by submitting a Merkle proof of a contradiction.
4. **Settle** per-anchor, not per-event.

This gives near-microtransaction economics with cryptographic auditability.

---

## Quickstart

```bash
npm install @hivecivilization/hivedrops-ref
```

### Sign an event

```typescript
import * as ed from "@noble/ed25519";
import { signEvent, verifyEvent } from "@hivecivilization/hivedrops-ref/event";

const agentPrivKey = ed.utils.randomPrivateKey();
const agentPubKey = await ed.getPublicKeyAsync(agentPrivKey);

const event = await signEvent({
  eventId: "evt-001",
  agentDid: "did:hive:agent:myagent",
  consumerDid: "did:hive:consumer:acme",
  service: "llm.completion",
  meterUnits: 1500,
  unitPriceMicroUsdc: 10,
  totalMicroUsdc: 15000,
  ts: new Date().toISOString(),
  nonce: crypto.randomUUID().replace(/-/g, ""),
}, agentPrivKey);

console.log(await verifyEvent(event, agentPubKey)); // true
```

### Accumulate and anchor

```typescript
import { UsageAccumulator } from "@hivecivilization/hivedrops-ref/accumulator";
import { stubAnchorFn } from "@hivecivilization/hivedrops-ref/anchor-stub";

const operatorPrivKey = ed.utils.randomPrivateKey();
const operatorPubKey = await ed.getPublicKeyAsync(operatorPrivKey);

const acc = new UsageAccumulator(
  {
    periodMs: 60_000,           // Anchor every 60 seconds
    thresholdMicroUsdc: 100_000_000, // Or when 100 USDC accumulated
    operatorPubKey,
    operatorPrivKey,
  },
  stubAnchorFn  // Replace with real L2 client in production
);

await acc.addEvent(event);
// ... add more events ...

// Or manually trigger anchor
const anchor = await acc.anchor();
console.log(anchor.merkleRoot); // hex root
```

### Settle a batch

```typescript
import { computeSettlement, buildSettlementInstructions } from "@hivecivilization/hivedrops-ref/settle";

const settlement = computeSettlement(anchor);
// { agentMicroUsdc: 9200000, treasuryMicroUsdc: 800000, ... }

const txs = buildSettlementInstructions(settlement, {
  agent: "0xAgentAddress",
  treasury: "0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E",
});
// [{ to: "0xAgent...", amountMicroUsdc: 9200000, memo: "..." }, ...]
// Pass to USDC.transferFrom() executor
```

### Challenge an anchor

```typescript
import { verifyChallenge } from "@hivecivilization/hivedrops-ref/challenge";

const tree = acc.getTree(anchor.batchId);
const proof = tree.proveByEventId("evt-001");

const result = await verifyChallenge(
  {
    batchId: anchor.batchId,
    eventId: "evt-001",
    claim: "wrong-price",
    proof,
    expected: { totalMicroUsdc: 15000 },
    observed: { totalMicroUsdc: 15001 }, // overcharged by 1 µUSDC
    event,
  },
  anchor,
  operatorPubKey,
  async (did) => agentPubKeyMap[did]
);

console.log(result.valid, result.severity); // true, "fatal"
```

### CLI

```bash
# Simulate event replay from JSONL file
npx hivedrops simulate events.jsonl --period 60s --threshold 100usdc

# Run a challenge
npx hivedrops challenge anchor.json event-proof.json
```

---

## Schema

### UsageEvent

| Field | Type | Description |
|-------|------|-------------|
| `eventId` | string | UUID v4, globally unique |
| `agentDid` | string | Agent's decentralized identifier |
| `consumerDid` | string | Consumer's decentralized identifier |
| `service` | string | Service name ("llm.completion", etc.) |
| `meterUnits` | number | Units consumed |
| `unitPriceMicroUsdc` | number | Price per unit in µUSDC |
| `totalMicroUsdc` | number | Must equal `meterUnits × unitPriceMicroUsdc` |
| `ts` | string | RFC3339 timestamp |
| `nonce` | string | ≥32 hex chars (random, anti-replay) |
| `sig` | string | ed25519 signature, base64url |

### MerkleAnchor

| Field | Type | Description |
|-------|------|-------------|
| `batchId` | string | UUID v4 |
| `merkleRoot` | string | Hex SHA-256 Merkle root |
| `eventCount` | number | Real event count (not padded) |
| `totalMicroUsdc` | number | Sum of all event totals |
| `periodStart` | string | RFC3339 batch start |
| `periodEnd` | string | RFC3339 batch end |
| `chainId` | number | EVM chain ID (8453 = Base) |
| `anchorTxHash` | string? | On-chain tx hash |
| `operatorSig` | string | ed25519 operator signature |

---

## Performance Numbers (from `examples/run-simulation.ts`)

Simulation: 1,000 events · 5 anchors · 1 simulated hour

| Metric | Value |
|--------|-------|
| Event signing throughput | ~1,200 events/sec |
| Events per batch | 200 |
| Total batches | 5 |
| Grand total settled | 103.64 USDC |
| Agent payout (92%) | 95.35 USDC |
| Treasury fee (8%) | 8.29 USDC |
| On-chain txs: without HiveDrops | 1,000 |
| On-chain txs: with HiveDrops | 10 (5 anchor + 5 settle) |
| Gas savings (@$0.05/tx) | $49.50 (100× compression) |

Run it yourself:
```bash
npx tsx examples/run-simulation.ts
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  UsageAccumulator                                    │
│  ┌───────────────┐    period ≥ N ms                 │
│  │ Open Batch    │ ──────────────────┐               │
│  │               │    total ≥ M USDC│               │
│  │ event[0]      │ ──────────────────┤               │
│  │ event[1]      │                  ▼               │
│  │ ...           │           anchor(batch)           │
│  │ event[N]      │           ├─ seal tree            │
│  └───────────────┘           ├─ compute root         │
│                              ├─ sign (operator key)  │
│                              ├─ call anchorFn(root)  │
│                              └─ open new batch       │
└─────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  MerkleAnchor   │
                    │  published      │
                    │  on L2          │
                    └────────┬────────┘
                             │ challenge window
                ┌────────────┴────────────┐
                ▼                         ▼
        no challenge               challenge submitted
        → settle via             → verifyChallenge()
          USDC transferFrom        ├─ forged-sig
                                   ├─ wrong-price
                                   ├─ double-count
                                   └─ missing (TODO)
```

---

## Integration Points

The following three functions are stubs in this reference implementation. Replace them for production use:

1. **`stubAnchorFn`** (`src/anchor-stub.ts`): Replace with a real Base/L2 RPC client call to the HiveDrops anchor contract.

2. **`AgentPubKeyResolver`** (`src/challenge.ts`): Replace with a DID resolution service (did:web, did:key, on-chain registry, etc.).

3. **Persistence hook** (`UsageAccumulator` constructor `onAnchorHook` param): Replace with a database write to persist anchors and trees between restarts.

---

## License

Apache 2.0 — Copyright 2026 Hive Civilization

See [LICENSE](LICENSE) for full terms.

---

## Related

- `@hivecivilization/prov-absence` — Sorted-Merkle non-membership proofs (for `missing` challenges)
- [SPEC.md](SPEC.md) — Full protocol specification
- [PRECOMPILE-NOTES.md](PRECOMPILE-NOTES.md) — L2 precompile embodiment notes
