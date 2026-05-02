# HiveDrops Protocol Specification

**Version:** 0.0.1  
**Status:** Reference Implementation  
**Cross-reference:** C13 Patent Claim — "Merkle-Rolled Metering with Threshold Settlement and Optional L2 Precompile Embodiment" (Provisional §17)

---

## 1. Overview

HiveDrops is a cryptographic metering protocol for usage-based settlement on agent infrastructure. It solves the trilemma of:

- **Cost**: Settling every microtransaction on-chain is prohibitively expensive.
- **Trust**: Settling via off-chain aggregation requires trusting the operator.
- **Auditability**: Batched settlement without cryptographic proofs offers no accountability.

**The HiveDrops solution**: Batch usage events into a rolling Merkle accumulator, anchor the root to L1/L2 periodically, and allow any party to challenge the published root by submitting a Merkle proof of a contradiction.

Settlement economics: **1 on-chain transaction per N events**, where N is determined by the anchoring policy (time period or USDC threshold, whichever triggers first).

---

## 2. Events

### 2.1 UsageEvent Structure

```typescript
{
  eventId: string;          // Globally unique (UUID v4 recommended)
  agentDid: string;         // DID of the agent performing work
  consumerDid: string;      // DID of the consumer being billed
  service: string;          // Service name ("llm.completion", etc.)
  meterUnits: number;       // Units consumed (tokens, calls, seconds)
  unitPriceMicroUsdc: number; // Price per unit in micro-USDC
  totalMicroUsdc: number;   // MUST equal meterUnits × unitPriceMicroUsdc
  ts: string;               // RFC3339 timestamp
  nonce: string;            // ≥ 32 hex chars (16 random bytes)
  sig: string;              // ed25519 signature, base64url (no padding)
}
```

### 2.2 Canonical Serialization

The canonical form of an event is `JSON.stringify` with keys sorted alphabetically:

```
agentDid, consumerDid, eventId, meterUnits, nonce, service,
totalMicroUsdc, ts, unitPriceMicroUsdc
```

The `sig` field is EXCLUDED from the signing preimage. It is INCLUDED in the Merkle leaf hash preimage (see §4.2).

### 2.3 Signing

Event signatures use **ed25519** over the canonical form:

```
sig = ed25519_sign(agentPrivKey, UTF8(canonicalEventWithoutSig))
```

Encoded as base64url (RFC 4648 §5, no padding).

### 2.4 Invariant

Every event MUST satisfy:

```
totalMicroUsdc === meterUnits × unitPriceMicroUsdc
```

Violations are detectable via the `wrong-price` challenge type (§6.3).

---

## 3. Batches

### 3.1 Batch Lifecycle

1. **Open**: A new batch opens when the accumulator starts, or immediately after the previous batch is anchored.
2. **Accumulating**: Events are added to the current batch. Each event is hashed and appended to the insertion-ordered Merkle tree.
3. **Close trigger**: The batch closes (is anchored) when EITHER:
   - The configured `periodMs` has elapsed since the batch opened (time-based trigger), OR
   - The accumulated `totalMicroUsdc` ≥ `thresholdMicroUsdc` (threshold-based trigger).
   
   Whichever condition fires first wins.
4. **Anchored**: The Merkle root is computed, the operator signs the anchor, and the anchor function is called to record the root on-chain.

### 3.2 Batch Immutability

Once a batch is anchored, its Merkle tree is sealed. Subsequent `add()` calls on a sealed tree throw an error. The accumulator immediately opens a fresh batch after anchoring.

---

## 4. Merkle Tree

### 4.1 Structure

- **Type**: Binary Merkle tree, insertion-ordered (NOT sorted).
- **Leaf ordering**: Corresponds exactly to event insertion order (time-ordered).
- **Size**: Always padded to the next power of 2 by duplicating the last real leaf.
- **Leaf count stored in anchor**: The REAL event count, not the padded count.

Rationale for insertion order (not sorted): Sorting would destroy the temporal audit trail and complicate proof generation for time-range queries. Non-membership proofs for sorted trees are deferred to `@hivecivilization/prov-absence`.

### 4.2 Hash Functions

**Domain separation** (prevents second-preimage attacks where internal nodes could be confused with leaves):

| Level | Preimage | Purpose |
|-------|----------|---------|
| Leaf  | `0x00 \|\| canonicalEventBytesWithSig` | One per event |
| Node  | `0x01 \|\| leftChild(32B) \|\| rightChild(32B)` | Internal nodes |

Both use **SHA-256**.

The `sig` field IS included in the leaf hash. This binds the agent's identity to the leaf — a forged event with the same content but a different signature produces a different leaf hash, and therefore a different Merkle root.

### 4.3 Padding Rule

If the tree has `n` real leaves and `n` is not a power of 2, the last real leaf is duplicated until `size = nextPow2(n)`. This is consistent with RFC 6962 (Certificate Transparency) Merkle trees.

The `treeSize` field in inclusion proofs always reflects the padded size.

### 4.4 Inclusion Proof

```typescript
{
  leafIndex: number;   // Index in the padded tree
  treeSize: number;    // Power-of-2 padded tree size
  leafHash: string;    // hex SHA-256(0x00 || eventBytes)
  path: Array<{
    sibling: string;   // hex sibling hash
    position: "left" | "right"; // sibling's position relative to current
  }>;
}
```

**Verification** (`verifyProof`):
1. Start with `current = leafHash`.
2. For each path step: if `position === "left"`, compute `nodeHash(sibling, current)`; otherwise compute `nodeHash(current, sibling)`.
3. After all steps, verify `current === root`.

---

## 5. Anchoring

### 5.1 MerkleAnchor Structure

```typescript
{
  batchId: string;         // UUID v4
  merkleRoot: string;      // Hex Merkle root
  eventCount: number;      // Real event count (not padded)
  totalMicroUsdc: number;  // Sum of all event.totalMicroUsdc
  periodStart: string;     // RFC3339, first event timestamp
  periodEnd: string;       // RFC3339, last event timestamp
  chainId: number;         // EVM chain ID (8453 = Base mainnet)
  anchorTxHash?: string;   // On-chain tx hash (absent if not yet submitted)
  operatorSig: string;     // ed25519 signature, base64url
}
```

### 5.2 Operator Signature

The operator signs the anchor over all fields EXCEPT `operatorSig`, with keys sorted alphabetically:

```
operatorSig = ed25519_sign(operatorPrivKey, UTF8(canonicalAnchorWithoutSig))
```

This signature allows any observer to verify that the operator committed to the root, event count, and total amount cryptographically.

### 5.3 Anchoring Policy

The **whichever-first** rule:
- If `elapsedMs ≥ periodMs` → time-triggered anchor.
- If `totalMicroUsdc ≥ thresholdMicroUsdc` → threshold-triggered anchor.
- Anchoring is atomic: seal tree, compute root, sign, call anchor function, open new batch.

### 5.4 On-Chain Anchor Function

In production, the anchor function calls the HiveDrops anchor contract:

```
anchorBatch(merkleRoot, totalMicroUsdc, batchId) → txHash
```

**USDC contract on Base**: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`  
**Treasury address**: `0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E`  
**Chain ID**: `8453` (Base mainnet)

In the reference implementation, this is replaced by `stubAnchorFn` (see `src/anchor-stub.ts`).

---

## 6. Challenge Types

A challenge is a proof that a published `MerkleAnchor` contains a contradiction. The protocol verifies:

1. The anchor's operator signature is valid.
2. The Merkle inclusion proof is valid against `anchor.merkleRoot`.
3. The claim-specific contradiction exists.

### 6.1 `forged-sig`

**Claim**: An event in the tree has an invalid agent signature. The operator may have fabricated or mutated the event content.

**Proof required**: Merkle inclusion proof + the event payload + the agentDid's public key.

**Verification**:
1. Verify Merkle proof.
2. Resolve agent's public key from `agentDid`.
3. Re-verify `event.sig` over `canonicalEventWithoutSig`.
4. If signature is invalid → challenge succeeds (fatal).

**Severity**: fatal.

### 6.2 `double-count`

**Claim**: The same `eventId` appears at two distinct leaf indices in the same batch. The operator counted the same work twice.

**Proof required**: Two Merkle inclusion proofs (`proof` + `siblingProof`) with different leaf indices.

**Verification**:
1. Verify both proofs against the same `anchor.merkleRoot`.
2. Confirm leaf indices differ.
3. Confirm both proofs correspond to the same `eventId` (via identical leaf hashes or matching event data).

**Severity**: fatal.

### 6.3 `wrong-price`

**Claim**: `event.totalMicroUsdc ≠ event.meterUnits × event.unitPriceMicroUsdc`. The operator may be overbilling.

**Proof required**: Merkle inclusion proof + the event payload.

**Verification**:
1. Verify Merkle proof.
2. Compute `expected = event.meterUnits × event.unitPriceMicroUsdc`.
3. Compare with `event.totalMicroUsdc`.
4. If they differ → challenge succeeds (fatal).

**Severity**: fatal.

### 6.4 `missing` (Future Work)

**Claim**: An event known to the consumer is absent from the batch tree.

**Status**: NOT IMPLEMENTED in the reference implementation. Full non-membership proofs require a sorted side-tree. See `@hivecivilization/prov-absence` for the sorted-Merkle approach.

Ref: C13 provisional §17 — non-membership proofs are SHOULD, not MUST, for the reference implementation.

---

## 7. Settlement Math

### 7.1 Default Splits

| Recipient | Share (bps) | Share (%) | Rationale |
|-----------|-------------|-----------|-----------|
| Agent/Provider | 9200 | 92% | Maximizes returns to contributors (Hive ambassador model) |
| Treasury | 800 | 8% | Protocol sustainability, audits, governance reserve |
| Consumer rebate | 0 | 0% | Optional; used for SLA credits, volume discounts |

### 7.2 Rounding

Integer truncation (floor). Remainder accrues to the agent share.

```
treasury = floor(total × treasuryBps / 10000)
rebate   = floor(total × rebateBps / 10000)
agent    = total - treasury - rebate
```

### 7.3 Settlement Instructions

`buildSettlementInstructions()` returns an array of `{ to, amountMicroUsdc, memo }` records. These are NOT broadcast by the reference implementation. An external on-chain executor (settlement contract) would broadcast these as `USDC.transferFrom()` calls.

---

## 8. Security Model

### 8.1 What HiveDrops Protects Against

| Threat | Mitigation |
|--------|-----------|
| Operator inflates event totals | `wrong-price` challenge detects arithmetic inconsistency |
| Operator fabricates agent activity | `forged-sig` challenge detects invalid ed25519 signatures |
| Operator double-counts an event | `double-count` challenge proves same eventId at two indices |
| Operator tampers with Merkle root post-signing | Operator's ed25519 signature binds root irrevocably |
| Challenger submits forged proof | `verifyProof` against published root rejects invalid paths |
| Cross-batch proof forgery | Proof from batch A fails to verify against batch B's root |

### 8.2 What HiveDrops Does NOT Protect Against

| Limitation | Notes |
|-----------|-------|
| **Operator refusing events** | If an operator declines to include a submitted event, the consumer has no cryptographic recourse within HiveDrops. This is an availability problem, not an integrity problem. It requires a gossip/event-receipt layer outside this scope. |
| **Agent collusion with operator** | If the agent and operator collude, they can fabricate mutually consistent events with valid signatures. |
| **Consumer non-payment** | HiveDrops is agnostic to payment enforcement; that is handled by the on-chain settlement contract and escrow. |
| **Non-membership proofs** | Without `@hivecivilization/prov-absence`, consumers cannot prove an event they submitted was omitted from the tree. |
| **Key compromise** | If the operator's signing key is stolen, an attacker can sign fraudulent anchors. Key rotation is outside scope. |
| **Reorg attacks** | If the L2 chain reorgs, the anchor tx hash may become invalid. Finality thresholds are the deployment's responsibility. |

---

## 9. Threat Model

### 9.1 Trust Assumptions

- **Agent**: Trusted to sign events honestly. Honest agent signatures allow consumers to detect forged events.
- **Operator**: Untrusted for content. The operator's job is to collect signed events and commit their Merkle root. The operator CAN:
  - Refuse to accept events (availability attack — not addressed here).
  - Submit anchors with incorrect totals (detectable by consumers via wrong-price challenges).
  - Include duplicate events (detectable via double-count challenges).
  - Include fabricated events (detectable via forged-sig challenges — IF the consumer has the event's expected content).
- **L2 chain**: Trusted for finality. The on-chain anchor is assumed to be immutable post-finality.
- **Challenger**: Untrusted for correctness. The `verifyChallenge` function rejects invalid proofs.

### 9.2 Cryptographic Dependencies

| Primitive | Algorithm | Library |
|-----------|-----------|---------|
| Event signing | ed25519 | `@noble/ed25519` |
| Merkle hashing | SHA-256 | `@noble/hashes/sha256` |
| Anchor signing | ed25519 | `@noble/ed25519` |

---

## 10. Performance

From the reference simulation (1,000 events, 5 anchors, 1 simulated hour):

| Metric | Value |
|--------|-------|
| Event signing throughput | ~1,200 events/second |
| Anchor compression ratio | 100x (1,000 events → 10 on-chain txs) |
| Gas savings (@$0.05/tx) | $49.50 saved vs. per-event settlement |
| Settlement per batch | ~5ms (pure computation) |

Scaling note: The accumulator is single-threaded in this reference implementation. Production deployments should use a worker-pool model for event signing at scale.

---

*Specification: HiveDrops v0.0.1 — Copyright 2026 Hive Civilization — Apache 2.0*
