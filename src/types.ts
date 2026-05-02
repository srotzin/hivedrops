/**
 * @file types.ts
 * @description Core type definitions for HiveDrops — Merkle-rolled metering
 *   for usage-based settlement on agent infrastructure.
 *
 * C13 patent claim: "Merkle-Rolled Metering with Threshold Settlement and
 * Optional L2 Precompile Embodiment"
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

// ---------------------------------------------------------------------------
// Usage Events
// ---------------------------------------------------------------------------

/**
 * A single metered usage event produced by an agent on behalf of a consumer.
 *
 * The `sig` field is an ed25519 signature (base64url-encoded) over the
 * canonical JSON serialization of the event WITHOUT the `sig` field.
 * The canonical form is produced by `canonicalizeEvent()` in event.ts.
 *
 * `totalMicroUsdc` MUST equal `meterUnits * unitPriceMicroUsdc`. This
 * invariant is checked by the `wrong-price` challenge type.
 *
 * `nonce` is a random hex string (≥ 16 bytes) to prevent replay attacks
 * within a batch even when identical (agentDid, consumerDid, service) tuples
 * recur across very short intervals.
 */
export interface UsageEvent {
  /** Globally unique event identifier (UUID v4 or similar). */
  eventId: string;
  /** DID of the agent that performed the work. */
  agentDid: string;
  /** DID of the consuming entity billed for the work. */
  consumerDid: string;
  /** Human-readable service name (e.g. "llm.completion", "search.web"). */
  service: string;
  /** Number of metered units consumed (API calls, tokens, seconds, etc.). */
  meterUnits: number;
  /** Price per unit in micro-USDC (1 USDC = 1,000,000 micro-USDC). */
  unitPriceMicroUsdc: number;
  /**
   * Total charge in micro-USDC. MUST satisfy:
   *   totalMicroUsdc === meterUnits * unitPriceMicroUsdc
   */
  totalMicroUsdc: number;
  /** RFC3339 timestamp of the event (e.g. "2026-01-15T10:30:00.000Z"). */
  ts: string;
  /** Random hex nonce (≥ 32 hex chars = 16 bytes). */
  nonce: string;
  /**
   * ed25519 signature (base64url, no padding) over the canonical event bytes.
   * The signature covers all fields EXCEPT `sig` itself.
   */
  sig: string;
}

// ---------------------------------------------------------------------------
// Merkle Inclusion Proof
// ---------------------------------------------------------------------------

/**
 * A Merkle inclusion proof for a leaf in a `UsageMerkleTree`.
 *
 * Domain separation:
 *   Leaf hash:  SHA-256(0x00 || leafBytes)
 *   Node hash:  SHA-256(0x01 || leftChild || rightChild)
 *
 * The tree is insertion-ordered (NOT sorted). Leaves at indices beyond the
 * original event count are duplicates of the last real leaf, padded to the
 * next power of 2.
 */
export interface MerkleInclusionProof {
  /** Index of this leaf in the original (padded) tree. */
  leafIndex: number;
  /** Total number of leaves in the padded tree (always a power of 2). */
  treeSize: number;
  /** The raw leaf hash (hex) — SHA-256(0x00 || canonicalEventBytes). */
  leafHash: string;
  /**
   * Sibling hashes from leaf level up to root (not including root).
   * Each entry indicates which side the proof node is on.
   */
  path: Array<{ sibling: string /* hex */; position: "left" | "right" }>;
}

// ---------------------------------------------------------------------------
// Merkle Anchor (the on-chain commitment)
// ---------------------------------------------------------------------------

/**
 * A sealed batch of usage events committed to on-chain by the operator.
 *
 * The anchor is signed by the operator (ed25519) over the canonical
 * serialization of all fields EXCEPT `operatorSig`. This allows any
 * observer to verify that the operator committed to a specific root,
 * event count, and total amount without trusting the operator's honesty.
 *
 * USDC contract on Base: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
 * Treasury address:       0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E
 */
export interface MerkleAnchor {
  /** Unique batch identifier (UUID v4 or similar). */
  batchId: string;
  /** Hex-encoded Merkle root of all events in this batch. */
  merkleRoot: string;
  /** Number of real events in this batch (not counting padding leaves). */
  eventCount: number;
  /** Sum of all `totalMicroUsdc` values in the batch. */
  totalMicroUsdc: number;
  /** RFC3339 timestamp of the first event in the batch. */
  periodStart: string;
  /** RFC3339 timestamp of the last event in the batch. */
  periodEnd: string;
  /** EVM chain ID (e.g. 8453 for Base mainnet). */
  chainId: number;
  /**
   * Transaction hash of the on-chain anchor call (if submitted).
   * Absent when the anchor has not yet been submitted.
   */
  anchorTxHash?: string;
  /**
   * ed25519 signature (base64url) by the operator over the canonical
   * anchor bytes (all fields excluding `operatorSig`).
   */
  operatorSig: string;
}

// ---------------------------------------------------------------------------
// Challenge
// ---------------------------------------------------------------------------

/**
 * A challenge submitted against a published MerkleAnchor.
 *
 * A successful challenge proves that the anchor's claimed merkleRoot,
 * eventCount, or totalMicroUsdc is inconsistent with at least one
 * of the events it claims to cover.
 *
 * Challenge types:
 *   - "double-count":  The same eventId appears at two distinct leaf indices
 *                      in the same batch (operator counted work twice).
 *   - "wrong-price":   An event's totalMicroUsdc ≠ meterUnits * unitPriceMicroUsdc.
 *   - "missing":       An event known to the consumer is absent from the tree.
 *                      NOTE: full non-membership proofs are deferred; see
 *                      @hivecivilization/prov-absence for a sorted side-tree
 *                      implementation.
 *   - "forged-sig":    An event in the tree has an invalid agent signature,
 *                      meaning the operator may have fabricated or mutated it.
 */
export interface Challenge {
  /** The batch being challenged. */
  batchId: string;
  /** The specific event being challenged. */
  eventId: string;
  /** The type of contradiction being alleged. */
  claim: "double-count" | "wrong-price" | "missing" | "forged-sig";
  /**
   * Merkle inclusion proof for the event (or first of two proofs for
   * double-count; the second is carried in `siblingProof`).
   */
  proof: MerkleInclusionProof;
  /**
   * For "double-count": a second inclusion proof showing the same eventId
   * at a different leaf index.
   */
  siblingProof?: MerkleInclusionProof;
  /**
   * What the challenger expected to see (subset of UsageEvent fields).
   * Used for "wrong-price" to carry the expected `totalMicroUsdc`.
   */
  expected: Partial<UsageEvent>;
  /**
   * What was actually observed in the anchor / event (subset of UsageEvent fields).
   */
  observed: Partial<UsageEvent>;
  /**
   * The full event payload being challenged (required for forged-sig,
   * wrong-price, and double-count; optional for missing).
   */
  event?: UsageEvent;
}

// ---------------------------------------------------------------------------
// Settlement
// ---------------------------------------------------------------------------

/**
 * A computed settlement breakdown derived from a MerkleAnchor.
 */
export interface SettlementBreakdown {
  batchId: string;
  totalMicroUsdc: number;
  agentMicroUsdc: number;
  treasuryMicroUsdc: number;
  consumerRebateMicroUsdc: number;
  splitBps: {
    agent: number;
    treasury: number;
    consumer_rebate: number;
  };
}

/**
 * A single on-chain transfer instruction.
 * An external executor (the on-chain settlement contract) would broadcast
 * these as USDC.transferFrom() calls.
 */
export interface SettlementTx {
  /** Recipient EVM address or DID-resolved address. */
  to: string;
  /** Amount to transfer in micro-USDC. */
  amountMicroUsdc: number;
  /** Human-readable memo for record-keeping. */
  memo: string;
}

// ---------------------------------------------------------------------------
// Anchor function type (the L2 integration point)
// ---------------------------------------------------------------------------

/**
 * Function signature for the L2 anchor submission function.
 *
 * In production this would call the HiveDrops anchor contract on Base.
 * In tests and the reference implementation this is replaced by
 * `stubAnchorFn` from anchor-stub.ts.
 *
 * @param root       Hex-encoded Merkle root.
 * @param totalAmount  Total micro-USDC settled in this batch.
 * @param batchId    The batch identifier string.
 * @returns          Transaction hash string (0x-prefixed).
 */
export type AnchorFn = (
  root: string,
  totalAmount: number,
  batchId: string
) => Promise<string>;

// ---------------------------------------------------------------------------
// Challenge result
// ---------------------------------------------------------------------------

export interface ChallengeResult {
  valid: boolean;
  reason: string;
  severity: "fatal" | "advisory";
}

// ---------------------------------------------------------------------------
// Accumulator config
// ---------------------------------------------------------------------------

export interface AccumulatorConfig {
  /** How long (ms) before an open batch is force-anchored. */
  periodMs: number;
  /** Micro-USDC accumulation threshold that triggers early anchoring. */
  thresholdMicroUsdc: number;
  /** Operator's ed25519 public key (32 bytes). */
  operatorPubKey: Uint8Array;
  /** Operator's ed25519 private key (32 bytes seed). */
  operatorPrivKey: Uint8Array;
  /** Chain ID to embed in anchors (default: 8453 for Base). */
  chainId?: number;
}

// ---------------------------------------------------------------------------
// Batch info (in-flight)
// ---------------------------------------------------------------------------

export interface BatchInfo {
  batchId: string;
  eventCount: number;
  totalMicroUsdc: number;
  /** Hex-encoded root of current in-flight batch (without padding). */
  tentativeRoot: string | null;
  periodStart: string;
}
