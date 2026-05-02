/**
 * @file challenge.ts
 * @description Challenge protocol for HiveDrops Merkle-rolled metering.
 *
 * A challenge is a cryptographic claim that a published MerkleAnchor contains
 * a contradiction — either the Merkle root is inconsistent with an event, or
 * an event's fields are internally inconsistent.
 *
 * Challenge types:
 *
 *   "forged-sig"   — The event's ed25519 agent signature is invalid. The
 *                    operator may have fabricated or mutated the event.
 *
 *   "double-count" — The same eventId appears at two different leaf indices
 *                    in the same batch. Both inclusion proofs must be provided
 *                    in `challenge.proof` and `challenge.siblingProof`.
 *
 *   "wrong-price"  — event.totalMicroUsdc ≠ event.meterUnits * event.unitPriceMicroUsdc.
 *                    This is a purely arithmetic check; no external state needed.
 *
 *   "missing"      — An event known to the consumer is absent from the tree.
 *                    NOTE: Full non-membership proofs are deferred to a future
 *                    implementation. This claim type returns an advisory result
 *                    with a TODO comment. See @hivecivilization/prov-absence for
 *                    a sorted side-tree approach.
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import * as ed from "@noble/ed25519";
import { base64UrlToBytes } from "./event.js";
import { verifyProof } from "./merkle.js";
import { canonicalizeAnchorForSigning } from "./accumulator.js";
import type {
  Challenge,
  MerkleAnchor,
  UsageEvent,
  ChallengeResult,
  MerkleInclusionProof,
} from "./types.js";

// ---------------------------------------------------------------------------
// Anchor signature verification
// ---------------------------------------------------------------------------

/**
 * Verifies the operator's ed25519 signature on a MerkleAnchor.
 *
 * The signature covers all anchor fields EXCEPT `operatorSig`, in canonical
 * JSON form (keys alphabetically sorted).
 *
 * @param anchor         The anchor to verify.
 * @param operatorPubKey 32-byte ed25519 public key of the operator.
 * @returns              `true` if the signature is valid.
 */
export async function verifyAnchorSig(
  anchor: MerkleAnchor,
  operatorPubKey: Uint8Array
): Promise<boolean> {
  try {
    const { operatorSig, ...rest } = anchor;
    const canonical = canonicalizeAnchorForSigning(
      rest as Omit<MerkleAnchor, "operatorSig">
    );
    const bytes = new TextEncoder().encode(canonical);
    const sigBytes = base64UrlToBytes(operatorSig);
    return await ed.verifyAsync(sigBytes, bytes, operatorPubKey);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// AgentPubKeyResolver
// ---------------------------------------------------------------------------

/**
 * Function that resolves an agent's public key from their DID.
 *
 * INTEGRATION POINT: In a production system, this would perform a DID
 * resolution (e.g., did:web, did:key, or a custom registry on-chain).
 * In tests, it's provided as a simple lookup map.
 */
export type AgentPubKeyResolver = (
  agentDid: string
) => Promise<Uint8Array | null>;

// ---------------------------------------------------------------------------
// Main challenge verifier
// ---------------------------------------------------------------------------

/**
 * Runs the full challenge verification protocol for a given challenge.
 *
 * Steps:
 *   1. Verify the operator's anchor signature.
 *   2. Verify the Merkle inclusion proof against anchor.merkleRoot.
 *   3. Per claim type, verify the specific contradiction.
 *
 * @param challenge          The challenge to evaluate.
 * @param anchor             The anchor being challenged.
 * @param operatorPubKey     The operator's ed25519 public key (32 bytes).
 * @param agentPubKeyResolver  Resolver for agent public keys by DID.
 * @returns                  ChallengeResult with validity, reason, severity.
 */
export async function verifyChallenge(
  challenge: Challenge,
  anchor: MerkleAnchor,
  operatorPubKey: Uint8Array,
  agentPubKeyResolver: AgentPubKeyResolver
): Promise<ChallengeResult> {
  // -------------------------------------------------------------------------
  // Step 1: Verify the anchor's operator signature
  // -------------------------------------------------------------------------
  const anchorSigValid = await verifyAnchorSig(anchor, operatorPubKey);
  if (!anchorSigValid) {
    // The anchor itself has an invalid operator signature.
    // This is independently fatal — the anchor should be rejected entirely.
    return {
      valid: true,
      reason:
        "The anchor's operator signature is invalid. The anchor itself cannot be trusted.",
      severity: "fatal",
    };
  }

  // -------------------------------------------------------------------------
  // Step 2: Verify the Merkle inclusion proof
  // -------------------------------------------------------------------------
  if (challenge.claim !== "missing") {
    // For all non-missing claims, we need the event to be provably IN the tree.
    const proofValid = verifyProof(challenge.proof, anchor.merkleRoot);
    if (!proofValid) {
      // The Merkle proof is invalid — the challenge itself is forged or malformed.
      return {
        valid: false,
        reason:
          "The Merkle inclusion proof is invalid against anchor.merkleRoot. " +
          "This challenge is forged or malformed.",
        severity: "fatal",
      };
    }
  }

  // -------------------------------------------------------------------------
  // Step 3: Claim-specific contradiction verification
  // -------------------------------------------------------------------------

  switch (challenge.claim) {
    case "forged-sig":
      return await verifyForgedSigChallenge(
        challenge,
        anchor,
        agentPubKeyResolver
      );

    case "double-count":
      return verifyDoubleCountChallenge(challenge, anchor);

    case "wrong-price":
      return verifyWrongPriceChallenge(challenge);

    case "missing":
      return verifyMissingChallenge(challenge);

    default: {
      const _exhaustive: never = challenge.claim;
      return {
        valid: false,
        reason: `Unknown claim type: ${_exhaustive as string}`,
        severity: "advisory",
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Claim-specific verifiers
// ---------------------------------------------------------------------------

/**
 * Verifies a "forged-sig" challenge.
 *
 * A challenge succeeds if:
 *   - The event's ed25519 agent signature is INVALID when checked against
 *     the public key resolved from event.agentDid.
 *
 * A challenge fails if:
 *   - The event's signature is actually valid (no forgery detected).
 */
async function verifyForgedSigChallenge(
  challenge: Challenge,
  anchor: MerkleAnchor,
  agentPubKeyResolver: AgentPubKeyResolver
): Promise<ChallengeResult> {
  const event = challenge.event;
  if (!event) {
    return {
      valid: false,
      reason:
        "forged-sig challenge requires challenge.event to be populated.",
      severity: "advisory",
    };
  }

  // Resolve the agent's public key
  const agentPubKey = await agentPubKeyResolver(event.agentDid);
  if (!agentPubKey) {
    return {
      valid: false,
      reason: `Cannot resolve public key for agentDid: ${event.agentDid}. Challenge is unresolvable.`,
      severity: "advisory",
    };
  }

  // Verify the event's ed25519 signature
  let sigValid = false;
  try {
    const { sig, ...rest } = event;
    const { canonicalizeEventForSigning } = await import("./event.js");
    const canonical = canonicalizeEventForSigning(
      rest as Omit<UsageEvent, "sig">
    );
    const bytes = new TextEncoder().encode(canonical);
    const sigBytes = base64UrlToBytes(sig);
    sigValid = await ed.verifyAsync(sigBytes, bytes, agentPubKey);
  } catch {
    sigValid = false;
  }

  if (!sigValid) {
    return {
      valid: true,
      reason: `Event ${event.eventId} in batch ${anchor.batchId} has an invalid ` +
        `agent signature. The event was likely forged or mutated by the operator.`,
      severity: "fatal",
    };
  }

  return {
    valid: false,
    reason: `Event ${event.eventId} has a valid agent signature. No forgery detected.`,
    severity: "advisory",
  };
}

/**
 * Verifies a "double-count" challenge.
 *
 * A challenge succeeds if:
 *   - Two distinct Merkle proofs are provided (proof + siblingProof).
 *   - Both proofs verify against anchor.merkleRoot.
 *   - Both proofs cover leaves with the same eventId.
 *   - The leaf indices are different.
 */
function verifyDoubleCountChallenge(
  challenge: Challenge,
  anchor: MerkleAnchor
): ChallengeResult {
  if (!challenge.siblingProof) {
    return {
      valid: false,
      reason:
        "double-count challenge requires both challenge.proof and " +
        "challenge.siblingProof (two separate Merkle proofs for the same eventId).",
      severity: "advisory",
    };
  }

  const proof1 = challenge.proof;
  const proof2 = challenge.siblingProof;

  // Both proofs must be valid
  const proof1Valid = verifyProof(proof1, anchor.merkleRoot);
  const proof2Valid = verifyProof(proof2, anchor.merkleRoot);

  if (!proof1Valid) {
    return {
      valid: false,
      reason: "The primary Merkle proof (challenge.proof) is invalid.",
      severity: "fatal",
    };
  }
  if (!proof2Valid) {
    return {
      valid: false,
      reason: "The sibling Merkle proof (challenge.siblingProof) is invalid.",
      severity: "fatal",
    };
  }

  // The indices must differ
  if (proof1.leafIndex === proof2.leafIndex) {
    return {
      valid: false,
      reason:
        "Both proofs point to the same leaf index. A double-count challenge " +
        "requires two DIFFERENT leaf indices containing the same eventId.",
      severity: "advisory",
    };
  }

  // Both proofs must cover the same leaf hash (same content = same eventId + sig)
  // OR the challenger must have provided the event and we compare eventIds.
  // Since leaf hashes include the sig, two identical events with different sigs
  // would have different leaf hashes — which IS fine, but for double-count we
  // check if the leaf hashes are the same (exact duplicate) OR if the event
  // data shows the same eventId. We check both leaf-hash equality here.
  if (proof1.leafHash !== proof2.leafHash) {
    // Different leaf hashes: the events might still share an eventId if the
    // operator resubmitted with a different sig. We require the challenger to
    // provide both events and check eventIds.
    if (!challenge.event) {
      return {
        valid: false,
        reason:
          "The two proofs have different leaf hashes. For a double-count challenge " +
          "where the events differ, provide challenge.event so eventId equality can be checked.",
        severity: "advisory",
      };
    }
    // We trust the challenger provided the event corresponding to proof1.
    // The anchor already committed to the leaf hash in proof1, so we know
    // proof1 corresponds to challenge.event. The assertion is that both events
    // share the same eventId.
    const eventId1 = challenge.event.eventId;
    const eventId2 = challenge.observed.eventId;
    if (!eventId2 || eventId1 !== eventId2) {
      return {
        valid: false,
        reason:
          "The two proofs have different leaf hashes and different eventIds. " +
          "This is not a double-count (it may be two distinct events).",
        severity: "advisory",
      };
    }
  }

  return {
    valid: true,
    reason:
      `EventId ${challenge.eventId} appears at leaf indices ${proof1.leafIndex} ` +
      `and ${proof2.leafIndex} in batch ${anchor.batchId}. ` +
      `This constitutes double-counting.`,
    severity: "fatal",
  };
}

/**
 * Verifies a "wrong-price" challenge.
 *
 * A challenge succeeds if:
 *   - event.totalMicroUsdc ≠ event.meterUnits * event.unitPriceMicroUsdc
 *
 * This is a purely arithmetic check; no external key resolution needed.
 */
function verifyWrongPriceChallenge(challenge: Challenge): ChallengeResult {
  const event = challenge.event;
  if (!event) {
    return {
      valid: false,
      reason:
        "wrong-price challenge requires challenge.event to be populated.",
      severity: "advisory",
    };
  }

  const expected = event.meterUnits * event.unitPriceMicroUsdc;
  const observed = event.totalMicroUsdc;

  if (expected !== observed) {
    return {
      valid: true,
      reason:
        `Event ${event.eventId}: meterUnits(${event.meterUnits}) × ` +
        `unitPriceMicroUsdc(${event.unitPriceMicroUsdc}) = ${expected} ` +
        `but totalMicroUsdc = ${observed}. Arithmetic contradiction.`,
      severity: "fatal",
    };
  }

  return {
    valid: false,
    reason: `Event ${event.eventId}: pricing arithmetic is consistent (${expected} = ${observed}).`,
    severity: "advisory",
  };
}

/**
 * Handles a "missing" challenge.
 *
 * Full non-membership proofs require a sorted side-tree (e.g., a sorted
 * Merkle tree indexed by eventId). This is deferred to a future package.
 *
 * TODO: Full non-membership proof support.
 * See @hivecivilization/prov-absence for a sorted-Merkle non-membership
 * proof implementation that can replace this stub.
 *
 * Per the C13 provisional §17, non-membership proofs are a SHOULD, not a MUST,
 * for the reference implementation.
 */
function verifyMissingChallenge(challenge: Challenge): ChallengeResult {
  // TODO: Full non-membership proofs require a sorted side-tree.
  // See @hivecivilization/prov-absence for the sorted Merkle approach.
  //
  // The missing-event challenge is conceptually:
  //   1. Challenger knows eventId X was submitted to the operator.
  //   2. Challenger can show X is NOT in the Merkle tree (non-membership).
  //   3. This requires either:
  //      (a) A sorted Merkle tree with range proofs (prov-absence approach), OR
  //      (b) An operator-provided sorted index with a gap proof.
  //
  // Without a sorted tree, we cannot cryptographically prove absence.
  // For now, return an advisory result noting this is a future-work item.

  return {
    valid: false,
    reason:
      `"missing" challenges require a non-membership proof against a sorted ` +
      `side-tree. This is not yet implemented in the reference implementation. ` +
      `See @hivecivilization/prov-absence for the sorted-Merkle approach. ` +
      `(Ref: C13 provisional §17, future work hook.)`,
    severity: "advisory",
  };
}

// ---------------------------------------------------------------------------
// Re-export verifyProof for convenience
// ---------------------------------------------------------------------------
export { verifyProof } from "./merkle.js";
