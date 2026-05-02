/**
 * @file merkle.ts
 * @description Insertion-ordered Merkle tree for HiveDrops usage batches.
 *
 * Design decisions:
 *   1. INSERTION-ORDERED (not sorted). Events are time-ordered; sorting would
 *      destroy the temporal audit trail. Provers must reference leaf indices.
 *
 *   2. DOMAIN-SEPARATED hashes:
 *      - Leaf:  SHA-256(0x00 || leafBytes)      (0x00 = leaf prefix)
 *      - Node:  SHA-256(0x01 || left || right)  (0x01 = node prefix)
 *      This prevents second-preimage attacks where an internal node could be
 *      confused with a leaf.
 *
 *   3. PADDING: The tree is always padded to the next power of 2 by duplicating
 *      the last real leaf. This is consistent with RFC-style Merkle trees used
 *      in Certificate Transparency (RFC 6962). The eventCount stored in the
 *      anchor records the REAL event count, not the padded count.
 *
 *   4. EMPTY TREE: A tree with zero events has root = SHA-256(0x00) as a
 *      sentinel value. In practice, batches with zero events are never anchored.
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import { sha256 } from "@noble/hashes/sha256";
import { eventHash, bytesToHex, hexToBytes } from "./event.js";
import type { UsageEvent, MerkleInclusionProof } from "./types.js";

// ---------------------------------------------------------------------------
// Low-level hash primitives
// ---------------------------------------------------------------------------

/**
 * Computes a Merkle leaf hash.
 * Domain separation: SHA-256(0x00 || rawBytes)
 *
 * Note: `eventHash()` in event.ts already applies the 0x00 prefix internally,
 * so this function is used when you already HAVE the raw (un-prefixed) bytes.
 * For events, always call `eventHash(event)` directly.
 */
export function leafHash(raw: Uint8Array): Uint8Array {
  const prefixed = new Uint8Array(1 + raw.length);
  prefixed[0] = 0x00;
  prefixed.set(raw, 1);
  return sha256(prefixed);
}

/**
 * Computes a Merkle internal node hash.
 * Domain separation: SHA-256(0x01 || left(32) || right(32))
 */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  const prefixed = new Uint8Array(1 + left.length + right.length);
  prefixed[0] = 0x01;
  prefixed.set(left, 1);
  prefixed.set(right, 1 + left.length);
  return sha256(prefixed);
}

// ---------------------------------------------------------------------------
// Helper: next power of 2
// ---------------------------------------------------------------------------

function nextPow2(n: number): number {
  if (n <= 0) return 1;
  let p = 1;
  while (p < n) p <<= 1;
  return p;
}

// ---------------------------------------------------------------------------
// verifyProof — pure function
// ---------------------------------------------------------------------------

/**
 * Verifies a Merkle inclusion proof against a known root.
 *
 * @param proof  The inclusion proof (from `proveByIndex` or `proveByEventId`).
 * @param root   Hex-encoded expected Merkle root.
 * @returns      `true` if the proof is valid.
 */
export function verifyProof(
  proof: MerkleInclusionProof,
  root: string
): boolean {
  try {
    let current = hexToBytes(proof.leafHash);
    for (const step of proof.path) {
      const sibling = hexToBytes(step.sibling);
      if (step.position === "left") {
        // sibling is on the left → sibling || current
        current = nodeHash(sibling, current);
      } else {
        // sibling is on the right → current || sibling
        current = nodeHash(current, sibling);
      }
    }
    return bytesToHex(current) === root;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// UsageMerkleTree
// ---------------------------------------------------------------------------

/**
 * An insertion-ordered Merkle tree for HiveDrops usage events.
 *
 * Usage pattern:
 *   const tree = new UsageMerkleTree();
 *   tree.add(event1);
 *   tree.add(event2);
 *   const root = tree.root();          // only computed when needed
 *   const proof = tree.proveByIndex(0);
 *   verifyProof(proof, root);          // → true
 *
 * The tree is MUTABLE until `seal()` is called (or until `root()` is first
 * called — calling root() does NOT seal it). The accumulator calls `seal()`
 * when a batch is anchored; subsequent `add()` calls throw.
 */
export class UsageMerkleTree {
  /** Ordered list of events (real, not padded). */
  private events: UsageEvent[] = [];
  /** Ordered list of leaf hashes corresponding to `events`. */
  private leafHashes: Uint8Array[] = [];
  /** Index mapping eventId → leaf index. */
  private eventIdIndex: Map<string, number> = new Map();
  /** Whether this tree has been sealed. */
  private sealed = false;

  // -------------------------------------------------------------------------
  // Mutation
  // -------------------------------------------------------------------------

  /**
   * Adds a usage event to the tree.
   * @throws If the tree has been sealed.
   */
  add(event: UsageEvent): void {
    if (this.sealed) {
      throw new Error(
        `UsageMerkleTree is sealed (batch already anchored). Cannot add event ${event.eventId}.`
      );
    }
    const idx = this.events.length;
    this.events.push(event);
    this.leafHashes.push(eventHash(event));
    this.eventIdIndex.set(event.eventId, idx);
  }

  /**
   * Seals the tree, preventing further additions.
   * Called automatically by the accumulator when a batch is anchored.
   */
  seal(): void {
    this.sealed = true;
  }

  // -------------------------------------------------------------------------
  // Root computation
  // -------------------------------------------------------------------------

  /**
   * Computes and returns the Merkle root of the current event set.
   *
   * The tree is padded to the next power of 2 by duplicating the last leaf.
   * An empty tree returns a fixed sentinel root (SHA-256(0x00 || 0x00)).
   *
   * This is called lazily and is NOT cached (to keep the implementation
   * simple; for production use a cached/dirty-flag approach).
   */
  root(): string {
    const n = this.leafHashes.length;
    if (n === 0) {
      // Sentinel: empty batch should never be anchored, but return a defined value.
      return bytesToHex(sha256(new Uint8Array([0x00, 0x00])));
    }
    const padded = this._paddedLeaves();
    return bytesToHex(this._buildRoot(padded));
  }

  // -------------------------------------------------------------------------
  // Proofs
  // -------------------------------------------------------------------------

  /**
   * Generates a Merkle inclusion proof for the event at `index`.
   *
   * @param index Zero-based leaf index into the REAL (unpadded) event list.
   * @throws If `index` is out of range.
   */
  proveByIndex(index: number): MerkleInclusionProof {
    if (index < 0 || index >= this.leafHashes.length) {
      throw new Error(
        `Index ${index} out of range [0, ${this.leafHashes.length}).`
      );
    }
    return this._buildProof(index);
  }

  /**
   * Generates a Merkle inclusion proof for the event with the given eventId.
   *
   * @param eventId The eventId to look up.
   * @throws If `eventId` is not found in this tree.
   */
  proveByEventId(eventId: string): MerkleInclusionProof {
    const idx = this.eventIdIndex.get(eventId);
    if (idx === undefined) {
      throw new Error(`Event ${eventId} not found in this tree.`);
    }
    return this._buildProof(idx);
  }

  // -------------------------------------------------------------------------
  // Accessors
  // -------------------------------------------------------------------------

  /** Returns the number of REAL events (not padded). */
  size(): number {
    return this.events.length;
  }

  /** Returns whether the tree is sealed. */
  isSealed(): boolean {
    return this.sealed;
  }

  /** Returns a copy of the events list. */
  getEvents(): ReadonlyArray<UsageEvent> {
    return [...this.events];
  }

  /** Returns the leaf hash (hex) at the given index. */
  getLeafHash(index: number): string {
    if (index < 0 || index >= this.leafHashes.length) {
      throw new Error(`Index ${index} out of range.`);
    }
    return bytesToHex(this.leafHashes[index]);
  }

  /** Returns whether the given eventId has been added. */
  hasEventId(eventId: string): boolean {
    return this.eventIdIndex.has(eventId);
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Returns the padded leaf array (always a power of 2 in length).
   * Padding = duplicate the last real leaf.
   */
  private _paddedLeaves(): Uint8Array[] {
    const n = this.leafHashes.length;
    if (n === 0) return [];
    const size = nextPow2(n);
    const padded: Uint8Array[] = [...this.leafHashes];
    const last = this.leafHashes[n - 1];
    while (padded.length < size) padded.push(last);
    return padded;
  }

  /**
   * Builds the Merkle root from a padded leaf array.
   * Iteratively computes parent levels.
   */
  private _buildRoot(leaves: Uint8Array[]): Uint8Array {
    if (leaves.length === 0) throw new Error("Cannot build root of empty tree");
    let level = leaves;
    while (level.length > 1) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(nodeHash(level[i], level[i + 1]));
      }
      level = next;
    }
    return level[0];
  }

  /**
   * Builds the full node-level representation of the tree.
   * Returns an array of levels: levels[0] = leaves, levels[last] = [root].
   */
  private _buildLevels(leaves: Uint8Array[]): Uint8Array[][] {
    const levels: Uint8Array[][] = [leaves];
    let current = leaves;
    while (current.length > 1) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < current.length; i += 2) {
        next.push(nodeHash(current[i], current[i + 1]));
      }
      levels.push(next);
      current = next;
    }
    return levels;
  }

  /**
   * Builds a Merkle inclusion proof for the leaf at `index`.
   */
  private _buildProof(index: number): MerkleInclusionProof {
    const padded = this._paddedLeaves();
    const treeSize = padded.length;
    const levels = this._buildLevels(padded);

    const path: Array<{ sibling: string; position: "left" | "right" }> = [];
    let currentIdx = index;

    for (let level = 0; level < levels.length - 1; level++) {
      const levelNodes = levels[level];
      let siblingIdx: number;
      let position: "left" | "right";

      if (currentIdx % 2 === 0) {
        // Current node is on the left; sibling is on the right.
        siblingIdx = currentIdx + 1;
        position = "right";
      } else {
        // Current node is on the right; sibling is on the left.
        siblingIdx = currentIdx - 1;
        position = "left";
      }

      path.push({
        sibling: bytesToHex(levelNodes[siblingIdx]),
        position,
      });

      currentIdx = Math.floor(currentIdx / 2);
    }

    return {
      leafIndex: index,
      treeSize,
      leafHash: bytesToHex(this.leafHashes[index]),
      path,
    };
  }
}
