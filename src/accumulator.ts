/**
 * @file accumulator.ts
 * @description Rolling usage accumulator with Merkle-batched anchoring.
 *
 * The UsageAccumulator collects usage events into batches and automatically
 * anchors (closes + commits) each batch when EITHER of two conditions is met:
 *   1. The configured `periodMs` has elapsed since the batch opened.
 *   2. The accumulated `totalMicroUsdc` has crossed `thresholdMicroUsdc`.
 *
 * Whichever condition triggers first wins. This is the "threshold settlement"
 * in the C13 claim: high-volume periods settle faster; low-volume periods
 * settle on a time cadence.
 *
 * Anchoring calls the injected `anchorFn` (see anchor-stub.ts for the stub;
 * replace with a live L2 client for production). The anchor is signed by the
 * operator's ed25519 key over the canonical anchor bytes (all fields except
 * `operatorSig`).
 *
 * Timer note: Real-timer auto-anchoring uses setInterval internally. For
 * deterministic tests, call `tick(nowMs)` directly rather than relying on
 * the wall clock. The `tick()` method is idempotent if no anchoring is due.
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import * as ed from "@noble/ed25519";
import { v4 as uuidv4 } from "./uuid.js";
import { canonicalizeEventForSigning, bytesToBase64Url, bytesToHex } from "./event.js";
import { UsageMerkleTree } from "./merkle.js";
import type {
  UsageEvent,
  MerkleAnchor,
  AccumulatorConfig,
  BatchInfo,
  AnchorFn,
} from "./types.js";

// ---------------------------------------------------------------------------
// Canonical anchor serialization (for operator signing)
// ---------------------------------------------------------------------------

/**
 * Produces a deterministic JSON string of a MerkleAnchor, excluding
 * the `operatorSig` field. Used as the preimage for the operator's signature.
 */
function canonicalizeAnchorForSigning(
  anchor: Omit<MerkleAnchor, "operatorSig">
): string {
  const keys: Array<keyof Omit<MerkleAnchor, "operatorSig">> = [
    "anchorTxHash",
    "batchId",
    "chainId",
    "eventCount",
    "merkleRoot",
    "periodEnd",
    "periodStart",
    "totalMicroUsdc",
  ];
  const ordered: Record<string, unknown> = {};
  for (const key of keys) {
    if (anchor[key] !== undefined) {
      ordered[key] = anchor[key];
    }
  }
  return JSON.stringify(ordered);
}

// ---------------------------------------------------------------------------
// UsageAccumulator
// ---------------------------------------------------------------------------

export class UsageAccumulator {
  private config: AccumulatorConfig & { chainId: number };
  private anchorFn: AnchorFn;

  // Current open batch
  private currentTree: UsageMerkleTree;
  private batchId: string;
  private batchStartMs: number;
  private batchTotal: number;
  private periodStart: string;

  // Closed anchors (immutable once sealed)
  private closedAnchors: Map<string, MerkleAnchor> = new Map();
  // Closed trees (for proof generation on historical batches)
  private closedTrees: Map<string, UsageMerkleTree> = new Map();

  // Whether any batch was sealed after a call to anchor()
  private lastAnchoredAt: number = 0;

  // Optional timer handle (real-clock mode)
  private timerHandle: ReturnType<typeof setInterval> | null = null;

  // Optional persistence hook
  private onAnchor?: (anchor: MerkleAnchor) => Promise<void> | void;

  /**
   * Constructs a new UsageAccumulator.
   *
   * @param config     Accumulator configuration (period, threshold, keys).
   * @param anchorFn   Function to call when anchoring a batch (stub or live).
   * @param clockMs    Optional clock function (defaults to Date.now). Override
   *                   in tests for deterministic time control.
   * @param onAnchor   Optional persistence hook called after each anchor.
   */
  constructor(
    config: AccumulatorConfig,
    anchorFn: AnchorFn,
    private clockMs: () => number = () => Date.now(),
    onAnchorHook?: (anchor: MerkleAnchor) => Promise<void> | void
  ) {
    this.config = { chainId: 8453, ...config };
    this.anchorFn = anchorFn;
    this.onAnchor = onAnchorHook;

    // Initialize first batch
    this.currentTree = new UsageMerkleTree();
    this.batchId = uuidv4();
    this.batchStartMs = this.clockMs();
    this.batchTotal = 0;
    this.periodStart = new Date(this.batchStartMs).toISOString();
  }

  // -------------------------------------------------------------------------
  // Real-timer mode (not used in tests)
  // -------------------------------------------------------------------------

  /**
   * Starts the real-clock interval timer that calls `tick()` periodically.
   * NOT suitable for tests — use `tick(nowMs)` directly instead.
   */
  startTimer(): void {
    if (this.timerHandle !== null) return;
    const checkInterval = Math.min(this.config.periodMs / 10, 5000);
    this.timerHandle = setInterval(() => {
      this.tick(this.clockMs()).catch((err) => {
        console.error("[UsageAccumulator] tick error:", err);
      });
    }, checkInterval);
  }

  /**
   * Stops the real-clock interval timer.
   */
  stopTimer(): void {
    if (this.timerHandle !== null) {
      clearInterval(this.timerHandle);
      this.timerHandle = null;
    }
  }

  // -------------------------------------------------------------------------
  // Core API
  // -------------------------------------------------------------------------

  /**
   * Adds a usage event to the current open batch.
   *
   * After adding, checks if the threshold has been crossed. If so, immediately
   * anchors the current batch (threshold-triggered anchoring).
   *
   * @param event The signed usage event to add.
   * @throws If the current batch has already been sealed (should not happen
   *         under normal use; the accumulator always opens a new batch after
   *         anchoring).
   */
  async addEvent(event: UsageEvent): Promise<void> {
    this.currentTree.add(event);
    this.batchTotal += event.totalMicroUsdc;

    // Check threshold-triggered anchoring
    if (this.batchTotal >= this.config.thresholdMicroUsdc) {
      await this.anchor();
    }
  }

  /**
   * Explicit time tick — checks whether the current batch should be anchored
   * based on elapsed time. Designed for use in tests with an injected clock.
   *
   * @param nowMs Current time in milliseconds. Defaults to `this.clockMs()`.
   */
  async tick(nowMs?: number): Promise<void> {
    const now = nowMs ?? this.clockMs();
    if (now - this.batchStartMs >= this.config.periodMs) {
      await this.anchor(now);
    }
  }

  /**
   * Closes the current batch, computes its Merkle root, signs the anchor,
   * calls the anchor function, and opens a new empty batch.
   *
   * This is idempotent in the sense that calling it on an already-sealed
   * batch is a no-op (a new batch should already be open).
   *
   * @param nowMs Optional current time in ms (defaults to clockMs()).
   * @returns     The sealed MerkleAnchor.
   */
  async anchor(nowMs?: number): Promise<MerkleAnchor> {
    const now = nowMs ?? this.clockMs();

    // Seal the current tree
    const tree = this.currentTree;
    tree.seal();

    const root = tree.root();
    const eventCount = tree.size();
    const periodEnd = new Date(now).toISOString();

    // Call the anchor function (stub or real)
    const anchorTxHash = await this.anchorFn(root, this.batchTotal, this.batchId);

    // Build the unsigned anchor (no operatorSig yet)
    const unsignedAnchor: Omit<MerkleAnchor, "operatorSig"> = {
      batchId: this.batchId,
      merkleRoot: root,
      eventCount,
      totalMicroUsdc: this.batchTotal,
      periodStart: this.periodStart,
      periodEnd,
      chainId: this.config.chainId,
      anchorTxHash,
    };

    // Sign the anchor with the operator's key
    const canonical = canonicalizeAnchorForSigning(unsignedAnchor);
    const canonicalBytes = new TextEncoder().encode(canonical);
    const sigBytes = await ed.signAsync(canonicalBytes, this.config.operatorPrivKey);
    const operatorSig = bytesToBase64Url(sigBytes);

    const anchor: MerkleAnchor = { ...unsignedAnchor, operatorSig };

    // Store the closed anchor and tree
    this.closedAnchors.set(this.batchId, anchor);
    this.closedTrees.set(this.batchId, tree);

    this.lastAnchoredAt = now;

    // Call persistence hook if provided
    if (this.onAnchor) {
      await this.onAnchor(anchor);
    }

    // Open a fresh batch
    this.currentTree = new UsageMerkleTree();
    this.batchId = uuidv4();
    this.batchStartMs = now;
    this.batchTotal = 0;
    this.periodStart = new Date(now).toISOString();

    return anchor;
  }

  // -------------------------------------------------------------------------
  // Accessors
  // -------------------------------------------------------------------------

  /**
   * Returns information about the current in-flight (not yet anchored) batch.
   */
  currentBatch(): BatchInfo {
    return {
      batchId: this.batchId,
      eventCount: this.currentTree.size(),
      totalMicroUsdc: this.batchTotal,
      tentativeRoot:
        this.currentTree.size() > 0 ? this.currentTree.root() : null,
      periodStart: this.periodStart,
    };
  }

  /**
   * Returns a copy of all closed (anchored) anchors.
   */
  getClosedAnchors(): MerkleAnchor[] {
    return Array.from(this.closedAnchors.values());
  }

  /**
   * Returns a specific closed anchor by batchId.
   */
  getAnchor(batchId: string): MerkleAnchor | undefined {
    return this.closedAnchors.get(batchId);
  }

  /**
   * Returns the closed Merkle tree for a given batchId (for proof generation).
   *
   * INTEGRATION POINT: In a production system, the trees would be serialized
   * to a database or IPFS. Here they are kept in-memory.
   */
  getTree(batchId: string): UsageMerkleTree | undefined {
    return this.closedTrees.get(batchId);
  }

  /**
   * Returns the number of closed batches.
   */
  closedBatchCount(): number {
    return this.closedAnchors.size;
  }
}

// ---------------------------------------------------------------------------
// Re-export canonicalize for use in challenge.ts
// ---------------------------------------------------------------------------
export { canonicalizeAnchorForSigning };
