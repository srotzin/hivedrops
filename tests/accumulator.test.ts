/**
 * @file accumulator.test.ts
 * @description Tests for UsageAccumulator rolling batch logic.
 *
 * All tests use an injected clock (fakeClock) for deterministic time control.
 * No real timers are used.
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import * as ed from "@noble/ed25519";
import { UsageAccumulator } from "../src/accumulator.js";
import { verifyAnchorSig } from "../src/challenge.js";
import { verifyProof } from "../src/merkle.js";
import { signEvent } from "../src/event.js";
import { stubAnchorFn } from "../src/anchor-stub.js";
import type { UsageEvent, AnchorFn } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let operatorPrivKey: Uint8Array;
let operatorPubKey: Uint8Array;
let agentPrivKey: Uint8Array;

const PERIOD_MS = 60_000; // 60 seconds
const THRESHOLD_MICRO_USDC = 100_000_000; // 100 USDC

beforeAll(async () => {
  operatorPrivKey = ed.utils.randomPrivateKey();
  operatorPubKey = await ed.getPublicKeyAsync(operatorPrivKey);
  agentPrivKey = ed.utils.randomPrivateKey();
});

async function makeEvent(
  id: string,
  microUsdc: number = 1_000_000,
  tsMs: number = Date.now()
): Promise<UsageEvent> {
  const meterUnits = microUsdc;
  const unitPrice = 1;
  return signEvent(
    {
      eventId: id,
      agentDid: "did:hive:agent:acc-test",
      consumerDid: "did:hive:consumer:acc-test",
      service: "acc.test",
      meterUnits,
      unitPriceMicroUsdc: unitPrice,
      totalMicroUsdc: meterUnits * unitPrice,
      ts: new Date(tsMs).toISOString(),
      nonce: id.padEnd(32, "0").slice(0, 32),
    },
    agentPrivKey
  );
}

function makeAccumulator(
  fakeClock: { nowMs: number },
  anchorFn: AnchorFn = stubAnchorFn
): UsageAccumulator {
  return new UsageAccumulator(
    {
      periodMs: PERIOD_MS,
      thresholdMicroUsdc: THRESHOLD_MICRO_USDC,
      operatorPubKey,
      operatorPrivKey,
    },
    anchorFn,
    () => fakeClock.nowMs
  );
}

// ---------------------------------------------------------------------------
// Period-based anchoring
// ---------------------------------------------------------------------------

describe("period-based anchoring", () => {
  it("does not anchor before period elapses", async () => {
    const clock = { nowMs: 1_000_000 };
    const acc = makeAccumulator(clock);

    await acc.addEvent(await makeEvent("evt-period-1", 1_000, clock.nowMs));
    clock.nowMs += PERIOD_MS - 1;
    await acc.tick(clock.nowMs);

    expect(acc.closedBatchCount()).toBe(0);
  });

  it("anchors when period elapses via tick()", async () => {
    const clock = { nowMs: 2_000_000 };
    const acc = makeAccumulator(clock);

    await acc.addEvent(await makeEvent("evt-period-2", 1_000, clock.nowMs));
    clock.nowMs += PERIOD_MS;
    await acc.tick(clock.nowMs);

    expect(acc.closedBatchCount()).toBe(1);
    const anchors = acc.getClosedAnchors();
    expect(anchors[0].eventCount).toBe(1);
  });

  it("opens a fresh batch after period anchor", async () => {
    const clock = { nowMs: 3_000_000 };
    const acc = makeAccumulator(clock);

    await acc.addEvent(await makeEvent("evt-period-fresh-1", 1_000, clock.nowMs));
    clock.nowMs += PERIOD_MS;
    await acc.tick(clock.nowMs);

    // New batch should be empty
    const batch = acc.currentBatch();
    expect(batch.eventCount).toBe(0);
    expect(batch.totalMicroUsdc).toBe(0);
  });

  it("tracks multiple period-based anchors", async () => {
    const clock = { nowMs: 4_000_000 };
    const acc = makeAccumulator(clock);

    for (let i = 0; i < 3; i++) {
      await acc.addEvent(await makeEvent(`evt-multi-period-${i}`, 1_000, clock.nowMs));
      clock.nowMs += PERIOD_MS;
      await acc.tick(clock.nowMs);
    }

    expect(acc.closedBatchCount()).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Threshold-based anchoring
// ---------------------------------------------------------------------------

describe("threshold-based anchoring", () => {
  it("anchors immediately when threshold is crossed", async () => {
    const clock = { nowMs: 5_000_000 };
    const acc = makeAccumulator(clock);

    // Add events totaling just over threshold
    for (let i = 0; i < 10; i++) {
      await acc.addEvent(
        await makeEvent(`evt-thresh-${i}`, THRESHOLD_MICRO_USDC / 9, clock.nowMs)
      );
    }

    // threshold should have triggered
    expect(acc.closedBatchCount()).toBeGreaterThanOrEqual(1);
  });

  it("threshold anchor includes all events up to and including the triggering one", async () => {
    const clock = { nowMs: 6_000_000 };
    const acc = makeAccumulator(clock);

    // Add 9 events worth 10 USDC each (90 USDC total — under threshold)
    for (let i = 0; i < 9; i++) {
      await acc.addEvent(await makeEvent(`evt-under-${i}`, 10_000_000, clock.nowMs));
    }
    expect(acc.closedBatchCount()).toBe(0);

    // Add 1 more (100 USDC total — hits threshold exactly)
    await acc.addEvent(await makeEvent("evt-tip-over", 10_000_000, clock.nowMs));
    expect(acc.closedBatchCount()).toBe(1);

    const anchor = acc.getClosedAnchors()[0];
    expect(anchor.eventCount).toBe(10);
    expect(anchor.totalMicroUsdc).toBe(100_000_000);
  });
});

// ---------------------------------------------------------------------------
// Whichever-first semantics
// ---------------------------------------------------------------------------

describe("whichever-first semantics", () => {
  it("threshold fires before period when threshold crosses first", async () => {
    const clock = { nowMs: 7_000_000 };
    const acc = makeAccumulator(clock);

    // Immediately add events exceeding threshold
    for (let i = 0; i < 5; i++) {
      await acc.addEvent(await makeEvent(`evt-wf-t-${i}`, 25_000_000, clock.nowMs));
    }

    // Now advance time — but threshold already fired
    clock.nowMs += PERIOD_MS;
    await acc.tick(clock.nowMs);

    // Should have ≥ 1 anchor from threshold; the tick should open a second
    const count = acc.closedBatchCount();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  it("period fires before threshold when period elapses first", async () => {
    const clock = { nowMs: 8_000_000 };
    const acc = makeAccumulator(clock);

    // Add 1 small event (well under threshold)
    await acc.addEvent(await makeEvent("evt-wf-p-1", 100, clock.nowMs));

    // Advance clock past period
    clock.nowMs += PERIOD_MS + 1;
    await acc.tick(clock.nowMs);

    expect(acc.closedBatchCount()).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Multiple consecutive batches — continuity
// ---------------------------------------------------------------------------

describe("multiple consecutive batches", () => {
  it("each new batch gets a different batchId", async () => {
    const clock = { nowMs: 9_000_000 };
    const acc = makeAccumulator(clock);

    const batchIds = new Set<string>();
    for (let i = 0; i < 5; i++) {
      await acc.addEvent(await makeEvent(`evt-continuity-${i}`, 1_000, clock.nowMs));
      clock.nowMs += PERIOD_MS;
      await acc.tick(clock.nowMs);
      const anchors = acc.getClosedAnchors();
      batchIds.add(anchors[anchors.length - 1].batchId);
    }

    expect(batchIds.size).toBe(5);
  });

  it("anchor signatures are verifiable for all closed batches", async () => {
    const clock = { nowMs: 10_000_000 };
    const acc = makeAccumulator(clock);

    for (let i = 0; i < 3; i++) {
      await acc.addEvent(await makeEvent(`evt-sigscheck-${i}`, 1_000, clock.nowMs));
      clock.nowMs += PERIOD_MS;
      await acc.tick(clock.nowMs);
    }

    for (const anchor of acc.getClosedAnchors()) {
      const valid = await verifyAnchorSig(anchor, operatorPubKey);
      expect(valid).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// All events provable by index AND eventId
// ---------------------------------------------------------------------------

describe("event provability", () => {
  it("all events in a batch are provable by index", async () => {
    const clock = { nowMs: 11_000_000 };
    const acc = makeAccumulator(clock);

    const eventIds: string[] = [];
    for (let i = 0; i < 15; i++) {
      const id = `evt-provable-${i}`;
      await acc.addEvent(await makeEvent(id, 1_000, clock.nowMs));
      eventIds.push(id);
    }

    // Force anchor
    clock.nowMs += PERIOD_MS;
    await acc.tick(clock.nowMs);

    const anchor = acc.getClosedAnchors()[0];
    const tree = acc.getTree(anchor.batchId);
    expect(tree).toBeDefined();

    for (let i = 0; i < 15; i++) {
      const proof = tree!.proveByIndex(i);
      expect(verifyProof(proof, anchor.merkleRoot)).toBe(true);
    }
  });

  it("all events in a batch are provable by eventId", async () => {
    const clock = { nowMs: 12_000_000 };
    const acc = makeAccumulator(clock);

    const eventIds: string[] = [];
    for (let i = 0; i < 10; i++) {
      const id = `evt-eid-provable-${i}`;
      await acc.addEvent(await makeEvent(id, 1_000, clock.nowMs));
      eventIds.push(id);
    }

    clock.nowMs += PERIOD_MS;
    await acc.tick(clock.nowMs);

    const anchor = acc.getClosedAnchors()[0];
    const tree = acc.getTree(anchor.batchId);

    for (const id of eventIds) {
      const proof = tree!.proveByEventId(id);
      expect(verifyProof(proof, anchor.merkleRoot)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Sealed batches cannot be mutated post-anchor
// ---------------------------------------------------------------------------

describe("sealed batch immutability", () => {
  it("adding an event to an anchored batch throws", async () => {
    const clock = { nowMs: 13_000_000 };
    const acc = makeAccumulator(clock);

    await acc.addEvent(await makeEvent("evt-seal-test-1", 1_000, clock.nowMs));
    clock.nowMs += PERIOD_MS;
    await acc.tick(clock.nowMs);

    const anchor = acc.getClosedAnchors()[0];
    const tree = acc.getTree(anchor.batchId);
    expect(tree).toBeDefined();
    expect(tree!.isSealed()).toBe(true);

    // Attempting to add to the sealed tree should throw
    expect(() =>
      tree!.add({
        eventId: "evt-evil",
        agentDid: "did:hive:agent:evil",
        consumerDid: "did:hive:consumer:evil",
        service: "evil",
        meterUnits: 1,
        unitPriceMicroUsdc: 1,
        totalMicroUsdc: 1,
        ts: new Date().toISOString(),
        nonce: "0".repeat(32),
        sig: "fake",
      })
    ).toThrow();
  });

  it("adding to accumulator after anchor goes into NEW batch", async () => {
    const clock = { nowMs: 14_000_000 };
    const acc = makeAccumulator(clock);

    await acc.addEvent(await makeEvent("evt-newbatch-1", 1_000, clock.nowMs));
    clock.nowMs += PERIOD_MS;
    await acc.tick(clock.nowMs);

    const firstBatchId = acc.getClosedAnchors()[0].batchId;

    // This should go into a NEW batch
    await acc.addEvent(await makeEvent("evt-newbatch-2", 1_000, clock.nowMs));
    const current = acc.currentBatch();
    expect(current.batchId).not.toBe(firstBatchId);
    expect(current.eventCount).toBe(1);
  });

  it("anchor totalMicroUsdc matches sum of events", async () => {
    const clock = { nowMs: 15_000_000 };
    const acc = makeAccumulator(clock);

    let expectedTotal = 0;
    for (let i = 0; i < 5; i++) {
      const amount = (i + 1) * 1_000_000;
      await acc.addEvent(await makeEvent(`evt-total-${i}`, amount, clock.nowMs));
      expectedTotal += amount;
    }

    clock.nowMs += PERIOD_MS;
    await acc.tick(clock.nowMs);

    const anchor = acc.getClosedAnchors()[0];
    expect(anchor.totalMicroUsdc).toBe(expectedTotal);
    expect(anchor.eventCount).toBe(5);
  });
});
