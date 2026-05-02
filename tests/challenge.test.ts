/**
 * @file challenge.test.ts
 * @description Tests for the HiveDrops challenge protocol.
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { UsageAccumulator } from "../src/accumulator.js";
import {
  verifyChallenge,
  verifyAnchorSig,
  type AgentPubKeyResolver,
} from "../src/challenge.js";
import { signEvent, bytesToBase64Url, bytesToHex } from "../src/event.js";
import { verifyProof } from "../src/merkle.js";
import { stubAnchorFn } from "../src/anchor-stub.js";
import type { UsageEvent, MerkleAnchor, Challenge } from "../src/types.js";

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

let operatorPrivKey: Uint8Array;
let operatorPubKey: Uint8Array;
let agentPrivKey: Uint8Array;
let agentPubKey: Uint8Array;
let agent2PrivKey: Uint8Array;
let agent2PubKey: Uint8Array;

const AGENT_DID = "did:hive:agent:challenge-test";
const AGENT2_DID = "did:hive:agent:challenge-test-2";

beforeAll(async () => {
  operatorPrivKey = ed.utils.randomPrivateKey();
  operatorPubKey = await ed.getPublicKeyAsync(operatorPrivKey);
  agentPrivKey = ed.utils.randomPrivateKey();
  agentPubKey = await ed.getPublicKeyAsync(agentPrivKey);
  agent2PrivKey = ed.utils.randomPrivateKey();
  agent2PubKey = await ed.getPublicKeyAsync(agent2PrivKey);
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASE_TS = 1_700_000_000_000;

async function makeEvent(
  id: string,
  microUsdc: number = 5_000_000,
  agentDid: string = AGENT_DID,
  key: Uint8Array | null = null,
  meterUnits?: number,
  unitPrice?: number
): Promise<UsageEvent> {
  const units = meterUnits ?? microUsdc;
  const price = unitPrice ?? 1;
  return signEvent(
    {
      eventId: id,
      agentDid,
      consumerDid: "did:hive:consumer:challenge-test",
      service: "challenge.test",
      meterUnits: units,
      unitPriceMicroUsdc: price,
      totalMicroUsdc: units * price,
      ts: new Date(BASE_TS).toISOString(),
      nonce: id.padEnd(32, "0").slice(0, 32),
    },
    key ?? agentPrivKey
  );
}

function makeAccumulator(nowMs: number = BASE_TS): {
  acc: UsageAccumulator;
  clock: { nowMs: number };
} {
  const clock = { nowMs };
  const acc = new UsageAccumulator(
    {
      periodMs: 60_000,
      thresholdMicroUsdc: 999_999_999_999, // never threshold-trigger
      operatorPubKey,
      operatorPrivKey,
    },
    stubAnchorFn,
    () => clock.nowMs
  );
  return { acc, clock };
}

function makeResolver(map: Record<string, Uint8Array>): AgentPubKeyResolver {
  return async (did: string) => map[did] ?? null;
}

async function buildSingleEventAnchor(
  eventId: string = "evt-ch-1",
  microUsdc: number = 5_000_000
): Promise<{ anchor: MerkleAnchor; event: UsageEvent; tree: ReturnType<UsageAccumulator["getTree"]> }> {
  const { acc, clock } = makeAccumulator();
  const event = await makeEvent(eventId, microUsdc);
  await acc.addEvent(event);
  clock.nowMs += 60_001;
  await acc.tick(clock.nowMs);

  const anchor = acc.getClosedAnchors()[0];
  const tree = acc.getTree(anchor.batchId);
  return { anchor, event, tree };
}

// ---------------------------------------------------------------------------
// Anchor signature verification
// ---------------------------------------------------------------------------

describe("verifyAnchorSig", () => {
  it("returns true for a valid operator-signed anchor", async () => {
    const { anchor } = await buildSingleEventAnchor();
    const valid = await verifyAnchorSig(anchor, operatorPubKey);
    expect(valid).toBe(true);
  });

  it("returns false when anchor fields are tampered", async () => {
    const { anchor } = await buildSingleEventAnchor();
    const tampered = { ...anchor, totalMicroUsdc: anchor.totalMicroUsdc + 1 };
    const valid = await verifyAnchorSig(tampered, operatorPubKey);
    expect(valid).toBe(false);
  });

  it("returns false with a different operator public key", async () => {
    const { anchor } = await buildSingleEventAnchor();
    const wrongKey = await ed.getPublicKeyAsync(ed.utils.randomPrivateKey());
    const valid = await verifyAnchorSig(anchor, wrongKey);
    expect(valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Honest anchor — challenge should fail (no contradiction)
// ---------------------------------------------------------------------------

describe("honest anchor + valid event → challenge fails", () => {
  it("wrong-price challenge fails for a correctly priced event", async () => {
    const { anchor, event, tree } = await buildSingleEventAnchor();
    const proof = tree!.proveByEventId(event.eventId);

    const challenge: Challenge = {
      batchId: anchor.batchId,
      eventId: event.eventId,
      claim: "wrong-price",
      proof,
      expected: { totalMicroUsdc: event.totalMicroUsdc },
      observed: { totalMicroUsdc: event.totalMicroUsdc },
      event,
    };

    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);
    expect(result.valid).toBe(false);
  });

  it("forged-sig challenge fails for a correctly signed event", async () => {
    const { anchor, event, tree } = await buildSingleEventAnchor();
    const proof = tree!.proveByEventId(event.eventId);

    const challenge: Challenge = {
      batchId: anchor.batchId,
      eventId: event.eventId,
      claim: "forged-sig",
      proof,
      expected: {},
      observed: {},
      event,
    };

    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);
    expect(result.valid).toBe(false);
    expect(result.severity).toBe("advisory");
  });
});

// ---------------------------------------------------------------------------
// forged-sig challenge
// ---------------------------------------------------------------------------

describe("forged-sig challenge", () => {
  it("succeeds when event has an invalid sig (wrong key)", async () => {
    // Build an event signed by agent2, but claim it's from agentDid
    const { acc, clock } = makeAccumulator();
    const forgedEvent = await makeEvent(
      "evt-forged",
      5_000_000,
      AGENT_DID,
      agent2PrivKey // signed with agent2's key, not agent's
    );
    await acc.addEvent(forgedEvent);
    clock.nowMs += 60_001;
    await acc.tick(clock.nowMs);

    const anchor = acc.getClosedAnchors()[0];
    const tree = acc.getTree(anchor.batchId)!;
    const proof = tree.proveByEventId("evt-forged");

    const challenge: Challenge = {
      batchId: anchor.batchId,
      eventId: "evt-forged",
      claim: "forged-sig",
      proof,
      expected: {},
      observed: {},
      event: forgedEvent,
    };

    // Resolver returns agentPubKey, but event was signed by agent2PrivKey
    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);

    expect(result.valid).toBe(true);
    expect(result.severity).toBe("fatal");
  });

  it("fails with advisory when challenge.event is missing", async () => {
    const { anchor, event, tree } = await buildSingleEventAnchor();
    const proof = tree!.proveByEventId(event.eventId);

    const challenge: Challenge = {
      batchId: anchor.batchId,
      eventId: event.eventId,
      claim: "forged-sig",
      proof,
      expected: {},
      observed: {},
      // No event field
    };

    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);
    expect(result.valid).toBe(false);
    expect(result.severity).toBe("advisory");
  });
});

// ---------------------------------------------------------------------------
// wrong-price challenge
// ---------------------------------------------------------------------------

describe("wrong-price challenge", () => {
  it("succeeds when math doesn't add up", async () => {
    const { acc, clock } = makeAccumulator();

    // Manually create an event with wrong totalMicroUsdc
    const badEvent = await signEvent(
      {
        eventId: "evt-bad-price",
        agentDid: AGENT_DID,
        consumerDid: "did:hive:consumer:challenge-test",
        service: "challenge.test",
        meterUnits: 100,
        unitPriceMicroUsdc: 1000,
        totalMicroUsdc: 99999, // WRONG: should be 100 * 1000 = 100_000
        ts: new Date(BASE_TS).toISOString(),
        nonce: "evt-bad-price00000000000000000000".slice(0, 32),
      },
      agentPrivKey
    );

    await acc.addEvent(badEvent);
    clock.nowMs += 60_001;
    await acc.tick(clock.nowMs);

    const anchor = acc.getClosedAnchors()[0];
    const tree = acc.getTree(anchor.batchId)!;
    const proof = tree.proveByEventId("evt-bad-price");

    const challenge: Challenge = {
      batchId: anchor.batchId,
      eventId: "evt-bad-price",
      claim: "wrong-price",
      proof,
      expected: { totalMicroUsdc: 100_000 },
      observed: { totalMicroUsdc: 99999 },
      event: badEvent,
    };

    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);
    expect(result.valid).toBe(true);
    expect(result.severity).toBe("fatal");
  });

  it("fails when price is correct", async () => {
    const { anchor, event, tree } = await buildSingleEventAnchor("evt-good-price", 50_000);
    const proof = tree!.proveByEventId("evt-good-price");

    const challenge: Challenge = {
      batchId: anchor.batchId,
      eventId: "evt-good-price",
      claim: "wrong-price",
      proof,
      expected: { totalMicroUsdc: event.totalMicroUsdc },
      observed: { totalMicroUsdc: event.totalMicroUsdc },
      event,
    };

    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// double-count challenge
// ---------------------------------------------------------------------------

describe("double-count challenge", () => {
  it("succeeds when same eventId appears at two different indices", async () => {
    const { acc, clock } = makeAccumulator();

    const originalEvent = await makeEvent("evt-dup", 1_000_000);
    // Re-sign with a slightly different nonce to get different leaf hash but same eventId
    // (operator added the same logical event twice with different nonces as a trick)
    // For this test, we force the exact same event object twice (same leaf hash)
    await acc.addEvent(originalEvent);
    await acc.addEvent(originalEvent); // exact duplicate (same sig, same leaf)

    clock.nowMs += 60_001;
    await acc.tick(clock.nowMs);

    const anchor = acc.getClosedAnchors()[0];
    const tree = acc.getTree(anchor.batchId)!;

    // Both index 0 and index 1 should have the same eventId
    const proof1 = tree.proveByIndex(0);
    const proof2 = tree.proveByIndex(1);

    expect(verifyProof(proof1, anchor.merkleRoot)).toBe(true);
    expect(verifyProof(proof2, anchor.merkleRoot)).toBe(true);
    expect(proof1.leafIndex).not.toBe(proof2.leafIndex);

    const challenge: Challenge = {
      batchId: anchor.batchId,
      eventId: "evt-dup",
      claim: "double-count",
      proof: proof1,
      siblingProof: proof2,
      expected: { eventId: "evt-dup" },
      observed: { eventId: "evt-dup" },
      event: originalEvent,
    };

    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);
    expect(result.valid).toBe(true);
    expect(result.severity).toBe("fatal");
  });

  it("fails when no siblingProof is provided", async () => {
    const { anchor, event, tree } = await buildSingleEventAnchor("evt-dc-nosib");
    const proof = tree!.proveByEventId("evt-dc-nosib");

    const challenge: Challenge = {
      batchId: anchor.batchId,
      eventId: "evt-dc-nosib",
      claim: "double-count",
      proof,
      // No siblingProof
      expected: {},
      observed: {},
    };

    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);
    expect(result.valid).toBe(false);
    expect(result.severity).toBe("advisory");
  });

  it("fails when same index used in both proofs", async () => {
    const { anchor, event, tree } = await buildSingleEventAnchor("evt-dc-same-idx");
    const proof = tree!.proveByEventId("evt-dc-same-idx");

    const challenge: Challenge = {
      batchId: anchor.batchId,
      eventId: "evt-dc-same-idx",
      claim: "double-count",
      proof,
      siblingProof: proof, // same proof as sibling
      expected: {},
      observed: {},
    };

    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tampered Merkle proof
// ---------------------------------------------------------------------------

describe("tampered Merkle proof", () => {
  it("challenge fails when Merkle proof is tampered", async () => {
    const { anchor, event, tree } = await buildSingleEventAnchor("evt-tampered-proof");
    const proof = tree!.proveByEventId("evt-tampered-proof");

    const tamperedProof = {
      ...proof,
      leafHash: "a".repeat(64), // corrupt the leaf hash
    };

    const challenge: Challenge = {
      batchId: anchor.batchId,
      eventId: "evt-tampered-proof",
      claim: "wrong-price",
      proof: tamperedProof,
      expected: {},
      observed: {},
      event,
    };

    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Cross-anchor proof forgery
// ---------------------------------------------------------------------------

describe("cross-anchor proof forgery", () => {
  it("proof from anchor A does not verify against anchor B's root", async () => {
    // Build two separate anchors
    const { acc: acc1, clock: c1 } = makeAccumulator(BASE_TS);
    const event1 = await makeEvent("evt-cross-A");
    await acc1.addEvent(event1);
    c1.nowMs += 60_001;
    await acc1.tick(c1.nowMs);

    const { acc: acc2, clock: c2 } = makeAccumulator(BASE_TS + 1000);
    const event2 = await makeEvent("evt-cross-B");
    await acc2.addEvent(event2);
    c2.nowMs += 60_001;
    await acc2.tick(c2.nowMs);

    const anchor1 = acc1.getClosedAnchors()[0];
    const anchor2 = acc2.getClosedAnchors()[0];
    const tree1 = acc1.getTree(anchor1.batchId)!;

    // Use proof from anchor1 against anchor2's challenge
    const proof = tree1.proveByEventId("evt-cross-A");

    const crossChallenge: Challenge = {
      batchId: anchor2.batchId, // wrong anchor
      eventId: "evt-cross-A",
      claim: "wrong-price",
      proof, // proof is for anchor1, not anchor2
      expected: {},
      observed: {},
      event: event1,
    };

    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    // This should fail because the proof doesn't verify against anchor2.merkleRoot
    const result = await verifyChallenge(
      crossChallenge,
      anchor2,
      operatorPubKey,
      resolver
    );
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Missing challenge returns advisory (future work)
// ---------------------------------------------------------------------------

describe("missing challenge", () => {
  it("returns advisory result with TODO message", async () => {
    const { anchor, event, tree } = await buildSingleEventAnchor("evt-missing-test");
    const proof = tree!.proveByEventId("evt-missing-test");

    const challenge: Challenge = {
      batchId: anchor.batchId,
      eventId: "evt-missing-id",
      claim: "missing",
      proof,
      expected: {},
      observed: {},
    };

    const resolver = makeResolver({ [AGENT_DID]: agentPubKey });
    const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);
    expect(result.valid).toBe(false);
    expect(result.severity).toBe("advisory");
    expect(result.reason).toContain("prov-absence");
  });
});
