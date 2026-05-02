/**
 * @file merkle.test.ts
 * @description Tests for UsageMerkleTree and verifyProof.
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { UsageMerkleTree, verifyProof, nodeHash, leafHash } from "../src/merkle.js";
import { signEvent, bytesToHex, hexToBytes } from "../src/event.js";
import type { UsageEvent } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let privKey: Uint8Array;
let privKey2: Uint8Array;

async function makeEvent(
  id: string,
  meterUnits: number = 100,
  unitPrice: number = 10,
  key?: Uint8Array
): Promise<UsageEvent> {
  const k = key ?? privKey;
  return signEvent(
    {
      eventId: id,
      agentDid: "did:hive:agent:test",
      consumerDid: "did:hive:consumer:test",
      service: "test.service",
      meterUnits,
      unitPriceMicroUsdc: unitPrice,
      totalMicroUsdc: meterUnits * unitPrice,
      ts: "2026-01-15T10:00:00.000Z",
      nonce: id.padEnd(32, "0").slice(0, 32),
    },
    k
  );
}

beforeAll(async () => {
  privKey = ed.utils.randomPrivateKey();
  privKey2 = ed.utils.randomPrivateKey();
});

// ---------------------------------------------------------------------------
// Basic tree construction
// ---------------------------------------------------------------------------

describe("UsageMerkleTree basic operations", () => {
  it("empty tree returns a defined root", () => {
    const tree = new UsageMerkleTree();
    const root = tree.root();
    expect(root).toHaveLength(64); // 32 bytes = 64 hex chars
  });

  it("single-event tree has size 1", async () => {
    const tree = new UsageMerkleTree();
    tree.add(await makeEvent("evt-1"));
    expect(tree.size()).toBe(1);
  });

  it("root changes when events are added", async () => {
    const tree = new UsageMerkleTree();
    const r0 = tree.root();
    tree.add(await makeEvent("evt-1"));
    const r1 = tree.root();
    tree.add(await makeEvent("evt-2"));
    const r2 = tree.root();
    expect(r0).not.toBe(r1);
    expect(r1).not.toBe(r2);
  });

  it("root is deterministic for the same events", async () => {
    const e1 = await makeEvent("evt-1");
    const e2 = await makeEvent("evt-2");

    const t1 = new UsageMerkleTree();
    t1.add(e1);
    t1.add(e2);

    const t2 = new UsageMerkleTree();
    t2.add(e1);
    t2.add(e2);

    expect(t1.root()).toBe(t2.root());
  });
});

// ---------------------------------------------------------------------------
// Insertion-ordered proofs
// ---------------------------------------------------------------------------

describe("Merkle inclusion proofs", () => {
  it("proves a single event (leaf index 0)", async () => {
    const tree = new UsageMerkleTree();
    const e = await makeEvent("evt-1");
    tree.add(e);
    const root = tree.root();
    const proof = tree.proveByIndex(0);
    expect(verifyProof(proof, root)).toBe(true);
  });

  it("proves by eventId", async () => {
    const tree = new UsageMerkleTree();
    const e = await makeEvent("evt-42");
    tree.add(e);
    const root = tree.root();
    const proof = tree.proveByEventId("evt-42");
    expect(verifyProof(proof, root)).toBe(true);
  });

  it("proves multiple events at specific indices", async () => {
    const tree = new UsageMerkleTree();
    const events: UsageEvent[] = [];
    for (let i = 0; i < 7; i++) {
      const e = await makeEvent(`evt-${i}`);
      events.push(e);
      tree.add(e);
    }
    const root = tree.root();
    for (let i = 0; i < events.length; i++) {
      const proof = tree.proveByIndex(i);
      expect(verifyProof(proof, root)).toBe(true);
    }
  });

  it("proves events in a power-of-2 sized tree", async () => {
    const tree = new UsageMerkleTree();
    for (let i = 0; i < 8; i++) {
      tree.add(await makeEvent(`evt-p2-${i}`));
    }
    const root = tree.root();
    for (let i = 0; i < 8; i++) {
      expect(verifyProof(tree.proveByIndex(i), root)).toBe(true);
    }
  });

  it("proveByIndex and proveByEventId return equivalent proofs", async () => {
    const tree = new UsageMerkleTree();
    const e = await makeEvent("evt-unique-99");
    tree.add(await makeEvent("evt-0"));
    tree.add(e);
    tree.add(await makeEvent("evt-2"));
    const root = tree.root();

    const proofByIdx = tree.proveByIndex(1);
    const proofById = tree.proveByEventId("evt-unique-99");

    expect(proofByIdx.leafIndex).toBe(proofById.leafIndex);
    expect(proofByIdx.leafHash).toBe(proofById.leafHash);
    expect(verifyProof(proofByIdx, root)).toBe(true);
    expect(verifyProof(proofById, root)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Tampering / invalid proofs
// ---------------------------------------------------------------------------

describe("proof tampering", () => {
  it("tampered leaf hash fails verification", async () => {
    const tree = new UsageMerkleTree();
    tree.add(await makeEvent("evt-t1"));
    tree.add(await makeEvent("evt-t2"));
    const root = tree.root();
    const proof = tree.proveByIndex(0);

    const tampered = { ...proof, leafHash: "0".repeat(64) };
    expect(verifyProof(tampered, root)).toBe(false);
  });

  it("tampered sibling hash fails verification", async () => {
    const tree = new UsageMerkleTree();
    tree.add(await makeEvent("evt-t1"));
    tree.add(await makeEvent("evt-t2"));
    const root = tree.root();
    const proof = tree.proveByIndex(0);

    if (proof.path.length > 0) {
      const tamperedPath = [
        { ...proof.path[0], sibling: "f".repeat(64) },
        ...proof.path.slice(1),
      ];
      const tampered = { ...proof, path: tamperedPath };
      expect(verifyProof(tampered, root)).toBe(false);
    }
  });

  it("proof from one tree fails against a different tree's root", async () => {
    const t1 = new UsageMerkleTree();
    t1.add(await makeEvent("evt-A"));
    t1.add(await makeEvent("evt-B"));
    const root1 = t1.root();

    const t2 = new UsageMerkleTree();
    t2.add(await makeEvent("evt-C"));
    t2.add(await makeEvent("evt-D"));
    const root2 = t2.root();

    const proof = t1.proveByIndex(0);
    expect(verifyProof(proof, root1)).toBe(true);
    expect(verifyProof(proof, root2)).toBe(false);
  });

  it("proof with swapped path positions fails", async () => {
    const tree = new UsageMerkleTree();
    for (let i = 0; i < 4; i++) tree.add(await makeEvent(`evt-swap-${i}`));
    const root = tree.root();
    const proof = tree.proveByIndex(0);

    if (proof.path.length >= 2) {
      const swapped = {
        ...proof,
        path: [proof.path[1], proof.path[0], ...proof.path.slice(2)],
      };
      expect(verifyProof(swapped, root)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

describe("tree sealing", () => {
  it("adding to a sealed tree throws", async () => {
    const tree = new UsageMerkleTree();
    tree.add(await makeEvent("evt-seal-1"));
    tree.seal();
    expect(() => tree.add({ eventId: "evt-seal-2" } as UsageEvent)).toThrow();
  });

  it("root can still be read from a sealed tree", async () => {
    const tree = new UsageMerkleTree();
    tree.add(await makeEvent("evt-seal-read"));
    tree.seal();
    expect(() => tree.root()).not.toThrow();
    expect(tree.root()).toHaveLength(64);
  });

  it("proofs can still be generated from a sealed tree", async () => {
    const tree = new UsageMerkleTree();
    tree.add(await makeEvent("evt-sealed-proof"));
    tree.seal();
    const proof = tree.proveByIndex(0);
    expect(verifyProof(proof, tree.root())).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Large tree
// ---------------------------------------------------------------------------

describe("large tree", () => {
  it("correctly handles 1,000 events — all proofs valid", async () => {
    const tree = new UsageMerkleTree();
    for (let i = 0; i < 1000; i++) {
      tree.add(await makeEvent(`evt-large-${i}`, 100 + i, 5));
    }
    const root = tree.root();

    // Check 50 random indices (full 1,000 would take a while)
    for (let i = 0; i < 50; i++) {
      const idx = Math.floor(Math.random() * 1000);
      const proof = tree.proveByIndex(idx);
      expect(verifyProof(proof, root)).toBe(true);
    }
  }, 30000); // 30s timeout for 1,000 sign + prove operations
});

// ---------------------------------------------------------------------------
// Domain separation sanity check
// ---------------------------------------------------------------------------

describe("domain separation", () => {
  it("leaf hash and node hash with same bytes produce different results", () => {
    const data = new Uint8Array(32).fill(0xab);
    const lh = leafHash(data);
    const nh = nodeHash(data, data);
    expect(bytesToHex(lh)).not.toBe(bytesToHex(nh));
  });
});

// ---------------------------------------------------------------------------
// Padding rule
// ---------------------------------------------------------------------------

describe("padding rule", () => {
  it("a 3-event tree has treeSize = 4 in its proofs", async () => {
    const tree = new UsageMerkleTree();
    tree.add(await makeEvent("evt-p1"));
    tree.add(await makeEvent("evt-p2"));
    tree.add(await makeEvent("evt-p3"));
    const proof = tree.proveByIndex(2); // last real leaf
    expect(proof.treeSize).toBe(4);
  });

  it("a 5-event tree has treeSize = 8 in its proofs", async () => {
    const tree = new UsageMerkleTree();
    for (let i = 0; i < 5; i++) tree.add(await makeEvent(`evt-pd-${i}`));
    const proof = tree.proveByIndex(0);
    expect(proof.treeSize).toBe(8);
  });
});
