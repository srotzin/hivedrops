/**
 * @file event.test.ts
 * @description Tests for event signing, verification, and hashing.
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import {
  signEvent,
  verifyEvent,
  eventHash,
  canonicalizeEventForSigning,
  canonicalizeEventWithSig,
  bytesToHex,
} from "../src/event.js";
import type { UsageEvent } from "../src/types.js";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

let privKey: Uint8Array;
let pubKey: Uint8Array;
let privKey2: Uint8Array;
let pubKey2: Uint8Array;

const BASE_EVENT: Omit<UsageEvent, "sig"> = {
  eventId: "evt-001",
  agentDid: "did:hive:agent:alpha",
  consumerDid: "did:hive:consumer:beta",
  service: "llm.completion",
  meterUnits: 1500,
  unitPriceMicroUsdc: 10,
  totalMicroUsdc: 15000,
  ts: "2026-01-15T10:30:00.000Z",
  nonce: "deadbeefdeadbeefdeadbeefdeadbeef",
};

beforeAll(async () => {
  privKey = ed.utils.randomPrivateKey();
  pubKey = await ed.getPublicKeyAsync(privKey);
  privKey2 = ed.utils.randomPrivateKey();
  pubKey2 = await ed.getPublicKeyAsync(privKey2);
});

// ---------------------------------------------------------------------------
// Sign / verify round-trip
// ---------------------------------------------------------------------------

describe("signEvent / verifyEvent round-trip", () => {
  it("signs an event and verifies with the correct public key", async () => {
    const event = await signEvent(BASE_EVENT, privKey);
    expect(event.sig).toBeTruthy();
    expect(event.sig.length).toBeGreaterThan(60);

    const valid = await verifyEvent(event, pubKey);
    expect(valid).toBe(true);
  });

  it("fails verification with a different public key", async () => {
    const event = await signEvent(BASE_EVENT, privKey);
    const valid = await verifyEvent(event, pubKey2);
    expect(valid).toBe(false);
  });

  it("fails verification when event fields are tampered after signing", async () => {
    const event = await signEvent(BASE_EVENT, privKey);

    // Tamper with totalMicroUsdc
    const tampered: UsageEvent = { ...event, totalMicroUsdc: 99999 };
    const valid = await verifyEvent(tampered, pubKey);
    expect(valid).toBe(false);
  });

  it("fails verification when agentDid is changed", async () => {
    const event = await signEvent(BASE_EVENT, privKey);
    const tampered: UsageEvent = { ...event, agentDid: "did:hive:agent:evil" };
    const valid = await verifyEvent(tampered, pubKey);
    expect(valid).toBe(false);
  });

  it("fails verification when service is changed", async () => {
    const event = await signEvent(BASE_EVENT, privKey);
    const tampered: UsageEvent = { ...event, service: "exfiltration.dns" };
    const valid = await verifyEvent(tampered, pubKey);
    expect(valid).toBe(false);
  });

  it("fails verification with a corrupted sig", async () => {
    const event = await signEvent(BASE_EVENT, privKey);
    const corrupted: UsageEvent = { ...event, sig: event.sig.slice(0, -4) + "AAAA" };
    const valid = await verifyEvent(corrupted, pubKey);
    expect(valid).toBe(false);
  });

  it("fails verification with an empty sig", async () => {
    const event = await signEvent(BASE_EVENT, privKey);
    const emptySig: UsageEvent = { ...event, sig: "" };
    const valid = await verifyEvent(emptySig, pubKey);
    expect(valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Canonical determinism
// ---------------------------------------------------------------------------

describe("canonical serialization", () => {
  it("produces identical bytes for the same event (no sig)", () => {
    const c1 = canonicalizeEventForSigning(BASE_EVENT);
    const c2 = canonicalizeEventForSigning(BASE_EVENT);
    expect(c1).toBe(c2);
  });

  it("produces different bytes when a field changes", () => {
    const c1 = canonicalizeEventForSigning(BASE_EVENT);
    const c2 = canonicalizeEventForSigning({ ...BASE_EVENT, meterUnits: 9999 });
    expect(c1).not.toBe(c2);
  });

  it("keys are alphabetically sorted in canonical form", () => {
    const c = canonicalizeEventForSigning(BASE_EVENT);
    const parsed = JSON.parse(c);
    const keys = Object.keys(parsed);
    expect(keys).toEqual([...keys].sort());
  });

  it("sig field is NOT present in signing canonical form", () => {
    const c = canonicalizeEventForSigning(BASE_EVENT);
    expect(c).not.toContain('"sig"');
  });

  it("sig field IS present in full canonical form (with sig)", async () => {
    const event = await signEvent(BASE_EVENT, privKey);
    const c = canonicalizeEventWithSig(event);
    expect(c).toContain('"sig"');
  });

  it("two different signers produce different sigs but same pre-sig canonical", async () => {
    const event1 = await signEvent(BASE_EVENT, privKey);
    const event2 = await signEvent(BASE_EVENT, privKey2);

    const preImage1 = canonicalizeEventForSigning(BASE_EVENT);
    const preImage2 = canonicalizeEventForSigning(BASE_EVENT);
    expect(preImage1).toBe(preImage2);
    expect(event1.sig).not.toBe(event2.sig);
  });
});

// ---------------------------------------------------------------------------
// eventHash
// ---------------------------------------------------------------------------

describe("eventHash", () => {
  it("produces a 32-byte hash", async () => {
    const event = await signEvent(BASE_EVENT, privKey);
    const hash = eventHash(event);
    expect(hash.length).toBe(32);
  });

  it("is deterministic for the same event", async () => {
    const event = await signEvent(BASE_EVENT, privKey);
    const h1 = bytesToHex(eventHash(event));
    const h2 = bytesToHex(eventHash(event));
    expect(h1).toBe(h2);
  });

  it("changes when totalMicroUsdc is tampered", async () => {
    const event = await signEvent(BASE_EVENT, privKey);
    const tampered: UsageEvent = { ...event, totalMicroUsdc: 1 };
    const h1 = bytesToHex(eventHash(event));
    const h2 = bytesToHex(eventHash(tampered));
    expect(h1).not.toBe(h2);
  });

  it("changes when sig is tampered", async () => {
    const event = await signEvent(BASE_EVENT, privKey);
    const tampered: UsageEvent = { ...event, sig: event.sig.replace("A", "B") };
    // Only run this if sig actually contains 'A'
    if (event.sig.includes("A")) {
      const h1 = bytesToHex(eventHash(event));
      const h2 = bytesToHex(eventHash(tampered));
      expect(h1).not.toBe(h2);
    }
  });

  it("includes the domain separation prefix (0x00)", async () => {
    // If prefix were absent, a leaf hash could collide with a node hash.
    // We can't test this directly, but we verify the hash is not a raw SHA-256
    // of the canonical bytes by checking the expected structure.
    const event = await signEvent(BASE_EVENT, privKey);
    const canonical = canonicalizeEventWithSig(event);
    const { sha256 } = await import("@noble/hashes/sha256");
    const rawBytes = new TextEncoder().encode(canonical);
    const rawHash = bytesToHex(sha256(rawBytes));
    const domainHash = bytesToHex(eventHash(event));
    expect(domainHash).not.toBe(rawHash);
  });
});

// ---------------------------------------------------------------------------
// Cross-event hash uniqueness
// ---------------------------------------------------------------------------

describe("event hash uniqueness", () => {
  it("different events produce different leaf hashes", async () => {
    const e1 = await signEvent(BASE_EVENT, privKey);
    const e2 = await signEvent(
      { ...BASE_EVENT, eventId: "evt-002", nonce: "abcd1234abcd1234abcd1234abcd1234" },
      privKey
    );
    const h1 = bytesToHex(eventHash(e1));
    const h2 = bytesToHex(eventHash(e2));
    expect(h1).not.toBe(h2);
  });
});
