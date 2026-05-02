/**
 * @file run-simulation.ts
 * @description HiveDrops reference simulation: 1,000 usage events across 5 anchors
 *   over a simulated 1-hour period.
 *
 * Demonstrates:
 *   1. Bulk event generation and signing
 *   2. Rolling accumulator with period-based anchoring
 *   3. Settlement computation per anchor
 *   4. One successful challenge (wrong-price event)
 *   5. One failed challenge (correct event, no contradiction)
 *   6. Gas-equivalent savings narrative
 *
 * Run: npx tsx examples/run-simulation.ts
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import * as ed from "@noble/ed25519";
import { UsageAccumulator } from "../src/accumulator.js";
import { verifyChallenge, type AgentPubKeyResolver } from "../src/challenge.js";
import {
  computeSettlement,
  buildSettlementInstructions,
  microUsdcToUsdc,
} from "../src/settle.js";
import { signEvent } from "../src/event.js";
import { stubAnchorFn } from "../src/anchor-stub.js";
import { verifyProof } from "../src/merkle.js";
import type { UsageEvent, MerkleAnchor, Challenge } from "../src/types.js";

// ---------------------------------------------------------------------------
// Simulation parameters
// ---------------------------------------------------------------------------

const TOTAL_EVENTS = 1000;
const SIMULATION_DURATION_MS = 3600 * 1000; // 1 hour
const PERIOD_MS = 3600_000 / 5; // Anchor every 12 minutes → 5 anchors over 1 hour
const THRESHOLD_MICRO_USDC = 999_999_999_999; // Never threshold-trigger (use period only)

const SERVICES = [
  { name: "llm.completion", unitPriceMicroUsdc: 1_000 },
  { name: "search.web", unitPriceMicroUsdc: 500 },
  { name: "embed.text", unitPriceMicroUsdc: 100 },
  { name: "image.generate", unitPriceMicroUsdc: 5_000 },
  { name: "audio.transcribe", unitPriceMicroUsdc: 2_000 },
];

const CONSUMER_DIDS = [
  "did:hive:consumer:acme-corp",
  "did:hive:consumer:beta-labs",
  "did:hive:consumer:gamma-io",
];

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

console.log("═".repeat(70));
console.log(" HiveDrops Reference Simulation");
console.log(" 1,000 Usage Events · 5 Anchors · 1 Simulated Hour");
console.log("═".repeat(70));
console.log();

const operatorPrivKey = ed.utils.randomPrivateKey();
const operatorPubKey = await ed.getPublicKeyAsync(operatorPrivKey);
const agentPrivKey = ed.utils.randomPrivateKey();
const agentPubKey = await ed.getPublicKeyAsync(agentPrivKey);

console.log("Keys generated:");
console.log(`  Operator pubkey: ${Buffer.from(operatorPubKey).toString("hex").slice(0, 16)}...`);
console.log(`  Agent pubkey:    ${Buffer.from(agentPubKey).toString("hex").slice(0, 16)}...`);
console.log();

// ---------------------------------------------------------------------------
// Generate events
// ---------------------------------------------------------------------------

const SIM_START_MS = 1_700_000_000_000; // Fixed epoch for reproducibility
const events: UsageEvent[] = [];
const WRONG_PRICE_EVENT_IDX = 42; // This event will have a wrong price for challenge testing

console.log(`Generating ${TOTAL_EVENTS} usage events...`);
const t0gen = Date.now();

for (let i = 0; i < TOTAL_EVENTS; i++) {
  const service = SERVICES[i % SERVICES.length];
  const meterUnits = 10 + (i % 100);
  const consumer = CONSUMER_DIDS[i % CONSUMER_DIDS.length];
  const tsMs = SIM_START_MS + Math.floor((i / TOTAL_EVENTS) * SIMULATION_DURATION_MS);

  const baseEvent: Omit<UsageEvent, "sig"> = {
    eventId: `evt-sim-${i.toString().padStart(4, "0")}`,
    agentDid: "did:hive:agent:sim-worker",
    consumerDid: consumer,
    service: service.name,
    meterUnits,
    unitPriceMicroUsdc: service.unitPriceMicroUsdc,
    totalMicroUsdc: meterUnits * service.unitPriceMicroUsdc,
    ts: new Date(tsMs).toISOString(),
    nonce: `${i.toString(16).padStart(16, "0")}${"0".repeat(16)}`.slice(0, 32),
  };

  // For event 42, introduce a wrong-price bug (totalMicroUsdc is off by 1)
  if (i === WRONG_PRICE_EVENT_IDX) {
    const wrongTotal = baseEvent.totalMicroUsdc + 1;
    events.push(
      await signEvent({ ...baseEvent, totalMicroUsdc: wrongTotal }, agentPrivKey)
    );
  } else {
    events.push(await signEvent(baseEvent, agentPrivKey));
  }
}

const genMs = Date.now() - t0gen;
console.log(`  Done: ${TOTAL_EVENTS} events signed in ${genMs}ms (${(genMs / TOTAL_EVENTS).toFixed(2)}ms/event)\n`);

// ---------------------------------------------------------------------------
// Accumulate & anchor
// ---------------------------------------------------------------------------

let virtualMs = SIM_START_MS;
const clock = { nowMs: virtualMs };

const acc = new UsageAccumulator(
  {
    periodMs: PERIOD_MS,
    thresholdMicroUsdc: THRESHOLD_MICRO_USDC,
    operatorPubKey,
    operatorPrivKey,
  },
  stubAnchorFn,
  () => clock.nowMs
);

console.log("Running accumulator...");
const t0acc = Date.now();

// Track the last time we opened a batch to fire period ticks correctly.
// Since events arrive ~3.6s apart and PERIOD_MS = 720,000ms, we need to
// detect when cumulative time since the last batch start exceeds PERIOD_MS.
let lastBatchStartMs = clock.nowMs;

for (const event of events) {
  const eventMs = new Date(event.ts).getTime();
  if (eventMs > clock.nowMs) {
    clock.nowMs = eventMs;
  }
  // Check if the current event's timestamp is at or past a period boundary.
  // We calculate how many full periods have elapsed since lastBatchStartMs.
  while (clock.nowMs >= lastBatchStartMs + PERIOD_MS) {
    const anchorAt = lastBatchStartMs + PERIOD_MS;
    await acc.tick(anchorAt);
    // After anchoring, the new batch starts at anchorAt.
    lastBatchStartMs = anchorAt;
  }
  await acc.addEvent(event);
}

// Anchor any remaining events
if (acc.currentBatch().eventCount > 0) {
  clock.nowMs = SIM_START_MS + SIMULATION_DURATION_MS;
  await acc.anchor(clock.nowMs);
}

const accMs = Date.now() - t0acc;
console.log(`  Done: accumulated in ${accMs}ms\n`);

const anchors = acc.getClosedAnchors();

// ---------------------------------------------------------------------------
// Per-anchor summary + settlement
// ---------------------------------------------------------------------------

console.log("═".repeat(70));
console.log(`ANCHOR SUMMARY (${anchors.length} batches)`);
console.log("═".repeat(70));

let grandTotal = 0;
let totalAgentPayout = 0;
let totalTreasuryPayout = 0;

for (let a = 0; a < anchors.length; a++) {
  const anchor = anchors[a];
  const settlement = computeSettlement(anchor);
  const txs = buildSettlementInstructions(settlement, {
    agent: "0xAgentMultisig0000000000000000000000",
    treasury: "0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E",
  });

  grandTotal += anchor.totalMicroUsdc;
  totalAgentPayout += settlement.agentMicroUsdc;
  totalTreasuryPayout += settlement.treasuryMicroUsdc;

  console.log(`\nBatch ${a + 1}/${anchors.length}: ${anchor.batchId}`);
  console.log(`  Events:      ${anchor.eventCount}`);
  console.log(`  Total:       ${microUsdcToUsdc(anchor.totalMicroUsdc)}`);
  console.log(`  Period:      ${anchor.periodStart} → ${anchor.periodEnd}`);
  console.log(`  Root:        ${anchor.merkleRoot.slice(0, 20)}...`);
  console.log(`  Anchor tx:   ${anchor.anchorTxHash}`);
  console.log(`  Settlement breakdown:`);
  for (const tx of txs) {
    console.log(
      `    → ${tx.to.slice(0, 20)}...  ${microUsdcToUsdc(tx.amountMicroUsdc)}`
    );
  }
}

// ---------------------------------------------------------------------------
// Overall summary
// ---------------------------------------------------------------------------

console.log("\n" + "═".repeat(70));
console.log("OVERALL SUMMARY");
console.log("═".repeat(70));
console.log(`  Total events processed:   ${TOTAL_EVENTS}`);
console.log(`  Total batches anchored:   ${anchors.length}`);
console.log(`  Grand total settled:      ${microUsdcToUsdc(grandTotal)}`);
console.log(`  Agent payout (92%):       ${microUsdcToUsdc(totalAgentPayout)}`);
console.log(`  Treasury fee (8%):        ${microUsdcToUsdc(totalTreasuryPayout)}`);

// Gas savings narrative
const GAS_PER_TX_USD = 0.05; // ~$0.05 per on-chain tx on Base (conservative estimate)
const perEventCost = TOTAL_EVENTS * GAS_PER_TX_USD;
const perAnchorCost = anchors.length * GAS_PER_TX_USD * 2; // anchor + settlement
const savings = perEventCost - perAnchorCost;
const compressionRatio = TOTAL_EVENTS / (anchors.length * 2);

console.log();
console.log("GAS-EQUIVALENT SAVINGS:");
console.log(`  Without HiveDrops: ${TOTAL_EVENTS} on-chain txs @ $${GAS_PER_TX_USD} = $${perEventCost.toFixed(2)}`);
console.log(`  With HiveDrops:    ${anchors.length * 2} on-chain txs (${anchors.length} anchor + ${anchors.length} settle) @ $${GAS_PER_TX_USD} = $${perAnchorCost.toFixed(2)}`);
console.log(`  Savings:           $${savings.toFixed(2)} (${compressionRatio.toFixed(0)}x compression)`);
console.log(`  Settlement ratio:  1 on-chain tx per ${(TOTAL_EVENTS / (anchors.length * 2)).toFixed(0)} events`);

// ---------------------------------------------------------------------------
// Challenge demonstration
// ---------------------------------------------------------------------------

console.log("\n" + "═".repeat(70));
console.log("CHALLENGE DEMONSTRATIONS");
console.log("═".repeat(70));

const resolver: AgentPubKeyResolver = async (did: string) => {
  if (did === "did:hive:agent:sim-worker") return agentPubKey;
  return null;
};

// Find the anchor that contains the wrong-price event
let wrongPriceAnchor: MerkleAnchor | null = null;
let wrongPriceEvent: UsageEvent | null = null;

for (const anchor of anchors) {
  const tree = acc.getTree(anchor.batchId);
  if (tree && tree.hasEventId(`evt-sim-${WRONG_PRICE_EVENT_IDX.toString().padStart(4, "0")}`)) {
    wrongPriceAnchor = anchor;
    wrongPriceEvent = events[WRONG_PRICE_EVENT_IDX];
    break;
  }
}

// --- Challenge 1: Successful wrong-price challenge ---
if (wrongPriceAnchor && wrongPriceEvent) {
  console.log("\n[Challenge 1] Wrong-price challenge (should SUCCEED)");
  console.log(`  Event:     ${wrongPriceEvent.eventId}`);
  console.log(`  Batch:     ${wrongPriceAnchor.batchId}`);
  console.log(`  meterUnits × unitPrice = ${wrongPriceEvent.meterUnits} × ${wrongPriceEvent.unitPriceMicroUsdc} = ${wrongPriceEvent.meterUnits * wrongPriceEvent.unitPriceMicroUsdc}`);
  console.log(`  recorded totalMicroUsdc = ${wrongPriceEvent.totalMicroUsdc} (off by 1)`);

  const tree = acc.getTree(wrongPriceAnchor.batchId)!;
  const proof = tree.proveByEventId(wrongPriceEvent.eventId);

  const challenge1: Challenge = {
    batchId: wrongPriceAnchor.batchId,
    eventId: wrongPriceEvent.eventId,
    claim: "wrong-price",
    proof,
    expected: {
      totalMicroUsdc: wrongPriceEvent.meterUnits * wrongPriceEvent.unitPriceMicroUsdc,
    },
    observed: { totalMicroUsdc: wrongPriceEvent.totalMicroUsdc },
    event: wrongPriceEvent,
  };

  const result1 = await verifyChallenge(
    challenge1,
    wrongPriceAnchor,
    operatorPubKey,
    resolver
  );
  console.log(`  Result:    valid=${result1.valid}, severity=${result1.severity}`);
  console.log(`  Reason:    ${result1.reason}`);
  console.log(`  → Challenge ${result1.valid ? "SUCCEEDED ✓" : "FAILED ✗"}`);
}

// --- Challenge 2: Failed challenge (honest event) ---
const firstAnchor = anchors[0];
const firstTree = acc.getTree(firstAnchor.batchId)!;
const honestEvent = firstTree.getEvents()[0];

console.log("\n[Challenge 2] Wrong-price challenge on honest event (should FAIL)");
console.log(`  Event:     ${honestEvent.eventId}`);
console.log(`  Batch:     ${firstAnchor.batchId}`);
console.log(`  meterUnits × unitPrice = ${honestEvent.meterUnits} × ${honestEvent.unitPriceMicroUsdc} = ${honestEvent.meterUnits * honestEvent.unitPriceMicroUsdc}`);
console.log(`  recorded totalMicroUsdc = ${honestEvent.totalMicroUsdc} (correct)`);

const honestProof = firstTree.proveByEventId(honestEvent.eventId);
const challenge2: Challenge = {
  batchId: firstAnchor.batchId,
  eventId: honestEvent.eventId,
  claim: "wrong-price",
  proof: honestProof,
  expected: {
    totalMicroUsdc: honestEvent.meterUnits * honestEvent.unitPriceMicroUsdc,
  },
  observed: { totalMicroUsdc: honestEvent.totalMicroUsdc },
  event: honestEvent,
};

const result2 = await verifyChallenge(
  challenge2,
  firstAnchor,
  operatorPubKey,
  resolver
);
console.log(`  Result:    valid=${result2.valid}, severity=${result2.severity}`);
console.log(`  Reason:    ${result2.reason}`);
console.log(`  → Challenge ${result2.valid ? "SUCCEEDED" : "FAILED ✓ (expected)"}`);

// ---------------------------------------------------------------------------
// Final
// ---------------------------------------------------------------------------

console.log("\n" + "═".repeat(70));
console.log("Simulation complete.");
console.log(
  `Summary: ${TOTAL_EVENTS} events → ${anchors.length} anchors → ` +
  `${microUsdcToUsdc(grandTotal)} settled → ${compressionRatio.toFixed(0)}x gas savings`
);
console.log("═".repeat(70));
