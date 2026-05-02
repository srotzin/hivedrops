#!/usr/bin/env node
/**
 * @file cli.ts
 * @description HiveDrops CLI — simulate and challenge commands.
 *
 * Usage:
 *   hivedrops simulate <events.jsonl> [--period 60s] [--threshold 100usdc]
 *   hivedrops challenge <anchor.json> <event-proof.json>
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from "fs";
import * as ed from "@noble/ed25519";
import { UsageAccumulator } from "./accumulator.js";
import { verifyChallenge, verifyAnchorSig } from "./challenge.js";
import { computeSettlement, buildSettlementInstructions, microUsdcToUsdc } from "./settle.js";
import { stubAnchorFn } from "./anchor-stub.js";
import { verifyEvent } from "./event.js";
import type { MerkleAnchor, Challenge, UsageEvent } from "./types.js";

// ---------------------------------------------------------------------------
// Duration/amount parsers
// ---------------------------------------------------------------------------

function parsePeriod(s: string): number {
  const m = s.match(/^(\d+(?:\.\d+)?)(ms|s|m|h)$/);
  if (!m) throw new Error(`Cannot parse period: ${s} (expected e.g. 60s, 5m, 1h)`);
  const val = parseFloat(m[1]);
  switch (m[2]) {
    case "ms": return val;
    case "s":  return val * 1000;
    case "m":  return val * 60 * 1000;
    case "h":  return val * 3600 * 1000;
    default:   throw new Error(`Unknown unit: ${m[2]}`);
  }
}

function parseThreshold(s: string): number {
  // Supports: 100usdc, 100000000microusdc, 100 (bare number = micro-USDC)
  const lower = s.toLowerCase();
  if (lower.endsWith("usdc") && !lower.endsWith("microusdc")) {
    return Math.round(parseFloat(lower) * 1_000_000);
  }
  if (lower.endsWith("microusdc")) {
    return parseInt(lower);
  }
  return parseInt(s, 10);
}

// ---------------------------------------------------------------------------
// simulate command
// ---------------------------------------------------------------------------

async function cmdSimulate(args: string[]): Promise<void> {
  const positional: string[] = [];
  let periodStr = "60s";
  let thresholdStr = "100usdc";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--period" && args[i + 1]) {
      periodStr = args[++i];
    } else if (args[i] === "--threshold" && args[i + 1]) {
      thresholdStr = args[++i];
    } else {
      positional.push(args[i]);
    }
  }

  const eventsPath = positional[0];
  if (!eventsPath) {
    console.error("Usage: hivedrops simulate <events.jsonl> [--period 60s] [--threshold 100usdc]");
    process.exit(1);
  }

  const periodMs = parsePeriod(periodStr);
  const thresholdMicroUsdc = parseThreshold(thresholdStr);

  console.log(`HiveDrops simulate: period=${periodStr} (${periodMs}ms), threshold=${thresholdStr} (${thresholdMicroUsdc} µUSDC)`);
  console.log(`Reading events from: ${eventsPath}\n`);

  const lines = readFileSync(eventsPath, "utf8")
    .split("\n")
    .filter((l) => l.trim());

  const events: UsageEvent[] = lines.map((line, i) => {
    try {
      return JSON.parse(line) as UsageEvent;
    } catch (e) {
      throw new Error(`Line ${i + 1}: invalid JSON — ${e}`);
    }
  });

  console.log(`Loaded ${events.length} events.\n`);

  // Generate operator keys for simulation
  const operatorPrivKey = ed.utils.randomPrivateKey();
  const operatorPubKey = await ed.getPublicKeyAsync(operatorPrivKey);

  const acc = new UsageAccumulator(
    { periodMs, thresholdMicroUsdc, operatorPubKey, operatorPrivKey },
    stubAnchorFn
  );

  // Simulate with monotonically increasing virtual time
  let virtualMs = Date.now();
  let i = 0;
  for (const event of events) {
    // Advance virtual time based on event timestamp
    const ts = new Date(event.ts).getTime();
    if (!isNaN(ts) && ts > virtualMs) {
      // Check if we need to tick (period may have elapsed)
      await acc.tick(ts);
      virtualMs = ts;
    }
    await acc.addEvent(event);
    i++;
  }

  // Close any remaining open batch
  const remaining = acc.currentBatch();
  if (remaining.eventCount > 0) {
    await acc.anchor(virtualMs + 1);
  }

  const anchors = acc.getClosedAnchors();

  console.log("=".repeat(60));
  console.log(`ANCHORS (${anchors.length} batches)`);
  console.log("=".repeat(60));

  let totalSettled = 0;
  const settlementTxsAll: Array<{ anchor: MerkleAnchor; txs: ReturnType<typeof buildSettlementInstructions> }> = [];

  for (const anchor of anchors) {
    const settlement = computeSettlement(anchor);
    const txs = buildSettlementInstructions(settlement, {
      agent: "0xAgentMultisigExample",
      treasury: "0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E",
    });
    settlementTxsAll.push({ anchor, txs });
    totalSettled += anchor.totalMicroUsdc;

    console.log(`\nBatch: ${anchor.batchId}`);
    console.log(`  Events:        ${anchor.eventCount}`);
    console.log(`  Total:         ${microUsdcToUsdc(anchor.totalMicroUsdc)}`);
    console.log(`  Period:        ${anchor.periodStart} → ${anchor.periodEnd}`);
    console.log(`  Merkle root:   ${anchor.merkleRoot.slice(0, 16)}...`);
    console.log(`  Anchor tx:     ${anchor.anchorTxHash}`);
    console.log(`  Settlement:`);
    for (const tx of txs) {
      console.log(`    → ${tx.to.slice(0, 12)}...  ${microUsdcToUsdc(tx.amountMicroUsdc)}  [${tx.memo.slice(0, 40)}...]`);
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log("SUMMARY");
  console.log("=".repeat(60));
  console.log(`  Total events:     ${events.length}`);
  console.log(`  Total batches:    ${anchors.length}`);
  console.log(`  Total settled:    ${microUsdcToUsdc(totalSettled)}`);
  console.log(`  On-chain txs:     ${anchors.length} anchor + ${anchors.length} settlement calls`);
  console.log(`  Events per tx:    ${(events.length / Math.max(1, anchors.length)).toFixed(1)} (vs 1 per event without HiveDrops)`);
  console.log(`  Compression:      ${events.length}x fewer on-chain txs`);
}

// ---------------------------------------------------------------------------
// challenge command
// ---------------------------------------------------------------------------

async function cmdChallenge(args: string[]): Promise<void> {
  const anchorPath = args[0];
  const proofPath = args[1];

  if (!anchorPath || !proofPath) {
    console.error("Usage: hivedrops challenge <anchor.json> <event-proof.json>");
    process.exit(1);
  }

  const anchor = JSON.parse(readFileSync(anchorPath, "utf8")) as MerkleAnchor;
  const payload = JSON.parse(readFileSync(proofPath, "utf8")) as {
    challenge: Challenge;
    operatorPubKey: string; // hex
    agentPubKeys?: Record<string, string>; // agentDid → hex pubkey
  };

  const challenge = payload.challenge;
  const operatorPubKey = Buffer.from(payload.operatorPubKey, "hex");

  // Build a simple pubkey resolver from the provided map
  const agentPubKeys: Record<string, string> = payload.agentPubKeys ?? {};
  const resolver = async (did: string) => {
    const hex = agentPubKeys[did];
    if (!hex) return null;
    return Buffer.from(hex, "hex");
  };

  console.log(`HiveDrops challenge: batchId=${anchor.batchId}`);
  console.log(`  Claim type: ${challenge.claim}`);
  console.log(`  EventId:    ${challenge.eventId}`);

  const result = await verifyChallenge(challenge, anchor, operatorPubKey, resolver);

  console.log(`\nResult:`);
  console.log(`  Valid:    ${result.valid}`);
  console.log(`  Severity: ${result.severity}`);
  console.log(`  Reason:   ${result.reason}`);

  if (result.valid && result.severity === "fatal") {
    console.log("\n!! CHALLENGE SUCCEEDED: Batch is disputable. !!");
    process.exit(2); // non-zero exit for scripting
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv;

  switch (cmd) {
    case "simulate":
      await cmdSimulate(rest);
      break;
    case "challenge":
      await cmdChallenge(rest);
      break;
    default:
      console.log("HiveDrops CLI");
      console.log("Commands:");
      console.log("  simulate <events.jsonl> [--period 60s] [--threshold 100usdc]");
      console.log("  challenge <anchor.json> <event-proof.json>");
      process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
