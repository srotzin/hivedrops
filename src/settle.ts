/**
 * @file settle.ts
 * @description Settlement computation for HiveDrops usage batches.
 *
 * SETTLEMENT RATIONALE (Hive Ambassador Economics):
 *   92% → Agent/Provider: Reflects Hive Civilization's philosophy of
 *     maximizing returns to the agents doing the work. This is analogous
 *     to the "ambassador split" in the Hive Civilization token model, where
 *     the vast majority of value flows to contributors.
 *   8% → Treasury: Protocol sustainability, security audits, bug bounties,
 *     governance reserve. Address: 0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E
 *
 *   Optional consumer_rebate: Reduces both agent and treasury proportionally.
 *   Consumer rebates are used for volume discounts, SLA credits, or dispute
 *   resolution payouts.
 *
 * USDC contract on Base: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
 * Treasury address:       0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E
 *
 * COPYRIGHT NOTICE:
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import type {
  MerkleAnchor,
  SettlementBreakdown,
  SettlementTx,
} from "./types.js";

// ---------------------------------------------------------------------------
// Default splits (in basis points, 1 bps = 0.01%)
// ---------------------------------------------------------------------------

/** Default agent share: 9200 bps = 92% */
export const DEFAULT_AGENT_BPS = 9200;
/** Default treasury share: 800 bps = 8% */
export const DEFAULT_TREASURY_BPS = 800;
/** Total basis points (always 10000) */
export const TOTAL_BPS = 10000;

// ---------------------------------------------------------------------------
// computeSettlement
// ---------------------------------------------------------------------------

/**
 * Computes the settlement breakdown for a MerkleAnchor.
 *
 * This is a PURE FUNCTION — it does not broadcast anything. The resulting
 * `SettlementBreakdown` is passed to `buildSettlementInstructions()` to
 * produce the actual transfer records.
 *
 * Rounding: integer truncation (floor). Any remainder after truncation is
 * left in the agent share (i.e., the agent gets any "dust").
 *
 * @param anchor  The sealed MerkleAnchor to settle.
 * @param splits  Optional override for the split percentages.
 *                - `agent`: bps for the agent (default 9200).
 *                - `treasury`: bps for the treasury (default 800).
 *                - `consumer_rebate`: bps for consumer rebate (default 0).
 *                The three values must sum to ≤ 10000. If they sum to < 10000,
 *                the remainder is added to the agent share.
 * @returns       A SettlementBreakdown with all amounts in micro-USDC.
 */
export function computeSettlement(
  anchor: MerkleAnchor,
  splits: {
    agent?: number;
    treasury?: number;
    consumer_rebate?: number;
  } = {}
): SettlementBreakdown {
  const agentBps = splits.agent ?? DEFAULT_AGENT_BPS;
  const treasuryBps = splits.treasury ?? DEFAULT_TREASURY_BPS;
  const consumerRebateBps = splits.consumer_rebate ?? 0;

  const totalBps = agentBps + treasuryBps + consumerRebateBps;
  if (totalBps > TOTAL_BPS) {
    throw new Error(
      `Split percentages sum to ${totalBps} bps, exceeding 10000 bps (100%). ` +
        `agent=${agentBps} + treasury=${treasuryBps} + consumer_rebate=${consumerRebateBps} = ${totalBps}`
    );
  }

  const total = anchor.totalMicroUsdc;

  // Compute each share with integer truncation
  const treasuryAmount = Math.floor((total * treasuryBps) / TOTAL_BPS);
  const consumerRebateAmount = Math.floor(
    (total * consumerRebateBps) / TOTAL_BPS
  );
  // Agent gets the remainder (avoids rounding dust being lost)
  const agentAmount = total - treasuryAmount - consumerRebateAmount;

  return {
    batchId: anchor.batchId,
    totalMicroUsdc: total,
    agentMicroUsdc: agentAmount,
    treasuryMicroUsdc: treasuryAmount,
    consumerRebateMicroUsdc: consumerRebateAmount,
    splitBps: {
      agent: agentBps,
      treasury: treasuryBps,
      consumer_rebate: consumerRebateBps,
    },
  };
}

// ---------------------------------------------------------------------------
// buildSettlementInstructions
// ---------------------------------------------------------------------------

/**
 * Builds the list of on-chain transfer instructions for a settlement.
 *
 * This is a PURE FUNCTION — it does NOT broadcast anything. The resulting
 * `SettlementTx[]` array represents the USDC.transferFrom() calls that a
 * settlement executor would broadcast.
 *
 * INTEGRATION POINT: Pass these to a real USDC multicall or settlement
 * contract to actually execute the transfers on-chain.
 *
 * @param settlement  The computed settlement breakdown.
 * @param recipientMap  A map from role names to EVM addresses (or DID-resolved
 *                      addresses). Keys: "agent", "treasury", "consumer_rebate".
 * @returns           Array of SettlementTx records.
 */
export function buildSettlementInstructions(
  settlement: SettlementBreakdown,
  recipientMap: {
    agent: string;
    treasury: string;
    consumer_rebate?: string;
  }
): SettlementTx[] {
  const txs: SettlementTx[] = [];

  if (settlement.agentMicroUsdc > 0) {
    txs.push({
      to: recipientMap.agent,
      amountMicroUsdc: settlement.agentMicroUsdc,
      memo: `HiveDrops batch=${settlement.batchId} agent_share (${settlement.splitBps.agent / 100}%)`,
    });
  }

  if (settlement.treasuryMicroUsdc > 0) {
    txs.push({
      to: recipientMap.treasury,
      amountMicroUsdc: settlement.treasuryMicroUsdc,
      memo: `HiveDrops batch=${settlement.batchId} treasury_fee (${settlement.splitBps.treasury / 100}%)`,
    });
  }

  if (
    settlement.consumerRebateMicroUsdc > 0 &&
    recipientMap.consumer_rebate
  ) {
    txs.push({
      to: recipientMap.consumer_rebate,
      amountMicroUsdc: settlement.consumerRebateMicroUsdc,
      memo: `HiveDrops batch=${settlement.batchId} consumer_rebate (${settlement.splitBps.consumer_rebate / 100}%)`,
    });
  }

  return txs;
}

// ---------------------------------------------------------------------------
// Convenience: micro-USDC to USDC string
// ---------------------------------------------------------------------------

/**
 * Converts micro-USDC to a human-readable USDC string.
 * e.g., 1_500_000 → "1.500000 USDC"
 */
export function microUsdcToUsdc(microUsdc: number): string {
  const usdc = microUsdc / 1_000_000;
  return `${usdc.toFixed(6)} USDC`;
}
