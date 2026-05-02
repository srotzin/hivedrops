/**
 * @file anchor-stub.ts
 * @description Stub implementation of the L2 anchor submission function.
 *
 * ============================================================
 * !!! INTEGRATION POINT — REPLACE IN PRODUCTION !!!
 * ============================================================
 * This module contains a STUB that returns a deterministic fake transaction
 * hash. It does NOT make any on-chain calls and does NOT interact with any
 * RPC endpoint.
 *
 * In a production deployment, this function would be replaced with a call to
 * the HiveDrops anchor contract on Base (or other EVM L2), e.g.:
 *
 *   import { createPublicClient, createWalletClient, http } from "viem";
 *   import { base } from "viem/chains";
 *
 *   const HIVEDROPS_CONTRACT = "0x...";  // deployed anchor contract
 *
 *   export async function productionAnchorFn(
 *     root: string,
 *     totalAmount: number,
 *     batchId: string
 *   ): Promise<string> {
 *     const walletClient = createWalletClient({ chain: base, transport: http(RPC_URL) });
 *     const hash = await walletClient.writeContract({
 *       address: HIVEDROPS_CONTRACT,
 *       abi: HIVEDROPS_ABI,
 *       functionName: "anchorBatch",
 *       args: [root, BigInt(totalAmount), batchId],
 *     });
 *     return hash;
 *   }
 *
 * USDC contract on Base: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
 * Treasury address:       0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E
 * Chain ID:               8453 (Base mainnet)
 *
 * The L2 precompile embodiment (future work) would make this a ~30k-gas
 * precompile CALL rather than a full contract write. See PRECOMPILE-NOTES.md.
 * ============================================================
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "./event.js";
import type { AnchorFn } from "./types.js";

/**
 * Returns a deterministic fake transaction hash derived from the root and batchId.
 *
 * The hash is: `0xstub_<hex(SHA-256(root || ":" || batchId))>`
 *
 * This is PURELY DETERMINISTIC and NOT a real transaction. It is useful for:
 *   - Tests that need a stable tx hash for assertion
 *   - Local simulations that don't require a live L2 connection
 *   - CI environments without RPC access
 *
 * @param root        Hex-encoded Merkle root.
 * @param totalAmount Total micro-USDC in the batch (logged but not hashed —
 *                    the root already commits to this value indirectly).
 * @param batchId     The batch identifier string.
 * @returns           A fake tx hash string of the form `0xstub_<64 hex chars>`.
 */
export const stubAnchorFn: AnchorFn = async (
  root: string,
  totalAmount: number,
  batchId: string
): Promise<string> => {
  // !! STUB — NO REAL ON-CHAIN CALL !!
  const preimage = new TextEncoder().encode(`${root}:${batchId}`);
  const hash = sha256(preimage);
  const hexHash = bytesToHex(hash);

  // Log clearly so anyone watching the console knows this is a stub.
  console.log(
    `[STUB anchor] batch=${batchId} root=${root.slice(0, 10)}... ` +
      `totalMicroUsdc=${totalAmount} → fake_tx=0xstub_${hexHash}`
  );

  return `0xstub_${hexHash}`;
};
