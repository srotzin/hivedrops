/**
 * @file event.ts
 * @description Usage event signing, verification, and hashing.
 *
 * Canonical form: JSON.stringify with keys sorted alphabetically, excluding
 * the `sig` field. This ensures deterministic serialization across platforms.
 *
 * Signing: ed25519 (via @noble/ed25519) over SHA-512 of canonical bytes.
 * Hashing: SHA-256 over canonical bytes INCLUDING the `sig` field
 *   (sig is part of the Merkle leaf — it binds the agent's identity to the event).
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import { sha256 } from "@noble/hashes/sha256";
import * as ed from "@noble/ed25519";
import type { UsageEvent } from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Sorted list of all UsageEvent keys EXCEPT `sig`, for canonical form. */
const CANONICAL_KEYS_WITHOUT_SIG: ReadonlyArray<keyof Omit<UsageEvent, "sig">> =
  [
    "agentDid",
    "consumerDid",
    "eventId",
    "meterUnits",
    "nonce",
    "service",
    "totalMicroUsdc",
    "ts",
    "unitPriceMicroUsdc",
  ] as const;

/** Sorted list of all UsageEvent keys INCLUDING `sig`, for leaf hashing. */
const CANONICAL_KEYS_WITH_SIG: ReadonlyArray<keyof UsageEvent> = [
  "agentDid",
  "consumerDid",
  "eventId",
  "meterUnits",
  "nonce",
  "service",
  "sig",
  "totalMicroUsdc",
  "ts",
  "unitPriceMicroUsdc",
] as const;

/**
 * Produces a deterministic JSON string of the event, with keys in
 * alphabetical order, EXCLUDING the `sig` field.
 *
 * Used as the preimage for ed25519 signing.
 */
export function canonicalizeEventForSigning(
  event: Omit<UsageEvent, "sig">
): string {
  const ordered: Record<string, unknown> = {};
  for (const key of CANONICAL_KEYS_WITHOUT_SIG) {
    ordered[key] = (event as unknown as Record<string, unknown>)[key];
  }
  return JSON.stringify(ordered);
}

/**
 * Produces a deterministic JSON string of the full event (including `sig`).
 *
 * Used as the preimage for the Merkle leaf hash.
 */
export function canonicalizeEventWithSig(event: UsageEvent): string {
  const ordered: Record<string, unknown> = {};
  for (const key of CANONICAL_KEYS_WITH_SIG) {
    ordered[key] = (event as unknown as Record<string, unknown>)[key];
  }
  return JSON.stringify(ordered);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Signs a usage event with an agent's ed25519 private key.
 *
 * The signature covers all event fields EXCEPT `sig` itself.
 * Returns a new UsageEvent with the `sig` field populated.
 *
 * @param event        Event to sign (without `sig` field).
 * @param agentPrivKey 32-byte ed25519 private key seed.
 * @returns            Signed event with base64url-encoded `sig`.
 */
export async function signEvent(
  event: Omit<UsageEvent, "sig">,
  agentPrivKey: Uint8Array
): Promise<UsageEvent> {
  const canonical = canonicalizeEventForSigning(event);
  const bytes = new TextEncoder().encode(canonical);
  const sigBytes = await ed.signAsync(bytes, agentPrivKey);
  const sigB64u = bytesToBase64Url(sigBytes);
  return { ...event, sig: sigB64u } as UsageEvent;
}

/**
 * Verifies the ed25519 signature on a usage event.
 *
 * @param event       The full signed event.
 * @param agentPubKey 32-byte ed25519 public key of the signing agent.
 * @returns           `true` if the signature is valid, `false` otherwise.
 */
export async function verifyEvent(
  event: UsageEvent,
  agentPubKey: Uint8Array
): Promise<boolean> {
  try {
    const { sig, ...rest } = event;
    const canonical = canonicalizeEventForSigning(rest as Omit<UsageEvent, "sig">);
    const bytes = new TextEncoder().encode(canonical);
    const sigBytes = base64UrlToBytes(sig);
    return await ed.verifyAsync(sigBytes, bytes, agentPubKey);
  } catch {
    return false;
  }
}

/**
 * Computes the SHA-256 Merkle leaf hash of a signed event.
 *
 * Domain separation: SHA-256(0x00 || canonicalEventBytesWithSig)
 *
 * The signature is INCLUDED in the leaf hash. This binds the agent's identity
 * to the leaf — a forged event with the same content but a different sig would
 * produce a different leaf hash and therefore a different Merkle root.
 *
 * @param event The fully signed event.
 * @returns     32-byte SHA-256 hash.
 */
export function eventHash(event: UsageEvent): Uint8Array {
  const canonical = canonicalizeEventWithSig(event);
  const bytes = new TextEncoder().encode(canonical);
  // Domain separation: leaf prefix 0x00
  const prefixed = new Uint8Array(1 + bytes.length);
  prefixed[0] = 0x00;
  prefixed.set(bytes, 1);
  return sha256(prefixed);
}

// ---------------------------------------------------------------------------
// Base64URL helpers (no padding, RFC 4648 §5)
// ---------------------------------------------------------------------------

export function bytesToBase64Url(bytes: Uint8Array): string {
  const b64 = Buffer.from(bytes).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlToBytes(b64u: string): Uint8Array {
  const b64 =
    b64u.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (b64u.length % 4)) % 4);
  return new Uint8Array(Buffer.from(b64, "base64"));
}

// ---------------------------------------------------------------------------
// Hex helpers (exported for use by other modules)
// ---------------------------------------------------------------------------

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}
