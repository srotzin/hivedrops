/**
 * @file uuid.ts
 * @description Minimal UUID v4 implementation using Node.js crypto module.
 *
 * Copyright 2026 Hive Civilization
 * SPDX-License-Identifier: Apache-2.0
 */

import { randomBytes } from "crypto";

/**
 * Generates a cryptographically random UUID v4.
 */
export function v4(): string {
  const bytes = randomBytes(16);
  // Set version bits (version 4)
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  // Set variant bits (variant 1)
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = bytes.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}
