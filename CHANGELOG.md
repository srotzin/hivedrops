# Changelog

All notable changes to `@hivecivilization/hivedrops-ref` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

- Phase 2: Real on-chain anchor function via `viem` client (Base testnet).
- Phase 2: Solidity `AnchorRegistry` + `SettlementVault` contracts.
- Phase 3: `@hivecivilization/prov-absence` — sorted-Merkle non-membership proofs for `missing` challenges.
- Phase 4: L2 precompile proposal for Base/Optimism.

---

## [0.0.1] — 2026-01-15

### Added

- `src/types.ts` — `UsageEvent`, `MerkleAnchor`, `Challenge`, `SettlementBreakdown`, `SettlementTx`, `AnchorFn`, `AccumulatorConfig`, `BatchInfo`, `MerkleInclusionProof`.
- `src/event.ts` — `signEvent`, `verifyEvent`, `eventHash`, canonical serialization helpers, base64url/hex utilities.
- `src/merkle.ts` — `UsageMerkleTree` (insertion-ordered, domain-separated, power-of-2 padded), `verifyProof` (pure function).
- `src/accumulator.ts` — `UsageAccumulator` with period- and threshold-triggered anchoring, injected clock for test determinism, persistence hook.
- `src/challenge.ts` — `verifyAnchorSig`, `verifyChallenge` (forged-sig, double-count, wrong-price, missing/TODO), `AgentPubKeyResolver` type.
- `src/settle.ts` — `computeSettlement` (92/8 split), `buildSettlementInstructions`, `microUsdcToUsdc`.
- `src/anchor-stub.ts` — `stubAnchorFn` (deterministic fake tx hash, no real RPC).
- `src/cli.ts` — `hivedrops simulate` and `hivedrops challenge` CLI commands.
- `tests/event.test.ts` — 19 tests.
- `tests/merkle.test.ts` — 20 tests.
- `tests/accumulator.test.ts` — 15 tests.
- `tests/challenge.test.ts` — 15 tests.
- `examples/run-simulation.ts` — 1,000-event simulation demo.
- `SPEC.md` — Full protocol specification.
- `PRECOMPILE-NOTES.md` — L2 precompile architectural notes.
- `README.md`, `LICENSE` (Apache 2.0), `.gitignore`, `CHANGELOG.md`.
- CI: `.github/workflows/ci.yml`.

### Notes

- All on-chain calls are stubbed (`stubAnchorFn`). No real RPC calls are made.
- `missing` challenge type returns advisory result (non-membership proofs deferred to `@hivecivilization/prov-absence`).
- Real-timer anchoring (`startTimer`) is included but all tests use injected clocks.
