# CLAUDE.md

Project notes and state for `acs-component-search`.

## Overview
CLI to search Red Hat Advanced Cluster Security (RHACS / StackRox) for deployments
running a given image component and report where/how/which version. Pure ESM
JavaScript (no build step). Node `>=18`. Single runtime dep: `commander@^12`.

- Entry: `bin/cli.js`
- Core: `src/client.js` (query build, fetch, row extraction), `src/format.js` (output)
- Tests: `test/unit.test.js` via `node --test` (`npm test`)

## Session state — 2026-11-23

### Node compatibility
- Confirmed compatible with latest Node (verified on **Node v26.13.1**, npm 11.20.0).
  Uses global `fetch`, `node:module` `createRequire`, `node:test`/`node:assert` —
  all stable, nothing removed/deprecated in current Node.
- Minor note (not yet changed): `engines.node` is `>=18`, but `commander@12`
  actually needs `^18.19.0 || >=20`. Consider tightening the floor.

### Build / test
- No `build` script exists (plain ESM, nothing to compile) — "build" is a no-op.
- **Bug fixed** in `src/client.js` `parseJsonLines`: a single-line JSON *array*
  body (e.g. `[{"a":1}]`) was double-wrapped as `[[{a:1}]]` because the per-line
  `JSON.parse` pushed the whole array as one element and the array-flattening
  fallback only ran when `out` was empty. Fix: flatten arrays in the per-line loop
  (`if (Array.isArray(parsed)) out.push(...parsed)`).
- Tests: **7/7 passing** after the fix (was 6/7).

### npm upload — BLOCKED (not published)
- Target: `https://registry.npmjs.org/`, auth token in `~/.npmrc`, account `devsops`.
- `npm publish --dry-run` OK: 6 files, 6.5 kB tarball, no secrets leaked.
- `npm publish` **failed: EOTP** — registry requires a one-time password (2FA).
  The token authenticates but is not an *automation* token, so it cannot complete
  a publish non-interactively. **`acs-component-search@1.0.0` is NOT on npm.**
- To finish uploading, do one of:
  - Create an npm **automation token** (bypasses 2FA), put it in `~/.npmrc`, re-run `npm publish`.
  - Run `npm publish` interactively and enter the OTP.
  - `npm publish --otp=<code>` with a fresh authenticator code.
- Note: the `parseJsonLines` fix is in the working tree but **not committed**.
