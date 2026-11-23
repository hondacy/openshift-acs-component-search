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

### git — committed & pushed
- Branch **`fix/parse-json-lines-array`** created off `main`, commit `4e220d5`.
- Contains the `parseJsonLines` fix + this `CLAUDE.md`.
- Pushed to `origin` (github.com/hondacy/openshift-acs-component-search.git).
- PR not yet opened: https://github.com/hondacy/openshift-acs-component-search/pull/new/fix/parse-json-lines-array
- (A later commit updating this file for the staging outcome may follow this note.)

### npm — real 1.0.0 NOT published; a STUB is live
Target registry: `https://registry.npmjs.org/`, token in `~/.npmrc`, account `devsops`.

Attempts made, in order:
1. `npm publish` → **EOTP** (registry requires a 2FA one-time password; token is
   not an automation token, so it can't publish non-interactively).
2. `npm publish --stage` → `--stage` is **not a valid flag** (npm warns
   "Unknown cli config", ignores it); same EOTP wall.
3. `npm stage publish` → this DID reach the registry (`POST /-/stage/package/...`)
   and created a **staging stub**, not the real package.

Current registry state (`npm view acs-component-search`):
- `dist-tags.latest = 0.0.0-stage`
- `versions = ["0.0.0-stage"]` — a placeholder: `description "Temporary package
  placeholder for staged publishing"`, `stub: true`, 2 files, 342 bytes,
  created 2026-11-23T10:07:33Z, maintainer `devsops`.
- **Your real `acs-component-search@1.0.0` is NOT on npm.** Anyone running
  `npm install acs-component-search` currently gets the empty 0.0.0-stage stub.
- Re-running `npm stage publish` now fails `E409 Conflict` ("Cannot stage
  previously published version 1.0.0").
- npm warned: tokens that bypass 2FA are being restricted —
  https://gh.io/npm-gat-bypass2fa-deprecation

To actually publish 1.0.0 (needs OTP/automation token, done by the user):
- `npm publish --otp=<code>` with a fresh authenticator code, OR
- put an npm **automation token** in `~/.npmrc`, then `npm publish`.
Open question for the user: whether to clean up / repoint the `0.0.0-stage` stub
(e.g. move the `latest` dist-tag, or unpublish the stub) once 1.0.0 is up.
