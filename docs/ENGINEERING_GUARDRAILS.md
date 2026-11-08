# FluxOpen — Engineering Guardrails (P0–P5)

Baseline: main commit `e8475620f5ce42d40c66c904636c851e4099bffa` (2026-11-08).

## Invariants (must not change silently)
- Existing Cloudflare secrets: `ADMIN_PASSWORD`, `SCAN_SIGNING_SECRET`, `GH_TOKEN`; GitHub Actions secret `SCAN_SIGNING_SECRET`. Never print or rotate values during routine releases.
- D1 binding `DB`; tables `sessions`, `login_failures`, `targets`, `scans`, `admin_identity`, `passkeys`, `webauthn_challenges`, `scan_dispatch`. No destructive migrations.
- Worker public endpoints, authenticated routes, WebAuthn origin/RP ID, HMAC payload and callback contract remain backward-compatible.
- Do not automatically widen scan scope or increase request rates; only authorized targets.
- Keep signed raw reports immutable; apply human-readable interpretation at read time.
- No paid dependencies, external LLM or mandatory SaaS beyond existing deployment. Self-hosted mode remains supported.

## Sequence and release gates
1. **P0 baseline**: inventory above, baseline SHA, no changes to production secrets/variables/bindings.
2. **P1 callback security**: review PR #13, test invalid signatures, replay, concurrent callbacks, legacy payload compatibility. Merge only after integration tests.
3. **P2 scanner reliability**: reproduce Nuclei timeout, Nikto help output, ZAP report path, FFUF SPA false positives; distinguish completed, skipped, warning and failed. Preserve passive/active authorization rules.
4. **P3 reporting**: improve accessible HTML, friendly titles and export filename, preserve raw JSON and historical D1 reports.
5. **P4 privacy**: redact sensitive query values in presentation and logs without altering signed source evidence; test XSS/HTML escaping.
6. **P5 QA/release**: unit tests, Node tests, scanner smoke, Worker integration and mobile E2E. Compare against baseline and use a small reversible deployment.

## Before every merge
- Run `python3 -m unittest discover -s tests -v` and `node --test tests/*.mjs` plus existing GitHub Actions CI.
- Validate Worker login/password, passkeys, CSRF, target authorization, dispatch, HMAC callback, D1 report retrieval and HTML/JSON exports.
- Record changed files, tests, impact, rollback commit and deployment verification.
- If any critical invariant fails: **do not merge or deploy**. Restore previous Worker version and revert the commit, leaving secrets and D1 intact.
