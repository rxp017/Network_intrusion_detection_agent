# Audit and verification — 15 September 2026

## Judge-feedback update — 24 September 2026

- The landing screen now leads with the held-out review queue outcome: raw classifier false-positive rate 33.41% versus queue false-positive rate 4.52%, with 89.42% queue recall. It also states the missed-attack cost and benchmark-replay boundary.
- Both modes now show a proposed follow-up, analyst approval/dismissal, optional note, and session export. Decisions use browser session storage only and always record `execution: "none"`; this is not live containment or a durable incident audit.
- The optional LLM cannot replace the model-derived follow-up. Direct wrong-class claims are rejected in favor of the built-in explanation. The guard is deliberately narrow; analysts must still compare prose with evidence.
- Built-in TreeSHAP wording now names the predicted-class model margin, not an attack score. The Docker image now includes the narrator module and its `httpx` runtime dependency, and CI has a container startup smoke test.
- Local verification: 63 non-browser tests, 8 Chromium browser tests, Ruff lint/format, JavaScript syntax, dependency integrity, and whitespace checks passed. Desktop and mobile screenshots were visually reviewed. Docker was unavailable locally; container status requires the new CI job.

The original audit evidence below is retained as a dated record of the earlier baseline.

## Fixed

| Original issue | Change |
|---|---|
| Random labels presented as benchmark evidence; original accuracy 36.8% versus a 41% majority baseline | Trained on a pinned public benchmark mirror; removed synthetic root CSVs; labelled the generator as a negative control |
| Claims of live capture and zero-day detection | Explicit benchmark replay and anomaly-candidate wording |
| Empty or incomplete requests produced predictions | Strict 42-feature validation, finite numeric bounds, field/type checks |
| Risk counted only the largest individual attack probability | Uses total non-Normal score and a validation-normal anomaly percentile |
| Excessive raw false alarms | Separate validation-derived review policy, with both operating points reported |
| Global rankings presented as local explanations | Native per-flow TreeSHAP; global gain separately labelled |
| Cross-split and training duplicates inflated evidence | Removed overlapping training rows and within-training feature duplicates |
| Incorrect anomaly false-positive reporting | Separate anomaly-only and joint Normal-plus-anomaly measurements |
| Relative paths broke startup outside the project folder | Resources resolved relative to the module |
| Unbounded requests and event-loop inference | Body/batch limits, stream cap, worker semaphore, threaded inference |
| Wildcard CORS and browser WebSocket origins | Same-origin browser behavior, local bind, origin checks and security headers |
| Internet-dependent dashboard | Local CSS, JavaScript, system fonts and SVG charts |
| No verification suite | Model/API/browser tests, clean installation, metric recomputation and CI |
| Git newline conversion could invalidate checksums | Canonical LF artifact JSON and replay, checked before publication |
| Synthetic generator could overwrite benchmark files | Separate ignored synthetic directory and refusal to overwrite |

## Verified locally

- CPython 3.14.7, Windows 11, pinned runtime requirements.
- Fresh virtual environment installed successfully; `pip check` passed.
- **50 tests passed:** 47 model/API tests and 3 Chromium end-to-end tests.
- Ruff lint, formatting, JavaScript syntax and Git whitespace checks passed.
- Chromium tested desktop (1600 px) and mobile (390 px), with non-local requests blocked. No unexpected browser errors.
- Pause/resume, scenarios, filters, keyboard inspection, JSON export, custom inference, invalid-input feedback and injection-safe rendering tested.
- Full 82,332-row metrics independently recomputed from the saved model and matched training output.
- Median/p95 inference including TreeSHAP: 30.7/35.1 ms across 100 local sequential flows. This is not throughput evidence.
- Dependency audit of **28 pinned runtime packages** found no known vulnerabilities in the queried database. [Machine-readable report](../verification/dependency-audit.json). Wheel hashes are not locked; this does not prove absence of vulnerabilities.
- Staged artifact bytes checked against the manifest before publication.

Two upstream deprecation warnings from the Starlette/httpx/AnyIO test-client integration remain visible. They do not fail the tests and are not suppressed.

## Remaining limits

- No live feature extraction, public API authentication, persistent incidents, SIEM connector or automatic containment.
- Analysis and Backdoor recall are below 10%; Worms has small test support.
- The review policy misses about 10.6% of labelled attacks at its measured operating point.
- The dataset mirror is pinned and hash-checked, not publisher-authenticated.
- Docker was unavailable locally; the container recipe is unverified.
- Linux CI status comes from GitHub Actions, not from the Windows result.
- No guarantee of production security, zero-day detection, hackathon eligibility or placement.

## Evidence

- [Full metrics and confusion matrix](../artifacts/evaluation.json)
- [Independent recomputation and timing](../verification/evaluation.json)
- [Artifact integrity manifest](../artifacts/manifest.json)
- [Desktop screenshot](images/dashboard.png) / [mobile screenshot](images/mobile.png)
- [Repeatable demo sequence](DEMO.md)
