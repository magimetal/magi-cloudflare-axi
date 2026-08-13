---
title: Cloudflare full capability parity roadmap
status: phase-4-in-progress
owner: magimetal
created: 2026-08-10
last_reviewed: 2026-08-11
current_phase: phase-4-in-progress
baseline_source_commit: 70ff690553722f731849ede6ba9ce98958395a23
baseline_capabilities: 172
canonical_tracker: capabilities/cloudflare-mcp-parity.json
---

# Cloudflare full capability parity roadmap

## Goal

Deliver source-evidenced, agent-safe CLI access to every capability registered by the pinned Cloudflare MCP source.

For this roadmap, **full parity** means functional parity with the 172 capabilities registered at Cloudflare MCP commit `70ff690553722f731849ede6ba9ce98958395a23`. It does not mean every Cloudflare REST/GraphQL endpoint or future upstream capability.

A capability counts complete only when it has:

1. registered-name identity;
2. authoritative input schema;
3. exact direct or hosted execution route;
4. output and error behavior contract;
5. correct safety policy;
6. hermetic real-binary verification;
7. generated discovery/help;
8. traceable evidence tied to pinned source.

Registered-name presence alone remains **inventory parity**, not full parity.

## Current baseline

| Dimension | Current | Target |
|---|---:|---:|
| Registered names | 172/172 | 172/172 |
| Canonical input schemas | 172/172 | 172/172 |
| Method metadata | 147/172 | Route-dependent |
| Path metadata | 13/172 | Every direct route complete |
| Capability-specific complete routes | 16/172 | 172/172, or maximal attainable parity with explicit blockers |
| Capability contract tests | 16/172 | 172/172 hermetically verified |

Phase 4C is in progress. Seven authenticated Browser reads are complete, verified, and discovery-verified: `get_url_markdown`, `get_url_links`, `scrape_url_elements`, `get_url_json`, `get_url_snapshot`, `get_crawl_result`, and `list_browser_sessions`. Exact contract vector: `I=172; S=172; R=B=P=V=16; D=11; X=40`; discovery is 11 verified and five generated, with 156 routes unresolved. For `list_browser_sessions`, pinned `GET /accounts/{account_id}/browser-run/devtools/session` is authority; official docs instead show `/browser-rendering/devtools/session` with optional `limit`/`offset`, while pinned zero-input handler exposes neither query. Binary PNG/PDF Browser reads remain.

Phase 3 exit gate for proven direct unauthenticated Blog cohort:

```text
I = S = 172
R = B = P = V = 9
D = 4
X = 40
Blog direct reads = 4/4 complete and discovery-verified
163 routes unresolved
```

Phase 3 completed `2026-08-11` for four Blog operations only. Research pool correction: initial 80 legacy `public_http` reads = Browser 9 + Radar 65 + Blog 4 + demo 1 + stack 1. Browser/Radar require authoritative route, transport, scope, and authentication reclassification during Phase 4 research; demo/stack require source-hosted or MCP route research during Phase 5. DNS Analytics is outside this legacy pool.

| Scope | Current | Target |
|---|---:|---:|
| Verified reads | 15/150 | 150/150 |
| Hermetically verified writes | 1/22 | 22/22 |
| Open blocker entries | 40 | 0 |
| Fully verified families | 1/18 | 18/18 |

Current access classifications:

| Classification | Count |
|---|---:|
| `raw_rest` | 126 |
| `modeled` | 7 |
| `mcp_remote` | 26 |
| `public_direct` | 6 |
| `raw_graphql` | 6 |
| `blocked` | 1 |

Current transport inventory:

| Transport | Count |
|---|---:|
| `public_http` | 78 |
| `rest` | 79 |
| `custom_container` | 7 |
| `graphql` | 6 |
| `internal_binding` | 1 |
| `mcp` | 1 |

Thirteen catalog records carry both `method` and `path_template`; operation-contract artifact contains sixteen complete routes.


## Completion formula

Track parity as independent dimensions, not one weighted percentage:

| Code | Dimension | Complete when |
|---|---|---|
| I | Inventory | Name and source registration match pinned source |
| S | Schema | Canonical JSON Schema is complete, or zero-input is evidenced |
| R | Route | Exact REST, GraphQL, public HTTP, or hosted MCP route is known |
| B | Behavior | Output, empty state, pagination, artifact, and error behavior are specified |
| P | Policy | Read/write, destructive, metered, egress, confirmation, and retry policy are verified |
| V | Verification | Real binary passes hermetic request/response and safety tests |
| D | Discovery | Schema, access recipe, focused help, and example are generated |
| X | External blocker | Provider exposure or evidence still prevents implementation |

Full parity gate:

```text
I = S = R = B = P = V = D = 172
X = 0
pinned-source drift = 0
release gate = pass
```

If Cloudflare exposes no usable route for one or more registered capabilities, project must report **maximal attainable parity** with exact vector and blocker count. It must not claim full parity.

## Tracking model

`capabilities/cloudflare-mcp-parity.json` remains canonical machine-readable tracker. Phase 0 versions schema and makes every parity dimension explicit.

Each capability record must eventually carry explicit status and evidence for every parity dimension:

```text
identity:
  name, family, apps, source_commit, source_ref
parity:
  inventory: { status, evidence_ids }
  schema: { status, evidence_ids }
  route: { status, evidence_ids }
  behavior: { status, evidence_ids }
  policy: { status, evidence_ids }
  verification: { status, evidence_ids }
  discovery: { status, evidence_ids }
  external_blocker: { status, blocker_id, evidence_ids }
schema_contract:
  input_schema, source_ref, content_hash
behavior_contract:
  output_contract, empty_state, pagination, artifact_behavior, error_behavior
safety_contract:
  operation, destructive, metered, data_egress, long_running, retry_policy
route_contract:
  transport, method/path/query/body mapping
  or MCP server/tool/protocol mapping
implementation:
  adapter, test_id, documentation_id, reviewed_at
```

Canonical status values:

| Dimension | Allowed values | Counts complete when |
|---|---|---|
| Inventory | `unresolved`, `complete` | `complete` |
| Schema | `unresolved`, `complete`, `zero_input_evidenced` | `complete` or `zero_input_evidenced` |
| Route | `unresolved`, `complete`, `external_blocked` | `complete` |
| Behavior | `unresolved`, `specified`, `verified` | `verified` |
| Policy | `unresolved`, `classified`, `verified` | `verified` |
| Verification | `unverified`, `hermetic_verified` | `hermetic_verified` |
| Discovery | `missing`, `generated`, `verified` | `verified` |
| External blocker | `none`, `open`, `resolved` | `none` or `resolved` |
| Implementation | `research`, `specified`, `implemented`, `verified`, `external_blocked` | Informational; never substitutes for parity dimensions |
| Evidence | `missing`, `source_verified`, `official_verified`, `hermetic_verified` | Per-dimension gate decides |
| Phase | `not_started`, `active`, `blocked`, `complete` | `complete` |

Dashboard rollups count only values in the final column. `X` is the number of records whose external blocker is `open` or whose route is `external_blocked`. CI derives I/S/R/B/P/V/D/X directly from these fields; it must not infer completion from `implementation`, transport, method, path, or free-text blocker fields.

Existing `input_fields` may remain as generated compact summary. It cannot remain canonical because it cannot represent nested objects, arrays, unions, defaults, refinements, or constraints.

Detailed 172-row progress must be generated from catalog into `docs/cloudflare-capability-parity.md`; never maintain that matrix manually.
### Manifest census contract

Pinned census reports exact registered identity, innermost dependency ownership, closure capability union, source spans, and SHA-256 integrity. Unsupported AST forms remain reported census blockers, not silent fail-closed omissions. CI and release gates use same pinned assertions.

## Target command architecture

Prefer one catalog-driven invocation surface instead of 172 hand-built subcommands:

```sh
magi-cloudflare-axi capability schema <name>
magi-cloudflare-axi capability invoke <name> --input '<json>'
magi-cloudflare-axi capability invoke <name> --file input.json
```

Dispatcher responsibilities:

1. load generated capability contract;
2. validate input before config, auth, or network;
3. resolve account/zone placeholders deterministically;
4. enforce per-capability safety flags;
5. construct exact request from route contract;
6. delegate to existing hardened REST, GraphQL, or MCP transport;
7. normalize output through existing AXI renderer;
8. return structured errors with exit `1` or `2`.

Specialized `account`, `zone`, raw REST, raw GraphQL, and MCP commands remain. Raw escape hatches never count as capability parity unless caller no longer needs to invent capability-specific route or schema details.

Safety is operation-independent:

- every metered capability, including reads, requires `--allow-metered`;
- every write requires `--allow-write`;
- every destructive capability requires exact `--confirm <capability>`;
- data-egress capabilities require explicit `--allow-egress`;
- long-running/asynchronous capabilities require explicit `--allow-long-running`;
- every missing guard fails before config, auth, or network;
- mutations, destructive operations, and MCP calls never retry.

## Workstreams

| ID | Workstream | Deliverable | Owner | Status |
|---|---|---|---|---|
| W1 | Source extraction | Deterministic names, schemas, registrations, dependency closure, and hashes | magimetal | complete |
| W2 | Catalog model | Versioned parity status/evidence model and generated rollups | magimetal | complete |
| W3 | Invocation dispatcher | `capability schema/invoke` with pre-network validation | magimetal | phase-2-slice-complete |
| W4 | Route mapping | Exact REST, GraphQL, public, and hosted MCP routes | magimetal | phase-2-slice-complete |
| W5 | Safety policy | Per-capability mutation, metering, destruction, egress, retry rules | magimetal | phase-2-slice-complete |
| W6 | Verification | Real-binary hermetic contract tests for all capabilities | magimetal | phase-2-slice-complete |
| W7 | Discovery/docs | Generated matrix, help, examples, README, and skill synchronization | magimetal | phase-2-slice-complete |
| W8 | Blocker closure | Evidence-backed resolution of 40 current blockers | magimetal | not_started |
| W9 | Drift governance | Pinned validation and latest-upstream change reports | magimetal | complete |

## Phase plan

### Phase 0 — Measurement and governance

**Status:** `complete`

**Objective:** Make every gap mechanically measurable before bulk implementation.

Tasks:

- [x] Version catalog schema and migrate parser in same change.
- [x] Add explicit inventory, schema, route, behavior, policy, verification, discovery, and external-blocker statuses with dimension-specific evidence.
- [x] Add catalog validator for status enums, duplicate names, source commit, evidence references, and denominator consistency.
- [x] Generate `docs/cloudflare-capability-parity.md` grouped by family, transport, operation, and blocker.
- [x] Add CI stale-generation check.
- [x] Separate `unresolved` from evidenced zero-input or externally unavailable.
- [x] Add phase metrics script with machine-readable JSON output.
- [x] Assign owners or tracking issues for W1–W9.

Exit gate:

- [x] 172 unique names still match exact pinned Git blobs (`scripts/extract-capability-names`, exact HEAD and commit-blob checks).
- [x] Every record has explicit status for I/S/R/B/P/V/D/X.
- [x] Generated dashboard reproduces baseline counts (`I=172; S=R=B=P=V=D=0; X=41`).
- [x] CI rejects invalid status, stale output, duplicate names, or denominator drift.

Phase 0 evidence (completed `2026-08-10`): `python3 scripts/catalog-governance.py self-test`, `python3 scripts/catalog-governance.py generate`, `python3 scripts/catalog-governance.py check`, generated metrics/report files, Rust typed-status mutation tests, and extractor exact-pin/blob self-test. No live/provider calls or credentials used.

### Phase 1 — Authoritative schema extraction

**Status:** `complete`

**Objective:** Replace 172 empty placeholder schemas.

Tasks:

- [x] Build deterministic extractor from pinned registration source.
- [x] Evaluate safest extraction method: static semantic TypeScript AST selected; no-I/O harness and regex-only extraction rejected as canonical sources.
- [x] Resolve shared definitions, nested objects, arrays, unions, optional/default fields, refinements, and transformations.
- [x] Preserve constraints as JSON Schema plus explicit runtime semantic contracts where JSON Schema cannot execute Zod behavior.
- [x] Mark genuine no-input tools `zero_input_evidenced`.
- [x] Record source file, symbol/line, commit, blob, expression hash, schema hash, and contract hash.
- [x] Generate compact `input_fields` from canonical schema.
- [x] Add positive and negative fixtures for every distinct schema shape.
- [x] Prove extractor never executes tool handlers or performs network calls.

Phase 1 evidence (completed `2026-08-10`): `tools/schema-extractor` reads only exact pinned Git blobs at commit `70ff690553722f731849ede6ba9ce98958395a23` and tree `1a51c6ff07170dfe3c3212c8fb96eb85d66f0b96`, with `GIT_NO_REPLACE_OBJECTS=1`, Oxc 0.75.1 typed AST and lexical resolution, bounded recursive dependency evaluation, and fail-closed diagnostics. Census v6 retains 9,072 unique semantic occurrences, 217 dependency nodes, 269 edges, 642 chains, exact Zod `4.4.3`, and all source spans/hashes. Compiler bundle v2 emits 168 complete registration-input contracts and 4 source-evidenced zero-input contracts with zero unresolved, Draft 2020-12 raw schemas, path-indexed defaults/normalizations/refinements/transforms/unknown-key behavior, request-context overlays, and lexicographic SHA-256 hashes. Exact static lowerings are hash/version-gated for Zod 4.4.3 default email, UUID, ISO date, and UTC datetime acceptance, IP/ASN refinements, Radar case normalization, Radar normalization helpers, stack-library request subsets, account selection overlays, and relative-time normalized output. URL behavior is not overclaimed as generic JSON Schema URI validation: ten contracts explicitly record external-runtime trimming, JavaScript WHATWG URL-constructor validation of trimmed input, and trimmed output when `normalize=false`; dynamic `nowISO()` descriptions remain explicit templates rather than lossy static claims. Every contract carries typed dependency provenance; 803 entries bind ID/name, source file/blob, classification, source span kind/span, and source SHA-256 under aggregate SHA-256 `bd6c83d69c8464ec0d5b428a2631972aa1d30acabdf89f310b1a06f8d5678d04`. Rehashed mutation tests reject deleted, emptied, or fabricated dependency provenance, nonempty unresolved reasons, and malformed dependency source hashes, blobs, or spans. `capabilities/cloudflare-input-schemas.json` and `capabilities/cloudflare-schema-fixtures.json` contain 172 contracts and positive/negative fixtures for all 137 distinct schema hashes. Independent `jsonschema` 0.38.1 validation enables Draft 2020-12 format assertions and metaschema checks. Catalog schema v2 joins every capability to its contract hash, generated compact fields, authoritative upstream evidence, and status while binding local artifacts separately by root hashes. Generated dashboard reports `I=172; S=172; R=B=P=V=D=0; X=41`. CI repeats compilation byte-for-byte, compares committed artifacts, validates fixtures, and runs with Node/Bun/TS executors replaced by poison commands; no upstream TypeScript, Zod module, registration, handler, provider call, credential, or network-capable schema resolver executes.

Exit gate:

- [x] Schema coverage 172/172.
- [x] `unresolved` schemas 0.
- [x] Every zero-input schema has source evidence.
- [x] Every schema parses and validates fixtures.
- [x] Repeated extraction from same commit is byte-stable.

### Phase 2 — Route contracts and dispatcher vertical slices

**Status:** `complete for five representative slices; 167 deferred`

**Objective:** Prove shared invocation architecture across transports before bulk expansion.

Tasks:

- [x] Define REST method, path placeholders, query mapping, body mapping, and scope contract.
- [x] Define GraphQL document, operation name, variable mapping, and response projection contract.
- [x] Define public URL, content type, pagination, and artifact contract.
- [x] Define hosted MCP server, tool, protocol, schema provenance, and result normalization contract.
- [x] Replace generic SDK labels with callable operation evidence.
- [x] Define operation-independent guard evaluation before config/auth/network.
- [x] Add hermetic negative tests for metered, write, destructive, data-egress, and long-running guard classes.
- [x] Implement `capability schema`.
- [x] Implement `capability invoke` with inline/file/stdin JSON input.
- [x] Complete representative vertical slices: REST read, public read, GraphQL read, hosted MCP read, and one hermetic write.

Current Phase 2 evidence (`2026-08-11`): five representative operation contracts bind D1 GET/DELETE, browser REST POST, GraphQL POST, and public no-auth MCP `tools/call`. Catalog/dashboard vector is `I=172; S=172; R=B=P=V=5; D=0; X=40`; 167 routes remain deferred to Phases 3–7. GraphQL and MCP contracts include exact semantic and protocol pins; all representative request, output, safety, and pre-network checks are hermetic. This is not an all-routes completion claim.

Exit gate:

- [x] Five representative slices pass real-binary contract tests.
- [x] Exact method, URL, headers, query, body, output, stderr, and exit code are asserted.
- [x] Invalid inputs fail before config, auth, or network.
- [x] Mutations and MCP calls are sent once only.
- [x] Every guard class has a pre-network rejection test.
- [x] Five representative routes complete; 167 deferred to Phases 3–7.
### Phase 3 — Proven direct unauthenticated Blog reads

**Status:** `complete for proven cohort`

**Objective:** Complete four source-proven Cloudflare Blog reads without expanding completion claims to unresolved legacy `public_http` entries.

Completed cohort:

- [x] `get_post`
- [x] `list_posts`
- [x] `list_tags`
- [x] `search_posts`
- [x] Exact routes, behavior, policy, response bounds, empty states, and hermetic tests.
- [x] Generated discovery and non-interactive examples.
- [x] No authentication headers or live provider calls.

Exit evidence: Blog reads 4/4 discovery-verified; global vector `I=172; S=172; R=B=P=V=9; D=4; X=40`; 163 routes unresolved.

The remaining 76 legacy `public_http` reads are not Phase 3 completions. Browser/Radar require authoritative route, transport, scope, and authentication reclassification during Phase 4 research; demo/stack require source-hosted or MCP route research during Phase 5.

### Phase 4 — Authenticated direct API read parity

**Status:** `in_progress`

**Objective:** Complete authenticated direct API reads and correct legacy Browser/Radar transport, scope, and authentication metadata from authoritative evidence.

Tasks:

- [ ] Map exact account/zone selectors and placeholder encoding.
- [ ] Replace legacy `public_http`/public-scope labels only after exact endpoint and authentication evidence is bound.
- [ ] Verify request projections, pagination, totals, and continuation commands.
- [ ] Reuse centralized endpoint/auth/redirect/request-bound controls.
- [ ] Add family-batched hermetic fixtures to avoid one bespoke server per tool.
- [ ] Cover least-privilege auth failures without exposing provider bodies.
- [ ] Enforce metering, data-egress, and long-running guards before config/auth/network for reads that require them.

Phase 4C evidence: `list_browser_sessions` binds pinned handler lines 522–560 (blob `ae998f642ba8548b715e1573bc0049c96c9e1f28`, SHA-256 `c6b05861d44395a6e2bc84ac37320cd04d9a7edded73cf14d410fce32e31a361`) to account-authenticated `GET /accounts/{account_id}/browser-run/devtools/session`. Output accepts a bare array or object `result` array; only egress opt-in applies; transient-read retries are allowed. Official route/query mismatch remains explicit. Seven Browser reads are discovery-verified; binary PNG/PDF reads remain.

Exit gate:

- [ ] Every direct REST read has exact schema and route.
- [ ] Every direct REST read passes capability contract test.
- [ ] No read requires raw path construction by caller.
- [ ] Account/zone scope remains explicit in output and suggestions.

### Phase 5 — GraphQL and hosted MCP read parity

**Status:** `not_started`

**Objective:** Complete read-classified non-REST transports from pinned source evidence.

Read scope: five GraphQL reads and 21 `mcp_remote` reads. One GraphQL write and five `mcp_remote` writes remain in Phase 6.

Tasks:

- [ ] Add operation-specific GraphQL documents and variable schemas for all five read-classified GraphQL capabilities.
- [ ] Verify mutation detection and operation classification per document.
- [ ] Map 21 read-classified `mcp_remote` entries to exact hosted server/tool contracts where public exposure exists.
- [ ] Derive schemas from pinned source or official documentation; do not depend on live `tools/list` or `tools/schema` calls.
- [ ] Normalize structured, text, SSE, and JSON-RPC error results.
- [ ] Preserve conservative safety when hosted metadata is incomplete.
- [ ] Enforce `--allow-metered`, `--allow-egress`, and `--allow-long-running` before config/auth/network when classification requires them.

Exit gate:

- [ ] GraphQL reads verified 5/5.
- [ ] Publicly exposed hosted MCP capabilities verified.
- [ ] Deprecated server mappings carry migration evidence and tests.
- [ ] No hosted call relies on local catalog operation metadata for safety.

### Phase 6 — Write parity

**Status:** `not_started`

**Objective:** Complete 22 write operations without live mutation testing.

Write scope includes five `public_http` writes, 13 REST writes, three custom-container writes, and one GraphQL write. Five writes are currently classified `mcp_remote`; transport and access dimensions overlap.

Tasks:

- [ ] Classify mutation, destructive, metered, long-running, data-egress, and combinations.
- [ ] Require `--allow-write` for every write.
- [ ] Require exact-name/path confirmation for destructive operations.
- [ ] Require `--allow-metered` for possible charges.
- [ ] Require `--allow-egress` and `--allow-long-running` when classification requires them.
- [ ] Disable automatic retries.
- [ ] Define idempotency and already-satisfied behavior only where provider semantics prove it.
- [ ] Test request construction and safeguards against hermetic servers only.
- [ ] Add explicit duplicate-attempt assertions.

Exit gate:

- [ ] Writes verified 22/22.
- [ ] Missing safety flags fail before config, auth, or network.
- [ ] Every metered, egress, and long-running guard fails before config, auth, or network when missing.
- [ ] Every write has success, provider failure, malformed response, and duplicate-attempt coverage.
- [ ] No paid, metered, destructive, or mutating live call exists in tests or release process.

### Phase 7 — External/internal blocker closure

**Status:** `not_started`

**Objective:** Reduce current blocker count from 40 to zero.

Current blocker ledger:

| ID | Family | Capabilities | Primary gap | Owner | Status |
|---|---|---:|---|---|---|
| B-DEX | `dex-analysis` | 18 | Archive/direct response contract unverified | unassigned | open |
| B-CASB | `cloudflare-one-casb` | 11 | Source-specific or undocumented product API | unassigned | open |
| B-CONTAINER | `sandbox-container` | 7 | Internal container runtime/public exposure | unassigned | open |
| B-OBS | `workers-observability` | 3 | Endpoint/runtime mapping | unassigned | open |
| B-STACK | `stack-mcp` | 1 | Public execution route | unassigned | open |

Closure order:

1. proven hosted MCP route;
2. official direct API route;
3. source-derived archive/file contract;
4. official source tests proving source-specific runtime behavior;
5. upstream exposure/documentation request when no route exists.

Each blocker closes only with:

- [ ] exact affected names;
- [ ] owner and review date;
- [ ] official source/documentation reference;
- [ ] schema and route decision;
- [ ] safety decision;
- [ ] hermetic fixture and test ID;
- [ ] blocker removed from canonical record.

Exit gate:

- [ ] Blockers 0.
- [ ] `external_blocked` 0.
- [ ] All 172 capabilities invocable through direct or hosted route.

If any blocker remains, stop at maximal attainable parity and publish exact gap vector.

### Phase 8 — AXI, documentation, and release closure

**Status:** `not_started`

**Objective:** Prove parity expansion preserved complete agent-facing contract.

Exit gate:

- [ ] Capability contracts verified 172/172.
- [ ] All ten AXI principles pass or carry evidence-backed `N/A`.
- [ ] TOON and strict JSON parse correctly.
- [ ] Errors remain structured on stdout with exit `1`/`2`.
- [ ] Empty states, totals, truncation, and selector-preserving suggestions are tested.
- [ ] README, help, skill, generated matrix, and catalog agree.
- [ ] Dependency advisory and license checks pass.
- [ ] Rust format, tests, clippy, release build, package, and clean-install checks pass.
- [ ] Pinned-source parity and generated-artifact checks pass in CI.
- [ ] Linux and macOS release artifacts pass smoke checks.

## Blocker policy

Accepted evidence, strongest first:

1. official Cloudflare API/OpenAPI or MCP documentation;
2. pinned registration, schema, handler, or transport source;
3. pinned official tests proving request/response behavior;
4. deterministic generated schema/route artifact;
5. hermetic real-binary contract test;
6. optional allowlisted live smoke result.

Every capability needs evidence for identity, schema, route, operation classification, safety, output behavior, and verification.

Evidence records must include source URL or repository-relative path, commit/documentation date, symbol or line, extracted fact, implementation decision, proving test, and generated content hash where applicable.

Never commit live responses, credentials, account names, zone names, or identifiers as fixtures.

## Live-call policy

Default: **no live Cloudflare calls**. CI and releases remain credential-free and hermetic.

Optional manual live calls are limited to:

```sh
magi-cloudflare-axi auth verify
magi-cloudflare-axi account list --page 1 --per-page 1 --limit 1
magi-cloudflare-axi zone list --page 1 --per-page 1 --limit 1
```

Controls:

- explicit operator approval;
- least-privilege read-only token;
- one page and one result maximum;
- serial execution;
- no persisted response body;
- report only command class, exit status, duration, and redacted shape.

Prohibited live operations:

- writes, deletes, mutations, GraphQL, and hosted MCP calls;
- tool list/schema calls;
- browser rendering, scans, AI, DEX, D1, containers, builds, logs, archives, or other metered services;
- operations that create, modify, execute, upload, download private data, or trigger asynchronous work.

Live evidence is optional and never substitutes for hermetic verification.

## Drift detection

### Every parity PR

- regenerate catalog and dashboard;
- compare generated output;
- run schema, route, evidence, safety, and test-coverage checks;
- fail on unexpected registered-name or schema-hash change;
- update this file's phase status and `last_reviewed` when a phase gate moves.

### Weekly during active work

- update dashboard metrics;
- review blocker owners and next actions;
- identify capabilities stuck in `research` or `specified`;
- record phase-gate movement in tracking issue or PR.

### Monthly and before release

- compare pinned commit with current upstream head;
- report added, removed, renamed, schema-changed, route-changed, and server-changed capabilities;
- review deprecations and hosted server availability;
- keep release parity measured against pinned commit until an isolated baseline-bump change lands.

Pinned commit updates must include:

| Change | Required action |
|---|---|
| Added capability | Full contract and tests before denominator update |
| Removed capability | Upstream-removal evidence and migration impact |
| Renamed capability | Targeted replacement guidance or breaking-change note |
| Schema changed | Regenerated fixtures and validation tests |
| Route changed | Transport and safety re-review |
| Safety changed | Release blocked until classification and tests update |

## Phase tracking

Update this table only when gate evidence exists.

| Phase | Entry state | Exit evidence | Tracking issue | Status | Completed |
|---|---|---|---|---|---|
| 0 — Measurement | Inventory baseline | Versioned tracker + generated dashboard CI | — | complete | 2026-08-10 |
| 1 — Schemas | Phase 0 complete | 172/172 canonical schemas | — | complete | 2026-08-10 |
| 2 — Routes/dispatcher | Phase 1 complete | Five verified transport slices; 167 capability routes deferred | — | complete | 2026-08-11 |
| 3 — Proven Blog reads | Phase 2 complete | Four Blog reads verified and discovery-verified; 163 total routes unresolved | — | complete-for-proven-cohort | 2026-08-11 |
| 4 — Authenticated direct API reads | Phase 3 cohort complete | Seven Browser reads verified and discovery-verified; 156 total routes unresolved | — | in_progress | — |
| 5 — GraphQL/MCP reads | Phase 2 complete | GraphQL reads 5/5 and exposed MCP reads verified | — | not_started | — |
| 6 — Writes | Phase 2 complete | Writes 22/22 hermetically verified | — | not_started | — |
| 7 — Blockers | Route research available | Blockers 0 | — | not_started | — |
| 8 — Release closure | Phases 1–7 complete | Full gate and artifacts pass | — | not_started | — |

## Risks and controls

| Risk | Impact | Control |
|---|---|---|
| Dynamic TypeScript/Zod composition | Incorrect schemas | Semantic extraction plus source fixture tests |
| Internal-only Cloudflare runtime | Full parity may be impossible | Hosted-route evidence or explicit maximal-attainable status |
| MCP server deprecation | Broken invocation | Provenance, scheduled drift checks, migration tests |
| Binary/archive responses | Data loss or memory exhaustion | Bounded streaming and explicit destination contracts |
| Read operation incurs cost | Unsafe classification | Separate operation and metering policy |
| Generic raw transport masks missing routes | False parity claim | Raw access never counts without capability-specific contract |
| Manual markdown matrix drifts | Incorrect progress | Generate detailed matrix from canonical catalog |
| Upstream denominator changes | Misleading completion | Pin commit and isolate baseline updates |

## Final definition of done

Full parity is complete only when:

- pinned source and catalog contain identical active names;
- all 172 capabilities have authoritative schemas;
- all 172 have complete direct or hosted routes;
- all 150 reads and 22 writes pass hermetic real-binary tests;
- all safety and output contracts are tested;
- blocker count is zero;
- generated documentation and CLI discovery agree;
- drift is zero against pinned baseline;
- AXI, Rust, package, security, and clean-install gates pass;
- no forbidden live operation was used as evidence.

Anything less reports exact vector, for example:

```text
inventory 172/172
schema 172/172
route 169/172
verified 165/172
external blockers 3
status maximal_attainable_parity
```
