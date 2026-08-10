---
title: Cloudflare full capability parity roadmap
status: active
owner: magimetal
created: 2026-08-10
last_reviewed: 2026-08-10
current_phase: phase-1
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
| Canonical input schemas | 0/172 | 172/172 |
| Method metadata | 147/172 | Route-dependent |
| Path metadata | 6/172 | Every direct route complete |
| Capability-specific complete routes | 0/172 | 172/172 |
| Capability contract tests | 0/172 | 172/172 |
| Reads | 150 inventoried | 150 verified |
| Writes | 22 inventoried | 22 verified hermetically |
| Entries carrying blockers | 41 | 0 |
| Families | 18 | 18 complete |

Current access classifications:

| Classification | Count |
|---|---:|
| `raw_rest` | 133 |
| `mcp_remote` | 26 |
| `public_direct` | 6 |
| `raw_graphql` | 6 |
| `blocked` | 1 |

Current transport inventory:

| Transport | Count |
|---|---:|
| `public_http` | 86 |
| `rest` | 71 |
| `custom_container` | 7 |
| `graphql` | 6 |
| `internal_binding` | 2 |

The six existing method/path pairs all identify `POST /graphql`; they do not yet prove operation-specific documents, variables, outputs, or behavior.

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
| W1 | Source extraction | Deterministic names, schemas, registrations, handlers, and hashes | magimetal | not_started |
| W2 | Catalog model | Versioned parity status/evidence model and generated rollups | magimetal | complete |
| W3 | Invocation dispatcher | `capability schema/invoke` with pre-network validation | magimetal | not_started |
| W4 | Route mapping | Exact REST, GraphQL, public, and hosted MCP routes | magimetal | not_started |
| W5 | Safety policy | Per-capability mutation, metering, destruction, egress, retry rules | magimetal | not_started |
| W6 | Verification | Real-binary hermetic contract tests for all capabilities | magimetal | not_started |
| W7 | Discovery/docs | Generated matrix, help, examples, README, and skill synchronization | magimetal | not_started |
| W8 | Blocker closure | Evidence-backed resolution of 41 current blockers | magimetal | not_started |
| W9 | Drift governance | Pinned validation and latest-upstream change reports | magimetal | active |

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

Phase 0 evidence (completed `2026-08-10`): `python3 scripts/catalog-governance.py self-test`, `python3 scripts/catalog-governance.py generate`, `python3 scripts/catalog-governance.py check`, generated metrics/report files, Rust typed-status mutation tests, and extractor exact-pin/blob self-test. No live/provider calls or credentials used. Phases 1–8 remain `not_started`; latest-upstream change reporting, schema extraction, routes, invocation, behavior, policy, verification, and blocker closure remain future work.

### Phase 1 — Authoritative schema extraction

**Status:** `not_started`

**Objective:** Replace 172 empty placeholder schemas.

Tasks:

- [ ] Build deterministic extractor from pinned registration source.
- [ ] Evaluate safest extraction method: no-I/O registration harness first, semantic TypeScript AST second; regex-only extraction cannot be canonical.
- [ ] Resolve shared definitions, nested objects, arrays, unions, optional/default fields, refinements, and transformations.
- [ ] Preserve constraints as JSON Schema.
- [ ] Mark genuine no-input tools `zero_input_evidenced`.
- [ ] Record source file, symbol/line, commit, and schema hash.
- [ ] Generate compact `input_fields` from canonical schema.
- [ ] Add positive and negative fixtures for every distinct schema shape.
- [ ] Prove extractor never executes tool handlers or performs network calls.

Exit gate:

- [ ] Schema coverage 172/172.
- [ ] `unresolved` schemas 0.
- [ ] Every zero-input schema has source evidence.
- [ ] Every schema parses and validates fixtures.
- [ ] Repeated extraction from same commit is byte-stable.

### Phase 2 — Route contracts and dispatcher vertical slices

**Status:** `not_started`

**Objective:** Prove shared invocation architecture across transports before bulk expansion.

Tasks:

- [ ] Define REST method, path placeholders, query mapping, body mapping, and scope contract.
- [ ] Define GraphQL document, operation name, variable mapping, and response projection contract.
- [ ] Define public URL, content type, pagination, and artifact contract.
- [ ] Define hosted MCP server, tool, protocol, schema provenance, and result normalization contract.
- [ ] Replace generic SDK labels with callable operation evidence.
- [ ] Define operation-independent guard evaluation before config/auth/network.
- [ ] Add hermetic negative tests for metered, write, destructive, data-egress, and long-running guard classes.
- [ ] Implement `capability schema`.
- [ ] Implement `capability invoke` with inline/file/stdin JSON input.
- [ ] Complete representative vertical slices: REST read, public read, GraphQL read, hosted MCP read, and one hermetic write.

Exit gate:

- [ ] Five representative slices pass real-binary contract tests.
- [ ] Exact method, URL, headers, query, body, output, stderr, and exit code are asserted.
- [ ] Invalid inputs fail before config, auth, or network.
- [ ] Mutations and MCP calls are sent once only.
- [ ] Every guard class has a pre-network rejection test.
- [ ] Every capability is classified route-complete or `external_blocked`; no guessed routes.

### Phase 3 — Public and unauthenticated read parity

**Status:** `not_started`

**Objective:** Complete public HTTP reads first because they have lowest credential risk.

Primary batch: 81 read-classified `public_http` capabilities, dominated by Radar, Browser Rendering, Cloudflare Blog, and DNS Analytics families. Five `public_http` writes remain in Phase 6.

Per-capability gate:

- [ ] Schema validation before network.
- [ ] Exact URL/query route evidence.
- [ ] Success, explicit empty state, provider error, malformed response, and response bound tests.
- [ ] Pagination semantics defined where applicable.
- [ ] Metering classification reviewed even when operation is a read.
- [ ] `--allow-metered` is enforced before config/auth/network for every metered read.
- [ ] Generated help and one non-interactive example.

Phase exit gate:

- [ ] All publicly reachable reads verified.
- [ ] No public capability requires caller-invented URL/path details.
- [ ] Public blocker count 0, or exact external blocker ledger published.

### Phase 4 — Authenticated REST read parity

**Status:** `not_started`

**Objective:** Complete account- and zone-scoped REST reads.

Tasks:

- [ ] Map exact account/zone selectors and placeholder encoding.
- [ ] Verify request projections, pagination, totals, and continuation commands.
- [ ] Reuse centralized endpoint/auth/redirect/request-bound controls.
- [ ] Add family-batched hermetic fixtures to avoid one bespoke server per tool.
- [ ] Cover least-privilege auth failures without exposing provider bodies.
- [ ] Enforce metering, data-egress, and long-running guards before config/auth/network for reads that require them.

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

**Objective:** Reduce current blocker count from 41 to zero.

Current blocker ledger:

| ID | Family | Capabilities | Primary gap | Owner | Status |
|---|---|---:|---|---|---|
| B-DEX | `dex-analysis` | 18 | Archive/direct response contract unverified | unassigned | open |
| B-CASB | `cloudflare-one-casb` | 11 | Source-specific or undocumented product API | unassigned | open |
| B-CONTAINER | `sandbox-container` | 7 | Internal container runtime/public exposure | unassigned | open |
| B-OBS | `workers-observability` | 3 | Endpoint/runtime mapping | unassigned | open |
| B-SHARED | `shared` | 1 | Internal AI binding | unassigned | open |
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
| 1 — Schemas | Phase 0 complete | 172/172 canonical schemas | — | not_started | — |
| 2 — Routes/dispatcher | Phase 1 complete | Five verified transport slices; all routes classified | — | not_started | — |
| 3 — Public reads | Phase 2 complete | Public read batch verified | — | not_started | — |
| 4 — Authenticated REST reads | Phase 2 complete | Direct REST reads verified | — | not_started | — |
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
