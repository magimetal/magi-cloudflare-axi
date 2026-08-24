# magi-cloudflare-axi

Agent-native Cloudflare CLI. Rust 2024, MSRV 1.87. Direct REST/GraphQL transport plus hosted Streamable HTTP MCP. No prompts. Default stdout TOON; `--format json` and `--format=json` emit strict JSON.

## Install

```sh
cargo install --path . --locked
npx skills add magimetal/magi-cloudflare-axi --skill magi-cloudflare-axi
```

Session hooks provide ambient live context; installable Agent Skill provides on-demand guidance. Either can be installed independently. Release archives include binary, notices, README, and skill.

Use `magi-cloudflare-axi --help`, `-v`, `-V`, or `--version`. Exact version probes bypass parser, config, auth, and network. No arguments prints compact home state: executable, resolved config/scope, registered-tool inventory count, complete next commands, and bounded live account state when credentials exist. Without credentials, home remains successful and gives exact setup guidance.

## Auth and config

Set `CLOUDFLARE_API_TOKEN` for bearer auth, or `CLOUDFLARE_API_KEY` plus `CLOUDFLARE_API_EMAIL` for direct global-key headers. Hosted MCP accepts only `CLOUDFLARE_API_TOKEN`. Resolution: CLI flags > environment > project `.cloudflare-axi.toml` > platform global config > defaults. Account typo alias `CLOUDFLARE_ACOUNT_ID` is accepted only after `CLOUDFLARE_ACCOUNT_ID`. Secret and unknown keys are rejected in TOML. Project config may select account/zone, but cannot set `api_base`/`endpoint`; custom endpoints must use CLI, environment, or global config so repository content cannot redirect ambient credentials.

## Commands

```sh
magi-cloudflare-axi auth status
magi-cloudflare-axi account list --fields id,name --page 1 --per-page 100
magi-cloudflare-axi --account <id> zone list --fields id,name,status,account
magi-cloudflare-axi account get <id>
magi-cloudflare-axi api GET /accounts --paginate --max-pages 3 --max-items 250
magi-cloudflare-axi graphql --query 'query { viewer { userName } }'
magi-cloudflare-axi tool list --server cloudflare
magi-cloudflare-axi tool schema search --server cloudflare
magi-cloudflare-axi capability schema d1_database_get
`capability schema d1_database_get` is offline and authoritative for registration-input schema.
magi-cloudflare-axi --account <id> capability invoke d1_database_get --input '{"database_id":"<uuid>"}'
magi-cloudflare-axi --account <id> capability invoke list_browser_sessions --input '{}' --allow-egress
magi-cloudflare-axi --account <id> capability invoke get_url_pdf --input '{"url":"https://example.com"}' --output page.pdf --allow-metered --allow-egress --allow-long-running
magi-cloudflare-axi --account <id> capability invoke get_url_screenshot --input '{"url":"https://example.com","viewport":{"width":1280,"height":720}}' --output page.png --allow-metered --allow-egress --allow-long-running
```

Account/zone lists validate fields before auth/network, preserve Cloudflare totals, apply `--limit` client-side, and return explicit zero-page messages. Raw pagination merges only top-level array results; nested arrays are never guessed.

Catalog schema v3 and Phase 4 governance are canonical.
Phase 3 Blog direct reads remain complete.
Phase 4E Logpush remains complete: invoke `magi-cloudflare-axi capability invoke logpush_jobs_by_account_id --input '{}' --allow-egress`; API token requires Logs Write permission. Bodyless `GET /accounts/{account_id}/logpush/jobs` returns first 100 jobs with no continuation.

Phase 4F authenticated `auditlogs_by_account_id` remains available at `GET /accounts/{account_id}/logs/audit`; invoke `magi-cloudflare-axi capability invoke auditlogs_by_account_id --input '{"since":"<since>","before":"<before>"}' --allow-egress`. Phase 4G adds AutoRAG `list_rags`. Invoke `magi-cloudflare-axi capability invoke list_rags --input '{}' --allow-egress`; OAuth scope additions are `account:read` and `rag:write` (least-privilege token permission is not asserted). It calls `GET /accounts/{account_id}/autorag/rags` with `page=1` and `per_page=20` defaults, strict response validation before projecting `autorags` and numeric `total_count`, bounded integer inputs, transient-read retries, no redirect credential forwarding, and an 8 MiB response bound. Phase 4H adds Workers Builds `workers_builds_get_build`. Invoke `magi-cloudflare-axi capability invoke workers_builds_get_build --input '{"buildUUID":"<buildUUID>"}' --allow-egress`; it uses account auth for `GET /accounts/{account_id}/builds/builds/{buildUUID}` with no query or body. `buildUUID` is a required non-empty string and is validated locally only as a safe single path segment of at most 256 bytes; UUID syntax is not claimed. The strict V4 envelope and full pinned `BuildDetails` response, including ignored nested fields, are validated before a strict ten-field projection: `buildUUID`, `createdOn` normalized to ISO, `status`, nullable `buildOutcome`, `branch`, `commitHash`, `commitMessage`, `commitAuthor`, `buildCommand`, and `deployCommand`. A null result is JSON null; environment variables and secret values are omitted, and unknown output is stripped. Pinned app OAuth scope additions are `account:read`, `workers:read`, and `workers_builds:read`; they are not API-token permissions or a least-privilege claim. Local AXI policy classifies this read as non-metered, data-egress, and `transient_read`, not upstream facts; transient GET retries, redirect refusal, credential/provider-message redaction where appropriate, and the 8 MiB response bound apply. Phase 4I adds Workers Builds `workers_builds_list_builds`. Invoke `magi-cloudflare-axi capability invoke workers_builds_list_builds --input '{"workerId":"<workerId>"}' --allow-egress`; it requests one page only with account auth using `GET /accounts/{account_id}/builds/workers/{workerId}/builds?page={page}&per_page={perPage}`, no body, and defaults page 1/perPage 10. Upstream requires a nonempty `workerId`; local AXI validates a safe single segment up to 256 bytes and rejects whitespace, control characters, and path delimiters; no other `workerId` syntax is claimed. Local AXI pagination safeguards constrain integer `page` to 1–10000 and `perPage` to 1–100; these bounds are local policy, while the pinned upstream contract specifies the query names and defaults. The strict `success=true` V4 envelope and full `BuildDetails` array, including nested details, plus optional or null `result_info` are validated before projection. Date fields are validated as ISO strings or finite numeric milliseconds and normalized to ISO. Output is stable newest-first with exactly eight fields per build: `buildUUID`, `createdOn`, `status`, `buildOutcome`, `branch`, `commitHash`, `commitMessage`, and `commitAuthor`; environment variables, secret values, `buildCommand`, `deployCommand`, and unknown output are omitted. A null `result` yields `builds=[]` and `pagination_info=null`; an empty array preserves valid `pagination_info`. The additions are app OAuth scopes: `account:read`, `workers:read`, and `workers_builds:read`; they are not API-token permissions or a least-privilege claim. Non-metered, data-egress, and `transient_read` are local AXI policy classifications, not upstream facts; `--allow-egress`, transient GET retries, redirect refusal, credential/provider-message detail redaction, and the 8 MiB response bound apply. Current Phase 4I vector: `I=172; S=172; R=B=P=V=23; D=18; X=40`; 23 exact operation contracts; reads verified 22/150; 18 discovery-verified and five generated; 149 routes remain unresolved.

## Output, errors, safety

Success and errors use one structured stdout payload. Stderr remains empty except catastrophic output serialization diagnostics. Exit `0` means success or empty result; `1` means auth/config/network/provider/output failure; `2` means invalid command or input. Provider bodies and dependency manuals are not copied into errors. Long values truncate with `--full` escape hatch.

Remote endpoints require HTTPS; loopback HTTP supports hermetic tests only. Redirects are never followed, preventing credentials or account context crossing origins. Requests are limited to 1 MiB and responses to 8 MiB. Reads may retry; mutations and MCP calls do not. Raw non-GET requires `--allow-write`; DELETE also requires exact `--confirm-delete PATH`. Unified `search` is read-safe, docs search requires `--allow-metered`, and every other MCP call requires `--allow-write --allow-metered --confirm TOOL`.

## Session integrations and release

`session setup --target claude|codex|opencode` explicitly installs preserving, prevalidated, idempotent, path-repairing integrations. New managed files use mode `0600` on Unix; updates preserve existing permissions. `session status` requires exactly one valid managed hook, validates selected targets and current executable path, and distinguishes missing/disabled Codex hook configuration from trust-unverified configuration. Codex trust cannot be confirmed non-interactively, so configured status directs review through `/hooks`. OpenCode uses its documented local plugin directory and current `experimental.chat.system.transform` hook. Repeated setup returns `unchanged` without rewriting files.

CI runs formatting, locked tests, clippy, release build, package verification, dependency advisory audit, pinned-source inventory validation, and clean-install smoke checks. Release jobs enforce tag/package version equality, repeat validation, and package skill plus notices. Linux and macOS archives are supported. No live Cloudflare calls are part of CI.

See `docs/plans/cloudflare-axi-contract.md`, `docs/plans/cloudflare-full-capability-parity-roadmap.md`, and `docs/cloudflare-api-evidence.md` for contract, phased parity work, and evidence limits.

Phase 0–4I governance artifacts: `capabilities/cloudflare-mcp-parity.json` is canonical; fixed per-name legacy-metadata digest protects migration integrity. Schema v3 adds typed evidence provenance plus hash-bound operation-contract artifacts. Repository-development commands `scripts/catalog-governance.py validate`, `self-test`, `generate`, `metrics`, `report`, `sync-schemas`, and `check` validate catalog, run negative mutations, regenerate deterministic artifacts, print them, and detect drift. CI rejects stale artifacts, source drift, duplicate names, denominator drift, invalid statuses, inapplicable evidence, operation-contract drift, and per-capability metadata drift. Commands are hermetic and credential-free. 149 routes remain unresolved for Phases 4–7.
