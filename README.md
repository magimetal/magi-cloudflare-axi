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
```

Account/zone lists validate fields before auth/network, preserve Cloudflare totals, apply `--limit` client-side, and return explicit zero-page messages. Raw pagination merges only top-level array results; nested arrays are never guessed.

Catalog schema v3 and Phase 4 governance are canonical.
Phase 3 blog direct reads remains complete.
`capability list/get` exposes 172 registered tool names at pinned source commit `70ff690553722f731849ede6ba9ce98958395a23`. Phase 4A completes three authenticated Browser reads: `get_url_markdown`, `get_url_links`, and `scrape_url_elements`; vector `I=172; S=172; R=B=P=V=12; D=7; X=40`. Browser discovery examples use one exact hermetic integration test. Remaining 160 routes unresolved. Browser route authority is pinned source `/browser-run`; official `/browser-rendering` docs corroborate product semantics but do not establish identical route/transport evidence, so mismatch remains explicit.

## Output, errors, safety

Success and errors use one structured stdout payload. Stderr remains empty except catastrophic output serialization diagnostics. Exit `0` means success or empty result; `1` means auth/config/network/provider/output failure; `2` means invalid command or input. Provider bodies and dependency manuals are not copied into errors. Long values truncate with `--full` escape hatch.

Remote endpoints require HTTPS; loopback HTTP supports hermetic tests only. Redirects are never followed, preventing credentials or account context crossing origins. Requests are limited to 1 MiB and responses to 8 MiB. Reads may retry; mutations and MCP calls do not. Raw non-GET requires `--allow-write`; DELETE also requires exact `--confirm-delete PATH`. Unified `search` is read-safe, docs search requires `--allow-metered`, and every other MCP call requires `--allow-write --allow-metered --confirm TOOL`.

## Session integrations and release

`session setup --target claude|codex|opencode` explicitly installs preserving, prevalidated, idempotent, path-repairing integrations. New managed files use mode `0600` on Unix; updates preserve existing permissions. `session status` requires exactly one valid managed hook, validates selected targets and current executable path, and distinguishes missing/disabled Codex hook configuration from trust-unverified configuration. Codex trust cannot be confirmed non-interactively, so configured status directs review through `/hooks`. OpenCode uses its documented local plugin directory and current `experimental.chat.system.transform` hook. Repeated setup returns `unchanged` without rewriting files.

CI runs formatting, locked tests, clippy, release build, package verification, dependency advisory audit, pinned-source inventory validation, and clean-install smoke checks. Release jobs enforce tag/package version equality, repeat validation, and package skill plus notices. Linux and macOS archives are supported. No live Cloudflare calls are part of CI.

See `docs/plans/cloudflare-axi-contract.md`, `docs/plans/cloudflare-full-capability-parity-roadmap.md`, and `docs/cloudflare-api-evidence.md` for contract, phased parity work, and evidence limits.

Phase 0–4A governance artifacts: `capabilities/cloudflare-mcp-parity.json` is canonical; fixed per-name legacy-metadata digest protects migration integrity. Schema v3 adds typed evidence provenance plus hash-bound operation-contract artifacts. Repository-development commands `scripts/catalog-governance.py validate`, `self-test`, `generate`, `metrics`, `report`, `sync-schemas`, and `check` validate the catalog, run negative mutations, regenerate deterministic artifacts, print them, and detect drift. CI rejects stale artifacts, source drift, duplicate names, denominator drift, invalid statuses, inapplicable evidence, operation-contract drift, and per-capability metadata drift. Commands are hermetic and credential-free. Remaining 160 routes stay unresolved for Phases 4–7.
