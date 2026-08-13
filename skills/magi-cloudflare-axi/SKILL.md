---
name: magi-cloudflare-axi
description: Use for non-interactive Cloudflare REST, GraphQL, capability catalog, and hosted MCP operations with structured TOON or JSON output.
---

Use `magi-cloudflare-axi --help` first. `-v`, `-V`, and `--version` are config/auth/network-free probes. No-args home includes bounded live account state when authenticated and exact setup guidance otherwise. Resolve account/zone IDs before writes. Modeled lists support validated `--fields`, provider totals, explicit empty states, and complete pagination commands; raw REST pagination merges top-level arrays only.

Use `--format json` for parsing and `--full` only when truncation guidance appears. Exit 0 success/empty, 1 auth/config/network/API/output, 2 usage. Errors are structured stdout. Raw non-GET requires `--allow-write`; DELETE exact `--confirm-delete PATH`. MCP writes require `--allow-write --confirm TOOL`; metered tools require `--allow-metered`.

Treat catalog schema v3 as pinned 172-name and 172-schema authority. Phase 3 Blog direct reads remain complete. Phase 4 remains in progress. Phase 4C adds authenticated `list_browser_sessions`; exact contracts total 16, with 11 discovery-verified and five generated. Seven Browser reads share exact hermetic discovery provenance in `tests/integration.rs::capability_browser_discovery_examples_are_exact`. Vector `I=172; S=172; R=B=P=V=16; D=11; X=40`; 156 routes remain unresolved. Pinned `GET /accounts/{account_id}/browser-run/devtools/session` is route authority. Official docs instead show `/browser-rendering/devtools/session` and optional `limit`/`offset`; pinned zero-input handler exposes neither query, so mismatch remains explicit. Binary PNG/PDF Browser reads remain.
registration-input schema is authoritative; use `capability schema d1_database_get` offline.
MCP writes require `--allow-write --allow-metered --confirm TOOL`.

Examples:

```sh
magi-cloudflare-axi --format json account list --fields id,name --page 1
magi-cloudflare-axi --account <id> zone list --fields id,name,status,account
magi-cloudflare-axi api GET /zones --paginate --max-pages 2 --max-items 100
printf 'query { viewer { userName } }' | magi-cloudflare-axi graphql --stdin
magi-cloudflare-axi tool schema search --server cloudflare
magi-cloudflare-axi capability schema d1_database_get
magi-cloudflare-axi --account <id> capability invoke d1_database_get --input '{"database_id":"<uuid>"}'
magi-cloudflare-axi --account <id> capability invoke list_browser_sessions --input '{}' --allow-egress
```

Governance: `python3 scripts/catalog-governance.py validate` checks catalog envelope, pinned evidence, statuses, blockers, and baseline. `check` detects stale generated metrics/report. No provider calls or credentials required.
