---
name: magi-cloudflare-axi
description: Use for non-interactive Cloudflare REST, GraphQL, capability catalog, and hosted MCP operations with structured TOON or JSON output.
---

Use `magi-cloudflare-axi --help` first. `-v`, `-V`, and `--version` are config/auth/network-free probes. No-args home includes bounded live account state when authenticated and exact setup guidance otherwise. Resolve account/zone IDs before writes. Modeled lists support validated `--fields`, provider totals, explicit empty states, and complete pagination commands; raw REST pagination merges top-level arrays only.

Use `--format json` for parsing and `--full` only when truncation guidance appears. Exit 0 success/empty, 1 auth/config/network/API/output, 2 usage. Errors are structured stdout. Raw non-GET requires `--allow-write`; DELETE exact `--confirm-delete PATH`. MCP writes require `--allow-write --confirm TOOL`; metered tools require `--allow-metered`.

Treat catalog schema v3 as pinned 172-name and 172-schema authority. Phase 3 Blog direct reads remain complete. Phase 4D adds authenticated `get_url_pdf` and `get_url_screenshot`; exact contracts total 18, with 13 discovery-verified and five generated. Phase 4 cohort has nine discovery-verified authenticated Browser reads; with Phase 2's generated `get_url_markdown`, Browser family has ten exact contracts. Vector `I=172; S=172; R=B=P=V=18; D=13; X=40`; 154 routes remain unresolved. Binary reads require explicit new filesystem `--output`, refuse overwrite, prepare a private sibling temporary file before auth/network, cap responses at 8 MiB, never retry or redirect, verify PDF/PNG MIME and signatures, and return path/MIME/bytes/SHA-256 metadata. Screenshot omits absent viewport; supplied viewport defaults nested width/height to 800×600 and strips unknown nested keys. Keep `list_browser_sessions` mismatch explicit: pinned route is `/accounts/{account_id}/browser-run/devtools/session`; official docs show `/browser-rendering/devtools/session` with optional `limit`/`offset`, but pinned zero-input handler exposes neither query. Phase 4 remains in progress.
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
magi-cloudflare-axi --account <id> capability invoke get_url_pdf --input '{"url":"https://example.com"}' --output page.pdf --allow-metered --allow-egress --allow-long-running
magi-cloudflare-axi --account <id> capability invoke get_url_screenshot --input '{"url":"https://example.com","viewport":{"width":1280,"height":720}}' --output page.png --allow-metered --allow-egress --allow-long-running
```

Governance: `python3 scripts/catalog-governance.py validate` checks catalog envelope, pinned evidence, statuses, blockers, and baseline. `check` detects stale generated metrics/report. No provider calls or credentials required.
