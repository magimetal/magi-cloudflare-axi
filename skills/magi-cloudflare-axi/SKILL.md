---
name: magi-cloudflare-axi
description: Use for non-interactive Cloudflare REST, GraphQL, capability catalog, and hosted MCP operations with structured TOON or JSON output.
---

Use `magi-cloudflare-axi --help` first. `-v`, `-V`, and `--version` are config/auth/network-free probes. No-args home includes bounded live account state when authenticated and exact setup guidance otherwise. Resolve account/zone IDs before writes. Modeled lists support validated `--fields`, provider totals, explicit empty states, and complete pagination commands; raw REST pagination merges top-level arrays only.

Use `--format json` for parsing and `--full` only when truncation guidance appears. Exit 0 success/empty, 1 auth/config/network/API/output, 2 usage. Errors are structured stdout. Raw non-GET requires `--allow-write`; DELETE exact `--confirm-delete PATH`. MCP writes require `--allow-write --confirm TOOL`; metered tools require `--allow-metered`.

Treat catalog schema v3 as pinned 172-name and 172-schema authority. Phase 3 Blog direct reads and Phase 4E Logpush remain complete. Invoke Logpush with `magi-cloudflare-axi capability invoke logpush_jobs_by_account_id --input '{}' --allow-egress`; API token requires Logs Write permission. Bodyless `GET /accounts/{account_id}/logpush/jobs` returns first 100 jobs with no continuation.

Phase 4F adds `auditlogs_by_account_id`; exact contracts total 20, with 15 discovery-verified. Invoke with `magi-cloudflare-axi capability invoke auditlogs_by_account_id --input '{"since":"<since>","before":"<before>"}' --allow-egress`. Pinned app-specific OAuth scope additions are `account:read` and `auditlogs:read`; no API-token permission label is invented. Route `GET /accounts/{account_id}/logs/audit` uses fixed portal headers, cursor pagination via `result_info`, preserves count without treating it as total, makes one request with no retry or redirect, validates full response before strict sensitive-field projection, and fails responses over 8 MiB. Current Phase 4F vector: `I=172; S=172; R=B=P=V=20; D=15; X=40`; 152 routes remain unresolved.
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
