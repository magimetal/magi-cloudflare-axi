---
name: magi-cloudflare-axi
description: Use for non-interactive Cloudflare REST, GraphQL, capability catalog, and hosted MCP operations with structured TOON or JSON output.
---

Use `magi-cloudflare-axi --help` first. `-v`, `-V`, and `--version` are config/auth/network-free probes. No-args home includes bounded live account state when authenticated and exact setup guidance otherwise. Resolve account/zone IDs before writes. Modeled lists support validated `--fields`, provider totals, explicit empty states, and complete pagination commands; raw REST pagination merges top-level arrays only.

Use `--format json` for parsing and `--full` only when truncation guidance appears. Exit 0 success/empty, 1 auth/config/network/API/output, 2 usage. Errors are structured stdout. Raw non-GET requires `--allow-write`; DELETE exact `--confirm-delete PATH`. MCP writes require `--allow-write --confirm TOOL`; metered tools require `--allow-metered`.

Treat catalog schema v3 as pinned 172-name and 172-schema authority. Phase 3 vector: `I=172; S=172; R=B=P=V=9; D=4; X=40`; four Blog public direct operations are discovery-verified, five earlier operation slices are discovery-generated, and 163 routes remain unresolved. `capability get get_post` returns `magi-cloudflare-axi capability invoke get_post --input '{"slug":"<slug>"}'`; list operations return full `capability invoke ... --input '{}'` commands; search returns `magi-cloudflare-axi capability invoke search_posts --input '{"query":"<query>"}'`. `search_posts` is POST; other Blog routes GET. Research pool: 80 legacy `public_http` reads = Browser 9 + Radar 65 + Blog 4 + demo 1 + stack 1. Browser/Radar require authoritative reclassification during Phase 4 research; demo/stack require route research during Phase 5.
`capability schema d1_database_get` is offline and authoritative for registration-input schema.
Safety flags: `--allow-write --allow-metered --confirm`.

Examples:

```sh
magi-cloudflare-axi --format json account list --fields id,name --page 1
magi-cloudflare-axi --account <id> zone list --fields id,name,status,account
magi-cloudflare-axi api GET /zones --paginate --max-pages 2 --max-items 100
printf 'query { viewer { userName } }' | magi-cloudflare-axi graphql --stdin
magi-cloudflare-axi tool schema search --server cloudflare
magi-cloudflare-axi capability schema d1_database_get
magi-cloudflare-axi --account <id> capability invoke d1_database_get --input '{"database_id":"<uuid>"}'
```

Governance: `python3 scripts/catalog-governance.py validate` checks catalog envelope, pinned evidence, statuses, blockers, and baseline. `check` detects stale generated metrics/report. No provider calls or credentials required.
