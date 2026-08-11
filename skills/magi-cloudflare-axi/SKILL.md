---
name: magi-cloudflare-axi
description: Use for non-interactive Cloudflare REST, GraphQL, capability catalog, and hosted MCP operations with structured TOON or JSON output.
---

Use `magi-cloudflare-axi --help` first. `-v`, `-V`, and `--version` are config/auth/network-free probes. No-args home includes bounded live account state when authenticated and exact setup guidance otherwise. Resolve account/zone IDs before writes. Modeled lists support validated `--fields`, provider totals, explicit empty states, and complete pagination commands; raw REST pagination merges top-level arrays only.

Use `--format json` for parsing and `--full` only when truncation guidance appears. Exit 0 success/empty, 1 auth/config/network/API/output, 2 usage. Errors are structured stdout. Raw non-GET requires `--allow-write`; DELETE exact `--confirm-delete PATH`. MCP writes require `--allow-write --confirm TOOL`; metered tools require `--allow-metered`.

Treat 172-entry catalog v2 as pinned registered-name and registration-input schema authority. Current vector: `I=172; S=172; R=B=P=V=D=0; X=41`; route and runtime behavior parity remain incomplete. Compact fields derive from canonical Draft 2020-12 contracts, including conditional account selection; live server schemas can still vary by auth/request context. Use `capability list --access <classification>` for access filtering. Default `tool list` is compact. Query live schemas before calls: `tool list --server <server>` then `tool schema <name> --server <server>`. Unified server name is `cloudflare`; it exposes Code Mode `search` and `execute`. Unknown remote tools other than unified `search` and docs `search_cloudflare_documentation` conservatively require `--allow-write --allow-metered --confirm TOOL`; docs search still requires `--allow-metered`.

Examples:

```sh
magi-cloudflare-axi --format json account list --fields id,name --page 1
magi-cloudflare-axi --account <id> zone list --fields id,name,status,account
magi-cloudflare-axi api GET /zones --paginate --max-pages 2 --max-items 100
printf 'query { viewer { userName } }' | magi-cloudflare-axi graphql --stdin
magi-cloudflare-axi tool schema search --server cloudflare
```

Governance: `python3 scripts/catalog-governance.py validate` checks catalog envelope, pinned evidence, statuses, blockers, and baseline. `check` detects stale generated metrics/report. No provider calls or credentials required.
