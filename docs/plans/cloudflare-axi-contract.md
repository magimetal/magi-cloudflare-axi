# Cloudflare AXI contract

Binary `magi-cloudflare-axi`; Rust 2024; MSRV 1.87; ISC. Direct Cloudflare REST/GraphQL plus hosted MCP `2026-07-28` stateless requests.

Output: one structured stdout payload, TOON default, strict JSON via `--format json` or `--format=json`, recursive 1000-codepoint truncation with `--full`. Errors use stdout and exit `1` operational or `2` usage. Provider bodies, dependency manuals, and credential values are excluded.

Home: no arguments validates endpoint and emits executable path, platform config paths, resolved scope, compact registered-tool inventory status, complete commands, and one bounded read-only `/accounts?page=1&per_page=3` summary when credentials exist. Missing credentials remain exit 0 with setup guidance.

Precedence: CLI > environment > project `.cloudflare-axi.toml` > platform global config > defaults. Credentials remain environment-only. `CLOUDFLARE_ACCOUNT_ID` > compatibility typo `CLOUDFLARE_ACOUNT_ID`.

Safety: endpoints are validated before auth and redirects are disabled. GET/HEAD and explicitly classified read POST may retry; mutations and MCP calls never retry. Raw non-GET requires `--allow-write`; DELETE requires exact path confirmation. Unified `search` is read-safe; docs search requires metered opt-in; every other remote tool requires write, metered, and exact-name confirmation because local inventory is not authoritative safety metadata.

Phase 3 blog direct reads remains complete.
Capability contract: catalog schema v3 proves 172 registered names and 172 canonical registration-input contracts. Phase 4E Logpush remains complete: invoke `magi-cloudflare-axi capability invoke logpush_jobs_by_account_id --input '{}' --allow-egress`; API token requires Logs Write permission. Bodyless `GET /accounts/{account_id}/logpush/jobs` returns first 100 jobs with no continuation.

Phase 4F adds authenticated `auditlogs_by_account_id`; exact contracts now total 20, with 15 discovery-verified. Invoke with `magi-cloudflare-axi capability invoke auditlogs_by_account_id --input '{"since":"<since>","before":"<before>"}' --allow-egress`. Pinned app-specific OAuth scope additions are `account:read` and `auditlogs:read`; no API-token permission label is invented. Route is `GET /accounts/{account_id}/logs/audit` with fixed portal headers, cursor pagination via `result_info`, count preserved but not treated as total, one request/no retry/no redirect, strict sensitive-field projection after full validation, and an 8 MiB failure bound. Current vector is `I=172; S=172; R=B=P=V=20; D=15; X=40`; 152 routes remain unresolved.

Session contract: setup is explicit, preserving, prevalidated across targets, atomically replacing each file, idempotent, and path-repairing for Claude, Codex, and OpenCode. New managed Unix files are `0600`; updates preserve permissions. Status requires exactly one valid owned handler and reports Codex enablement separately from non-interactively unverifiable trust. Session-end capture is N/A: CLI owns no durable Cloudflare workflow state, so writing transcript/session identifiers would add sensitive state without useful continuity.

Example: `magi-cloudflare-axi capability invoke d1_database_get --input '{"database_id":"<uuid>"}'`.
