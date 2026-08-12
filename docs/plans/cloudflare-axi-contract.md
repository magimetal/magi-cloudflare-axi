# Cloudflare AXI contract

Binary `magi-cloudflare-axi`; Rust 2024; MSRV 1.87; ISC. Direct Cloudflare REST/GraphQL plus hosted MCP `2026-07-28` stateless requests.

Output: one structured stdout payload, TOON default, strict JSON via `--format json` or `--format=json`, recursive 1000-codepoint truncation with `--full`. Errors use stdout and exit `1` operational or `2` usage. Provider bodies, dependency manuals, and credential values are excluded.

Home: no arguments validates endpoint and emits executable path, platform config paths, resolved scope, compact registered-tool inventory status, complete commands, and one bounded read-only `/accounts?page=1&per_page=3` summary when credentials exist. Missing credentials remain exit 0 with setup guidance.

Precedence: CLI > environment > project `.cloudflare-axi.toml` > platform global config > defaults. Credentials remain environment-only. `CLOUDFLARE_ACCOUNT_ID` > compatibility typo `CLOUDFLARE_ACOUNT_ID`.

Safety: endpoints are validated before auth and redirects are disabled. GET/HEAD and explicitly classified read POST may retry; mutations and MCP calls never retry. Raw non-GET requires `--allow-write`; DELETE requires exact path confirmation. Unified `search` is read-safe; docs search requires metered opt-in; every other remote tool requires write, metered, and exact-name confirmation because local inventory is not authoritative safety metadata.

Capability contract: catalog schema v3 proves 172 registered names and 172 canonical registration-input contracts. Phase 3 vector: `I=172; S=172; R=B=P=V=9; D=4; X=40`. Four Blog public direct operations are route, behavior, policy, hermetically verified, and discovery verified; `search_posts` uses corrected `POST /search`, other Blog routes use GET. Five earlier representative operations remain discovery-generated. Remaining 163 routes unresolved; no live calls required.

`capability invoke d1_database_get` is representative operation entry point.

Session contract: setup is explicit, preserving, prevalidated across targets, atomically replacing each file, idempotent, and path-repairing for Claude, Codex, and OpenCode. New managed Unix files are `0600`; updates preserve permissions. Status requires exactly one valid owned handler and reports Codex enablement separately from non-interactively unverifiable trust. Session-end capture is N/A: CLI owns no durable Cloudflare workflow state, so writing transcript/session identifiers would add sensitive state without useful continuity.
