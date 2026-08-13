# Cloudflare AXI contract

Binary `magi-cloudflare-axi`; Rust 2024; MSRV 1.87; ISC. Direct Cloudflare REST/GraphQL plus hosted MCP `2026-07-28` stateless requests.

Output: one structured stdout payload, TOON default, strict JSON via `--format json` or `--format=json`, recursive 1000-codepoint truncation with `--full`. Errors use stdout and exit `1` operational or `2` usage. Provider bodies, dependency manuals, and credential values are excluded.

Home: no arguments validates endpoint and emits executable path, platform config paths, resolved scope, compact registered-tool inventory status, complete commands, and one bounded read-only `/accounts?page=1&per_page=3` summary when credentials exist. Missing credentials remain exit 0 with setup guidance.

Precedence: CLI > environment > project `.cloudflare-axi.toml` > platform global config > defaults. Credentials remain environment-only. `CLOUDFLARE_ACCOUNT_ID` > compatibility typo `CLOUDFLARE_ACOUNT_ID`.

Safety: endpoints are validated before auth and redirects are disabled. GET/HEAD and explicitly classified read POST may retry; mutations and MCP calls never retry. Raw non-GET requires `--allow-write`; DELETE requires exact path confirmation. Unified `search` is read-safe; docs search requires metered opt-in; every other remote tool requires write, metered, and exact-name confirmation because local inventory is not authoritative safety metadata.

Phase 3 blog direct reads remains complete.
Capability contract: catalog schema v3 proves 172 registered names and 172 canonical registration-input contracts. Phase 4D adds authenticated `get_url_pdf` and `get_url_screenshot`; 18 exact contracts now exist, with 13 discovery-verified and five generated. Phase 4 cohort has nine discovery-verified authenticated Browser reads; with Phase 2's generated `get_url_markdown`, Browser family has ten exact contracts. Vector: `I=172; S=172; R=B=P=V=18; D=13; X=40`; 154 routes remain unresolved. PDF posts `{url}` to `/accounts/{account_id}/browser-run/pdf` and requires `application/pdf` plus `%PDF-`; screenshot posts `{url,viewport}` to `/accounts/{account_id}/browser-run/screenshot` and requires `image/png` plus PNG signature. Screenshot omits absent viewport because JSON cannot represent JavaScript `undefined`; supplied viewport defaults nested width/height to 800×600 and strips unknown nested keys. Both require explicit new filesystem `--output`, refuse overwrite, create a private sibling temporary file before auth/network, enforce 8 MiB maximum, disable retries and redirects, and emit path, MIME type, bytes, and SHA-256 metadata. For `list_browser_sessions`, pinned `GET /accounts/{account_id}/browser-run/devtools/session` remains authoritative; official docs instead show `/browser-rendering/devtools/session` with optional `limit`/`offset`, while pinned zero-input handler exposes neither query. Phase 4 remains in progress.

Session contract: setup is explicit, preserving, prevalidated across targets, atomically replacing each file, idempotent, and path-repairing for Claude, Codex, and OpenCode. New managed Unix files are `0600`; updates preserve permissions. Status requires exactly one valid owned handler and reports Codex enablement separately from non-interactively unverifiable trust. Session-end capture is N/A: CLI owns no durable Cloudflare workflow state, so writing transcript/session identifiers would add sensitive state without useful continuity.

Example: `magi-cloudflare-axi capability invoke d1_database_get --input '{"database_id":"<uuid>"}'`.
