# Cloudflare API evidence

- REST base: `https://api.cloudflare.com/client/v4`; GraphQL endpoint: `/graphql`.
- Direct API auth: bearer API token, or `X-Auth-Key` plus `X-Auth-Email` global-key headers.
- Hosted MCP source snapshot: `70ff690553722f731849ede6ba9ce98958395a23`.
- Pinned source registered-name extractor and catalog both return 172 unique names. Extractor resolves names at registration call sites; declaration-only `hyperdrive_config_create` is excluded. Empty catalog `input_fields` and generic SDK labels are not treated as schema evidence.
- Pinned `apps/ai-gateway/src/auth-integration.spec.ts` sends direct stateless requests with `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, optional `Mcp-Name`, and `_meta` client/protocol fields; response has no session ID.
- Current Cloudflare Agents documentation lists `https://mcp.cloudflare.com/mcp`, bearer API-token automation, `search`/`execute`, product server URLs, and stateless compatibility.
- Current Cloudflare source marks AutoRAG, Radar, and GraphQL product servers deprecated in favor of unified Cloudflare API MCP; server metadata reports this while preserving access.
- Current Claude and Codex hook docs require event → matcher group → command handler nesting. Current Codex feature key is `hooks`; current OpenCode docs confirm global plugin directory and plugin shell context.
- Remote HTTP is rejected except explicit loopback test endpoints. Endpoint userinfo, query, fragment, and traversal are rejected before credentials.

Unknown product mappings, catalog input schemas, and generic SDK labels remain unverified until source-derived or official endpoint evidence exists.
