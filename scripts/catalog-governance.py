#!/usr/bin/env python3
"""Deterministic catalog validation, schema integration, metrics, reports, and tests."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).parents[1]
CATALOG = ROOT / "capabilities/cloudflare-mcp-parity.json"
SCHEMAS = ROOT / "capabilities/cloudflare-input-schemas.json"
FIXTURES = ROOT / "capabilities/cloudflare-schema-fixtures.json"
OPERATION_FILE = ROOT / "capabilities/cloudflare-operation-contracts.json"
METRICS = ROOT / "docs/cloudflare-capability-parity-metrics.json"
REPORT = ROOT / "docs/cloudflare-capability-parity.md"
COMMIT = "70ff690553722f731849ede6ba9ce98958395a23"
REPO = "https://github.com/cloudflare/mcp-server-cloudflare"
LEGACY_METADATA_SHA256 = "331059a021c239af4d5f8d5e61986090a47aea12af1f1eaf65640039008df2f1"
SCHEMA_VERSION = 3
SCHEMA_EVIDENCE_ID = "ev-phase1-canonical-schemas"
SCHEMA_SOURCE_REF = f"https://github.com/cloudflare/mcp-server-cloudflare/commit/{COMMIT}"
SCHEMA_EVIDENCE_FACT = (
    "Registration-input schemas originate from exact pinned upstream registration files and "
    "dependency declarations enumerated by source file, blob, span, and expression hash in "
    "local capabilities/cloudflare-input-schemas.json; local artifact identity is bound "
    "separately by schema_artifacts and per-capability contract hashes."
)
DEPENDENCY_PROVENANCE_COUNT = 803
DEPENDENCY_PROVENANCE_SHA256 = "bd6c83d69c8464ec0d5b428a2631972aa1d30acabdf89f310b1a06f8d5678d04"
OPERATION_BUNDLE_SHA256 = "d9b9528bd9f53de5b1c621c00e6d9938051c7bb6208205bd6333a6dda208469a"
OPERATION_CONTRACT_HASHES = {'d1_database_delete': 'd20fe0588da599ada8ff20f3baba6e948041033b6b635546943ec423173970da', 'd1_database_get': '6f17fcc6c6d39125a11e32b7716f3d3f8f96ea2048eb2d7a55ef15f5ca8bd5c7', 'get_crawl_result': 'e0743e3581acf1b7b0961b2588632a77838ae54a4ad922b58c635e15f040ac52', 'get_post': 'c8db96e377307473c88cd2948acb864dd48016ab131b668941c1dec0b43af4e1', 'get_url_html_content': '5a84bbcdbead36b9caae6cde60445f71d614681f387d0b0b02ee2b6e4c2b4909', 'get_url_json': '930b1ee212733b0fcd7e600bd346001ddb6e0154f99bbeebe27bc079e42cdb6d', 'get_url_links': '5c2aad547b8c1a50e9af0290d29b2bbe7639d4d580a0c8d6713b30c0ef31ae83', 'get_url_markdown': '853f582a9e39fe0a908117b2b7982be75d4c3c96c5bf5927d767ce8adc70abed', 'get_url_pdf': 'c544d991b6a98bace228cd7eb1bb124bd4934a6fa1cf318523579769e9e9780d', 'get_url_screenshot': '97ac366335b2110918db9244d13dfb4bafc35492032810778fd52200497fdbdc', 'get_url_snapshot': '3efc9a49696872d3ee6635a132056725737832846914cd816a0e18bc55b37588', 'graphql_schema_overview': '72fdb97a538fc6cf3a465e62c9d612a59605cc3829a21d08d3918a016d53d0cc', 'list_browser_sessions': 'e4a219d186616d0e00b5f33e3b856350282a727a4fcccbaac3920fe2aa34a5a1', 'list_posts': 'f9a765b3d1a962ab8d09cbdf304f855cbdbe87a03b73a9e280b343d4bec0a46c', 'list_tags': '7702537f950b693041ce32f2dc8d8c82c226cf4058b45319e060383a0095b2bd', 'scrape_url_elements': 'a5b4b365d1239a717b90f27a5cc3f7f9378f393e4e73e92ce3d3bb32ee54d415', 'search_cloudflare_documentation': '9c1240a95b266aebc995c0a4bd8aa08cb7a5bc25a8bd562162336a75e7f2aa41', 'search_posts': '50cedf16e00086e8505bee4d83bfe202687f5d15eaffa3e7f71723651a3cae91'}

OFFICIAL_DOCS = {
    "d1_database_delete": ("https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/delete/", "2026-08-11", "de0453348a3c58fb2510b64d6300831647c628eb3988acca56f7a9106edb7c5e"),
    "d1_database_get": ("https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/get/", "2026-08-11", "a1ea6b9e967b6c193355fbaedefbeb047bc49540c2ace13ef3fa827ac0addc3b"),
    "get_url_links": ("https://developers.cloudflare.com/browser-run/quick-actions/links-endpoint/", "2026-08-11", "f93231d6c8b6595e800caedf84fd192b4fca87cdac08f98398b2a4d7b3951af8"),
    "get_url_markdown": ("https://developers.cloudflare.com/browser-run/quick-actions/markdown-endpoint/", "2026-08-11", "2b0747bfcfc7f4204edf6ae04f452b5c9717263fc86a991e4826ab68d1aa204c"),
    "scrape_url_elements": ("https://developers.cloudflare.com/browser-run/quick-actions/scrape-endpoint/", "2026-08-11", "7f28c72cfe039655921ac6cd70ab38c76b563a70d84deb938a14631b64b38778"),
    "get_url_html_content": ("https://developers.cloudflare.com/browser-run/quick-actions/content-endpoint/", "2026-08-11", "2669a9587a5f409e7a21886f5635a0891a82331c6482ac64a3dca68bee00f607"),
    "graphql_schema_overview": ("https://developers.cloudflare.com/analytics/graphql-api/", "2026-08-11", "acc7f28b024fe8f70fb78877c2d801855994b2232e7d3d8a518afbe3055e75a6"),
    "search_cloudflare_documentation": ("https://developers.cloudflare.com/agents/model-context-protocol/cloudflare/servers-for-cloudflare/", "2026-08-11", "b46c2fac1b78f9a7a5476c41185277085c5da89180cf70dced0f3b0cf67792e8"),
    "get_url_json": ("https://developers.cloudflare.com/browser-run/quick-actions/json-endpoint/", "2026-08-11", "3004d5ccf35fa6596d4c9fb9e4463745a27d0f2e21924518b1a305818473461d"),
    "get_url_snapshot": ("https://developers.cloudflare.com/browser-run/quick-actions/snapshot/", "2026-08-11", "ff55ab1aeaf002b1a0f44bf41b22fdde0dae06a3b598986459291e8e0e2a8040"),
    "get_crawl_result": ("https://developers.cloudflare.com/browser-run/quick-actions/crawl-endpoint/", "2026-08-11", "cba30f5a58b1ed9e6e55bcc48669e3658b0530e1058f8607abb6b1e6d9ffd9df"),
    "list_browser_sessions": ("https://developers.cloudflare.com/api/resources/browser_rendering/subresources/devtools/subresources/session/methods/list", "2026-08-11", "59ba44d507b73288df01ee02c0afb380b353875cf92b42151535f18e4f61a257"),
    "get_url_pdf": ("https://developers.cloudflare.com/browser-run/quick-actions/pdf-endpoint/", "2026-08-11", "3eaf8175aa4ebee4c2bd04ff702ba3bbdf1470c650b9f89cc3064c6fe1653e5a"),
    "get_url_screenshot": ("https://developers.cloudflare.com/browser-run/quick-actions/screenshot-endpoint/", "2026-08-11", "f743f6b6bc692170cd0b5832e6f502dbad7c8bc1d27d271923e7d2870df8af41")
}
DIMENSIONS = (
    "inventory",
    "schema",
    "route",
    "behavior",
    "policy",
    "verification",
    "discovery",
    "external_blocker",
)
STATUSES = {
    "inventory": {"unresolved", "complete"},
    "schema": {"unresolved", "complete", "zero_input_evidenced"},
    "route": {"unresolved", "complete", "external_blocked"},
    "behavior": {"unresolved", "specified", "verified"},
    "policy": {"unresolved", "classified", "verified"},
    "verification": {"unverified", "hermetic_verified"},
    "discovery": {"missing", "generated", "verified"},
    "external_blocker": {"none", "open", "resolved"},
}
EVIDENCE_REQUIRED = {
    "inventory": {"complete"},
    "schema": {"complete", "zero_input_evidenced"},
    "route": {"complete", "external_blocked"},
    "behavior": {"specified", "verified"},
    "policy": {"classified", "verified"},
    "verification": {"hermetic_verified"},
    "discovery": {"generated", "verified"},
    "external_blocker": {"open", "resolved"},
}
COMPLETE_STATUSES = {
    "inventory": {"complete"},
    "schema": {"complete", "zero_input_evidenced"},
    "route": {"complete"},
    "behavior": {"verified"},
    "policy": {"verified"},
    "verification": {"hermetic_verified"},
    "discovery": {"verified"},
    "external_blocker": {"none", "resolved"},
}
LEGACY_ENUMS = {"scope": {"public", "account", "zone", "custom"}, "operation": {"read", "write"}, "transport": {"rest", "graphql", "mcp", "public_http", "internal_binding", "custom_container"}, "cli_access": {"modeled", "raw_rest", "raw_graphql", "public_direct", "blocked", "mcp_remote"}}
FAMILIES = {"ai-gateway": 5, "auditlogs": 1, "autorag": 3, "browser-rendering": 13, "cloudflare-blog": 4, "cloudflare-one-casb": 11, "demo-day": 1, "dex-analysis": 18, "dns-analytics": 3, "graphql": 6, "logpush": 1, "radar": 66, "sandbox-container": 7, "shared": 7, "stack-mcp": 2, "workers-bindings": 18, "workers-builds": 3, "workers-observability": 3}
TRANSPORTS = {"public_http": 76, "rest": 81, "custom_container": 7, "graphql": 6, "internal_binding": 1, "mcp": 1}
ACCESS = {"raw_rest": 124, "modeled": 9, "mcp_remote": 26, "public_direct": 6, "raw_graphql": 6, "blocked": 1}
OPERATIONS = {"read": 150, "write": 22}
BLOCKER_FAMILY = {"dex-analysis": "B-DEX", "cloudflare-one-casb": "B-CASB", "sandbox-container": "B-CONTAINER", "workers-observability": "B-OBS", "shared": "B-SHARED", "stack-mcp": "B-STACK"}
RECORD_KEYS = {
    "name",
    "family",
    "apps",
    "source",
    "source_ref",
    "source_commit",
    "description",
    "input_fields",
    "schema_contract_sha256",
    "scope",
    "operation",
    "transport",
    "cli_access",
    "parity",
}


class GovernanceError(ValueError):
    pass


def fail(path, message):
    raise GovernanceError(f"{path}: {message}")


def require_keys(value, required, optional, path):
    if not isinstance(value, dict):
        fail(path, "object required")
    missing = set(required) - set(value)
    extra = set(value) - set(required) - set(optional)
    if missing:
        fail(path, f"missing keys: {sorted(missing)}")
    if extra:
        fail(path, f"unknown keys: {sorted(extra)}")

def require_text(value, path):
    if not isinstance(value, str) or not value:
        fail(path, "nonempty string required")


def is_hex(value, length):
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def valid_span(value):
    if not isinstance(value, dict) or set(value) != {
        "start_byte",
        "end_byte",
        "start_line",
        "end_line",
    }:
        return False
    if any(not isinstance(value[key], int) or isinstance(value[key], bool) for key in value):
        return False
    return (
        0 <= value["start_byte"] < value["end_byte"]
        and 1 <= value["start_line"] <= value["end_line"]
    )

def valid_dependency_provenance(value):
    expected = {
        "id",
        "name",
        "file",
        "blob_oid",
        "classification",
        "source_span_kind",
        "source_span",
        "source_sha256",
    }
    return (
        isinstance(value, dict)
        and set(value) == expected
        and all(
            isinstance(value[field], str) and value[field]
            for field in expected - {"source_span"}
        )
        and not value["file"].startswith("/")
        and value["classification"]
        in {
            "dependency_node",
            "external_package_boundary",
            "language_builtin_boundary",
            "lexical_parameter_boundary",
        }
        and is_hex(value["blob_oid"], 40)
        and is_hex(value["source_sha256"], 64)
        and valid_span(value["source_span"])
    )

def legacy_digest(records):
    generated = {
        "source_ref",
        "parity",
        "input_fields",
        "schema_contract_sha256",
    }
    payload = [
        {key: value for key, value in record.items() if key not in generated}
        for record in records
    ]
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def json_sha256(value):
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()

def valid_line_span(value):
    if not isinstance(value, str) or not value:
        return False
    spans = value.split(';')
    return all(
        '-' in span
        and span.split('-', 1)[0].isdigit()
        and span.split('-', 1)[1].isdigit()
        and int(span.split('-', 1)[0]) > 0
        and int(span.split('-', 1)[0]) <= int(span.split('-', 1)[1])
        for span in spans
    )

def safe_relative_path(value):
    return isinstance(value, str) and bool(value) and not value.startswith('/') and '\\' not in value and all(part not in {'', '.', '..'} for part in value.split('/'))

def valid_source_ref(value):
    if value == SCHEMA_SOURCE_REF:
        return True
    if not isinstance(value, str) or ':' not in value:
        return False
    path, location = value.rsplit(':', 1)
    return safe_relative_path(path) and (location.isdigit() or valid_line_span(location))
def valid_test_id(value):
    if not isinstance(value, str) or '::' not in value:
        return False
    path, name = value.split('::', 1)
    if not (path.startswith('tests/') and path.endswith('.rs') and safe_relative_path(path) and bool(name) and all(char.isalnum() or char == '_' for char in name)):
        return False
    source = (ROOT / path).read_text() if (ROOT / path).is_file() else ''
    import re
    return re.search(rf'\b(?:async\s+)?fn\s+{re.escape(name)}\s*\(', source) is not None

def valid_date(value):
    if not isinstance(value, str) or len(value) != 10:
        return False
    try:
        import datetime
        datetime.date.fromisoformat(value)
        return True
    except ValueError:
        return False

def validate_provenance(item, path):
    provenance = item['provenance']
    kind = provenance['kind']
    if kind == 'missing':
        if not provenance['context_ref'] or provenance['fact'] != item['fact']:
            fail(path, 'missing provenance fact mismatch')
    elif kind == 'pinned_git':
        if provenance['repo'] != REPO or provenance['commit'] != COMMIT or not valid_source_ref(provenance['source_ref']):
            fail(path, 'pinned git source mismatch')
        values = (provenance['blob'], provenance['span'], provenance['source_sha256'])
        if values != (None, None, None) and not (is_hex(values[0], 40) and valid_line_span(values[1]) and is_hex(values[2], 64)):
            fail(path, 'pinned git identity must be wholly absent or exact')
    elif kind == 'official_docs':
        from urllib.parse import urlparse
        parsed = urlparse(provenance['url'])
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or not valid_date(provenance['documentation_date']) or not is_hex(provenance['fact_sha256'], 64):
            fail(path, 'invalid official documentation provenance')
    elif kind == 'generated_artifact':
        artifact = provenance['artifact']
        if artifact not in {'capabilities/cloudflare-input-schemas.json', 'capabilities/cloudflare-operation-contracts.json'} or not safe_relative_path(artifact) or not is_hex(provenance['sha256'], 64) or provenance['fact'] != item['fact']:
            fail(path, 'invalid generated artifact provenance')
        capability = provenance.get('capability')
        contract_hash = provenance.get('contract_sha256')
        if (capability is None) != (contract_hash is None) or (capability is not None and (not capability or not is_hex(contract_hash, 64))):
            fail(path, 'invalid generated artifact binding')
        if capability is not None:
            if artifact.endswith('input-schemas.json'):
                contract = next((row for row in json.loads(SCHEMAS.read_text())['contracts'] if row.get('capability') == capability), None)
            else:
                contract = next((row for row in json.loads(OPERATION_FILE.read_text())['contracts'] if row.get('capability') == capability), None)
            if contract is None or contract.get('contract_sha256') != contract_hash:
                fail(path, 'generated artifact contract binding mismatch')
    elif kind == 'hermetic_test' and (not valid_test_id(provenance['test_id']) or provenance['fact'] != item['fact']):
        fail(path, 'invalid hermetic test provenance')


def compact_schema_type(schema):
    if "enum" in schema:
        return "enum"
    kind = schema.get("type")
    if kind == "array":
        return f"array<{compact_schema_type(schema.get('items', {}))}>"
    if isinstance(kind, str):
        return kind
    branches = schema.get("anyOf") or schema.get("oneOf")
    if isinstance(branches, list):
        return "|".join(sorted({compact_schema_type(branch) for branch in branches}))
    return "any"


def compact_input_fields(contract):
    schema = contract["raw_input_schema"]
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))
    fields = []
    for name, field_schema in properties.items():
        field = {
            "name": name,
            "type": compact_schema_type(field_schema),
            "required": name in required,
        }
        if "default" in field_schema:
            field["default"] = field_schema["default"]
        fields.append(field)
    for overlay in contract["context_overlays"]:
        if overlay["operation"] != "extend_optional_property":
            continue
        if overlay["property"] in properties:
            fail(contract["capability"], "context overlay duplicates base property")
        fields.append(
            {
                "name": overlay["property"],
                "type": compact_schema_type(overlay["schema"]),
                "required": False,
                "condition": overlay["predicate"],
            }
        )
    return sorted(fields, key=lambda field: field["name"])

def apply_schema_bundle(catalog):
    bundle = json.loads(SCHEMAS.read_text())
    fixtures = json.loads(FIXTURES.read_text())
    operations = json.loads(OPERATION_FILE.read_text())
    contracts = {item["capability"]: item for item in bundle["contracts"]}
    operation_by_name = {item["capability"]: item for item in operations["contracts"]}
    evidence = [item for item in catalog["evidence"] if not item["id"].startswith("ev-d1-") and not item["id"].startswith("ev-operation-") and item["id"] != SCHEMA_EVIDENCE_ID]
    evidence.append({"id": SCHEMA_EVIDENCE_ID, "dimension": "schema", "provenance": {"kind": "pinned_git", "repo": REPO, "commit": COMMIT, "source_ref": SCHEMA_SOURCE_REF, "blob": None, "span": None, "source_sha256": None}, "fact": SCHEMA_EVIDENCE_FACT})
    for name, contract in operation_by_name.items():
        pinned = contract["evidence"]["pinned_handler"]
        test_id = contract["implementation"]["test_id"]
        prefix = f"ev-operation-{name}"
        handler = {"kind": "pinned_git", "repo": REPO, "commit": COMMIT, "source_ref": f"{pinned['file']}:{pinned['lines']}", "blob": pinned["blob_oid"], "span": pinned["lines"], "source_sha256": pinned["source_sha256"]}
        evidence.extend([
            {"id": prefix + "-route", "dimension": "route", "provenance": handler, "fact": "Pinned operation route and request construction."},
            {"id": prefix + "-behavior", "dimension": "behavior", "provenance": handler, "fact": "Authoritative operation behavior."},
            {"id": prefix + "-behavior-test", "dimension": "behavior", "provenance": {"kind": "hermetic_test", "test_id": test_id, "fact": "Hermetic exact-request transport test."}, "fact": "Hermetic exact-request transport test."},
            {"id": prefix + "-policy", "dimension": "policy", "provenance": handler, "fact": "Authoritative operation safety policy."},
            {"id": prefix + "-policy-test", "dimension": "policy", "provenance": {"kind": "hermetic_test", "test_id": test_id, "fact": "Hermetic exact-request transport test."}, "fact": "Hermetic exact-request transport test."},
            {"id": prefix + "-verification", "dimension": "verification", "provenance": {"kind": "hermetic_test", "test_id": test_id, "fact": "Hermetic exact-request transport test."}, "fact": "Hermetic exact-request transport test."},
            {"id": prefix + "-discovery", "dimension": "discovery", "provenance": {"kind": "generated_artifact", "artifact": "capabilities/cloudflare-operation-contracts.json", "sha256": json_sha256(operations), "fact": "Generated operation contract artifact.", "capability": name, "contract_sha256": contract["contract_sha256"]}, "fact": "Generated operation contract artifact."},
        ])
        if name in {"get_url_links", "get_url_markdown", "scrape_url_elements", "get_url_json", "get_url_snapshot", "get_crawl_result", "list_browser_sessions", "get_url_pdf", "get_url_screenshot", "get_post", "list_posts", "list_tags", "search_posts"}:
            evidence.append({"id": prefix + "-discovery-test", "dimension": "discovery", "provenance": {"kind": "hermetic_test", "test_id": "tests/integration.rs::capability_browser_discovery_examples_are_exact" if name in {"get_url_links", "get_url_markdown", "scrape_url_elements", "get_url_json", "get_url_snapshot", "get_crawl_result", "list_browser_sessions", "get_url_pdf", "get_url_screenshot"} else "tests/integration.rs::capability_blog_discovery_examples_are_exact", "fact": "Hermetic exact discovery example test."}, "fact": "Hermetic exact discovery example test."})
    catalog["evidence"] = sorted(evidence, key=lambda item: item["id"])
    for row in catalog["capabilities"]:
        contract = contracts[row["name"]]
        row["schema_contract_sha256"] = contract["contract_sha256"]
        row["input_fields"] = compact_input_fields(contract)
        prefix = f"ev-operation-{row['name']}"
        if row["name"] in operation_by_name:
            blog = row["name"] in {"get_post", "list_posts", "list_tags", "search_posts"}
            browser = row["name"] in {"get_url_links", "get_url_markdown", "scrape_url_elements", "get_url_json", "get_url_snapshot", "get_crawl_result", "list_browser_sessions", "get_url_pdf", "get_url_screenshot"}
            row["parity"].update({"route": {"status": "complete", "evidence_ids": [prefix + "-route"]}, "behavior": {"status": "verified", "evidence_ids": [prefix + "-behavior", prefix + "-behavior-test"]}, "policy": {"status": "verified", "evidence_ids": [prefix + "-policy", prefix + "-policy-test"]}, "verification": {"status": "hermetic_verified", "evidence_ids": [prefix + "-verification"]}, "discovery": {"status": "verified" if blog or browser else "generated", "evidence_ids": [prefix + "-discovery"] + ([prefix + "-discovery-test"] if blog or browser else [])}, "external_blocker": {"status": "none", "evidence_ids": []}})
    catalog["operation_artifacts"] = {"path": "capabilities/cloudflare-operation-contracts.json", "bundle_sha256": json_sha256({**operations, "bundle_sha256": None}), "contracts": [{"capability": item["capability"], "contract_sha256": item["contract_sha256"]} for item in operations["contracts"]]}
    catalog["schema_artifacts"] = {"bundle_sha256": json_sha256(bundle), "fixtures_sha256": json_sha256(fixtures)}
    catalog["legacy_metadata_sha256"] = legacy_digest(catalog["capabilities"])


def validate_schema_artifacts(catalog):
    bundle = json.loads(SCHEMAS.read_text())
    fixtures = json.loads(FIXTURES.read_text())
    contracts = bundle.get("contracts")
    if (
        bundle.get("version") != "2"
        or bundle.get("compiler_version") != "phase1-oxc-static-0.4"
        or bundle.get("source_access") != "exact_pinned_git_blobs"
        or bundle.get("execution_policy") != "static_only; never import or execute upstream TypeScript, Zod modules, registrations, or handlers"
        or bundle.get("zod_version") != "4.4.3"
        or bundle.get("source_commit") != COMMIT
        or bundle.get("tree_oid") != "1a51c6ff07170dfe3c3212c8fb96eb85d66f0b96"
        or bundle.get("dialect") != "https://json-schema.org/draft/2020-12/schema"
        or bundle.get("candidate_complete_count") != 168
        or bundle.get("candidate_zero_input_count") != 4
        or bundle.get("unresolved_count") != 0
        or bundle.get("dependency_provenance_count") != DEPENDENCY_PROVENANCE_COUNT
        or bundle.get("dependency_provenance_sha256") != DEPENDENCY_PROVENANCE_SHA256
        or not isinstance(contracts, list)
        or len(contracts) != 172
    ):
        fail("schema artifact", "invalid bundle envelope or coverage")
    rows = catalog["capabilities"]
    if [item.get("capability") for item in contracts] != [row["name"] for row in rows]:
        fail("schema artifact", "capability join mismatch")
    schemas_by_hash = {}
    capabilities_by_hash = {}
    status_counts = {"candidate_complete": 0, "candidate_zero_input": 0}
    dependency_provenance_count = 0
    dependency_provenance_by_capability = {}
    for row, contract in zip(rows, contracts):
        schema = contract.get("raw_input_schema")
        schema_hash = contract.get("raw_input_schema_sha256")
        contract_hash = contract.get("contract_sha256")
        status = contract.get("status")
        dependency_provenance = contract.get("dependency_provenance")
        dependency_ids = ([entry.get("id") for entry in dependency_provenance] if isinstance(dependency_provenance, list) and all(valid_dependency_provenance(entry) for entry in dependency_provenance) else None)
        expression_hash = contract.get("schema_expression_sha256")
        schema_span = contract.get("schema_span")
        if dependency_ids is not None:
            dependency_provenance_count += len(dependency_provenance)
            dependency_provenance_by_capability[row["name"]] = dependency_provenance
        unhashed = dict(contract)
        unhashed["contract_sha256"] = None
        expected_status = (
            "zero_input_evidenced"
            if contract.get("status") == "candidate_zero_input"
            else "complete"
        )
        if status in status_counts:
            status_counts[status] += 1
        if (
            status not in status_counts
            or not isinstance(schema, dict)
            or json_sha256(schema) != schema_hash
            or json_sha256(unhashed) != contract_hash
            or row["schema_contract_sha256"] != contract_hash
            or row["input_fields"] != compact_input_fields(contract)
            or row["parity"]["schema"]
            != {"status": expected_status, "evidence_ids": [SCHEMA_EVIDENCE_ID]}
            or not row["source"].startswith(contract.get("source_file", "") + ":")
            or not isinstance(contract.get("source_file"), str)
            or not contract["source_file"]
            or not is_hex(contract.get("source_blob_oid"), 40)
            or not valid_span(contract.get("registration_span"))
            or not is_hex(schema_hash, 64)
            or not is_hex(contract_hash, 64)
            or (
                status == "candidate_complete"
                and (not valid_span(schema_span) or not is_hex(expression_hash, 64))
            )
            or (
                status == "candidate_zero_input"
                and (
                    schema_span is not None
                    or expression_hash is not None
                    or schema != {"properties": {}, "type": "object"}
                )
            )
            or dependency_ids is None
            or dependency_ids != sorted(set(dependency_ids))
            or contract.get("unresolved_reasons") != []
        ):
            fail(row["name"], "schema artifact contract mismatch")
        if schema_hash in schemas_by_hash and schemas_by_hash[schema_hash] != schema:
            fail(row["name"], "schema hash collision or conflict")
        schemas_by_hash[schema_hash] = schema
        capabilities_by_hash.setdefault(schema_hash, []).append(row["name"])
    if status_counts != {"candidate_complete": 168, "candidate_zero_input": 4}:
        fail("schema artifact", f"derived contract status counts mismatch: {status_counts}")
    if (
        dependency_provenance_count != DEPENDENCY_PROVENANCE_COUNT
        or json_sha256(dependency_provenance_by_capability)
        != DEPENDENCY_PROVENANCE_SHA256
    ):
        fail("schema artifact", "derived dependency provenance mismatch")
    fixture_rows = fixtures.get("fixtures")
    fixture_by_hash = {
        item.get("raw_input_schema_sha256"): item
        for item in fixture_rows or []
        if isinstance(item, dict)
    }
    if (
        fixtures.get("version") != "schema-fixtures-v1"
        or fixtures.get("source_commit") != COMMIT
        or fixtures.get("tree_oid") != bundle["tree_oid"]
        or fixtures.get("bundle_sha256") != json_sha256(bundle)
        or fixtures.get("contract_count") != 172
        or fixtures.get("distinct_schema_count") != len(schemas_by_hash)
        or catalog.get("schema_artifacts")
        != {
            "bundle_sha256": json_sha256(bundle),
            "fixtures_sha256": json_sha256(fixtures),
        }
        or len(fixture_by_hash) != len(schemas_by_hash)
        or set(fixture_by_hash) != set(schemas_by_hash)
    ):
        fail("schema fixtures", "fixture envelope or shape coverage mismatch")
    for schema_hash, capabilities in capabilities_by_hash.items():
        fixture = fixture_by_hash[schema_hash]
        if fixture.get("capabilities") != capabilities or "positive" not in fixture or "negative" not in fixture:
            fail(schema_hash, "fixture capability join or instances mismatch")


def provenance_kind(item):
    return item["provenance"]["kind"]
def validate_evidence_kind(dimension, status, items, path):
    kinds = {provenance_kind(item) for item in items}
    authoritative = {"pinned_git", "official_docs"}
    if status in COMPLETE_STATUSES[dimension] and "missing" in kinds:
        fail(path, "completed status cannot use missing evidence")
    if dimension in {"schema", "route"} and status in COMPLETE_STATUSES[dimension]:
        if not kinds.intersection(authoritative):
            fail(path, "schema or route completion requires source or official evidence")
    if dimension == "route" and status == "external_blocked":
        if "missing" in kinds or not kinds.intersection(authoritative):
            fail(path, "route assertion requires source or official evidence")
    if dimension == "behavior" and status == "specified":
        if not kinds.intersection(authoritative):
            fail(path, "specified behavior requires source or official evidence")
    if dimension == "policy" and status == "classified":
        if not kinds.intersection(authoritative):
            fail(path, "classified policy requires source or official evidence")
    if dimension in {"behavior", "policy"} and status == "verified":
        if "hermetic_test" not in kinds or not kinds.intersection(authoritative):
            fail(path, "verified contract requires authoritative and hermetic evidence")
    if dimension == "verification" and status == "hermetic_verified":
        if "hermetic_test" not in kinds:
            fail(path, "hermetic verification requires hermetic evidence")
    if dimension == "discovery" and status in {"generated", "verified"}:
        if "missing" in kinds or "generated_artifact" not in kinds or (status == "verified" and "hermetic_test" not in kinds):
            fail(path, "discovery status evidence mismatch")
    if dimension == "external_blocker" and status == "resolved":
        if not kinds or "missing" in kinds:
            fail(path, "resolved blocker requires non-missing resolution evidence")
def validate_operation_contracts(catalog, operations, rows, evidence):
    require_keys(
        operations,
        {"version", "source_commit", "canonicalization", "bundle_sha256", "contract_count", "contracts"},
        set(),
        "$.operation_artifacts",
    )
    contracts = operations["contracts"]
    if (
        not isinstance(contracts, list)
        or operations["contract_count"] != len(contracts)
        or [item.get("capability") for item in contracts] != list(OPERATION_CONTRACT_HASHES)
    ):
        fail("$.operation_artifacts", "operation contract count or identity mismatch")
    contracted = set(OPERATION_CONTRACT_HASHES)
    active_statuses = {
        "route": {"complete"},
        "behavior": {"specified", "verified"},
        "policy": {"classified", "verified"},
        "verification": {"hermetic_verified"},
        "discovery": {"generated", "verified"},
    }
    for row in rows:
        if row["name"] not in contracted:
            for dimension, statuses in active_statuses.items():
                if row["parity"][dimension]["status"] in statuses:
                    fail(row["name"], f"completed {dimension} lacks operation contract")
    if operations["version"] != "phase4d-operation-contracts-v1" or operations["source_commit"] != COMMIT:
        fail("$.operation_artifacts", "operation source mismatch")
    if operations["canonicalization"] != "lexicographic compact JSON SHA-256; bundle hash sets bundle_sha256=null; each contract hash sets contract_sha256=null":
        fail("$.operation_artifacts", "operation canonicalization mismatch")
    by_name = {row["name"]: row for row in rows}
    if len(by_name) != len(rows):
        fail("$.operation_artifacts", "duplicate catalog capability")
    for index, contract in enumerate(contracts):
        path = f"$.operation_artifacts.contracts[{index}]"
        require_keys(contract, {"capability", "contract_sha256", "route", "behavior", "safety", "implementation", "evidence"}, set(), path)
        capability = contract["capability"]
        expected_contract_hash = OPERATION_CONTRACT_HASHES.get(capability)
        if capability not in by_name or expected_contract_hash is None or not is_hex(contract["contract_sha256"], 64):
            fail(path, "invalid capability or contract hash")
        expected_keys = {
            "route": {"transport", "method", "path_template", "path_parameters", "query_parameters", "body", "scope", "content_type", "auth"},
            "behavior": {"output_projection", "empty_state", "pagination", "artifact", "error"},
            "safety": {"operation", "destructive", "metered", "data_egress", "long_running", "retry_policy"},
            "implementation": {"status", "adapter", "test_id", "documentation_id", "reviewed_at"},
            "evidence": {"pinned_handler"},
        }
        if capability in {"get_post", "list_posts", "list_tags", "search_posts"}:
            expected_keys["route"].add("host")
        if capability not in {"get_post", "list_posts", "list_tags", "search_posts"}:
            expected_keys["evidence"].add("official_docs")
        else:
            expected_keys["evidence"].add("pinned_deployment")
        if capability == "search_cloudflare_documentation":
            expected_keys["route"] |= {"protocol", "tool"}
        if capability == "graphql_schema_overview":
            expected_keys["behavior"] |= {"fixed_document_sha256", "defaults", "pagination_output", "numeric_pagination"}
        if capability == "search_cloudflare_documentation":
            expected_keys["behavior"] |= {"result_fields", "projection_validation"}
        if capability == "graphql_schema_overview":
            expected_keys["evidence"].add("query_helper")
        for section, keys in expected_keys.items():
            require_keys(contract[section], keys, set(), f"{path}.{section}")
        for parameter in contract["route"]["path_parameters"]:
            require_keys(parameter, {"name", "source", "format", "max_length"}, set(), f"{path}.route.path_parameters")
        pinned = contract["evidence"]["pinned_handler"]
        if contract["implementation"]["status"] != "verified" or not valid_test_id(contract["implementation"]["test_id"]):
            fail(path, "invalid operation status or test ID")
        def validate_pinned_evidence(item, evidence_path):
            require_keys(item, {"commit", "file", "blob_oid", "lines", "source_sha256"}, set(), evidence_path)
            if item["commit"] != COMMIT or not safe_relative_path(item["file"]):
                fail(evidence_path, "invalid pinned evidence source")
            if not is_hex(item["blob_oid"], 40) or not valid_line_span(item["lines"]) or not is_hex(item["source_sha256"], 64):
                fail(evidence_path, "incomplete pinned evidence identity")

        validate_pinned_evidence(pinned, f"{path}.evidence.pinned_handler")
        for evidence_name, evidence_item in contract["evidence"].items():
            if evidence_name in {"pinned_handler", "query_helper"}:
                validate_pinned_evidence(evidence_item, f"{path}.evidence.{evidence_name}")
        if capability == "list_browser_sessions":
            expected = {
                "route": {"transport": "rest", "method": "GET", "path_template": "/accounts/{account_id}/browser-run/devtools/session", "path_parameters": [{"name": "account_id", "source": "resolved_account", "format": "single_path_segment", "max_length": 32}], "query_parameters": [], "body": "none", "scope": "account", "content_type": "application/json", "auth": "account"},
                "behavior": {"output_projection": "session_array", "empty_state": "empty_array", "pagination": "none", "artifact": "none", "error": "bare_json_or_result_array"},
                "safety": {"operation": "read", "destructive": False, "metered": False, "data_egress": True, "long_running": False, "retry_policy": "transient_read"},
                "implementation": {"status": "verified", "adapter": "rest", "test_id": "tests/transport.rs::capability_list_browser_sessions_exact_request", "documentation_id": "cloudflare-browser-list-browser-sessions", "reviewed_at": "2026-08-11"},
                "pinned_handler": {"commit": COMMIT, "file": "apps/browser-rendering/src/tools/browser.tools.ts", "blob_oid": "ae998f642ba8548b715e1573bc0049c96c9e1f28", "lines": "522-560", "source_sha256": "c6b05861d44395a6e2bc84ac37320cd04d9a7edded73cf14d410fce32e31a361"},
            }
            actual = {key: contract[key] for key in ("route", "behavior", "safety", "implementation")}
            actual["pinned_handler"] = contract["evidence"]["pinned_handler"]
            if actual != expected:
                fail(path, "Browser sessions operation semantic mismatch")
        if capability in {"get_url_pdf", "get_url_screenshot"}:
            expected = {
                "get_url_pdf": {
                    "route": {"transport": "rest", "method": "POST", "path_template": "/accounts/{account_id}/browser-run/pdf", "path_parameters": [{"name": "account_id", "source": "resolved_account", "format": "single_path_segment", "max_length": 32}], "query_parameters": [], "body": "{url}", "scope": "account", "content_type": "application/json", "auth": "account"},
                    "behavior": {"output_projection": "binary_pdf", "empty_state": "new_file", "pagination": "none", "artifact": "filesystem_new_file", "error": "binary_media_and_signature"},
                    "safety": {"operation": "read", "destructive": False, "metered": True, "data_egress": True, "long_running": True, "retry_policy": "never"},
                    "test_id": "tests/transport.rs::capability_get_url_pdf_exact_request", "lines": "146-194", "source_sha256": "772c45de366c6caca12226ee605c9c055f3790bf836abac98b069c9e655f30eb"
                },
                "get_url_screenshot": {
                    "route": {"transport": "rest", "method": "POST", "path_template": "/accounts/{account_id}/browser-run/screenshot", "path_parameters": [{"name": "account_id", "source": "resolved_account", "format": "single_path_segment", "max_length": 32}], "query_parameters": [], "body": "{url,viewport}", "scope": "account", "content_type": "application/json", "auth": "account"},
                    "behavior": {"output_projection": "binary_png", "empty_state": "new_file", "pagination": "none", "artifact": "filesystem_new_file", "error": "binary_media_and_signature"},
                    "safety": {"operation": "read", "destructive": False, "metered": True, "data_egress": True, "long_running": True, "retry_policy": "never"},
                    "test_id": "tests/transport.rs::capability_get_url_screenshot_exact_request", "lines": "92-144", "source_sha256": "19aa8f9fc558723f9e1a7ca6e0ea16d75cb99af15ff871ca485289e74b9f4354"
                }
            }[capability]
            actual = {key: contract[key] for key in ("route", "behavior", "safety")}
            actual["implementation"] = contract["implementation"]
            actual["pinned_handler"] = contract["evidence"]["pinned_handler"]
            expected_test_id = expected.pop("test_id")
            expected_lines = expected.pop("lines")
            expected_source_sha256 = expected.pop("source_sha256")
            expected["implementation"] = {"status": "verified", "adapter": "rest", "test_id": expected_test_id, "documentation_id": f"cloudflare-browser-{capability}", "reviewed_at": "2026-08-11"}
            expected["pinned_handler"] = {"commit": COMMIT, "file": "apps/browser-rendering/src/tools/browser.tools.ts", "blob_oid": "ae998f642ba8548b715e1573bc0049c96c9e1f28", "lines": expected_lines, "source_sha256": expected_source_sha256}
            if actual != expected:
                fail(path, "browser binary operation semantic mismatch")

        if capability == "graphql_schema_overview" and (contract["behavior"].get("fixed_document_sha256") != "7a041df0f3b28c0eccf5c3dfa2ae5b1f4d2be4b3aaef8457ca08342d4bb5b94" or contract["behavior"].get("defaults") != {"page": 1, "pageSize": 100} or contract["behavior"].get("pagination_output") != ["page", "pageSize", "totalTypes", "totalPages", "hasNextPage", "hasPreviousPage"] or contract["behavior"].get("numeric_pagination") != "javascript_number_slice_semantics"):
            fail(path, "GraphQL semantic pin mismatch")
        if capability == "search_cloudflare_documentation" and (contract["behavior"].get("result_fields") != ["similarity", "id", "url", "title", "text"] or contract["behavior"].get("projection_validation") != "strict_projection_and_field_type_validation"):
            fail(path, "MCP semantic pin mismatch")
        pinned = contract["evidence"]["pinned_handler"]
        if capability in {"get_post", "list_posts", "list_tags", "search_posts"}:
            deployment = contract["evidence"].get("pinned_deployment")
            if not deployment:
                fail(path, "Blog operation deployment evidence required")
            validate_pinned_evidence(deployment, f"{path}.evidence.pinned_deployment")
        else:
            docs = contract["evidence"]["official_docs"]
            require_keys(docs, {"url", "documentation_date", "fact_sha256"}, set(), f"{path}.evidence.official_docs")
            if not valid_date(docs["documentation_date"]) or not is_hex(docs["fact_sha256"], 64):
                fail(path, "invalid official operation evidence")
            if tuple(docs[key] for key in ("url", "documentation_date", "fact_sha256")) != OFFICIAL_DOCS[capability]:
                fail(path, "official operation evidence digest pin mismatch")
        if capability == "d1_database_get":
            expected = {
                "transport": "rest", "method": "GET", "path_template": "/accounts/{account_id}/d1/database/{database_id}", "scope": "account", "body": "none", "content_type": "application/json",
                "output_projection": "result", "empty_state": "not_applicable_detail", "pagination": "none", "artifact": "none", "error": "structured_cloudflare_api",
                "operation": "read", "destructive": False, "metered": False, "data_egress": False, "long_running": False, "retry_policy": "transient_read",
                "adapter": "rest", "documentation_id": "cloudflare-d1-database-get", "reviewed_at": "2026-08-11",
            }
            actual = {**{key: contract["route"][key] for key in ("transport", "method", "path_template", "scope", "body", "content_type")}, **{key: contract["behavior"][key] for key in ("output_projection", "empty_state", "pagination", "artifact", "error")}, **{key: contract["safety"][key] for key in ("operation", "destructive", "metered", "data_egress", "long_running", "retry_policy")}, **{key: contract["implementation"][key] for key in ("adapter", "documentation_id", "reviewed_at")}}
            if actual != expected or contract["route"]["path_parameters"] != [{"name": "account_id", "source": "resolved_account", "format": "single_path_segment", "max_length": 32}, {"name": "database_id", "source": "input", "format": "uuid", "max_length": None}]:
                fail(path, "D1 operation semantics mismatch")
        if contract["contract_sha256"] != json_sha256({**contract, "contract_sha256": None}):
            fail(path, "operation semantic hash mismatch")
        if contract["contract_sha256"] != expected_contract_hash:
            fail(path, "operation contract identity mismatch")
        schema_contract = next((item for item in json.loads(SCHEMAS.read_text())["contracts"] if item.get("capability") == capability), None)
        if schema_contract is None or by_name[capability]["schema_contract_sha256"] != schema_contract["contract_sha256"]:
            fail(path, "catalog/schema operation join mismatch")
        row = by_name[capability]
        blog = capability in {"get_post", "list_posts", "list_tags", "search_posts"}
        expected_transport = "public_http" if blog else contract["route"]["transport"]
        if row["scope"] != contract["route"]["scope"] or row["operation"] != contract["safety"]["operation"]:
            fail(path, "catalog operation scope/operation join mismatch")
        if row["transport"] != expected_transport:
            fail(path, "catalog transport join mismatch")
        if capability == "get_url_html_content" and row["cli_access"] != "raw_rest":
            fail(path, "browser legacy metadata join mismatch")
        if capability in {"get_url_pdf", "get_url_screenshot"} and row["cli_access"] != "modeled":
            fail(path, "binary Browser access classification mismatch")
        if capability == "search_cloudflare_documentation" and row["cli_access"] != "mcp_remote":
            fail(path, "MCP legacy metadata join mismatch")
        if capability not in {"get_url_html_content", "search_cloudflare_documentation"} and row.get("method") is not None and row["method"] != contract["route"]["method"]:
            fail(path, "catalog method join mismatch")
        if capability not in {"get_url_html_content", "search_cloudflare_documentation"} and row.get("path_template") is not None and row["path_template"] != contract["route"]["path_template"]:
            fail(path, "catalog path join mismatch")
        if capability in {"get_post", "list_posts", "list_tags", "search_posts"}:
            evidence_items = (contract["evidence"]["pinned_handler"], contract["evidence"]["pinned_deployment"])
        else:
            evidence_items = (contract["evidence"]["pinned_handler"], contract["evidence"].get("official_docs"))
        for evidence_item in evidence_items:
            if not evidence_item:
                fail(path, "operation evidence missing")

        def exact_authority(item):
            provenance = item["provenance"]
            pinned = contract["evidence"]["pinned_handler"]
            if provenance["kind"] == "pinned_git":
                return all(provenance.get(left) == right for left, right in (("repo", REPO), ("commit", COMMIT), ("source_ref", f"{pinned['file']}:{pinned['lines']}"), ("blob", pinned["blob_oid"]), ("span", pinned["lines"]), ("source_sha256", pinned["source_sha256"])))
            docs = contract["evidence"].get("official_docs")
            return docs is not None and provenance["kind"] == "official_docs" and all(provenance.get(left) == docs[right] for left, right in (("url", "url"), ("documentation_date", "documentation_date"), ("fact_sha256", "fact_sha256")))

        def exact_test(item):
            provenance = item["provenance"]
            return provenance["kind"] == "hermetic_test" and provenance.get("test_id") == contract["implementation"]["test_id"]

        def exact_discovery(item):
            provenance = item["provenance"]
            browser_discovery = {"get_url_links", "get_url_markdown", "scrape_url_elements", "get_url_json", "get_url_snapshot", "get_crawl_result", "list_browser_sessions", "get_url_pdf", "get_url_screenshot"}
            return (
                provenance["kind"] == "generated_artifact"
                and provenance.get("artifact") == "capabilities/cloudflare-operation-contracts.json"
                and provenance.get("capability") == capability
                and provenance.get("contract_sha256") == contract["contract_sha256"]
            ) or (
                capability in browser_discovery
                and provenance["kind"] == "hermetic_test"
                and provenance.get("test_id") == "tests/integration.rs::capability_browser_discovery_examples_are_exact"
            ) or (
                blog
                and provenance["kind"] == "hermetic_test"
                and provenance.get("test_id") == "tests/integration.rs::capability_blog_discovery_examples_are_exact"
            )
        active_statuses = {
            "route": {"complete"},
            "behavior": {"specified", "verified"},
            "policy": {"classified", "verified"},
            "verification": {"hermetic_verified"},
            "discovery": {"generated", "verified"},
        }
        applicability = {
            "route": exact_authority,
            "behavior": lambda item: exact_authority(item) or exact_test(item),
            "policy": lambda item: exact_authority(item) or exact_test(item),
            "verification": exact_test,
            "discovery": exact_discovery,
        }
        for dimension, statuses in active_statuses.items():
            state = row["parity"][dimension]
            if state["status"] in statuses and not all(applicability[dimension](evidence[item_id]) for item_id in state["evidence_ids"]):
                fail(row["name"], f"completed {dimension} evidence does not reverse-join operation contract")
def validate_route_and_discovery(catalog, rows, evidence):
    operations = json.loads(OPERATION_FILE.read_text())
    validate_operation_contracts(catalog, operations, rows, evidence)

def validate(catalog):
    root_keys = {"schema_version", "catalog_id", "source", "denominator", "schema_artifacts", "operation_artifacts", "legacy_metadata_sha256", "evidence", "blockers", "capabilities"}
    require_keys(catalog, root_keys, set(), "$")
    require_keys(catalog["source"], {"repo", "commit", "ref"}, set(), "$.source")
    if catalog["schema_version"] != SCHEMA_VERSION or catalog["catalog_id"] != "cloudflare-mcp-parity" or catalog["source"] != {"repo": REPO, "commit": COMMIT, "ref": "pinned-source"}:
        fail("$", "unsupported catalog envelope or pinned source")
    operations = json.loads(OPERATION_FILE.read_text())
    contracts = operations.get("contracts", [])
    if operations.get("version") != "phase4d-operation-contracts-v1" or json_sha256({**operations, "bundle_sha256": None}) != OPERATION_BUNDLE_SHA256 or operations.get("bundle_sha256") != OPERATION_BUNDLE_SHA256 or operations.get("contract_count") != len(contracts) or contracts != sorted(contracts, key=lambda item: item.get("capability", "")) or len(contracts) != 18:
        fail("$.operation_artifacts", "operation bundle parsing or hash mismatch")
    for contract in contracts:
        capability = contract.get("capability")
        unhashed = {**contract, "contract_sha256": None}
        if capability not in OPERATION_CONTRACT_HASHES or contract.get("contract_sha256") != OPERATION_CONTRACT_HASHES[capability] or json_sha256(unhashed) != OPERATION_CONTRACT_HASHES[capability]:
            fail("$.operation_artifacts", "operation contract hash mismatch")
    expected_operation_artifacts = {"path": "capabilities/cloudflare-operation-contracts.json", "bundle_sha256": OPERATION_BUNDLE_SHA256, "contracts": [{"capability": item["capability"], "contract_sha256": item["contract_sha256"]} for item in contracts]}
    if catalog["operation_artifacts"] != expected_operation_artifacts:
        fail("$.operation_artifacts", "catalog operation artifact binding mismatch")
    rows = catalog["capabilities"]
    if catalog["denominator"] != 172 or not isinstance(rows, list) or len(rows) != 172: fail("$.capabilities", "expected denominator and record count 172")
    names = [row.get("name") for row in rows]
    if any(not isinstance(name, str) or not name for name in names) or names != sorted(names) or len(set(names)) != 172: fail("$.capabilities", "names must be sorted and unique")
    if catalog["legacy_metadata_sha256"] != LEGACY_METADATA_SHA256 or legacy_digest(rows) != LEGACY_METADATA_SHA256:
        fail("$.legacy_metadata_sha256", "legacy metadata identity mismatch")
    if not isinstance(catalog["evidence"], list): fail("$.evidence", "array required")
    evidence = {}
    for index, item in enumerate(catalog["evidence"]):
        path = f"$.evidence[{index}]"
        require_keys(item, {"id", "dimension", "provenance", "fact"}, set(), path)
        provenance = item["provenance"]
        if item["id"] in evidence or item["dimension"] not in DIMENSIONS or not isinstance(provenance, dict) or provenance.get("kind") not in {"missing", "pinned_git", "official_docs", "generated_artifact", "hermetic_test"}: fail(path, "invalid or duplicate evidence")
        kind = provenance["kind"]
        required = {"kind", "context_ref", "fact"} if kind == "missing" else {"kind", "repo", "commit", "source_ref", "blob", "span", "source_sha256"} if kind == "pinned_git" else {"kind", "url", "documentation_date", "fact_sha256"} if kind == "official_docs" else {"kind", "artifact", "sha256", "fact"} if kind == "generated_artifact" else {"kind", "test_id", "fact"}
        optional = {"capability", "contract_sha256"} if kind == "generated_artifact" else set()
        require_keys(provenance, required, optional, f"{path}.provenance")
        validate_provenance(item, path)
        if kind == "generated_artifact":
            actual = json_sha256(json.loads((ROOT / provenance["artifact"]).read_text()))
            if actual != provenance["sha256"]:
                fail(path, "generated artifact hash mismatch")
        evidence[item["id"]] = item
    expected_schema_evidence = {"id": SCHEMA_EVIDENCE_ID, "dimension": "schema", "provenance": {"kind": "pinned_git", "repo": REPO, "commit": COMMIT, "source_ref": SCHEMA_SOURCE_REF, "blob": None, "span": None, "source_sha256": None}, "fact": SCHEMA_EVIDENCE_FACT}
    validate_route_and_discovery(catalog, rows, evidence)
    if evidence.get(SCHEMA_EVIDENCE_ID) != expected_schema_evidence: fail("$.evidence", "Phase 1 schema evidence provenance mismatch")

    if not isinstance(catalog["blockers"], list):
        fail("$.blockers", "array required")
    blockers = {}
    for index, blocker in enumerate(catalog["blockers"]):
        path = f"$.blockers[{index}]"
        fields = {"id", "status", "family", "summary", "affected_names"}
        require_keys(blocker, fields, set(), path)
        require_text(blocker["id"], f"{path}.id")
        require_text(blocker["summary"], f"{path}.summary")
        affected = blocker["affected_names"]
        if (
            blocker["id"] in blockers
            or blocker["status"] not in {"open", "resolved"}
            or blocker["family"] not in BLOCKER_FAMILY
            or blocker["id"] != BLOCKER_FAMILY[blocker["family"]]
            or not isinstance(affected, list)
            or not affected
            or any(not isinstance(name, str) or not name for name in affected)
            or affected != sorted(set(affected))
        ):
            fail(path, "invalid blocker ledger entry")
        blockers[blocker["id"]] = blocker

    used_evidence = set()
    for index, row in enumerate(rows):
        path = f"$.capabilities[{index}]"
        require_keys(
            row,
            RECORD_KEYS,
            {"method", "path_template", "sdk_method", "blocker"},
            path,
        )
        for field in (
            "name",
            "family",
            "source",
            "source_ref",
            "source_commit",
            "description",
            "scope",
            "operation",
            "transport",
            "cli_access",
        ):
            require_text(row[field], f"{path}.{field}")
        if (
            row["source_commit"] != COMMIT
            or row["source_ref"] != row["source"]
            or row["family"] not in FAMILIES
            or any(row[field] not in allowed for field, allowed in LEGACY_ENUMS.items())
        ):
            fail(path, "legacy metadata drift")
        if not isinstance(row["apps"], list) or not row["apps"]:
            fail(f"{path}.apps", "nonempty string array required")
        if any(not isinstance(app, str) or not app for app in row["apps"]):
            fail(f"{path}.apps", "nonempty string array required")
        if not isinstance(row["input_fields"], list):
            fail(f"{path}.input_fields", "array required")
        for field_index, field in enumerate(row["input_fields"]):
            field_path = f"{path}.input_fields[{field_index}]"
            require_keys(field, {"name", "type", "required"}, {"default", "condition"}, field_path)
            require_text(field["name"], f"{field_path}.name")
            require_text(field["type"], f"{field_path}.type")
            if not isinstance(field["required"], bool):
                fail(f"{field_path}.required", "boolean required")
            if "condition" in field:
                require_text(field["condition"], f"{field_path}.condition")
        require_text(row["schema_contract_sha256"], f"{path}.schema_contract_sha256")
        for optional in ("method", "path_template", "sdk_method", "blocker"):
            if optional in row:
                require_text(row[optional], f"{path}.{optional}")
        if row["cli_access"] == "blocked" and not row.get("blocker"):
            fail(path, "blocked capability lacks legacy blocker")

        parity = row["parity"]
        require_keys(parity, set(DIMENSIONS), set(), f"{path}.parity")
        for dimension in DIMENSIONS:
            state_path = f"{path}.parity.{dimension}"
            state = parity[dimension]
            optional = {"blocker_id"} if dimension == "external_blocker" else set()
            require_keys(state, {"status", "evidence_ids"}, optional, state_path)
            ids = state["evidence_ids"]
            if (
                state["status"] not in STATUSES[dimension]
                or not isinstance(ids, list)
                or any(not isinstance(evidence_id, str) or not evidence_id for evidence_id in ids)
                or len(ids) != len(set(ids))
            ):
                fail(state_path, "invalid status or duplicate evidence")
            if state["status"] in EVIDENCE_REQUIRED[dimension] and not ids:
                fail(state_path, "status requires evidence")
            if dimension == "inventory" and (
                state["status"] != "complete" or len(ids) != 1
            ):
                fail(state_path, "inventory requires one evidence")
            if dimension == "external_blocker":
                if state["status"] == "none" and ("blocker_id" in state or ids):
                    fail(state_path, "none cannot have blocker_id or evidence")
                if state["status"] in {"open", "resolved"} and not state.get("blocker_id"):
                    fail(state_path, "blocker status requires id")
            referenced = []
            for evidence_id in ids:
                item = evidence.get(evidence_id)
                if not item or item["dimension"] != dimension:
                    fail(state_path, f"invalid evidence ref {evidence_id}")
                referenced.append(item)
                used_evidence.add(evidence_id)
            if dimension == "inventory":
                item = referenced[0]
                if provenance_kind(item) != "pinned_git" or item["provenance"]["source_ref"] != row["source"]:
                    fail(state_path, "inventory evidence mismatch")
            validate_evidence_kind(dimension, state["status"], referenced, state_path)

        external = parity["external_blocker"]
        if external["status"] in {"open", "resolved"}:
            if external["blocker_id"] not in blockers:
                fail(path, "dangling blocker")
        if external["status"] == "open" and not row.get("blocker"):
            fail(path, "open blocker lacks legacy blocker")

    if set(evidence) != used_evidence:
        fail("$.evidence", "orphan evidence")
    for blocker_id, blocker in blockers.items():
        actual = sorted(
            row["name"]
            for row in rows
            if row["parity"]["external_blocker"].get("blocker_id") == blocker_id
        )
        if actual != blocker["affected_names"]:
            fail(f"$.blockers[{blocker_id}]", "affected names mismatch")
        if any(row["family"] != blocker["family"] for row in rows if row["name"] in actual):
            fail(f"$.blockers[{blocker_id}]", "family mismatch")
        open_record = any(
            row["parity"]["external_blocker"].get("blocker_id") == blocker_id
            and row["parity"]["external_blocker"]["status"] == "open"
            for row in rows
        )
        expected_status = "open" if open_record else "resolved"
        if blocker["status"] != expected_status:
            fail(f"$.blockers[{blocker_id}]", "ledger status mismatch")

    for field, expected in (
        ("family", FAMILIES),
        ("transport", TRANSPORTS),
        ("cli_access", ACCESS),
        ("operation", OPERATIONS),
    ):
        actual = {value: sum(row[field] == value for row in rows) for value in expected}
        if actual != expected or sum(actual.values()) != 172:
            fail("$.capabilities", f"{field} baseline mismatch")
    if sum("method" in row for row in rows) != 147:
        fail("$.capabilities", "method baseline mismatch")
    if sum("path_template" in row for row in rows) != 15:
        fail("$.capabilities", "path baseline mismatch")
    if sum("blocker" in row for row in rows) != 40:
        fail("$.capabilities", "legacy blocker baseline mismatch")
    validate_schema_artifacts(catalog)


def metric_vector(rows):
    dimensions = {
        "I": "inventory",
        "S": "schema",
        "R": "route",
        "B": "behavior",
        "P": "policy",
        "V": "verification",
        "D": "discovery",
    }
    result = {}
    for code, dimension in dimensions.items():
        result[code] = sum(
            row["parity"][dimension]["status"] in COMPLETE_STATUSES[dimension]
            for row in rows
        )
    result["X"] = sum(
        row["parity"]["external_blocker"]["status"] == "open"
        or row["parity"]["route"]["status"] == "external_blocked"
        for row in rows
    )
    return result


def metrics(catalog):
    rows = catalog["capabilities"]
    output = {
        "schema_version": SCHEMA_VERSION,
        "catalog_commit": COMMIT,
        "denominator": len(rows),
        "parity": metric_vector(rows),
        "dimensions": {},
        "groups": {},
    }
    for dimension in DIMENSIONS:
        counts = {
            status: sum(row["parity"][dimension]["status"] == status for row in rows)
            for status in sorted(STATUSES[dimension])
        }
        output["dimensions"][dimension] = {
            "counts": counts,
            "complete": sum(
                row["parity"][dimension]["status"] in COMPLETE_STATUSES[dimension]
                for row in rows
            ),
        }
    for field in ("family", "transport", "cli_access", "operation"):
        output["groups"][field] = {}
        for value in sorted({row[field] for row in rows}):
            selected = [row for row in rows if row[field] == value]
            output["groups"][field][value] = {
                "count": len(selected),
                "parity": metric_vector(selected),
            }
    output["groups"]["blocker"] = {
        blocker["id"]: {
            "count": len(blocker["affected_names"]),
            "status": blocker["status"],
            "family": blocker["family"],
            "parity": {"X": len(blocker["affected_names"])},
        }
        for blocker in sorted(catalog["blockers"], key=lambda item: item["id"])
    }
    return output


def report(catalog, metric):
    lines = [
        "# Cloudflare capability parity (generated)",
        "",
        f"Pinned source: `{COMMIT}`",
        f"Denominator: **{metric['denominator']}**. Full parity is not claimed.",
        "",
        "## Parity dimensions",
        "",
        "| Dimension | Status counts | Complete |",
        "|---|---|---|",
    ]
    for dimension in DIMENSIONS:
        value = metric["dimensions"][dimension]
        counts = json.dumps(value["counts"], sort_keys=True)
        lines.append(f"| {dimension} | {counts} | {value['complete']} |")
    lines += [
        "",
        "## Global parity",
        "",
        "| I | S | R | B | P | V | D | X |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
        "| " + " | ".join(str(metric["parity"][code]) for code in "ISRBPVDX") + " |",
    ]
    for title, field in (
        ("Family", "family"),
        ("Transport", "transport"),
        ("Access classification", "cli_access"),
        ("Read/write operation", "operation"),
    ):
        lines += [
            "",
            f"## {title} summary",
            "",
            "| Group | Count | I | S | R | B | P | V | D | X |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for name, group in metric["groups"][field].items():
            values = [name, str(group["count"])]
            values.extend(str(group["parity"][code]) for code in "ISRBPVDX")
            lines.append("| " + " | ".join(values) + " |")
    lines += [
        "",
        "## Blocker ledger",
        "",
        "| ID | Count | X | Status | Family |",
        "|---|---:|---:|---|---|",
    ]
    for name, group in metric["groups"]["blocker"].items():
        lines.append(
            f"| {name} | {group['count']} | {group['parity']['X']} | "
            f"{group['status']} | {group['family']} |"
        )
    lines += [
        "",
        "## Capability details",
        "",
        "| Name | Family | Transport | Access | Operation | I | S | R | B | P | V | D | X | Blocker |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in catalog["capabilities"]:
        vector = metric_vector([row])
        values = [
            row["name"],
            row["family"],
            row["transport"],
            row["cli_access"],
            row["operation"],
        ]
        values.extend("Y" if vector[code] else "N" for code in "ISRBPVDX")
        values.append(row["parity"]["external_blocker"].get("blocker_id", ""))
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines) + "\n"


def artifacts_current(metrics_text, report_text, generated_metrics, generated_report):
    return metrics_text == generated_metrics and report_text == generated_report


def mutation_cases(catalog):
    tests = []

    def add(label, mutate):
        tests.append((label, mutate))

    invalid_status = {
        "inventory": "verified",
        "schema": "verified",
        "route": "verified",
        "behavior": "complete",
        "policy": "complete",
        "verification": "verified",
        "discovery": "complete",
        "external_blocker": "verified",
    }
    for dimension in DIMENSIONS:
        add(
            f"cross-dimension invalid status {dimension}",
            lambda value, dimension=dimension: value["capabilities"][0]["parity"][
                dimension
            ].__setitem__("status", invalid_status[dimension]),
        )
    add("duplicate name", lambda value: value["capabilities"].__setitem__(1, copy.deepcopy(value["capabilities"][0])))
    add("171 records", lambda value: value["capabilities"].pop())
    add("173 records", lambda value: value["capabilities"].append(copy.deepcopy(value["capabilities"][-1])))
    add("denominator drift", lambda value: value.__setitem__("denominator", 171))
    add("record source commit", lambda value: value["capabilities"][0].__setitem__("source_commit", "bad"))
    add("schema version drift", lambda value: value.__setitem__("schema_version", 2))
    add("catalog ID drift", lambda value: value.__setitem__("catalog_id", "wrong"))
    add("source commit drift", lambda value: value["source"].__setitem__("commit", "bad"))
    add("legacy metadata identity drift", lambda value: value.__setitem__("legacy_metadata_sha256", "bad"))
    for location, target in (
        ("root", lambda value: value),
        ("capability", lambda value: value["capabilities"][0]),
        ("parity", lambda value: value["capabilities"][0]["parity"]),
        ("dimension", lambda value: value["capabilities"][0]["parity"]["inventory"]),
        ("evidence", lambda value: value["evidence"][0]),
        ("blocker", lambda value: value["blockers"][0]),
    ):
        add(f"unknown {location} key", lambda value, target=target: target(value).__setitem__("extra", 1))
    add("dangling evidence", lambda value: value["capabilities"][0]["parity"]["inventory"]["evidence_ids"].__setitem__(0, "missing"))
    add("duplicate evidence ref", lambda value: value["capabilities"][0]["parity"]["inventory"]["evidence_ids"].append(value["capabilities"][0]["parity"]["inventory"]["evidence_ids"][0]))
    add("duplicate evidence ID", lambda value: value["evidence"].append(copy.deepcopy(value["evidence"][0])))
    add("wrong evidence dimension", lambda value: value["evidence"][0].__setitem__("dimension", "schema"))
    add("orphan evidence", lambda value: value["evidence"].append(dict(value["evidence"][0], id="orphan")))
    add("inventory empty evidence", lambda value: value["capabilities"][0]["parity"]["inventory"].__setitem__("evidence_ids", []))
    add("open blocker no id", lambda value: value["capabilities"][1]["parity"]["external_blocker"].pop("blocker_id"))
    add("none blocker with id", lambda value: value["capabilities"][0]["parity"]["external_blocker"].__setitem__("blocker_id", "B-CASB"))
    add("invalid ledger status", lambda value: value["blockers"][0].__setitem__("status", "bad"))
    add("invalid blocker family", lambda value: value["blockers"][0].__setitem__("family", "radar"))
    add("malformed apps", lambda value: value["capabilities"][0].__setitem__("apps", "bad"))
    add("empty apps", lambda value: value["capabilities"][0].__setitem__("apps", []))
    add("malformed input fields", lambda value: value["capabilities"][0].__setitem__("input_fields", [{"surprise": 1}]))
    add("schema bundle artifact hash drift", lambda value: value["schema_artifacts"].__setitem__("bundle_sha256", "bad"))
    add("schema fixture artifact hash drift", lambda value: value["schema_artifacts"].__setitem__("fixtures_sha256", "bad"))
    add("schema contract hash drift", lambda value: value["capabilities"][0].__setitem__("schema_contract_sha256", "bad"))
    add("schema compact fields drift", lambda value: value["capabilities"][0].__setitem__("input_fields", []))

    def complete_without_evidence(value, dimension, status):
        value["capabilities"][0]["parity"][dimension]["status"] = status
        value["capabilities"][0]["parity"][dimension]["evidence_ids"] = []

    for dimension, status in (
        ("schema", "complete"),
        ("schema", "zero_input_evidenced"),
        ("route", "complete"),
        ("route", "external_blocked"),
        ("behavior", "specified"),
        ("behavior", "verified"),
        ("policy", "classified"),
        ("policy", "verified"),
        ("verification", "hermetic_verified"),
        ("discovery", "generated"),
        ("discovery", "verified"),
    ):
        add(
            f"{dimension} {status} without evidence",
            lambda value, dimension=dimension, status=status: complete_without_evidence(
                value, dimension, status
            ),
        )
    add("resolved blocker without evidence", lambda value: (value["capabilities"][1]["parity"]["external_blocker"].__setitem__("status", "resolved"), value["capabilities"][1]["parity"]["external_blocker"].__setitem__("evidence_ids", [])))

    def completion_with_evidence(value, dimension, status, kind):
        fact = "test evidence"
        provenance = {"kind": "missing", "context_ref": "tests/catalog.rs:1", "fact": fact} if kind == "missing" else {"kind": "hermetic_test", "test_id": "tests/transport.rs::capability_d1_database_get_exact_request", "fact": fact} if kind == "hermetic_verified" else {"kind": "pinned_git", "repo": REPO, "commit": COMMIT, "source_ref": "tests/catalog.rs:1", "blob": None, "span": None, "source_sha256": None}
        item = {"id": f"test-{dimension}", "dimension": dimension, "provenance": provenance, "fact": fact}
        value["evidence"].append(item)
        value["capabilities"][0]["parity"][dimension] = {"status": status, "evidence_ids": [item["id"]]}

    def completion_with_conflicting_missing(value, dimension, status):
        completion_with_evidence(value, dimension, status, "hermetic_verified")
        fact = "test evidence"
        missing = {"id": f"test-{dimension}-missing", "dimension": dimension, "provenance": {"kind": "missing", "context_ref": "tests/catalog.rs:2", "fact": fact}, "fact": fact}
        value["evidence"].append(missing)
        value["capabilities"][0]["parity"][dimension]["evidence_ids"].append(missing["id"])

    add("schema complete with missing evidence", lambda value: completion_with_evidence(value, "schema", "complete", "missing"))
    add("verification complete with missing evidence", lambda value: completion_with_evidence(value, "verification", "hermetic_verified", "missing"))
    add("behavior verified without hermetic evidence", lambda value: completion_with_evidence(value, "behavior", "verified", "source_verified"))
    add("discovery generated with hermetic and missing evidence", lambda value: completion_with_conflicting_missing(value, "discovery", "generated"))
    add("discovery verified with hermetic and missing evidence", lambda value: completion_with_conflicting_missing(value, "discovery", "verified"))
    add("wrong evidence source repo", lambda value: value["evidence"][0]["provenance"].__setitem__("repo", "https://example.com"))
    add("wrong evidence source commit", lambda value: value["evidence"][0]["provenance"].__setitem__("commit", "bad"))
    add("wrong inventory source ref", lambda value: value["evidence"][0]["provenance"].__setitem__("source_ref", "wrong.ts:1"))

    def phase1_schema_evidence(value):
        return next(item for item in value["evidence"] if item["id"] == SCHEMA_EVIDENCE_ID)

    add("wrong Phase 1 schema evidence source repo", lambda value: phase1_schema_evidence(value)["provenance"].__setitem__("repo", "https://example.com"))
    add("wrong Phase 1 schema evidence source commit", lambda value: phase1_schema_evidence(value)["provenance"].__setitem__("commit", "bad"))
    add("wrong Phase 1 schema evidence source ref", lambda value: phase1_schema_evidence(value)["provenance"].__setitem__("source_ref", "capabilities/cloudflare-input-schemas.json"))
    add("wrong Phase 1 schema evidence kind", lambda value: phase1_schema_evidence(value)["provenance"].__setitem__("kind", "official_docs"))


    def rename_phase1_schema_evidence(value):
        phase1_schema_evidence(value)["id"] = "alternate-schema-evidence"
        for row in value["capabilities"]:
            row["parity"]["schema"]["evidence_ids"] = ["alternate-schema-evidence"]

    add("schema rows reference alternate evidence", rename_phase1_schema_evidence)

    def borrowed_d1_completion(value, dimension, status):
        target = next(row for row in value["capabilities"] if row["name"] == "ai_search")
        source = next(row for row in value["capabilities"] if row["name"] == "d1_database_get")
        target["parity"][dimension] = {"status": status, "evidence_ids": list(source["parity"][dimension]["evidence_ids"])}

    for dimension, status in (("route", "complete"), ("behavior", "specified"), ("policy", "classified"), ("verification", "hermetic_verified"), ("discovery", "generated")):
        add(f"uncontracted capability borrowed D1 {dimension}", lambda value, dimension=dimension, status=status: borrowed_d1_completion(value, dimension, status))
    add("none blocker with evidence", lambda value: value["capabilities"][0]["parity"]["external_blocker"]["evidence_ids"].append(value["capabilities"][1]["parity"]["external_blocker"]["evidence_ids"][0]))

    def swap_field(value, field, left, right):
        value["capabilities"][left][field], value["capabilities"][right][field] = value["capabilities"][right][field], value["capabilities"][left][field]

    read_index = next(index for index, row in enumerate(catalog["capabilities"]) if row["name"] == "d1_database_get")
    write_index = next(index for index, row in enumerate(catalog["capabilities"]) if row["name"] == "d1_database_delete")
    add("swap operation metadata", lambda value: swap_field(value, "operation", read_index, write_index))
    add("route external blocked with missing evidence", lambda value: completion_with_evidence(value, "route", "external_blocked", "missing"))
    add("route external blocked with hermetic-only evidence", lambda value: completion_with_evidence(value, "route", "external_blocked", "hermetic_verified"))
    return tests


def self_test(catalog):
    rejected = []
    cases = mutation_cases(catalog)
    for label, mutate in cases:
        changed = copy.deepcopy(catalog)
        mutate(changed)
        try:
            validate(changed)
        except (GovernanceError, KeyError, TypeError, json.JSONDecodeError):
            rejected.append(label)
        else:
            fail("self-test", f"mutation accepted: {label}")

    def swap_operation_evidence(value, dimension):
        left = next(row for row in value["capabilities"] if row["name"] == "d1_database_get")
        right = next(row for row in value["capabilities"] if row["name"] == "d1_database_delete")
        left["parity"][dimension]["evidence_ids"], right["parity"][dimension]["evidence_ids"] = right["parity"][dimension]["evidence_ids"], left["parity"][dimension]["evidence_ids"]

    for dimension in ("route", "behavior", "policy", "verification", "discovery"):
        changed = copy.deepcopy(catalog)
        swap_operation_evidence(changed, dimension)
        try:
            validate(changed)
        except (GovernanceError, KeyError, TypeError, json.JSONDecodeError):
            rejected.append(f"cross-capability {dimension} evidence swap")
        else:
            fail("self-test", f"mutation accepted: cross-capability {dimension} evidence swap")
    operation_mutations = []
    operations = json.loads(OPERATION_FILE.read_text())
    for index, contract in enumerate(operations["contracts"]):
        operation_mutations.extend(
            (
                (f"{contract['capability']} semantic mutation", index, "semantic"),
                (f"{contract['capability']} unknown-field mutation", index, "unknown"),
                (f"{contract['capability']} official fact_sha mutation", index, "fact_sha"),
            )
        )
    evidence = {item["id"]: item for item in catalog["evidence"]}
    for label, index, kind in operation_mutations:
        changed = copy.deepcopy(operations)
        contract = changed["contracts"][index]
        if kind == "semantic":
            contract["behavior"]["output_projection"] += "_mutated"
        elif kind == "unknown":
            contract["route"]["extra"] = True
        else:
            docs = contract["evidence"].get("official_docs")
            if docs:
                docs["fact_sha256"] = ("0" if docs["fact_sha256"][0] != "0" else "1") + docs["fact_sha256"][1:]
            else:
                contract["evidence"]["pinned_handler"]["source_sha256"] = "0" + contract["evidence"]["pinned_handler"]["source_sha256"][1:]
        contract["contract_sha256"] = json_sha256({**contract, "contract_sha256": None})
        changed["bundle_sha256"] = json_sha256({**changed, "bundle_sha256": None})
        try:
            validate_operation_contracts(catalog, changed, catalog["capabilities"], evidence)
        except (GovernanceError, KeyError, TypeError):
            rejected.append(label)
        else:
            fail("self-test", f"mutation accepted: {label}")

    baseline = metric_vector(catalog["capabilities"])
    legacy_changes = (
        ("implementation", {"status": "verified"}),
        ("description", "changed free text"),
        ("method", "DELETE"),
        ("path_template", "/invented"),
        ("transport", "graphql"),
        ("cli_access", "blocked"),
        ("blocker", "changed free text"),
    )
    for field, value in legacy_changes:
        rows = copy.deepcopy(catalog["capabilities"])
        rows[0][field] = value
        if metric_vector(rows) != baseline:
            fail("self-test", f"metrics inferred completion from {field}")
    route_only = copy.deepcopy(catalog["capabilities"])
    route_only[0]["parity"]["route"]["status"] = "external_blocked"
    if metric_vector(route_only)["X"] != baseline["X"] + 1:
        fail("self-test", "X omitted route-only blocker")
    route_only[0]["parity"]["external_blocker"]["status"] = "open"
    if metric_vector(route_only)["X"] != baseline["X"] + 1:
        fail("self-test", "X double-counted blocker union")
    generated_metrics = json.dumps(metrics(catalog), indent=2) + "\n"
    generated_report = report(catalog, metrics(catalog))
    if artifacts_current(
        generated_metrics + "stale",
        generated_report,
        generated_metrics,
        generated_report,
    ) or artifacts_current(
        generated_metrics,
        generated_report + "stale",
        generated_metrics,
        generated_report,
    ):
        fail("self-test", "stale artifacts accepted")
    return {
        "self_test": "ok",
        "rejected_count": len(rejected),
        "rejected": rejected,
        "metric_invariance": len(legacy_changes),
        "x_union": "ok",
        "stale_checks": "ok",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=["validate", "metrics", "report", "generate", "check", "self-test", "sync-schemas"],
    )
    args = parser.parse_args()
    catalog = json.loads(CATALOG.read_text())
    if args.command == "sync-schemas":
        apply_schema_bundle(catalog)
        CATALOG.write_text(json.dumps(catalog, indent=2) + "\n")
        print("catalog schema sync: ok")
        return
    validate(catalog)
    if args.command == "self-test":
        print(json.dumps(self_test(catalog), sort_keys=True))
        return
    metric = metrics(catalog)
    generated_metrics = json.dumps(metric, indent=2) + "\n"
    generated_report = report(catalog, metric)
    if args.command == "generate":
        METRICS.write_text(generated_metrics)
        REPORT.write_text(generated_report)
    elif args.command == "metrics":
        print(generated_metrics, end="")
    elif args.command == "report":
        print(generated_report, end="")
    elif args.command == "check" and not artifacts_current(
        METRICS.read_text(),
        REPORT.read_text(),
        generated_metrics,
        generated_report,
    ):
        fail("check", "generated artifact drift")
    if args.command not in {"metrics", "report"}:
        print("catalog governance: ok")


if __name__ == "__main__":
    try:
        main()
    except (GovernanceError, json.JSONDecodeError, KeyError, TypeError) as error:
        print(f"catalog governance: invalid ({error})", file=sys.stderr)
        raise SystemExit(1) from error
