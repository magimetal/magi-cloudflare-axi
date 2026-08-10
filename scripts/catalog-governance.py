#!/usr/bin/env python3
"""Deterministic Phase 0 catalog validation, metrics, reports, and tests."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).parents[1]
CATALOG = ROOT / "capabilities/cloudflare-mcp-parity.json"
METRICS = ROOT / "docs/cloudflare-capability-parity-metrics.json"
REPORT = ROOT / "docs/cloudflare-capability-parity.md"
COMMIT = "70ff690553722f731849ede6ba9ce98958395a23"
REPO = "https://github.com/cloudflare/mcp-server-cloudflare"
LEGACY_METADATA_SHA256 = "3645e8c99babc36a7af479ce2be8c423fb64acebcf5f8df768cb9bdbf41a7171"
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
LEGACY_ENUMS = {
    "scope": {"public", "account", "zone", "custom"},
    "operation": {"read", "write"},
    "transport": {
        "rest",
        "graphql",
        "public_http",
        "internal_binding",
        "custom_container",
    },
    "cli_access": {
        "modeled",
        "raw_rest",
        "raw_graphql",
        "public_direct",
        "blocked",
        "mcp_remote",
    },
}
FAMILIES = {
    "ai-gateway": 5,
    "auditlogs": 1,
    "autorag": 3,
    "browser-rendering": 13,
    "cloudflare-blog": 4,
    "cloudflare-one-casb": 11,
    "demo-day": 1,
    "dex-analysis": 18,
    "dns-analytics": 3,
    "graphql": 6,
    "logpush": 1,
    "radar": 66,
    "sandbox-container": 7,
    "shared": 7,
    "stack-mcp": 2,
    "workers-bindings": 18,
    "workers-builds": 3,
    "workers-observability": 3,
}
TRANSPORTS = {
    "public_http": 86,
    "rest": 71,
    "custom_container": 7,
    "graphql": 6,
    "internal_binding": 2,
}
ACCESS = {
    "raw_rest": 133,
    "mcp_remote": 26,
    "public_direct": 6,
    "raw_graphql": 6,
    "blocked": 1,
}
OPERATIONS = {"read": 150, "write": 22}
BLOCKER_FAMILY = {
    "dex-analysis": "B-DEX",
    "cloudflare-one-casb": "B-CASB",
    "sandbox-container": "B-CONTAINER",
    "workers-observability": "B-OBS",
    "shared": "B-SHARED",
    "stack-mcp": "B-STACK",
}
EVIDENCE_KINDS = {
    "missing",
    "source_verified",
    "official_verified",
    "hermetic_verified",
}
RECORD_KEYS = {
    "name",
    "family",
    "apps",
    "source",
    "source_ref",
    "source_commit",
    "description",
    "input_fields",
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


def legacy_digest(records):
    payload = [
        {key: value for key, value in record.items() if key not in {"source_ref", "parity"}}
        for record in records
    ]
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_evidence_kind(dimension, status, items, path):
    kinds = {item["kind"] for item in items}
    authoritative = {"source_verified", "official_verified"}
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
        if "hermetic_verified" not in kinds or not kinds.intersection(authoritative):
            fail(path, "verified contract requires authoritative and hermetic evidence")
    if dimension == "verification" and status == "hermetic_verified":
        if "hermetic_verified" not in kinds:
            fail(path, "hermetic verification requires hermetic evidence")
    if dimension == "discovery" and status in {"generated", "verified"}:
        if "missing" in kinds or "hermetic_verified" not in kinds:
            fail(path, "discovery status requires non-missing hermetic generation evidence")
    if dimension == "external_blocker" and status == "resolved":
        if not kinds or "missing" in kinds:
            fail(path, "resolved blocker requires non-missing resolution evidence")


def validate(catalog):
    root_keys = {
        "schema_version",
        "catalog_id",
        "source",
        "denominator",
        "legacy_metadata_sha256",
        "evidence",
        "blockers",
        "capabilities",
    }
    require_keys(catalog, root_keys, set(), "$")
    if catalog["schema_version"] != 1 or catalog["catalog_id"] != "cloudflare-mcp-parity":
        fail("$", "invalid schema envelope")
    require_keys(catalog["source"], {"repo", "commit", "ref"}, set(), "$.source")
    expected_source = {"repo": REPO, "commit": COMMIT, "ref": "pinned-source"}
    if catalog["source"] != expected_source:
        fail("$.source", "pinned source mismatch")
    rows = catalog["capabilities"]
    if catalog["denominator"] != 172 or not isinstance(rows, list) or len(rows) != 172:
        fail("$.capabilities", "expected denominator and record count 172")
    if any(not isinstance(row, dict) for row in rows):
        fail("$.capabilities", "capability objects required")
    names = [row.get("name") for row in rows]
    if any(not isinstance(name, str) or not name for name in names):
        fail("$.capabilities", "nonempty names required")
    if names != sorted(names) or len(set(names)) != 172:
        fail("$.capabilities", "names must be sorted and unique")
    if (
        catalog["legacy_metadata_sha256"] != LEGACY_METADATA_SHA256
        or legacy_digest(rows) != LEGACY_METADATA_SHA256
    ):
        fail("$.legacy_metadata_sha256", "per-capability legacy metadata drift")

    if not isinstance(catalog["evidence"], list):
        fail("$.evidence", "array required")
    evidence = {}
    for index, item in enumerate(catalog["evidence"]):
        path = f"$.evidence[{index}]"
        fields = {
            "id",
            "dimension",
            "kind",
            "source_repo",
            "source_commit",
            "source_ref",
            "fact",
        }
        require_keys(item, fields, set(), path)
        for field in ("id", "source_repo", "source_commit", "source_ref", "fact"):
            require_text(item[field], f"{path}.{field}")
        if (
            item["id"] in evidence
            or item["dimension"] not in DIMENSIONS
            or item["kind"] not in EVIDENCE_KINDS
            or item["source_repo"] != REPO
            or item["source_commit"] != COMMIT
        ):
            fail(path, "invalid or duplicate evidence")
        evidence[item["id"]] = item

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
            require_keys(field, {"name", "type", "required"}, {"default"}, field_path)
            require_text(field["name"], f"{field_path}.name")
            require_text(field["type"], f"{field_path}.type")
            if not isinstance(field["required"], bool):
                fail(f"{field_path}.required", "boolean required")
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
                if item["kind"] != "source_verified" or item["source_ref"] != row["source"]:
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
    if sum("path_template" in row for row in rows) != 6:
        fail("$.capabilities", "path baseline mismatch")
    if sum("blocker" in row for row in rows) != 41:
        fail("$.capabilities", "legacy blocker baseline mismatch")


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
        "schema_version": 1,
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
    add("wrong root source commit", lambda value: value["source"].__setitem__("commit", "bad"))
    add("record source commit", lambda value: value["capabilities"][0].__setitem__("source_commit", "bad"))
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
    add("affected-name mismatch", lambda value: value["blockers"][0]["affected_names"].pop())
    add("orphan blocker", lambda value: value["blockers"].append({"id":"B-ORPHAN","status":"open","family":"shared","summary":"orphan","affected_names":["ai_search"]}))
    add("invalid blocker family", lambda value: value["blockers"][0].__setitem__("family", "radar"))
    add("malformed apps", lambda value: value["capabilities"][0].__setitem__("apps", "bad"))
    add("empty apps", lambda value: value["capabilities"][0].__setitem__("apps", []))
    add("malformed input fields", lambda value: value["capabilities"][0].__setitem__("input_fields", [{"surprise": 1}]))

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
        item = {
            "id": f"test-{dimension}",
            "dimension": dimension,
            "kind": kind,
            "source_repo": REPO,
            "source_commit": COMMIT,
            "source_ref": value["capabilities"][0]["source"],
            "fact": "test evidence",
        }
        value["evidence"].append(item)
        value["capabilities"][0]["parity"][dimension] = {
            "status": status,
            "evidence_ids": [item["id"]],
        }

    def completion_with_conflicting_missing(value, dimension, status):
        completion_with_evidence(value, dimension, status, "hermetic_verified")
        missing = dict(
            value["evidence"][-1],
            id=f"test-{dimension}-missing",
            kind="missing",
        )
        value["evidence"].append(missing)
        value["capabilities"][0]["parity"][dimension]["evidence_ids"].append(
            missing["id"]
        )

    add("schema complete with missing evidence", lambda value: completion_with_evidence(value, "schema", "complete", "missing"))
    add("verification complete with missing evidence", lambda value: completion_with_evidence(value, "verification", "hermetic_verified", "missing"))
    add("behavior verified without hermetic evidence", lambda value: completion_with_evidence(value, "behavior", "verified", "source_verified"))
    add("discovery generated with hermetic and missing evidence", lambda value: completion_with_conflicting_missing(value, "discovery", "generated"))
    add("discovery verified with hermetic and missing evidence", lambda value: completion_with_conflicting_missing(value, "discovery", "verified"))
    add("wrong evidence source repo", lambda value: value["evidence"][0].__setitem__("source_repo", "https://example.com"))
    add("wrong evidence source commit", lambda value: value["evidence"][0].__setitem__("source_commit", "bad"))
    add("wrong inventory source ref", lambda value: value["evidence"][0].__setitem__("source_ref", "wrong.ts:1"))
    add("none blocker with evidence", lambda value: value["capabilities"][0]["parity"]["external_blocker"]["evidence_ids"].append(value["capabilities"][1]["parity"]["external_blocker"]["evidence_ids"][0]))

    def swap_field(value, field, left, right):
        value["capabilities"][left][field], value["capabilities"][right][field] = (
            value["capabilities"][right][field],
            value["capabilities"][left][field],
        )

    read_index = next(index for index, row in enumerate(catalog["capabilities"]) if row["operation"] == "read")
    write_index = next(index for index, row in enumerate(catalog["capabilities"]) if row["operation"] == "write")
    rest_index = next(index for index, row in enumerate(catalog["capabilities"]) if row["transport"] == "rest")
    public_index = next(index for index, row in enumerate(catalog["capabilities"]) if row["transport"] == "public_http")
    raw_index = next(index for index, row in enumerate(catalog["capabilities"]) if row["cli_access"] == "raw_rest")
    remote_index = next(index for index, row in enumerate(catalog["capabilities"]) if row["cli_access"] == "mcp_remote")
    add("swap operation metadata", lambda value: swap_field(value, "operation", read_index, write_index))
    add("route external blocked with missing evidence", lambda value: completion_with_evidence(value, "route", "external_blocked", "missing"))
    add("route external blocked with hermetic-only evidence", lambda value: completion_with_evidence(value, "route", "external_blocked", "hermetic_verified"))
    add("swap transport metadata", lambda value: swap_field(value, "transport", rest_index, public_index))
    add("swap access metadata", lambda value: swap_field(value, "cli_access", raw_index, remote_index))
    add("per-name description drift", lambda value: value["capabilities"][0].__setitem__("description", "changed"))
    return tests


def self_test(catalog):
    rejected = []
    cases = mutation_cases(catalog)
    for label, mutate in cases:
        changed = copy.deepcopy(catalog)
        mutate(changed)
        try:
            validate(changed)
        except (GovernanceError, KeyError, TypeError):
            rejected.append(label)
    if len(rejected) != len(cases):
        fail("self-test", f"mutation suite rejected {len(rejected)}/{len(cases)}")

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
        choices=["validate", "metrics", "report", "generate", "check", "self-test"],
    )
    args = parser.parse_args()
    catalog = json.loads(CATALOG.read_text())
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
