"""Source-test consumption ledger; importing or iterating a fixture is not a claim."""

import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def case_label(value, index):
    return str(value.get("id", value.get("name", index))) if isinstance(value, dict) else str(index)


class Consumption:
    def __init__(self, root=ROOT, runtime="python"):
        self.root = Path(root)
        self.runtime = runtime
        self.spec = json.loads((self.root / "conformance/consumption-v1.json").read_text())
        self.manifest = json.loads((self.root / "conformance/vectors/manifest.json").read_text())
        self.values = {name: json.loads((self.root / "conformance/vectors" / name).read_text())
                       for name in self.manifest["files"]}
        self.expected = set()
        self.claimed = set()
        self.metadata = set()
        if self.spec["schema_version"] != 1 or set(self.spec["files"]) != set(self.values):
            raise AssertionError("consumption file inventory mismatch")
        for name, value in self.values.items():
            spec = self.spec["files"][name]
            if set(spec["fields"]) != set(value):
                raise AssertionError(f"consumption field inventory mismatch: {name}")
            if not spec["runtimes"] or not set(spec["runtimes"]) <= {"python", "typescript"}:
                raise AssertionError(f"invalid applicability: {name}")
            applicable = runtime in spec["runtimes"]
            if not applicable and not spec.get("inapplicable_reason"):
                raise AssertionError(f"missing applicability reason: {name}")
            registry = []
            for field, data in value.items():
                registry.append(field)
                if isinstance(data, list):
                    registry.extend(f"{field}/{case_label(row, i)}" for i, row in enumerate(data))
                elif isinstance(data, dict):
                    registry.extend(f"{field}/{key}" for key in data)
                rule = spec["fields"][field]
                mode = rule["mode"]
                if mode == "metadata":
                    if rule["expected"] != data:
                        raise AssertionError(f"metadata mismatch: {name}:{field}")
                    self.metadata.add((name, field))
                elif mode == "cases":
                    if not isinstance(data, (list, dict)) or not data:
                        raise AssertionError(f"invalid case group: {name}:{field}")
                    if applicable:
                        keys = data if isinstance(data, dict) else [case_label(row, i) for i, row in enumerate(data)]
                        self.expected.update((name, f"{field}/{key}") for key in keys)
                elif mode == "value":
                    if applicable:
                        self.expected.add((name, field))
                else:
                    raise AssertionError(f"unknown consumption mode: {mode}")
            if len(registry) != len(set(registry)) or registry != self.manifest["files"][name]["cases"]:
                raise AssertionError(f"manifest case registry mismatch: {name}")

        for name in self.spec["contracts"]["wrapper_pairs"]:
            self.expected.add(("@contracts", "wrapper_pairs/" + name))
        for group, contracts in self.spec["contracts"].items():
            if group == "wrapper_pairs":
                continue
            for references in contracts.values():
                for name, reference in references:
                    if name == "@contracts":
                        self.expected.add(("@contracts", reference))

    def contract(self, group, name):
        self.claim("@contracts", f"{group}/{name}")

    def claim(self, name, ref):
        item = (name, ref)
        if item not in self.expected:
            raise AssertionError(f"unknown or inapplicable claim: {name}:{ref}")
        self.claimed.add(item)

    def case(self, name, field, row):
        """Claim one asserted list item (or a dictionary key), never its siblings."""
        data = self.values[name][field]
        if isinstance(data, dict):
            self.claim(name, f"{field}/{row}")
            return
        if isinstance(row, dict) and ("id" in row or "name" in row):
            key = str(row.get("id", row.get("name")))
            matches = [i for i, candidate in enumerate(data) if case_label(candidate, i) == key]
        else:
            matches = [i for i, candidate in enumerate(data) if candidate == row]
        if len(matches) != 1 or data[matches[0]] != row:
            raise AssertionError(f"ambiguous or foreign case: {name}:{field}")
        self.claim(name, f"{field}/{case_label(row, matches[0])}")

    def value(self, name, *fields):
        """Claim atomic inputs/goldens after the owning test has asserted its result."""
        for field in fields:
            self.claim(name, field)

    def equal(self, name, field, actual):
        """Whole-group equality may claim every child because every value is compared."""
        expected = self.values[name][field]
        if actual != expected:
            raise AssertionError(f"whole-group equality failed: {name}:{field}")
        if self.spec["files"][name]["fields"][field]["mode"] == "value":
            self.value(name, field)
        else:
            for key in expected if isinstance(expected, dict) else expected:
                self.case(name, field, key)

    def assert_complete(self):
        missing = sorted(self.expected - self.claimed)
        if missing:
            raise AssertionError("unconsumed applicable corpus cases:\n" + "\n".join(f"{n}:{r}" for n, r in missing))
        receipt = {"runtime": self.runtime,
                   "spec_sha256": hashlib.sha256((self.root / "conformance/consumption-v1.json").read_bytes()).hexdigest(),
                   "manifest_sha256": hashlib.sha256((self.root / "conformance/vectors/manifest.json").read_bytes()).hexdigest(), "semantic_claims": sorted([list(v) for v in self.claimed]),
                   "integrity_metadata": sorted([list(v) for v in self.metadata])}
        if self.root == ROOT and (path := os.environ.get("DRACLA_CONFORMANCE_RECEIPT")):
            Path(path).write_text(json.dumps(receipt, indent=2) + "\n")
        return receipt


CLAIMS = Consumption()
