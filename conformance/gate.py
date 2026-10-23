"""Run the complete source-only M1 conformance gate (no deployment side effects)."""

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def contract_inventory(root=ROOT):
    """Join normative inventories to asserted case references, never counts alone."""
    root = Path(root)
    spec = json.loads((root / "conformance/consumption-v1.json").read_text())
    vectors = root / "conformance/vectors"
    load = lambda name: json.loads((vectors / name).read_text())
    contracts = spec["contracts"]
    for name, rule in spec["files"].items():
        expected = ["python"] if name == "replay-v1.json" else ["python", "typescript"]
        if rule["runtimes"] != expected:
            raise AssertionError(f"unapproved runtime applicability: {name}")
    hld = (root / "design/high-level-design.md").read_text()
    table = hld.split("| Repository branch and path `P` |", 1)[1].split("\n\n", 1)[0]
    rows = [line for line in table.splitlines() if line.startswith("| records ") or line.startswith("| coverage ")]
    fixtures = load("artifact-identities-v1.json")["identities"]
    identities = {}
    for line in rows:
        cells = [c.strip() for c in line.split("|")[1:-1]]
        location = re.fullmatch(r"(records|coverage) `([^`]+)`: `([^`]+)`", cells[0])
        if not location:
            raise AssertionError("unknown identity table syntax")
        repository, branch, template = location.groups()
        pattern = re.escape(template)
        for token, expression in {"aa": r"[A-Za-z0-9_-]{2}", "bb": r"[A-Za-z0-9_-]{2}",
                                  "event_id": r"[A-Za-z0-9_-]{43}", "request_id": r"[A-Za-z0-9_-]{22}",
                                  "shard": r"(?:[0-2][0-9]|3[01])"}.items():
            pattern = pattern.replace(re.escape("<" + token + ">"), expression)
        kind, capability, version = cells[1].strip("`"), cells[2], int(cells[3])
        matches = [i for i, row in enumerate(fixtures) if row[0:2] == [repository, branch]
                   and re.fullmatch(pattern, row[2]) and row[3:] == [kind, capability]]
        if len(matches) != 1 or version != 1 or kind in identities:
            raise AssertionError(f"unrepresented identity row: {line}")
        identities[kind] = [["artifact-identities-v1.json", f"identities/{matches[0]}"]]
    if identities != contracts["identity_rows"] or len(fixtures) != len(identities):
        raise AssertionError("identity contract inventory mismatch")
    form_table = hld.split("| Table 5.4-A form `type` |", 1)[1].split("\n\n", 1)[0]
    form_rows = {}
    for line in form_table.splitlines():
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) != 3 or not cells[0].startswith("`"):
            continue
        action = cells[0].strip("`")
        writes, terminals = re.findall(r"`([^`]+)`", cells[1]), re.findall(r"`([^`]+)`", cells[2])
        # desired_scope is a constraint in the terminal column, not an event type.
        terminals = [name for name in terminals if name not in {"desired_scope", "null"}]
        form_rows[action] = (writes[0], terminals)
    actions = load("action-form-v1.json")["actions"]
    actual = {row["type"]: (row["write_type"], row["terminal_types"]) for row in actions}
    if actual != form_rows or set(contracts["form_rows"]) != set(actual):
        raise AssertionError("Table 5.4-A contract inventory mismatch")
    event_types = {row["type"] for row in load("events-v1.json")["events"]}
    if set(contracts["event_types"]) != event_types or set(load("event-identities-v1.json")["event_types_v1"]) != event_types:
        raise AssertionError("event type contract inventory mismatch")
    wrappers = {f"{capability}:{wrapper}" for capability, names in {
        "records": ("portal-records", "control", "recovery"),
        "coverage": ("portal-coverage", "enforcer-coverage", "control", "recovery"),
    }.items() for wrapper in names}
    if set(contracts["wrapper_pairs"]) != wrappers:
        raise AssertionError("wrapper pair contract inventory mismatch")
    expected_schemas = {"coverage-source", "active-agreement", "exemption-fold", "coverage-shard",
        "derived-index", "status-detail", "reader-authority", "derived-state", "decision-fence", "inflight",
        "prepared-operation", "artifact-envelope", "wrapped-key-copy", "keyring", "action-form",
        "project-configuration", "materialization-generations", "canonical-event", "agreement-metadata",
        "release-profile"}
    if set(contracts["closed_schemas"]) != expected_schemas:
        raise AssertionError("closed schema contract inventory mismatch")
    return contracts


def verify_receipts(receipts, root=ROOT):
    # Each runtime also enforces completeness in its unchanged required command.
    sys.path.insert(0, str(root))
    from core.tests.corpus_consumption import Consumption
    contracts = contract_inventory(root)
    if {r["runtime"] for r in receipts} != {"python", "typescript"} or len(receipts) != 2:
        raise AssertionError("both independent runtime receipts required")
    for receipt in receipts:
        for key, path in (("spec_sha256", "conformance/consumption-v1.json"),
                          ("manifest_sha256", "conformance/vectors/manifest.json")):
            if receipt[key] != hashlib.sha256((Path(root) / path).read_bytes()).hexdigest():
                raise AssertionError("stale runtime consumption receipt")
        claims = {tuple(v) for v in receipt["semantic_claims"]}
        expected = Consumption(root, receipt["runtime"]).expected
        if claims != expected or len(claims) != len(receipt["semantic_claims"]):
            raise AssertionError("incomplete or foreign runtime consumption receipt")
        for group in contracts.values():
            for name, references in group.items():
                if not references or not all(tuple(ref) in claims for ref in references):
                    raise AssertionError(f"unclaimed contract: {receipt['runtime']}:{name}")
    return {r["runtime"]: len(r["semantic_claims"]) for r in receipts}


def packaging_smoke(python, temporary, run):
    dist = temporary / "dist"
    run([python, "-m", "hatchling", "build", "-t", "wheel", "-d", str(dist)])
    wheels = list(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise AssertionError("exactly one wheel required")
    target = temporary / "installed"
    run([python, "-m", "pip", "install", "--no-deps", "--no-index", "--target", str(target), str(wheels[0])])
    public = [alias.asname or alias.name for node in ast.parse((ROOT / "core/dracla/conformance/__init__.py").read_text()).body
              if isinstance(node, ast.ImportFrom) for alias in node.names]
    code = '''import importlib,json,pathlib,sys,zipfile
installed,wheel,names,source=sys.argv[1:]
source_paths={pathlib.Path(source).resolve(),(pathlib.Path(source)/"core").resolve()}
sys.path[:]=[p for p in sys.path if not p or pathlib.Path(p).resolve() not in source_paths]
sys.path.insert(0,installed)
c=importlib.import_module("dracla.conformance")
assert pathlib.Path(c.__file__).is_relative_to(pathlib.Path(installed))
assert not any(pathlib.Path(p).resolve()==pathlib.Path(source).resolve() for p in sys.path if p)
assert all(hasattr(c,name) for name in json.loads(names))
assert c.canonical_json({"a":1})==b'{"a":1}'
with zipfile.ZipFile(wheel) as z:
 assert not any(n.startswith(("conformance/", "core/tests/")) or "/vectors/" in n for n in z.namelist())
v=importlib.import_module("dracla.conformance.vectors")
try:v.generate()
except ValueError as e:assert "source checkout" in str(e)
else:raise AssertionError("shared corpus must remain source-only")
print("installed conformance public surface:",len(json.loads(names)))
'''
    run([python, "-I", "-c", code, str(target), str(wheels[0]), json.dumps(public), str(ROOT)], cwd=temporary)


def main():
    python = str(ROOT / ".venv/bin/python")
    with tempfile.TemporaryDirectory(prefix="dracla-m1-gate-") as directory:
        temporary = Path(directory)
        def run(argv, *, cwd=ROOT, env=None):
            print("RUN", " ".join(argv[:5]), flush=True)
            subprocess.run(argv, cwd=cwd, env=env, check=True)
        paths = {runtime: temporary / (runtime + ".json") for runtime in ("python", "typescript")}
        run([python, "-m", "unittest", "discover", "-s", "core/tests", "-t", ".", "-v"],
            env={**os.environ, "DRACLA_CONFORMANCE_RECEIPT": str(paths["python"])})
        run([python, "-m", "dracla.conformance.vectors", "--check"])
        run(["npm", "--prefix", "api", "run", "typecheck"])
        run(["npm", "--prefix", "api", "run", "test:conformance"],
            env={**os.environ, "DRACLA_CONFORMANCE_RECEIPT": str(paths["typescript"])})
        counts = verify_receipts([json.loads(path.read_text()) for path in paths.values()])
        packaging_smoke(python, temporary, run)
        print("PASS M1 gate", json.dumps(counts), flush=True)


if __name__ == "__main__":
    main()
