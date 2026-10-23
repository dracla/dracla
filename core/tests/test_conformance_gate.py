"""Fail-closed consumption and normative contract/traceability coverage."""

import ast
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest

from core.tests.corpus_consumption import Consumption, ROOT
from conformance.gate import contract_inventory


_MATRIX_PATH = re.compile(
    r"(?P<path>(?:core/tests|api/test|core/dracla|conformance|design|dracla/conformance)/"
    r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.(?:py|mjs|json|md))"
)
_INLINE_CODE = re.compile(r"`([^`]+)`")
_LOCAL_LINK = re.compile(r"\]\((?!https?://)([^)#]+)")


def _local_path(root, path):
    if path.startswith("dracla/"):
        path = "core/" + path
    return root / path


def _python_symbols(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    classes = {}
    functions = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.add(node.name)
        elif isinstance(node, ast.ClassDef):
            classes[node.name] = {
                child.name for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
    return classes, functions


def _typescript_titles(path):
    return {
        match.group(2)
        for match in re.finditer(
            r"(?m)^\s*(?:test|it)\s*\(\s*(['\"])(.*?)\1", path.read_text()
        )
    }


def _resolve_python(root, path, selector, context):
    classes, functions = _python_symbols(_local_path(root, path))
    if selector is None:
        return (path, None)
    parts = selector.split("::")
    if len(parts) == 1:
        if parts[0] in classes:
            return (path, parts[0])
        if parts[0] in functions:
            return (path, None)
        owners = [name for name, methods in classes.items() if parts[0] in methods]
        if len(owners) == 1:
            return (path, owners[0])
        if context and context[0] == path and parts[0] in classes.get(context[1], set()):
            return context
    elif len(parts) == 2 and parts[0] in classes and parts[1] in classes[parts[0]]:
        return (path, parts[0])
    raise AssertionError(f"unresolved Python evidence: {path}::{selector}")


def _resolve_typescript(root, path, selector):
    if selector is not None and selector not in _typescript_titles(_local_path(root, path)):
        raise AssertionError(f"unresolved TypeScript evidence: {path}::{selector}")


def _resolve_json(root, path, selector):
    if selector is not None and selector not in json.loads(_local_path(root, path).read_text()):
        raise AssertionError(f"unresolved JSON evidence: {path}::{selector}")


def _is_automated_reference(path, selector):
    if path.startswith(("core/tests/test_", "api/test/")):
        return True
    return path == "conformance/gate.py" and selector in {
        "contract_inventory", "verify_receipts", "packaging_smoke"
    }


def _resolve_command(root, token, paths):
    """Validate only the repository's documented command forms."""
    if token.startswith("cd api && npm run "):
        scripts = json.loads((root / "api/package.json").read_text())["scripts"]
        names = re.findall(r"npm run ([A-Za-z0-9:_-]+)", token)
        if not names or any(name not in scripts for name in names):
            raise AssertionError(f"unknown npm evidence script: {token}")
        return True
    if ".venv/bin/python" not in token:
        return False
    if not (root / ".venv/bin/python").exists():
        raise AssertionError("missing .venv/bin/python for evidence command")
    if token.startswith(".venv/bin/python conformance/gate.py"):
        return True
    if token.startswith(".venv/bin/python -m dracla.conformance.vectors --check"):
        if not (root / "core/dracla/conformance/vectors.py").is_file():
            raise AssertionError("missing vector generator for evidence command")
        return True
    if "-m unittest " in token:
        if " discover " in token:
            match = re.search(r"-s (core/tests)\b", token)
            if not match or not (root / match.group(1)).is_dir():
                raise AssertionError(f"unresolved unittest discovery suite: {token}")
        elif not paths:
            raise AssertionError(f"unresolved unittest suite: {token}")
        return True
    if "-m json.tool " in token:
        if not any(path.endswith(".json") for path, _ in paths):
            raise AssertionError(f"unresolved JSON evidence command: {token}")
        return True
    if "-m py_compile " in token:
        if not any(path.endswith(".py") for path, _ in paths):
            raise AssertionError(f"unresolved Python syntax suite: {token}")
        return True
    if "-m pytest " in token:
        if "core/tests" not in token or not (root / "core/tests").is_dir():
            raise AssertionError(f"unresolved pytest suite: {token}")
        return True
    if "-m coverage " in token:
        if "-m coverage report" in token:
            return False
        if "-m unittest " not in token or not paths:
            raise AssertionError(f"unresolved coverage test suite: {token}")
        source_match = re.search(r"--source=([A-Za-z0-9_.]+)", token)
        source = source_match.group(1) if source_match else None
        if source:
            source_path = root / "core" / Path(*source.split("."))
            source_path = source_path.with_suffix(".py")
            if not source_path.is_file():
                raise AssertionError(f"unresolved coverage source: {source}")
        return True
    raise AssertionError(f"unknown Python evidence command: {token}")


def _validate_matrix(text, root, *, require_all_slices=True):
    rows = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.startswith("| M1-"):
            continue
        cells = [cell.strip() for cell in line.split("|")[1:-1]]
        if len(cells) < 4:
            raise AssertionError(f"malformed matrix row {line_number}")
        rows.append((line_number, cells))
    if require_all_slices:
        slices = {cells[0].split()[0] for _, cells in rows}
        expected = {f"M1-{index}" for index in range(1, 20)}
        if slices != expected:
            raise AssertionError(f"matrix slices do not cover M1-1 through M1-19: {slices}")

    contexts = {"python": None, "typescript": None}
    for line_number, cells in rows:
        slice_name, requirement, evidence = cells[:3]
        if not requirement or not evidence:
            raise AssertionError(f"missing matrix evidence for {slice_name} row {line_number}")
        automated = False
        row_continuation = None
        for token in _INLINE_CODE.findall(evidence):
            references = []
            for match in _MATRIX_PATH.finditer(token):
                path = match.group("path")
                if not _local_path(root, path).is_file():
                    raise AssertionError(f"unresolved evidence file at row {line_number}: {path}")
                suffix = token[match.end():]
                selector = suffix[2:] if suffix.startswith("::") else None
                references.append((path, selector))
                if path.endswith(".py"):
                    context = contexts["python"]
                    if selector is not None and selector.startswith("..."):
                        raise AssertionError(f"malformed Python evidence at row {line_number}: {token}")
                    contexts["python"] = _resolve_python(root, path, selector, context)
                    row_continuation = ("python", path, contexts["python"])
                    automated |= _is_automated_reference(path, selector)
                elif path.endswith(".mjs"):
                    _resolve_typescript(root, path, selector)
                    contexts["typescript"] = path
                    row_continuation = ("typescript", path, path)
                    automated |= _is_automated_reference(path, selector)
                elif path.endswith(".json"):
                    _resolve_json(root, path, selector)
                    row_continuation = ("json", path, selector)
            if token.startswith("...::"):
                selector = token[5:]
                continuation = row_continuation
                if continuation is None:
                    if selector.startswith("M1-"):
                        continuation = ("typescript", contexts["typescript"], contexts["typescript"])
                    elif selector.startswith(("test_", "assert_")):
                        context = contexts["python"]
                        continuation = ("python", context[0], context) if context else None
                    else:
                        continuation = None
                if continuation is None:
                    raise AssertionError(f"unresolved continuation evidence at row {line_number}: {token}")
                runtime, path, context = continuation
                if path is None:
                    raise AssertionError(f"unresolved continuation evidence at row {line_number}: {token}")
                if runtime == "typescript":
                    _resolve_typescript(root, path, selector)
                elif runtime == "python":
                    contexts["python"] = _resolve_python(root, path, selector, context)
                else:
                    _resolve_json(root, path, selector)
                row_continuation = continuation
                automated |= _is_automated_reference(path, selector)
            if _resolve_command(root, token, references):
                automated = True
        for target in _LOCAL_LINK.findall(evidence):
            link_path = root / "design" / target
            if not link_path.is_file():
                raise AssertionError(f"unresolved matrix link at row {line_number}: {target}")
        if not automated:
            raise AssertionError(f"no resolvable automated evidence for {slice_name} row {line_number}")
    return rows


class TestConformanceGate(unittest.TestCase):
    def ledger(self, *, extra=False, runtimes=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        vectors = root / "conformance/vectors"
        vectors.mkdir(parents=True)
        cases = [{"id": "first", "expected": True}, {"id": "second", "expected": False}]
        if extra:
            cases.append({"id": "new", "expected": True})
        value = {"cases": cases}
        spec = {"schema_version": 1, "files": {"probe.json": {
            "runtimes": runtimes or ["python", "typescript"], "inapplicable_reason": "explicit test applicability",
            "fields": {"cases": {"mode": "cases"}}}}, "contracts": {"wrapper_pairs": {}}}
        manifest = {"files": {"probe.json": {"cases": ["cases"] + ["cases/" + row["id"] for row in cases]}}}
        for path, data in ((vectors / "probe.json", value), (vectors / "manifest.json", manifest),
                           (root / "conformance/consumption-v1.json", spec)):
            path.write_text(json.dumps(data))
        return Consumption(root)

    def test_missing_and_new_case_fail_until_individually_asserted(self):
        for extra in (False, True):
            ledger = self.ledger(extra=extra)
            ledger.case("probe.json", "cases", {"id": "first", "expected": True})
            with self.assertRaisesRegex(AssertionError, "unconsumed"):
                ledger.assert_complete()
            for row in ledger.values["probe.json"]["cases"][1:]:
                ledger.case("probe.json", "cases", row)
            self.assertEqual(len(ledger.assert_complete()["semantic_claims"]), 3 if extra else 2)

    def test_unknown_foreign_and_inapplicable_claims_reject(self):
        ledger = self.ledger()
        for name, ref in (("missing.json", "cases/first"), ("probe.json", "cases/missing")):
            with self.assertRaisesRegex(AssertionError, "unknown or inapplicable"):
                ledger.claim(name, ref)
        with self.assertRaisesRegex(AssertionError, "foreign case"):
            ledger.case("probe.json", "cases", {"id": "first", "expected": False})
        excluded = self.ledger(runtimes=["typescript"])
        self.assertEqual(excluded.assert_complete()["semantic_claims"], [])
        with self.assertRaisesRegex(AssertionError, "inapplicable"):
            excluded.claim("probe.json", "cases/first")

    def test_whole_group_equality_does_not_claim_a_failed_comparison(self):
        ledger = self.ledger()
        with self.assertRaisesRegex(AssertionError, "equality failed"):
            ledger.equal("probe.json", "cases", [])
        self.assertFalse(ledger.claimed)
        ledger.equal("probe.json", "cases", copy.deepcopy(ledger.values["probe.json"]["cases"]))
        self.assertEqual(len(ledger.assert_complete()["semantic_claims"]), 2)

    def test_new_field_and_mismatched_manifest_registry_fail(self):
        ledger = self.ledger()
        path = ledger.root / "conformance/vectors/probe.json"
        path.write_text(json.dumps({**ledger.values["probe.json"], "unowned": []}))
        with self.assertRaisesRegex(AssertionError, "field inventory"):
            Consumption(ledger.root)
        path.write_text(json.dumps(ledger.values["probe.json"]))
        manifest = ledger.root / "conformance/vectors/manifest.json"
        value = json.loads(manifest.read_text())
        value["files"]["probe.json"]["cases"].pop()
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(AssertionError, "case registry"):
            Consumption(ledger.root)

    def test_normative_contract_inventory_is_represented_for_both_runtimes(self):
        contracts = contract_inventory()
        self.assertTrue({"agreement-metadata", "release-profile"} <= set(contracts["closed_schemas"]))
        for runtime in ("python", "typescript"):
            expected = Consumption(runtime=runtime).expected
            for group in contracts.values():
                for name, references in group.items():
                    self.assertTrue(references, name)
                    self.assertTrue(all(tuple(ref) in expected for ref in references), (runtime, name))
        python = Consumption().expected
        typescript = Consumption(runtime="typescript").expected
        self.assertTrue(python - typescript)
        self.assertEqual({name for name, _ in python - typescript}, {"replay-v1.json"})

    def test_every_m1_slice_has_resolvable_automated_traceability(self):
        text = (ROOT / "design/verification-matrix.md").read_text()
        _validate_matrix(text, ROOT)

    def test_matrix_rejects_evidence_free_rows(self):
        text = "| M1-1 | requirement | No automated evidence remains | PASS |\n"
        with self.assertRaisesRegex(AssertionError, "no resolvable automated evidence"):
            _validate_matrix(text, ROOT, require_all_slices=False)

    def test_matrix_rejects_moved_python_and_typescript_identifiers(self):
        python = (
            "| M1-1 | requirement | "
            "`core/tests/test_conformance_gate.py::TestConformanceGate::test_moved` | PASS |\n"
        )
        with self.assertRaisesRegex(AssertionError, "unresolved Python evidence"):
            _validate_matrix(python, ROOT, require_all_slices=False)
        typescript = (
            "| M1-1 | requirement | "
            "`api/test/conformance.test.mjs::M1-1 missing test title` | PASS |\n"
        )
        with self.assertRaisesRegex(AssertionError, "unresolved TypeScript evidence"):
            _validate_matrix(typescript, ROOT, require_all_slices=False)
        continued_python = (
            "| M1-1 | requirement | "
            "`core/tests/test_conformance_gate.py::TestConformanceGate`; `...::missing_test` | PASS |\n"
        )
        with self.assertRaisesRegex(AssertionError, "unresolved Python evidence"):
            _validate_matrix(continued_python, ROOT, require_all_slices=False)
        continued_typescript = (
            "| M1-1 | requirement | "
            "`api/test/conformance.test.mjs::complete shared manifest and file registry match independently hashed bytes`; "
            "`...::missing title` | PASS |\n"
        )
        with self.assertRaisesRegex(AssertionError, "unresolved TypeScript evidence"):
            _validate_matrix(continued_typescript, ROOT, require_all_slices=False)

    def test_matrix_rejects_json_only_evidence(self):
        json_only = (
            "| M1-15 | requirement | "
            "`conformance/vectors/events-v1.json::source_first_add_paths`; "
            "`...::shrink_only_cases` | PASS |\n"
        )
        with self.assertRaisesRegex(AssertionError, "no resolvable automated evidence"):
            _validate_matrix(json_only, ROOT, require_all_slices=False)

        source_row = next(
            line for line in (ROOT / "design/verification-matrix.md").read_text().splitlines()
            if line.startswith("| M1-15 | Authenticated historical first-add event")
        )
        cells = [cell.strip() for cell in source_row.split("|")[1:-1]]
        existing_row_without_tests = (
            f"| {cells[0]} | {cells[1]} | "
            "`conformance/vectors/events-v1.json::source_first_add_paths`; "
            "`...::shrink_only_cases` | PASS |\n"
        )
        with self.assertRaisesRegex(AssertionError, "no resolvable automated evidence"):
            _validate_matrix(existing_row_without_tests, ROOT, require_all_slices=False)

    def test_matrix_rejects_production_only_continuation_evidence(self):
        row = (
            "| M1-2 | requirement | "
            "`core/dracla/conformance/envelope.py`; `...::decrypt_artifact` | PASS |\n"
        )
        with self.assertRaisesRegex(AssertionError, "no resolvable automated evidence"):
            _validate_matrix(row, ROOT, require_all_slices=False)
