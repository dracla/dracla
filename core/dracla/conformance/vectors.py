"""Generate the source-test corpus through its Python contract authors.

Fixed secrets and independent goldens live under conformance/authoring, outside
the installed package. Production encryption continues to use fresh nonces.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def source_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "conformance/authoring/build.py").is_file():
        raise ValueError("vector generation requires the source checkout")
    return root


def generate(root: Path | None = None) -> dict[str, bytes]:
    """Return all corpus bytes, without reading the destination corpus."""
    root = source_root() if root is None else Path(root)
    spec = importlib.util.spec_from_file_location(
        "dracla_vector_authoring", root / "conformance/authoring/build.py")
    author = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(author)
    outputs, registry = author.build(root)
    manifest = {"manifest_version": 1, "files": {}}
    for name, raw in sorted(outputs.items()):
        metadata = registry[name]
        manifest["files"][name] = {
            "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "contract_version": 1,
            "authoring_slices": metadata["authoring_slices"],
            "cases": metadata["cases"],
        }
    outputs["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    return outputs


def check(root: Path | None = None) -> tuple[str, ...]:
    """Return missing, extra or changed files, including the digest manifest."""
    root = source_root() if root is None else Path(root)
    expected = generate(root)
    directory = root / "conformance/vectors"
    entries = tuple(directory.iterdir())
    unsupported = {p.name for p in entries if p.is_symlink() or not p.is_file()}
    actual = {p.name: p.read_bytes() for p in entries if p.name not in unsupported}
    changed = {name for name in expected.keys() | actual.keys()
               if expected.get(name) != actual.get(name)}
    return tuple(sorted(changed | unsupported))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        root = source_root()
        if args.check:
            changed = check(root)
            if changed:
                print("conformance vectors differ: " + ", ".join(changed), file=sys.stderr)
                return 1
        else:
            outputs = generate(root)
            directory = root / "conformance/vectors"
            directory.mkdir(parents=True, exist_ok=True)
            for name, raw in outputs.items():
                (directory / name).write_bytes(raw)
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"conformance generation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
