"""M2/1 behavioral evidence: configuration, release preflight and installed CLI."""
from __future__ import annotations

import hashlib
import io
from contextlib import redirect_stdout
import runpy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from dracla.cli.app import main
from dracla.cli.config import ConfigError, compose_install
from dracla.cli.release import ReleaseError, ReleaseIdentity, load_release_policy
from dracla.conformance.canonical import canonical_json
from dracla.provisioning import InstallInput, initial_plan

ROOT = Path(__file__).resolve().parents[2]


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class ReleaseFixture:
    """Only runtime test data; never installed as production provenance."""
    def __init__(self):
        self.distributions = {
            "dracla": SimpleNamespace(version="0.0.1", metadata={"Name": "dracla"}, requires=["alpha[feature]>=1"]),
            "alpha": SimpleNamespace(version="1.0", metadata={"Name": "Alpha"},
                requires=['beta==2.0; extra == "feature"', 'build-tool; extra == "dev"', 'missing; python_version < "3.0"']),
            "beta": SimpleNamespace(version="2.0", metadata={"Name": "beta"}, requires=["alpha>=1"]),
        }
        self.constraints = b"alpha==1.0\nbeta==2.0\n"
        self.policy = {"release_policy_version": 1, "package_version": "0.0.1", "source_commit_oid": "a" * 40,
            "provenance_identity": "dracla/dracla/.github/workflows/release.yml@refs/tags/0.0.1",
            "dependency_constraints_sha256": digest(self.constraints)}
        self.calls = []

    def load(self, *, policy_bytes=None):
        values = {"release-policy.json": canonical_json(self.policy) if policy_bytes is None else policy_bytes,
                  "dependency-constraints.txt": self.constraints}
        def read(name):
            self.calls.append(name)
            return values[name]
        return load_release_policy(read_resource=read, distribution=self.distributions.__getitem__)

    def bind(self):
        self.policy["dependency_constraints_sha256"] = digest(self.constraints)


class ConfigurationTests(unittest.TestCase):
    def test_defaults_case_and_exact_names(self):
        for owner in ("Acme", "123", "true", "null"):
            with self.subTest(owner=owner):
                config = compose_install([f"github.owner={owner}"])
                self.assertEqual(config, InstallInput(owner, owner))
        config = compose_install(["github.owner=Acme", "project.slug=Acme-CLA", "dry_run=true", "force=true"])
        plan = initial_plan(config)
        self.assertEqual([r.name for r in plan.repositories], [f"acme-cla-cla-{r}" for r in ("records", "coverage", "control")])
        self.assertEqual(plan, initial_plan(config))
        self.assertFalse(plan.complete)
        self.assertFalse(compose_install(["github.owner=acme"]).dry_run)

    def test_rejections_do_not_echo_input_or_expand_secrets(self):
        invalid = [[], ["github.owner="], ["github.owner= acme"], ["github.owner=https://example.com"],
            ["github.owner=é"], ["github.owner=-bad"], ["github.owner=a" * 40],
            ["github.owner=acme", "project.slug=-bad"], ["github.owner=acme", "project.slug=" + "a" * 64],
            ["github.owner=acme", "project.slug=é"], ["github.owner=acme", "dry_run=yes"],
            ["github.owner=acme", "force=1"], ["github.owner=${oc.env:GH_TOKEN}"], ["github.owner=${bad}"],
            ["github.owner=acme", "+other=secret"], ["github.owner=acme", "hydra.run.dir=/tmp/x"],
            ["github.owner=acme", "--multirun"], ["github.owner=a,b"], ["github.owner=a=b"],
            ["github.owner=a", "github.owner=b"], ["github.owner=acme", "_target_=evil"]]
        with patch.dict(os.environ, {"GH_TOKEN": "SECRET-NEVER-EXPAND"}):
            for args in invalid:
                with self.subTest(args=args), self.assertRaises(ConfigError) as raised:
                    compose_install(args)
                self.assertNotIn("SECRET", str(raised.exception))
        for config in [("a", "a", 1, False), ("a", " a", False, False), ("a", "a", False, "true"), ("-bad", "a", False, False), ("a", "é", False, False), ("a", 1, False, False)]:
            with self.assertRaises(ValueError):
                InstallInput(*config)

    def test_scoped_composition_no_files_cwd_or_hydra_state(self):
        from hydra.core.global_hydra import GlobalHydra
        old = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            os.chdir(directory)
            try:
                before = set(Path(directory).rglob("*"))
                for _ in range(2):
                    compose_install(["github.owner=acme", "dry_run=true"])
                    self.assertFalse(GlobalHydra.instance().is_initialized())
                    self.assertEqual(Path.cwd(), Path(directory))
                self.assertEqual(set(Path(directory).rglob("*")), before)
            finally:
                os.chdir(old)


class ReleaseTests(unittest.TestCase):
    def test_local_identity_and_transitive_extra_closure_without_network(self):
        f = ReleaseFixture()
        with patch("urllib.request.urlopen", side_effect=AssertionError("unexpected HTTP")), \
             patch("urllib.request.build_opener", side_effect=AssertionError("unexpected HTTP")), \
             patch("socket.create_connection", side_effect=AssertionError("unexpected network")):
            result = f.load()
        self.assertEqual(result, ReleaseIdentity("0.0.1", "a" * 40, f.policy["provenance_identity"],
            digest(canonical_json(f.policy)), digest(f.constraints)))
        self.assertEqual(f.calls, ["release-policy.json", "dependency-constraints.txt"])
        f.policy["source_commit_oid"] = "b" * 64
        self.assertEqual(f.load().source_commit_oid, "b" * 64)

    def test_closed_canonical_five_field_policy(self):
        original = ReleaseFixture().policy
        mutations = [{**original, "extra": "x"}, {k: v for k, v in original.items() if k != "package_version"},
            {**original, "release_policy_version": True}, {**original, "release_policy_version": 2},
            {**original, "allowed_artifacts_url": "https://example.com/obsolete-manifest.json"}]
        for value in mutations:
            f = ReleaseFixture(); f.policy = value
            with self.subTest(value=value), self.assertRaises(ReleaseError): f.load()
        for raw in (json.dumps(original).encode(), b'{"x":1,"x":1}', b'[]', b'\xff', b'', b'x' * (1024 * 1024 + 1)):
            with self.subTest(raw_length=len(raw)), self.assertRaises(ReleaseError):
                ReleaseFixture().load(policy_bytes=raw)

    def test_invalid_policy_and_unavailable_resources_fail_before_planning(self):
        mutations = {"package_version": ["0.0.2", "v0.0.1", True], "source_commit_oid": ["a" * 39, "A" * 40],
            "provenance_identity": ["", "workflow\nsecret"], "dependency_constraints_sha256": ["x", "sha256:" + "0" * 64]}
        for key, values in mutations.items():
            for value in values:
                f = ReleaseFixture(); f.policy[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ReleaseError): f.load()
        with self.assertRaises(ReleaseError):
            load_release_policy(read_resource=lambda _: (_ for _ in ()).throw(FileNotFoundError()),
                                distribution=ReleaseFixture().distributions.__getitem__)

    def test_constraints_and_runtime_closure_reject_invalid_evidence(self):
        bad = [b"alpha==1.0\nbeta==2.0", b"alpha==1.0\r\nbeta==2.0\r\n", b"Alpha==1.0\nbeta==2.0\n",
            b"beta==2.0\nalpha==1.0\n", b"alpha==1.0\nalpha==1.0\n", b"alpha>=1\nbeta==2.0\n",
            b"alpha==v1.0\nbeta==2.0\n", b"alpha==1.0; python_version>='3'\n", b"alpha==1.0\n",
            b"alpha==1.0\nbeta==2.0\nextra==1.0\n", b"dracla==0.0.1\n", b"\n", b"\xff\n"]
        bad.extend(b"alpha==1.0" + separator + b"beta==2.0\n" for separator in
                   (b"\x0b", b"\x0c", "\u0085".encode(), "\u2028".encode()))
        for data in bad:
            f = ReleaseFixture(); f.constraints = data; f.bind()
            with self.subTest(data=data), self.assertRaises(ReleaseError): f.load()
        changes = [lambda f: setattr(f.distributions["alpha"], "version", "1.1"),
            lambda f: setattr(f.distributions["alpha"], "requires", ["beta>=3"]),
            lambda f: setattr(f.distributions["alpha"], "requires", ["missing"]),
            lambda f: setattr(f.distributions["alpha"], "requires", ["beta @ https://example.com/beta.whl"]),
            lambda f: f.distributions["beta"].metadata.update(Name="wrong")]
        for change in changes:
            f = ReleaseFixture(); change(f)
            with self.assertRaises(ReleaseError): f.load()

    def test_default_packaged_reads_are_bounded_and_reject_oversize(self):
        f = ReleaseFixture()
        for oversized in ("release-policy.json", "dependency-constraints.txt"):
            calls = []
            values = {"release-policy.json": canonical_json(f.policy), "dependency-constraints.txt": f.constraints}
            values[oversized] = b"x" * (1024 * 1024 + 16)
            class Stream(io.BytesIO):
                def read(self, size=-1):
                    calls.append(size)
                    return super().read(size)
            def resource(name):
                def open_resource(mode):
                    self.assertEqual(mode, "rb")
                    return Stream(values[name])
                return SimpleNamespace(open=open_resource)
            with patch("dracla.cli.release.resources.files", return_value=SimpleNamespace(joinpath=resource)), \
                 self.assertRaises(ReleaseError):
                load_release_policy(distribution=f.distributions.__getitem__)
            self.assertTrue(calls)
            self.assertEqual(set(calls), {1024 * 1024 + 1})

    def test_resource_failure_is_redacted(self):
        with self.assertRaises(ReleaseError) as raised:
            load_release_policy(read_resource=lambda _: (_ for _ in ()).throw(RuntimeError("SECRET")),
                                distribution=ReleaseFixture().distributions.__getitem__)
        self.assertNotIn("SECRET", str(raised.exception))


class CliTests(unittest.TestCase):
    def test_dispatch_and_preflight_order_and_force(self):
        for args, code in (([], 0), (["--help"], 0), (["install", "-h"], 0), (["verify"], 2),
                           (["unknown-SECRET"], 2), (["install", "github.owner=${oc.env:GH_TOKEN}"], 2)):
            out = io.StringIO()
            def forbidden(): self.fail("Release loading must follow valid configuration")
            self.assertEqual(main(args, output=out, release_loader=forbidden), code)
            self.assertNotIn("SECRET", out.getvalue())
        f = ReleaseFixture()
        for extra in ([], ["dry_run=true"], ["force=true"], ["dry_run=true", "force=true"]):
            out = io.StringIO()
            with patch.dict(os.environ, {"GH_TOKEN": "SECRET", "GITHUB_TOKEN": "SECRET"}):
                self.assertEqual(main(["install", "github.owner=acme"] + extra, output=out, release_loader=f.load), 2)
            text = out.getvalue()
            self.assertIn("acme/acme-cla-records", text)
            self.assertIn("blocked", text)
            self.assertIn("Live account", text)
            self.assertIn("This deploy key is an integrity credential", text)
            self.assertIn("hosted operator", text)
            self.assertNotIn("SECRET", text)
            if "dry_run=true" not in extra: self.assertIn("M3, M5 and M6", text)
        out = io.StringIO()
        self.assertEqual(main(["install", "github.owner=acme"], output=out,
            release_loader=lambda: (_ for _ in ()).throw(RuntimeError("SECRET"))), 1)
        self.assertNotIn("SECRET", out.getvalue())
        self.assertEqual(main(["install", "github.owner=acme"], output=out,
            release_loader=lambda: (_ for _ in ()).throw(ReleaseError("Unavailable release evidence"))), 2)

    def test_no_application_files_network_processes_or_credential_reads(self):
        # Initialize imported client libraries before installing operation spies.
        compose_install(["github.owner=acme"])
        out = io.StringIO()
        f = ReleaseFixture()
        original_open, original_os_open = io.open, os.open
        def read_only_open(file, mode="r", *args, **kwargs):
            if any(c in mode for c in "wax+"): self.fail("unexpected file write")
            return original_open(file, mode, *args, **kwargs)
        def read_only_os_open(file, flags, *args, **kwargs):
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                self.fail("unexpected low-level file write")
            return original_os_open(file, flags, *args, **kwargs)
        with patch("io.open", side_effect=read_only_open), \
             patch("os.open", side_effect=read_only_os_open), \
             patch("builtins.open", side_effect=AssertionError("unexpected filesystem I/O")), \
             patch("os.mkdir", side_effect=AssertionError("unexpected mkdir")), \
             patch("os.chdir", side_effect=AssertionError("unexpected chdir")), \
             patch("subprocess.Popen", side_effect=AssertionError("unexpected process")), \
             patch("urllib.request.urlopen", side_effect=AssertionError("unexpected HTTP")), \
             patch("os.getenv", side_effect=AssertionError("credential read before discovery")):
            # Hydra reads packaged YAML through io.open, never writes a run/config.
            self.assertEqual(main(["install", "github.owner=acme", "dry_run=true"], output=out, release_loader=f.load), 2)
        self.assertIn("Declared release:", out.getvalue())
        self.assertNotIn("Final artifact manifest:", out.getvalue())

    def test_entrypoint_wrappers_and_rejected_packaged_configuration(self):
        import dracla.cli
        out = io.StringIO()
        with patch("sys.argv", ["dracla", "--help"]), redirect_stdout(out):
            self.assertEqual(dracla.cli.main(), 0)
            with self.assertRaises(SystemExit) as raised:
                runpy.run_module("dracla.cli", run_name="__main__")
            self.assertEqual(raised.exception.code, 0)
        from omegaconf import OmegaConf
        with patch("hydra.compose", return_value=OmegaConf.create({"other": "invalid"})):
            with self.assertRaises(ConfigError): compose_install(["github.owner=acme"])
        with self.assertRaises(ReleaseError): load_release_policy()

    def test_installed_wheel_console_module_resources_and_core_import(self):
        with tempfile.TemporaryDirectory(prefix="dracla-m2-cli-") as temporary:
            base = Path(temporary)
            dist, target, work = base / "dist", base / "installed", base / "work"
            work.mkdir()
            build = subprocess.run([sys.executable, "-m", "hatchling", "build", "-t", "wheel", "-d", str(dist)],
                                   cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            wheel, = dist.glob("*.whl")
            install = subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--no-index",
                "--target", str(target), str(wheel)], text=True, capture_output=True)
            self.assertEqual(install.returncode, 0, install.stderr)
            with zipfile.ZipFile(wheel) as archive:
                self.assertIn("dracla/cli/conf/install.yaml", archive.namelist())
                meta = archive.read("dracla-0.0.1.dist-info/METADATA").decode()
                self.assertIn("hydra-core==1.4.0.dev8", meta)
                self.assertNotIn("dracla/release-policy.json", archive.namelist())
            env = {**os.environ, "PYTHONPATH": str(target), "GH_TOKEN": "SECRET", "GITHUB_TOKEN": "SECRET"}
            before = sorted(str(p.relative_to(work)) for p in work.rglob("*"))
            for command in ([str(target / "bin/dracla")], [sys.executable, "-m", "dracla.cli"]):
                for args, expected in ((["--help"], 0), (["verify"], 2),
                                       (["install", "github.owner=acme", "dry_run=true"], 2),
                                       (["install", "github.owner=acme", "force=true"], 2)):
                    result = subprocess.run(command + args, cwd=work, env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertNotIn("SECRET", result.stdout + result.stderr)
                    self.assertEqual(sorted(str(p.relative_to(work)) for p in work.rglob("*")), before)
                    if args[0] == "install": self.assertIn("Release evidence is unavailable", result.stdout)
            # Exercise default installed-resource and metadata reads with an explicit
            # temporary fixture. The actual development wheel stays evidence-free.
            from importlib import metadata
            from packaging.requirements import Requirement
            from packaging.utils import canonicalize_name
            installed_dist = metadata.Distribution.at(target / "dracla-0.0.1.dist-info")
            pending, pins = [installed_dist], {}
            while pending:
                current = pending.pop()
                for value in current.requires or ():
                    requirement = Requirement(value)
                    if requirement.marker and not requirement.marker.evaluate({"extra": ""}):
                        continue
                    name = canonicalize_name(requirement.name)
                    if name not in pins:
                        dependency = metadata.distribution(name)
                        pins[name] = dependency.version
                        pending.append(dependency)
            fixture = ReleaseFixture()
            fixture.constraints = "".join(f"{name}=={version}\n" for name, version in sorted(pins.items())).encode()
            fixture.bind()
            (target / "dracla/release-policy.json").write_bytes(canonical_json(fixture.policy))
            (target / "dracla/dependency-constraints.txt").write_bytes(fixture.constraints)
            positive = '''from unittest.mock import patch
from dracla.cli.app import main
with patch("urllib.request.urlopen", side_effect=AssertionError("unexpected HTTP")), \
     patch("urllib.request.build_opener", side_effect=AssertionError("unexpected HTTP")), \
     patch("socket.create_connection", side_effect=AssertionError("unexpected network")):
    result = main(["install","github.owner=acme","dry_run=true"])
raise SystemExit(result)
'''
            result = subprocess.run([sys.executable, "-c", positive], cwd=work,
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertIn("Declared release:", result.stdout)
            self.assertNotIn("Final artifact manifest:", result.stdout)
            self.assertIn("acme/acme-cla-records", result.stdout)
            self.assertEqual(sorted(str(p.relative_to(work)) for p in work.rglob("*")), before)
            probe = '''import importlib,sys,pathlib
sys.path.insert(0,sys.argv[1])
import dracla.conformance as c
import dracla.provisioning
assert pathlib.Path(c.__file__).is_relative_to(pathlib.Path(sys.argv[1]))
assert not any(n == 'hydra' or n.startswith('hydra.') for n in sys.modules)
from dracla.cli import main
assert not any(n == 'hydra' or n.startswith('hydra.') for n in sys.modules)
'''
            result = subprocess.run([sys.executable, "-I", "-c", probe, str(target)], cwd=work, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
