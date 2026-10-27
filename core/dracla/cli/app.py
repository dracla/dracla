"""Registered client commands and truthful, redacted install reporting."""
from __future__ import annotations

import sys
from typing import Callable, TextIO

from dracla.administration import Administration, AdminScope, discover
from dracla.github_admin import GitHubAdministration, credentials_from_environment
from dracla.provisioning import administration_scope, plan_install
from .config import ConfigError, compose_install, compose_verify, compose_reconcile, prompt_recovery_keys
from .release import ReleaseError, ReleaseIdentity, load_release_policy

_HELP = ("Usage: dracla install github.owner=LOGIN [project.slug=SLUG] [dry_run=true] [force=true]\n"
         "       dracla {verify|reconcile} project.id=ID github.owner=LOGIN github.owner_id=ID "
         "records.name=NAME records.id=ID coverage.name=NAME coverage.id=ID control.name=NAME control.id=ID")


def main(argv: list[str] | None = None, *, release_loader: Callable[[], ReleaseIdentity] = load_release_policy,
         output: TextIO | None = None, credential_provider: Callable[[], str | None] = credentials_from_environment,
         admin_factory: Callable[[AdminScope], Administration] | None = None,
         verify_factory: Callable | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    out = sys.stdout if output is None else output
    if not args or args in (["--help"], ["-h"]):
        print(_HELP, file=out)
        return 0
    if args[0] not in _COMMANDS:
        print("Unknown command. " + _HELP, file=out)
        return 2
    if args[1:] in (["--help"], ["-h"]):
        print(_HELP, file=out)
        return 0
    return _COMMANDS[args[0]](args[1:], out, release_loader, credential_provider, admin_factory,
                             verify_factory=verify_factory)


def _install(args: list[str], out: TextIO, release_loader: Callable[[], ReleaseIdentity],
             credential_provider: Callable[[], str | None],
             admin_factory: Callable[[AdminScope], Administration] | None, *, verify_factory=None) -> int:
    try:
        config = compose_install(args)
        release = release_loader()
        scope = administration_scope(config)
        admin = (admin_factory(scope) if admin_factory is not None else
                 GitHubAdministration(scope, credential_provider=credential_provider))
        plan = plan_install(config, release, discover(admin, scope))
        print(f"Declared release: {release.package_version}; source: {release.source_commit_oid}", file=out)
        print(f"Declared workflow: {release.provenance_identity}", file=out)
        print(f"Policy: {release.policy_sha256}", file=out)
        print(f"Constraints: {release.dependency_constraints_sha256}", file=out)
        print(f"Plan: {plan.owner}/{plan.slug} — {'ready' if plan.complete else 'blocked'}", file=out)
        print(f"Owner ID: {plan.owner_id if plan.owner_id is not None else 'unknown'}", file=out)
        for repo in plan.repositories:
            print(f"  {repo.role}: {repo.owner}/{repo.name}; ID: {repo.id if repo.id is not None else 'unassigned'}", file=out)
        for step in plan.steps:
            print(f"Step [{step.engine}; {step.state}]: {step.description}", file=out)
        for warning in plan.warnings:
            print(f"Warning: {warning}", file=out)
        for blocker in plan.blockers:
            print(f"Blocked: {blocker}", file=out)
        return 0 if config.dry_run and plan.complete else 2
    except (ConfigError, ReleaseError) as error:
        print(str(error), file=out)
        return 2
    except Exception:
        print("Internal failure; no installation was performed.", file=out)
        return 1


def _verify(args, out, release_loader, credential_provider, admin_factory, *, verify_factory=None):
    from dracla.records import OperatorCredentials, RecordsError, RepositoryTransport, WrappedKeys, verify_project

    try:
        binding = compose_verify(args)
        release_loader()
        keys, transport = (verify_factory(binding) if verify_factory is not None else
                           (WrappedKeys('recovery', prompt_recovery_keys),
                            RepositoryTransport(OperatorCredentials(credential_provider))))
        report = verify_project(binding, keys, transport)
        print(f'Events: {report.source_oid}; coverage: {report.coverage_oid}; '
              f'derived: {report.derived_oid}; operations: {report.operations_oid}', file=out)
        if report.valid:
            print('Verification passed; no repository changes made.', file=out)
            return 0
        print('Verification incomplete: '+', '.join(report.discrepancies), file=out)
        return 2
    except (ConfigError, ReleaseError) as error:
        print(str(error), file=out)
        return 2
    except RecordsError as error:
        print('Verification unavailable: '+error.category, file=out)
        return 2
    except Exception:
        print('Verification unavailable.', file=out)
        return 1


def _reconcile(args, out, release_loader, credential_provider, admin_factory, *, verify_factory=None):
    from datetime import datetime, timezone
    from functools import cache
    from dracla.records import OperatorCredentials, RecordsError, RepositoryTransport, WrappedKeys
    from dracla.records.reconcile import reconcile_project

    try:
        binding = compose_reconcile(args)
        release = release_loader()
        keys, transport = (verify_factory(binding) if verify_factory is not None else
                           (WrappedKeys('recovery', cache(prompt_recovery_keys)),
                            RepositoryTransport(OperatorCredentials(credential_provider))))
        report = reconcile_project(binding, keys, transport,
            built_at=datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
            dracla_version=release.package_version)
        if report.source_oid is not None:
            print('Events: ' + report.source_oid, file=out)
        if report.valid:
            print('Reconciliation complete; authenticated projections and operation guards verified.', file=out)
            return 0
        print('Reconciliation blocked: ' + report.reason, file=out)
        return 2
    except (ConfigError, ReleaseError) as error:
        print(str(error), file=out)
        return 2
    except RecordsError as error:
        print('Reconciliation unavailable: ' + error.category, file=out)
        return 2
    except Exception:
        print('Reconciliation unavailable.', file=out)
        return 1


# Keep the public command surface tied to actual handlers.
_COMMANDS = {"install": _install, "verify": _verify, "reconcile": _reconcile}
