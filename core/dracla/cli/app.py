"""Registered client commands and truthful, redacted install reporting."""
from __future__ import annotations

import sys
from typing import Callable, TextIO

from dracla.administration import Administration, AdminScope, discover
from dracla.github_admin import GitHubAdministration, credentials_from_environment
from dracla.provisioning import administration_scope, plan_install
from .config import ConfigError, compose_install
from .release import ReleaseError, ReleaseIdentity, load_release_policy

_COMMANDS = frozenset({"install"})
_HELP = "Usage: dracla install github.owner=LOGIN [project.slug=SLUG] [dry_run=true] [force=true]"


def main(argv: list[str] | None = None, *, release_loader: Callable[[], ReleaseIdentity] = load_release_policy,
         output: TextIO | None = None, credential_provider: Callable[[], str | None] = credentials_from_environment,
         admin_factory: Callable[[AdminScope], Administration] | None = None) -> int:
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
    try:
        config = compose_install(args[1:])
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
