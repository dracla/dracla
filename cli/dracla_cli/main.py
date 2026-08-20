"""dracla — command line entry point.

Every command runs as the administrator, with their own credentials, and no
DraCLA service is in the path (D11, D12).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

from . import __version__
from .admin import GitHubAdmin
from .config import describe, resolve
from dracla.github import GitHubError
from dracla.githost import BlobConflict, NotFastForward, NotFound

from .errors import Aborted, CliError
from .install import InstallFailed, run
from .workflow import RECONCILE_IMPLEMENTED

PORTAL = "https://dracla.yadan.net"


def _token() -> str:
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True,
                             text=True, timeout=10)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        # OSError, not FileNotFoundError: `gh` present but not executable
        # raises PermissionError, which is not a FileNotFoundError.
        pass
    raise CliError("no GitHub credentials found",
                   hint="run `gh auth login`, or set GITHUB_TOKEN")


def _isatty(stream) -> bool:
    """.isatty() raises ValueError on a closed file object."""
    try:
        return stream.isatty()
    except ValueError:
        return False


def install_links(slug: str) -> list[tuple[str, str]]:
    """The two App installations the administrator completes in GitHub's UI.

    A GitHub App cannot install another App; installation is a user action
    through GitHub's own UI. Offering the link is the intended flow, and GitHub
    owns the consent screen, repository picker, and permission display (§9).
    """
    base = "https://github.com/apps"
    return [
        ("records", f"{base}/dracla-records/installations/new?state={slug}"),
        ("enforcement", f"{base}/dracla-enforcer/installations/new?state={slug}"),
    ]


def _check_confirmable(cfg) -> None:
    """Refuse an invocation that could never be confirmed, before any network.

    C1: prompting without a terminal used to raise EOFError and exit 0. Refusing
    is the right answer rather than auto-confirming — this creates repositories,
    and a script that did not pass `force=true` did not consent.

    Checked here, ahead of any API call, because an invocation that cannot
    possibly succeed should fail immediately rather than after a round trip.
    The *prompt* itself still waits until after the organization gate (§6.10.3.1).
    """
    if cfg.dry_run or cfg.force:
        return
    # sys.stdin is None when fd 0 is closed, and .isatty() raises on a closed
    # file object. Either way there is no terminal to ask.
    if sys.stdin is None or not _isatty(sys.stdin):
        raise CliError(
            "cannot ask for confirmation: stdin is not a terminal",
            hint="pass force=true to proceed without a prompt, e.g.\n"
                 f"    dracla install github.org={cfg.org} force=true")


def _confirm(cfg, warnings=()) -> bool:
    """Prompt. Invoked by run() after the gate passes, never before.

    Takes the preflight warnings so the operator sees them BEFORE answering.
    They used to be printed after run() returned, which meant an upgrade over
    existing repositories was approved against the words "About to create" and
    only afterwards revealed as reuse.
    """
    if cfg.dry_run or cfg.force:
        return True
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    # stderr, not stdout: `dracla install ... > log` must not send the prompt
    # to the file and leave the operator staring at a blank terminal while
    # input() blocks. _check_confirmable cannot catch that — stdin IS a tty.
    # Say what will actually happen, PER REPOSITORY. A single verb chosen from
    # whether any warning exists announced "Reusing existing" for a repository
    # that did not exist yet — the same defect as "About to create" on a re-run,
    # in the other direction.
    reused = {w.split()[0] for w in warnings}
    for repo in (cfg.records_repo, cfg.coverage_repo):
        verb = "reuse existing" if repo in reused else "create"
        print(f"  will {verb} {repo} (private)", file=sys.stderr)
    try:
        sys.stderr.write("Continue? [y/N] ")
        sys.stderr.flush()
        answer = input()
    except EOFError:
        raise CliError("no answer given; nothing was created",
                       hint="pass force=true to skip the prompt") from None
    if answer.strip().lower() not in ("y", "yes"):
        raise Aborted("cancelled; nothing was created")
    return True


def _print_steps(out) -> None:
    width = max((len(s.what) for s in out.steps), default=0)
    for step in out.steps:
        print(f"  {step.what.ljust(width)}  {step}")


def cmd_install(args: argparse.Namespace) -> int:
    cfg = resolve(args.overrides)
    if args.show_config:
        print(describe(cfg))
        return 0

    _check_confirmable(cfg)
    admin = GitHubAdmin(_token())

    try:
        # Confirmation is passed in rather than called here, so the
        # organization gate blocks before the operator is asked to approve
        # anything (§6.10.3.1).
        out = run(admin, cfg, version=__version__,
                  confirm=lambda warnings: _confirm(cfg, warnings))
    except InstallFailed as e:
        # B3: say what already exists, so the operator can act on the fact that
        # re-running is the recovery.
        if e.outcome is not None and e.outcome.steps:
            print("completed before the failure:", file=sys.stderr)
            _print_steps(e.outcome)
        raise

    # Warnings were shown before the prompt (see _confirm); repeat them here
    # only when there was no prompt to show them at.
    if cfg.dry_run or cfg.force:
        for warning in out.warnings:
            print(f"warning: {warning}", file=sys.stderr)
    _print_steps(out)

    print()
    print("Next:")
    step = 0
    for label, url in install_links(cfg.slug):
        step += 1
        print(f"  {step}. install the {label} App")
        print(f"     {url}")
    step += 1
    print(f"  {step}. connect at {PORTAL}/connect")
    print()
    print("Connecting is where the project is registered and configured — "
          "recipient,")
    print("scope, privacy policy, and the agreement itself. Until then this "
          "project")
    print("is provisioned but not yet able to accept signatures.")
    print()
    print("If any step above failed, re-run the same command: install is "
          "idempotent,")
    print("and re-running is the intended recovery.")

    if not RECONCILE_IMPLEMENTED:
        print()
        print("Note: reconciliation is not implemented yet (M2). A placeholder "
              "workflow")
        print("was seeded; re-run install after upgrading dracla to enable it.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dracla",
        description="Administer Contributor License Agreements on GitHub.")
    p.add_argument("--version", action="version", version=f"dracla {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    i = sub.add_parser(
        "install",
        help="provision a project's repository pair and workflow",
        description="Provision the repository pair. Takes Hydra-style "
                    "overrides, e.g. dracla install github.org=acme")
    i.add_argument("overrides", nargs="*", metavar="KEY=VALUE",
                   help="Hydra overrides. github.org=ORG is required. "
                        "recipient.slug=SLUG defaults to the org; "
                        "dry_run=true and force=true modify execution.")
    i.add_argument("--show-config", action="store_true",
                   help="print the resolved configuration and exit, without "
                        "contacting GitHub")
    i.set_defaults(func=cmd_install)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CliError as e:
        print(f"error: {e}", file=sys.stderr)
        if e.hint:
            print(file=sys.stderr)
            for line in e.hint.splitlines():
                print(f"  {line}" if line else "", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except (GitHubError, NotFound, BlobConflict, NotFastForward) as e:
        # core's transport errors are not CliError — they are raised at a
        # service, not a person. Without this they reach the operator as a
        # traceback: an expired GITHUB_TOKEN, an org that needs SAML SSO
        # authorization, or a rate limit all looked like a crash.
        print(f"error: GitHub refused the request: {e}", file=sys.stderr)
        print(file=sys.stderr)
        print("  check that your token is valid and authorized for this",
              file=sys.stderr)
        print("  organization: gh auth status", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
