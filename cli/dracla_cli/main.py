"""dracla — command line entry point.

Every command runs as the administrator, with their own credentials. There is no
DraCLA service in the path (design D11, D12), which is also why `REQ-REC-5`'s
"readable without DraCLA" holds literally: this is the tool an auditor would use.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

from . import __version__
from .config import ProjectConfig, Recipient, Scope, Confirmation
from .errors import CliError
from .provision import Provisioner, preflight
from .seed import Seeder

PORTAL = "https://dracla.yadan.net"


def _token() -> str:
    """The administrator's own GitHub token."""
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True,
                             text=True, timeout=10)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (FileNotFoundError, subprocess.SubprocessError):
        pass
    raise CliError(
        "no GitHub credentials found",
        hint="run `gh auth login`, or set GITHUB_TOKEN")


def _install_links(slug: str) -> str:
    """The two App installations the administrator completes in GitHub's UI.

    A GitHub App cannot install another App — installation is a user action
    through GitHub's own UI. Offering the link is the intended flow, not a
    workaround, and GitHub owns the consent screen, repository picker, and
    permission display (design §9).
    """
    return (
        f"  1. records     https://github.com/apps/dracla-records/"
        f"installations/new?state={slug}\n"
        f"  2. enforcement https://github.com/apps/dracla-enforcer/"
        f"installations/new?state={slug}\n")


def cmd_install(args: argparse.Namespace) -> int:
    cfg = ProjectConfig(
        slug=args.slug,
        recipient=Recipient(legal_name=args.recipient, contact=args.contact),
        scope=Scope(orgs=args.org or [], repos=args.repo or []),
        privacy_policy_url=args.privacy_policy,
        retention_statement=args.retention or (
            "Agreement evidence is retained after revocation. Revocation "
            "changes coverage for future contributions; it does not delete the "
            "record or withdraw rights already granted."),
        confirmations=[Confirmation("read", "I have read and accept this agreement")],
    )
    cfg.validate()

    prov = Provisioner(_token(), args.owner, dry_run=args.dry_run)

    for w in preflight(prov, cfg):
        print(f"  warning: {w}\n", file=sys.stderr)

    pair = prov.provision(cfg)
    print(f"records   {pair.records}")
    print(f"coverage  {pair.coverage}")
    if pair.created:
        print(f"created   {', '.join(pair.created)}")

    seeder = Seeder(_token(), pair.records, dry_run=args.dry_run)
    print(f"events    {seeder.ensure_events_branch()}")
    print(f"config    {seeder.seed_config(cfg)}")
    print(f"workflow  {seeder.seed_workflow(pair.coverage, __version__)}")

    if args.agreement:
        text = open(args.agreement, encoding="utf-8").read()
        print(f"agreement {seeder.seed_agreement(cfg, text, args.version)}")
    else:
        print("agreement skipped — pass --agreement to publish one")

    print("\nNext, install the two GitHub Apps (GitHub shows the consent screen):")
    print(_install_links(cfg.slug))
    print(f"Then the project page will be {PORTAL}/p/{cfg.slug}")
    return 0


def cmd_config_show(args: argparse.Namespace) -> int:
    from dracla.github import GitHubHost                # noqa: PLC0415
    host = GitHubHost(repo=args.records, token=_token())
    content, _ = host.read("main", "config/project.json")
    print(content)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dracla",
        description="Administer Contributor License Agreements on GitHub.")
    p.add_argument("--version", action="version", version=f"dracla {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    i = sub.add_parser("install", help="provision a project's repository pair")
    i.add_argument("--owner", required=True, help="GitHub org or user to own the repos")
    i.add_argument("--slug", required=True, help="project slug, e.g. acme")
    i.add_argument("--recipient", required=True,
                   help="legal person receiving the granted rights "
                        "(need not be the GitHub org)")
    i.add_argument("--contact", required=True, help="contact for the recipient")
    i.add_argument("--org", action="append", help="org in scope (repeatable)")
    i.add_argument("--repo", action="append", help="repo in scope (repeatable)")
    i.add_argument("--privacy-policy", required=True, help="URL of your privacy policy")
    i.add_argument("--retention", help="retention statement shown before signing")
    i.add_argument("--agreement", help="path to the agreement text to publish")
    i.add_argument("--version", dest="version", default="v1", help="agreement version")
    i.add_argument("--dry-run", action="store_true", help="show what would happen")
    i.set_defaults(func=cmd_install)

    c = sub.add_parser("config", help="inspect project configuration")
    csub = c.add_subparsers(dest="config_command", required=True)
    cs = csub.add_parser("show", help="print the resolved config from canonical")
    cs.add_argument("--records", required=True, help="owner/name of the records repo")
    cs.set_defaults(func=cmd_config_show)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CliError as e:
        print(f"error: {e}", file=sys.stderr)
        if e.hint:
            print(f"  {e.hint}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
