"""Install's configuration, composed by Hydra (§6.10.3).

    dracla install github.org=acme recipient.slug=projx

Composition is Hydra's Compose API rather than anything hand-rolled. That is not
only about not reimplementing a config system badly — struct mode rejects
unknown keys, the structured schema below gives type checking, `???` gives
missing-value reporting, and the override grammar handles quoting, nesting, and
list syntax that a naive splitter gets wrong.

`core` never sees any of this: composition resolves here and what reaches the
records repository is plain, inert data (§6.9).
"""

from __future__ import annotations

import re

from dataclasses import dataclass, field
from pathlib import Path

from hydra import compose, initialize_config_dir
from hydra.core.config_store import ConfigStore
from hydra.errors import ConfigCompositionException, OverrideParseException
from omegaconf import MISSING, OmegaConf
from omegaconf.errors import MissingMandatoryValue, OmegaConfBaseException

from .errors import CliError

CONF_DIR = Path(__file__).parent / "conf"


@dataclass
class GitHub:
    org: str = MISSING


@dataclass
class Recipient:
    slug: str = MISSING


@dataclass
class InstallSchema:
    """The structured schema. Struct mode plus this is what makes a mistyped
    key an error instead of a silently ignored line."""
    github: GitHub = field(default_factory=GitHub)
    recipient: Recipient = field(default_factory=Recipient)
    force: bool = False
    dry_run: bool = False


# GitHub account names: letters, digits, hyphens; no leading or
# trailing hyphen. Deliberately narrow — a name that fails this is a
# typo, and the alternative is a 404 after the operator has confirmed.
_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")

cs = ConfigStore.instance()
cs.store(name="install_schema", node=InstallSchema)


@dataclass(frozen=True)
class InstallConfig:
    org: str
    slug: str
    force: bool = False
    dry_run: bool = False
    # The overrides as typed, so an error can suggest the user's own command
    # back to them with one thing added, rather than a generic incantation.
    overrides: tuple[str, ...] = ()

    def command(self, *extra: str) -> str:
        """The invocation that produced this config, with `extra` applied.

        A replaced key keeps its original position rather than moving to the
        end, so the suggestion reads as the operator's own command with one
        thing changed — which is the point of echoing it back at all.
        """
        replacing = {e.split("=", 1)[0]: e for e in extra}
        used: set[str] = set()
        parts: list[str] = []
        for given in self.overrides:
            key = given.split("=", 1)[0]
            if key in replacing:
                parts.append(replacing[key])
                used.add(key)
            else:
                parts.append(given)
        parts.extend(e for k, e in replacing.items() if k not in used)
        return " ".join(["dracla install", *parts])

    @property
    def records_name(self) -> str:
        return f"{self.slug}-cla-records"

    @property
    def coverage_name(self) -> str:
        return f"{self.slug}-cla-coverage"

    @property
    def records_repo(self) -> str:
        return f"{self.org}/{self.records_name}"

    @property
    def coverage_repo(self) -> str:
        return f"{self.org}/{self.coverage_name}"


def describe(cfg: "InstallConfig") -> str:
    """Render the resolved configuration (C2).

    A Hydra application should let an operator see what the overrides actually
    resolved to. --dry-run reports intended *actions*; this reports the config
    that produced them, which is what you want when an interpolated default
    surprises you.
    """
    return "\n".join([
        f"github.org         {cfg.org}",
        f"recipient.slug     {cfg.slug}",
        f"force              {str(cfg.force).lower()}",
        f"dry_run            {str(cfg.dry_run).lower()}",
        "",
        f"records repository   {cfg.records_repo}",
        f"coverage repository  {cfg.coverage_repo}",
    ])


def resolve(overrides: list[str]) -> InstallConfig:
    """Compose the install configuration from overrides.

    Hydra's errors are precise but framed for an application author; they are
    translated here into something an operator can act on.
    """
    try:
        # version_base is omitted deliberately: it is deprecated in Hydra 1.4
        # and removed in 1.5, so passing it would warn on every invocation.
        with initialize_config_dir(config_dir=str(CONF_DIR.resolve())):
            cfg = compose(config_name="config", overrides=list(overrides))
    except OverrideParseException as e:
        raise CliError(
            "could not parse an override",
            hint=f"overrides look like key=value, e.g. github.org=acme\n"
                 f"    {e}") from None
    except ConfigCompositionException as e:
        raise CliError(
            str(e).splitlines()[0],
            hint="install takes github.org and optionally recipient.slug. "
                 "Recipient details, scope, and policy text are configured in "
                 "the portal, not here.") from None

    try:
        org = cfg.github.org
        slug = cfg.recipient.slug
    except MissingMandatoryValue:
        raise CliError("github.org is required",
                       hint="dracla install github.org=YOUR-ORG") from None
    except OmegaConfBaseException as e:
        raise CliError(str(e)) from None

    # The schema types these as `str`, which rejects null, lists and mappings —
    # but an empty or blank string is a valid `str` and would compose repository
    # names like `/-cla-records`. GitHub account names are also a narrow set, so
    # anything that cannot be one is a typo worth catching before the network.
    for key, value in (("github.org", org), ("recipient.slug", slug)):
        if not str(value).strip():
            raise CliError(f"{key} is empty",
                           hint=f"dracla install github.org=YOUR-ORG")
        if not _NAME.fullmatch(str(value)):
            raise CliError(
                f"{key} is not a usable GitHub name: {value!r}",
                hint="GitHub names use letters, digits and hyphens.")

    return InstallConfig(org=str(org), slug=str(slug),
                         force=bool(cfg.force),
                         dry_run=bool(cfg.dry_run),
                         overrides=tuple(overrides))
