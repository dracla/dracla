"""Scoped, side-effect-free client composition with a closed override grammar."""
from __future__ import annotations

import re

from dracla.provisioning import InstallInput


class ConfigError(ValueError):
    """Unsupported or incomplete configuration; diagnostics never echo input."""


def compose_install(overrides: list[str]) -> InstallInput:
    # Reject resolver expressions and Hydra control syntax before composing.
    allowed = {"github.owner", "project.slug", "dry_run", "force"}
    seen = set()
    composed_overrides = []
    for override in overrides:
        if type(override) is not str or override.count("=") != 1:
            raise ConfigError("Install accepts supported key=value overrides only")
        key, value = override.split("=", 1)
        if key not in allowed or key in seen:
            raise ConfigError("Unknown or repeated install configuration key")
        seen.add(key)
        if key in {"dry_run", "force"}:
            valid = value in {"true", "false"}
        else:
            valid = re.fullmatch(r"[a-zA-Z0-9-]+", value, re.ASCII) is not None
        if not valid:
            raise ConfigError("Invalid install configuration value")
        composed_overrides.append(override if key in {"dry_run", "force"} else f'{key}="{value}"')
    try:
        from hydra import compose, initialize_config_module
        from omegaconf import OmegaConf

        with initialize_config_module(config_module="dracla.cli.conf"):
            composed = compose(config_name="install", overrides=composed_overrides)
            plain = OmegaConf.to_container(composed, resolve=True, throw_on_missing=True)
        if (type(plain) is not dict or set(plain) != {"github", "project", "dry_run", "force"}
                or type(plain["github"]) is not dict or set(plain["github"]) != {"owner"}
                or type(plain["project"]) is not dict or set(plain["project"]) != {"slug"}):
            raise ConfigError("Invalid packaged install configuration")
        return InstallInput(plain["github"]["owner"], plain["project"]["slug"], plain["dry_run"], plain["force"])
    except ConfigError:
        raise
    except Exception:
        # Hydra errors may contain the original override. Keep them out of output.
        raise ConfigError("Install configuration is incomplete or invalid") from None
