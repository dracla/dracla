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


def compose_verify(overrides: list[str]):
    """Resolve only non-secret identifiers; recovery material is never an override."""
    from dracla.administration import RepositoryRef, numeric_id
    from dracla.records import ProjectBinding

    names = {'project.id', 'github.owner', 'github.owner_id'} | {
        role + '.' + field for role in ('records', 'coverage', 'control') for field in ('name', 'id')}
    values = {}
    try:
        for override in overrides:
            if type(override) is not str or '=' not in override:
                raise ValueError()
            key, value = override.split('=', 1)
            if key not in names or key in values or not value:
                raise ValueError()
            values[key] = value
        if set(values) != names:
            raise ValueError()
        def number(text):
            if re.fullmatch(r'[1-9][0-9]{0,15}', text) is None:
                raise ValueError()
            return numeric_id(int(text))
        repos = tuple(RepositoryRef(role, values['github.owner'], values[role+'.name'],
                                    number(values[role+'.id'])) for role in ('records', 'coverage', 'control'))
        return ProjectBinding(values['project.id'], number(values['github.owner_id']), repos)
    except Exception:
        raise ConfigError('Verify requires exact project, owner and three repository identities') from None


def prompt_recovery_keys():
    """Prompt only after repository authorization; never echo the secret input."""
    from getpass import getpass
    from getpass import GetPassWarning
    import warnings
    from dracla.records.credentials import unique_json

    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', GetPassWarning)
            raw = getpass('Recovery wrapping keys (JSON: generation to 64 hex characters): ')
        if len(raw) > 65536:
            raise ValueError()
        value = unique_json(raw.encode())
        if type(value) is not dict or not value or any(
                not generation or type(key) is not str or re.fullmatch(r'[0-9a-fA-F]{64}', key) is None
                for generation, key in value.items()):
            raise ValueError()
        return {generation: bytes.fromhex(key) for generation, key in value.items()}
    except Exception:
        raise ConfigError('Recovery material is unavailable or invalid') from None
