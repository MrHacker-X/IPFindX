"""Configuration handling: defaults, optional JSON file, env overrides."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

__all__ = ["Config", "ConfigError", "load_config"]

DEFAULT_CONFIG_PATHS = [
    "ipfindx.json",
    os.path.expanduser("~/.config/ipfindx/config.json"),
]


class ConfigError(ValueError):
    """User-facing configuration error (missing file, bad JSON, invalid types)."""


@dataclass
class Config:
    # network behaviour
    timeout: float = 10.0
    rate_limit: float = 4.0          # geo API calls per second, per provider
    batch_workers: int = 8           # concurrent workers for batch scans
    max_targets: int = 4096          # hard limit on CIDR/range expansion
    providers: List[str] = field(default_factory=lambda: ["ip-api", "ipwhois", "ipinfo"])
    # threat intelligence
    abuseipdb_key: Optional[str] = None
    ipinfo_token: Optional[str] = None
    # recon
    recon_timeout: float = 2.0
    top_ports: List[int] = field(default_factory=lambda: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443])
    ping_count: int = 3
    max_trace_hops: int = 15
    # storage
    cache_enabled: bool = True
    cache_ttl: int = 3600            # seconds
    cache_db: str = os.path.join(str(Path.home()), ".cache", "ipfindx", "cache.sqlite3")
    history_db: str = os.path.join(str(Path.home()), ".local", "share", "ipfindx", "history.sqlite3")
    output_dir: str = "output-ipfindx"

    @classmethod
    def from_file(cls, path: str) -> "Config":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError as exc:
            raise ConfigError(f"config file not found: {path}") from exc
        except OSError as exc:
            raise ConfigError(f"could not read config file {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigError(f"malformed JSON in config file {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"config file {path} must contain a JSON object")
        cfg = cls()
        for key, value in data.items():
            if hasattr(cfg, key) and not key.startswith("_"):
                setattr(cfg, key, value)
        cfg.apply_env()
        cfg.validate()
        return cfg

    def apply_env(self) -> None:
        """Environment overrides: IPFINDX_ABUSEIPDB_KEY, IPFINDX_IPINFO_TOKEN, IPFINDX_TIMEOUT."""
        self.abuseipdb_key = os.environ.get("IPFINDX_ABUSEIPDB_KEY", self.abuseipdb_key)
        self.ipinfo_token = os.environ.get("IPFINDX_IPINFO_TOKEN", self.ipinfo_token)
        if os.environ.get("IPFINDX_TIMEOUT"):
            try:
                self.timeout = float(os.environ["IPFINDX_TIMEOUT"])
            except ValueError as exc:
                raise ConfigError(
                    f"IPFINDX_TIMEOUT must be a number, got {os.environ['IPFINDX_TIMEOUT']!r}"
                ) from exc

    def validate(self) -> None:
        """Validate important numeric / typed fields; raise ConfigError on bad input."""
        self.timeout = _require_number("timeout", self.timeout, minimum=0.1)
        self.rate_limit = _require_number("rate_limit", self.rate_limit, minimum=0.01)
        self.batch_workers = _require_int("batch_workers", self.batch_workers, minimum=1)
        self.max_targets = _require_int("max_targets", self.max_targets, minimum=1)
        self.cache_ttl = _require_int("cache_ttl", self.cache_ttl, minimum=0)
        self.recon_timeout = _require_number("recon_timeout", self.recon_timeout, minimum=0.1)
        self.ping_count = _require_int("ping_count", self.ping_count, minimum=1)
        self.max_trace_hops = _require_int("max_trace_hops", self.max_trace_hops, minimum=1)
        if not isinstance(self.providers, list) or not all(isinstance(p, str) for p in self.providers):
            raise ConfigError("providers must be a list of strings")
        if not isinstance(self.cache_enabled, bool):
            raise ConfigError("cache_enabled must be a boolean")
        if not isinstance(self.output_dir, str) or not self.output_dir:
            raise ConfigError("output_dir must be a non-empty string")


def _require_number(name: str, value: Any, minimum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} must be a number, got {type(value).__name__}")
    num = float(value)
    if num < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {num}")
    return num


def _require_int(name: str, value: Any, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        # allow whole floats like 8.0 from JSON
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        else:
            raise ConfigError(f"{name} must be an integer, got {type(value).__name__}")
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return int(value)


def load_config(explicit: Optional[str] = None) -> Config:
    """Load config from an explicit path, or probe the default locations.

    Explicit ``-c`` paths always fail loudly on missing/malformed files.
    Auto-discovered default paths also raise :class:`ConfigError` when the
    file exists but cannot be parsed — silent fallback only when no file is
    present.
    """
    if explicit:
        if not os.path.isfile(explicit):
            raise ConfigError(f"config file not found: {explicit}")
        return Config.from_file(explicit)
    candidates = [p for p in DEFAULT_CONFIG_PATHS if p and os.path.isfile(p)]
    if candidates:
        return Config.from_file(candidates[0])
    cfg = Config()
    cfg.apply_env()
    cfg.validate()
    return cfg
