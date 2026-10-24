"""
config.py -- configuration loading and logging shared by every PRESERVE module.

Role in the system
------------------
PRESERVE is a user-space memory-pressure governor. Every number that changes
its behaviour (cgroup limits, PSI thresholds, cost-model weights, arena size,
workload sizes) lives in ``preserve.conf`` so that experiments are reproduced
by editing one file rather than the code. This module is the single place
that reads that file, so no other module contains a magic number.

The file is parsed with :mod:`configparser` (INI syntax, standard library).
Two small conventions are added on top:

* ``{uid}`` inside a value expands to the uid of the *human* who started the
  program. Under ``sudo`` the effective uid is 0, so the real user's uid is
  taken from ``SUDO_UID``. This matters because systemd delegates a cgroup
  subtree per user (``user@<uid>.service``), and PRESERVE places its test
  cgroup inside that delegated subtree.
* Relative paths are resolved against the project root (the directory that
  holds ``preserve.conf``), never against the current working directory.
* **Named scenarios.** A section ``[scenario.<name>]`` overrides individual
  base values with keys of the form ``<section>.<key> = value``. For example,
  ``workloads.compute_working_set_mb = 300`` in ``[scenario.B]`` replaces
  ``[workloads] compute_working_set_mb`` when scenario B is selected. Every
  override must name a key that exists in the base sections, so a typo fails
  at start-up. ``[scenarios] default`` names the scenario used when none is
  given. Experiments therefore differ only in a small, readable set of
  overrides, and everything else is guaranteed identical.

Logging
-------
:func:`setup_logging` sends every record to stdout *and* to
``evidence/governor.log`` with a millisecond timestamp, so the console output
seen during a demo is preserved verbatim as evidence. When the governor runs
as root via sudo, the log file is handed back to the invoking user so that
later unprivileged runs can still append to it.

Standalone use::

    python3 src/config.py [--config PATH]     # print the parsed configuration
"""
from __future__ import annotations

import argparse
import configparser
import logging
import os
import re
import shlex
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "preserve.conf"

_SIZE_RE = re.compile(r"^\s*(\d+)\s*([KMGT]?)\s*$", re.IGNORECASE)
_SIZE_MULT = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}

LOGGER_NAME = "preserve"
SCENARIO_PREFIX = "scenario."


def parse_size(text: str) -> int | None:
    """Convert a cgroup-style size ("512M", "1G", "4096", "max") to bytes.

    ``max`` is the cgroup v2 spelling of "no limit" and is returned as None.
    """
    value = text.strip()
    if value.lower() == "max":
        return None
    match = _SIZE_RE.match(value)
    if not match:
        raise ValueError(f"not a size: {text!r} (expected e.g. 512M, 1G or max)")
    return int(match.group(1)) * _SIZE_MULT[match.group(2).upper()]


def format_size(nbytes: int | None) -> str:
    """Inverse of :func:`parse_size` for writing cgroup interface files."""
    return "max" if nbytes is None else str(int(nbytes))


def invoking_ids() -> tuple[int, int]:
    """Return (uid, gid) of the user who started the program.

    Under sudo the process runs with euid 0, but SUDO_UID/SUDO_GID record who
    asked for it. Outside sudo these are simply the real uid/gid.
    """
    uid = int(os.environ.get("SUDO_UID", os.getuid()))
    gid = int(os.environ.get("SUDO_GID", os.getgid()))
    return uid, gid


def give_to_invoking_user(path: Path) -> None:
    """chown a file we created as root back to the sudo caller (best effort).

    Evidence files (logs, CSVs) should stay readable and appendable by the
    student account after a privileged run.
    """
    if os.geteuid() != 0 or "SUDO_UID" not in os.environ:
        return
    uid, gid = invoking_ids()
    try:
        os.chown(path, uid, gid)
    except OSError:
        pass


class Config:
    """Typed, read-only view of ``preserve.conf``.

    Every getter raises ``KeyError`` naming the missing section/key, so a
    typo in the configuration fails loudly at start-up instead of silently
    falling back to a hidden default.
    """

    def __init__(self, path: str | Path | None = None, scenario: str | None = None) -> None:
        self.path = Path(path or DEFAULT_CONFIG_PATH).resolve()
        if not self.path.is_file():
            raise FileNotFoundError(f"configuration file not found: {self.path}")
        self.root = self.path.parent
        self._cp = configparser.ConfigParser(
            inline_comment_prefixes=("#",), interpolation=None
        )
        self._cp.read(self.path)
        self.scenario = scenario or self._cp.get("scenarios", "default", fallback=None)
        self.scenario_description = ""
        self.overrides: dict[tuple[str, str], str] = {}
        if self.scenario is not None:
            self._load_scenario(self.scenario)

    def _load_scenario(self, name: str) -> None:
        section = SCENARIO_PREFIX + name
        if not self._cp.has_section(section):
            raise KeyError(f"{self.path}: unknown scenario {name!r} (defined: {', '.join(self.scenarios())})")
        for dotted, value in self._cp.items(section):
            if dotted == "description":
                self.scenario_description = value.strip()
                continue
            base_section, _, key = dotted.partition(".")
            if not key or not self._cp.has_option(base_section, key):
                raise KeyError(f"{self.path}: [{section}] {dotted}: no base key [{base_section}] {key}")
            self.overrides[(base_section, key)] = value

    def scenarios(self) -> list[str]:
        return [s[len(SCENARIO_PREFIX):] for s in self._cp.sections() if s.startswith(SCENARIO_PREFIX)]

    # -- raw access -------------------------------------------------------
    def _raw(self, section: str, key: str) -> str:
        if (section, key) in self.overrides:
            return self.overrides[(section, key)]
        try:
            return self._cp.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            raise KeyError(f"{self.path}: missing [{section}] {key}") from None

    def sections(self) -> list[str]:
        return [s for s in self._cp.sections() if not s.startswith(SCENARIO_PREFIX)]

    def items(self, section: str) -> list[tuple[str, str]]:
        return [(k, self._raw(section, k)) for k, _ in self._cp.items(section)]

    # -- typed getters ----------------------------------------------------
    def get_str(self, section: str, key: str) -> str:
        uid, _ = invoking_ids()
        return self._raw(section, key).strip().replace("{uid}", str(uid))

    def get_int(self, section: str, key: str) -> int:
        return int(self.get_str(section, key))

    def get_float(self, section: str, key: str) -> float:
        return float(self.get_str(section, key))

    def get_bool(self, section: str, key: str) -> bool:
        value = self.get_str(section, key).lower()
        if value not in configparser.ConfigParser.BOOLEAN_STATES:
            raise ValueError(f"[{section}] {key}: not a boolean: {value!r}")
        return configparser.ConfigParser.BOOLEAN_STATES[value]

    def get_size(self, section: str, key: str) -> int | None:
        return parse_size(self.get_str(section, key))

    def get_path(self, section: str, key: str) -> Path:
        p = Path(self.get_str(section, key)).expanduser()
        return p if p.is_absolute() else (self.root / p)

    def get_args(self, section: str, key: str) -> list[str]:
        """Split a value into an argv list with shell quoting rules."""
        return shlex.split(self.get_str(section, key))


_logging_ready = False


def setup_logging(cfg: Config, to_file: bool = True) -> logging.Logger:
    """Configure the ``preserve`` logger hierarchy once per process.

    Modules obtain child loggers with ``logging.getLogger("preserve.<name>")``
    so each record shows which subsystem (sensor, capture, ...) produced it.
    """
    global _logging_ready
    root = logging.getLogger(LOGGER_NAME)
    if _logging_ready:
        return root
    root.setLevel(getattr(logging, cfg.get_str("logging", "level").upper()))
    root.propagate = False
    fmt = logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)
    if to_file:
        log_path = cfg.get_path("paths", "log_file")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
        give_to_invoking_user(log_path)
    _logging_ready = True
    return root


def _main() -> int:
    ap = argparse.ArgumentParser(description="Print the parsed PRESERVE configuration.")
    ap.add_argument("--config", default=None, help="path to preserve.conf")
    ap.add_argument("--scenario", default=None, help="show effective values for this scenario")
    args = ap.parse_args()
    cfg = Config(args.config, args.scenario)
    print(f"# {cfg.path}  (project root {cfg.root})")
    print(f"# scenario {cfg.scenario}: {cfg.scenario_description}  (available: {', '.join(cfg.scenarios())})")
    for section in cfg.sections():
        print(f"[{section}]")
        for key, _ in cfg.items(section):
            mark = "  <- scenario override" if (section, key) in cfg.overrides else ""
            print(f"  {key:28s} = {cfg.get_str(section, key)}{mark}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
