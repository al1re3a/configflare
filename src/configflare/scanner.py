from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

CONFIG_NAMES = {
    ".mcp.json", "mcp.json", "mcp-config.json", "claude_desktop_config.json",
    "cline_mcp_settings.json", "settings.json",
}
SEVERITY_WEIGHT = {"low": 5, "medium": 15, "high": 30, "critical": 50}
SECRET_KEY = re.compile(r"(?:token|secret|password|api[_-]?key|private[_-]?key)", re.I)
DANGEROUS_ARG = re.compile(
    r"(?:dangerously[-_]skip[-_]permissions|allow[-_]all|no[-_]sandbox|chmod\s+777)", re.I
)
PLACEHOLDER = re.compile(r"^(?:\$\{?[A-Z_][A-Z0-9_]*\}?|<[^>]+>|env:[A-Z_][A-Z0-9_]*)$")


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    location: str
    message: str
    fingerprint: str


@dataclass(frozen=True)
class Report:
    score: int
    level: str
    files_scanned: int
    servers_scanned: int
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [asdict(item) for item in self.findings]
        return data


def _fingerprint(rule: str, path: Path, location: str) -> str:
    raw = f"{rule}\0{path.as_posix()}\0{location}".encode()
    return hashlib.sha256(raw).hexdigest()[:12]


def _finding(rule: str, severity: str, path: Path, location: str, message: str) -> Finding:
    return Finding(rule, severity, path.as_posix(), location, message, _fingerprint(rule, path, location))


def discover_configs(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    found: list[Path] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in {".git", "node_modules", ".venv", "vendor"}]
        for name in files:
            path = Path(current, name)
            relative = path.relative_to(root).as_posix().lower()
            if name.lower() in CONFIG_NAMES or ("mcp" in relative and name.endswith(".json")):
                found.append(path)
    return sorted(found)


def _server_findings(path: Path, name: str, server: Any) -> list[Finding]:
    location = f"mcpServers.{name}"
    if not isinstance(server, dict):
        return [_finding("invalid-server", "high", path, location, "Server definition must be an object")]
    findings: list[Finding] = []
    command = server.get("command")
    if not isinstance(command, str) or not command.strip():
        findings.append(_finding("missing-command", "high", path, location, "Server has no executable command"))
    elif Path(command).is_absolute() and not Path(command).exists():
        findings.append(_finding("missing-executable", "high", path, f"{location}.command", "Absolute executable path does not exist"))
    elif not Path(command).is_absolute() and shutil.which(command) is None:
        findings.append(_finding("unknown-command", "medium", path, f"{location}.command", f"Command '{command}' is not on PATH"))

    args = server.get("args", [])
    if not isinstance(args, list):
        findings.append(_finding("invalid-args", "medium", path, f"{location}.args", "args must be an array"))
    else:
        for index, arg in enumerate(args):
            if DANGEROUS_ARG.search(str(arg)):
                findings.append(_finding("dangerous-flag", "critical", path, f"{location}.args[{index}]", "Permission or sandbox bypass flag detected"))
            if str(arg).strip() in {"/", "\\", "C:\\", "C:/"}:
                findings.append(_finding("broad-filesystem-root", "high", path, f"{location}.args[{index}]", "Server appears to receive an entire filesystem root"))

    env = server.get("env", {})
    if not isinstance(env, dict):
        findings.append(_finding("invalid-env", "medium", path, f"{location}.env", "env must be an object"))
    else:
        for key, value in env.items():
            text = str(value)
            if SECRET_KEY.search(str(key)) and text and not PLACEHOLDER.match(text):
                findings.append(_finding("hardcoded-secret", "critical", path, f"{location}.env.{key}", "Credential-like environment value is hardcoded; the value is not included in this report"))
            if text.startswith("http://") and "localhost" not in text and "127.0.0.1" not in text:
                findings.append(_finding("insecure-url", "high", path, f"{location}.env.{key}", "Remote endpoint uses unencrypted HTTP"))
    return findings


def scan_path(target: str | Path) -> Report:
    root = Path(target).resolve()
    files = discover_configs(root)
    findings: list[Finding] = []
    servers_scanned = 0
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            findings.append(_finding("invalid-json", "high", path, "$", f"Configuration cannot be parsed: {type(error).__name__}"))
            continue
        servers = data.get("mcpServers", {}) if isinstance(data, dict) else {}
        if not isinstance(servers, dict):
            findings.append(_finding("invalid-servers", "high", path, "mcpServers", "mcpServers must be an object"))
            continue
        servers_scanned += len(servers)
        for name, server in servers.items():
            findings.extend(_server_findings(path, str(name), server))
    score = min(100, sum(SEVERITY_WEIGHT[item.severity] for item in findings))
    severities = {item.severity for item in findings}
    level = "critical" if "critical" in severities or score >= 70 else "high" if "high" in severities or score >= 40 else "medium" if findings else "low"
    return Report(score, level, len(files), servers_scanned, tuple(findings))
