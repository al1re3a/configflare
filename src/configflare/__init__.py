"""Security checks for MCP and coding-agent configuration."""

from .scanner import Finding, Report, scan_path

__all__ = ["Finding", "Report", "scan_path"]
__version__ = "1.0.0"
