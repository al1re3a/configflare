# ConfigFlare

**Find the dangerous MCP setting before an agent finds it.**

ConfigFlare is a zero-runtime-dependency Python CLI that audits MCP and coding-agent configuration for hardcoded credentials, missing commands, whole-disk access, insecure endpoints, malformed schemas, and permission-bypass flags.

```bash
pip install -e .
configflare . --fail-on high
```

## Why

Coding agents can execute commands and reach sensitive data. Their small JSON configuration files deserve the same review discipline as application code. ConfigFlare produces deterministic, secret-safe reports locally—no source or credentials are uploaded.

## Checks

- Invalid JSON and malformed `mcpServers` entries
- Missing or unavailable executables
- Hardcoded values under token, secret, password, and key fields
- Full filesystem roots passed to tools
- Permission and sandbox bypass arguments
- Non-local HTTP endpoints without TLS
- Stable fingerprints for CI deduplication

Credential values are never copied into findings.

## Output

```bash
configflare ~/.config --format text
configflare .mcp.json --format markdown
configflare . --format json --fail-on critical
```

Exit code `2` means the selected risk threshold was reached. Exit code `0` means the policy passed.

## CI

```yaml
- run: python -m pip install .
- run: configflare . --fail-on high
```

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

See `examples/unsafe.mcp.json` for an intentionally unsafe fixture.

## License

MIT
