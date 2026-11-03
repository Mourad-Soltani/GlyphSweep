# GlyphSweep

**Offline CLI for sweeping high-entropy secrets and forging strong ones.**

Detect potential leaked secrets via Shannon entropy + patterns, score any string's strength, and generate cryptographically secure secrets with policy controls. Stdlib-only Python. Perfect for pre-commit hooks, CI gates, or local audits.

Built by Mourad.Soltani

## Features

- Scan directories or files for high-entropy candidate secrets
- Score entropy, detect common weak patterns, estimate crack time
- Generate strong secrets (passwords, API keys, tokens) with custom length/charset
- JSON output for scripting and CI
- Exit non-zero on findings (configurable)
- Health tests included

## Quick Start

```bash
# Score a secret
python3 glyphsweep.py score "MyP@ssw0rd123"

# Generate a strong one
python3 glyphsweep.py generate --length 32 --symbols

# Scan a directory
python3 glyphsweep.py scan ./src --min-entropy 4.0 --json

# Run tests
python3 -m pytest tests/ -q
```

## Requirements

- Python 3.9+
- No external dependencies

## License

MIT — Built by Mourad.Soltani
