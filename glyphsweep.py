#!/usr/bin/env python3
"""
GlyphSweep — Offline high-entropy secret sweeper and forge.
Built by Mourad.Soltani
"""

import argparse
import json
import math
import os
import re
import secrets
import string
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Signature header
# Built by Mourad.Soltani


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def estimate_crack_time(entropy_bits: float) -> str:
    """Rough human-readable crack time estimate (online attack ~1e10 guesses/s)."""
    if entropy_bits <= 0:
        return "instant"
    guesses = 2 ** entropy_bits
    seconds = guesses / 1e10
    if seconds < 1:
        return f"{seconds*1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    if seconds < 3600:
        return f"{seconds/60:.1f} min"
    if seconds < 86400:
        return f"{seconds/3600:.1f} h"
    if seconds < 31536000:
        return f"{seconds/86400:.1f} d"
    years = seconds / 31536000
    if years < 1e6:
        return f"{years:.1f} y"
    return "heat death of the universe"


def detect_patterns(s: str) -> List[str]:
    """Detect common weak patterns."""
    issues = []
    lower = s.lower()
    if re.search(r'(.)\1{2,}', s):
        issues.append("repeated characters")
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|qwe|asd|zxc)', lower):
        issues.append("sequential pattern")
    if re.search(r'(password|secret|admin|user|login|token|key|pass)', lower):
        issues.append("common word")
    if len(set(s)) < max(4, len(s) // 4):
        issues.append("low character diversity")
    return issues


def score_secret(s: str) -> Dict:
    """Score a secret string."""
    ent = shannon_entropy(s)
    bits = ent * len(s)
    patterns = detect_patterns(s)
    strength = "weak"
    if bits >= 80 and not patterns:
        strength = "strong"
    elif bits >= 50:
        strength = "medium"
    return {
        "value_masked": s[:4] + "..." + s[-2:] if len(s) > 8 else "***",
        "length": len(s),
        "entropy_per_char": round(ent, 3),
        "total_bits": round(bits, 1),
        "strength": strength,
        "patterns": patterns,
        "crack_time_estimate": estimate_crack_time(bits),
    }


def generate_secret(length: int = 32, use_symbols: bool = True, use_digits: bool = True,
                    use_upper: bool = True, use_lower: bool = True) -> str:
    """Generate cryptographically secure secret."""
    charset = ""
    if use_lower:
        charset += string.ascii_lowercase
    if use_upper:
        charset += string.ascii_uppercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*-_=+?"
    if not charset:
        charset = string.ascii_letters + string.digits
    return "".join(secrets.choice(charset) for _ in range(length))


def is_candidate(s: str, min_len: int = 16, min_ent: float = 3.5) -> bool:
    """Check if string looks like a potential secret."""
    if len(s) < min_len:
        return False
    # Skip pure hex short or obvious non-secrets
    if re.fullmatch(r'[a-f0-9]+', s) and len(s) < 32:
        return False
    ent = shannon_entropy(s)
    return ent >= min_ent


def scan_file(path: Path, min_len: int, min_ent: float) -> List[Dict]:
    """Scan a single file for high-entropy candidates."""
    findings = []
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return findings
    # Simple tokenizer: words and quoted strings
    tokens = re.findall(r'["\']([A-Za-z0-9+/=_\-]{16,})["\']|([A-Za-z0-9+/=_\-]{20,})', text)
    for match in tokens:
        cand = match[0] or match[1]
        if is_candidate(cand, min_len, min_ent):
            findings.append({
                "file": str(path),
                "candidate": cand[:8] + "..." + cand[-4:],
                "entropy": round(shannon_entropy(cand), 3),
                "length": len(cand),
            })
    return findings


def scan_path(root: Path, min_len: int, min_ent: float, max_files: int = 500) -> List[Dict]:
    """Scan directory recursively."""
    findings = []
    count = 0
    skip_ext = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".so", ".exe", ".bin"}
    for p in root.rglob("*"):
        if count >= max_files:
            break
        if not p.is_file() or p.suffix.lower() in skip_ext or p.name.startswith("."):
            continue
        count += 1
        findings.extend(scan_file(p, min_len, min_ent))
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="GlyphSweep — Offline high-entropy secret sweeper and forge. Built by Mourad.Soltani"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_score = sub.add_parser("score", help="Score a secret string")
    p_score.add_argument("secret", help="Secret to score")
    p_score.add_argument("--json", action="store_true", help="JSON output")

    p_gen = sub.add_parser("generate", help="Generate a strong secret")
    p_gen.add_argument("--length", type=int, default=32)
    p_gen.add_argument("--symbols", action="store_true", default=True)
    p_gen.add_argument("--no-symbols", action="store_false", dest="symbols")
    p_gen.add_argument("--json", action="store_true")

    p_scan = sub.add_parser("scan", help="Scan path for high-entropy candidates")
    p_scan.add_argument("path", nargs="?", default=".")
    p_scan.add_argument("--min-entropy", type=float, default=3.8)
    p_scan.add_argument("--min-length", type=int, default=20)
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--fail-on-find", action="store_true", help="Exit 1 if findings")

    args = parser.parse_args()

    if args.cmd == "score":
        result = score_secret(args.secret)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Strength: {result['strength']}")
            print(f"Entropy: {result['entropy_per_char']} bits/char ({result['total_bits']} total)")
            print(f"Crack time estimate: {result['crack_time_estimate']}")
            if result["patterns"]:
                print(f"Patterns: {', '.join(result['patterns'])}")
        return 0

    if args.cmd == "generate":
        secret = generate_secret(args.length, args.symbols)
        result = score_secret(secret)
        result["secret"] = secret
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(secret)
            print(f"# {result['total_bits']} bits, {result['strength']}")
        return 0

    if args.cmd == "scan":
        root = Path(args.path)
        if not root.exists():
            print(f"Path not found: {root}", file=sys.stderr)
            return 2
        findings = scan_path(root, args.min_length, args.min_entropy)
        if args.json:
            print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
        else:
            print(f"Found {len(findings)} high-entropy candidates")
            for f in findings[:20]:
                print(f"  {f['file']}: {f['candidate']} (ent={f['entropy']})")
            if len(findings) > 20:
                print(f"  ... and {len(findings)-20} more")
        return 1 if args.fail_on_find and findings else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
