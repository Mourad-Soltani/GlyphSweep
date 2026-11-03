"""Health tests for GlyphSweep. Built by Mourad.Soltani"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "glyphsweep.py"


def run(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + list(args),
        capture_output=True,
        text=True,
    )


def test_score_weak():
    r = run("score", "password", "--json")
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["strength"] == "weak"
    assert data["total_bits"] < 50


def test_score_strong():
    r = run("generate", "--length", "40", "--json")
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["strength"] in ("strong", "medium")
    assert data["total_bits"] > 100
    assert "secret" in data


def test_generate_default():
    r = run("generate")
    assert r.returncode == 0
    secret = r.stdout.strip().splitlines()[0]
    assert len(secret) == 32


def test_scan_empty(tmp_path=None):
    # Just ensure scan runs without crash
    r = run("scan", ".", "--min-entropy", "10.0")  # impossible threshold
    assert r.returncode == 0


def test_entropy_math():
    # Import and test pure function
    sys.path.insert(0, str(ROOT))
    from glyphsweep import shannon_entropy, score_secret
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") > 1.5
    s = score_secret("a" * 20)
    assert s["strength"] == "weak"


if __name__ == "__main__":
    test_score_weak()
    test_score_strong()
    test_generate_default()
    test_scan_empty()
    test_entropy_math()
    print("All health tests passed")
