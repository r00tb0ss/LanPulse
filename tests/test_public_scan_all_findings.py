from pathlib import Path

JS = (Path(__file__).resolve().parents[1] / "static" / "publicscan.js").read_text()


def test_all_findings_listed():
    assert "slice(0, 8)" not in JS
    assert "ps-find" in JS
