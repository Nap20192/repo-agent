"""OWASP R&D script: corpus inventory, gap analysis against our maps, snapshot diff."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import owasp_rnd as rnd


def _corpora(tmp: Path) -> Path:
    w = tmp / "owasp-wstg"
    (w / "checklists").mkdir(parents=True)
    (w / "checklists" / "checklist.json").write_text(json.dumps({"categories": {"Injection": {"id": "WSTG-INJT", "tests": [
        {"id": "WSTG-INJT-05", "name": "Testing for SQL Injection", "objectives": ["Identify SQL injection points."], "reference": "https://x/05"},
        {"id": "WSTG-INJT-99", "name": "Testing for Made Up", "objectives": [], "reference": ""}]}}}))
    (w / "document" / "4-Web_Application_Security_Testing" / "07-Input_Validation_Testing").mkdir(parents=True)
    (w / "document" / "4-Web_Application_Security_Testing" / "07-Input_Validation_Testing" / "05-Testing_for_SQL_Injection.md").write_text("# x")
    c = tmp / "owasp-CheatSheetSeries" / "cheatsheets"
    c.mkdir(parents=True)
    (c / "SQL_Injection_Prevention_Cheat_Sheet.md").write_text("# SQL Injection Prevention Cheat Sheet\n\nbody\n")
    (c / "Access_Control_Cheat_Sheet.md").write_text("# Access Control Cheat Sheet\n")
    t = tmp / "owasp-Top10" / "2021" / "docs" / "en"
    t.mkdir(parents=True)
    (t / "A03_2021-Injection.md").write_text("# A03:2021 – Injection\n\n## List of Mapped CWEs\n\n[CWE-89 SQL](https://cwe/89)\n\n[CWE-79 XSS](https://cwe/79)\n")
    a = tmp / "owasp-ASVS" / "5.0" / "en"
    a.mkdir(parents=True)
    (a / "0x15-V6-Authentication.md").write_text("# V6 Authentication\n\n## V6.2 Password Security\n\n| **6.2.1** | Verify that passwords are at least 8 characters. | 1 |\n")
    (a / "0x20-V11-Cryptography.md").write_text("# V11 Cryptography\n\n| **11.1.1** | Verify crypto inventory. | 2 |\n")
    return tmp


def test_inventory_reads_all_four_corpora(tmp_path):
    inv = rnd.inventory(_corpora(tmp_path))
    assert inv["wstg"]["WSTG-INJT-05"]["name"] == "Testing for SQL Injection" and inv["wstg"]["WSTG-INJT-05"]["category"] == "WSTG-INJT"
    assert inv["wstg_docs"] == {"07-Input_Validation_Testing": 1}
    assert set(inv["cheatsheets"]) == {"SQL_Injection_Prevention_Cheat_Sheet", "Access_Control_Cheat_Sheet"}
    assert inv["top10"]["A03:2021"] == {"name": "Injection", "cwes": ["CWE-89", "CWE-79"]}
    assert inv["asvs"]["6.2.1"] == {"chapter": "V6 Authentication", "level": 1, "text": "Verify that passwords are at least 8 characters."}
    assert rnd.inventory(tmp_path / "nowhere") == {"wstg": {}, "wstg_docs": {}, "cheatsheets": {}, "top10": {}, "asvs": {}}


def test_gaps_against_our_maps(tmp_path):
    inv = rnd.inventory(_corpora(tmp_path))
    ours = {
        "wstg_map": {"CWE-89": "WSTG-INJT-05", "CWE-22": "WSTG-ATHZ-01"},
        "cheat_map": {"CWE-89": "SQL_Injection_Prevention_Cheat_Sheet", "CWE-22": "File_Upload_Cheat_Sheet"},
        "top10_map": {"CWE-89": "A03:2021", "CWE-352": "A03:2021"},
        "skill_cwes": {"CWE-89"},
        "skills": {"sql-injection": "SQL injection testing", "authz-idor": "authorization"},
        "anchor_cwes": {"CWE-89": 5, "CWE-703": 3, "": 40},
    }
    g = rnd.gaps(inv, ours)
    assert g["anchors_no_wstg"] == [("CWE-703", 3)]
    assert g["wstg_no_skill"] == ["WSTG-INJT-99"]  # INJT-05 is covered via CWE-89 → sql-injection
    assert g["cheat_missing"] == ["File_Upload_Cheat_Sheet"] and g["cheat_available"] == 2
    assert g["top10_disagree"] == [("CWE-352", "A03:2021")]  # official A03 list has no CSRF
    assert g["asvs_zero"] == ["V11 Cryptography"]  # V6 matched by the authz/auth skill keyword


def test_diff_and_report(tmp_path):
    inv = rnd.inventory(_corpora(tmp_path))
    old = json.loads(json.dumps(inv))
    old["wstg"].pop("WSTG-INJT-99")
    d = rnd.diff(old, inv)
    assert d["wstg"]["new"] == ["WSTG-INJT-99"] and d["cheatsheets"]["new"] == []
    md = rnd.report(inv, d, rnd.gaps(inv, {"wstg_map": {}, "cheat_map": {}, "top10_map": {}, "skill_cwes": set(), "skills": {}, "anchor_cwes": {}}))
    assert "## Novelties" in md and "WSTG-INJT-99" in md and "## Gaps" in md and "| V11 Cryptography" in md
