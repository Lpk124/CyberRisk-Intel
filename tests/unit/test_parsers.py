from pathlib import Path

from cyberrisk_intel.ingestion.attack.mitre import parse_attack_stix
from cyberrisk_intel.ingestion.vulnerability.cve import parse_cve_v5
from cyberrisk_intel.ingestion.vulnerability.kev import parse_kev

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_parse_kev() -> None:
    rows = parse_kev((FIXTURES / "kev.json").read_bytes())
    assert rows[0]["cve_id"] == "CVE-2021-44228"
    assert rows[0]["known_ransomware_use"] is True


def test_parse_cve_v5_with_cna_and_adp() -> None:
    item = parse_cve_v5((FIXTURES / "cve.json").read_bytes())
    assert item.cve_id == "CVE-2024-9999"
    assert item.cvss_score == 7.5
    assert item.cwe_ids == ["CWE-79"]
    assert item.affected_products == ["Example / Widget"]


def test_parse_attack_stix() -> None:
    tactics, techniques = parse_attack_stix((FIXTURES / "attack.json").read_bytes())
    assert tactics[0]["attack_id"] == "TA0001"
    assert techniques[0]["attack_id"] == "T1190"
    assert techniques[0]["tactics"] == ["initial-access"]
