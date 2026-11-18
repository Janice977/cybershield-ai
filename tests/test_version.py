from src.version import VERSION
from src.engine import export_report

def test_report_version_matches_release():
    assert export_report([])["version"] == VERSION
