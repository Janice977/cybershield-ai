from pathlib import Path
from src.engine import read_events,detect,triage,normalize

def test_sample_all_four_rules():
    alerts=detect(read_events(Path(__file__).parent.parent/'data'/'sample_events.csv'))
    assert {'CSAI-001','CSAI-002','CSAI-003','CSAI-004'}<=set(a['rule_id'] for a in alerts)
def test_below_threshold():
    x=[{'timestamp':'2026-01-01T00:00:00Z','event_type':'login_failed','src_ip':'192.0.2.1'}]
    assert detect(normalize(x))==[]
def test_invalid_date_ignored():
    assert normalize([{'timestamp':'invalid','event_type':'login_failed'}])==[]
def test_triage_no_automatic_action():
    alert=detect(read_events(Path(__file__).parent.parent/'data'/'sample_events.csv'))[0]
    assert 'revisão humana' in triage(alert)['status']
