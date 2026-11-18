from src.anomaly import score_alerts, alert_features


def _alert():
    return {'rule_id':'CSAI-002', 'severity':'high', 'evidence_count':4, 'entity':'198.51.100.5'}


def test_empty():
    assert score_alerts([]) == []


def test_features():
    assert alert_features(_alert()).tolist() == [4.0, 1.0, 1.0, 0.0, 0.0]


def test_scoring_reproducible():
    first = score_alerts([_alert()])
    assert first == score_alerts([_alert()])
    assert isinstance(first[0]['demo_anomaly'], bool)
    assert 'sintéticos' in first[0]['disclaimer']
