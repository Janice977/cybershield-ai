"""Experimental alert-level anomaly scoring (NOT attack probability).

The reference model is fitted on synthetic benign-like alert feature vectors.
It is educational only; do not infer real-world performance from its output.
"""
from functools import lru_cache
import numpy as np
from sklearn.ensemble import IsolationForest

FEATURE_NAMES = ('evidence_count', 'severity_high', 'rule_auth', 'rule_ot', 'rule_malware')


def alert_features(alert):
    """Convert an existing rule alert into a fixed, inspectable feature vector."""
    rule = str(alert.get('rule_id', ''))
    return np.array([
        min(max(int(alert.get('evidence_count', 0)), 0), 100),
        int(alert.get('severity') == 'high'),
        int(rule in ('CSAI-001', 'CSAI-002')),
        int(rule == 'CSAI-003'),
        int(rule == 'CSAI-004'),
    ], dtype=float)


@lru_cache(maxsize=1)
def demo_model():
    """Deterministic synthetic reference only, not a trained SOC model."""
    rng = np.random.default_rng(42)
    n = 500
    evidence = np.clip(rng.poisson(2, n), 0, 100)
    high = rng.binomial(1, .15, n)
    categories = rng.choice(3, n, p=[.75, .15, .10])
    x = np.column_stack([evidence, high, categories == 0, categories == 1, categories == 2]).astype(float)
    return IsolationForest(n_estimators=100, contamination=.1, random_state=42).fit(x)


def score_alerts(alerts):
    """Return metadata aligned to alerts. Negative decision means demo anomaly."""
    if not alerts:
        return []
    matrix = np.vstack([alert_features(a) for a in alerts])
    model = demo_model()
    decision = model.decision_function(matrix)
    predicted = model.predict(matrix)
    return [{
        'rule_id': a.get('rule_id'),
        'entity': a.get('entity'),
        'anomaly_score': round(float(s), 5),
        'demo_anomaly': bool(p == -1),
        'features': dict(zip(FEATURE_NAMES, [float(v) for v in row])),
        'disclaimer': 'Score experimental, treinado com dados sintéticos; não é probabilidade nem confirmação de ataque.'
    } for a, row, s, p in zip(alerts, matrix, decision, predicted)]
