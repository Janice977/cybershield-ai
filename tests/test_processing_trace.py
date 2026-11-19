"""Trace must reflect executed operations without leaking event fields."""
import json
from pathlib import Path

from src.engine import detect, read_events, normalize, triage, export_report, RULES
from src.anomaly import score_alerts
from src.processing_trace import record_step
from src.version import VERSION

SAMPLE = Path(__file__).parent.parent / "data" / "sample_events.csv"


def test_sample_trace_matches_real_results():
    trace = []
    events = read_events(SAMPLE, trace=trace)
    alerts = detect(events, trace=trace)
    scores = score_alerts(alerts, trace=trace)
    for alert in alerts:
        triage(alert)
    record_step(trace, "Triagem", f"{len(alerts)} orientações de revisão humana produzidas.")
    export_report(alerts)
    record_step(trace, "Relatório", "Relatório JSON de regras gerado para esta execução.")

    assert len(events) == 12
    assert len(alerts) == 4
    assert len(scores) == 4
    assert len(trace) == 11
    assert [entry["etapa"] for entry in trace] == list(range(1, 12))
    assert trace[0]["fase"] == "Leitura"
    assert trace[1]["resultado"] == "12 evento(s) válido(s); 0 descartado(s)."
    for rule_id in RULES:
        log = next(x for x in trace if x["fase"] == f"Regra {rule_id}")
        assert log["resultado"] == f"Regra avaliada; {sum(a['rule_id'] == rule_id for a in alerts)} alerta(s) gerado(s)."
    assert trace[-3]["fase"] == "IA experimental"
    assert trace[-1]["fase"] == "Relatório"


def test_private_values_are_not_in_trace():
    trace = []
    events = read_events(SAMPLE, trace=trace)
    scores = score_alerts(detect(events, trace=trace), trace=trace)
    payload = json.dumps(trace, ensure_ascii=False)
    for private in ("192.0.2.10", "198.51.100.5", "admin", "daniel", "camara-fria-demo", "estacao-demo"):
        assert private not in payload
    assert scores


def test_trace_is_opt_in_and_detection_unchanged():
    events = read_events(SAMPLE)
    trace = []
    with_trace = detect(events, trace=trace)
    without_trace = detect(events)
    assert with_trace == without_trace
    assert len([x for x in trace if x["fase"].startswith("Regra")]) == 4


def test_below_threshold_records_zero_alerts():
    rows = normalize([{"timestamp":"2026-01-01T00:00:00Z", "event_type":"login_failed", "src_ip":"192.0.2.1", "username":"secret-person"}])
    trace=[]
    assert detect(rows, trace=trace) == []
    assert score_alerts([], trace=trace) == []
    assert any("0 alerta(s) no total" in x["resultado"] for x in trace)
    assert trace[-1]["resultado"] == "Nenhum alerta para pontuar; modelo não executado."
    assert "secret-person" not in json.dumps(trace)


def test_normalization_discards_bad_rows_and_counts(tmp_path):
    data=[{"timestamp":"invalid", "event_type":"login_failed", "username":"secret"},
          {"timestamp":"2026-11-17T10:00:00Z", "event_type":"login_failed", "username":"another-secret"}]
    path=tmp_path/"test.json"
    path.write_text(json.dumps(data),encoding="utf-8")
    trace=[]
    parsed=read_events(path,trace=trace)
    assert len(parsed)==1
    assert trace[0]["resultado"]=="2 registro(s) lido(s) do formato JSON."
    assert trace[1]["resultado"]=="1 evento(s) válido(s); 1 descartado(s)."
    assert "secret" not in json.dumps(trace)


def test_trace_will_not_write_if_not_requested():
    record_step(None, "Teste", "um passo")


def test_version_increment():
    assert VERSION == "3.3.0"
