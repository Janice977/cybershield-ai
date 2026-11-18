"""Dashboard educacional offline-first — dados autorizados somente."""
import csv, json, tempfile
from pathlib import Path
import pandas as pd
import streamlit as st
from src.engine import read_events, detect, triage, export_report
from src.anomaly import score_alerts
from src.version import VERSION
from src.upload_security import uploads_enabled, validate_upload, SAFE_UPLOAD_ERROR
st.set_page_config(page_title=f"CyberShield AI v{VERSION}",page_icon="🛡️",layout="wide")
st.title(f"🛡️ CyberShield AI v{VERSION} | Centro de triagem")
st.caption("Projeto colaborativo • regras explicáveis • dados locais • revisão humana")
st.warning("Demonstração educacional: nenhum alerta confirma um ataque. Não enviar dados pessoais ou confidenciais a hospedagens públicas.")
st.sidebar.header("Configuração")
upload_allowed = uploads_enabled()
if upload_allowed:
    mode = st.sidebar.radio("Fonte de dados", ["Exemplo sintético", "Enviar CSV/JSON"])
else:
    mode = "Exemplo sintético"
    st.sidebar.info("Demonstração pública: envio de arquivos desativado por segurança.")
fail=st.sidebar.slider("Falhas por janela",3,15,5)
spray=st.sidebar.slider("Contas diferentes por origem",2,12,4)
win=st.sidebar.slider("Janela (minutos)",1,60,10)
if mode=="Enviar CSV/JSON":
    up=st.file_uploader("Enviar CSV ou JSON autorizado (máximo 5 MB)",type=["csv","json"])
    if not up: st.info("Selecione um arquivo para começar.");st.stop()
    try:
        suffix = validate_upload(up.name, up.size)
    except ValueError as exc:
        st.error(str(exc))
        st.stop()
    with tempfile.TemporaryDirectory() as temp:
        path=Path(temp)/("entrada"+suffix)
        path.write_bytes(up.getvalue())
        try: events=read_events(path)
        except (ValueError, KeyError, UnicodeError, TypeError, OSError, csv.Error, json.JSONDecodeError):
            st.error(SAFE_UPLOAD_ERROR)
            st.stop()
else:
    events=read_events(Path(__file__).parent/'data'/'sample_events.csv')
alerts=detect(events,window_minutes=win,fail_threshold=fail,spray_accounts=spray)
low,med,high=st.columns(3)
low.metric("Eventos válidos",len(events));med.metric("Alertas",len(alerts));high.metric("Severidade alta",sum(a['severity']=='high' for a in alerts))
left,right=st.columns([2,1])
with left:
    st.subheader("Eventos por tipo")
    if events: st.bar_chart(pd.Series([e['event_type'] for e in events]).value_counts(),horizontal=True)
    else: st.info("Nenhum evento válido")
with right:
    st.subheader("Alertas por regra")
    if alerts: st.bar_chart(pd.Series([a['rule_id'] for a in alerts]).value_counts())
    else: st.info("Nenhum alerta detectado")
st.subheader("Investigação orientada")
if not alerts: st.success("Nenhuma regra disparou. Isso não garante ausência de ameaças.")
for a in alerts:
    with st.expander(f"{a['severity'].upper()} · {a['rule_id']} · {a['title']} · {a['entity']}"):
        t=triage(a)
        st.write(t['summary']);st.write(t['assessment'])
        st.caption(f"MITRE ATT&CK (hipótese): {a['mitre_attack']} — {t['status']}")
        for step in t['next_steps']: st.write('• '+step)
        st.info(t['privacy_check'])
        st.json(a['evidence'])
st.download_button("⬇️ Baixar relatório JSON",json.dumps(export_report(alerts),ensure_ascii=False,indent=2),file_name="cybershield_v322_relatorio.json",mime="application/json")
st.subheader("Dados carregados (até 100 linhas)")
if events: st.dataframe(pd.DataFrame([{**e,'timestamp':e['timestamp'].isoformat()} for e in events[:100]]),use_container_width=True)
st.caption("Não usa API externa nem modelo generativo. A pontuação experimental desta interface não equivale às métricas da avaliação independente v2.2.")

# Pontuação experimental: separada das regras e sem ações automatizadas.
st.subheader("IA experimental aplicada aos alertas")
st.caption("Modelo treinado em dados sintéticos de demonstração. A pontuação não representa probabilidade de ataque, nem reproduz a avaliação independente v2.2.")
if alerts:
    scores = score_alerts(alerts)
    st.dataframe(pd.DataFrame([{
        "Regra": x["rule_id"], "Entidade": x["entity"],
        "Pontuação de anomalia": x["anomaly_score"],
        "Anomalia (demo)": x["demo_anomaly"],
    } for x in scores]), use_container_width=True)
    st.download_button("⬇️ Baixar relatório com IA experimental", json.dumps({
        "rules": export_report(alerts), "ai_experimental": scores,
        "disclaimer": "IA experimental sobre alertas, treinamento sintético e validação humana obrigatória"
    }, ensure_ascii=False, indent=2), file_name="cybershield_v322_ia_relatorio.json", mime="application/json")
else:
    st.info("Sem alertas das regras para pontuar nesta demonstração.")
