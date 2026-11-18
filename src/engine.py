"""CyberShield AI: defensive, offline-first event analysis."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import csv, json, ipaddress
from pathlib import Path
from src.version import VERSION

RULES = {
 "CSAI-001": ("Possível força bruta", "T1110", "Validar tentativas com a equipe, revisar autenticação e MFA."),
 "CSAI-002": ("Possível pulverização de senhas", "T1110.003", "Confirmar contas-alvo, limites de autenticação e MFA."),
 "CSAI-003": ("Alteração suspeita de parâmetro OT", "T0836", "Acionar responsável OT; conferir manutenção autorizada e telemetria; NÃO alterar remotamente o equipamento."),
 "CSAI-004": ("Evento de malware informado", "T1204", "Isolar somente com autorização, preservar evidências e abrir investigação."),
}

def read_events(path):
    path=Path(path)
    if path.stat().st_size>5_000_000: raise ValueError("Arquivo maior que 5 MB")
    if path.suffix.lower()=='.csv':
        with path.open(encoding='utf-8-sig',newline='') as f: rows=list(csv.DictReader(f))
    elif path.suffix.lower()=='.json':
        rows=json.loads(path.read_text(encoding='utf-8'))
    else: raise ValueError("Formato suportado: CSV ou JSON")
    if not isinstance(rows,list) or len(rows)>20000: raise ValueError("Esperada lista de até 20.000 eventos")
    return normalize(rows)

def normalize(rows):
    out=[]
    for i,e in enumerate(rows):
        if not isinstance(e,dict): continue
        try:
            dt=datetime.fromisoformat(str(e['timestamp']).replace('Z','+00:00'))
            if dt.tzinfo is None: continue
            dt=dt.astimezone(timezone.utc)
        except (KeyError,ValueError,TypeError): continue
        out.append({"timestamp":dt,"event_type":str(e.get('event_type',''))[:80],
          "src_ip":str(e.get('src_ip',''))[:64],"username":str(e.get('username',''))[:100],
          "asset":str(e.get('asset',''))[:100],"value":str(e.get('value',''))[:100],
          "authorized":str(e.get('authorized','')).strip().lower()})
    return sorted(out,key=lambda e:e['timestamp'])

def alert(rule_id, anchor, evidence, severity, entity):
    name,technique,advice=RULES[rule_id]
    return {"id":f"{rule_id}-{len(evidence):03d}-{anchor.strftime('%Y%m%d%H%M%S')}",
      "rule_id":rule_id,"title":name,"severity":severity,"entity":entity,
      "timestamp":anchor.isoformat(),"evidence_count":len(evidence),
      "evidence":evidence[:10],"mitre_attack":technique,"recommendation":advice,
      "confidence":"heurística: requer validação humana"}

def detect(events,window_minutes=10,fail_threshold=5,spray_accounts=4):
    events=normalize(events) if events and isinstance(events[0].get('timestamp'),str) else events
    result=[]; logins=defaultdict(list)
    for e in events:
        if e['event_type']=='login_failed' and e['src_ip']:logins[e['src_ip']].append(e)
    for ip,rows in logins.items():
        left=0
        for right,e in enumerate(rows):
            while e['timestamp']-rows[left]['timestamp']>timedelta(minutes=window_minutes): left+=1
            w=rows[left:right+1]
            if len(w)>=fail_threshold:
                result.append(alert('CSAI-001',e['timestamp'],[{"timestamp":x['timestamp'].isoformat(),"username":x['username']} for x in w], 'high' if len(w)>=10 else 'medium',ip));break
        left=0
        for right,e in enumerate(rows):
            while e['timestamp']-rows[left]['timestamp']>timedelta(minutes=window_minutes):left+=1
            w=rows[left:right+1]
            if len(set(x['username'] for x in w if x['username']))>=spray_accounts:
                result.append(alert('CSAI-002',e['timestamp'],[{"timestamp":x['timestamp'].isoformat(),"username":x['username']} for x in w], 'high',ip));break
    for e in events:
        if e['event_type']=='ot_setpoint_change' and e['authorized']=='false':
            result.append(alert('CSAI-003',e['timestamp'],[{"asset":e['asset'],"value":e['value']}],'high',e['asset'] or 'OT'))
        if e['event_type']=='malware_detected':
            result.append(alert('CSAI-004',e['timestamp'],[{"asset":e['asset']}],'high',e['asset'] or 'endpoint'))
    return sorted(result,key=lambda x:(x['severity']!='high',x['timestamp']))

def triage(a):
    """Explainable deterministic agent; no external AI or automated remediation."""
    return {"summary":f"{a['title']} associado a {a['entity']}.",
     "assessment":f"{a['evidence_count']} evidência(s); severidade {a['severity']}. Indício, não confirmação.",
     "next_steps":["Preservar logs originais e registrar horários (UTC).",
      a['recommendation'],"Correlacionar com outras fontes antes de classificar como incidente confirmado.",
      "Escalar ao responsável e documentar decisões."],
     "privacy_check":"Verificar se dados pessoais foram afetados; não presumir vazamento ou obrigação automática de comunicar à ANPD.",
     "status":"triagem pendente de revisão humana"}

def export_report(alerts):
    return {"project":"CyberShield AI","version":VERSION,"data_origin":"Somente dados fornecidos pelo operador",
      "alerts": [{**a,"triage":triage(a)} for a in alerts],"caution":"Ferramenta de apoio, não valida ataque nem substitui equipe SOC/DPO."}
