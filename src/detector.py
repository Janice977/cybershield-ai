from collections import defaultdict
from datetime import datetime, timedelta, timezone

WINDOW_MINUTES = 10
THRESHOLD = 5

def detect_bruteforce(events, threshold=THRESHOLD, window_minutes=WINDOW_MINUTES):
    """Detecta >= threshold falhas de login por IP numa janela móvel.

    Os resultados indicam suspeita, não confirmam um ataque.
    """
    grouped = defaultdict(list)
    for event in events:
        if event.get("event_type") != "login_failed":
            continue
        ip = event.get("src_ip")
        try:
            timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        except (ValueError, TypeError, KeyError):
            continue
        if not ip or timestamp.tzinfo is None:
            continue
        grouped[ip].append(timestamp.astimezone(timezone.utc))

    alerts = []
    for ip, times in grouped.items():
        times.sort()
        left = 0
        for right, current in enumerate(times):
            while current - times[left] > timedelta(minutes=window_minutes):
                left += 1
            count = right - left + 1
            if count >= threshold:
                alerts.append({
                    "rule_id": "CSAI-001",
                    "source_ip": ip,
                    "failed_attempts": count,
                    "window_minutes": window_minutes,
                    "first_seen": times[left].isoformat(),
                    "last_seen": current.isoformat(),
                    "severity": "high" if count >= threshold * 2 else "medium",
                    "description": "Possível tentativa de força bruta: múltiplas falhas de autenticação.",
                    "recommendation": "Validar com o proprietário do sistema, revisar logs e MFA; não bloquear automaticamente."
                })
                # somente primeiro alerta por IP para evitar notificações duplicadas
                break
    return alerts
