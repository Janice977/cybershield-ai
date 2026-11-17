# Arquitetura

CSV/JSON (somente operador) → validação e normalização (`read_events`) → regras por janelas e eventos (`detect`) → triagem determinística (`triage`) → JSON/Streamlit. Sem APIs externas, sem conectores OT e sem ações automáticas. MITRE ATT&CK é rótulo de referência, não evidência de atribuição. Regras são heurísticas e exigem investigação humana.
