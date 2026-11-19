
# 🛡️ CyberShield AI v3.3.0 — Community

**Open Source Cybersecurity & AI-Powered Defensive Monitoring**

O CyberShield AI é um projeto open source desenvolvido em Python para apoiar a detecção de eventos suspeitos, a triagem de alertas e o aprendizado colaborativo em cibersegurança.

## 🚀 Demonstração online

**Acesse o aplicativo:**

https://cybershield-ai-community.streamlit.app/

## 🔐 Funcionalidades

- Detecção de possíveis ataques de força bruta e pulverização de senhas.
- Identificação de eventos suspeitos em ambientes OT simulados.
- Análise de eventos de malware informados nos registros.
- Pontuação experimental de anomalias com Isolation Forest.
- Painel interativo desenvolvido em Streamlit.
- Geração de relatórios JSON.
- Histórico real e reproduzível das etapas de processamento: leitura, validação, avaliação das regras, pontuação de IA experimental, triagem e relatório.
- Orientações defensivas para investigação SOC N1.

## 🤖 Inteligência Artificial

A versão 3.3.0 mantém a integração de um modelo experimental de aprendizado de máquina aos alertas produzidos pelo motor de regras.

O modelo utiliza dados sintéticos e suas pontuações não representam probabilidades de ataque.

A ferramenta não realiza bloqueios automáticos nem substitui a análise de profissionais de Segurança da Informação.

## 💻 Google Colab

O repositório disponibiliza notebooks para demonstrações e experimentos educacionais.

Os notebooks das versões anteriores permanecem disponíveis para consulta e reprodução dos experimentos.

## 🤝 Contribua com o projeto

Convidamos estudantes, pesquisadores, desenvolvedores e profissionais de cibersegurança a contribuir com novas funcionalidades, testes, documentação e melhorias.

Consulte:

- `CONTRIBUTING.md`
- `SECURITY.md`
- `docs/ROADMAP.md`

Utilize as abas **Issues**, **Pull Requests** e **Discussions** do GitHub para participar.

## ⚠️ Segurança e limitações

Este projeto é experimental e educacional. Não foi validado para proteção de ambientes de produção.

Utilize exclusivamente dados fictícios ou devidamente autorizados. Não envie dados pessoais, credenciais ou informações confidenciais ao aplicativo público.

**CyberShield AI — Tecnologia aberta, inteligência coletiva e cibersegurança para todos.**


## Controles de upload

A demonstração pública desabilita uploads por padrão. Para habilitar em **instalação privada controlada**, o operador precisa definir **todas** as variáveis: `CYBERSHIELD_DEPLOYMENT_MODE=private`, `CYBERSHIELD_ENABLE_UPLOADS=1` e `CYBERSHIELD_PUBLIC_DEMO=0`. Não habilite uploads no Streamlit Community Cloud. Essa configuração não substitui autenticação, isolamento, proteção de dados ou avaliação de segurança.

A automação `.github/workflows/dependency-audit.yml` executa `pip-audit` semanalmente, sob demanda e em alterações de dependências. Alertas devem ser triados; intervalos de versões não garantem reprodução bit a bit.

## 📋 Histórico de processamento (v3.3.0)

A aplicação Streamlit registra as **etapas realmente executadas** para os dados e parâmetros escolhidos, com contagens de registros, eventos válidos, alertas por regra e pontuações experimentais. O resultado aparece na seção **Histórico real de processamento** e pode ser exportado para JSON.

**Não se trata de uma API externa, monitoramento ao vivo ou integração com SIEM.** O histórico não registra horários fabricados, dados pessoais, endereços IP, nomes de contas nem conteúdo bruto dos eventos. Um novo ajuste nos controles do Streamlit provoca uma nova execução e atualiza os resultados.

O painel usa dados sintéticos por padrão; uploads seguem proibidos na demonstração pública. As orientações de triagem exigem revisão humana.
