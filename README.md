# CyberShield AI v3.0 — Comunidade 🛡️

Protótipo **defensivo e open source** (MIT), para análise de logs autorizados. Inclui painel Streamlit e notebook interativo Google Colab.

## Google Colab (mais simples)
Baixe e abra `CyberShield_AI_v3_Colab.ipynb` em [Google Colab](https://colab.research.google.com/), execute todas as células. O notebook é independente e usa dados sintéticos; exibe gráficos, controles de limiar e exportação JSON.

## Streamlit (computador ou hospedagem privada)
```bash
python -m pip install -r requirements.txt
python -m pytest -q
streamlit run app.py
```
O Colab gratuito **não hospeda um site Streamlit público por padrão**. Por segurança, não incluímos túnel público. Use o notebook interativo no Colab e o Streamlit em ambiente local/privado.

## Contribua
Leia `CONTRIBUTING.md`, `SECURITY.md` e `docs/ROADMAP.md`. Abrir issues, enviar pull requests, acrescentar testes e criar novas regras são formas de colaborar.

## Limitações
* Quatro regras heurísticas para demonstração; nenhuma detecção equivale a ataque comprovado.
* A camada de *machine learning* v2.2 é experimento separado; não está integrada à interface v3.
* Não envia dados a APIs; não executa bloqueios nem acessa sistemas OT reais.
* Utilize somente dados autorizados. Não publique registros contendo informações pessoais, tokens ou segredos.


## Notebook v3.1 (Google Colab)

Abra `CyberShield_AI_v3_1_Colab.ipynb` no Colab e execute todas as células. O notebook combina painel de regras com **avaliação separada** do Isolation Forest em dados sintéticos; não afirma que os alertas do painel foram classificados pelo modelo. Saídas: `cybershield_relatorio_v31.json` e `cybershield_avaliacao_v22.json`.
