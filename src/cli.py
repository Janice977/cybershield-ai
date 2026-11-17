import argparse,json
from pathlib import Path
from .engine import read_events,detect,export_report

def main():
    parser=argparse.ArgumentParser(description='CyberShield AI — análise offline defensiva')
    parser.add_argument('input',help='Arquivo .csv ou .json')
    parser.add_argument('--output',default='reports/alertas.json')
    args=parser.parse_args()
    alerts=detect(read_events(args.input))
    path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(export_report(alerts),indent=2,ensure_ascii=False),encoding='utf-8')
    print(f'{len(alerts)} alertas. Relatório: {path}')
if __name__=='__main__':main()
