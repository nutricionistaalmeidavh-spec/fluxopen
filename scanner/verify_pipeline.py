"""Exercise the signed workflow/report contract without DNS or scanner execution."""
import argparse
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from security import verify_manifest
from scanner.runner import command


def build_report(payload, signature, secret, expected_id):
    manifest = verify_manifest(payload, signature, secret, resolve=False)
    if manifest['id'] != expected_id:
        raise ValueError('scan_id não corresponde ao manifesto assinado')
    from urllib.parse import urlsplit
    host = urlsplit(manifest['url']).hostname
    modules = []
    for tool in manifest['tools']:
        args = command(tool, manifest['url'], host)
        if not args or not all(isinstance(arg, str) for arg in args):
            raise ValueError('Contrato de argumentos inválido')
        modules.append({'tool': tool, 'status': 'skipped', 'seconds': 0,
                        'excerpt': 'TESTE DE INTEGRAÇÃO: assinatura e argumentos validados. Scanner não executado; nenhum acesso ao alvo.'})
    now = int(time.time())
    return {'id': manifest['id'], 'url': manifest['url'], 'mode': manifest['mode'],
            'started': now, 'ended': now, 'status': 'completed',
            'verification_only': True, 'modules': modules, 'findings': []}


def main():
    parser = argparse.ArgumentParser()
    for flag in ('payload', 'signature', 'expected-id', 'output'):
        parser.add_argument('--' + flag, required=True)
    args = parser.parse_args()
    report = build_report(args.payload, args.signature,
                          os.environ.get('SCAN_SIGNING_SECRET', ''), args.expected_id)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'report.json').write_text(json.dumps(report, ensure_ascii=False))
    print('Contrato assinado validado; nenhum scanner executado.')


if __name__ == '__main__':
    main()
