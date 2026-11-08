"""One-shot, fixed-scope GitHub Actions dispatch for operator-approved ArtiSys root."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from security import sign_manifest

SCAN_ID = "25d3aad623c8b467bf5c329b614ca01f"
URL = "https://artisys.dev/"
TOOLS = ("zap", "subfinder", "httpx", "katana", "testssl")
REQUEST = ROOT / ".fluxopen" / "requests" / "artisys-20261108.json"


def request_manifest(data, now=None):
    if not isinstance(data, dict) or set(data) != {"id", "url", "mode", "tools", "expires_utc"}:
        raise ValueError("Manifesto de operação inválido")
    if data["id"] != SCAN_ID or data["url"] != URL or data["mode"] != "passive":
        raise ValueError("A operação só autoriza a página inicial de artisys.dev")
    if data["tools"] != list(TOOLS):
        raise ValueError("Ferramentas diferentes do escopo conservador")
    try:
        expires = int(datetime.strptime(data["expires_utc"], "%Y-%m-%dT%H:%M:%SZ")
                      .replace(tzinfo=timezone.utc).timestamp())
    except (ValueError, TypeError):
        raise ValueError("Prazo inválido") from None
    instant = int(time.time()) if now is None else int(now)
    if expires < instant or expires > instant + 3 * 86400:
        raise ValueError("Autorização fora da janela")
    return dict(id=SCAN_ID,url=URL,tools=list(TOOLS),mode="passive",issued=instant,expires=min(instant+3600,expires))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    opts = parser.parse_args()
    data = json.loads(REQUEST.read_text())
    manifest = request_manifest(data)
    key = os.getenv("SCAN_SIGNING_SECRET", "")
    packed, signature = sign_manifest(manifest, key)
    output = Path(opts.output)
    output.mkdir(parents=True, exist_ok=True)
    args = [sys.executable, str(ROOT / "scanner" / "runner.py"),
            "--payload", packed, "--signature", signature,
            "--expected-id", SCAN_ID, "--output", str(output)]
    os.execvpe(sys.executable, args, dict(os.environ))


if __name__ == "__main__":
    main()
