"""Run signed, low-rate scans in isolated Docker containers and normalize evidence."""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from security import verify_manifest, ACTIVE  # noqa: E402

IMAGES = {
    "zap": "ghcr.io/zaproxy/zaproxy:stable",
    "nuclei": "projectdiscovery/nuclei:latest",
    "subfinder": "projectdiscovery/subfinder:latest",
    "httpx": "projectdiscovery/httpx:latest",
    "katana": "projectdiscovery/katana:latest",
    "testssl": "ghcr.io/testssl/testssl.sh:latest",
    "nikto": "ghcr.io/sullo/nikto:latest",
    "ffuf": "fluxopen/misc:local",
    "feroxbuster": "fluxopen/misc:local",
    "sqlmap": "fluxopen/misc:local",
}
TIMEOUTS = {"zap": 360, "nuclei": 300, "subfinder": 120, "httpx": 90,
            "katana": 180, "ffuf": 150, "feroxbuster": 180,
            "sqlmap": 240, "testssl": 360, "nikto": 210}
MISC = {"ffuf", "feroxbuster", "sqlmap"}

def command(tool, target, host):
    """Arguments are lists, never shells; scope remains the single input host."""
    if tool == "zap":
        return ["zap-baseline.py", "-t", target, "-m", "1", "-I",
                "-J", "zap.json", "-r", "zap.html"]
    if tool == "nuclei":
        return ["-u", target, "-jsonl", "-o", "/out/nuclei.jsonl", "-rl", "2",
                "-c", "1", "-timeout", "8", "-retries", "0", "-ni",
                "-etags", "dos,stress,fuzz", "-severity", "medium,high,critical"]
    if tool == "subfinder":
        return ["-d", host, "-silent", "-o", "/out/subfinder.txt"]
    if tool == "httpx":
        return ["-u", target, "-json", "-silent", "-o", "/out/httpx.jsonl"]
    if tool == "katana":
        return ["-u", target, "-d", "1", "-rl", "2", "-c", "1", "-silent",
                "-jsonl", "-fs", "fqdn", "-o", "/out/katana.jsonl"]
    if tool == "ffuf":
        return ["ffuf", "-u", target.rstrip("/") + "/FUZZ",
                "-w", "/out/wordlist.txt", "-rate", "2", "-t", "1",
                "-timeout", "10", "-maxtime", "120", "-of", "json",
                "-o", "/out/ffuf.json", "-s"]
    if tool == "feroxbuster":
        return ["feroxbuster", "-u", target, "-w", "/out/wordlist.txt",
                "--rate-limit", "2", "--threads", "1", "--depth", "1",
                "--no-recursion", "--json", "--output", "/out/feroxbuster.jsonl",
                "--time-limit", "2m", "--quiet"]
    if tool == "sqlmap":
        return ["python", "/opt/sqlmap/sqlmap.py", "-u", target, "--batch",
                "--smart", "--level", "1", "--risk", "1", "--threads", "1",
                "--timeout", "8", "--retries", "0", "--technique", "BE",
                "--output-dir", "/out/sqlmap"]
    if tool == "testssl":
        return ["--fast", "--quiet", "--color", "0", "--jsonfile-pretty",
                "/out/testssl.json", target]
    if tool == "nikto":
        return ["-h", target, "-timeout", "10s", "-maxtime", "2m",
                "-output", "/tmp/nikto.json", "-Format", "json"]
    raise ValueError("Scanner não reconhecido")

def docker_args(tool, root):
    base = ["docker", "run", "--rm", "--init", "--pids-limit", "256",
            "--memory", "1024m", "--cpus", "1", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--network", "bridge"]
    if tool == "zap":
        base += ["-v", str(root) + ":/zap/wrk"]
    elif tool == "nikto":
        base += ["-v", str(root) + ":/tmp"]
    else:
        base += ["-v", str(root) + ":/out"]
    return base + [IMAGES[tool]]

def parse_jsonl(path, max_rows=100):
    if not path.exists():
        return []
    result = []
    with path.open(errors="replace") as handle:
        for line in handle:
            if len(result) >= max_rows:
                break
            try:
                result.append(json.loads(line))
            except (ValueError, json.JSONDecodeError):
                pass
    return result

def normalize_findings(tool, root):
    """Normalize structured findings and ZAP stdout fallback, never infer exploits."""
    findings = []
    if tool == "nuclei":
        for item in parse_jsonl(root / "nuclei.jsonl"):
            if not isinstance(item, dict):
                continue
            meta = item.get("info") or {}
            findings.append({"tool": tool, "rule_id": str(item.get("template-id", ""))[:120],
                "severity": str(meta.get("severity", "info")).lower(),
                "title": str(meta.get("name", item.get("template-id", "Nuclei")))[:180],
                "url": str(item.get("matched-at", ""))[:500],
                "description": str(item.get("template-id", ""))[:300]})
    elif tool == "zap":
        path = root / "zap.json"
        if path.exists():
            try:
                data = json.loads(path.read_text(errors="replace"))
                for site in data.get("site", []) if isinstance(data, dict) else []:
                    for alert in site.get("alerts", []):
                        if not isinstance(alert, dict):
                            continue
                        raw_instances = alert.get("instances", [])
                        instances = raw_instances if isinstance(raw_instances, list) else []
                        urls = [str(x.get("uri"))[:500] for x in instances[:12]
                                if isinstance(x, dict) and x.get("uri")]
                        try:
                            count = max(1, min(999, int(alert.get("count", len(instances) or 1))))
                        except (ValueError, TypeError):
                            count = max(1, len(instances))
                        risk = str(alert.get("riskdesc", alert.get("riskcode", "info"))).split(" ")[0].lower()
                        severity = {"0": "info", "1": "low", "2": "medium", "3": "high"}.get(risk, risk)
                        findings.append({"tool": "zap",
                            "rule_id": str(alert.get("pluginid", alert.get("alertRef", "")))[:60],
                            "severity": severity, "title": str(alert.get("name", ""))[:180],
                            "url": urls[0] if urls else str(site.get("@name", ""))[:500],
                            "urls": urls, "occurrences": count,
                            "description": str(alert.get("desc", ""))[:500]})
            except (ValueError, OSError):
                pass
        if not findings and (root / "zap.log").is_file():
            # ZAP report generation may fail even though baseline warnings are printed.
            # Preserve rule IDs and occurrences; warnings are NOT confirmed exploits.
            log = (root / "zap.log").read_text(errors="replace")[-60000:]
            sections = list(re.finditer(
                r"(?m)^\s*WARN-NEW:\s*(.+?)\s+\[(\d{5})\]\s+x\s+(\d+)\s*$", log))
            for index, match in enumerate(sections[:100]):
                following = log[match.end():sections[index+1].start()
                                if index+1 < len(sections) else len(log)]
                urls = re.findall(r"https?://[^\s()<>]+", following)[:12]
                findings.append({"tool": "zap", "rule_id": match.group(2),
                    "severity": "warning", "title": match.group(1)[:180],
                    "url": urls[0] if urls else "", "urls": urls,
                    "occurrences": min(999, int(match.group(3))),
                    "description": "Aviso do ZAP Baseline; requer validação técnica."})
    elif tool == "testssl" and (root / "testssl.json").exists():
        try:
            data = json.loads((root / "testssl.json").read_text(errors="replace"))
            entries = []
            if isinstance(data, list):
                entries = [(x, "") for x in data]
            elif isinstance(data, dict):
                # --jsonfile-pretty emits a nested scanResult containing section arrays.
                # clientProblem* are scanner/CLI issues, NOT target vulnerabilities.
                for endpoint in data.get("scanResult", []):
                    if not isinstance(endpoint, dict):
                        continue
                    host = str(endpoint.get("targetHost", ""))[:250]
                    for section, records in endpoint.items():
                        if isinstance(records, list) and section != "pretest":
                            entries.extend((x, host) for x in records)
            for item, host in entries:
                if not isinstance(item, dict):
                    continue
                severity = str(item.get("severity", "info")).lower()
                if severity not in ("low", "medium", "high", "critical", "warn", "warning"):
                    continue
                rule_id = str(item.get("id", ""))[:120]
                finding = str(item.get("finding", ""))[:400]
                if not finding or re.search(r"\b(?:not offered|not supported|not vulnerable|disabled)\b",
                                            finding, re.IGNORECASE):
                    continue
                if severity == "warn":
                    severity = "warning"
                findings.append({"tool": "testssl", "rule_id": rule_id,
                    "severity": severity, "title": rule_id,
                    "url": "https://" + host + "/" if host else "",
                    "description": finding})
        except (ValueError, OSError):
            pass
    return findings[:150]

def excerpt(root, tool, stdout):
    """Preview the tool's actual structured output, not just console chatter."""
    filenames = {
        "zap": "zap.json", "nuclei": "nuclei.jsonl",
        "subfinder": "subfinder.txt", "httpx": "httpx.jsonl",
        "katana": "katana.jsonl", "ffuf": "ffuf.json",
        "feroxbuster": "feroxbuster.jsonl", "testssl": "testssl.json",
        "nikto": "nikto.json",
    }
    filename = filenames.get(tool)
    preview = ""
    if filename:
        path = root / filename
        if path.exists() and path.is_file():
            try:
                with path.open("r", errors="replace") as stream:
                    preview = stream.read(8000)
            except OSError:
                pass
    log = (stdout or "")[-2000:]
    return (("Dados de " + filename + ":\\n" + preview + "\\n") if preview else "") + log

def execute(tool, target, host, root):
    began = time.time()
    if tool == "testssl" and urlsplit(target).scheme != "https":
        return dict(tool=tool, status="skipped", seconds=0, excerpt="TLS não se aplica a uma URL HTTP.")
    if tool == "sqlmap" and not urlsplit(target).query:
        return dict(tool=tool, status="skipped", seconds=0,
                    excerpt="Sem parâmetro de query na URL. SQLmap não tentará descobrir formulários ou outras URLs.")
    command_line = docker_args(tool, root) + command(tool, target, host)
    try:
        result = subprocess.run(command_line, cwd=ROOT, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=TIMEOUTS[tool], check=False, errors="replace")
        log = result.stdout[-60000:]
        (root / (tool + ".log")).write_text(log)
        status = "ok" if result.returncode == 0 else "warning"
        if result.returncode in (125, 126, 127):
            status = "error"
        metrics = {}
        if tool == "zap":
            count = re.search(r"(?<!\\w)WARN-NEW:\\s*(\\d+)(?=\\s|$)", log)
            if count:
                metrics["zap_warnings"] = int(count.group(1))
        return dict(tool=tool, status=status, code=result.returncode,
                    seconds=round(time.time() - began, 1),
                    excerpt=excerpt(root, tool, log), **metrics)
    except subprocess.TimeoutExpired:
        return dict(tool=tool, status="error", seconds=round(time.time() - began, 1),
                    excerpt="Tempo limite atingido; execução interrompida.")
    except (OSError, ValueError) as exc:
        return dict(tool=tool, status="error", seconds=round(time.time() - began, 1),
                    excerpt="Falha ao iniciar: " + str(exc)[:400])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-id", default="")
    args = parser.parse_args()
    secret = os.environ.get("SCAN_SIGNING_SECRET", "")
    manifest = verify_manifest(args.payload, args.signature, secret, resolve=True)
    if args.expected_id and args.expected_id != manifest["id"]:
        raise ValueError("scan_id não corresponde ao manifesto assinado")
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o777)  # Official images run under different non-root UIDs.
    (output / "wordlist.txt").write_text((ROOT / "scanner" / "wordlist.txt").read_text())
    started = int(time.time())
    report = {"id": manifest["id"], "url": manifest["url"], "mode": manifest["mode"],
              "started": started, "ended": None, "status": "running",
              "modules": [], "findings": []}
    try:
        if any(tool in MISC for tool in manifest["tools"]):
            built = subprocess.run(["docker", "build", "-t", "fluxopen/misc:local",
                                    "-f", "scanner/Dockerfile.misc", "."],
                                   cwd=ROOT, capture_output=True, text=True, timeout=600)
            if built.returncode:
                print("Erro ao construir imagem auxiliar:", built.stderr[-2000:], flush=True)
        host = urlsplit(manifest["url"]).hostname
        for tool in manifest["tools"]:
            # Repeat DNS check to limit stale resolver data before every tool.
            from security import normalize_target
            try:
                normalize_target(manifest["url"], resolve=True)
                result = execute(tool, manifest["url"], host, output)
            except ValueError as exc:
                result = dict(tool=tool, status="error", seconds=0, excerpt=str(exc))
            result["findings"] = normalize_findings(tool, output)
            report["findings"].extend(result.pop("findings"))
            report["modules"].append(result)
            print(tool + ": " + result["status"], flush=True)
            (output / "progress.json").write_text(json.dumps(report, ensure_ascii=False))
    finally:
        report["ended"] = int(time.time())
        successes = sum(m["status"] in ("ok", "warning", "skipped") for m in report["modules"])
        errors = sum(m["status"] == "error" for m in report["modules"])
        report["status"] = "failed" if not successes else ("completed_with_errors" if errors else "completed")
        report["findings"] = report["findings"][:200]
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] != "failed" else 1

if __name__ == "__main__":
    sys.exit(main())
