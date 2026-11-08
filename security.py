"""Strict, shared scan scope and manifest validation (stdlib only)."""
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import socket
import time
import urllib.parse

TOOLS = ("zap", "nuclei", "subfinder", "httpx", "katana", "ffuf",
         "feroxbuster", "sqlmap", "testssl", "nikto")
PASSIVE = ("zap", "subfinder", "httpx", "katana", "testssl")
ACTIVE = tuple(item for item in TOOLS if item not in PASSIVE)
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")


def normalize_target(value, resolve=True):
    """Only public HTTP(S) DNS hosts, no credentials, private IPs or arbitrary ports."""
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("URL inválida ou muito longa")
    if any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("Caracteres não permitidos na URL")
    try:
        parsed = urllib.parse.urlsplit(value)
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower()
        port = parsed.port
    except (ValueError, UnicodeError):
        raise ValueError("URL inválida") from None
    if parsed.scheme not in ("http", "https") or not host or not HOST_RE.fullmatch(host):
        raise ValueError("Informe URL HTTP(S) de um domínio público")
    if host.startswith((".", "-")) or ".." in host or "." not in host:
        raise ValueError("Domínio inválido")
    if parsed.username or parsed.password or parsed.fragment or "@" in parsed.netloc:
        raise ValueError("Credenciais e fragmentos não são aceitos na URL")
    if host.endswith((".local", ".internal", ".localhost", ".test", ".invalid", ".example")):
        raise ValueError("Domínio reservado ou interno")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Use um domínio, não um IP")
    if port not in (None, 80, 443, 8080, 8443):
        raise ValueError("Porta fora do conjunto permitido")
    if resolve:
        try:
            addresses = socket.getaddrinfo(host, port or (443 if parsed.scheme == "https" else 80),
                                           type=socket.SOCK_STREAM)
            ips = [ipaddress.ip_address(info[4][0]) for info in addresses]
        except (socket.gaierror, ValueError, OSError):
            raise ValueError("Não foi possível resolver o domínio público") from None
        if not ips or any(not ip.is_global for ip in ips):
            raise ValueError("O alvo resolve para rede privada ou não pública")
    authority = host + ((":" + str(port)) if port else "")
    return urllib.parse.urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, ""))


def validate_selection(tools, mode):
    if not isinstance(tools, list) or not tools or len(tools) > len(TOOLS):
        raise ValueError("Selecione ao menos uma ferramenta")
    if len(tools) != len(set(tools)) or any(tool not in TOOLS for tool in tools):
        raise ValueError("Ferramenta desconhecida ou repetida")
    if mode not in ("passive", "active"):
        raise ValueError("Modo inválido")
    if mode == "passive" and any(tool not in PASSIVE for tool in tools):
        raise ValueError("Ferramentas ativas exigem autorização extra")
    return tools


def sign_manifest(manifest, secret):
    if len(secret) < 32:
        raise ValueError("SCAN_SIGNING_SECRET exige ao menos 32 caracteres")
    raw = json.dumps(manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    packed = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    signature = hmac.new(secret.encode(), packed.encode(), hashlib.sha256).hexdigest()
    return packed, signature


def verify_manifest(packed, signature, secret, resolve=True, now=None):
    if len(secret) < 32 or not isinstance(packed, str) or len(packed) > 8192:
        raise ValueError("Manifesto inválido")
    expected = hmac.new(secret.encode(), packed.encode(), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        raise ValueError("Assinatura de autorização inválida")
    try:
        data = json.loads(base64.urlsafe_b64decode(packed + "=" * (-len(packed) % 4)))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Manifesto não é JSON válido") from None
    if not isinstance(data, dict) or set(data) != {"id", "url", "tools", "mode", "issued", "expires"}:
        raise ValueError("Campos do manifesto inválidos")
    instant = int(now if now is not None else time.time())
    if not isinstance(data["issued"], int) or not isinstance(data["expires"], int):
        raise ValueError("Prazo inválido")
    if data["issued"] > instant + 60 or data["expires"] < instant or data["expires"] - data["issued"] > 7200:
        raise ValueError("Autorização expirada ou inválida")
    if not isinstance(data["id"], str) or not re.fullmatch(r"[a-f0-9]{32}", data["id"]):
        raise ValueError("Identificador da auditoria inválido")
    validate_selection(data["tools"], data["mode"])
    if normalize_target(data["url"], resolve=resolve) != data["url"]:
        raise ValueError("URL não canônica")
    return data
