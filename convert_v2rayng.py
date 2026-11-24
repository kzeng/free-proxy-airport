"""Convert a Clash/Mihomo YAML snapshot to a v2rayNG share-link subscription.

Usage: python convert_v2rayng.py input.yaml output/v2rayng.txt
The scheduled workflow runs this after generating clash.yaml, then publishes both files.
"""

from __future__ import annotations

import argparse
import base64
import json
from collections import Counter
from pathlib import Path
from urllib.parse import quote, urlencode

import yaml


def share_link(proxy: dict) -> str | None:
    kind = proxy.get("type")
    if kind not in {"ss", "vmess", "vless", "trojan", "hysteria2"}:
        return None
    host = str(proxy.get("server", ""))
    name = str(proxy.get("name", ""))
    try:
        port = int(proxy.get("port"))
    except (TypeError, ValueError):
        return None
    if not host or not name or not 1 <= port <= 65535:
        return None
    address = f"[{host}]" if ":" in host and not host.startswith("[") else host
    fragment = quote(name, safe="")

    if kind == "ss":
        method, password = proxy.get("cipher"), proxy.get("password")
        # SIP002 plugin/2022 variants need separate validation; do not silently lose options.
        if not method or not password or proxy.get("plugin") or str(method).startswith("2022-"):
            return None
        userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{address}:{port}#{fragment}"

    if kind == "vmess":
        if not proxy.get("uuid") or proxy.get("network", "tcp") not in {"tcp", "ws", "grpc"}:
            return None
        network = proxy.get("network", "tcp")
        ws = proxy.get("ws-opts") or {}
        grpc = proxy.get("grpc-opts") or {}
        if network == "ws":
            host_header = (ws.get("headers") or {}).get("Host", "")
            path = ws.get("path", "/")
        elif network == "grpc":
            host_header = grpc.get("grpc-mode", "")
            path = grpc.get("grpc-service-name", "")
        else:
            host_header, path = "", ""
        payload = {
            "v": "2", "ps": name, "add": host, "port": str(port),
            "id": str(proxy["uuid"]), "aid": str(proxy.get("alterId", 0)),
            "scy": str(proxy.get("cipher", "auto")), "net": network,
            "type": host_header if network == "grpc" else "none",
            "host": host_header if network != "grpc" else "", "path": path,
            "tls": "tls" if proxy.get("tls") else "", "sni": proxy.get("servername") or proxy.get("sni") or "",
            "fp": proxy.get("client-fingerprint", ""),
            "insecure": "1" if proxy.get("skip-cert-verify") else "0",
        }
        encoded = base64.b64encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()).decode()
        return f"vmess://{encoded}"

    credential = proxy.get("uuid") if kind == "vless" else proxy.get("password")
    if not credential:
        return None
    network = proxy.get("network", "tcp")
    if kind == "hysteria2":
        if network != "tcp" or proxy.get("obfs"):
            return None
        params = {"sni": proxy.get("sni") or proxy.get("servername") or ""}
        if proxy.get("skip-cert-verify"):
            params["insecure"] = "1"
    else:
        if network not in {"tcp", "ws", "grpc", "httpupgrade", "xhttp"}:
            return None
        reality = proxy.get("reality-opts") or {}
        params = {
            "type": network,
            "security": "reality" if reality else "tls" if kind == "trojan" or proxy.get("tls") else "none",
        }
        if kind == "vless":
            params["encryption"] = "none"
            if proxy.get("flow"):
                params["flow"] = proxy["flow"]
        if reality:
            if not reality.get("public-key"):
                return None
            params["pbk"] = reality["public-key"]
            params["sid"] = reality.get("short-id", "")
        for key, source in (("sni", proxy.get("servername") or proxy.get("sni")),
                            ("fp", proxy.get("client-fingerprint")),
                            ("alpn", ",".join(proxy["alpn"]) if isinstance(proxy.get("alpn"), list) else proxy.get("alpn"))):
            if source:
                params[key] = source
        if proxy.get("skip-cert-verify"):
            params["insecure"] = "1"
        if network in {"ws", "httpupgrade"}:
            opts = proxy.get(f"{network}-opts") or {}
            if opts.get("v2ray-http-upgrade"):
                return None
            params["path"] = opts.get("path", "/")
            host_header = (opts.get("headers") or {}).get("Host")
            if host_header:
                params["host"] = host_header
        elif network == "grpc":
            opts = proxy.get("grpc-opts") or {}
            params["serviceName"] = opts.get("grpc-service-name", "")
            if opts.get("grpc-mode"):
                params["mode"] = opts["grpc-mode"]
        elif network == "xhttp":
            opts = proxy.get("xhttp-opts") or {}
            params["path"] = opts.get("path", "/")
            for key in ("host", "mode"):
                if opts.get(key):
                    params[key] = opts[key]
    return f"{kind}://{quote(str(credential), safe='')}@{address}:{port}?{urlencode(params)}#{fragment}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = yaml.safe_load(args.input.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("proxies"), list):
        raise ValueError("input is not a Clash config with proxies")
    links, skipped = [], Counter()
    for proxy in data["proxies"]:
        link = share_link(proxy) if isinstance(proxy, dict) else None
        if link:
            links.append(link)
        else:
            skipped[proxy.get("type", "unknown") if isinstance(proxy, dict) else "unknown"] += 1
    if not links:
        raise ValueError("no convertible proxies; refusing to write empty subscription")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(links) + "\n", encoding="utf-8")
    print(f"converted={len(links)} skipped={dict(skipped)} source={args.input} output={args.output}")


if __name__ == "__main__":
    main()
