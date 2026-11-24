from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import stat
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
import yaml


VERSION = "v7"
OUTPUT_PATH = Path("output/clash.yaml")
TEST_URL = "http://www.gstatic.com/generate_204"
# kzeng added: 分组健康检查与切换策略，用于抑制节点抖动。
#   GROUP_INTERVAL  - 每隔多少秒探活一次（原值 120 过于激进，63 个节点两分钟测一轮太费电/流量）
#   GROUP_TOLERANCE - 延迟差在此毫秒数以内不切换节点（原值 0，差 1ms 就切，IP 会频繁跳）
#   GROUP_LAZY      - 只在该分组被实际使用时才探活，未使用的分组不再空转测速
GROUP_INTERVAL = 300
GROUP_TOLERANCE = 50
GROUP_LAZY = True
SOURCE_TIMEOUT = 25
LATENCY_TIMEOUT_MS = 5000
LATENCY_TEST_ATTEMPTS = 3
MIN_SUCCESSFUL_TESTS = 2
LATENCY_PROBE_INTERVAL = 1
MAX_CONFIG_CHECKS = 64
MAX_RETRIES = 3
MAX_WORKERS = int(os.getenv("FREE_PROXY_AIRPORT_MAX_WORKERS", "24"))
MAX_CANDIDATES = int(os.getenv("FREE_PROXY_AIRPORT_MAX_CANDIDATES", "0"))
MAX_OUTPUT_AGE = timedelta(hours=24)

SOURCE_GROUPS = [
    # kzeng added: openRunner 三个地址均返回 404，保留配置以便日后恢复。
    # {
    #     "name": "openRunner clash-freenode",
    #     "primary": "https://raw.githubusercontent.com/openRunner/clash-freenode/main/sub.yaml",
    #     "fallbacks": [
    #         "https://raw.githubusercontent.com/openRunner/clash-freenode/main/clash.yaml",
    #         "https://raw.githubusercontent.com/openrunner/clash-freenode/main/clash.yaml",
    #     ],
    # },
    {
        "name": "snakem982 proxypool",
        # kzeng added: 原 primary 返回 404，改用已验证可解析节点的备用地址。
        # "primary": "https://raw.githubusercontent.com/snakem982/proxypool/main/clash.yaml",
        "primary": "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml",
        "fallbacks": [
            "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml",
        ],
    },
    # kzeng added: Flikify 及两个备用地址均解析出 0 个节点，保留配置以便日后恢复。
    # {
    #     "name": "Flikify Free-Node",
    #     "primary": "https://raw.githubusercontent.com/Flikify/Free-Node/main/clash.yaml",
    #     "fallbacks": [
    #         "https://raw.githubusercontent.com/a2470982985/getNode/main/clash.yaml",
    #         "https://cdn.jsdelivr.net/gh/a2470982985/getNode@main/clash.yaml",
    #     ],
    # },
    {
        "name": "zhuhaiuk free-nodes",
        "primary": "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/clash_config.yaml",
        "fallbacks": [
            "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/extra_clash_config.yaml",
        ],
    },
    {
        "name": "kooker FreeSubsCheck",
        "primary": "https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/all.yaml",
        "fallbacks": [
            "https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/mihomo.yaml",
        ],
    },
    {
        "name": "free-node-hub",
        "primary": "https://raw.githubusercontent.com/liuweicool77-maker/free-node-hub/main/dist/free-proxies.yaml",
        "fallbacks": [],
    },
    {
        "name": "Billow001 free-nodes-sub",
        "primary": "https://raw.githubusercontent.com/Billow001/free-nodes-sub/main/FreeNodes001.yaml",
        "fallbacks": [],
    },
    {
        "name": "free-clash-v2ray GitHub Pages",
        # kzeng added: latest.yaml 返回 404；动态发现仍可找到当天的订阅文件。
        # "primary": "https://free-clash-v2ray.github.io/uploads/latest.yaml",
        "primary": "discover:free-clash-v2ray",
        "fallbacks": [],
    },
]

SUPPORTED_PROXY_TYPES = {
    "ss",
    "ssr",
    "vmess",
    "vless",
    "trojan",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "socks5",
    "http",
}

REQUIRED_GROUPS = (
    "AUTO-FAST",
    "HK-POOL",
    "JP-POOL",
    "US-POOL",
    "LOW-LATENCY-POOL",
    "AI-POOL",
    "FALLBACK",
    "PROXY",
)


@dataclass
class ProxyMetric:
    proxy: dict[str, Any]
    latency: int
    region: str
    health_score: float


def fetch_text(url: str, retries: int = MAX_RETRIES) -> str:
    headers = {
        "User-Agent": f"free-proxy-airport/{VERSION} (+https://github.com/)",
        "Accept": "text/plain, text/yaml, application/yaml, */*",
    }
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=SOURCE_TIMEOUT)
            response.raise_for_status()
            return response.content.decode("utf-8", errors="replace")
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError(f"failed to fetch {url}: {last_error}")


def maybe_base64_decode(text: str) -> str:
    compact = "".join(text.split())
    if not compact or len(compact) % 4 != 0:
        return text
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return text
    try:
        decoded = base64.b64decode(compact, validate=True).decode("utf-8")
    except Exception:
        return text
    return decoded if "proxies:" in decoded or "://" in decoded else text


def load_yaml_document(text: str) -> Any:
    try:
        return yaml.safe_load(maybe_base64_decode(text))
    except yaml.YAMLError as exc:
        print(f"[WARN] YAML document parse failed: {exc}")
        return None


def extract_proxy_block(text: str) -> list[Any]:
    lines = maybe_base64_decode(text).splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        if re.match(r"^proxies\s*:\s*$", line):
            start = index
            break
    if start is None:
        return []

    block: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line.startswith((" ", "\t", "-")) and re.match(r"^[A-Za-z0-9_-]+\s*:", line):
            break
        block.append(line)

    try:
        parsed = yaml.safe_load("proxies:\n" + "\n".join(block))
    except yaml.YAMLError as exc:
        print(f"[WARN] proxy block parse failed: {exc}")
        return []
    if isinstance(parsed, dict) and isinstance(parsed.get("proxies"), list):
        return parsed["proxies"]
    return []


def extract_proxies(text: str) -> list[dict[str, Any]]:
    document = load_yaml_document(text)
    if isinstance(document, dict):
        proxies = document.get("proxies", [])
    elif isinstance(document, list):
        proxies = document
    else:
        proxies = []

    if not proxies:
        proxies = extract_proxy_block(text)

    clean: list[dict[str, Any]] = []
    for proxy in proxies:
        if isinstance(proxy, dict):
            clean.append(dict(proxy))
    return clean


def collect_proxies() -> tuple[int, list[dict[str, Any]]]:
    collected: list[dict[str, Any]] = []
    for source in SOURCE_GROUPS:
        source_found: list[dict[str, Any]] = []
        for url in expand_source_urls(source):
            try:
                text = fetch_text(url)
                found = extract_proxies(text)
                print(f"[OK] source={source['name']} proxies={len(found)} url={url}")
                if found:
                    source_found.extend(found)
                    break
            except Exception as exc:
                print(f"[WARN] source={source['name']} skipped url={url} error={exc}")
        collected.extend(source_found)

    sanitized = sanitize_and_deduplicate(collected)
    if MAX_CANDIDATES > 0 and len(sanitized) > MAX_CANDIDATES:
        print(f"[WARN] limiting candidates from {len(sanitized)} to {MAX_CANDIDATES}")
        sanitized = sanitized[:MAX_CANDIDATES]
    return len(collected), sanitized


def expand_source_urls(source: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for item in [source["primary"], *source.get("fallbacks", [])]:
        if item == "discover:free-clash-v2ray":
            urls.extend(discover_free_clash_v2ray_urls())
        else:
            urls.append(str(item))
    return unique_ordered(urls)


def discover_free_clash_v2ray_urls() -> list[str]:
    readme_url = "https://raw.githubusercontent.com/free-clash-v2ray/free-clash-v2ray.github.io/main/README.md"
    try:
        text = fetch_text(readme_url)
    except Exception as exc:
        print(f"[WARN] free-clash-v2ray discovery failed: {exc}")
        return []
    pattern = r"https://free-clash-v2ray\.github\.io/uploads/\d{4}/\d{2}/[0-9]-\d{8}\.yaml"
    return unique_ordered(re.findall(pattern, text))[:8]


def unique_ordered(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def sanitize_and_deduplicate(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen_fingerprints: set[str] = set()
    seen_names: set[str] = set()
    result: list[dict[str, Any]] = []

    for index, raw in enumerate(proxies, start=1):
        proxy = normalize_proxy(raw, index)
        if not proxy:
            continue

        fingerprint = proxy_fingerprint(proxy)
        if fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)

        base_name = str(proxy["name"]).strip() or f"node-{index}"
        name = base_name
        suffix = 2
        while name in seen_names:
            name = f"{base_name}-{suffix}"
            suffix += 1
        proxy["name"] = name
        seen_names.add(name)
        result.append(proxy)
    return result


def normalize_proxy(raw: dict[str, Any], index: int) -> dict[str, Any] | None:
    proxy = {key: value for key, value in raw.items() if value is not None}
    proxy_type = str(proxy.get("type", "")).lower().strip()
    if proxy_type not in SUPPORTED_PROXY_TYPES:
        return None

    if proxy_type == "hy2":
        proxy_type = "hysteria2"
    proxy["type"] = proxy_type

    name = str(proxy.get("name", "")).strip() or f"node-{index}"
    server = str(proxy.get("server", "")).strip()
    if not server:
        return None

    try:
        port = int(proxy.get("port"))
    except Exception:
        return None
    if port <= 0 or port > 65535:
        return None

    proxy["name"] = name
    proxy["server"] = server
    proxy["port"] = port
    return proxy


def proxy_fingerprint(proxy: dict[str, Any]) -> str:
    important = {
        "type": proxy.get("type"),
        "server": proxy.get("server"),
        "port": proxy.get("port"),
        "uuid": proxy.get("uuid"),
        "password": proxy.get("password"),
        "cipher": proxy.get("cipher"),
        "network": proxy.get("network"),
    }
    payload = json.dumps(important, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def find_or_install_mihomo() -> Path:
    for name in ("mihomo", "clash-meta", "clash"):
        found = shutil.which(name)
        if found:
            print(f"[OK] using proxy engine: {found}")
            return Path(found)

    install_dir = Path(tempfile.gettempdir()) / "free-proxy-airport-mihomo"
    install_dir.mkdir(parents=True, exist_ok=True)
    binary = install_dir / ("mihomo.exe" if os.name == "nt" else "mihomo")
    if binary.exists():
        print(f"[OK] using cached proxy engine: {binary}")
        return binary

    url = select_mihomo_asset()
    print(f"[INFO] downloading proxy engine: {url}")
    archive = download_file(url, install_dir)
    extracted = extract_mihomo_binary(archive, install_dir)
    extracted.chmod(extracted.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    if extracted != binary:
        shutil.copy2(extracted, binary)
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return binary


def select_mihomo_asset() -> str:
    api_url = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
    headers = {"User-Agent": "free-proxy-airport", "Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.get(api_url, headers=headers, timeout=SOURCE_TIMEOUT)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict) or not isinstance(data.get("assets"), list):
        raise RuntimeError("Mihomo latest release API returned no asset list")
    assets = data["assets"]
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        os_token = "darwin"
    elif system == "linux":
        os_token = "linux"
    elif system == "windows":
        os_token = "windows"
    else:
        raise RuntimeError(f"unsupported OS for Mihomo download: {system}")

    if machine in {"x86_64", "amd64"}:
        arch_tokens = ["amd64-compatible", "amd64"]
    elif machine in {"arm64", "aarch64"}:
        arch_tokens = ["arm64"]
    else:
        raise RuntimeError(f"unsupported architecture for Mihomo download: {machine}")

    candidates: list[tuple[int, str]] = []
    for asset in assets:
        name = str(asset.get("name", "")).lower()
        download_url = str(asset.get("browser_download_url", ""))
        if not download_url:
            continue
        if os_token not in name:
            continue
        if not any(token in name for token in arch_tokens):
            continue
        if not (name.endswith(".gz") or name.endswith(".zip")):
            continue
        score = 0
        if "compatible" in name:
            score += 10
        if "go120" not in name:
            score += 2
        candidates.append((score, download_url))

    if not candidates:
        available = [str(asset.get("name")) for asset in assets if isinstance(asset, dict)]
        raise RuntimeError(
            f"no matching Mihomo asset for {system}/{machine} in release "
            f"{data.get('tag_name', 'unknown')}; available assets: {available}"
        )
    candidates.sort(reverse=True)
    return candidates[0][1]


def download_file(url: str, directory: Path) -> Path:
    target = directory / Path(url.split("?")[0]).name
    with requests.get(url, stream=True, timeout=SOURCE_TIMEOUT) as response:
        response.raise_for_status()
        with target.open("wb") as file:
            for chunk in response.iter_content(chunk_size=1024 * 512):
                if chunk:
                    file.write(chunk)
    return target


def extract_mihomo_binary(archive: Path, directory: Path) -> Path:
    if archive.suffix == ".gz" and not archive.name.endswith(".tar.gz"):
        target = directory / archive.name[:-3]
        with gzip.open(archive, "rb") as source, target.open("wb") as dest:
            shutil.copyfileobj(source, dest)
        return target

    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zipped:
            zipped.extractall(directory)
        for path in directory.rglob("*"):
            if path.is_file() and "mihomo" in path.name.lower():
                return path

    raise RuntimeError(f"unsupported Mihomo archive: {archive}")


def write_benchmark_config(path: Path, proxies: list[dict[str, Any]], controller_port: int) -> None:
    names = [str(proxy["name"]) for proxy in proxies]
    mixed_port = find_free_port()
    while mixed_port == controller_port:
        mixed_port = find_free_port()
    config = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": f"127.0.0.1:{controller_port}",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "BENCHMARK",
                "type": "select",
                "proxies": names or ["DIRECT"],
            }
        ],
        "rules": ["MATCH,BENCHMARK"],
    }
    path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")


def engine_log_summary(log_path: Path, proxies: list[dict[str, Any]]) -> str:
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    excerpt = lines if len(lines) <= 20 else lines[:10] + ["... (log truncated) ..."] + lines[-10:]
    summary = ("\n".join(excerpt) or "(no engine output)")[:4000]
    # Upstream node configs may contain credentials; never include them in CI logs.
    secrets: set[str] = set()

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() in {"password", "uuid", "private-key", "token", "auth-str"}:
                    if isinstance(item, str) and item:
                        secrets.add(item)
                else:
                    collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(proxies)
    for secret in sorted(secrets, key=len, reverse=True):
        summary = summary.replace(secret, "***")
    return summary


def check_benchmark_config(
    engine: Path, temp_dir: Path, proxies: list[dict[str, Any]], controller_port: int
) -> tuple[bool, str]:
    config_path = temp_dir / "benchmark.yaml"
    write_benchmark_config(config_path, proxies, controller_port)
    try:
        check = subprocess.run(
            [str(engine), "-t", "-d", str(temp_dir), "-f", str(config_path)],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Mihomo config check timed out with {len(proxies)} nodes") from exc
    if check.returncode == 0:
        return True, ""
    log_path = temp_dir / "config-check.log"
    log_path.write_text(check.stdout + check.stderr, encoding="utf-8")
    return False, engine_log_summary(log_path, proxies)


def filter_invalid_benchmark_proxies(
    engine: Path, temp_dir: Path, proxies: list[dict[str, Any]], controller_port: int
) -> list[dict[str, Any]]:
    checks = 0

    def check(items: list[dict[str, Any]]) -> tuple[bool, str]:
        nonlocal checks
        checks += 1
        if checks > MAX_CONFIG_CHECKS:
            raise RuntimeError(f"Mihomo config isolation exceeded {MAX_CONFIG_CHECKS} checks; preserving published output")
        return check_benchmark_config(engine, temp_dir, items, controller_port)

    valid, error = check(proxies)
    if valid:
        print(f"[INFO] Mihomo config check passed for {len(proxies)} candidates")
        return proxies

    # An engine/environment failure also occurs with zero nodes: don't blame the sources.
    baseline_valid, baseline_error = check([])
    if not baseline_valid:
        raise RuntimeError(f"Mihomo cannot load an empty benchmark config:\n{baseline_error}")

    def isolate(items: list[dict[str, Any]], known_error: str | None = None) -> list[dict[str, Any]]:
        if known_error is None:
            valid, error = check(items)
        else:
            valid, error = False, known_error
        if valid:
            return items
        if len(items) == 1:
            fingerprint = proxy_fingerprint(items[0])[:12]
            print(f"[DROP] invalid Mihomo config for node fingerprint={fingerprint}: {error}")
            return []
        middle = len(items) // 2
        return isolate(items[:middle]) + isolate(items[middle:])

    print(f"[WARN] Mihomo rejected the candidate config; isolating invalid nodes:\n{error}")
    filtered = isolate(proxies, error)
    if not filtered:
        raise RuntimeError("Mihomo rejected all candidate nodes; keeping published subscription unchanged")
    valid, error = check(filtered)
    if not valid:
        raise RuntimeError(f"Mihomo still rejects combined candidate config:\n{error}")
    print(f"[WARN] removed {len(proxies) - len(filtered)} invalid nodes before benchmarking ({checks} config checks)")
    return filtered


def wait_for_controller(
    controller_url: str, process: subprocess.Popen[str], log_path: Path, proxies: list[dict[str, Any]]
) -> None:
    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError(
                f"Mihomo exited before controller became ready (exit {process.returncode}):\n"
                f"{engine_log_summary(log_path, proxies)}"
            )
        try:
            response = requests.get(f"{controller_url}/version", timeout=1)
            if response.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"Mihomo controller did not become ready:\n{engine_log_summary(log_path, proxies)}")


def benchmark_proxies(proxies: list[dict[str, Any]]) -> list[ProxyMetric]:
    if not proxies:
        return []

    engine = find_or_install_mihomo()
    try:
        version = subprocess.run(
            [str(engine), "-v"], capture_output=True, text=True, errors="replace", timeout=10, check=False
        )
        version_line = (version.stdout + version.stderr).splitlines()
        version_label = version_line[0][:160] if version_line else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        version_label = "unavailable"
    print(f"[INFO] Mihomo engine={engine} version={version_label}", flush=True)
    with tempfile.TemporaryDirectory(prefix="free-proxy-airport-") as temp_name:
        temp_dir = Path(temp_name)
        config_path = temp_dir / "benchmark.yaml"
        controller_port = find_free_port()
        controller_url = f"http://127.0.0.1:{controller_port}"
        started = time.monotonic()
        print(f"[INFO] preflighting {len(proxies)} candidates with Mihomo config test", flush=True)
        proxies = filter_invalid_benchmark_proxies(engine, temp_dir, proxies, controller_port)
        print(f"[INFO] preflight completed in {time.monotonic() - started:.1f}s", flush=True)

        log_path = temp_dir / "mihomo.log"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [str(engine), "-d", str(temp_dir), "-f", str(config_path)],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                wait_for_controller(controller_url, process, log_path, proxies)
                print(f"[INFO] Mihomo controller ready on localhost:{controller_port}", flush=True)
                metrics = run_delay_tests(controller_url, proxies)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
        print(f"[INFO] benchmark finished in {time.monotonic() - started:.1f}s; kept={len(metrics)}/{len(proxies)}", flush=True)
        return metrics


def run_delay_tests(controller_url: str, proxies: list[dict[str, Any]]) -> list[ProxyMetric]:
    workers = max(1, min(MAX_WORKERS, len(proxies)))
    metrics: list[ProxyMetric] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(test_single_proxy, controller_url, proxy): proxy
            for proxy in proxies
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            proxy = futures[future]
            try:
                metric = future.result()
            except Exception as exc:
                print(f"[DROP] {proxy.get('name')} failed: {exc}")
                continue
            if metric:
                metrics.append(metric)
            if completed % 25 == 0 or completed == len(futures):
                print(f"[INFO] tested {completed}/{len(futures)} kept={len(metrics)}")
    metrics.sort(key=lambda item: item.health_score, reverse=True)
    return metrics


def test_single_proxy(controller_url: str, proxy: dict[str, Any]) -> ProxyMetric | None:
    name = str(proxy["name"])
    url = (
        f"{controller_url}/proxies/{quote(name, safe='')}/delay"
        f"?timeout={LATENCY_TIMEOUT_MS}&url={quote(TEST_URL, safe='')}"
    )
    latencies: list[int] = []
    attempts = 0
    for attempt in range(LATENCY_TEST_ATTEMPTS):
        if attempt:
            time.sleep(LATENCY_PROBE_INTERVAL)
        attempts += 1
        try:
            response = requests.get(url, timeout=(LATENCY_TIMEOUT_MS / 1000) + 3)
            if response.status_code == 200:
                latency = int(response.json().get("delay", 0))
                if 0 < latency <= LATENCY_TIMEOUT_MS:
                    latencies.append(latency)
        except (requests.RequestException, ValueError, TypeError, KeyError, AttributeError):
            pass
        if len(latencies) >= MIN_SUCCESSFUL_TESTS:
            break
        if LATENCY_TEST_ATTEMPTS - attempts + len(latencies) < MIN_SUCCESSFUL_TESTS:
            break

    if len(latencies) < MIN_SUCCESSFUL_TESTS:
        return None
    latency = round(statistics.median(latencies))
    region = detect_region(name)
    score = health_score(latency, region, len(latencies) / attempts)
    return ProxyMetric(proxy=proxy, latency=latency, region=region, health_score=score)


def detect_region(name: str) -> str:
    text = name.lower()
    patterns = {
        "HK": (
            "regex:\\bhk\\b",
            "hong kong",
            "\\u9999\\u6e2f",
            "\U0001f1ed\U0001f1f0",
        ),
        "JP": (
            "regex:\\bjp\\b",
            "japan",
            "\\u65e5\\u672c",
            "\U0001f1ef\U0001f1f5",
        ),
        "US": (
            "regex:\\bus\\b",
            "regex:\\busa\\b",
            "united states",
            "america",
            "\\u7f8e\\u56fd",
            "\\u7f8e\\u570b",
            "\U0001f1fa\U0001f1f8",
        ),
        "SG": (
            "regex:\\bsg\\b",
            "singapore",
            "\\u65b0\\u52a0\\u5761",
            "\U0001f1f8\U0001f1ec",
        ),
    }
    for region, tokens in patterns.items():
        for token in tokens:
            if token.startswith("regex:"):
                if re.search(token.removeprefix("regex:"), text):
                    return region
                continue
            if token.startswith("\\u"):
                token = token.encode("utf-8").decode("unicode_escape")
            if token in text:
                return region
    return "OTHER"


def region_bonus(region: str) -> int:
    if region in {"HK", "SG", "JP"}:
        return 3
    if region == "US":
        return 2
    return 1


def health_score(latency: int, region: str, success_rate: float) -> float:
    # Comparable 0–1 components: measured latency matters most; no name-based fake stability.
    latency_score = 1 / (1 + latency / 500)
    return 0.7 * latency_score + 0.25 * success_rate + 0.05 * region_bonus(region) / 3


def low_latency_pool(metrics: list[ProxyMetric]) -> list[str]:
    if not metrics:
        return ["DIRECT"]
    ordered = sorted(metrics, key=lambda item: (item.latency, -item.health_score))
    size = min(max(3, len(ordered) // 5), 30, len(ordered))
    return [item.proxy["name"] for item in ordered[:size]]


def names_for_region(metrics: list[ProxyMetric], region: str) -> list[str]:
    names = [item.proxy["name"] for item in metrics if item.region == region]
    if names:
        return names
    if metrics:
        return [item.proxy["name"] for item in metrics[: min(5, len(metrics))]]
    return ["DIRECT"]


def build_config(metrics: list[ProxyMetric]) -> dict[str, Any]:
    if not metrics:
        raise ValueError("cannot build a subscription without tested live nodes")

    proxies = [item.proxy for item in metrics]
    all_names = [item.proxy["name"] for item in metrics]
    hk_names = names_for_region(metrics, "HK")
    jp_names = names_for_region(metrics, "JP")
    us_names = names_for_region(metrics, "US")
    low_latency_names = low_latency_pool(metrics)

    return {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "unified-delay": True,
        "tcp-concurrent": True,
        "global-client-fingerprint": "chrome",
        "generated-by": f"free-proxy-airport-{VERSION}",
        "generated-at": datetime.now(timezone.utc).isoformat(),
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "AUTO-FAST",
                "type": "url-test",
                "proxies": all_names,
                "url": TEST_URL,
                # kzeng added: 300s 探活 / 50ms 容差 / 懒测
                "interval": GROUP_INTERVAL,
                "tolerance": GROUP_TOLERANCE,
                "lazy": GROUP_LAZY,
            },
            {
                "name": "HK-POOL",
                "type": "url-test",
                "proxies": hk_names,
                "url": TEST_URL,
                # kzeng added: 300s 探活 / 50ms 容差 / 懒测
                "interval": GROUP_INTERVAL,
                "tolerance": GROUP_TOLERANCE,
                "lazy": GROUP_LAZY,
            },
            {
                "name": "JP-POOL",
                "type": "url-test",
                "proxies": jp_names,
                "url": TEST_URL,
                # kzeng added: 300s 探活 / 50ms 容差 / 懒测
                "interval": GROUP_INTERVAL,
                "tolerance": GROUP_TOLERANCE,
                "lazy": GROUP_LAZY,
            },
            {
                "name": "US-POOL",
                "type": "url-test",
                "proxies": us_names,
                "url": TEST_URL,
                # kzeng added: 300s 探活 / 50ms 容差 / 懒测
                "interval": GROUP_INTERVAL,
                "tolerance": GROUP_TOLERANCE,
                "lazy": GROUP_LAZY,
            },
            {
                "name": "LOW-LATENCY-POOL",
                "type": "url-test",
                "proxies": low_latency_names,
                "url": TEST_URL,
                # kzeng added: 300s 探活 / 50ms 容差 / 懒测
                "interval": GROUP_INTERVAL,
                "tolerance": GROUP_TOLERANCE,
                "lazy": GROUP_LAZY,
            },
            {
                # Backward compatibility for clients selecting the old group name.
                "name": "AI-POOL",
                "type": "select",
                "proxies": ["LOW-LATENCY-POOL"],
            },
            {
                "name": "FALLBACK",
                "type": "fallback",
                "proxies": ["AUTO-FAST", "HK-POOL", "JP-POOL", "US-POOL"],
                "url": TEST_URL,
                # kzeng added: 300s 探活 / 懒测；fallback 按顺序取第一个可用，不适用 tolerance
                "interval": GROUP_INTERVAL,
                "lazy": GROUP_LAZY,
            },
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["AUTO-FAST", "FALLBACK"],
            },
        ],
        "rules": [
            "DOMAIN-SUFFIX,openai.com,LOW-LATENCY-POOL",
            "DOMAIN-SUFFIX,chatgpt.com,LOW-LATENCY-POOL",
            "DOMAIN-SUFFIX,claude.ai,LOW-LATENCY-POOL",
            "DOMAIN-SUFFIX,anthropic.com,LOW-LATENCY-POOL",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY",
        ],
    }


def write_config(config: dict[str, Any]) -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        yaml.safe_dump(config, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def validate_config(config: dict[str, Any]) -> None:
    if not isinstance(config.get("proxies"), list) or not config["proxies"]:
        raise RuntimeError("generated config has no proxies")
    if any(
        not isinstance(proxy, dict) or proxy.get("type") not in SUPPORTED_PROXY_TYPES
        for proxy in config["proxies"]
    ):
        raise RuntimeError("generated config contains a non-proxy fallback or unsupported node")
    try:
        generated_at = datetime.fromisoformat(config["generated-at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("generated config has no valid generated-at timestamp") from exc
    if generated_at.tzinfo is None:
        raise RuntimeError("generated-at must include a timezone")
    age = datetime.now(timezone.utc) - generated_at
    if age > MAX_OUTPUT_AGE or age < -timedelta(minutes=5):
        raise RuntimeError("generated config timestamp is stale or too far in the future")
    groups = config.get("proxy-groups", [])
    group_names = {group.get("name") for group in groups if isinstance(group, dict)}
    missing = [name for name in REQUIRED_GROUPS if name not in group_names]
    if missing:
        raise RuntimeError(f"generated config missing groups: {missing}")
    rules = config.get("rules", [])
    for rule in (
        "DOMAIN-SUFFIX,openai.com,LOW-LATENCY-POOL",
        "DOMAIN-SUFFIX,chatgpt.com,LOW-LATENCY-POOL",
        "DOMAIN-SUFFIX,claude.ai,LOW-LATENCY-POOL",
        "DOMAIN-SUFFIX,anthropic.com,LOW-LATENCY-POOL",
        "GEOIP,CN,DIRECT",
        "MATCH,PROXY",
    ):
        if rule not in rules:
            raise RuntimeError(f"generated config missing rule: {rule}")


def print_summary(
    total_nodes: int,
    candidates: int,
    metrics: list[ProxyMetric],
    passed_latency_test: int,
    output_source: str,
) -> None:
    hk_count = sum(1 for item in metrics if item.region == "HK")
    jp_count = sum(1 for item in metrics if item.region == "JP")
    us_count = sum(1 for item in metrics if item.region == "US")
    avg_latency = (
        round(sum(item.latency for item in metrics) / len(metrics), 2)
        if passed_latency_test
        else "n/a (no successful latency tests)"
    )
    print(f"[SUMMARY] total_nodes={total_nodes}")
    print(f"[SUMMARY] legal_candidates={candidates}")
    print(f"[SUMMARY] passed_latency_test={passed_latency_test}")
    print(f"[SUMMARY] output_nodes={len(metrics)}")
    print(f"[SUMMARY] output_source={output_source}")
    print(f"[SUMMARY] region_HK={hk_count} region_JP={jp_count} region_US={us_count}")
    print(f"[SUMMARY] avg_latency_ms={avg_latency}")
    print(f"[SUMMARY] output={OUTPUT_PATH}")


def main() -> None:
    total_nodes, candidates = collect_proxies()
    if not candidates:
        raise RuntimeError("no candidates from sources; keeping the published subscription unchanged")
    # Benchmark infrastructure errors must fail the job before publishing stale output.
    metrics = benchmark_proxies(candidates)
    if not metrics:
        raise RuntimeError("no nodes passed latency tests; keeping the published subscription unchanged")

    metrics.sort(key=lambda item: item.health_score, reverse=True)
    config = build_config(metrics)
    validate_config(config)
    write_config(config)
    print_summary(total_nodes, len(candidates), metrics, len(metrics), "benchmark")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise
