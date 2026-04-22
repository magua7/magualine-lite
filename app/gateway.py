from __future__ import annotations

import json
import re
import socket
import time
from functools import lru_cache
from ipaddress import ip_address, ip_network
from typing import Iterable
from urllib.parse import urlparse

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, Response as FastAPIResponse

from .config import get_settings
from .detection import inspect_request, looks_like_auth_attempt
from .storage import (
    add_auth_attempt,
    add_blocked_ip,
    add_cc_ban,
    add_log,
    clear_recent_auth_failures,
    count_recent_requests,
    count_recent_auth_failures,
    get_block_reason,
    get_cc_block_reason,
    init_db,
)

HOP_BY_HOP_HEADERS = {
    "accept-encoding",
    "connection",
    "content-encoding",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}
STATIC_PATH_EXTENSIONS = (
    ".css",
    ".js",
    ".mjs",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".webp",
    ".avif",
    ".mp4",
    ".mp3",
    ".txt",
    ".xml",
)


settings = get_settings()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, title="magualine-gateway")
BRUTE_FORCE_THRESHOLD = 8


def _parse_ip_value(value: str | None) -> str | None:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    try:
        return str(ip_address(candidate))
    except ValueError:
        return None


def _extract_forwarded_for_ip(value: str | None) -> str | None:
    if not value:
        return None
    for item in str(value).split(","):
        candidate = _parse_ip_value(item)
        if candidate:
            return candidate
    return None


def _is_trusted_proxy_ip(value: str | None) -> bool:
    parsed = _parse_ip_value(value)
    if not parsed:
        return False

    source_ip = ip_address(parsed)
    for proxy in settings.trusted_proxy_ips:
        trusted_proxy = str(proxy or "").strip()
        if not trusted_proxy:
            continue
        try:
            if "/" in trusted_proxy:
                if source_ip in ip_network(trusted_proxy, strict=False):
                    return True
            elif source_ip == ip_address(trusted_proxy):
                return True
        except ValueError:
            continue
    return False


def decode_body_text(body: bytes, limit: int) -> str:
    if not body or limit <= 0:
        return ""
    return body[:limit].decode("utf-8", errors="ignore")


def build_inspect_text(body: bytes) -> str:
    if not body:
        return ""

    limit = max(settings.detection_body_limit, settings.log_body_limit + 1024)
    if limit <= 0:
        return ""

    if len(body) <= limit:
        return body.decode("utf-8", errors="ignore")

    head_limit = max(1, limit // 2)
    tail_limit = max(1, limit - head_limit)
    head_text = body[:head_limit].decode("utf-8", errors="ignore")
    tail_text = body[-tail_limit:].decode("utf-8", errors="ignore")
    return f"{head_text}\n...[body truncated for inspection]...\n{tail_text}"


def get_client_ip(request: Request) -> str:
    source_ip = request.client.host if request.client else "unknown"
    if not _is_trusted_proxy_ip(source_ip):
        return source_ip

    # Only trust forwarding headers when the direct peer is a known reverse proxy.
    forwarded_for = _extract_forwarded_for_ip(request.headers.get("x-forwarded-for"))
    if forwarded_for:
        return forwarded_for

    real_ip = _parse_ip_value(request.headers.get("x-real-ip"))
    if real_ip:
        return real_ip

    return source_ip


def filter_headers(headers: Iterable[tuple[str, str]]) -> dict[str, str]:
    clean_headers: dict[str, str] = {}
    for key, value in headers:
        if key.lower() in HOP_BY_HOP_HEADERS:
            continue
        clean_headers[key] = value
    return clean_headers


def resolve_forwarded_port(request: Request) -> str:
    if request.url.port:
        return str(request.url.port)
    return "443" if request.url.scheme == "https" else "80"


def serialize_request_headers(headers: Iterable[tuple[str, str]]) -> str:
    captured: dict[str, str] = {}
    for key, value in headers:
        lowered = key.lower()
        if lowered in HOP_BY_HOP_HEADERS:
            continue
        if lowered in SENSITIVE_HEADERS:
            captured[key] = "[REDACTED]"
        else:
            captured[key] = value[:1000]
    return json.dumps(captured, ensure_ascii=False)


def get_request_host(request: Request) -> str:
    return str(request.headers.get("host") or "").strip()[:255]


def get_destination_host(request: Request, upstream_url: str) -> str:
    parsed_upstream = urlparse(upstream_url)
    return parsed_upstream.hostname or ""


@lru_cache(maxsize=512)
def resolve_destination_ip(hostname: str) -> str:
    hostname = (hostname or "").strip()
    if not hostname:
        return "-"
    try:
        return str(ip_address(hostname))
    except ValueError:
        pass
    try:
        candidates = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return "-"

    for candidate in candidates:
        sockaddr = candidate[4]
        if sockaddr and sockaddr[0]:
            return sockaddr[0]
    return "-"


def build_upstream_url(request: Request, full_path: str) -> str:
    query = request.url.query
    base = settings.upstream_url
    path = "/" + full_path.lstrip("/")
    url = f"{base}{path}"
    if query:
        url = f"{url}?{query}"
    return url


def display_rule_name(rule_name: str | None) -> str:
    mapping = {
        "manual_block": "手动封禁",
        "sql_injection": "SQL 注入",
        "xss": "跨站脚本",
        "ssti": "模板注入",
        "ssrf": "服务端请求伪造",
        "xxe_injection": "XXE 实体注入",
        "xxe_dtd_subset_decl": "XXE DTD 子集声明",
        "xxe_entity_declaration": "XXE 实体声明",
        "xxe_external_entity_uri": "XXE 外部实体引用",
        "nosql_injection": "NoSQL 注入",
        "nosql_operator_payload": "NoSQL 操作符注入",
        "nosql_regex_payload": "NoSQL 正则注入",
        "nosql_where_javascript": "NoSQL 脚本注入",
        "ldap_injection": "LDAP 注入",
        "ldap_wildcard_auth_bypass": "LDAP 通配绕过",
        "ldap_boolean_injection": "LDAP 布尔注入",
        "ldap_objectclass_enumeration": "LDAP 枚举探测",
        "file_inclusion": "文件包含",
        "file_inclusion_stream_wrapper": "文件包含流包装器",
        "file_inclusion_remote_url_param": "远程文件包含",
        "file_inclusion_local_target": "本地文件泄露探测",
        "path_traversal": "目录穿越",
        "command_injection": "命令注入",
        "deserialization_probe": "反序列化探测",
        "scanner_probe": "扫描探测",
        "scanner_probe_extended": "扫描器指纹探测",
        "scanner_probe_recon_suite": "侦察工具指纹",
        "scanner_probe_oast_marker": "OAST 探测标记",
        "scanner_probe_fuzz_placeholder": "模糊测试占位符",
        "sensitive_probe": "敏感路径探测",
        "sensitive_probe_extended": "敏感路径探测",
        "sensitive_probe_repository_metadata": "仓库元数据探测",
        "sensitive_probe_admin_interfaces": "管理界面探测",
        "sensitive_probe_config_leak": "配置文件泄露探测",
        "sensitive_probe_debug_surface": "调试面探测",
        "java_ecosystem_probe": "Java 生态路径探测",
        "java_probe_actuator_surface": "Spring Actuator 探测",
        "java_probe_middleware_surface": "Java 中间件控制台探测",
        "java_probe_archive_descriptor": "Java 描述文件探测",
        "php_ecosystem_probe": "PHP 生态路径探测",
        "php_probe_debug_surface": "PHP 调试端点探测",
        "php_probe_dependency_surface": "PHP 依赖目录探测",
        "php_probe_storage_surface": "PHP 存储日志探测",
        "webshell_upload": "WebShell 上传",
        "webshell_probe": "WebShell 探测",
        "brute_force": "暴力破解",
        "cc_attack": "CC 高频访问",
        "cve_exploit_attempt": "CVE 漏洞利用",
        "cve_log4shell": "Log4Shell 利用",
        "cve_spring4shell": "Spring4Shell 利用",
        "cve_struts_ognl": "Struts OGNL 利用",
        "cve_confluence_ognl": "Confluence OGNL 利用",
        "cve_citrix_traversal": "Citrix 路径穿越",
        "cve_apache_traversal": "Apache 路径穿越",
        "cve_phpunit_eval_stdin": "PHPUnit 利用",
        "cve_thinkphp_rce": "ThinkPHP 远程执行",
        "cve_fastjson_auto_type": "Fastjson 利用",
        "cve_weblogic_console_traversal": "WebLogic 利用",
        "cve_jboss_invoker_deserialization": "JBoss 利用",
        "cve_spring_gateway_spel": "Spring Gateway 利用",
        "cve_laravel_ignition_rce": "Laravel Ignition 利用",
        "cve_php_cgi_arg_injection": "PHP CGI 利用",
        "cve_drupalgeddon2": "Drupal 利用",
        "cve_yii_debug_rce": "Yii Debug 利用",
        "security_guard": "流量防护",
    }
    return mapping.get(rule_name or "", rule_name or "流量防护")


def is_allowlisted_request(client_ip: str, path: str) -> bool:
    if client_ip in settings.allow_ips:
        return True
    return any(path.startswith(prefix) for prefix in settings.allow_path_prefixes)


def is_static_like_path(path: str) -> bool:
    lowered = path.lower()
    return any(lowered.endswith(ext) for ext in STATIC_PATH_EXTENSIONS)


@lru_cache(maxsize=128)
def _compiled_cc_patterns(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error:
            continue
    return tuple(compiled)


def should_check_cc(method: str, path: str) -> bool:
    if not settings.cc_enabled:
        return False
    if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        return False
    if is_static_like_path(path):
        return False
    if any(path.startswith(prefix) for prefix in settings.allow_path_prefixes):
        return False
    compiled = _compiled_cc_patterns(settings.cc_protected_patterns)
    if not compiled:
        return True
    return any(pattern.search(path) for pattern in compiled)


def blocked_response(reason: str, rule_name: str | None = None) -> HTMLResponse:
    html = """
    <!DOCTYPE html>
    <html lang="zh-CN">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>magualine 流量防护</title>
        <style>
          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            background: linear-gradient(160deg, #091224, #14274a 50%, #e7eefb);
            color: #0f172a;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          }
          .card {
            width: min(560px, calc(100vw - 32px));
            background: rgba(255,255,255,0.95);
            border-radius: 24px;
            padding: 32px;
            box-shadow: 0 30px 80px rgba(15, 23, 42, 0.28);
          }
          h1 {
            margin: 0 0 8px;
            font-size: 34px;
          }
          .tag {
            display: inline-block;
            padding: 6px 10px;
            border-radius: 999px;
            background: #dbeafe;
            color: #1d4ed8;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
          }
          p {
            line-height: 1.7;
            color: #334155;
          }
        </style>
      </head>
      <body>
        <div class="card">
          <span class="tag">magualine</span>
          <h1>请求已被拦截</h1>
          <p>您的访问已违规，IP 已被管理员记录，请正确访问。</p>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(content=html, status_code=403)


@app.on_event("startup")
async def startup() -> None:
    init_db()
    timeout = httpx.Timeout(settings.request_timeout)
    app.state.http_client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)


@app.on_event("shutdown")
async def shutdown() -> None:
    client: httpx.AsyncClient | None = getattr(app.state, "http_client", None)
    if client:
        await client.aclose()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.api_route("/", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy(request: Request, full_path: str = "") -> Response:
    started = time.perf_counter()
    client_ip = get_client_ip(request)
    query = request.url.query
    body = await request.body()
    inspect_text = build_inspect_text(body)
    body_preview = decode_body_text(body, settings.log_body_limit)
    user_agent = request.headers.get("user-agent", "")
    content_type = request.headers.get("content-type", "")
    authorization = request.headers.get("authorization", "")
    method = request.method.upper()
    path = "/" + full_path.lstrip("/")
    request_host = get_request_host(request)
    request_headers_json = serialize_request_headers(request.headers.items())
    upstream_url = build_upstream_url(request, full_path)
    destination_host = get_destination_host(request, upstream_url)
    destination_ip = resolve_destination_ip(destination_host)
    request_allowlisted = is_allowlisted_request(client_ip, path)

    manual_block_reason = get_block_reason(client_ip)
    if manual_block_reason:
        duration_ms = int((time.perf_counter() - started) * 1000)
        add_log(
            client_ip=client_ip,
            destination_host=destination_host,
            request_host=request_host,
            destination_ip=destination_ip,
            method=method,
            path=path,
            query_string=query,
            user_agent=user_agent,
            request_headers=request_headers_json,
            action="blocked",
            attack_type="manual_block",
            attack_detail=manual_block_reason,
            cve_id=None,
            rule_category="policy",
            rule_layer="policy",
            matched_field="client_ip",
            risk_score=85,
            status_code=403,
            upstream_status=None,
            duration_ms=duration_ms,
            body_preview=body_preview,
        )
        return blocked_response(manual_block_reason, "manual_block")

    cc_block_reason = get_cc_block_reason(client_ip)
    if cc_block_reason:
        duration_ms = int((time.perf_counter() - started) * 1000)
        add_log(
            client_ip=client_ip,
            destination_host=destination_host,
            request_host=request_host,
            destination_ip=destination_ip,
            method=method,
            path=path,
            query_string=query,
            user_agent=user_agent,
            request_headers=request_headers_json,
            action="blocked",
            attack_type="cc_attack",
            attack_detail=cc_block_reason,
            cve_id=None,
            rule_category="rate_limit",
            rule_layer="behavior",
            matched_field="client_ip",
            risk_score=60,
            status_code=403,
            upstream_status=None,
            duration_ms=duration_ms,
            body_preview=body_preview,
        )
        return blocked_response(cc_block_reason, "cc_attack")

    if should_check_cc(method, path) and not request_allowlisted:
        recent_ip_hits = count_recent_requests(client_ip, settings.cc_window_seconds)
        recent_path_hits = count_recent_requests(client_ip, settings.cc_window_seconds, path=path)
        trigger_reason = None

        if recent_ip_hits >= max(1, settings.cc_max_requests_per_ip - 1):
            trigger_reason = (
                f"{settings.cc_window_seconds} 秒内来自该 IP 的请求超过 "
                f"{settings.cc_max_requests_per_ip} 次，触发 CC 高频访问限制"
            )
        elif recent_path_hits >= max(1, settings.cc_max_requests_per_path - 1):
            trigger_reason = (
                f"{settings.cc_window_seconds} 秒内针对同一路径的请求超过 "
                f"{settings.cc_max_requests_per_path} 次，触发 CC 高频访问限制"
            )

        if trigger_reason:
            add_cc_ban(client_ip, trigger_reason, settings.cc_block_minutes)
            duration_ms = int((time.perf_counter() - started) * 1000)
            add_log(
                client_ip=client_ip,
                destination_host=destination_host,
                request_host=request_host,
                destination_ip=destination_ip,
                method=method,
                path=path,
                query_string=query,
                user_agent=user_agent,
                request_headers=request_headers_json,
                action="blocked",
                attack_type="cc_attack",
                attack_detail=trigger_reason,
                cve_id=None,
                rule_category="rate_limit",
                rule_layer="behavior",
                matched_field="path",
                risk_score=60,
                status_code=403,
                upstream_status=None,
                duration_ms=duration_ms,
                body_preview=body_preview,
            )
            return blocked_response(trigger_reason, "cc_attack")

    detection = None
    if not request_allowlisted and not is_static_like_path(path):
        detection = inspect_request(
            method,
            path,
            query,
            inspect_text,
            user_agent,
            content_type,
            headers=dict(request.headers.items()),
        )
    if detection and detection.blocked:
        duration_ms = int((time.perf_counter() - started) * 1000)
        add_log(
            client_ip=client_ip,
            destination_host=destination_host,
            request_host=request_host,
            destination_ip=destination_ip,
            method=method,
            path=path,
            query_string=query,
            user_agent=user_agent,
            request_headers=request_headers_json,
            action="blocked",
            attack_type=detection.rule_name,
            attack_detail=f"{detection.matched_on}: {detection.detail}",
            cve_id=detection.cve_id,
            rule_category=detection.rule_category,
            rule_layer=detection.rule_layer,
            matched_field=detection.matched_on,
            risk_score=detection.risk_score,
            severity_hint=detection.severity,
            status_code=403,
            upstream_status=None,
            duration_ms=duration_ms,
            body_preview=body_preview,
        )
        if detection.cve_id:
            reason = f"{detection.cve_id} 命中位置：{detection.matched_on}"
        else:
            reason = f"{display_rule_name(detection.rule_name)} 命中位置：{detection.matched_on}"
        return blocked_response(reason, detection.rule_name)

    headers = filter_headers(request.headers.items())
    if settings.forward_original_host and request_host:
        parsed_request_host = urlparse(f"//{request_host}")
        headers["host"] = request_host
        headers["x-forwarded-host"] = request_host
        headers["x-forwarded-server"] = parsed_request_host.hostname or request_host.split(":", 1)[0]
    headers["x-forwarded-for"] = client_ip
    headers["x-real-ip"] = client_ip
    headers["x-forwarded-proto"] = request.url.scheme
    headers["x-forwarded-port"] = resolve_forwarded_port(request)

    try:
        upstream_response = await app.state.http_client.request(
            method,
            upstream_url,
            headers=headers,
            content=body if body else None,
        )
    except httpx.HTTPError as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        add_log(
            client_ip=client_ip,
            destination_host=destination_host,
            request_host=request_host,
            destination_ip=destination_ip,
            method=method,
            path=path,
            query_string=query,
            user_agent=user_agent,
            request_headers=request_headers_json,
            action="error",
            attack_type=None,
            attack_detail=str(exc)[:300],
            cve_id=None,
            status_code=502,
            upstream_status=None,
            duration_ms=duration_ms,
            body_preview=body_preview,
        )
        return JSONResponse(
            status_code=502,
            content={"message": "源站请求失败", "detail": str(exc)},
        )

    auth_attempt = looks_like_auth_attempt(method, path, query, inspect_text, authorization)
    if auth_attempt:
        if upstream_response.status_code in {200, 201, 204, 301, 302, 303}:
            add_auth_attempt(client_ip, path, True, upstream_response.status_code)
            clear_recent_auth_failures(client_ip)
        elif upstream_response.status_code in {401, 403, 429}:
            add_auth_attempt(client_ip, path, False, upstream_response.status_code)
            recent_failures = count_recent_auth_failures(client_ip)
            if recent_failures >= BRUTE_FORCE_THRESHOLD:
                duration_ms = int((time.perf_counter() - started) * 1000)
                reason = f"10 分钟内登录失败 {recent_failures} 次"
                add_blocked_ip(client_ip, f"暴力破解阈值触发：{reason}", created_by="system")
                add_log(
                    client_ip=client_ip,
                    destination_host=destination_host,
                    request_host=request_host,
                    destination_ip=destination_ip,
                    method=method,
                    path=path,
                    query_string=query,
                    user_agent=user_agent,
                    request_headers=request_headers_json,
                    action="blocked",
                    attack_type="brute_force",
                    attack_detail=reason,
                    cve_id=None,
                    rule_category="auth",
                    rule_layer="behavior",
                    matched_field="path",
                    risk_score=85,
                    status_code=403,
                    upstream_status=upstream_response.status_code,
                    duration_ms=duration_ms,
                    body_preview=body_preview,
                )
                return blocked_response(reason, "brute_force")

    duration_ms = int((time.perf_counter() - started) * 1000)
    add_log(
        client_ip=client_ip,
        destination_host=destination_host,
        request_host=request_host,
        destination_ip=destination_ip,
        method=method,
        path=path,
        query_string=query,
        user_agent=user_agent,
        request_headers=request_headers_json,
        action="allowed",
        attack_type=None,
        attack_detail=None,
        cve_id=None,
        status_code=upstream_response.status_code,
        upstream_status=upstream_response.status_code,
        duration_ms=duration_ms,
        body_preview=body_preview,
    )

    response_headers = filter_headers(upstream_response.headers.items())
    return FastAPIResponse(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get("content-type"),
    )


if __name__ == "__main__":
    uvicorn.run("app.gateway:app", host="0.0.0.0", port=8080)
