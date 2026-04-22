from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable, Iterable, Mapping, Protocol, Sequence
from urllib.parse import parse_qsl, unquote, unquote_plus

from .rule_loader import load_json_rule_specs


LOGIN_PATH_PATTERN = re.compile(
    r"(/login|/signin|/sign-in|/auth|/session|/oauth|/token|/admin|/console|/manager)",
    re.IGNORECASE,
)
LOGIN_FIELD_PATTERN = re.compile(
    r"(username=|user=|account=|password=|passwd=|pwd=)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RequestData:
    method: str
    path: str
    query: str
    body_text: str
    user_agent: str
    content_type: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedRequest:
    method: str
    path: str
    query: str
    body: str
    headers_text: str
    user_agent: str
    content_type: str

    def get_target(self, target: str) -> str:
        mapping = {
            "path": self.path,
            "query": self.query,
            "body": self.body,
            "headers": self.headers_text,
            "user_agent": self.user_agent,
            "content_type": self.content_type,
        }
        return mapping.get(target, "")


@dataclass(frozen=True)
class RuleMatch:
    matched_on: str
    detail: str
    matched_value: str


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    title: str
    layer: str
    category: str
    severity: str
    score: int
    targets: tuple[str, ...]
    pattern: re.Pattern[str] | None = None
    tags: tuple[str, ...] = ()
    description: str = ""
    cve_id: str | None = None
    block_on_match: bool = True
    matcher: Callable[["DetectionRule", RequestData, NormalizedRequest], RuleMatch | None] | None = None


@dataclass
class DetectionResult:
    blocked: bool
    rule_name: str | None = None
    matched_on: str | None = None
    detail: str | None = None
    cve_id: str | None = None
    rule_title: str | None = None
    rule_layer: str | None = None
    rule_category: str | None = None
    severity: str | None = None
    risk_score: int = 0
    tags: tuple[str, ...] = ()
    matched_value: str | None = None
    all_matches: list[dict[str, object]] = field(default_factory=list)


class ExternalRuleProvider(Protocol):
    def load_rules(self) -> Iterable[DetectionRule | Mapping[str, object]]:
        ...


LAYER_PRIORITY = {
    "critical": 5,
    "protocol": 4,
    "application": 3,
    "content": 2,
    "behavior": 1,
}

SEVERITY_PRIORITY = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

FIELD_SCORE_BONUS = {
    "body": 10,
    "query": 7,
    "path": 6,
    "headers": 5,
    "user_agent": 3,
    "content_type": 2,
}

SCANNER_WORDS = (
    "sqlmap",
    "nmap",
    "nikto",
    "acunetix",
    "dirbuster",
    "dirsearch",
    "gobuster",
    "masscan",
    "nuclei",
    "wpscan",
    "whatweb",
    "fscan",
    "zgrab",
    "nessus",
    "jaeles",
    "crawlergo",
    "xray",
    "httpx",
    "feroxbuster",
)

EXTERNAL_RULE_PROVIDERS: list[ExternalRuleProvider | Callable[[], Iterable[DetectionRule | Mapping[str, object]]]] = []
LOGGER = logging.getLogger(__name__)
REGEX_FLAG_MAP = {
    "ASCII": re.ASCII,
    "DOTALL": re.DOTALL,
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "VERBOSE": re.VERBOSE,
}


def register_rule_provider(provider: ExternalRuleProvider | Callable[[], Iterable[DetectionRule | Mapping[str, object]]]) -> None:
    if provider in EXTERNAL_RULE_PROVIDERS:
        return
    EXTERNAL_RULE_PROVIDERS.append(provider)
    get_detection_rules.cache_clear()
    get_rule_metadata_index.cache_clear()


def clear_rule_providers() -> None:
    EXTERNAL_RULE_PROVIDERS.clear()
    get_detection_rules.cache_clear()
    get_rule_metadata_index.cache_clear()


def _compile_regex_flags(value: object) -> int:
    if isinstance(value, int):
        return value

    if isinstance(value, str):
        tokens = [token for token in re.split(r"[|,\s]+", value.upper()) if token]
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        tokens = [str(token).strip().upper() for token in value if str(token).strip()]
    else:
        return re.IGNORECASE

    flags = 0
    for token in tokens:
        if token not in REGEX_FLAG_MAP:
            raise ValueError(f"unsupported regex flag: {token}")
        flags |= REGEX_FLAG_MAP[token]
    return flags or re.IGNORECASE


def _normalize_targets(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        targets = (value.strip(),)
    elif isinstance(value, Sequence):
        targets = tuple(str(item).strip() for item in value if str(item).strip())
    else:
        targets = ()
    if not targets:
        return ("path", "query", "body")
    return tuple(targets)


def compile_rule_spec(spec: Mapping[str, object]) -> DetectionRule:
    pattern = spec.get("pattern")
    flags = _compile_regex_flags(spec.get("flags"))
    compiled_pattern: re.Pattern[str] | None
    if isinstance(pattern, re.Pattern):
        compiled_pattern = pattern
    elif isinstance(pattern, str):
        compiled_pattern = re.compile(pattern, flags)
    else:
        compiled_pattern = None

    rule_id = str(spec.get("rule_id") or spec.get("id") or "").strip()
    if not rule_id:
        raise ValueError("rule_id is required")

    title = str(spec.get("title") or spec.get("name") or "").strip()
    if not title:
        raise ValueError(f"title is required for rule {rule_id}")

    targets = _normalize_targets(spec.get("targets") or ("path", "query", "body"))
    if not compiled_pattern:
        raise ValueError(f"pattern is required for external rule {rule_id}")

    return DetectionRule(
        rule_id=rule_id,
        title=title,
        layer=str(spec.get("layer") or "content").strip(),
        category=str(spec.get("category") or "generic").strip(),
        severity=str(spec.get("severity") or "medium").strip(),
        score=int(spec.get("score") or 50),
        targets=targets,
        pattern=compiled_pattern,
        tags=tuple(spec.get("tags") or ()),
        description=str(spec.get("description") or "").strip(),
        cve_id=str(spec.get("cve_id") or "").strip() or None,
        block_on_match=bool(spec.get("block_on_match", True)),
    )


def adapt_external_rule_specs(specs: Iterable[Mapping[str, object]]) -> tuple[DetectionRule, ...]:
    rules: list[DetectionRule] = []
    for spec in specs:
        try:
            rules.append(compile_rule_spec(spec))
        except Exception as exc:
            source = str(spec.get("source_file") or "external-rules")
            rule_id = str(spec.get("rule_id") or spec.get("id") or "").strip() or "unknown-rule"
            LOGGER.warning("Skipping invalid external rule %s from %s: %s", rule_id, source, exc)
            continue
    return tuple(rules)


def looks_like_auth_attempt(method: str, path: str, query: str, body_text: str, authorization: str = "") -> bool:
    # body_text is the inspection sample prepared by the gateway, not the shorter log preview.
    joined = f"{path}?{query}"
    if authorization.lower().startswith("basic "):
        return True
    if method.upper() not in {"POST", "PUT", "PATCH"}:
        return False
    if LOGIN_PATH_PATTERN.search(joined):
        return True
    if LOGIN_FIELD_PATTERN.search(body_text):
        return True
    return False


def _decode_text(value: str) -> str:
    text = str(value or "")
    for _ in range(2):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text


def _collapse_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _normalize_path(path: str) -> str:
    text = _decode_text(path)
    text = text.replace("\\", "/")
    text = re.sub(r"/{2,}", "/", text)
    return _collapse_text(text).lower()


def _normalize_query(query: str) -> str:
    raw = query.lstrip("?")
    if not raw:
        return ""
    decoded = _decode_text(raw)
    try:
        pairs = parse_qsl(decoded, keep_blank_values=True)
    except ValueError:
        pairs = []
    if pairs:
        normalized_pairs = [f"{key}={value}" for key, value in pairs]
        return _collapse_text("&".join(normalized_pairs)).lower()
    return _collapse_text(decoded).lower()


def _normalize_body(body_text: str) -> str:
    text = _decode_text(body_text or "")
    text = text.replace("\x00", "")
    return _collapse_text(text).lower()


def _normalize_headers(headers: Mapping[str, str]) -> str:
    parts: list[str] = []
    for key in sorted(headers):
        value = _collapse_text(_decode_text(headers.get(key, ""))).lower()
        parts.append(f"{str(key).strip().lower()}: {value}")
    return "\n".join(parts)


def normalize_request(
    method: str,
    path: str,
    query: str,
    body_text: str,
    user_agent: str,
    content_type: str = "",
    headers: Mapping[str, str] | None = None,
) -> NormalizedRequest:
    header_values = dict(headers or {})
    return NormalizedRequest(
        method=str(method or "").upper(),
        path=_normalize_path(path),
        query=_normalize_query(query),
        body=_normalize_body(body_text),
        headers_text=_normalize_headers(header_values),
        user_agent=_collapse_text(_decode_text(user_agent)).lower(),
        content_type=_collapse_text(_decode_text(content_type)).lower(),
    )


def _snippet(value: str, limit: int = 220) -> str:
    text = _collapse_text(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


def _regex_matcher(rule: DetectionRule, _: RequestData, normalized: NormalizedRequest) -> RuleMatch | None:
    if not rule.pattern:
        return None
    for target in rule.targets:
        value = normalized.get_target(target)
        if not value:
            continue
        match = rule.pattern.search(value)
        if match:
            matched = match.group(0)
            return RuleMatch(
                matched_on=target,
                detail=_snippet(matched),
                matched_value=_snippet(matched),
            )
    return None


def _webshell_upload_matcher(rule: DetectionRule, original: RequestData, normalized: NormalizedRequest) -> RuleMatch | None:
    method = normalized.method
    if method not in {"POST", "PUT", "PATCH"}:
        return None

    path_hit = re.search(r"(/upload|/file|/import|/attachment|/media|/editor|/api/.+upload)", normalized.path, re.IGNORECASE)
    filename_hit = re.search(
        r"filename\s*=\s*['\"]?[^'\"]+\.(php\d*|phtml|jsp|jspx|asp|aspx|cer|asa|py|sh|pl|cgi)['\"]?",
        original.body_text or "",
        re.IGNORECASE,
    )
    payload_hit = re.search(
        r"(<\?php|<%@\s*page|runtime\.getruntime\(\)\.exec|processbuilder|cmd\.exe|powershell\.exe|eval\s*\(|assert\s*\(|base64_decode\s*\(|shell_exec\s*\(|passthru\s*\(|system\s*\(|exec\s*\(|request\.getparameter)",
        normalized.body,
        re.IGNORECASE,
    )

    if filename_hit and payload_hit:
        detail = f"{filename_hit.group(1)} + {payload_hit.group(0)[:120]}"
        return RuleMatch("body", detail, detail)
    if path_hit and filename_hit:
        detail = f"suspicious extension {filename_hit.group(1)}"
        return RuleMatch("body", detail, detail)
    return None


def _sensitive_probe_matcher(rule: DetectionRule, _: RequestData, normalized: NormalizedRequest) -> RuleMatch | None:
    if not rule.pattern:
        return None
    match = rule.pattern.search(normalized.path)
    if not match:
        return None
    return RuleMatch("path", _snippet(match.group(0)), _snippet(match.group(0)))


def _scanner_probe_matcher(rule: DetectionRule, _: RequestData, normalized: NormalizedRequest) -> RuleMatch | None:
    scanner_match = _regex_matcher(rule, _, normalized)
    if scanner_match:
        return scanner_match

    path = normalized.path
    aggressive_probe = re.search(
        r"(/wp-admin|/wp-login\.php|/manager/html|/actuator|/swagger|/v3/api-docs|/boaform/admin/formlogin|/phpmyadmin|/\.env|/\.git)",
        path,
        re.IGNORECASE,
    )
    if aggressive_probe:
        value = aggressive_probe.group(0)
        return RuleMatch("path", _snippet(value), _snippet(value))
    return None


def _field_bonus(field_name: str) -> int:
    return FIELD_SCORE_BONUS.get(field_name, 0)


def _coerce_rule(item: DetectionRule | Mapping[str, object]) -> DetectionRule:
    if isinstance(item, DetectionRule):
        return item
    return compile_rule_spec(item)


def _builtin_rules() -> list[DetectionRule]:
    return [
        DetectionRule(
            rule_id="cve_log4shell",
            title="Log4Shell exploit fingerprint",
            layer="critical",
            category="cve",
            severity="high",
            score=92,
            targets=("path", "query", "body", "headers", "user_agent"),
            pattern=re.compile(r"(\$\{jndi:(ldap|ldaps|rmi|dns|iiop)|%24%7bjndi:(ldap|ldaps|rmi|dns|iiop))", re.IGNORECASE),
            tags=("cve", "jndi", "rce"),
            description="Detects common Log4Shell JNDI payloads.",
            cve_id="CVE-2021-44228",
        ),
        DetectionRule(
            rule_id="cve_spring4shell",
            title="Spring4Shell exploit fingerprint",
            layer="critical",
            category="cve",
            severity="high",
            score=90,
            targets=("query", "body"),
            pattern=re.compile(r"(class\.module\.classloader|class\.module\.classloader\.resources\.context\.parent\.pipeline\.first)", re.IGNORECASE),
            tags=("cve", "java", "rce"),
            description="Detects Spring4Shell property binding exploit chains.",
            cve_id="CVE-2022-22965",
        ),
        DetectionRule(
            rule_id="cve_struts_ognl",
            title="Apache Struts OGNL exploit fingerprint",
            layer="critical",
            category="cve",
            severity="high",
            score=89,
            targets=("content_type", "body", "headers"),
            pattern=re.compile(r"(%\{\(#_memberaccess|#context\[['\"]com\.opensymphony\.xwork2\.dispatcher\.httpservletresponse['\"]\]|multipart/form-data.{0,120}%\{)", re.IGNORECASE),
            tags=("cve", "ognl", "rce"),
            description="Detects OGNL exploit fragments commonly seen in Struts attacks.",
            cve_id="CVE-2017-5638",
        ),
        DetectionRule(
            rule_id="cve_confluence_ognl",
            title="Confluence OGNL exploit fingerprint",
            layer="critical",
            category="cve",
            severity="high",
            score=88,
            targets=("path", "query", "body"),
            pattern=re.compile(r"(\$\{.*@java\.lang\.runtime@getruntime\(\)\.exec|%24%7b.*@java\.lang\.runtime@getruntime\(\)\.exec)", re.IGNORECASE),
            tags=("cve", "ognl", "rce"),
            description="Detects Confluence OGNL RCE style payloads.",
            cve_id="CVE-2022-26134",
        ),
        DetectionRule(
            rule_id="cve_citrix_traversal",
            title="Citrix ADC traversal fingerprint",
            layer="critical",
            category="cve",
            severity="high",
            score=86,
            targets=("path",),
            pattern=re.compile(r"(/vpn/\.\./vpns/|/vpn/%2e%2e/vpns/)", re.IGNORECASE),
            tags=("cve", "path-traversal"),
            description="Detects Citrix ADC traversal probes.",
            cve_id="CVE-2019-19781",
        ),
        DetectionRule(
            rule_id="cve_apache_traversal",
            title="Apache path traversal fingerprint",
            layer="critical",
            category="cve",
            severity="high",
            score=84,
            targets=("path", "query"),
            pattern=re.compile(r"(/\.\%2e/|\.\%2e/\.\%2e/|\.\./\.\./etc/passwd)", re.IGNORECASE),
            tags=("cve", "path-traversal"),
            description="Detects Apache traversal exploit payloads.",
            cve_id="CVE-2021-41773",
        ),
        DetectionRule(
            rule_id="cve_phpunit_eval_stdin",
            title="PHPUnit eval-stdin fingerprint",
            layer="critical",
            category="cve",
            severity="high",
            score=84,
            targets=("path",),
            pattern=re.compile(r"(phpunit/.+eval-stdin\.php|/vendor/phpunit/phpunit/src/util/php/eval-stdin\.php)", re.IGNORECASE),
            tags=("cve", "php", "rce"),
            description="Detects public PHPUnit eval-stdin probes.",
            cve_id="CVE-2017-9841",
        ),
        DetectionRule(
            rule_id="cve_thinkphp_rce",
            title="ThinkPHP invokeFunction fingerprint",
            layer="critical",
            category="cve",
            severity="high",
            score=82,
            targets=("path", "query", "body"),
            pattern=re.compile(r"(think\\app/invokefunction|/index\.php\?s=/index/\\think\\app/invokefunction)", re.IGNORECASE),
            tags=("cve", "php", "rce"),
            description="Detects ThinkPHP invokeFunction exploit probes.",
            cve_id="CVE-2018-20062",
        ),
        DetectionRule(
            rule_id="webshell_upload",
            title="WebShell upload pattern",
            layer="critical",
            category="webshell",
            severity="high",
            score=90,
            targets=("path", "body"),
            tags=("upload", "webshell"),
            description="Detects suspicious script uploads and execution payloads.",
            matcher=_webshell_upload_matcher,
        ),
        DetectionRule(
            rule_id="sql_injection",
            title="SQL injection probe",
            layer="application",
            category="sqli",
            severity="high",
            score=80,
            targets=("path", "query", "body", "headers"),
            pattern=re.compile(
                r"(\bunion\b.{0,24}\bselect\b|\bselect\b.{0,20}\bfrom\b|\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?|\bbenchmark\s*\(|\bsleep\s*\(|\bload_file\s*\(|\binto\s+outfile\b|\binformation_schema\b|\bxp_cmdshell\b|\bpg_sleep\s*\()",
                re.IGNORECASE,
            ),
            tags=("sql", "db"),
            description="Detects common SQL injection keywords and time-based payloads.",
        ),
        DetectionRule(
            rule_id="xss",
            title="Cross-site scripting payload",
            layer="application",
            category="xss",
            severity="medium",
            score=68,
            targets=("path", "query", "body", "headers"),
            pattern=re.compile(
                r"(<script\b|</script>|javascript:|vbscript:|onerror\s*=|onload\s*=|onfocus\s*=|svg/onload|srcdoc=|document\.cookie|window\.location|alert\s*\()",
                re.IGNORECASE,
            ),
            tags=("browser", "script"),
            description="Detects typical stored and reflected XSS payload fragments.",
        ),
        DetectionRule(
            rule_id="ssti",
            title="Server-side template injection payload",
            layer="application",
            category="ssti",
            severity="high",
            score=74,
            targets=("path", "query", "body"),
            pattern=re.compile(
                r"(\{\{.*?(?:7\*7|config|cycler|joiner|namespace|request|self)\}\}|\$\{.*?(?:7\*7|jndi:|scriptengine|runtime|getclass)\}|#\{.*?7\*7.*?\}|<%=?\s*.*?(?:runtime|processbuilder|request)\s*%>)",
                re.IGNORECASE,
            ),
            tags=("template", "server-side"),
            description="Detects Jinja2/Twig/Freemarker/EL style SSTI probes.",
        ),
        DetectionRule(
            rule_id="ssrf",
            title="Server-side request forgery payload",
            layer="application",
            category="ssrf",
            severity="high",
            score=72,
            targets=("query", "body", "headers"),
            pattern=re.compile(
                r"((?:https?|gopher|dict|ftp|file)://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200))",
                re.IGNORECASE,
            ),
            tags=("ssrf", "metadata"),
            description="Detects SSRF payloads targeting localhost or cloud metadata services.",
        ),
        DetectionRule(
            rule_id="command_injection",
            title="Command execution payload",
            layer="application",
            category="rce",
            severity="high",
            score=78,
            targets=("query", "body", "headers"),
            pattern=re.compile(
                r"(\|\||&&|;\s*(?:cat|curl|wget|bash|sh|powershell|python|perl|ruby|nc|telnet)\b|`[^`]+`|\$\([^)]*\)|(?:cmd\.exe|/bin/sh|/bin/bash|powershell\.exe|runtime\.getruntime\(\)\.exec|processbuilder))",
                re.IGNORECASE,
            ),
            tags=("rce", "command"),
            description="Detects shell chaining and command execution primitives.",
        ),
        DetectionRule(
            rule_id="deserialization_probe",
            title="Deserialization gadget probe",
            layer="application",
            category="deserialization",
            severity="high",
            score=71,
            targets=("query", "body", "headers"),
            pattern=re.compile(
                r"(ysoserial|java\.util\.priorityqueue|commonscollections\d?|org\.apache\.commons\.collections|rmi://|ldap://)",
                re.IGNORECASE,
            ),
            tags=("java", "deserialization"),
            description="Detects deserialization gadget and gadget-chain references.",
        ),
        DetectionRule(
            rule_id="path_traversal",
            title="Path traversal payload",
            layer="content",
            category="path_traversal",
            severity="medium",
            score=60,
            targets=("path", "query", "body"),
            pattern=re.compile(r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini|boot\.ini|/proc/self/environ)", re.IGNORECASE),
            tags=("file", "lfi"),
            description="Detects classic traversal and file disclosure targets.",
        ),
        DetectionRule(
            rule_id="webshell_probe",
            title="WebShell command parameter probe",
            layer="content",
            category="webshell",
            severity="high",
            score=70,
            targets=("query", "body"),
            pattern=re.compile(
                r"((?:cmd|exec|shell|code|eval|assert|ant|system|passthru)\s*=\s*(?:whoami|id|cat|ls|pwd|ipconfig|ifconfig)|(?:base64_decode|eval|assert)\s*\()",
                re.IGNORECASE,
            ),
            tags=("webshell", "command"),
            description="Detects common webshell parameters and execution primitives.",
        ),
        DetectionRule(
            rule_id="scanner_probe",
            title="Scanner or crawler probe",
            layer="behavior",
            category="scanner",
            severity="medium",
            score=58,
            targets=("user_agent", "headers", "path", "query"),
            pattern=re.compile("|".join(re.escape(word) for word in SCANNER_WORDS), re.IGNORECASE),
            tags=("scanner", "probe"),
            description="Detects known scanner user-agents and request signatures.",
            matcher=_scanner_probe_matcher,
        ),
        DetectionRule(
            rule_id="sensitive_probe",
            title="Sensitive path probe",
            layer="behavior",
            category="sensitive_path",
            severity="medium",
            score=55,
            targets=("path",),
            pattern=re.compile(
                r"("
                r"/\.env(?:\.|$)|"
                r"/\.git(?:/|$)|"
                r"/phpmyadmin(?:/|$)|"
                r"/adminer(?:/|$)|"
                r"/druid(?:/|$)|"
                r"/grafana(?:/|$)|"
                r"/prometheus(?:/|$)|"
                r"/kibana(?:/|$)|"
                r"/server-status(?:$|\?)|"
                r"/server-info(?:$|\?)|"
                r"/manager/html(?:/|$)|"
                r"/actuator(?:/|$)|"
                r"/nacos(?:/|$)|"
                r"/jenkins(?:/|$)|"
                r"/solr(?:/|$)|"
                r"/elasticsearch(?:/|$)|"
                r"/wp-admin(?:/|$)|"
                r"/wp-login\.php(?:$|\?)|"
                r"/swagger(?:/|$)|"
                r"/swagger-ui(?:/|$)|"
                r"/swagger-resources(?:/|$)|"
                r"/v2/api-docs(?:$|\?)|"
                r"/v3/api-docs(?:$|\?)|"
                r"/api/jsonws(?:/|$)|"
                r"/console/login(?:$|\?)|"
                r"/system/console(?:/|$)|"
                r"/boaform/admin/formlogin(?:$|\?)"
                r")",
                re.IGNORECASE,
            ),
            tags=("exposure", "probe"),
            description="Detects probes against sensitive management and debug endpoints.",
            matcher=_sensitive_probe_matcher,
        ),
    ]


def _load_external_json_rules() -> tuple[DetectionRule, ...]:
    return adapt_external_rule_specs(load_json_rule_specs())


@lru_cache(maxsize=1)
def get_detection_rules() -> tuple[DetectionRule, ...]:
    rules = list(_builtin_rules())
    known_rule_ids = {rule.rule_id for rule in rules if rule.rule_id}
    for provider in EXTERNAL_RULE_PROVIDERS:
        try:
            provided = provider.load_rules() if hasattr(provider, "load_rules") else provider()
        except Exception as exc:
            LOGGER.warning("Failed to load external rule provider %r: %s", provider, exc)
            continue
        for item in provided or ():
            try:
                rule = _coerce_rule(item)
            except Exception as exc:
                LOGGER.warning("Failed to normalize external rule from provider %r: %s", provider, exc)
                continue
            if rule.rule_id and rule.rule_id in known_rule_ids:
                LOGGER.warning("Skipping duplicate rule_id already provided by builtin or earlier rule: %s", rule.rule_id)
                continue
            if rule.rule_id:
                known_rule_ids.add(rule.rule_id)
            rules.append(rule)

    rules.sort(
        key=lambda rule: (
            LAYER_PRIORITY.get(rule.layer, 0),
            rule.score,
            SEVERITY_PRIORITY.get(rule.severity, 0),
        ),
        reverse=True,
    )
    return tuple(rules)


@lru_cache(maxsize=1)
def get_rule_metadata_index() -> dict[str, dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    for rule in get_detection_rules():
        index[rule.rule_id] = {
            "title": rule.title,
            "layer": rule.layer,
            "category": rule.category,
            "severity": rule.severity,
            "score": rule.score,
            "tags": rule.tags,
            "cve_id": rule.cve_id,
        }
    return index


def _evaluate_rule(rule: DetectionRule, original: RequestData, normalized: NormalizedRequest) -> RuleMatch | None:
    if rule.matcher:
        return rule.matcher(rule, original, normalized)
    return _regex_matcher(rule, original, normalized)


def _result_from_rule(rule: DetectionRule, match: RuleMatch) -> DetectionResult:
    risk_score = min(100, max(0, rule.score + _field_bonus(match.matched_on)))
    return DetectionResult(
        blocked=rule.block_on_match,
        rule_name=rule.rule_id,
        rule_title=rule.title,
        matched_on=match.matched_on,
        detail=match.detail,
        matched_value=match.matched_value,
        cve_id=rule.cve_id,
        rule_layer=rule.layer,
        rule_category=rule.category,
        severity=rule.severity,
        risk_score=risk_score,
        tags=rule.tags,
    )


def inspect_request(
    method: str,
    path: str,
    query: str,
    body_text: str,
    user_agent: str,
    content_type: str = "",
    headers: Mapping[str, str] | None = None,
) -> DetectionResult:
    # body_text should come from the gateway's inspection text so detection can inspect
    # more than the shorter body preview stored in logs.
    original = RequestData(
        method=str(method or ""),
        path=str(path or ""),
        query=str(query or ""),
        body_text=str(body_text or ""),
        user_agent=str(user_agent or ""),
        content_type=str(content_type or ""),
        headers=dict(headers or {}),
    )
    normalized = normalize_request(
        method=method,
        path=path,
        query=query,
        body_text=body_text,
        user_agent=user_agent,
        content_type=content_type,
        headers=headers,
    )

    matches: list[DetectionResult] = []
    for rule in get_detection_rules():
        matched = _evaluate_rule(rule, original, normalized)
        if not matched:
            continue
        matches.append(_result_from_rule(rule, matched))

    if not matches:
        return DetectionResult(blocked=False)

    matches.sort(
        key=lambda result: (
            1 if result.blocked else 0,
            result.risk_score,
            LAYER_PRIORITY.get(result.rule_layer or "", 0),
            SEVERITY_PRIORITY.get(result.severity or "", 0),
        ),
        reverse=True,
    )
    best = matches[0]
    best.all_matches = [
        {
            "rule_id": item.rule_name,
            "title": item.rule_title,
            "layer": item.rule_layer,
            "category": item.rule_category,
            "severity": item.severity,
            "score": item.risk_score,
            "matched_on": item.matched_on,
            "detail": item.detail,
            "cve_id": item.cve_id,
            "tags": list(item.tags),
        }
        for item in matches
    ]
    return best


register_rule_provider(_load_external_json_rules)
