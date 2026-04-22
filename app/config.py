from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _parse_csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip() for item in str(value).split(",") if item.strip())


def _parse_float(value: str | None, default: float) -> float:
    if value is None:
        return default
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    upstream_url: str
    admin_username: str
    admin_password: str
    secret_key: str
    data_dir: Path
    rules_dir: Path
    detection_body_limit: int
    log_body_limit: int
    request_timeout: int
    allow_ips: tuple[str, ...]
    allow_path_prefixes: tuple[str, ...]
    trusted_proxy_ips: tuple[str, ...]
    forward_original_host: bool
    cc_enabled: bool
    cc_window_seconds: int
    cc_max_requests_per_ip: int
    cc_max_requests_per_path: int
    cc_block_minutes: int
    cc_protected_patterns: tuple[str, ...]
    admin_login_window_seconds: int
    admin_login_max_failures: int
    admin_login_lock_seconds: int
    geo_lookup_enabled: bool
    geo_provider: str
    geo_lookup_timeout: float
    geo_failure_backoff_seconds: int
    dashscope_api_key: str
    bailian_app_id: str
    bailian_workspace_id: str
    bailian_base_url: str
    bailian_timeout: int
    screen_target_name: str
    screen_target_label: str
    screen_target_lng: float
    screen_target_lat: float
    screen_flow_debug: bool

    @property
    def db_path(self) -> Path:
        return self.data_dir / "magualine.db"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    data_dir = Path(os.getenv("DATA_DIR", "/app/data")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)

    upstream_url = os.getenv("UPSTREAM_URL", "http://host.docker.internal:8090").rstrip("/")
    rules_dir = Path(os.getenv("RULES_DIR", str(Path(__file__).resolve().parent.parent / "rules"))).resolve()
    log_body_limit = max(1, _parse_int(os.getenv("LOG_BODY_LIMIT"), 4096))
    detection_body_limit = max(
        log_body_limit + 1024,
        _parse_int(os.getenv("DETECTION_BODY_LIMIT"), 65536),
    )

    return Settings(
        upstream_url=upstream_url,
        admin_username=os.getenv("ADMIN_USERNAME", "admin"),
        admin_password=os.getenv("ADMIN_PASSWORD", "ChangeThisPassword123"),
        secret_key=os.getenv("SECRET_KEY", "magualine-change-this-secret-key"),
        data_dir=data_dir,
        rules_dir=rules_dir,
        detection_body_limit=detection_body_limit,
        log_body_limit=log_body_limit,
        request_timeout=_parse_int(os.getenv("REQUEST_TIMEOUT"), 30),
        allow_ips=_parse_csv(os.getenv("ALLOW_IPS", "127.0.0.1,::1")),
        allow_path_prefixes=_parse_csv(
            os.getenv(
                "ALLOW_PATH_PREFIXES",
                "/health,/favicon.ico,/robots.txt,/styles/,/js/,/images/,/webjars/,/static/",
            )
        ),
        trusted_proxy_ips=_parse_csv(os.getenv("TRUSTED_PROXY_IPS", "")),
        forward_original_host=_parse_bool(os.getenv("FORWARD_ORIGINAL_HOST", "false"), default=False),
        cc_enabled=_parse_bool(os.getenv("CC_ENABLED", "true"), default=True),
        cc_window_seconds=_parse_int(os.getenv("CC_WINDOW_SECONDS"), 60),
        cc_max_requests_per_ip=_parse_int(os.getenv("CC_MAX_REQUESTS_PER_IP"), 120),
        cc_max_requests_per_path=_parse_int(os.getenv("CC_MAX_REQUESTS_PER_PATH"), 45),
        cc_block_minutes=_parse_int(os.getenv("CC_BLOCK_MINUTES"), 1440),
        cc_protected_patterns=_parse_csv(os.getenv("CC_PROTECTED_PATTERNS", "")),
        admin_login_window_seconds=max(60, _parse_int(os.getenv("ADMIN_LOGIN_WINDOW_SECONDS"), 600)),
        admin_login_max_failures=max(1, _parse_int(os.getenv("ADMIN_LOGIN_MAX_FAILURES"), 6)),
        admin_login_lock_seconds=max(30, _parse_int(os.getenv("ADMIN_LOGIN_LOCK_SECONDS"), 300)),
        geo_lookup_enabled=_parse_bool(os.getenv("GEO_LOOKUP_ENABLED", "true"), default=True),
        geo_provider=os.getenv("GEO_PROVIDER", "ip-api").strip().lower() or "ip-api",
        geo_lookup_timeout=max(0.5, _parse_float(os.getenv("GEO_LOOKUP_TIMEOUT"), 3.0)),
        geo_failure_backoff_seconds=max(5, _parse_int(os.getenv("GEO_FAILURE_BACKOFF_SECONDS"), 300)),
        dashscope_api_key=os.getenv("DASHSCOPE_API_KEY", "").strip(),
        bailian_app_id=os.getenv("BAILIAN_APP_ID", "").strip(),
        bailian_workspace_id=os.getenv("BAILIAN_WORKSPACE_ID", "").strip(),
        bailian_base_url=os.getenv("BAILIAN_BASE_URL", "https://dashscope.aliyuncs.com").rstrip("/"),
        bailian_timeout=_parse_int(os.getenv("BAILIAN_TIMEOUT"), 300),
        screen_target_name=os.getenv("SCREEN_TARGET_NAME", "防护主站").strip() or "防护主站",
        screen_target_label=os.getenv("SCREEN_TARGET_LABEL", "香港 · 业务区").strip() or "香港 · 业务区",
        screen_target_lng=_parse_float(os.getenv("SCREEN_TARGET_LNG"), 114.1694),
        screen_target_lat=_parse_float(os.getenv("SCREEN_TARGET_LAT"), 22.3193),
        screen_flow_debug=_parse_bool(os.getenv("SCREEN_FLOW_DEBUG", "false"), default=False),
    )
