from __future__ import annotations

import json
import logging
import math
import re
import sqlite3
import threading
import time
from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path

from .config import get_settings
from .detection import get_rule_metadata_index
from .ip_geo import classify_special_ip, lookup_ip_geo, should_cache_geo_result

logger = logging.getLogger(__name__)


REGION_BUCKET_RULES = {
    "华北": ("北京", "天津", "河北", "山西", "内蒙古"),
    "华东": ("上海", "江苏", "浙江", "安徽", "福建", "江西", "山东"),
    "华南": ("广东", "广西", "海南"),
    "华中": ("河南", "湖北", "湖南"),
    "西部": ("重庆", "四川", "贵州", "云南", "西藏", "陕西", "甘肃", "青海", "宁夏", "新疆"),
    "东北": ("辽宁", "吉林", "黑龙江"),
}

SCREEN_BUCKET_ORDER = ("华北", "华东", "华南", "华中", "西部", "东北", "本地", "海外", "未知")

SCREEN_TARGET = {
    "name": "防护主站",
    "label": "香港 · 业务区",
    "lng": 114.1694,
    "lat": 22.3193,
}

REGION_COORDINATES = {
    "华北": {"lng": 116.4074, "lat": 39.9042},
    "华东": {"lng": 121.4737, "lat": 31.2304},
    "华南": {"lng": 113.2644, "lat": 23.1291},
    "华中": {"lng": 114.3055, "lat": 30.5928},
    "西部": {"lng": 104.0665, "lat": 30.5728},
    "东北": {"lng": 126.6424, "lat": 45.7567},
    "本地": {"lng": 112.9389, "lat": 28.2282},
    "海外": {"lng": 12.4964, "lat": 41.9028},
    "未知": {"lng": 12.4964, "lat": 41.9028},
}

COUNTRY_COORDINATES = {
    "中国": {"lng": 104.1954, "lat": 35.8617},
    "美国": {"lng": -98.5795, "lat": 39.8283},
    "英国": {"lng": -2.2426, "lat": 53.4808},
    "荷兰": {"lng": 5.2913, "lat": 52.1326},
    "德国": {"lng": 10.4515, "lat": 51.1657},
    "俄罗斯": {"lng": 105.3188, "lat": 61.5240},
    "日本": {"lng": 138.2529, "lat": 36.2048},
    "韩国": {"lng": 127.7669, "lat": 35.9078},
    "新加坡": {"lng": 103.8198, "lat": 1.3521},
    "加拿大": {"lng": -106.3468, "lat": 56.1304},
    "法国": {"lng": 2.2137, "lat": 46.2276},
    "澳大利亚": {"lng": 133.7751, "lat": -25.2744},
    "印度": {"lng": 78.9629, "lat": 20.5937},
    "巴西": {"lng": -51.9253, "lat": -14.2350},
    "中国香港": {"lng": 114.1694, "lat": 22.3193},
    "中国台湾": {"lng": 121.5654, "lat": 23.6978},
    "香港": {"lng": 114.1694, "lat": 22.3193},
    "台湾": {"lng": 121.5654, "lat": 23.6978},
}

PROVINCE_COORDINATES = {
    "北京": {"lng": 116.4074, "lat": 39.9042},
    "天津": {"lng": 117.2000, "lat": 39.1333},
    "河北": {"lng": 114.5149, "lat": 38.0428},
    "山西": {"lng": 112.5489, "lat": 37.8706},
    "内蒙古": {"lng": 111.6708, "lat": 40.8183},
    "上海": {"lng": 121.4737, "lat": 31.2304},
    "江苏": {"lng": 118.7632, "lat": 32.0617},
    "浙江": {"lng": 120.1551, "lat": 30.2741},
    "安徽": {"lng": 117.2830, "lat": 31.8612},
    "江西": {"lng": 115.8582, "lat": 28.6829},
    "广东": {"lng": 113.2644, "lat": 23.1291},
    "湖北": {"lng": 114.3055, "lat": 30.5928},
    "湖南": {"lng": 112.9389, "lat": 28.2282},
    "四川": {"lng": 104.0665, "lat": 30.5728},
    "重庆": {"lng": 106.5516, "lat": 29.5630},
    "山东": {"lng": 117.1201, "lat": 36.6512},
    "福建": {"lng": 119.2965, "lat": 26.0745},
    "河南": {"lng": 113.6254, "lat": 34.7466},
    "海南": {"lng": 110.3312, "lat": 20.0319},
    "辽宁": {"lng": 123.4315, "lat": 41.8057},
    "吉林": {"lng": 125.3235, "lat": 43.8171},
    "黑龙江": {"lng": 126.6424, "lat": 45.7567},
    "陕西": {"lng": 108.9398, "lat": 34.3416},
    "广西": {"lng": 108.3200, "lat": 22.8240},
    "云南": {"lng": 102.7123, "lat": 25.0406},
    "贵州": {"lng": 106.6302, "lat": 26.6470},
    "西藏": {"lng": 91.1172, "lat": 29.6469},
    "甘肃": {"lng": 103.8343, "lat": 36.0611},
    "青海": {"lng": 101.7782, "lat": 36.6171},
    "宁夏": {"lng": 106.2309, "lat": 38.4872},
    "新疆": {"lng": 87.6168, "lat": 43.8256},
    "香港": {"lng": 114.1694, "lat": 22.3193},
    "澳门": {"lng": 113.5439, "lat": 22.1987},
    "台湾": {"lng": 121.5654, "lat": 23.6978},
}

COUNTRY_NAME_ALIASES = {
    "CN": "中国",
    "CHN": "中国",
    "China": "中国",
    "china": "中国",
    "中国大陆": "中国",
    "中华人民共和国": "中国",
    "中国香港": "中国",
    "香港": "中国",
    "Hong Kong": "中国",
    "hong kong": "中国",
    "HK": "中国",
    "中国澳门": "中国",
    "澳门": "中国",
    "Macao": "中国",
    "Macau": "中国",
    "macao": "中国",
    "macau": "中国",
    "中国台湾": "中国",
    "台湾": "中国",
    "Taiwan": "中国",
    "taiwan": "中国",
    "US": "美国",
    "USA": "美国",
    "United States": "美国",
    "United States of America": "美国",
    "united states": "美国",
    "GB": "英国",
    "UK": "英国",
    "United Kingdom": "英国",
    "united kingdom": "英国",
    "JP": "日本",
    "Japan": "日本",
    "DE": "德国",
    "Germany": "德国",
    "SG": "新加坡",
    "Singapore": "新加坡",
    "FR": "法国",
    "France": "法国",
    "CA": "加拿大",
    "Canada": "加拿大",
    "AU": "澳大利亚",
    "Australia": "澳大利亚",
    "IN": "印度",
    "India": "印度",
    "BR": "巴西",
    "Brazil": "巴西",
    "RU": "俄罗斯",
    "Russia": "俄罗斯",
    "KR": "韩国",
    "Korea": "韩国",
    "South Korea": "韩国",
    "NL": "荷兰",
    "Netherlands": "荷兰",
}

CHINA_PROVINCE_ALIASES = {
    "Beijing": "北京",
    "Beijing Municipality": "北京",
    "Tianjin": "天津",
    "Hebei": "河北",
    "Shanxi": "山西",
    "Inner Mongolia": "内蒙古",
    "Inner Mongolia Autonomous Region": "内蒙古",
    "Liaoning": "辽宁",
    "Jilin": "吉林",
    "Heilongjiang": "黑龙江",
    "Shanghai": "上海",
    "Jiangsu": "江苏",
    "Zhejiang": "浙江",
    "Zhejiang Province": "浙江",
    "Anhui": "安徽",
    "Fujian": "福建",
    "Jiangxi": "江西",
    "Shandong": "山东",
    "Henan": "河南",
    "Hubei": "湖北",
    "Hunan": "湖南",
    "Guangdong": "广东",
    "Guangdong Province": "广东",
    "Guangxi": "广西",
    "Guangxi Zhuang Autonomous Region": "广西",
    "Hainan": "海南",
    "Chongqing": "重庆",
    "Sichuan": "四川",
    "Guizhou": "贵州",
    "Yunnan": "云南",
    "Tibet": "西藏",
    "Xizang": "西藏",
    "Shaanxi": "陕西",
    "Gansu": "甘肃",
    "Qinghai": "青海",
    "Ningxia": "宁夏",
    "Xinjiang": "新疆",
    "Hong Kong": "香港",
    "Hong Kong SAR": "香港",
    "HK": "香港",
    "Macao": "澳门",
    "Macau": "澳门",
    "Macao SAR": "澳门",
    "Taiwan": "台湾",
    "台湾省": "台湾",
    "香港特别行政区": "香港",
    "澳门特别行政区": "澳门",
}


def _normalize_geo_name(value: str) -> str:
    text = str(value or "").strip()
    for token in ("省", "市", "特别行政区", "自治区", "壮族", "回族", "维吾尔"):
        text = text.replace(token, "")
    return text.strip()


def _lookup_name_alias(aliases: dict[str, str], value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text in aliases:
        return aliases[text]
    lowered = text.lower()
    for key, alias in aliases.items():
        if key.lower() == lowered:
            return alias
    return text


def _normalize_country_name(value: str) -> str:
    return _lookup_name_alias(COUNTRY_NAME_ALIASES, value)


def _normalize_china_province_name(value: str) -> str:
    text = _lookup_name_alias(CHINA_PROVINCE_ALIASES, value)
    text = _normalize_geo_name(text)
    return _lookup_name_alias(CHINA_PROVINCE_ALIASES, text)


def _contains_cjk(value: str) -> bool:
    return any("\u4e00" <= char <= "\u9fff" for char in str(value or ""))


def _geo_label_parts(label: str) -> list[str]:
    text = str(label or "").strip()
    if not text:
        return []
    return [
        part.strip()
        for part in re.split(r"[/|·,，\s]+", text)
        if part and part.strip()
    ]


def _resolve_chinese_province(country: str, region: str, city: str, label: str = "") -> str:
    for candidate in (region, city, country, *_geo_label_parts(label)):
        province = _normalize_china_province_name(candidate)
        if province in PROVINCE_COORDINATES:
            return province
    return ""


def _build_flow_display_geo(country: str, region: str, city: str, label: str, bucket: str) -> dict[str, str]:
    raw_country = str(country or "").strip()
    display_country = _normalize_country_name(raw_country)
    source_label = str(label or "").strip()
    province = _resolve_chinese_province(raw_country, region, city, source_label)
    normalized_region = _normalize_geo_name(region)
    normalized_city = _normalize_geo_name(city)

    if display_country == "中国" or province:
        display_country = "中国"
        display_region = province
        display_city = normalized_city if normalized_city != display_region and _contains_cjk(normalized_city) else ""
        label_parts = [display_country]
        if display_region:
            label_parts.append(display_region)
        if display_city:
            label_parts.append(display_city)
        display_label = " · ".join(label_parts)
        return {
            "display_country": display_country,
            "display_region": display_region,
            "display_city": display_city,
            "display_label": display_label,
            "source_province": display_region,
        }

    if display_country:
        display_region = normalized_region
        display_city = normalized_city if normalized_city != display_region else ""
        label_parts = [display_country]
        if display_region:
            label_parts.append(display_region)
        elif display_city:
            label_parts.append(display_city)
        return {
            "display_country": display_country,
            "display_region": display_region,
            "display_city": display_city,
            "display_label": " · ".join(label_parts),
            "source_province": "",
        }

    fallback_label = source_label or _build_location_label(country, region, city, bucket)
    return {
        "display_country": "",
        "display_region": "",
        "display_city": "",
        "display_label": fallback_label,
        "source_province": "",
    }


def _geo_coordinates(country: str, region: str, city: str, bucket: str) -> dict:
    normalized_country = _normalize_country_name(country)
    province = _resolve_chinese_province(country, region, city)
    for candidate in (
        city,
        _normalize_geo_name(city),
        region,
        _normalize_geo_name(region),
        province,
        country,
        normalized_country,
        _normalize_geo_name(country),
        bucket,
    ):
        if candidate in PROVINCE_COORDINATES:
            return PROVINCE_COORDINATES[candidate]
        if candidate in COUNTRY_COORDINATES:
            return COUNTRY_COORDINATES[candidate]
        if candidate in REGION_COORDINATES:
            return REGION_COORDINATES[candidate]
    return REGION_COORDINATES["未知"]


def _build_location_label(country: str, region: str, city: str, bucket: str) -> str:
    raw_country = str(country or "").strip()
    country = _normalize_country_name(raw_country)
    region = _normalize_geo_name(region)
    city = _normalize_geo_name(city)
    province = _resolve_chinese_province(raw_country, region, city)

    if country and country != "中国":
        return country
    if province:
        return province
    if city:
        return city
    if region:
        return region
    if bucket in REGION_COORDINATES:
        return bucket
    return "未知"


def _build_screen_flow_name(country: str, region: str, city: str, bucket: str, label: str) -> str:
    raw_country = str(country or "").strip()
    country = _normalize_country_name(raw_country)
    region = _normalize_geo_name(region)
    city = _normalize_geo_name(city)
    label = str(label or "").strip()
    province = _resolve_chinese_province(raw_country, region, city, label)

    if country and country != "中国":
        return _normalize_geo_name(country) or "未知"

    if province:
        return province

    if region:
        return region

    if label:
        parts = [
            _normalize_geo_name(part)
            for part in label.replace("|", "/").replace("·", "/").split("/")
            if _normalize_geo_name(part)
        ]
        if len(parts) >= 2:
            return parts[1]
        if parts:
            return parts[0]

    if city:
        return city

    if bucket in REGION_COORDINATES:
        return bucket

    return "未知"


def _get_screen_target() -> dict[str, object]:
    settings = get_settings()
    return {
        "name": str(settings.screen_target_name or SCREEN_TARGET["name"]).strip() or SCREEN_TARGET["name"],
        "label": str(settings.screen_target_label or SCREEN_TARGET["label"]).strip() or SCREEN_TARGET["label"],
        "lng": float(settings.screen_target_lng),
        "lat": float(settings.screen_target_lat),
    }


SCREEN_GEO_PLACEHOLDER_SOURCE = "screen-placeholder"


def _is_screen_placeholder_geo(geo: dict | None) -> bool:
    return str((geo or {}).get("source") or "").strip().lower() == SCREEN_GEO_PLACEHOLDER_SOURCE


def _ensure_geo(ip: str, geo_cache: dict[str, dict]) -> dict:
    cached = geo_cache.get(ip)
    if cached and not _is_screen_placeholder_geo(cached):
        return cached
    if cached:
        geo_cache.pop(ip, None)

    cached = get_cached_ip_geo(ip)
    if not cached:
        cached = lookup_ip_geo(ip)
        if should_cache_geo_result(cached):
            cache_ip_geo(ip, cached)

    geo_cache[ip] = cached
    return cached


def _screen_geo(ip: str, geo_cache: dict[str, dict], *, eager: bool = False, lookup_cache: bool = True) -> dict:
    ip_text = str(ip or "").strip()
    if not ip_text:
        return {}

    cached = geo_cache.get(ip_text)
    if cached and not _is_screen_placeholder_geo(cached):
        return cached
    if cached:
        geo_cache.pop(ip_text, None)

    special = classify_special_ip(ip_text)
    if special is not None:
        geo_cache[ip_text] = special
        return special

    if lookup_cache:
        cached = get_cached_ip_geo(ip_text)
        if cached:
            geo_cache[ip_text] = cached
            return cached

    if eager:
        return _ensure_geo(ip_text, geo_cache)

    placeholder = {
        "label": "未知位置",
        "country": "",
        "region": "",
        "city": "",
        "isp": "",
        "source": SCREEN_GEO_PLACEHOLDER_SOURCE,
    }
    return placeholder


def _screen_geo_prewarm_ips(rows: list[dict], limit: int = 80) -> set[str]:
    stats: dict[str, dict[str, int]] = {}
    selected: set[str] = set()
    selected_order: list[str] = []

    def add_selected(ip_value: str) -> None:
        if ip_value and ip_value not in selected:
            selected.add(ip_value)
            selected_order.append(ip_value)

    for index, row in enumerate(rows):
        ip = str(row.get("screen_client_ip") or row.get("client_ip") or "").strip()
        if not ip:
            continue
        severity = str(row.get("screen_severity") or row.get("severity") or "").strip().lower()
        action = str(row.get("screen_action") or row.get("action") or "").strip()
        item = stats.setdefault(
            ip,
            {"count": 0, "critical": 0, "high": 0, "blocked": 0, "first_index": index},
        )
        item["count"] += 1
        item["first_index"] = min(item["first_index"], index)
        if severity == "critical":
            item["critical"] += 1
        if is_high_risk_severity(severity):
            item["high"] += 1
        if action == "blocked":
            item["blocked"] += 1
        if index < min(SCREEN_RAW_FLOW_LIMIT, limit):
            add_selected(ip)

    ranked = sorted(
        stats.items(),
        key=lambda item: (
            int(item[1]["critical"]),
            int(item[1]["high"]),
            int(item[1]["blocked"]),
            int(item[1]["count"]),
            -int(item[1]["first_index"]),
        ),
        reverse=True,
    )
    for ip, _stats in ranked[:max(16, limit // 4)]:
        add_selected(ip)
    return set(selected_order[:limit])


def _stable_text_hash(value: str) -> int:
    seed = 2166136261
    for char in str(value or ""):
        seed ^= ord(char)
        seed = (seed * 16777619) & 0xFFFFFFFF
    return seed


def _pseudo_geo_from_ip(ip: str, target_lng: float, target_lat: float) -> dict:
    seed = _stable_text_hash(ip)
    lng = ((seed & 0xFFFF) / 0xFFFF) * 358.0 - 179.0
    lat = (((seed >> 16) & 0xFFFF) / 0xFFFF) * 125.0 - 55.0
    if abs(lng - float(target_lng)) < 18.0 and abs(lat - float(target_lat)) < 12.0:
        lng = ((lng + 83.0 + 180.0) % 358.0) - 179.0
        lat = max(-55.0, min(70.0, -lat + 18.0))
    return {"lng": max(-179.0, min(179.0, lng)), "lat": max(-55.0, min(70.0, lat))}


def _pseudo_geo_tile(coords: dict) -> str:
    lng = round(float(coords.get("lng") or 0.0), 1)
    lat = round(float(coords.get("lat") or 0.0), 1)
    return f"{lng}:{lat}"


def _is_resolved_screen_geo(geo: dict | None) -> bool:
    source = str((geo or {}).get("source") or "").strip().lower()
    if source == "local":
        return True
    if source != "remote":
        return False
    return any(str((geo or {}).get(key) or "").strip() for key in ("country", "region", "city"))


ALERT_STATUS_DISPOSITIONS = (
    "real_attack",
    "customer_business",
    "pending_business",
    "notified_event",
    "whitelist_traffic",
)
ALERT_STATUS_ATTACK_DISPOSITIONS = tuple(
    status for status in ALERT_STATUS_DISPOSITIONS if status != "whitelist_traffic"
)
ALERT_STATUS_ALERT_VIEW = ALERT_STATUS_ATTACK_DISPOSITIONS
ALERT_STATUS_ACTIVE = ALERT_STATUS_DISPOSITIONS

VALID_SEVERITIES = ("critical", "high", "medium", "low")
HIGH_RISK_SEVERITIES = ("critical", "high")
# 大屏热数据与冷数据分层缓存，避免每次都重复做整批聚合。
# Performance-only: align cache reuse with the visible-page polling cadence.
SCREEN_SUMMARY_CACHE_TTL_SECONDS = 7
SCREEN_DETAIL_CACHE_TTL_SECONDS = 7
_SCREEN_CACHE_LOCK = threading.Lock()
_SCREEN_CACHE = {
    "summary": {"hours": None, "expires_at": 0.0, "updated_at": "", "payload": None},
    "detail": {"hours": None, "expires_at": 0.0, "updated_at": "", "payload": None},
}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _screen_cache_stamp(kind: str, hours: int) -> str:
    with _SCREEN_CACHE_LOCK:
        record = _SCREEN_CACHE.get(kind, {})
        if record.get("hours") != hours:
            return ""
        return str(record.get("updated_at") or "")


def _screen_cache_response(kind: str, hours: int) -> dict | None:
    now = time.monotonic()
    with _SCREEN_CACHE_LOCK:
        record = _SCREEN_CACHE.get(kind, {})
        if (
            record.get("payload") is None
            or record.get("hours") != hours
            or now >= float(record.get("expires_at") or 0.0)
        ):
            return None
        payload = dict(record["payload"])
    payload["server_time"] = utcnow_iso()
    return payload


def _screen_cache_store(kind: str, hours: int, ttl_seconds: int, payload: dict, updated_at: str) -> dict:
    stored_payload = dict(payload)
    with _SCREEN_CACHE_LOCK:
        _SCREEN_CACHE[kind] = {
            "hours": hours,
            "expires_at": time.monotonic() + max(1, ttl_seconds),
            "updated_at": updated_at,
            "payload": stored_payload,
        }
    response = dict(stored_payload)
    response["server_time"] = utcnow_iso()
    return response


def _screen_cache_stale(kind: str, hours: int, error: Exception | str, fallback: dict) -> dict:
    message = str(error)
    with _SCREEN_CACHE_LOCK:
        record = _SCREEN_CACHE.get(kind, {})
        if record.get("payload") is not None and record.get("hours") == hours:
            payload = dict(record["payload"])
            payload["server_time"] = utcnow_iso()
            payload["stale"] = True
            payload["error"] = message
            return payload
    fallback_payload = dict(fallback)
    fallback_payload["server_time"] = utcnow_iso()
    fallback_payload["stale"] = True
    fallback_payload["error"] = message
    return fallback_payload


def get_connection() -> sqlite3.Connection:
    db_path = get_settings().db_path
    connection = sqlite3.connect(db_path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL;")
    connection.execute("PRAGMA synchronous=NORMAL;")
    return connection


def ensure_column(connection: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


STATIC_RULE_METADATA = {
    "manual_block": {"category": "policy", "layer": "policy", "severity": "high", "score": 85},
    "cc_attack": {"category": "rate_limit", "layer": "behavior", "severity": "medium", "score": 60},
    "brute_force": {"category": "auth", "layer": "behavior", "severity": "high", "score": 88},
    "security_guard": {"category": "generic", "layer": "content", "severity": "low", "score": 40},
}


def _default_rule_metadata(attack_type: str | None) -> dict[str, object]:
    attack_type = str(attack_type or "").strip()
    if not attack_type:
        return {"category": None, "layer": None, "severity": None, "score": 0}
    rule_meta = get_rule_metadata_index().get(attack_type)
    if rule_meta:
        return dict(rule_meta)
    return dict(
        STATIC_RULE_METADATA.get(
            attack_type,
            {"category": "generic", "layer": "content", "severity": "medium", "score": 45},
        )
    )


def _normalize_risk_score(risk_score: int | None, attack_type: str | None) -> int:
    fallback = int(_default_rule_metadata(attack_type).get("score") or 0)
    try:
        score = int(risk_score if risk_score is not None else fallback)
    except (TypeError, ValueError):
        score = fallback
    return max(0, min(score, 100))


def _normalize_severity(value: str | None) -> str | None:
    candidate = str(value or "").strip().lower()
    if candidate in VALID_SEVERITIES:
        return candidate
    return None


def classify_log(
    action: str,
    attack_type: str | None,
    *,
    risk_score: int | None = None,
    rule_category: str | None = None,
    severity_hint: str | None = None,
) -> tuple[str, str]:
    hinted_severity = _normalize_severity(severity_hint)
    if action == "allowed":
        if hinted_severity in HIGH_RISK_SEVERITIES:
            return hinted_severity, "real_attack"
        return "low", "not_applicable"

    if action == "error":
        return "medium", "pending_business"

    metadata = _default_rule_metadata(attack_type)
    score = _normalize_risk_score(risk_score, attack_type)
    category = str(rule_category or metadata.get("category") or "").strip().lower()
    severity = hinted_severity or _normalize_severity(metadata.get("severity"))

    if not severity:
        if score >= 90 or category in {"cve", "webshell"}:
            severity = "critical"
        elif score >= 75 or category in {"rce", "sqli", "auth"}:
            severity = "high"
        elif score >= 45 or action == "blocked":
            severity = "medium"
        else:
            severity = "low"

    if severity in HIGH_RISK_SEVERITIES or category in {"cve", "rce", "webshell", "sqli", "auth"}:
        return severity, "real_attack"

    if severity == "medium" or action == "blocked":
        return "medium", "pending_business"

    return severity, "not_applicable"


def is_high_risk_severity(value: str | None) -> bool:
    return str(value or "").strip().lower() in HIGH_RISK_SEVERITIES


def normalize_log_severity(value: str | None) -> str:
    return _normalize_severity(value) or "medium"


def build_severity_distribution(rows: list[sqlite3.Row | dict]) -> list[dict]:
    counts = {key: 0 for key in VALID_SEVERITIES}
    for row in rows:
        severity = normalize_log_severity((row["severity"] if isinstance(row, sqlite3.Row) else row.get("severity")))
        counts[severity] += 1

    labels = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
    }
    return [{"name": labels[key], "count": counts[key]} for key in VALID_SEVERITIES]


SCREEN_SEGMENT_BUSINESS_NORMAL = "business_normal"
SCREEN_SEGMENT_BUSINESS_FALSE_POSITIVE = "business_false_positive"
SCREEN_SEGMENT_WHITELIST = "whitelist_traffic"
SCREEN_SEGMENT_ATTACK_SUSPECTED = "attack_suspected"
SCREEN_SEGMENT_ATTACK_CONFIRMED = "attack_confirmed"
SCREEN_SEGMENTS = (
    SCREEN_SEGMENT_BUSINESS_NORMAL,
    SCREEN_SEGMENT_BUSINESS_FALSE_POSITIVE,
    SCREEN_SEGMENT_WHITELIST,
    SCREEN_SEGMENT_ATTACK_SUSPECTED,
    SCREEN_SEGMENT_ATTACK_CONFIRMED,
)
SCREEN_AUTO_WHITELIST_PATHS = {"/", "/favicon.ico"}
SCREEN_LOW_RISK_NOISE_PATHS = {
    "/robots.txt",
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/live",
    "/livez",
    "/metrics",
    "/status",
    "/ping",
}
SCREEN_STATIC_PATH_PREFIXES = (
    "/static/",
    "/assets/",
    "/images/",
    "/img/",
    "/css/",
    "/js/",
    "/fonts/",
    "/vendor/",
    "/webjars/",
    "/public/",
)
SCREEN_CALLBACK_PATH_KEYWORDS = ("callback", "callbacks", "webhook", "notify", "notification", "oauth", "sso")
SCREEN_BUSINESS_HOST_EXACT = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
SCREEN_BUSINESS_HOST_SUFFIXES = (".internal", ".local", ".localhost", ".svc", ".svc.cluster.local")
SCREEN_TRUSTED_CLIENT_CIDRS = (
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)
SCREEN_STRONG_ATTACK_CATEGORIES = {
    "auth",
    "cve",
    "deserialization",
    "file_inclusion",
    "ldap",
    "nosql",
    "path_traversal",
    "rce",
    "sqli",
    "ssrf",
    "ssti",
    "webshell",
    "xxe",
}
SCREEN_HIGH_CONFIDENCE_ATTACK_TYPES = {
    "brute_force",
    "command_injection",
    "deserialization_probe",
    "file_inclusion",
    "ldap_injection",
    "nosql_injection",
    "path_traversal",
    "sql_injection",
    "ssrf",
    "ssti",
    "webshell_probe",
    "webshell_upload",
    "xss",
    "xxe_injection",
}
SCREEN_PROBE_ATTACK_PREFIXES = (
    "scanner_probe",
    "sensitive_probe",
    "java_",
    "php_",
)
SCREEN_OFFENSIVE_UA_PATTERNS = (
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"nuclei", re.IGNORECASE),
    re.compile(r"dirsearch", re.IGNORECASE),
    re.compile(r"gobuster", re.IGNORECASE),
    re.compile(r"feroxbuster", re.IGNORECASE),
    re.compile(r"ffuf", re.IGNORECASE),
    re.compile(r"masscan", re.IGNORECASE),
    re.compile(r"nmap", re.IGNORECASE),
    re.compile(r"zgrab", re.IGNORECASE),
    re.compile(r"nikto", re.IGNORECASE),
    re.compile(r"hydra", re.IGNORECASE),
    re.compile(r"wpscan", re.IGNORECASE),
    re.compile(r"whatweb", re.IGNORECASE),
    re.compile(r"acunetix", re.IGNORECASE),
)
SCREEN_HEALTHCHECK_UA_PATTERNS = (
    re.compile(r"kube-probe", re.IGNORECASE),
    re.compile(r"prometheus", re.IGNORECASE),
    re.compile(r"health.?check", re.IGNORECASE),
    re.compile(r"googlehc", re.IGNORECASE),
    re.compile(r"elb-healthchecker", re.IGNORECASE),
    re.compile(r"uptime", re.IGNORECASE),
    re.compile(r"statuscake", re.IGNORECASE),
)
SCREEN_BUSINESS_HEADER_PATTERNS = (
    re.compile(r"^stripe-signature$", re.IGNORECASE),
    re.compile(r"^x-github-event$", re.IGNORECASE),
    re.compile(r"^x-gitlab-event$", re.IGNORECASE),
    re.compile(r"^x-hub-signature(?:-256)?$", re.IGNORECASE),
    re.compile(r"^x-slack-signature$", re.IGNORECASE),
    re.compile(r"^x-shopify-topic$", re.IGNORECASE),
    re.compile(r"^x-wechat-signature$", re.IGNORECASE),
    re.compile(r"^x-lark-signature$", re.IGNORECASE),
    re.compile(r"^x-webhook-(?:id|signature)$", re.IGNORECASE),
    re.compile(r"^x-callback-token$", re.IGNORECASE),
    re.compile(r"^x-business-[\\w-]+$", re.IGNORECASE),
)
SCREEN_STRONG_PAYLOAD_PATTERN = re.compile(
    r"(?i)(?:"
    r"\.\./|%2e%2e%2f|%252e%252e|"
    r"/etc/passwd|cmd(?:=|%3d)|"
    r"\bunion\b.{0,24}\bselect\b|select.{0,24}\bfrom\b|"
    r"sleep\s*\(|benchmark\s*\(|xp_cmdshell|"
    r"<script\b|%3cscript|"
    r"/bin/(?:sh|bash)|cmd\.exe|powershell(?:\.exe)?|"
    r";\s*(?:cat|wget|curl|bash|sh)\b|"
    r"\$\{jndi:|jndi:(?:ldap|rmi|dns)|"
    r"nslookup\b|base64_decode\s*\(|shell_exec\s*\(|assert\s*\(|"
    r"<\?php|webshell"
    r")"
)


def _coerce_row_dict(row: sqlite3.Row | dict | None) -> dict:
    if isinstance(row, dict):
        return row
    if isinstance(row, sqlite3.Row):
        return dict(row)
    return dict(row or {})


def _normalize_screen_path(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return "/"
    path = text.split("?", 1)[0].strip() or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return path


def _normalize_screen_host(value: str | None) -> str:
    return str(value or "").strip().lower()


def _normalize_screen_alert_status_value(value: str | None) -> str:
    status = str(value or "").strip().lower()
    if status in {"resolved", "resolved_event"}:
        return "notified_event"
    if status in {*ALERT_STATUS_DISPOSITIONS, "not_applicable"}:
        return status
    return ""


def _parse_screen_headers(value: object) -> dict[str, str]:
    if isinstance(value, dict):
        headers = value
    elif isinstance(value, str):
        try:
            headers = json.loads(value)
        except Exception:
            headers = {"raw": value}
    else:
        headers = {}

    normalized: dict[str, str] = {}
    for key, header_value in (headers or {}).items():
        header_key = str(key or "").strip().lower()
        if not header_key:
            continue
        normalized[header_key] = str(header_value or "").strip()
    return normalized


def _screen_trusted_ip_rules() -> tuple[str, ...]:
    rules = list(SCREEN_TRUSTED_CLIENT_CIDRS)
    for raw_value in get_settings().allow_ips:
        candidate = str(raw_value or "").strip()
        if not candidate:
            continue
        if "/" in candidate:
            rules.append(candidate)
            continue
        try:
            suffix = "/32" if ip_address(candidate).version == 4 else "/128"
            rules.append(f"{candidate}{suffix}")
        except ValueError:
            continue
    return tuple(dict.fromkeys(rules))


def _screen_business_path_prefixes() -> tuple[str, ...]:
    configured = tuple(str(item or "").strip() for item in get_settings().allow_path_prefixes if str(item or "").strip())
    return tuple(dict.fromkeys(configured + SCREEN_STATIC_PATH_PREFIXES))


def _screen_ip_in_networks(ip_text: str | None, networks: tuple[str, ...] | list[str]) -> bool:
    ip_candidate = str(ip_text or "").strip()
    if not ip_candidate:
        return False
    try:
        source_ip = ip_address(ip_candidate)
    except ValueError:
        return False

    for raw_network in networks:
        candidate = str(raw_network or "").strip()
        if not candidate:
            continue
        try:
            if source_ip in ip_network(candidate, strict=False):
                return True
        except ValueError:
            continue
    return False


def _screen_matches_header_patterns(headers: dict[str, str], patterns: tuple[re.Pattern[str], ...]) -> bool:
    for key, value in (headers or {}).items():
        for pattern in patterns:
            if pattern.search(key) or pattern.search(value):
                return True
    return False


def _screen_matches_user_agent(user_agent: str, patterns: tuple[re.Pattern[str], ...]) -> bool:
    return any(pattern.search(user_agent or "") for pattern in patterns)


def _is_high_confidence_attack_type(attack_type: str, rule_category: str, cve_id: str) -> bool:
    attack = str(attack_type or "").strip().lower()
    category = str(rule_category or "").strip().lower()
    if cve_id:
        return True
    if attack.startswith("cve_") or attack == "cve_exploit_attempt":
        return True
    if attack in SCREEN_HIGH_CONFIDENCE_ATTACK_TYPES:
        return True
    return category in SCREEN_STRONG_ATTACK_CATEGORIES


def _is_low_confidence_probe(attack_type: str, rule_category: str) -> bool:
    attack = str(attack_type or "").strip().lower()
    category = str(rule_category or "").strip().lower()
    if not attack and not category:
        return True
    if category in {"generic", "rate_limit", "scanner"}:
        return True
    return any(attack.startswith(prefix) for prefix in SCREEN_PROBE_ATTACK_PREFIXES)


def _screen_combined_text(row: dict) -> str:
    return " ".join(
        part
        for part in (
            str(row.get("screen_path") or ""),
            str(row.get("query_string") or ""),
            str(row.get("attack_detail") or ""),
            str(row.get("body_preview") or ""),
            str(row.get("matched_field") or ""),
        )
        if part
    )


def _match_screen_known_business_rule(row: sqlite3.Row | dict) -> str:
    context = _coerce_row_dict(row)
    path = str(context.get("screen_path") or _normalize_screen_path(context.get("path")))
    method = str(context.get("screen_method") or str(context.get("method") or "").strip().upper())
    client_ip = str(context.get("screen_client_ip") or str(context.get("client_ip") or "").strip())
    destination_host = str(context.get("screen_destination_host") or _normalize_screen_host(context.get("destination_host")))
    request_host = str(context.get("screen_request_host") or _normalize_screen_host(context.get("request_host")))
    user_agent = str(context.get("screen_user_agent") or str(context.get("user_agent") or ""))
    headers = context.get("screen_request_headers")
    if not isinstance(headers, dict):
        headers = _parse_screen_headers(context.get("request_headers"))

    if _screen_ip_in_networks(client_ip, _screen_trusted_ip_rules()):
        return "trusted_client_ip"

    for host in (destination_host, request_host):
        if not host:
            continue
        if host in SCREEN_BUSINESS_HOST_EXACT or any(host.endswith(suffix) for suffix in SCREEN_BUSINESS_HOST_SUFFIXES):
            return "trusted_host"

    if path in SCREEN_LOW_RISK_NOISE_PATHS and method in {"GET", "HEAD"}:
        return "low_risk_noise_path"

    if any(path.startswith(prefix) for prefix in _screen_business_path_prefixes()) and method in {"GET", "HEAD"}:
        return "static_or_allowed_prefix"

    if any(keyword in path.lower() for keyword in SCREEN_CALLBACK_PATH_KEYWORDS) and _screen_matches_header_patterns(
        headers,
        SCREEN_BUSINESS_HEADER_PATTERNS,
    ):
        return "callback_path"

    if _screen_matches_user_agent(user_agent, SCREEN_HEALTHCHECK_UA_PATTERNS):
        return "healthcheck_user_agent"

    if _screen_matches_header_patterns(headers, SCREEN_BUSINESS_HEADER_PATTERNS):
        return "business_header"

    return ""


def _has_screen_strong_attack_signal(row: sqlite3.Row | dict) -> bool:
    context = _coerce_row_dict(row)
    alert_status = str(context.get("screen_alert_status") or _normalize_screen_alert_status_value(context.get("alert_status")))
    action = str(context.get("screen_action") or str(context.get("action") or "").strip().lower())
    severity = normalize_log_severity(context.get("screen_severity") or context.get("severity"))
    attack_type = str(context.get("screen_attack_type") or str(context.get("attack_type") or "").strip())
    rule_category = str(context.get("screen_rule_category") or str(context.get("rule_category") or "").strip().lower())
    cve_id = str(context.get("screen_cve_id") or str(context.get("cve_id") or "").strip())
    user_agent = str(context.get("screen_user_agent") or str(context.get("user_agent") or ""))

    if alert_status == "real_attack":
        return True
    if severity in HIGH_RISK_SEVERITIES:
        return True
    if _is_high_confidence_attack_type(attack_type, rule_category, cve_id):
        return True
    if _screen_matches_user_agent(user_agent, SCREEN_OFFENSIVE_UA_PATTERNS):
        return True
    if SCREEN_STRONG_PAYLOAD_PATTERN.search(str(context.get("screen_text_blob") or _screen_combined_text(context))):
        return True
    return False


def is_auto_whitelist_noise(row: sqlite3.Row | dict) -> bool:
    context = _coerce_row_dict(row)
    alert_status = str(context.get("screen_alert_status") or _normalize_screen_alert_status_value(context.get("alert_status")))
    action = str(context.get("screen_action") or str(context.get("action") or "").strip().lower())
    severity = normalize_log_severity(context.get("screen_severity") or context.get("severity"))
    method = str(context.get("screen_method") or str(context.get("method") or "").strip().upper())
    path = str(context.get("screen_path") or _normalize_screen_path(context.get("path")))
    attack_type = str(context.get("screen_attack_type") or str(context.get("attack_type") or "").strip())
    rule_category = str(context.get("screen_rule_category") or str(context.get("rule_category") or "").strip().lower())

    if path not in SCREEN_AUTO_WHITELIST_PATHS:
        return False
    if method not in {"GET", "HEAD"}:
        return False
    if alert_status in {"real_attack", "notified_event"}:
        return False
    if severity in HIGH_RISK_SEVERITIES:
        return False
    if _has_screen_strong_attack_signal(context):
        return False
    if action not in {"allowed", "blocked", ""}:
        return False
    if action == "blocked" and not _is_low_confidence_probe(attack_type, rule_category):
        return False
    return True


def apply_screen_auto_whitelist(row: sqlite3.Row | dict) -> dict:
    context = _coerce_row_dict(row)
    if not is_auto_whitelist_noise(context):
        return context
    context["screen_auto_whitelist"] = True
    context["screen_segment"] = SCREEN_SEGMENT_WHITELIST
    context["screen_effective_alert_status"] = "whitelist_traffic"
    context["screen_effective_disposition"] = "whitelist_traffic"
    context["screen_effective_handled"] = True
    context["screen_effective_traffic_kind"] = "normal"
    return context


def classify_screen_segment(row: sqlite3.Row | dict) -> str:
    context = _coerce_row_dict(row)
    existing = str(context.get("screen_segment") or "").strip()
    if existing in SCREEN_SEGMENTS:
        return existing

    context = apply_screen_auto_whitelist(context)
    existing = str(context.get("screen_segment") or "").strip()
    if existing in SCREEN_SEGMENTS:
        return existing

    alert_status = str(
        context.get("screen_effective_alert_status")
        or context.get("screen_alert_status")
        or _normalize_screen_alert_status_value(context.get("alert_status"))
    )
    if alert_status == "whitelist_traffic":
        context["screen_segment"] = SCREEN_SEGMENT_WHITELIST
        return SCREEN_SEGMENT_WHITELIST
    action = str(context.get("screen_action") or str(context.get("action") or "").strip().lower())
    attack_type = str(context.get("screen_attack_type") or str(context.get("attack_type") or "").strip())
    rule_category = str(context.get("screen_rule_category") or str(context.get("rule_category") or "").strip().lower())
    traffic_kind = str(context.get("screen_traffic_kind") or str(context.get("traffic_kind") or "").strip().lower())
    business_rule = str(context.get("screen_business_rule") or _match_screen_known_business_rule(context))
    strong_attack = bool(context.get("screen_has_strong_attack_signal"))
    if "screen_has_strong_attack_signal" not in context:
        strong_attack = _has_screen_strong_attack_signal(context)
    high_confidence = _is_high_confidence_attack_type(
        attack_type,
        rule_category,
        str(context.get("screen_cve_id") or str(context.get("cve_id") or "").strip()),
    )
    severity = normalize_log_severity(context.get("screen_severity") or context.get("severity"))
    business_suppressed = bool(business_rule and not strong_attack and not high_confidence and alert_status != "real_attack")
    flagged = bool(
        attack_type
        or traffic_kind == "abnormal"
        or action in {"blocked", "error"}
        or alert_status in ALERT_STATUS_ACTIVE
    )
    attack_candidate = bool(
        alert_status == "real_attack"
        or strong_attack
        or (alert_status == "notified_event" and (high_confidence or severity in HIGH_RISK_SEVERITIES))
        or (severity in HIGH_RISK_SEVERITIES and flagged)
        or (high_confidence and action in {"blocked", "error"})
    )

    if alert_status == "real_attack":
        segment = SCREEN_SEGMENT_ATTACK_CONFIRMED
    elif alert_status == "customer_business":
        segment = SCREEN_SEGMENT_BUSINESS_FALSE_POSITIVE
    elif business_suppressed and not attack_candidate:
        segment = SCREEN_SEGMENT_BUSINESS_FALSE_POSITIVE if flagged else SCREEN_SEGMENT_BUSINESS_NORMAL
    elif alert_status == "notified_event":
        segment = SCREEN_SEGMENT_ATTACK_CONFIRMED if attack_candidate or strong_attack else SCREEN_SEGMENT_BUSINESS_FALSE_POSITIVE
    elif alert_status == "pending_business":
        segment = SCREEN_SEGMENT_ATTACK_SUSPECTED if attack_candidate and not business_suppressed else SCREEN_SEGMENT_BUSINESS_FALSE_POSITIVE
    elif attack_candidate and not business_suppressed:
        segment = SCREEN_SEGMENT_ATTACK_SUSPECTED
    elif flagged:
        segment = SCREEN_SEGMENT_BUSINESS_FALSE_POSITIVE
    else:
        segment = SCREEN_SEGMENT_BUSINESS_NORMAL

    context["screen_segment"] = segment
    return segment


def _screen_disposition_for_row(row: sqlite3.Row | dict) -> str:
    context = _coerce_row_dict(row)
    existing = str(context.get("screen_effective_disposition") or "").strip()
    if existing:
        return existing

    segment = classify_screen_segment(context)
    alert_status = str(context.get("screen_alert_status") or _normalize_screen_alert_status_value(context.get("alert_status")))
    disposition = _normalize_screen_disposition(alert_status)

    if segment == SCREEN_SEGMENT_WHITELIST:
        disposition = "whitelist_traffic"
    elif not disposition:
        if segment == SCREEN_SEGMENT_ATTACK_CONFIRMED:
            disposition = "real_attack"
        elif segment == SCREEN_SEGMENT_ATTACK_SUSPECTED:
            disposition = "pending_business"
        elif segment == SCREEN_SEGMENT_BUSINESS_FALSE_POSITIVE:
            disposition = "customer_business" if context.get("screen_business_rule") else "pending_business"

    context["screen_effective_disposition"] = disposition
    return disposition


def is_screen_attack_row(row: sqlite3.Row | dict) -> bool:
    return classify_screen_segment(row) in {SCREEN_SEGMENT_ATTACK_CONFIRMED, SCREEN_SEGMENT_ATTACK_SUSPECTED}


def is_screen_handled_row(row: sqlite3.Row | dict) -> bool:
    context = _coerce_row_dict(row)
    existing = context.get("screen_effective_handled")
    if isinstance(existing, bool):
        return existing

    handled_status = str(context.get("screen_handled_status") or str(context.get("handled_status") or "unhandled")).strip().lower()
    alert_status = str(
        context.get("screen_effective_alert_status")
        or context.get("screen_alert_status")
        or _normalize_screen_alert_status_value(context.get("alert_status"))
    )
    handled = (
        classify_screen_segment(context) == SCREEN_SEGMENT_WHITELIST
        or handled_status == "handled"
        or alert_status in {"notified_event", "whitelist_traffic"}
    )
    context["screen_effective_handled"] = handled
    return handled


def _prepare_screen_row(row: sqlite3.Row | dict) -> dict:
    context = _coerce_row_dict(row)
    if context.get("_screen_context_ready"):
        return context

    headers = _parse_screen_headers(context.get("request_headers"))
    context["screen_request_headers"] = headers
    context["screen_client_ip"] = str(context.get("client_ip") or "").strip()
    context["screen_destination_host"] = _normalize_screen_host(context.get("destination_host"))
    context["screen_request_host"] = _normalize_screen_host(context.get("request_host"))
    context["screen_method"] = str(context.get("method") or "").strip().upper()
    context["screen_path"] = _normalize_screen_path(context.get("path"))
    context["screen_action"] = str(context.get("action") or "").strip().lower()
    context["screen_attack_type"] = str(context.get("attack_type") or "").strip()
    context["screen_cve_id"] = str(context.get("cve_id") or "").strip()
    context["screen_rule_category"] = str(context.get("rule_category") or "").strip().lower()
    context["screen_rule_layer"] = str(context.get("rule_layer") or "").strip().lower()
    context["screen_severity"] = normalize_log_severity(context.get("severity"))
    context["screen_alert_status"] = _normalize_screen_alert_status_value(context.get("alert_status"))
    context["screen_handled_status"] = str(context.get("handled_status") or "unhandled").strip().lower()
    context["screen_traffic_kind"] = str(context.get("traffic_kind") or "").strip().lower()
    context["screen_user_agent"] = str(context.get("user_agent") or "")
    context["screen_text_blob"] = _screen_combined_text(context)
    context["screen_business_rule"] = _match_screen_known_business_rule(context)
    context["screen_has_strong_attack_signal"] = _has_screen_strong_attack_signal(context)
    effective_state = derive_effective_log_state(context)
    context["screen_alert_status"] = effective_state["effective_alert_status"]
    context["screen_handled_status"] = effective_state["effective_handled_status"]
    context["screen_traffic_kind"] = effective_state["effective_traffic_kind"]
    context["screen_effective_alert_status"] = effective_state["effective_alert_status"]
    context["screen_effective_disposition"] = effective_state["effective_disposition"]
    context["screen_effective_handled"] = effective_state["effective_handled_status"] == "handled"
    context["screen_effective_traffic_kind"] = effective_state["effective_traffic_kind"]
    context["_screen_context_ready"] = True
    classify_screen_segment(context)
    _screen_disposition_for_row(context)
    is_screen_handled_row(context)
    return context


def _normalize_effective_alert_status(value: str | None) -> str:
    return _normalize_screen_alert_status_value(value) or "not_applicable"


def classify_traffic_kind(
    action: str,
    attack_type: str | None,
    alert_status: str | None,
    *,
    strong_attack_signal: bool = False,
) -> str:
    normalized_status = _normalize_effective_alert_status(alert_status)
    if normalized_status == "whitelist_traffic":
        return "normal"
    if normalized_status in ALERT_STATUS_ATTACK_DISPOSITIONS:
        return "abnormal"
    if strong_attack_signal:
        return "abnormal"
    if str(action or "").strip().lower() in {"blocked", "error"}:
        return "abnormal"
    if str(attack_type or "").strip():
        return "abnormal"
    return "normal"


def derive_effective_log_state(row: sqlite3.Row | dict | None = None, **fields: object) -> dict[str, str]:
    context = _coerce_row_dict(row)
    context.update(fields)

    alert_status = _normalize_effective_alert_status(
        context.get("screen_alert_status") or context.get("alert_status")
    )
    handled_status = str(
        context.get("screen_handled_status") or context.get("handled_status") or "unhandled"
    ).strip().lower()
    if handled_status not in {"handled", "unhandled"}:
        handled_status = "unhandled"

    context["alert_status"] = alert_status
    context["screen_alert_status"] = alert_status
    strong_attack_signal = _has_screen_strong_attack_signal(context)

    if alert_status != "whitelist_traffic" and is_auto_whitelist_noise(context):
        alert_status = "whitelist_traffic"
        handled_status = "handled"
    elif alert_status in {"whitelist_traffic", "notified_event"}:
        handled_status = "handled"

    traffic_kind = classify_traffic_kind(
        str(context.get("screen_action") or context.get("action") or ""),
        str(context.get("screen_attack_type") or context.get("attack_type") or ""),
        alert_status,
        strong_attack_signal=strong_attack_signal,
    )
    if alert_status == "whitelist_traffic":
        traffic_kind = "normal"

    disposition = "reported_alert" if alert_status == "notified_event" else (
        alert_status if alert_status in SCREEN_DISPOSITION_KEYS else ""
    )
    return {
        "effective_alert_status": alert_status,
        "effective_handled_status": handled_status,
        "effective_traffic_kind": traffic_kind,
        "effective_disposition": disposition,
    }


def init_db() -> None:
    with closing(get_connection()) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                destination_host TEXT,
                request_host TEXT,
                destination_ip TEXT,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                query_string TEXT,
                user_agent TEXT,
                request_headers TEXT,
                action TEXT NOT NULL,
                attack_type TEXT,
                attack_detail TEXT,
                cve_id TEXT,
                severity TEXT,
                alert_status TEXT,
                handled_status TEXT,
                traffic_kind TEXT,
                rule_category TEXT,
                rule_layer TEXT,
                matched_field TEXT,
                risk_score INTEGER,
                status_updated_at TEXT,
                status_code INTEGER,
                upstream_status INTEGER,
                duration_ms INTEGER,
                body_preview TEXT
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                reason TEXT,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cc_bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                reason TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                path TEXT NOT NULL,
                success INTEGER NOT NULL,
                status_code INTEGER
            );

            CREATE TABLE IF NOT EXISTS ip_geo_cache (
                ip TEXT PRIMARY KEY,
                label TEXT,
                country TEXT,
                region TEXT,
                city TEXT,
                isp TEXT,
                source TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_request_logs_created_at
            ON request_logs(created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_request_logs_client_ip
            ON request_logs(client_ip);

            CREATE INDEX IF NOT EXISTS idx_request_logs_client_ip_created_at
            ON request_logs(client_ip, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_request_logs_action_created_at
            ON request_logs(action, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_request_logs_traffic_kind_created_at
            ON request_logs(traffic_kind, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_request_logs_attack_type_created_at
            ON request_logs(attack_type, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_request_logs_severity_created_at
            ON request_logs(severity, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_request_logs_path_created_at
            ON request_logs(path, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_request_logs_handled_status_created_at
            ON request_logs(handled_status, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_request_logs_alert_status_created_at
            ON request_logs(alert_status, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_request_logs_destination_host_created_at
            ON request_logs(destination_host, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_cc_bans_expires_at
            ON cc_bans(expires_at DESC);

            CREATE INDEX IF NOT EXISTS idx_ip_geo_cache_updated_at
            ON ip_geo_cache(updated_at DESC);

            CREATE INDEX IF NOT EXISTS idx_auth_attempts_ip_created_at
            ON auth_attempts(client_ip, created_at DESC);
            """
        )
        ensure_column(connection, "request_logs", "destination_host", "destination_host TEXT")
        ensure_column(connection, "request_logs", "request_host", "request_host TEXT")
        ensure_column(connection, "request_logs", "destination_ip", "destination_ip TEXT")
        ensure_column(connection, "request_logs", "severity", "severity TEXT")
        ensure_column(connection, "request_logs", "alert_status", "alert_status TEXT")
        ensure_column(connection, "request_logs", "handled_status", "handled_status TEXT")
        ensure_column(connection, "request_logs", "status_updated_at", "status_updated_at TEXT")
        ensure_column(connection, "request_logs", "cve_id", "cve_id TEXT")
        ensure_column(connection, "request_logs", "request_headers", "request_headers TEXT")
        ensure_column(connection, "request_logs", "traffic_kind", "traffic_kind TEXT")
        ensure_column(connection, "request_logs", "rule_category", "rule_category TEXT")
        ensure_column(connection, "request_logs", "rule_layer", "rule_layer TEXT")
        ensure_column(connection, "request_logs", "matched_field", "matched_field TEXT")
        ensure_column(connection, "request_logs", "risk_score", "risk_score INTEGER")
        connection.execute(
            """
            UPDATE request_logs
            SET severity = COALESCE(severity,
                CASE
                    WHEN action = 'allowed' THEN 'low'
                    WHEN action = 'error' THEN 'medium'
                    WHEN attack_type IN ('webshell_upload', 'brute_force', 'command_injection', 'sql_injection')
                        OR attack_type LIKE 'cve_%'
                        OR rule_category = 'cve'
                    THEN CASE
                        WHEN attack_type IN ('webshell_upload', 'command_injection')
                            OR attack_type LIKE 'cve_%'
                            OR rule_category = 'cve'
                        THEN 'critical'
                        ELSE 'high'
                    END
                    WHEN action = 'blocked' THEN 'medium'
                    ELSE 'low'
                END
            ),
            alert_status = CASE
                WHEN alert_status = 'pending' THEN
                    CASE
                        WHEN attack_type IN ('webshell_upload', 'brute_force', 'command_injection', 'sql_injection')
                            OR attack_type LIKE 'cve_%'
                            OR rule_category = 'cve'
                        THEN 'real_attack'
                        WHEN action IN ('blocked', 'error') THEN 'pending_business'
                        ELSE 'not_applicable'
                    END
                WHEN alert_status IN ('resolved', 'resolved_event') THEN 'notified_event'
                WHEN alert_status IN ('real_attack', 'customer_business', 'pending_business', 'notified_event', 'whitelist_traffic', 'not_applicable') THEN alert_status
                WHEN alert_status IS NULL THEN
                    CASE
                        WHEN attack_type IN ('webshell_upload', 'brute_force', 'command_injection', 'sql_injection')
                            OR attack_type LIKE 'cve_%'
                            OR rule_category = 'cve'
                        THEN 'real_attack'
                        WHEN action IN ('blocked', 'error') THEN 'pending_business'
                        ELSE 'not_applicable'
                    END
                ELSE alert_status
            END,
            handled_status = CASE
                WHEN alert_status IN ('whitelist_traffic', 'notified_event') THEN 'handled'
                WHEN handled_status IN ('handled', 'unhandled') THEN handled_status
                WHEN alert_status IN ('resolved', 'resolved_event', 'notified_event') THEN 'handled'
                ELSE 'unhandled'
            END,
            status_updated_at = COALESCE(status_updated_at, created_at),
            traffic_kind = CASE
                WHEN alert_status = 'whitelist_traffic' THEN 'normal'
                WHEN traffic_kind IN ('normal', 'abnormal') THEN traffic_kind
                WHEN alert_status IN ('real_attack', 'customer_business', 'pending_business', 'notified_event') THEN 'abnormal'
                WHEN action IN ('blocked', 'error') THEN 'abnormal'
                WHEN COALESCE(attack_type, '') <> '' THEN 'abnormal'
                ELSE 'normal'
            END,
            rule_category = COALESCE(rule_category,
                CASE
                    WHEN attack_type = 'manual_block' THEN 'policy'
                    WHEN attack_type = 'cc_attack' THEN 'rate_limit'
                    WHEN attack_type = 'brute_force' THEN 'auth'
                    WHEN attack_type IN ('sql_injection') THEN 'sqli'
                    WHEN attack_type IN ('xss') THEN 'xss'
                    WHEN attack_type IN ('path_traversal') THEN 'path_traversal'
                    WHEN attack_type IN ('command_injection') THEN 'rce'
                    WHEN attack_type IN ('webshell_upload', 'webshell_probe') THEN 'webshell'
                    WHEN attack_type IN ('scanner_probe', 'sensitive_probe') THEN 'scanner'
                    WHEN attack_type IN ('ssti') THEN 'ssti'
                    WHEN attack_type IN ('ssrf') THEN 'ssrf'
                    WHEN attack_type LIKE 'cve_%' OR attack_type = 'cve_exploit_attempt' THEN 'cve'
                    ELSE NULL
                END
            ),
            rule_layer = COALESCE(rule_layer,
                CASE
                    WHEN attack_type = 'manual_block' THEN 'policy'
                    WHEN attack_type IN ('cc_attack', 'scanner_probe', 'sensitive_probe', 'brute_force') THEN 'behavior'
                    WHEN attack_type IN ('sql_injection', 'xss', 'ssti', 'ssrf', 'command_injection', 'deserialization_probe') THEN 'application'
                    WHEN attack_type IN ('path_traversal', 'webshell_probe') THEN 'content'
                    WHEN attack_type IN ('webshell_upload') OR attack_type LIKE 'cve_%' OR attack_type = 'cve_exploit_attempt' THEN 'critical'
                    ELSE NULL
                END
            ),
            risk_score = COALESCE(risk_score,
                CASE
                    WHEN attack_type = 'manual_block' THEN 85
                    WHEN attack_type = 'brute_force' THEN 88
                    WHEN attack_type = 'cc_attack' THEN 60
                    WHEN attack_type = 'sql_injection' THEN 80
                    WHEN attack_type = 'xss' THEN 68
                    WHEN attack_type = 'ssti' THEN 74
                    WHEN attack_type = 'ssrf' THEN 72
                    WHEN attack_type = 'command_injection' THEN 78
                    WHEN attack_type = 'deserialization_probe' THEN 71
                    WHEN attack_type = 'path_traversal' THEN 60
                    WHEN attack_type = 'webshell_probe' THEN 70
                    WHEN attack_type = 'webshell_upload' THEN 90
                    WHEN attack_type = 'scanner_probe' THEN 58
                    WHEN attack_type = 'sensitive_probe' THEN 55
                    WHEN attack_type LIKE 'cve_%' OR attack_type = 'cve_exploit_attempt' THEN 88
                    ELSE 0
                END
            )
            """
        )
        connection.execute(
            """
            UPDATE request_logs
            SET severity = 'critical'
            WHERE severity = 'high'
              AND (
                  attack_type IN ('webshell_upload', 'command_injection')
                  OR attack_type LIKE 'cve_%'
                  OR rule_category = 'cve'
              )
            """
        )
        connection.execute("DELETE FROM cc_bans WHERE expires_at <= ?", (utcnow_iso(),))
        connection.commit()


def add_log(
    *,
    client_ip: str,
    destination_host: str | None,
    destination_ip: str | None,
    request_host: str | None = None,
    method: str,
    path: str,
    query_string: str,
    user_agent: str,
    request_headers: str | None,
    action: str,
    attack_type: str | None,
    attack_detail: str | None,
    cve_id: str | None,
    rule_category: str | None = None,
    rule_layer: str | None = None,
    matched_field: str | None = None,
    risk_score: int | None = None,
    severity_hint: str | None = None,
    status_code: int | None,
    upstream_status: int | None,
    duration_ms: int | None,
    body_preview: str | None,
) -> None:
    metadata = _default_rule_metadata(attack_type)
    normalized_rule_category = str(rule_category or metadata.get("category") or "").strip() or None
    normalized_rule_layer = str(rule_layer or metadata.get("layer") or "").strip() or None
    normalized_risk_score = _normalize_risk_score(risk_score, attack_type)
    severity, alert_status = classify_log(
        action,
        attack_type,
        risk_score=normalized_risk_score,
        rule_category=normalized_rule_category,
        severity_hint=severity_hint,
    )
    effective_state = derive_effective_log_state(
        {
            "client_ip": client_ip,
            "destination_host": destination_host,
            "request_host": request_host,
            "destination_ip": destination_ip,
            "method": method,
            "path": path,
            "query_string": query_string,
            "user_agent": user_agent,
            "request_headers": request_headers,
            "action": action,
            "attack_type": attack_type,
            "attack_detail": attack_detail,
            "cve_id": cve_id,
            "severity": severity,
            "alert_status": alert_status,
            "handled_status": "unhandled",
            "rule_category": normalized_rule_category,
            "rule_layer": normalized_rule_layer,
            "matched_field": matched_field,
            "risk_score": normalized_risk_score,
            "body_preview": body_preview,
        }
    )
    alert_status = effective_state["effective_alert_status"]
    handled_status = effective_state["effective_handled_status"]
    traffic_kind = effective_state["effective_traffic_kind"]
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO request_logs (
                created_at, client_ip, destination_host, request_host, destination_ip, method, path, query_string, user_agent,
                request_headers, action, attack_type, attack_detail, cve_id, severity, alert_status, handled_status, traffic_kind,
                rule_category, rule_layer, matched_field, risk_score, status_updated_at,
                status_code, upstream_status, duration_ms, body_preview
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utcnow_iso(),
                client_ip,
                destination_host,
                request_host,
                destination_ip,
                method,
                path,
                query_string,
                user_agent,
                request_headers,
                action,
                attack_type,
                attack_detail,
                cve_id,
                severity,
                alert_status,
                handled_status,
                traffic_kind,
                normalized_rule_category,
                normalized_rule_layer,
                matched_field,
                normalized_risk_score,
                utcnow_iso(),
                status_code,
                upstream_status,
                duration_ms,
                body_preview,
            ),
        )
        connection.commit()


def list_logs(
    *,
    page: int = 1,
    page_size: int = 20,
    alerts_only: bool = False,
    traffic_kind: str | None = None,
    action: str | None = None,
    keyword: str | None = None,
    severity: str | None = None,
    alert_status: str | None = None,
    handled_status: str | None = None,
) -> dict:
    base_sql = """
        FROM request_logs
    """
    clauses = []
    params: list[object] = []

    if alerts_only:
        placeholders = ", ".join("?" for _ in ALERT_STATUS_ALERT_VIEW)
        clauses.append(f"alert_status IN ({placeholders})")
        params.extend(ALERT_STATUS_ALERT_VIEW)

    if traffic_kind:
        clauses.append("traffic_kind = ?")
        params.append(traffic_kind)

    if action:
        clauses.append("action = ?")
        params.append(action)

    if keyword:
        clauses.append("(client_ip LIKE ? OR destination_host LIKE ? OR destination_ip LIKE ? OR path LIKE ? OR attack_type LIKE ? OR attack_detail LIKE ? OR cve_id LIKE ? OR rule_category LIKE ? OR matched_field LIKE ?)")
        like_value = f"%{keyword}%"
        params.extend([like_value, like_value, like_value, like_value, like_value, like_value, like_value, like_value, like_value])

    if severity:
        clauses.append("severity = ?")
        params.append(severity)

    if alert_status:
        clauses.append("alert_status = ?")
        params.append(alert_status)

    if handled_status:
        clauses.append("handled_status = ?")
        params.append(handled_status)

    where_sql = ""
    if clauses:
        where_sql = " WHERE " + " AND ".join(clauses)

    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size

    total_sql = "SELECT COUNT(*) AS total " + base_sql + where_sql
    data_sql = """
        SELECT id, created_at, client_ip, destination_host, request_host, destination_ip, method, path, query_string, user_agent,
               action, attack_type, attack_detail, cve_id, severity, alert_status, handled_status, traffic_kind,
               rule_category, rule_layer, matched_field, risk_score,
               status_code, upstream_status, duration_ms, body_preview
    """ + base_sql + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?"

    with closing(get_connection()) as connection:
        total = connection.execute(total_sql, params).fetchone()["total"] or 0
        rows = connection.execute(data_sql, [*params, page_size, offset]).fetchall()

    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


def get_log_detail(log_id: int) -> dict | None:
    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT id, created_at, client_ip, destination_host, request_host, destination_ip, method, path, query_string, user_agent,
                   request_headers, action, attack_type, attack_detail, cve_id,
                   severity, alert_status, handled_status, traffic_kind, rule_category, rule_layer, matched_field, risk_score,
                   status_updated_at, status_code,
                   upstream_status, duration_ms, body_preview
            FROM request_logs
            WHERE id = ?
            """,
            (log_id,),
        ).fetchone()

    if not row:
        return None

    data = dict(row)
    raw_headers = data.get("request_headers")
    if raw_headers:
        try:
            data["request_headers"] = json.loads(raw_headers)
        except Exception:
            data["request_headers"] = {"raw": raw_headers}
    else:
        data["request_headers"] = {}
    return data


def _build_hourly_trend(rows: list[sqlite3.Row], bucket_count: int = 12) -> list[dict]:
    end_hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start_hour = end_hour - timedelta(hours=bucket_count - 1)

    buckets: list[dict] = []
    index: dict[datetime, dict] = {}
    for offset in range(bucket_count):
        bucket_time = start_hour + timedelta(hours=offset)
        bucket = {
            "_time": bucket_time,
            "label": bucket_time.strftime("%H:00"),
            "total": 0,
            "blocked": 0,
            "high": 0,
        }
        buckets.append(bucket)
        index[bucket_time] = bucket

    for row in rows:
        try:
            created_at = datetime.fromisoformat(row["created_at"]).astimezone(timezone.utc)
        except Exception:
            continue

        bucket_key = created_at.replace(minute=0, second=0, microsecond=0)
        bucket = index.get(bucket_key)
        if not bucket:
            continue

        bucket["total"] += 1
        if row["action"] == "blocked":
            bucket["blocked"] += 1
        if is_high_risk_severity(row["severity"]):
            bucket["high"] += 1

    for bucket in buckets:
        bucket.pop("_time", None)
    return buckets


def _infer_geo_bucket(ip: str, geo: dict | None) -> str:
    special = classify_special_ip(ip)
    if special is not None:
        if special.get("country") in {"本机", "内网"}:
            return "本地"
        return "未知"

    if not geo:
        return "未知"

    country = str(geo.get("country") or "")
    region = str(geo.get("region") or "")
    city = str(geo.get("city") or "")
    geo_text = f"{country}{region}{city}"

    if country and country != "中国":
        return "海外"

    for bucket, keywords in REGION_BUCKET_RULES.items():
        if any(keyword in geo_text for keyword in keywords):
            return bucket

    return "未知"


def get_overview(hours: int = 24) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    now_iso = utcnow_iso()
    with closing(get_connection()) as connection:
        totals = connection.execute(
            """
            SELECT
                COUNT(*) AS total_requests,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked_requests,
                SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END) AS allowed_requests,
                SUM(CASE WHEN traffic_kind = 'normal' THEN 1 ELSE 0 END) AS normal_requests,
                SUM(CASE WHEN traffic_kind = 'abnormal' THEN 1 ELSE 0 END) AS abnormal_requests,
                COUNT(DISTINCT client_ip) AS unique_ips
            FROM request_logs
            WHERE created_at >= ?
            """,
            (since,),
        ).fetchone()

        top_attack_types = connection.execute(
            """
            SELECT attack_type AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
              AND COALESCE(attack_type, '') <> ''
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        top_source_ips = connection.execute(
            """
            SELECT client_ip AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY client_ip
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        top_paths = connection.execute(
            """
            SELECT path AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY path
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        blocked_ip_count = connection.execute("SELECT COUNT(*) AS count FROM blocked_ips").fetchone()["count"]
        cc_ban_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM cc_bans
            WHERE expires_at > ?
            """,
            (now_iso,),
        ).fetchone()["count"]

        alert_totals = connection.execute(
            """
            SELECT
                SUM(CASE WHEN handled_status = 'handled' AND alert_status IN ('real_attack', 'customer_business', 'pending_business', 'notified_event', 'whitelist_traffic') THEN 1 ELSE 0 END) AS total_alerts,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND severity = 'critical' THEN 1 ELSE 0 END) AS critical_risk_alerts,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_risk_alerts,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND severity = 'high' THEN 1 ELSE 0 END) AS high_only_alerts,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND severity = 'medium' THEN 1 ELSE 0 END) AS medium_risk_alerts,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND severity = 'low' THEN 1 ELSE 0 END) AS low_risk_alerts,
                SUM(CASE WHEN handled_status = 'handled' AND alert_status = 'real_attack' THEN 1 ELSE 0 END) AS real_attack_alerts,
                SUM(CASE WHEN handled_status = 'handled' AND alert_status = 'customer_business' THEN 1 ELSE 0 END) AS customer_business_alerts,
                SUM(CASE WHEN handled_status = 'handled' AND alert_status = 'pending_business' THEN 1 ELSE 0 END) AS pending_business_alerts,
                SUM(CASE WHEN handled_status = 'handled' AND alert_status = 'notified_event' THEN 1 ELSE 0 END) AS notified_event_alerts,
                SUM(CASE WHEN handled_status = 'handled' AND alert_status = 'whitelist_traffic' THEN 1 ELSE 0 END) AS whitelist_traffic_alerts,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND COALESCE(handled_status, 'unhandled') <> 'handled' THEN 1 ELSE 0 END) AS unhandled_alerts,
                SUM(CASE WHEN handled_status = 'handled' AND alert_status IN ('real_attack', 'customer_business', 'pending_business', 'notified_event', 'whitelist_traffic') THEN 1 ELSE 0 END) AS handled_alerts,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND COALESCE(handled_status, 'unhandled') <> 'handled' AND alert_status = 'real_attack' THEN 1 ELSE 0 END) AS inferred_real_attack_alerts,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND COALESCE(handled_status, 'unhandled') <> 'handled' AND alert_status = 'customer_business' THEN 1 ELSE 0 END) AS inferred_customer_business_alerts,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND COALESCE(handled_status, 'unhandled') <> 'handled' AND alert_status = 'pending_business' THEN 1 ELSE 0 END) AS inferred_pending_business_alerts,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND COALESCE(handled_status, 'unhandled') <> 'handled' AND alert_status = 'notified_event' THEN 1 ELSE 0 END) AS inferred_notified_event_alerts,
                SUM(CASE WHEN COALESCE(handled_status, 'unhandled') <> 'handled' AND alert_status = 'whitelist_traffic' THEN 1 ELSE 0 END) AS inferred_whitelist_traffic_alerts
            FROM request_logs
            WHERE created_at >= ?
            """,
            (since,),
        ).fetchone()

        brute_force_events = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND attack_type = 'brute_force'
            """,
            (since,),
        ).fetchone()["count"]

        webshell_upload_events = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND attack_type = 'webshell_upload'
            """,
            (since,),
        ).fetchone()["count"]

        cve_alert_events = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND (rule_category = 'cve' OR (cve_id IS NOT NULL AND cve_id <> ''))
            """,
            (since,),
        ).fetchone()["count"]

        cc_attack_events = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND attack_type = 'cc_attack'
            """,
            (since,),
        ).fetchone()["count"]

        sensitive_probe_events = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND attack_type = 'sensitive_probe'
            """,
            (since,),
        ).fetchone()["count"]

        latest_high_risk_alerts = connection.execute(
            """
            SELECT id, created_at, client_ip, path, attack_type, attack_detail, cve_id, alert_status
            FROM request_logs
            WHERE created_at >= ? AND severity IN ('critical', 'high')
            ORDER BY id DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        recent_alert_stream = connection.execute(
            """
            SELECT id, created_at, client_ip, path, attack_type, attack_detail,
                   cve_id, alert_status, severity, action
            FROM request_logs
            WHERE created_at >= ? AND traffic_kind = 'abnormal'
            ORDER BY id DESC
            LIMIT 8
            """,
            (since,),
        ).fetchall()

        top_cve_ids = connection.execute(
            """
            SELECT cve_id AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND cve_id IS NOT NULL AND cve_id <> ''
            GROUP BY cve_id
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        # 趋势图只统计 abnormal 流量，和大屏其他威胁口径保持一致。
        trend_rows = connection.execute(
            """
            SELECT created_at, action, severity
            FROM request_logs
            WHERE created_at >= ?
            ORDER BY created_at ASC
            """,
            ((datetime.now(timezone.utc) - timedelta(hours=12)).isoformat(),),
        ).fetchall()

        geo_cache_rows = connection.execute(
            """
            SELECT ip, label, country, region, city, isp, source
            FROM ip_geo_cache
            """
        ).fetchall()
        geo_cache = {row["ip"]: dict(row) for row in geo_cache_rows}

        ip_rows = connection.execute(
            """
            SELECT client_ip, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY client_ip
            """,
            (since,),
        ).fetchall()

    total_requests = totals["total_requests"] or 0
    blocked_requests = totals["blocked_requests"] or 0
    allowed_requests = totals["allowed_requests"] or 0
    blocked_rate = round((blocked_requests / total_requests) * 100, 1) if total_requests else 0.0
    hourly_trend = _build_hourly_trend(list(trend_rows))

    geo_counter: Counter[str] = Counter()
    for row in ip_rows:
        ip = row["client_ip"]
        count = row["count"] or 0
        bucket = _infer_geo_bucket(ip, geo_cache.get(ip))
        geo_counter[bucket] += count

    geo_buckets = [{"name": bucket, "count": geo_counter.get(bucket, 0)} for bucket in SCREEN_BUCKET_ORDER]
    active_geo_buckets = sorted(
        (item for item in geo_buckets if item["count"] > 0),
        key=lambda item: item["count"],
        reverse=True,
    )
    handled_disposition_counts = {
        "real_attack": int(alert_totals["real_attack_alerts"] or 0),
        "customer_business": int(alert_totals["customer_business_alerts"] or 0),
        "pending_business": int(alert_totals["pending_business_alerts"] or 0),
        "reported_alert": int(alert_totals["notified_event_alerts"] or 0),
        "whitelist_traffic": int(alert_totals["whitelist_traffic_alerts"] or 0),
    }
    inferred_disposition_counts = {
        "real_attack": int(alert_totals["inferred_real_attack_alerts"] or 0),
        "customer_business": int(alert_totals["inferred_customer_business_alerts"] or 0),
        "pending_business": int(alert_totals["inferred_pending_business_alerts"] or 0),
        "reported_alert": int(alert_totals["inferred_notified_event_alerts"] or 0),
        "whitelist_traffic": int(alert_totals["inferred_whitelist_traffic_alerts"] or 0),
    }
    handled_alerts = _validate_screen_total(int(alert_totals["handled_alerts"] or 0), handled_disposition_counts, "overview")
    diagnostics = {
        "handled_total_raw": int(alert_totals["handled_alerts"] or 0),
        "handled_total": handled_alerts,
        "handled_total_mismatch": int(alert_totals["handled_alerts"] or 0) != handled_alerts,
        "unhandled_total": int(alert_totals["unhandled_alerts"] or 0),
    }

    return {
        "window_hours": hours,
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "allowed_requests": allowed_requests,
        "normal_requests": totals["normal_requests"] or 0,
        "abnormal_requests": totals["abnormal_requests"] or 0,
        "unique_ips": totals["unique_ips"] or 0,
        "blocked_rate": blocked_rate,
        "blocked_ip_count": blocked_ip_count,
        "cc_ban_count": cc_ban_count or 0,
        "total_alerts": handled_alerts,
        "critical_risk_alerts": alert_totals["critical_risk_alerts"] or 0,
        "high_risk_alerts": alert_totals["high_risk_alerts"] or 0,
        "high_only_alerts": alert_totals["high_only_alerts"] or 0,
        "medium_risk_alerts": alert_totals["medium_risk_alerts"] or 0,
        "low_risk_alerts": alert_totals["low_risk_alerts"] or 0,
        "real_attack_alerts": handled_disposition_counts["real_attack"],
        "customer_business_alerts": handled_disposition_counts["customer_business"],
        "pending_business_alerts": handled_disposition_counts["pending_business"],
        "notified_event_alerts": handled_disposition_counts["reported_alert"],
        "resolved_event_alerts": handled_disposition_counts["reported_alert"],
        "whitelist_traffic_alerts": handled_disposition_counts["whitelist_traffic"],
        "unhandled_alerts": alert_totals["unhandled_alerts"] or 0,
        "handled_alerts": handled_alerts,
        "pending_alerts": alert_totals["unhandled_alerts"] or 0,
        "resolved_alerts": handled_alerts,
        "disposition_counts": handled_disposition_counts,
        "inferred_disposition_counts": inferred_disposition_counts,
        "auto_labeled_counts": {"whitelist_traffic": handled_disposition_counts["whitelist_traffic"]},
        "diagnostics": diagnostics,
        "brute_force_events": brute_force_events or 0,
        "webshell_upload_events": webshell_upload_events or 0,
        "cve_alert_events": cve_alert_events or 0,
        "cc_attack_events": cc_attack_events or 0,
        "sensitive_probe_events": sensitive_probe_events or 0,
        "cc_protection": {
            "enabled": get_settings().cc_enabled,
            "window_seconds": get_settings().cc_window_seconds,
            "max_requests_per_ip": get_settings().cc_max_requests_per_ip,
            "max_requests_per_path": get_settings().cc_max_requests_per_path,
            "block_minutes": get_settings().cc_block_minutes,
            "current_banned_ips": cc_ban_count or 0,
            "events_24h": cc_attack_events or 0,
        },
        "top_attack_types": [dict(row) for row in top_attack_types],
        "top_source_ips": [dict(row) for row in top_source_ips],
        "top_paths": [dict(row) for row in top_paths],
        "latest_high_risk_alerts": [dict(row) for row in latest_high_risk_alerts],
        "recent_alert_stream": [dict(row) for row in recent_alert_stream],
        "top_cve_ids": [dict(row) for row in top_cve_ids],
        "hourly_trend": hourly_trend,
        "geo_buckets": geo_buckets,
        "active_geo_buckets": active_geo_buckets[:6],
    }


def _legacy_get_screen_data_from_overview(hours: int = 24) -> dict:
    overview = get_overview(hours=hours)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    with closing(get_connection()) as connection:
        recent_rows = connection.execute(
            """
            SELECT id, created_at, client_ip, destination_host, destination_ip, path, action,
                   attack_type, attack_detail, cve_id, severity, alert_status, handled_status, traffic_kind,
                   rule_category, rule_layer
            FROM request_logs
            WHERE created_at >= ?
            ORDER BY id DESC
            LIMIT 320
            """,
            (since,),
        ).fetchall()

        timeline_rows = connection.execute(
            """
            SELECT created_at, action, severity
            FROM request_logs
            WHERE created_at >= ?
            ORDER BY created_at ASC
            """,
            (since,),
        ).fetchall()

        attack_ip_rows = connection.execute(
            """
            SELECT client_ip AS ip, COUNT(*) AS count,
                   SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                   SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_count
            FROM request_logs
            WHERE created_at >= ? AND traffic_kind = 'abnormal'
            GROUP BY client_ip
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        victim_rows = connection.execute(
            """
            SELECT path AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND traffic_kind = 'abnormal'
            GROUP BY path
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        destination_row = connection.execute(
            """
            SELECT COALESCE(NULLIF(destination_host, ''), '业务主站') AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY COALESCE(NULLIF(destination_host, ''), '业务主站')
            ORDER BY count DESC
            LIMIT 1
            """,
            (since,),
        ).fetchone()

        geo_cache_rows = connection.execute(
            """
            SELECT ip, label, country, region, city, isp, source
            FROM ip_geo_cache
            """
        ).fetchall()

    geo_cache = {row["ip"]: dict(row) for row in geo_cache_rows}

    if not victim_rows:
        with closing(get_connection()) as connection:
            victim_rows = connection.execute(
                """
                SELECT path AS name, COUNT(*) AS count
                FROM request_logs
                WHERE created_at >= ?
                GROUP BY path
                ORDER BY count DESC
                LIMIT 5
                """,
                (since,),
            ).fetchall()

    for ip in {row["client_ip"] for row in recent_rows}:
        _ensure_geo(ip, geo_cache)

    abnormal_rows = [dict(row) for row in recent_rows if row["traffic_kind"] == "abnormal"]
    flow_seed = abnormal_rows[:]
    if not flow_seed:
        flow_seed = [dict(row) for row in recent_rows]

    flow_counter: dict[str, dict] = {}
    origin_counter: Counter[str] = Counter()
    attack_ip_items: list[dict] = []

    if not attack_ip_rows and recent_rows:
        fallback_counter: Counter[str] = Counter(row["client_ip"] for row in recent_rows)
        attack_ip_rows = [
            {"ip": ip, "count": count, "critical_count": 0, "high_count": 0}
            for ip, count in fallback_counter.most_common(5)
        ]

    for row in flow_seed:
        ip = row["client_ip"]
        geo = geo_cache.get(ip) or {}
        bucket = _infer_geo_bucket(ip, geo)
        source_name = _build_screen_flow_name(
            geo.get("country", ""),
            geo.get("region", ""),
            geo.get("city", ""),
            bucket,
            geo.get("label", ""),
        )
        coords = _geo_coordinates(
            geo.get("country", ""),
            geo.get("region", ""),
            geo.get("city", ""),
            bucket,
        )
        key = f"{source_name}:{bucket}"
        item = flow_counter.setdefault(
            key,
            {
                "key": key,
                "source_name": source_name,
                "source_bucket": bucket,
                "source_country": str(geo.get("country", "") or ""),
                "source_region": str(geo.get("region", "") or ""),
                "source_city": str(geo.get("city", "") or ""),
                "source_label": str(geo.get("label", "") or source_name),
                "source_lng": coords["lng"],
                "source_lat": coords["lat"],
                "count": 0,
                "blocked_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "top_rule": row["cve_id"] or row["attack_type"] or "manual_block",
            },
        )
        item["count"] += 1
        if row["action"] == "blocked":
            item["blocked_count"] += 1
        if row["severity"] == "critical":
            item["critical_count"] += 1
        if is_high_risk_severity(row["severity"]):
            item["high_count"] += 1
        origin_counter[source_name] += 1

    target_settings = _get_screen_target()
    target_name = destination_row["name"] if destination_row and destination_row["name"] else target_settings["name"]
    if target_name in {"unknown", "未知主机"}:
        target_name = target_settings["name"]

    globe_flows = sorted(
        flow_counter.values(),
        key=lambda item: (item["critical_count"], item["high_count"], item["blocked_count"], item["count"]),
        reverse=True,
    )[:8]
    for item in globe_flows:
        item["severity"] = (
            "critical"
            if item["critical_count"]
            else ("high" if item["high_count"] else ("medium" if item["blocked_count"] else "low"))
        )
        item["target_name"] = target_name
        item["target_label"] = target_settings["label"]
        item["target_lng"] = target_settings["lng"]
        item["target_lat"] = target_settings["lat"]

    attack_source_top = [{"name": name, "count": count} for name, count in origin_counter.most_common(5)]

    for row in attack_ip_rows:
        ip = row["ip"]
        geo = geo_cache.get(ip) or {}
        bucket = _infer_geo_bucket(ip, geo)
        attack_ip_items.append(
            {
                "ip": ip,
                "count": row["count"],
                "critical_count": row["critical_count"],
                "high_count": row["high_count"],
                "label": _build_location_label(
                    geo.get("country", ""),
                    geo.get("region", ""),
                    geo.get("city", ""),
                    bucket,
                ),
                "geo_label": str(geo.get("label", "") or ""),
                "bucket": bucket,
            }
        )

    severity_distribution = [
        {"name": "严重", "count": int(overview["critical_risk_alerts"] or 0)},
        {"name": "高危", "count": int(overview["high_only_alerts"] or 0)},
        {"name": "中危", "count": int(overview["medium_risk_alerts"] or 0)},
        {"name": "低危", "count": int(overview["low_risk_alerts"] or 0)},
    ]

    alert_status_labels = {
        "real_attack": "真实攻击行为",
        "customer_business": "客户业务行为",
        "pending_business": "待确认业务行为",
        "notified_event": "已通报事件告警",
    }

    recent_alert_seed = abnormal_rows[:]
    if not recent_alert_seed:
        recent_alert_seed = [dict(row) for row in recent_rows]

    recent_alerts: list[dict] = []
    for row in recent_alert_seed[:8]:
        geo = geo_cache.get(row["client_ip"]) or {}
        handled_status = str(row["handled_status"] or "unhandled")
        alert_status = str(row["alert_status"] or "")
        recent_alerts.append(
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "client_ip": row["client_ip"],
                "attack_type": row["attack_type"],
                "attack_detail": row["attack_detail"],
                "cve_id": row["cve_id"],
                "severity": str(row["severity"] or "medium"),
                "action": row["action"],
                "alert_status": alert_status,
                "alert_status_text": alert_status_labels.get(alert_status, "待研判"),
                "handled_status": handled_status,
                "handled_text": "已处理" if handled_status == "handled" else "待处理",
                "attack_label": row["cve_id"] or row["attack_type"] or "异常流量",
                "rule_text": row["cve_id"] or row["attack_type"] or "异常流量",
                "location": str(geo.get("label", "") or _build_location_label(
                    geo.get("country", ""),
                    geo.get("region", ""),
                    geo.get("city", ""),
                    _infer_geo_bucket(row["client_ip"], geo),
                )),
            }
        )

    timeline_24h = _build_hourly_trend([dict(row) for row in timeline_rows], bucket_count=24)
    top_paths = [dict(row) for row in victim_rows]
    target_focuses = [
        {
            "path": str(item.get("name") or "/"),
            "count": int(item.get("count") or 0),
            "label": str(item.get("name") or "/"),
        }
        for item in top_paths[:5]
    ]

    target_payload = {
        "name": target_name,
        "label": target_settings["label"],
        "lng": target_settings["lng"],
        "lat": target_settings["lat"],
        "focus_summary": "重点防护对象：业务主站",
        "focus_targets": target_focuses,
    }

    hero_payload = {
        "name": target_name,
        "label": target_settings["label"],
        "summary": "围绕最近 24 小时的攻击流向、来源区域与重点告警进行持续观察。",
    }

    summary_payload = {
        "window_hours": hours,
        "total_alerts": max(int(overview["total_alerts"] or 0), int(overview["abnormal_requests"] or 0)),
        "unique_ips": int(overview["unique_ips"] or 0),
        "blocked_requests": int(overview["blocked_requests"] or 0),
        "high_risk_alerts": int(overview["high_risk_alerts"] or 0),
        "blocked_ip_count": int(overview["blocked_ip_count"] or 0),
    }

    globe_payload = {
        "target": target_payload,
        "flows": globe_flows,
    }

    timeline_payload = {
        "window_hours": hours,
        "items": timeline_24h,
    }

    rankings_payload = {
        "attack_ips": attack_ip_items,
        "attack_types": overview["top_attack_types"],
        "origins": attack_source_top,
        "victims": top_paths,
        "severity_distribution": severity_distribution,
    }

    alerts_payload = {
        "updated_at": recent_alerts[0]["created_at"] if recent_alerts else (recent_rows[0]["created_at"] if recent_rows else ""),
        "items": recent_alerts,
    }

    agent_items = get_agent_status_items()
    agents_payload = {
        "items": agent_items,
        "online_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() == "online"),
        "offline_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() != "online"),
    }

    return {
        "window_hours": hours,
        "hero": hero_payload,
        "summary": summary_payload,
        "globe": globe_payload,
        "timeline": timeline_payload,
        "rankings": rankings_payload,
        "alerts": alerts_payload,
        "agents": agents_payload,
        "target": target_payload,
        "overview": overview,
        "globe_flows": globe_flows,
        "attack_ip_top5": attack_ip_items,
        "attack_source_top5": attack_source_top,
        "victim_targets_top5": top_paths,
        "timeline_24h": timeline_24h,
        "severity_distribution": severity_distribution,
        "recent_alerts": recent_alerts,
        "top_attack_types": overview["top_attack_types"],
        "top_cve_ids": overview["top_cve_ids"],
        "agent_status": agent_items,
    }


def _load_ip_geo_rows(connection: sqlite3.Connection, ips: set[str] | None) -> dict[str, dict]:
    cleaned = sorted(str(ip or "").strip() for ip in (ips or set()) if str(ip or "").strip())
    if not cleaned:
        return {}
    placeholders = ",".join("?" for _ in cleaned)
    rows = connection.execute(
        f"""
        SELECT ip, label, country, region, city, isp, source
        FROM ip_geo_cache
        WHERE ip IN ({placeholders})
        """,
        tuple(cleaned),
    ).fetchall()
    return {row["ip"]: dict(row) for row in rows}


def _build_screen_severity_distribution(summary: dict) -> list[dict]:
    return [
        {"name": "严重", "count": int(summary.get("critical_risk_alerts") or 0)},
        {"name": "高危", "count": int(summary.get("high_only_alerts") or 0)},
        {"name": "中危", "count": int(summary.get("medium_risk_alerts") or 0)},
        {"name": "低危", "count": int(summary.get("low_risk_alerts") or 0)},
    ]


def _build_hourly_trend_from_aggregates(rows: list[sqlite3.Row], bucket_count: int = 24) -> list[dict]:
    bucket_count = max(1, bucket_count)
    now_bucket = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    buckets: list[dict] = []
    index: dict[str, dict] = {}
    for offset in range(bucket_count - 1, -1, -1):
        bucket_time = now_bucket - timedelta(hours=offset)
        key = bucket_time.strftime("%Y-%m-%dT%H")
        item = {
            "label": bucket_time.strftime("%H:00"),
            "total": 0,
            "blocked": 0,
            "high": 0,
        }
        buckets.append(item)
        index[key] = item

    for row in rows:
        bucket = index.get(str(row["hour_bucket"] or ""))
        if not bucket:
            continue
        bucket["total"] = int(row["total"] or 0)
        bucket["blocked"] = int(row["blocked"] or 0)
        bucket["high"] = int(row["high"] or 0)
    return buckets


def _build_screen_severity_distribution(summary: dict) -> list[dict]:
    return [
        {"key": "critical", "name": "严重", "count": int(summary.get("critical_risk_alerts") or 0)},
        {"key": "high", "name": "高危", "count": int(summary.get("high_only_alerts") or 0)},
        {"key": "medium", "name": "中危", "count": int(summary.get("medium_risk_alerts") or 0)},
        {"key": "low", "name": "低危", "count": int(summary.get("low_risk_alerts") or 0)},
    ]


def _build_recent_screen_alerts(rows: list[sqlite3.Row], geo_cache: dict[str, dict]) -> list[dict]:
    alert_status_labels = {
        "real_attack": "真实攻击行为",
        "customer_business": "客户业务行为",
        "pending_business": "待确认业务行为",
        "notified_event": "已通报事件告警",
        "whitelist_traffic": "白名单流量",
    }
    recent_alerts: list[dict] = []
    for row in rows:
        prepared = _prepare_screen_row(row)
        ip = str(prepared.get("screen_client_ip") or "")
        geo = _ensure_geo(ip, geo_cache) if ip else {}
        handled_status = "handled" if is_screen_handled_row(prepared) else "unhandled"
        alert_status = str(
            prepared.get("screen_effective_alert_status")
            or prepared.get("screen_alert_status")
            or prepared.get("alert_status")
            or ""
        )
        recent_alerts.append(
            {
                "id": prepared.get("id"),
                "created_at": prepared.get("created_at"),
                "client_ip": ip,
                "attack_type": prepared.get("screen_attack_type") or prepared.get("attack_type"),
                "attack_detail": prepared.get("attack_detail"),
                "cve_id": prepared.get("screen_cve_id") or prepared.get("cve_id"),
                "severity": str(prepared.get("screen_severity") or prepared.get("severity") or "medium"),
                "action": prepared.get("screen_action") or prepared.get("action"),
                "alert_status": alert_status,
                "alert_status_text": alert_status_labels.get(alert_status, "待研判"),
                "handled_status": handled_status,
                "handled_text": "已处理" if handled_status == "handled" else "待处理",
                "attack_label": prepared.get("screen_cve_id") or prepared.get("screen_attack_type") or "异常流量",
                "rule_text": prepared.get("screen_cve_id") or prepared.get("screen_attack_type") or "异常流量",
                "location": str(
                    geo.get("label", "")
                    or _build_location_label(
                        geo.get("country", ""),
                        geo.get("region", ""),
                        geo.get("city", ""),
                        _infer_geo_bucket(ip, geo),
                    )
                ),
                "screen_segment": prepared.get("screen_segment"),
            }
        )
    return recent_alerts

    alert_status_labels = {
        "real_attack": "真实攻击行为",
        "customer_business": "客户业务行为",
        "pending_business": "待确认业务行为",
        "notified_event": "已通报事件告警",
    }
    recent_alerts: list[dict] = []
    for row in rows:
        ip = str(row["client_ip"] or "")
        geo = _ensure_geo(ip, geo_cache) if ip else {}
        handled_status = str(row["handled_status"] or "unhandled")
        alert_status = str(row["alert_status"] or "")
        recent_alerts.append(
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "client_ip": ip,
                "attack_type": row["attack_type"],
                "attack_detail": row["attack_detail"],
                "cve_id": row["cve_id"],
                "severity": str(row["severity"] or "medium"),
                "action": row["action"],
                "alert_status": alert_status,
                "alert_status_text": alert_status_labels.get(alert_status, "待研判"),
                "handled_status": handled_status,
                "handled_text": "已处理" if handled_status == "handled" else "待处理",
                "attack_label": row["cve_id"] or row["attack_type"] or "异常流量",
                "rule_text": row["cve_id"] or row["attack_type"] or "异常流量",
                "location": str(
                    geo.get("label", "")
                    or _build_location_label(
                        geo.get("country", ""),
                        geo.get("region", ""),
                        geo.get("city", ""),
                        _infer_geo_bucket(ip, geo),
                    )
                ),
            }
        )
    return recent_alerts


def _screen_summary_fallback(hours: int) -> dict:
    updated_at = _screen_cache_stamp("summary", hours)
    return {
        "window_hours": hours,
        "server_time": utcnow_iso(),
        "updated_at": updated_at,
        "summary_updated_at": updated_at,
        "detail_updated_at": _screen_cache_stamp("detail", hours),
        "summary": {
            "window_hours": hours,
            "total_alerts": 0,
            "unique_ips": 0,
            "blocked_requests": 0,
            "high_risk_alerts": 0,
            "blocked_ip_count": 0,
            "cc_ban_count": 0,
            "cc_attack_events": 0,
        },
        "timeline": {"window_hours": hours, "items": []},
        "alerts": {"updated_at": "", "items": []},
        "rankings": {"severity_distribution": _build_screen_severity_distribution({})},
    }


def _screen_detail_fallback(hours: int) -> dict:
    target = _get_screen_target()
    updated_at = _screen_cache_stamp("detail", hours)
    target_payload = {
        "name": target["name"],
        "label": target["label"],
        "lng": target["lng"],
        "lat": target["lat"],
        "focus_summary": "重点防护对象：业务主站",
        "focus_targets": [],
    }
    return {
        "window_hours": hours,
        "server_time": utcnow_iso(),
        "updated_at": updated_at,
        "summary_updated_at": _screen_cache_stamp("summary", hours),
        "detail_updated_at": updated_at,
        "hero": {
            "name": target["name"],
            "label": target["label"],
            "summary": "围绕最近 24 小时的攻击流向、来源区域与重点告警进行持续观察。",
        },
        "target": target_payload,
        "globe": {"target": target_payload, "flows": []},
        "rankings": {
            "attack_ips": [],
            "attack_types": [],
            "origins": [],
            "victims": [],
        },
        "agents": {"items": [], "online_count": 0, "offline_count": 0},
    }


def _compute_screen_summary_data(hours: int = 24) -> dict:
    return _slice_screen_summary_payload(get_screen_snapshot(hours=hours), hours=hours)


def _compute_screen_detail_data(hours: int = 24) -> dict:
    return _slice_screen_detail_payload(get_screen_snapshot(hours=hours), hours=hours)

    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    snapshot_time = utcnow_iso()

    with closing(get_connection()) as connection:
        flow_rows = connection.execute(
            """
            SELECT id, created_at, client_ip, destination_host, destination_ip, path, action,
                   attack_type, attack_detail, cve_id, severity, alert_status, handled_status, traffic_kind,
                   rule_category, rule_layer
            FROM request_logs
            WHERE created_at >= ? AND traffic_kind = 'abnormal'
            ORDER BY id DESC
            LIMIT 360
            """,
            (since,),
        ).fetchall()
        if not flow_rows:
            flow_rows = connection.execute(
                """
                SELECT id, created_at, client_ip, destination_host, destination_ip, path, action,
                       attack_type, attack_detail, cve_id, severity, alert_status, handled_status, traffic_kind,
                       rule_category, rule_layer
                FROM request_logs
                WHERE created_at >= ?
                ORDER BY id DESC
                LIMIT 240
                """,
                (since,),
            ).fetchall()

        attack_ip_rows = connection.execute(
            """
            SELECT client_ip AS ip, COUNT(*) AS count,
                   SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                   SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_count
            FROM request_logs
            WHERE created_at >= ? AND traffic_kind = 'abnormal'
            GROUP BY client_ip
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        victim_rows = connection.execute(
            """
            SELECT path AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND traffic_kind = 'abnormal'
            GROUP BY path
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        attack_type_rows = connection.execute(
            """
            SELECT attack_type AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
              AND COALESCE(attack_type, '') <> ''
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        destination_row = connection.execute(
            """
            SELECT COALESCE(NULLIF(destination_host, ''), '业务主站') AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY COALESCE(NULLIF(destination_host, ''), '业务主站')
            ORDER BY count DESC
            LIMIT 1
            """,
            (since,),
        ).fetchone()

        detail_ips = {str(row["client_ip"] or "") for row in flow_rows}
        detail_ips.update(str(row["ip"] or "") for row in attack_ip_rows)
        geo_cache = _load_ip_geo_rows(connection, detail_ips)

    for ip in detail_ips:
        if ip:
            _ensure_geo(ip, geo_cache)

    flow_counter: dict[str, dict] = {}
    origin_counter: Counter[str] = Counter()
    attack_ip_items: list[dict] = []
    flow_seed = [dict(row) for row in flow_rows]

    if not attack_ip_rows and flow_rows:
        fallback_counter: Counter[str] = Counter(row["client_ip"] for row in flow_rows)
        attack_ip_rows = [
            {"ip": ip, "count": count, "critical_count": 0, "high_count": 0}
            for ip, count in fallback_counter.most_common(5)
        ]

    for row in flow_seed:
        ip = row["client_ip"]
        geo = geo_cache.get(ip) or {}
        bucket = _infer_geo_bucket(ip, geo)
        source_name = _build_screen_flow_name(
            geo.get("country", ""),
            geo.get("region", ""),
            geo.get("city", ""),
            bucket,
            geo.get("label", ""),
        )
        coords = _geo_coordinates(
            geo.get("country", ""),
            geo.get("region", ""),
            geo.get("city", ""),
            bucket,
        )
        key = f"{source_name}:{bucket}"
        item = flow_counter.setdefault(
            key,
            {
                "key": key,
                "source_name": source_name,
                "source_bucket": bucket,
                "source_country": str(geo.get("country", "") or ""),
                "source_region": str(geo.get("region", "") or ""),
                "source_city": str(geo.get("city", "") or ""),
                "source_label": str(geo.get("label", "") or source_name),
                "source_lng": coords["lng"],
                "source_lat": coords["lat"],
                "count": 0,
                "blocked_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "top_rule": row["cve_id"] or row["attack_type"] or "manual_block",
            },
        )
        item["count"] += 1
        if row["action"] == "blocked":
            item["blocked_count"] += 1
        if row["severity"] == "critical":
            item["critical_count"] += 1
        if is_high_risk_severity(row["severity"]):
            item["high_count"] += 1
        origin_counter[source_name] += 1

    target_settings = _get_screen_target()
    target_name = destination_row["name"] if destination_row and destination_row["name"] else target_settings["name"]
    if target_name in {"unknown", "未知主机"}:
        target_name = target_settings["name"]

    globe_flows = sorted(
        flow_counter.values(),
        key=lambda item: (item["critical_count"], item["high_count"], item["blocked_count"], item["count"]),
        reverse=True,
    )[:10]
    for item in globe_flows:
        item["severity"] = (
            "critical"
            if item["critical_count"]
            else ("high" if item["high_count"] else ("medium" if item["blocked_count"] else "low"))
        )
        item["target_name"] = target_name
        item["target_label"] = target_settings["label"]
        item["target_lng"] = target_settings["lng"]
        item["target_lat"] = target_settings["lat"]

    attack_source_top = [{"name": name, "count": count} for name, count in origin_counter.most_common(5)]

    for row in attack_ip_rows:
        ip = row["ip"]
        geo = geo_cache.get(ip) or {}
        bucket = _infer_geo_bucket(ip, geo)
        attack_ip_items.append(
            {
                "ip": ip,
                "count": row["count"],
                "critical_count": row["critical_count"],
                "high_count": row["high_count"],
                "label": _build_location_label(
                    geo.get("country", ""),
                    geo.get("region", ""),
                    geo.get("city", ""),
                    bucket,
                ),
                "geo_label": str(geo.get("label", "") or ""),
                "bucket": bucket,
            }
        )

    top_paths = [dict(row) for row in victim_rows]
    target_focuses = [
        {
            "path": str(item.get("name") or "/"),
            "count": int(item.get("count") or 0),
            "label": str(item.get("name") or "/"),
        }
        for item in top_paths[:5]
    ]

    target_payload = {
        "name": target_name,
        "label": target_settings["label"],
        "lng": target_settings["lng"],
        "lat": target_settings["lat"],
        "focus_summary": "重点防护对象：业务主站",
        "focus_targets": target_focuses,
    }
    agent_items = get_agent_status_items()

    return {
        "window_hours": hours,
        "server_time": snapshot_time,
        "updated_at": snapshot_time,
        "summary_updated_at": _screen_cache_stamp("summary", hours),
        "detail_updated_at": snapshot_time,
        "hero": {
            "name": target_name,
            "label": target_settings["label"],
            "summary": "围绕最近 24 小时的攻击流向、来源区域与重点告警进行持续观察。",
        },
        "target": target_payload,
        "globe": {"target": target_payload, "flows": globe_flows},
        "rankings": {
            "attack_ips": attack_ip_items,
            "attack_types": [dict(row) for row in attack_type_rows],
            "origins": attack_source_top,
            "victims": top_paths,
        },
        "agents": {
            "items": agent_items,
            "online_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() == "online"),
            "offline_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() != "online"),
        },
    }


def _legacy_get_screen_summary_data_split_cache(hours: int = 24) -> dict:
    cached = _screen_cache_response("summary", hours)
    if cached is not None:
        return cached
    try:
        payload = _compute_screen_summary_data(hours=hours)
        updated_at = str(payload.get("summary_updated_at") or payload.get("updated_at") or utcnow_iso())
        payload["detail_updated_at"] = payload.get("detail_updated_at") or _screen_cache_stamp("detail", hours)
        return _screen_cache_store("summary", hours, SCREEN_SUMMARY_CACHE_TTL_SECONDS, payload, updated_at)
    except Exception as exc:
        return _screen_cache_stale("summary", hours, exc, _screen_summary_fallback(hours))


def _legacy_get_screen_detail_data_split_cache(hours: int = 24) -> dict:
    cached = _screen_cache_response("detail", hours)
    if cached is not None:
        return cached
    try:
        payload = _compute_screen_detail_data(hours=hours)
        updated_at = str(payload.get("detail_updated_at") or payload.get("updated_at") or utcnow_iso())
        payload["summary_updated_at"] = payload.get("summary_updated_at") or _screen_cache_stamp("summary", hours)
        return _screen_cache_store("detail", hours, SCREEN_DETAIL_CACHE_TTL_SECONDS, payload, updated_at)
    except Exception as exc:
        return _screen_cache_stale("detail", hours, exc, _screen_detail_fallback(hours))


def _legacy_get_screen_data_split_merge(hours: int = 24) -> dict:
    summary_payload = _legacy_get_screen_summary_data_split_cache(hours=hours)
    detail_payload = _legacy_get_screen_detail_data_split_cache(hours=hours)
    summary_updated_at = str(summary_payload.get("summary_updated_at") or "")
    detail_updated_at = str(detail_payload.get("detail_updated_at") or "")
    updated_at = max(summary_updated_at, detail_updated_at)

    rankings = dict(detail_payload.get("rankings") or {})
    rankings["severity_distribution"] = (
        (summary_payload.get("rankings") or {}).get("severity_distribution")
        or rankings.get("severity_distribution")
        or _build_screen_severity_distribution({})
    )

    return {
        "window_hours": hours,
        "server_time": utcnow_iso(),
        "updated_at": updated_at,
        "summary_updated_at": summary_updated_at,
        "detail_updated_at": detail_updated_at,
        "hero": detail_payload.get("hero") or _screen_detail_fallback(hours)["hero"],
        "summary": summary_payload.get("summary") or _screen_summary_fallback(hours)["summary"],
        "globe": detail_payload.get("globe") or _screen_detail_fallback(hours)["globe"],
        "timeline": summary_payload.get("timeline") or _screen_summary_fallback(hours)["timeline"],
        "rankings": rankings,
        "alerts": summary_payload.get("alerts") or _screen_summary_fallback(hours)["alerts"],
        "agents": detail_payload.get("agents") or _screen_detail_fallback(hours)["agents"],
        "target": detail_payload.get("target") or _screen_detail_fallback(hours)["target"],
        "globe_flows": (detail_payload.get("globe") or {}).get("flows", []),
        "attack_ip_top5": rankings.get("attack_ips", []),
        "attack_source_top5": rankings.get("origins", []),
        "victim_targets_top5": rankings.get("victims", []),
        "timeline_24h": (summary_payload.get("timeline") or {}).get("items", []),
        "severity_distribution": rankings.get("severity_distribution", []),
        "recent_alerts": (summary_payload.get("alerts") or {}).get("items", []),
        "top_attack_types": rankings.get("attack_types", []),
        "agent_status": (detail_payload.get("agents") or {}).get("items", []),
        "stale": bool(summary_payload.get("stale") or detail_payload.get("stale")),
    }


SCREEN_SNAPSHOT_CACHE_TTL_SECONDS = 7
SCREEN_RAW_FLOW_LIMIT = 240
SCREEN_AGGREGATED_FLOW_LIMIT = 72
SCREEN_DISPOSITION_KEYS = ("real_attack", "customer_business", "pending_business", "reported_alert", "whitelist_traffic")
SCREEN_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_SCREEN_SNAPSHOT_CACHE_LOCK = threading.Lock()
_SCREEN_SNAPSHOT_CACHE = {
    "hours": None,
    "expires_at": 0.0,
    "updated_at": "",
    "payload": None,
}


def _empty_screen_disposition_counts() -> dict[str, int]:
    return {key: 0 for key in SCREEN_DISPOSITION_KEYS}


def _normalize_screen_disposition(value: str | None) -> str:
    status = str(value or "").strip().lower()
    if status == "notified_event":
        return "reported_alert"
    if status in SCREEN_DISPOSITION_KEYS:
        return status
    return ""


def _is_valid_observed_target_host(value: str | None) -> bool:
    host = str(value or "").strip().lower()
    if not host:
        return False
    invalid_hosts = {"unknown", "未知主机", "host.docker.internal", "localhost", "127.0.0.1", "::1"}
    if host in invalid_hosts:
        return False
    if host.endswith(".internal") or host.endswith(".localhost") or host.endswith(".local"):
        return False
    return True


def _screen_severity_weight(value: str | None) -> int:
    return SCREEN_SEVERITY_WEIGHT.get(str(value or "").strip().lower(), 0)


def _validate_screen_total(total_handled: int, disposition_counts: dict[str, int], scope: str) -> int:
    corrected_total = sum(int(disposition_counts.get(key) or 0) for key in SCREEN_DISPOSITION_KEYS)
    if int(total_handled or 0) != corrected_total:
        logger.warning(
            "screen total mismatch in %s: total_handled=%s sum=%s counts=%s",
            scope,
            total_handled,
            corrected_total,
            disposition_counts,
        )
    return corrected_total


def _build_screen_snapshot_fallback(hours: int) -> dict:
    target = _get_screen_target()
    disposition_counts = _empty_screen_disposition_counts()
    inferred_disposition_counts = _empty_screen_disposition_counts()
    total_handled = _validate_screen_total(0, disposition_counts, "fallback")
    updated_at = utcnow_iso()
    target_payload = {
        "name": target["name"],
        "label": target["label"],
        "lng": target["lng"],
        "lat": target["lat"],
        "focus_summary": "monitoring target",
        "focus_targets": [],
    }
    agent_items = get_agent_status_items()
    severity_distribution = [
        {"key": "critical", "name": "严重", "count": 0},
        {"key": "high", "name": "高危", "count": 0},
        {"key": "medium", "name": "中危", "count": 0},
        {"key": "low", "name": "低危", "count": 0},
    ]
    return {
        "window_hours": hours,
        "server_time": updated_at,
        "updated_at": updated_at,
        "summary_updated_at": updated_at,
        "detail_updated_at": updated_at,
        "stale": True,
        "summary": {
            "window_hours": hours,
            "total_handled": total_handled,
            "total_alerts": total_handled,
            "unique_ips": 0,
            "blocked_requests": 0,
            "high_risk_alerts": 0,
            "blocked_ip_count": 0,
            "cc_ban_count": 0,
            "cc_attack_events": 0,
            "disposition_counts": disposition_counts,
        },
        "timeline": {"window_hours": hours, "items": []},
        "alerts": {"updated_at": "", "items": []},
        "rankings": {
            "severity_distribution": severity_distribution,
            "attack_ips": [],
            "attack_types": [],
            "origins": [],
            "victims": [],
        },
        "agents": {
            "items": agent_items,
            "online_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() == "online"),
            "offline_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() != "online"),
        },
        "hero": {
            "name": target["name"],
            "label": target["label"],
            "summary": "recent external attack activity overview",
        },
        "target": target_payload,
        "globe": {
            "target": target_payload,
            "raw_flows": [],
            "aggregated_flows": [],
            "flows": [],
        },
        "raw_flows": [],
        "aggregated_flows": [],
        "attack_ip_top5": [],
        "attack_source_top5": [],
        "victim_targets_top5": [],
        "timeline_24h": [],
        "severity_distribution": severity_distribution,
        "recent_alerts": [],
        "top_attack_types": [],
        "agent_status": agent_items,
        "disposition_counts": disposition_counts,
        "total_handled": total_handled,
    }


def _legacy_build_screen_snapshot_full_scan(hours: int = 24) -> dict:
    target_settings = _get_screen_target()
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    snapshot_time = utcnow_iso()

    with closing(get_connection()) as connection:
        rows = [
            dict(row)
            for row in connection.execute(
                """
                SELECT id, created_at, client_ip, destination_host, destination_ip, request_host, path, action,
                       attack_type, attack_detail, cve_id, severity, alert_status, handled_status, traffic_kind,
                       rule_category, rule_layer
                FROM request_logs
                WHERE created_at >= ?
                ORDER BY created_at DESC, id DESC
                """,
                (since,),
            ).fetchall()
        ]
        blocked_ip_count = int(connection.execute("SELECT COUNT(*) AS count FROM blocked_ips").fetchone()["count"] or 0)
        cc_ban_count = int(
            connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM cc_bans
                WHERE expires_at > ?
                """,
                (snapshot_time,),
            ).fetchone()["count"]
            or 0
        )
        geo_cache = _load_ip_geo_rows(connection, {str(row.get("client_ip") or "") for row in rows})

    for ip in tuple(geo_cache.keys()):
        if ip:
            _ensure_geo(ip, geo_cache)

    unique_ips = {str(row.get("client_ip") or "") for row in rows if str(row.get("client_ip") or "").strip()}
    total_requests = len(rows)
    blocked_requests = sum(1 for row in rows if str(row.get("action") or "") == "blocked")
    disposition_counts = _empty_screen_disposition_counts()
    severity_counter: Counter[str] = Counter()
    attack_type_counter: Counter[str] = Counter()
    victim_counter: Counter[str] = Counter()
    origin_counter: Counter[str] = Counter()
    destination_counter: Counter[str] = Counter()
    attack_ip_stats: dict[str, dict] = {}
    aggregated_flow_map: dict[str, dict] = {}
    raw_flow_items: list[dict] = []
    abnormal_rows: list[dict] = []

    for row in rows:
        ip = str(row.get("client_ip") or "").strip()
        disposition = _normalize_screen_disposition(row.get("alert_status"))
        severity = str(row.get("severity") or "").strip().lower()
        is_abnormal = str(row.get("traffic_kind") or "").strip() == "abnormal" or bool(disposition)

        handled = str(row.get("handled_status") or "").strip() == "handled"
        if disposition and handled:
            disposition_counts[disposition] += 1
        elif disposition:
            inferred_disposition_counts[disposition] += 1
        if not is_abnormal:
            continue

        abnormal_rows.append(row)
        if severity:
            severity_counter[severity] += 1

        attack_type = str(row.get("attack_type") or "").strip()
        if attack_type:
            attack_type_counter[attack_type] += 1

        path = str(row.get("path") or "").strip() or "/"
        victim_counter[path] += 1

        destination_host = str(row.get("destination_host") or "").strip()
        if destination_host and destination_host not in {"unknown", "未知主机"}:
            destination_counter[destination_host] += 1

        geo = _ensure_geo(ip, geo_cache) if ip else {}
        bucket = _infer_geo_bucket(ip, geo)
        source_name = _build_screen_flow_name(
            geo.get("country", ""),
            geo.get("region", ""),
            geo.get("city", ""),
            bucket,
            geo.get("label", ""),
        )
        source_label = str(
            geo.get("label", "")
            or _build_location_label(geo.get("country", ""), geo.get("region", ""), geo.get("city", ""), bucket)
        )
        coords = _geo_coordinates(geo.get("country", ""), geo.get("region", ""), geo.get("city", ""), bucket)
        origin_counter[source_name] += 1

        ip_item = attack_ip_stats.setdefault(
            ip or "unknown",
            {
                "ip": ip or "unknown",
                "count": 0,
                "critical_count": 0,
                "high_count": 0,
                "label": _build_location_label(geo.get("country", ""), geo.get("region", ""), geo.get("city", ""), bucket),
                "geo_label": str(geo.get("label", "") or source_label),
                "bucket": bucket,
            },
        )
        ip_item["count"] += 1
        if severity == "critical":
            ip_item["critical_count"] += 1
        if is_high_risk_severity(severity):
            ip_item["high_count"] += 1

        aggregated_key = f"{source_name}:{bucket}"
        aggregated_item = aggregated_flow_map.setdefault(
            aggregated_key,
            {
                "key": aggregated_key,
                "source_name": source_name,
                "source_bucket": bucket,
                "source_geo": source_label,
                "source_country": str(geo.get("country", "") or ""),
                "source_region": str(geo.get("region", "") or ""),
                "source_city": str(geo.get("city", "") or ""),
                "source_label": source_label,
                "source_lng": coords["lng"],
                "source_lat": coords["lat"],
                "count": 0,
                "blocked_count": 0,
                "critical_count": 0,
                "high_count": 0,
            },
        )
        aggregated_item["count"] += 1
        if str(row.get("action") or "") == "blocked":
            aggregated_item["blocked_count"] += 1
        if severity == "critical":
            aggregated_item["critical_count"] += 1
        if is_high_risk_severity(severity):
            aggregated_item["high_count"] += 1

        raw_flow_items.append(
            {
                "event_id": int(row.get("id") or 0),
                "key": f"event-{row.get('id') or 0}",
                "timestamp": str(row.get("created_at") or ""),
                "count": 1,
                "source_ip": ip,
                "source_name": source_name,
                "source_geo": source_label,
                "source_bucket": bucket,
                "source_country": str(geo.get("country", "") or ""),
                "source_region": str(geo.get("region", "") or ""),
                "source_city": str(geo.get("city", "") or ""),
                "source_label": source_label,
                "source_lng": coords["lng"],
                "source_lat": coords["lat"],
                "severity": severity,
                "action": str(row.get("action") or ""),
                "attack_type": attack_type,
                "attack_detail": str(row.get("attack_detail") or ""),
                "cve_id": str(row.get("cve_id") or ""),
            }
        )

    dominant_destination_host = ""
    for host, _count in destination_counter.most_common():
        if _is_valid_observed_target_host(host):
            dominant_destination_host = host
            break

    target_name = target_settings["name"]
    total_handled = _validate_screen_total(sum(disposition_counts.values()), disposition_counts, "screen_snapshot_fallback")

    aggregated_flows = sorted(
        aggregated_flow_map.values(),
        key=lambda item: (
            int(item["critical_count"] or 0),
            int(item["high_count"] or 0),
            int(item["blocked_count"] or 0),
            int(item["count"] or 0),
        ),
        reverse=True,
    )[:SCREEN_AGGREGATED_FLOW_LIMIT]
    for item in aggregated_flows:
        item["severity"] = (
            "critical"
            if item["critical_count"]
            else ("high" if item["high_count"] else ("medium" if item["blocked_count"] else "low"))
        )
        item["target_name"] = target_name
        item["target_label"] = target_settings["label"]
        item["target_lng"] = target_settings["lng"]
        item["target_lat"] = target_settings["lat"]

    raw_flows = sorted(
        raw_flow_items,
        key=lambda item: (
            str(item.get("timestamp") or ""),
            _screen_severity_weight(item.get("severity")),
            int(item.get("event_id") or 0),
        ),
        reverse=True,
    )[:SCREEN_RAW_FLOW_LIMIT]
    for item in raw_flows:
        item["target_name"] = target_name
        item["target_label"] = target_settings["label"]
        item["target_lng"] = target_settings["lng"]
        item["target_lat"] = target_settings["lat"]

    attack_ip_items = sorted(
        attack_ip_stats.values(),
        key=lambda item: (int(item["critical_count"] or 0), int(item["high_count"] or 0), int(item["count"] or 0)),
        reverse=True,
    )[:5]
    attack_source_top = [{"name": name, "count": count} for name, count in origin_counter.most_common(5)]
    top_paths = [{"name": name, "count": count} for name, count in victim_counter.most_common(5)]
    top_attack_types = [{"name": name, "count": count} for name, count in attack_type_counter.most_common(5)]
    recent_alerts = _build_recent_screen_alerts(abnormal_rows[:8], geo_cache)
    severity_distribution = [
        {"key": "critical", "name": "严重", "count": int(severity_counter.get("critical", 0))},
        {"key": "high", "name": "高危", "count": int(severity_counter.get("high", 0))},
        {"key": "medium", "name": "中危", "count": int(severity_counter.get("medium", 0))},
        {"key": "low", "name": "低危", "count": int(severity_counter.get("low", 0))},
    ]
    target_focuses = [
        {
            "path": str(item.get("name") or "/"),
            "count": int(item.get("count") or 0),
            "label": str(item.get("name") or "/"),
        }
        for item in top_paths
    ]
    target_payload = {
        "name": target_name,
        "label": target_settings["label"],
        "lng": target_settings["lng"],
        "lat": target_settings["lat"],
        "focus_summary": "screen snapshot target",
        "focus_targets": target_focuses,
        "observed_target_host": dominant_destination_host,
        "dominant_destination_host": dominant_destination_host,
    }
    agent_items = get_agent_status_items()
    return {
        "window_hours": hours,
        "server_time": snapshot_time,
        "updated_at": snapshot_time,
        "summary_updated_at": snapshot_time,
        "detail_updated_at": snapshot_time,
        "stale": False,
        "summary": {
            "window_hours": hours,
            "total_handled": total_handled,
            "total_alerts": total_handled,
            "unique_ips": len(unique_ips),
            "blocked_requests": blocked_requests,
            "high_risk_alerts": int(severity_counter.get("critical", 0) + severity_counter.get("high", 0)),
            "blocked_ip_count": blocked_ip_count,
            "cc_ban_count": cc_ban_count,
            "cc_attack_events": sum(1 for row in abnormal_rows if str(row.get("attack_type") or "") == "cc_attack"),
            "disposition_counts": disposition_counts,
            "inferred_disposition_counts": inferred_disposition_counts,
            "auto_labeled_counts": inferred_disposition_counts,
        },
        "timeline": {
            "window_hours": hours,
            "items": _build_hourly_trend(rows, bucket_count=min(max(hours, 1), 24)),
        },
        "alerts": {
            "updated_at": recent_alerts[0]["created_at"] if recent_alerts else "",
            "items": recent_alerts,
        },
        "rankings": {
            "severity_distribution": severity_distribution,
            "attack_ips": attack_ip_items,
            "attack_types": top_attack_types,
            "origins": attack_source_top,
            "victims": top_paths,
        },
        "agents": {
            "items": agent_items,
            "online_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() == "online"),
            "offline_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() != "online"),
        },
        "hero": {
            "name": target_name,
            "label": target_settings["label"],
            "summary": "recent external attack activity overview",
            "observed_target_host": dominant_destination_host,
        },
        "target": target_payload,
        "globe": {
            "target": target_payload,
            "raw_flows": raw_flows,
            "aggregated_flows": aggregated_flows,
            "flows": raw_flows,
        },
        "raw_flows": raw_flows,
        "aggregated_flows": aggregated_flows,
        "attack_ip_top5": attack_ip_items,
        "attack_source_top5": attack_source_top,
        "victim_targets_top5": top_paths,
        "timeline_24h": _build_hourly_trend(rows, bucket_count=min(max(hours, 1), 24)),
        "severity_distribution": severity_distribution,
        "recent_alerts": recent_alerts,
        "top_attack_types": top_attack_types,
        "agent_status": agent_items,
        "disposition_counts": disposition_counts,
        "inferred_disposition_counts": inferred_disposition_counts,
        "auto_labeled_counts": inferred_disposition_counts,
        "total_handled": total_handled,
    }


def _build_screen_snapshot(hours: int = 24) -> dict:
    target_settings = _get_screen_target()
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    snapshot_time = utcnow_iso()

    with closing(get_connection()) as connection:
        rows = [
            dict(row)
            for row in connection.execute(
                """
                SELECT
                    id, created_at, client_ip, destination_host, request_host, destination_ip,
                    method, path, query_string, user_agent, request_headers,
                    action, attack_type, attack_detail, cve_id, severity,
                    alert_status, handled_status, traffic_kind,
                    rule_category, rule_layer, matched_field, risk_score, body_preview
                FROM request_logs
                WHERE created_at >= ?
                ORDER BY created_at DESC, id DESC
                """,
                (since,),
            ).fetchall()
        ]
        blocked_ip_count = int(connection.execute("SELECT COUNT(*) AS count FROM blocked_ips").fetchone()["count"] or 0)
        cc_ban_count = int(
            connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM cc_bans
                WHERE expires_at > ?
                """,
                (snapshot_time,),
            ).fetchone()["count"]
            or 0
        )

    prepared_rows = [_prepare_screen_row(row) for row in rows]
    segment_counts = {segment: 0 for segment in SCREEN_SEGMENTS}
    disposition_counts = _empty_screen_disposition_counts()
    inferred_disposition_counts = _empty_screen_disposition_counts()
    severity_counter: Counter[str] = Counter()
    attack_type_counter: Counter[str] = Counter()
    victim_counter: Counter[str] = Counter()
    observed_host_counter: Counter[str] = Counter()
    unique_attack_ips: set[str] = set()
    attack_rows: list[dict] = []
    total_unhandled = 0
    blocked_requests = 0
    high_risk_alerts = 0
    cc_attack_events = 0

    for row in prepared_rows:
        segment = classify_screen_segment(row)
        segment_counts[segment] = int(segment_counts.get(segment) or 0) + 1

        disposition = _screen_disposition_for_row(row)
        handled = is_screen_handled_row(row)
        if disposition:
            if handled:
                disposition_counts[disposition] = int(disposition_counts.get(disposition) or 0) + 1
            else:
                inferred_disposition_counts[disposition] = int(inferred_disposition_counts.get(disposition) or 0) + 1

        if segment != SCREEN_SEGMENT_BUSINESS_NORMAL and not handled:
            total_unhandled += 1

        if not is_screen_attack_row(row):
            continue

        attack_rows.append(row)
        client_ip = str(row.get("screen_client_ip") or "")
        if client_ip:
            unique_attack_ips.add(client_ip)
        if str(row.get("screen_action") or "") == "blocked":
            blocked_requests += 1
        if is_high_risk_severity(row.get("screen_severity")):
            high_risk_alerts += 1
        if str(row.get("screen_attack_type") or "").strip() == "cc_attack":
            cc_attack_events += 1

        severity_counter[str(row.get("screen_severity") or "medium")] += 1
        attack_type = str(row.get("screen_attack_type") or "").strip()
        if attack_type:
            attack_type_counter[attack_type] += 1

        victim_counter[str(row.get("screen_path") or "/") or "/"] += 1
        observed_host = str(row.get("screen_destination_host") or row.get("screen_request_host") or "").strip()
        if _is_valid_observed_target_host(observed_host):
            observed_host_counter[observed_host] += 1

    all_attack_ips = {
        str(row.get("screen_client_ip") or "").strip()
        for row in attack_rows
        if str(row.get("screen_client_ip") or "").strip()
    }
    selected_attack_ips = _screen_geo_prewarm_ips(attack_rows)
    with closing(get_connection()) as connection:
        geo_cache = _load_ip_geo_rows(connection, all_attack_ips)

    for ip in tuple(selected_attack_ips):
        _screen_geo(ip, geo_cache, eager=True)

    attack_ip_stats: dict[str, dict] = {}
    aggregated_flow_map: dict[str, dict] = {}
    origin_counter: Counter[str] = Counter()
    raw_flows: list[dict] = []

    for index, row in enumerate(attack_rows):
        client_ip = str(row.get("screen_client_ip") or "").strip()
        geo = _screen_geo(client_ip, geo_cache, eager=False, lookup_cache=False) if client_ip else {}
        bucket = _infer_geo_bucket(client_ip, geo)
        source_name = _build_screen_flow_name(
            str(geo.get("country", "") or ""),
            str(geo.get("region", "") or ""),
            str(geo.get("city", "") or ""),
            bucket,
            str(geo.get("label", "") or ""),
        )
        source_label = str(
            geo.get("label", "")
            or _build_location_label(
                str(geo.get("country", "") or ""),
                str(geo.get("region", "") or ""),
                str(geo.get("city", "") or ""),
                bucket,
            )
        )
        coords = _geo_coordinates(
            str(geo.get("country", "") or ""),
            str(geo.get("region", "") or ""),
            str(geo.get("city", "") or ""),
            bucket,
        )
        display_geo = _build_flow_display_geo(
            str(geo.get("country", "") or ""),
            str(geo.get("region", "") or ""),
            str(geo.get("city", "") or ""),
            source_label,
            bucket,
        )
        geo_source = str(geo.get("source", "") or "")
        geo_resolved = _is_resolved_screen_geo(geo)
        display_coords = coords
        display_geo_mode = "resolved" if geo_resolved else "pseudo"
        display_coord_source = geo_source or "geo"
        pseudo_tile = ""
        if client_ip and not geo_resolved:
            display_coords = _pseudo_geo_from_ip(
                client_ip,
                float(target_settings["lng"]),
                float(target_settings["lat"]),
            )
            display_coord_source = "pseudo_ip_hash"
            pseudo_tile = _pseudo_geo_tile(display_coords)
        severity = str(row.get("screen_severity") or "medium")
        origin_counter[source_name] += 1

        attack_ip_item = attack_ip_stats.setdefault(
            client_ip or "unknown",
            {
                "ip": client_ip or "unknown",
                "count": 0,
                "critical_count": 0,
                "high_count": 0,
                "label": _build_location_label(
                    str(geo.get("country", "") or ""),
                    str(geo.get("region", "") or ""),
                    str(geo.get("city", "") or ""),
                    bucket,
                ),
                "geo_label": str(geo.get("label", "") or source_label),
                "bucket": bucket,
            },
        )
        attack_ip_item["count"] += 1
        if severity == "critical":
            attack_ip_item["critical_count"] += 1
        if is_high_risk_severity(severity):
            attack_ip_item["high_count"] += 1

        aggregated_key = (
            f"{source_name}:{bucket}" if geo_resolved else f"unresolved:{bucket}:{pseudo_tile or client_ip}"
        )
        aggregated_item = aggregated_flow_map.setdefault(
            aggregated_key,
            {
                "key": aggregated_key,
                "source_name": source_name,
                "source_bucket": bucket,
                "source_geo": source_label,
                "source_country": str(geo.get("country", "") or ""),
                "source_region": str(geo.get("region", "") or ""),
                "source_city": str(geo.get("city", "") or ""),
                "source_province": display_geo["source_province"],
                "source_label": source_label,
                "display_country": display_geo["display_country"],
                "display_region": display_geo["display_region"],
                "display_city": display_geo["display_city"],
                "display_label": display_geo["display_label"],
                "source_lng": display_coords["lng"],
                "source_lat": display_coords["lat"],
                "geo_resolved": geo_resolved,
                "geo_source": geo_source or SCREEN_GEO_PLACEHOLDER_SOURCE,
                "display_geo_mode": display_geo_mode,
                "display_coord_source": display_coord_source,
                "pseudo_tile": pseudo_tile,
                "count": 0,
                "blocked_count": 0,
                "critical_count": 0,
                "high_count": 0,
            },
        )
        aggregated_item["count"] += 1
        if str(row.get("screen_action") or "") == "blocked":
            aggregated_item["blocked_count"] += 1
        if severity == "critical":
            aggregated_item["critical_count"] += 1
        if is_high_risk_severity(severity):
            aggregated_item["high_count"] += 1

        if index >= SCREEN_RAW_FLOW_LIMIT:
            continue

        raw_flows.append(
            {
                "event_id": int(row.get("id") or 0),
                "key": f"event-{int(row.get('id') or 0)}",
                "timestamp": str(row.get("created_at") or ""),
                "count": 1,
                "source_ip": client_ip,
                "source_name": source_name,
                "source_geo": source_label,
                "source_bucket": bucket,
                "source_country": str(geo.get("country", "") or ""),
                "source_region": str(geo.get("region", "") or ""),
                "source_city": str(geo.get("city", "") or ""),
                "source_province": display_geo["source_province"],
                "source_label": source_label,
                "display_country": display_geo["display_country"],
                "display_region": display_geo["display_region"],
                "display_city": display_geo["display_city"],
                "display_label": display_geo["display_label"],
                "source_lng": display_coords["lng"],
                "source_lat": display_coords["lat"],
                "geo_resolved": geo_resolved,
                "geo_source": geo_source or SCREEN_GEO_PLACEHOLDER_SOURCE,
                "display_geo_mode": display_geo_mode,
                "display_coord_source": display_coord_source,
                "pseudo_tile": pseudo_tile,
                "severity": severity,
                "action": str(row.get("screen_action") or row.get("action") or ""),
                "attack_type": str(row.get("screen_attack_type") or row.get("attack_type") or ""),
                "attack_detail": str(row.get("attack_detail") or ""),
                "cve_id": str(row.get("screen_cve_id") or row.get("cve_id") or ""),
                "screen_segment": row.get("screen_segment"),
            }
        )

    handled_total_raw = sum(int(disposition_counts.get(key) or 0) for key in SCREEN_DISPOSITION_KEYS)
    total_handled = _validate_screen_total(handled_total_raw, disposition_counts, "screen_snapshot")
    dominant_destination_host = ""
    for host, _count in observed_host_counter.most_common():
        if _is_valid_observed_target_host(host):
            dominant_destination_host = host
            break

    top_paths = [{"name": name, "count": count} for name, count in victim_counter.most_common(5)]
    target_focuses = [
        {
            "path": str(item.get("name") or "/"),
            "count": int(item.get("count") or 0),
            "label": str(item.get("name") or "/"),
        }
        for item in top_paths
    ]
    top_attack_types = [{"name": name, "count": count} for name, count in attack_type_counter.most_common(5)]
    attack_source_top = [{"name": name, "count": count} for name, count in origin_counter.most_common(5)]
    attack_ip_items = sorted(
        attack_ip_stats.values(),
        key=lambda item: (int(item["critical_count"] or 0), int(item["high_count"] or 0), int(item["count"] or 0)),
        reverse=True,
    )[:5]

    aggregated_flows = sorted(
        aggregated_flow_map.values(),
        key=lambda item: (
            int(item["critical_count"] or 0),
            int(item["high_count"] or 0),
            int(item["blocked_count"] or 0),
            int(item["count"] or 0),
        ),
        reverse=True,
    )[:SCREEN_AGGREGATED_FLOW_LIMIT]
    for item in aggregated_flows:
        item["severity"] = (
            "critical"
            if item["critical_count"]
            else ("high" if item["high_count"] else ("medium" if item["blocked_count"] else "low"))
        )
        item["target_name"] = target_settings["name"]
        item["target_label"] = target_settings["label"]
        item["target_lng"] = target_settings["lng"]
        item["target_lat"] = target_settings["lat"]

    for item in raw_flows:
        item["target_name"] = target_settings["name"]
        item["target_label"] = target_settings["label"]
        item["target_lng"] = target_settings["lng"]
        item["target_lat"] = target_settings["lat"]

    severity_distribution = [
        {"key": "critical", "name": "严重", "count": int(severity_counter.get("critical", 0))},
        {"key": "high", "name": "高危", "count": int(severity_counter.get("high", 0))},
        {"key": "medium", "name": "中危", "count": int(severity_counter.get("medium", 0))},
        {"key": "low", "name": "低危", "count": int(severity_counter.get("low", 0))},
    ]
    recent_alerts = _build_recent_screen_alerts(attack_rows[:8], geo_cache)
    returned_raw_flow_count = len(raw_flows)
    total_raw_flow_count = len(attack_rows)
    returned_aggregated_flow_count = len(aggregated_flows)
    total_aggregated_flow_count = len(aggregated_flow_map)
    raw_flow_keys = {
        str(item.get("key") or item.get("event_id") or f"{item.get('source_ip')}:{item.get('timestamp')}")
        for item in raw_flows
    }
    geo_resolved_raw_flow_count = sum(1 for item in raw_flows if bool(item.get("geo_resolved")))
    flow_debug = {
        "attack_rows_total": len(prepared_rows),
        "attack_rows_after_filter": len(attack_rows),
        "distinct_attack_ips": len(all_attack_ips),
        "raw_flows_before_dedup": len(attack_rows),
        "raw_flows_after_dedup": len(raw_flow_keys),
        "representative_flows_count": returned_aggregated_flow_count,
        "geo_resolved_raw_flow_count": geo_resolved_raw_flow_count,
        "geo_placeholder_raw_flow_count": returned_raw_flow_count - geo_resolved_raw_flow_count,
        "rendered_candidate_flow_count": returned_raw_flow_count + returned_aggregated_flow_count,
        "dropped_by_normalize_key_count": max(0, returned_raw_flow_count - len(raw_flow_keys)),
        "dropped_by_profile_limit_count": max(0, returned_raw_flow_count - 50),
    }
    diagnostics = {
        "handled_total_raw": handled_total_raw,
        "handled_total": total_handled,
        "handled_total_mismatch": handled_total_raw != total_handled,
        "unhandled_total": total_unhandled,
        "observed_target_host": dominant_destination_host,
        "dominant_destination_host": dominant_destination_host,
        "total_raw_flow_count": total_raw_flow_count,
        "returned_raw_flow_count": returned_raw_flow_count,
        "total_aggregated_flow_count": total_aggregated_flow_count,
        "returned_aggregated_flow_count": returned_aggregated_flow_count,
        "segment_counts": dict(segment_counts),
        "auto_whitelist_count": int(disposition_counts.get("whitelist_traffic") or 0),
        "flow_debug": flow_debug,
    }
    target_payload = {
        "name": target_settings["name"],
        "label": target_settings["label"],
        "lng": target_settings["lng"],
        "lat": target_settings["lat"],
        "focus_summary": "",
        "focus_targets": target_focuses,
        "observed_target_host": dominant_destination_host,
        "dominant_destination_host": dominant_destination_host,
    }
    agent_items = get_agent_status_items()
    timeline_items = _build_hourly_trend(attack_rows, bucket_count=min(max(hours, 1), 24))

    return {
        "window_hours": hours,
        "server_time": snapshot_time,
        "updated_at": snapshot_time,
        "summary_updated_at": snapshot_time,
        "detail_updated_at": snapshot_time,
        "stale": False,
        "diagnostics": diagnostics,
        "summary": {
            "window_hours": hours,
            "total_handled": total_handled,
            "total_alerts": total_handled,
            "total_unhandled": total_unhandled,
            "unique_ips": len(unique_attack_ips),
            "blocked_requests": blocked_requests,
            "high_risk_alerts": high_risk_alerts,
            "blocked_ip_count": blocked_ip_count,
            "cc_ban_count": cc_ban_count,
            "cc_attack_events": cc_attack_events,
            "auto_whitelist_count": int(disposition_counts.get("whitelist_traffic") or 0),
            "disposition_counts": disposition_counts,
            "inferred_disposition_counts": inferred_disposition_counts,
            "auto_labeled_counts": {"whitelist_traffic": int(disposition_counts.get("whitelist_traffic") or 0)},
            "segment_counts": dict(segment_counts),
            "diagnostics": diagnostics,
        },
        "timeline": {
            "window_hours": hours,
            "items": timeline_items,
        },
        "alerts": {
            "updated_at": recent_alerts[0]["created_at"] if recent_alerts else "",
            "items": recent_alerts,
        },
        "rankings": {
            "severity_distribution": severity_distribution,
            "attack_ips": attack_ip_items,
            "attack_types": top_attack_types,
            "origins": attack_source_top,
            "victims": top_paths,
        },
        "agents": {
            "items": agent_items,
            "online_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() == "online"),
            "offline_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() != "online"),
        },
        "hero": {
            "name": target_settings["name"],
            "label": target_settings["label"],
            "summary": "",
            "observed_target_host": dominant_destination_host,
        },
        "target": target_payload,
        "globe": {
            "target": target_payload,
            "raw_flows": raw_flows,
            "aggregated_flows": aggregated_flows,
            "representative_flows": aggregated_flows,
            "flows": raw_flows if raw_flows else aggregated_flows,
            "total_raw_flow_count": total_raw_flow_count,
            "returned_raw_flow_count": returned_raw_flow_count,
            "total_aggregated_flow_count": total_aggregated_flow_count,
            "returned_aggregated_flow_count": returned_aggregated_flow_count,
        },
        "raw_flows": raw_flows,
        "aggregated_flows": aggregated_flows,
        "representative_flows": aggregated_flows,
        "total_raw_flow_count": total_raw_flow_count,
        "returned_raw_flow_count": returned_raw_flow_count,
        "total_aggregated_flow_count": total_aggregated_flow_count,
        "returned_aggregated_flow_count": returned_aggregated_flow_count,
        "attack_ip_top5": attack_ip_items,
        "attack_source_top5": attack_source_top,
        "victim_targets_top5": top_paths,
        "timeline_24h": timeline_items,
        "severity_distribution": severity_distribution,
        "recent_alerts": recent_alerts,
        "top_attack_types": top_attack_types,
        "agent_status": agent_items,
        "disposition_counts": disposition_counts,
        "inferred_disposition_counts": inferred_disposition_counts,
        "auto_labeled_counts": {"whitelist_traffic": int(disposition_counts.get("whitelist_traffic") or 0)},
        "total_handled": total_handled,
        "observed_target_host": dominant_destination_host,
        "dominant_destination_host": dominant_destination_host,
        **({"debug": flow_debug} if get_settings().screen_flow_debug else {}),
    }

    target_settings = _get_screen_target()
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    snapshot_time = utcnow_iso()

    with closing(get_connection()) as connection:
        totals = connection.execute(
            """
            SELECT
                COUNT(*) AS total_requests,
                COUNT(DISTINCT client_ip) AS unique_ips,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked_requests,
                SUM(CASE WHEN traffic_kind = 'abnormal' THEN 1 ELSE 0 END) AS abnormal_total,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND handled_status = 'handled' THEN 1 ELSE 0 END) AS handled_total_raw,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND COALESCE(handled_status, 'unhandled') <> 'handled' THEN 1 ELSE 0 END) AS unhandled_total,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_risk_alerts,
                SUM(CASE WHEN traffic_kind = 'abnormal' AND attack_type = 'cc_attack' THEN 1 ELSE 0 END) AS cc_attack_events
            FROM request_logs
            WHERE created_at >= ?
            """,
            (since,),
        ).fetchone()
        blocked_ip_count = int(connection.execute("SELECT COUNT(*) AS count FROM blocked_ips").fetchone()["count"] or 0)
        cc_ban_count = int(
            connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM cc_bans
                WHERE expires_at > ?
                """,
                (snapshot_time,),
            ).fetchone()["count"]
            or 0
        )
        handled_status_rows = connection.execute(
            """
            SELECT alert_status, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
              AND handled_status = 'handled'
              AND alert_status IN ('real_attack', 'customer_business', 'pending_business', 'notified_event')
            GROUP BY alert_status
            """,
            (since,),
        ).fetchall()
        inferred_status_rows = connection.execute(
            """
            SELECT alert_status, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
              AND COALESCE(handled_status, 'unhandled') <> 'handled'
              AND alert_status IN ('real_attack', 'customer_business', 'pending_business', 'notified_event')
            GROUP BY alert_status
            """,
            (since,),
        ).fetchall()
        severity_rows = connection.execute(
            """
            SELECT COALESCE(severity, 'medium') AS severity, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
            GROUP BY COALESCE(severity, 'medium')
            """,
            (since,),
        ).fetchall()
        attack_type_rows = connection.execute(
            """
            SELECT attack_type AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
              AND COALESCE(attack_type, '') <> ''
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()
        victim_rows = connection.execute(
            """
            SELECT COALESCE(path, '/') AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
            GROUP BY COALESCE(path, '/')
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()
        observed_host_rows = connection.execute(
            """
            SELECT destination_host AS host, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
              AND COALESCE(destination_host, '') <> ''
            GROUP BY destination_host
            ORDER BY count DESC
            LIMIT 20
            """,
            (since,),
        ).fetchall()
        attack_ip_rows = connection.execute(
            """
            SELECT
                client_ip AS ip,
                COUNT(*) AS count,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_count
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
            GROUP BY client_ip
            ORDER BY critical_count DESC, high_count DESC, count DESC, client_ip ASC
            LIMIT 5
            """,
            (since,),
        ).fetchall()
        raw_flow_rows = connection.execute(
            f"""
            SELECT id, created_at, client_ip, action, attack_type, attack_detail, cve_id, severity
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
            ORDER BY created_at DESC,
                     CASE COALESCE(severity, '')
                         WHEN 'critical' THEN 4
                         WHEN 'high' THEN 3
                         WHEN 'medium' THEN 2
                         WHEN 'low' THEN 1
                         ELSE 0
                     END DESC,
                     id DESC
            LIMIT {SCREEN_RAW_FLOW_LIMIT}
            """,
            (since,),
        ).fetchall()
        aggregated_source_rows = connection.execute(
            """
            SELECT
                client_ip,
                COUNT(*) AS count,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked_count,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_count
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
            GROUP BY client_ip
            """,
            (since,),
        ).fetchall()
        trend_rows = connection.execute(
            """
            SELECT
                substr(created_at, 1, 13) AS hour_bucket,
                COUNT(*) AS total,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked,
                SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
            GROUP BY substr(created_at, 1, 13)
            ORDER BY hour_bucket ASC
            """,
            (since,),
        ).fetchall()
        recent_alert_rows = connection.execute(
            """
            SELECT
                id, created_at, client_ip, attack_type, attack_detail, cve_id,
                severity, action, alert_status, handled_status
            FROM request_logs
            WHERE created_at >= ?
              AND traffic_kind = 'abnormal'
            ORDER BY created_at DESC, id DESC
            LIMIT 8
            """,
            (since,),
        ).fetchall()

        # 预热所有会进入地球代表线、来源排行、攻击 IP 排行和最近告警的 IP，
        # 避免只有局部来源命中 geo 缓存，其余长尾来源都掉进占位的“未知位置”。
        selected_ips = {
            str(row["client_ip"] or "").strip()
            for row in list(raw_flow_rows) + list(recent_alert_rows)
            if str(row["client_ip"] or "").strip()
        }
        selected_ips.update(str(row["ip"] or "").strip() for row in attack_ip_rows if str(row["ip"] or "").strip())
        selected_ips.update(
            str(row["client_ip"] or "").strip() for row in aggregated_source_rows if str(row["client_ip"] or "").strip()
        )
        geo_cache = _load_ip_geo_rows(connection, selected_ips)

    disposition_counts = _empty_screen_disposition_counts()
    for row in handled_status_rows:
        key = _normalize_screen_disposition(row["alert_status"])
        if key:
            disposition_counts[key] += int(row["count"] or 0)

    inferred_disposition_counts = _empty_screen_disposition_counts()
    for row in inferred_status_rows:
        key = _normalize_screen_disposition(row["alert_status"])
        if key:
            inferred_disposition_counts[key] += int(row["count"] or 0)

    handled_total_raw = int(totals["handled_total_raw"] or 0)
    total_handled = _validate_screen_total(handled_total_raw, disposition_counts, "screen_snapshot")
    handled_mismatch = handled_total_raw != total_handled
    if handled_mismatch:
        logger.warning(
            "screen snapshot handled mismatch: raw=%s corrected=%s counts=%s",
            handled_total_raw,
            total_handled,
            disposition_counts,
        )

    total_raw_flow_count = int(totals["abnormal_total"] or 0)
    severity_counter: Counter[str] = Counter()
    for row in severity_rows:
        severity_counter[str(row["severity"] or "medium").strip().lower()] += int(row["count"] or 0)

    dominant_destination_host = ""
    for row in observed_host_rows:
        host = str(row["host"] or "").strip()
        if _is_valid_observed_target_host(host):
            dominant_destination_host = host
            break

    for ip in tuple(selected_ips):
        _screen_geo(ip, geo_cache, eager=True)

    attack_ip_items: list[dict] = []
    for row in attack_ip_rows:
        ip = str(row["ip"] or "").strip() or "unknown"
        geo = _screen_geo(ip, geo_cache, eager=False)
        bucket = _infer_geo_bucket(ip, geo)
        attack_ip_items.append(
            {
                "ip": ip,
                "count": int(row["count"] or 0),
                "critical_count": int(row["critical_count"] or 0),
                "high_count": int(row["high_count"] or 0),
                "label": _build_location_label(
                    str(geo.get("country", "") or ""),
                    str(geo.get("region", "") or ""),
                    str(geo.get("city", "") or ""),
                    bucket,
                ),
                "geo_label": str(geo.get("label", "") or ""),
                "bucket": bucket,
            }
        )

    aggregated_flow_map: dict[str, dict] = {}
    origin_counter: Counter[str] = Counter()
    for row in aggregated_source_rows:
        ip = str(row["client_ip"] or "").strip()
        geo = _screen_geo(ip, geo_cache, eager=False)
        bucket = _infer_geo_bucket(ip, geo)
        source_name = _build_screen_flow_name(
            str(geo.get("country", "") or ""),
            str(geo.get("region", "") or ""),
            str(geo.get("city", "") or ""),
            bucket,
            str(geo.get("label", "") or ""),
        )
        source_label = str(
            geo.get("label", "")
            or _build_location_label(
                str(geo.get("country", "") or ""),
                str(geo.get("region", "") or ""),
                str(geo.get("city", "") or ""),
                bucket,
            )
        )
        coords = _geo_coordinates(
            str(geo.get("country", "") or ""),
            str(geo.get("region", "") or ""),
            str(geo.get("city", "") or ""),
            bucket,
        )
        origin_counter[source_name] += int(row["count"] or 0)
        aggregated_key = f"{source_name}:{bucket}"
        aggregated_item = aggregated_flow_map.setdefault(
            aggregated_key,
            {
                "key": aggregated_key,
                "source_name": source_name,
                "source_bucket": bucket,
                "source_geo": source_label,
                "source_country": str(geo.get("country", "") or ""),
                "source_region": str(geo.get("region", "") or ""),
                "source_city": str(geo.get("city", "") or ""),
                "source_label": source_label,
                "source_lng": coords["lng"],
                "source_lat": coords["lat"],
                "count": 0,
                "blocked_count": 0,
                "critical_count": 0,
                "high_count": 0,
            },
        )
        aggregated_item["count"] += int(row["count"] or 0)
        aggregated_item["blocked_count"] += int(row["blocked_count"] or 0)
        aggregated_item["critical_count"] += int(row["critical_count"] or 0)
        aggregated_item["high_count"] += int(row["high_count"] or 0)

    total_aggregated_flow_count = len(aggregated_flow_map)
    # 代表线使用地区/来源聚合结果，承担“全局态势”背景层；
    # 原始事件飞线保留最近高优样本，作为动态强调层。
    aggregated_flows = sorted(
        aggregated_flow_map.values(),
        key=lambda item: (
            int(item["critical_count"] or 0),
            int(item["high_count"] or 0),
            int(item["blocked_count"] or 0),
            int(item["count"] or 0),
        ),
        reverse=True,
    )[:SCREEN_AGGREGATED_FLOW_LIMIT]
    for item in aggregated_flows:
        item["severity"] = (
            "critical"
            if item["critical_count"]
            else ("high" if item["high_count"] else ("medium" if item["blocked_count"] else "low"))
        )
        item["target_name"] = target_settings["name"]
        item["target_label"] = target_settings["label"]
        item["target_lng"] = target_settings["lng"]
        item["target_lat"] = target_settings["lat"]

    raw_flows: list[dict] = []
    for row in raw_flow_rows:
        ip = str(row["client_ip"] or "").strip()
        geo = _screen_geo(ip, geo_cache, eager=True)
        bucket = _infer_geo_bucket(ip, geo)
        source_name = _build_screen_flow_name(
            str(geo.get("country", "") or ""),
            str(geo.get("region", "") or ""),
            str(geo.get("city", "") or ""),
            bucket,
            str(geo.get("label", "") or ""),
        )
        source_label = str(
            geo.get("label", "")
            or _build_location_label(
                str(geo.get("country", "") or ""),
                str(geo.get("region", "") or ""),
                str(geo.get("city", "") or ""),
                bucket,
            )
        )
        coords = _geo_coordinates(
            str(geo.get("country", "") or ""),
            str(geo.get("region", "") or ""),
            str(geo.get("city", "") or ""),
            bucket,
        )
        raw_flows.append(
            {
                "event_id": int(row["id"] or 0),
                "key": f"event-{int(row['id'] or 0)}",
                "timestamp": str(row["created_at"] or ""),
                "count": 1,
                "source_ip": ip,
                "source_name": source_name,
                "source_geo": source_label,
                "source_bucket": bucket,
                "source_country": str(geo.get("country", "") or ""),
                "source_region": str(geo.get("region", "") or ""),
                "source_city": str(geo.get("city", "") or ""),
                "source_label": source_label,
                "source_lng": coords["lng"],
                "source_lat": coords["lat"],
                "severity": str(row["severity"] or "").strip().lower() or "medium",
                "action": str(row["action"] or ""),
                "attack_type": str(row["attack_type"] or ""),
                "attack_detail": str(row["attack_detail"] or ""),
                "cve_id": str(row["cve_id"] or ""),
                "target_name": target_settings["name"],
                "target_label": target_settings["label"],
                "target_lng": target_settings["lng"],
                "target_lat": target_settings["lat"],
            }
        )

    top_paths = [dict(row) for row in victim_rows]
    top_attack_types = [dict(row) for row in attack_type_rows]
    attack_source_top = [{"name": name, "count": count} for name, count in origin_counter.most_common(5)]
    recent_alerts = _build_recent_screen_alerts(list(recent_alert_rows), geo_cache)
    severity_distribution = [
        {"key": "critical", "name": "严重", "count": int(severity_counter.get("critical", 0))},
        {"key": "high", "name": "高危", "count": int(severity_counter.get("high", 0))},
        {"key": "medium", "name": "中危", "count": int(severity_counter.get("medium", 0))},
        {"key": "low", "name": "低危", "count": int(severity_counter.get("low", 0))},
    ]
    target_focuses = [
        {
            "path": str(item.get("name") or "/"),
            "count": int(item.get("count") or 0),
            "label": str(item.get("name") or "/"),
        }
        for item in top_paths
    ]
    returned_raw_flow_count = len(raw_flows)
    returned_aggregated_flow_count = len(aggregated_flows)
    flow_focus_summary = (
        f"地球展示最近 Top {returned_raw_flow_count} 条真实攻击连线"
        if total_raw_flow_count > returned_raw_flow_count
        else "地球展示最近真实攻击连线"
    )
    target_payload = {
        "name": target_settings["name"],
        "label": target_settings["label"],
        "lng": target_settings["lng"],
        "lat": target_settings["lat"],
        "focus_summary": flow_focus_summary,
        "focus_targets": target_focuses,
        "observed_target_host": dominant_destination_host,
        "dominant_destination_host": dominant_destination_host,
    }
    agent_items = get_agent_status_items()
    diagnostics = {
        "handled_total_raw": handled_total_raw,
        "handled_total": total_handled,
        "handled_total_mismatch": handled_mismatch,
        "unhandled_total": int(totals["unhandled_total"] or 0),
        "observed_target_host": dominant_destination_host,
        "dominant_destination_host": dominant_destination_host,
        "total_raw_flow_count": total_raw_flow_count,
        "returned_raw_flow_count": returned_raw_flow_count,
        "total_aggregated_flow_count": total_aggregated_flow_count,
        "returned_aggregated_flow_count": returned_aggregated_flow_count,
    }
    return {
        "window_hours": hours,
        "server_time": snapshot_time,
        "updated_at": snapshot_time,
        "summary_updated_at": snapshot_time,
        "detail_updated_at": snapshot_time,
        "stale": False,
        "diagnostics": diagnostics,
        "summary": {
            "window_hours": hours,
            "total_handled": total_handled,
            "total_alerts": total_handled,
            "total_unhandled": int(totals["unhandled_total"] or 0),
            "unique_ips": int(totals["unique_ips"] or 0),
            "blocked_requests": int(totals["blocked_requests"] or 0),
            "high_risk_alerts": int(totals["high_risk_alerts"] or 0),
            "blocked_ip_count": blocked_ip_count,
            "cc_ban_count": cc_ban_count,
            "cc_attack_events": int(totals["cc_attack_events"] or 0),
            "disposition_counts": disposition_counts,
            "inferred_disposition_counts": inferred_disposition_counts,
            "auto_labeled_counts": inferred_disposition_counts,
            "diagnostics": diagnostics,
        },
        "timeline": {
            "window_hours": hours,
            "items": _build_hourly_trend_from_aggregates(trend_rows, bucket_count=min(max(hours, 1), 24)),
        },
        "alerts": {
            "updated_at": recent_alerts[0]["created_at"] if recent_alerts else "",
            "items": recent_alerts,
        },
        "rankings": {
            "severity_distribution": severity_distribution,
            "attack_ips": attack_ip_items,
            "attack_types": top_attack_types,
            "origins": attack_source_top,
            "victims": top_paths,
        },
        "agents": {
            "items": agent_items,
            "online_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() == "online"),
            "offline_count": sum(1 for item in agent_items if str(item.get("status") or "").strip() != "online"),
        },
        "hero": {
            "name": target_settings["name"],
            "label": target_settings["label"],
            "summary": flow_focus_summary,
            "observed_target_host": dominant_destination_host,
        },
        "target": target_payload,
        "globe": {
            "target": target_payload,
            "raw_flows": raw_flows,
            "aggregated_flows": aggregated_flows,
            "representative_flows": aggregated_flows,
            "flows": raw_flows if raw_flows else aggregated_flows,
            "total_raw_flow_count": total_raw_flow_count,
            "returned_raw_flow_count": returned_raw_flow_count,
            "total_aggregated_flow_count": total_aggregated_flow_count,
            "returned_aggregated_flow_count": returned_aggregated_flow_count,
        },
        "raw_flows": raw_flows,
        "aggregated_flows": aggregated_flows,
        "representative_flows": aggregated_flows,
        "total_raw_flow_count": total_raw_flow_count,
        "returned_raw_flow_count": returned_raw_flow_count,
        "total_aggregated_flow_count": total_aggregated_flow_count,
        "returned_aggregated_flow_count": returned_aggregated_flow_count,
        "attack_ip_top5": attack_ip_items,
        "attack_source_top5": attack_source_top,
        "victim_targets_top5": top_paths,
        "timeline_24h": _build_hourly_trend_from_aggregates(trend_rows, bucket_count=min(max(hours, 1), 24)),
        "severity_distribution": severity_distribution,
        "recent_alerts": recent_alerts,
        "top_attack_types": top_attack_types,
        "agent_status": agent_items,
        "disposition_counts": disposition_counts,
        "inferred_disposition_counts": inferred_disposition_counts,
        "auto_labeled_counts": inferred_disposition_counts,
        "total_handled": total_handled,
        "observed_target_host": dominant_destination_host,
        "dominant_destination_host": dominant_destination_host,
    }

 
def _slice_screen_summary_payload(snapshot: dict, hours: int = 24) -> dict:
    rankings = dict(snapshot.get("rankings") or {})
    summary_payload = dict(snapshot.get("summary") or {})
    return {
        "window_hours": snapshot.get("window_hours", hours),
        "server_time": utcnow_iso(),
        "updated_at": snapshot.get("updated_at", ""),
        "summary_updated_at": snapshot.get("summary_updated_at", ""),
        "detail_updated_at": snapshot.get("detail_updated_at", ""),
        "stale": bool(snapshot.get("stale")),
        "summary": summary_payload,
        "timeline": dict(snapshot.get("timeline") or {"window_hours": hours, "items": []}),
        "alerts": dict(snapshot.get("alerts") or {"updated_at": "", "items": []}),
        "rankings": {
            "severity_distribution": list(rankings.get("severity_distribution") or []),
        },
        "disposition_counts": dict(snapshot.get("disposition_counts") or _empty_screen_disposition_counts()),
        "inferred_disposition_counts": dict(snapshot.get("inferred_disposition_counts") or _empty_screen_disposition_counts()),
        "auto_labeled_counts": dict(snapshot.get("auto_labeled_counts") or summary_payload.get("auto_labeled_counts") or {}),
        "total_handled": int(snapshot.get("total_handled") or summary_payload.get("total_handled") or 0),
        "diagnostics": dict(snapshot.get("diagnostics") or summary_payload.get("diagnostics") or {}),
    }


def _slice_screen_detail_payload(snapshot: dict, hours: int = 24) -> dict:
    rankings = dict(snapshot.get("rankings") or {})
    globe = dict(snapshot.get("globe") or {})
    return {
        "window_hours": snapshot.get("window_hours", hours),
        "server_time": utcnow_iso(),
        "updated_at": snapshot.get("updated_at", ""),
        "summary_updated_at": snapshot.get("summary_updated_at", ""),
        "detail_updated_at": snapshot.get("detail_updated_at", ""),
        "stale": bool(snapshot.get("stale")),
        "hero": dict(snapshot.get("hero") or {}),
        "target": dict(snapshot.get("target") or {}),
        "globe": globe,
        "rankings": {
            "severity_distribution": list(rankings.get("severity_distribution") or []),
            "attack_ips": list(rankings.get("attack_ips") or []),
            "attack_types": list(rankings.get("attack_types") or []),
            "origins": list(rankings.get("origins") or []),
            "victims": list(rankings.get("victims") or []),
        },
        "agents": dict(snapshot.get("agents") or {}),
        "summary": dict(snapshot.get("summary") or {}),
        "disposition_counts": dict(snapshot.get("disposition_counts") or _empty_screen_disposition_counts()),
        "inferred_disposition_counts": dict(snapshot.get("inferred_disposition_counts") or _empty_screen_disposition_counts()),
        "auto_labeled_counts": dict(snapshot.get("auto_labeled_counts") or {}),
        "total_handled": int(snapshot.get("total_handled") or 0),
        "diagnostics": dict(snapshot.get("diagnostics") or {}),
        "total_raw_flow_count": int(snapshot.get("total_raw_flow_count") or globe.get("total_raw_flow_count") or 0),
        "returned_raw_flow_count": int(snapshot.get("returned_raw_flow_count") or globe.get("returned_raw_flow_count") or 0),
        "total_aggregated_flow_count": int(
            snapshot.get("total_aggregated_flow_count") or globe.get("total_aggregated_flow_count") or 0
        ),
        "returned_aggregated_flow_count": int(
            snapshot.get("returned_aggregated_flow_count") or globe.get("returned_aggregated_flow_count") or 0
        ),
    }


def get_screen_snapshot(hours: int = 24) -> dict:
    now = time.monotonic()
    with _SCREEN_SNAPSHOT_CACHE_LOCK:
        if (
            _SCREEN_SNAPSHOT_CACHE.get("payload") is not None
            and _SCREEN_SNAPSHOT_CACHE.get("hours") == hours
            and float(_SCREEN_SNAPSHOT_CACHE.get("expires_at") or 0.0) > now
        ):
            payload = dict(_SCREEN_SNAPSHOT_CACHE["payload"])
            payload["server_time"] = utcnow_iso()
            return payload

    try:
        payload = _build_screen_snapshot(hours=hours)
    except Exception as exc:
        logger.warning("screen snapshot build failed: %s", exc)
        with _SCREEN_SNAPSHOT_CACHE_LOCK:
            if _SCREEN_SNAPSHOT_CACHE.get("payload") is not None and _SCREEN_SNAPSHOT_CACHE.get("hours") == hours:
                cached_payload = dict(_SCREEN_SNAPSHOT_CACHE["payload"])
                cached_payload["server_time"] = utcnow_iso()
                cached_payload["stale"] = True
                cached_payload["error"] = str(exc)
                return cached_payload
        fallback = _build_screen_snapshot_fallback(hours)
        fallback["error"] = str(exc)
        return fallback

    with _SCREEN_SNAPSHOT_CACHE_LOCK:
        _SCREEN_SNAPSHOT_CACHE["hours"] = hours
        _SCREEN_SNAPSHOT_CACHE["expires_at"] = time.monotonic() + SCREEN_SNAPSHOT_CACHE_TTL_SECONDS
        _SCREEN_SNAPSHOT_CACHE["updated_at"] = str(payload.get("updated_at") or utcnow_iso())
        _SCREEN_SNAPSHOT_CACHE["payload"] = dict(payload)
    response = dict(payload)
    response["server_time"] = utcnow_iso()
    return response


def get_screen_summary_data(hours: int = 24) -> dict:
    return _slice_screen_summary_payload(get_screen_snapshot(hours=hours), hours=hours)


def get_screen_detail_data(hours: int = 24) -> dict:
    return _slice_screen_detail_payload(get_screen_snapshot(hours=hours), hours=hours)


def get_screen_data(hours: int = 24) -> dict:
    snapshot = get_screen_snapshot(hours=hours)
    rankings = dict(snapshot.get("rankings") or {})
    globe = dict(snapshot.get("globe") or {})
    payload = dict(snapshot)
    payload["server_time"] = utcnow_iso()
    payload["globe_flows"] = (
        globe.get("raw_flows")
        or globe.get("representative_flows")
        or globe.get("aggregated_flows")
        or globe.get("flows")
        or []
    )
    payload["attack_ip_top5"] = list(rankings.get("attack_ips") or [])
    payload["attack_source_top5"] = list(rankings.get("origins") or [])
    payload["victim_targets_top5"] = list(rankings.get("victims") or [])
    payload["timeline_24h"] = list((snapshot.get("timeline") or {}).get("items", []))
    payload["severity_distribution"] = list(rankings.get("severity_distribution") or [])
    payload["recent_alerts"] = list((snapshot.get("alerts") or {}).get("items", []))
    payload["top_attack_types"] = list(rankings.get("attack_types") or [])
    payload["agent_status"] = list((snapshot.get("agents") or {}).get("items", []))
    payload["disposition_counts"] = dict(snapshot.get("disposition_counts") or _empty_screen_disposition_counts())
    payload["inferred_disposition_counts"] = dict(
        snapshot.get("inferred_disposition_counts") or _empty_screen_disposition_counts()
    )
    payload["total_handled"] = int(snapshot.get("total_handled") or 0)
    payload["diagnostics"] = dict(snapshot.get("diagnostics") or {})
    payload["total_raw_flow_count"] = int(snapshot.get("total_raw_flow_count") or globe.get("total_raw_flow_count") or 0)
    payload["returned_raw_flow_count"] = int(
        snapshot.get("returned_raw_flow_count") or globe.get("returned_raw_flow_count") or 0
    )
    payload["total_aggregated_flow_count"] = int(
        snapshot.get("total_aggregated_flow_count") or globe.get("total_aggregated_flow_count") or 0
    )
    payload["returned_aggregated_flow_count"] = int(
        snapshot.get("returned_aggregated_flow_count") or globe.get("returned_aggregated_flow_count") or 0
    )
    if get_settings().screen_flow_debug and "debug" not in payload:
        payload["debug"] = dict(payload.get("diagnostics", {}).get("flow_debug") or {})
    return payload


def list_blocked_ips(page: int = 1, page_size: int = 20) -> dict:
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size

    with closing(get_connection()) as connection:
        total = connection.execute("SELECT COUNT(*) AS count FROM blocked_ips").fetchone()["count"]
        rows = connection.execute(
            """
            SELECT id, ip, reason, created_at, created_by
            FROM blocked_ips
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (page_size, offset),
        ).fetchall()

    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


def list_cc_bans(page: int = 1, page_size: int = 20) -> dict:
    clear_expired_cc_bans()
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size
    now_iso = utcnow_iso()

    with closing(get_connection()) as connection:
        total = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM cc_bans
            WHERE expires_at > ?
            """,
            (now_iso,),
        ).fetchone()["count"]
        rows = connection.execute(
            """
            SELECT id, ip, reason, created_at, expires_at
            FROM cc_bans
            WHERE expires_at > ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (now_iso, page_size, offset),
        ).fetchall()

    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


def get_agent_status_items() -> list[dict]:
    status_file = get_settings().data_dir / "agent_status.json"
    items: list[dict] = []

    if status_file.exists():
        try:
            payload = json.loads(status_file.read_text(encoding="utf-8"))
            raw_items = payload.get("items") if isinstance(payload, dict) else payload
            if isinstance(raw_items, list):
                for item in raw_items:
                    if not isinstance(item, dict):
                        continue
                    status = str(item.get("status") or "").strip().lower()
                    if status not in {"online", "offline"}:
                        status = "offline"
                    items.append(
                        {
                            "name": str(item.get("name") or item.get("agent_name") or "Agent").strip(),
                            "status": status,
                            "status_text": "在线" if status == "online" else "离线",
                            "last_seen": str(item.get("last_seen") or item.get("updated_at") or "").strip(),
                            "description": str(item.get("description") or item.get("source") or "心跳监测").strip(),
                        }
                    )
        except Exception:
            items = []

    if items:
        return items

    ai_online = bool(get_settings().dashscope_api_key and get_settings().bailian_app_id)
    return [
        {
            "name": "AI 分析 Agent",
            "status": "online" if ai_online else "offline",
            "status_text": "在线" if ai_online else "离线",
            "last_seen": utcnow_iso() if ai_online else "",
            "description": "百炼日志分析链路",
        }
    ]


def count_recent_requests(client_ip: str, window_seconds: int, path: str | None = None) -> int:
    since = (datetime.now(timezone.utc) - timedelta(seconds=max(1, window_seconds))).isoformat()
    sql = """
        SELECT COUNT(*) AS count
        FROM request_logs
        WHERE client_ip = ? AND created_at >= ?
    """
    params: list[object] = [client_ip, since]

    if path:
        sql += " AND path = ?"
        params.append(path)

    with closing(get_connection()) as connection:
        row = connection.execute(sql, params).fetchone()
    return int(row["count"] or 0)


def add_blocked_ip(ip: str, reason: str | None, created_by: str = "admin") -> None:
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO blocked_ips (ip, reason, created_at, created_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, created_by=excluded.created_by
            """,
            (ip.strip(), reason or "", utcnow_iso(), created_by),
        )
        connection.commit()


def clear_expired_cc_bans() -> None:
    with closing(get_connection()) as connection:
        connection.execute("DELETE FROM cc_bans WHERE expires_at <= ?", (utcnow_iso(),))
        connection.commit()


def add_cc_ban(ip: str, reason: str | None, block_minutes: int) -> None:
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=max(1, block_minutes))).isoformat()
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO cc_bans (ip, reason, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                reason=excluded.reason,
                created_at=excluded.created_at,
                expires_at=excluded.expires_at
            """,
            (ip.strip(), reason or "", utcnow_iso(), expires_at),
        )
        connection.commit()


def get_cc_block_reason(ip: str) -> str | None:
    clear_expired_cc_bans()
    with closing(get_connection()) as connection:
        row = connection.execute(
            "SELECT reason FROM cc_bans WHERE ip = ? AND expires_at > ?",
            (ip, utcnow_iso()),
        ).fetchone()
    if not row:
        return None
    return row["reason"] or "CC 高频访问已被临时限制"


def get_cached_ip_geo(ip: str, max_age_hours: int = 72) -> dict | None:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()
    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT ip, label, country, region, city, isp, source, updated_at
            FROM ip_geo_cache
            WHERE ip = ? AND updated_at >= ?
            """,
            (ip, cutoff),
        ).fetchone()
    if not row:
        return None
    cached = dict(row)
    return cached if should_cache_geo_result(cached) else None


def cache_ip_geo(ip: str, geo: dict) -> None:
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO ip_geo_cache (ip, label, country, region, city, isp, source, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                label=excluded.label,
                country=excluded.country,
                region=excluded.region,
                city=excluded.city,
                isp=excluded.isp,
                source=excluded.source,
                updated_at=excluded.updated_at
            """,
            (
                ip,
                geo.get("label", ""),
                geo.get("country", ""),
                geo.get("region", ""),
                geo.get("city", ""),
                geo.get("isp", ""),
                geo.get("source", ""),
                utcnow_iso(),
            ),
        )
        connection.commit()


def update_log_status(log_id: int, alert_status: str) -> None:
    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT action, attack_type, severity, alert_status, handled_status, method, path, query_string,
                   user_agent, request_headers, attack_detail, cve_id, rule_category, rule_layer,
                   matched_field, body_preview
            FROM request_logs
            WHERE id = ?
            """,
            (log_id,),
        ).fetchone()
        if not row:
            return
        effective_state = derive_effective_log_state(
            row,
            alert_status=alert_status,
            handled_status="handled",
        )
        connection.execute(
            """
            UPDATE request_logs
            SET alert_status = ?, handled_status = ?, traffic_kind = ?, status_updated_at = ?
            WHERE id = ?
            """,
            (
                effective_state["effective_alert_status"],
                effective_state["effective_handled_status"],
                effective_state["effective_traffic_kind"],
                utcnow_iso(),
                log_id,
            ),
        )
        connection.commit()


def bulk_update_log_status(log_ids: list[int], alert_status: str) -> None:
    clean_ids = [int(log_id) for log_id in log_ids if str(log_id).strip()]
    if not clean_ids:
        return

    placeholders = ", ".join("?" for _ in clean_ids)
    with closing(get_connection()) as connection:
        rows = connection.execute(
            f"""
            SELECT id, action, attack_type, severity, alert_status, handled_status, method, path, query_string,
                   user_agent, request_headers, attack_detail, cve_id, rule_category, rule_layer,
                   matched_field, body_preview
            FROM request_logs
            WHERE id IN ({placeholders})
            """,
            clean_ids,
        ).fetchall()
        updated_at = utcnow_iso()
        for row in rows:
            effective_state = derive_effective_log_state(
                row,
                alert_status=alert_status,
                handled_status="handled",
            )
            connection.execute(
                """
                UPDATE request_logs
                SET alert_status = ?, handled_status = ?, traffic_kind = ?, status_updated_at = ?
                WHERE id = ?
                """,
                (
                    effective_state["effective_alert_status"],
                    effective_state["effective_handled_status"],
                    effective_state["effective_traffic_kind"],
                    updated_at,
                    int(row["id"]),
                ),
            )
        connection.commit()


def add_auth_attempt(client_ip: str, path: str, success: bool, status_code: int | None) -> None:
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO auth_attempts (created_at, client_ip, path, success, status_code)
            VALUES (?, ?, ?, ?, ?)
            """,
            (utcnow_iso(), client_ip, path, 1 if success else 0, status_code),
        )
        connection.commit()


def get_recent_auth_failure_state(
    client_ip: str,
    *,
    path: str | None = None,
    window_seconds: int = 600,
) -> dict[str, object]:
    since = (datetime.now(timezone.utc) - timedelta(seconds=max(1, window_seconds))).isoformat()
    query = """
        SELECT COUNT(*) AS count, MAX(created_at) AS last_failed_at
        FROM auth_attempts
        WHERE client_ip = ? AND success = 0 AND created_at >= ?
    """
    params: list[object] = [client_ip, since]
    if path:
        query += " AND path = ?"
        params.append(path)

    with closing(get_connection()) as connection:
        row = connection.execute(
            query,
            params,
        ).fetchone()
    return {
        "count": int(row["count"] or 0),
        "last_failed_at": str(row["last_failed_at"] or ""),
    }


def count_recent_auth_failures(client_ip: str, window_minutes: int = 10, path: str | None = None) -> int:
    return int(
        get_recent_auth_failure_state(
            client_ip,
            path=path,
            window_seconds=max(1, window_minutes * 60),
        )["count"]
    )


def clear_recent_auth_failures(client_ip: str, path: str | None = None) -> None:
    with closing(get_connection()) as connection:
        if path:
            connection.execute("DELETE FROM auth_attempts WHERE client_ip = ? AND path = ?", (client_ip, path))
        else:
            connection.execute("DELETE FROM auth_attempts WHERE client_ip = ?", (client_ip,))
        connection.commit()


def remove_blocked_ip(record_id: int) -> None:
    with closing(get_connection()) as connection:
        connection.execute("DELETE FROM blocked_ips WHERE id = ?", (record_id,))
        connection.commit()


def remove_cc_ban(record_id: int) -> None:
    with closing(get_connection()) as connection:
        connection.execute("DELETE FROM cc_bans WHERE id = ?", (record_id,))
        connection.commit()


def get_block_reason(ip: str) -> str | None:
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT reason FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
    if not row:
        return None
    return row["reason"] or "手动封禁"


def get_ip_analysis_data(hours: int = 24) -> dict:
    """获取用于日志分析的IP异常数据，供AI分析使用。"""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    with closing(get_connection()) as connection:
        # 短时间内多次访问的IP（5分钟内访问超过20次）
        frequent_short_ips = connection.execute(
            """
            SELECT client_ip,
                   COUNT(*) AS total_count,
                   SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked_count,
                   SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_count,
                   MIN(created_at) AS first_seen,
                   MAX(created_at) AS last_seen,
                   GROUP_CONCAT(DISTINCT attack_type) AS attack_types
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY client_ip
            HAVING total_count >= 10
            ORDER BY total_count DESC
            LIMIT 20
            """,
            (since,),
        ).fetchall()

        # 访问量最多的IP
        top_access_ips = connection.execute(
            """
            SELECT client_ip,
                   COUNT(*) AS total_count,
                   SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked_count,
                   SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_count,
                   COUNT(DISTINCT path) AS unique_paths,
                   GROUP_CONCAT(DISTINCT attack_type) AS attack_types,
                   MIN(created_at) AS first_seen,
                   MAX(created_at) AS last_seen
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY client_ip
            ORDER BY total_count DESC
            LIMIT 10
            """,
            (since,),
        ).fetchall()

        # 攻击程度最严重的IP（高危攻击次数最多）
        most_dangerous_ips = connection.execute(
            """
                   SELECT client_ip,
                   COUNT(*) AS total_count,
                   SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_count,
                   SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked_count,
                   GROUP_CONCAT(DISTINCT attack_type) AS attack_types,
                   GROUP_CONCAT(DISTINCT cve_id) AS cve_ids,
                   MIN(created_at) AS first_seen,
                   MAX(created_at) AS last_seen
            FROM request_logs
            WHERE created_at >= ? AND severity IN ('critical', 'high')
            GROUP BY client_ip
            ORDER BY high_count DESC
            LIMIT 10
            """,
            (since,),
        ).fetchall()

        # 扫描探测行为（访问了大量不同路径的IP）
        scanner_ips = connection.execute(
            """
            SELECT client_ip,
                   COUNT(*) AS total_count,
                   COUNT(DISTINCT path) AS unique_paths,
                   SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked_count,
                   GROUP_CONCAT(DISTINCT attack_type) AS attack_types,
                   MIN(created_at) AS first_seen,
                   MAX(created_at) AS last_seen
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY client_ip
            HAVING unique_paths >= 5
            ORDER BY unique_paths DESC
            LIMIT 10
            """,
            (since,),
        ).fetchall()

        # 已封禁的IP（与日志中出现的IP对比）
        blocked_ip_rows = connection.execute(
            "SELECT ip, reason, created_at FROM blocked_ips ORDER BY id DESC LIMIT 20"
        ).fetchall()

        # 总体统计
        totals = connection.execute(
            """
            SELECT
                COUNT(*) AS total_requests,
                COUNT(DISTINCT client_ip) AS unique_ips,
                SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked_count,
                SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN attack_type='brute_force' THEN 1 ELSE 0 END) AS brute_force_count,
                SUM(CASE WHEN attack_type='webshell_upload' THEN 1 ELSE 0 END) AS webshell_count,
                SUM(CASE WHEN attack_type='sql_injection' THEN 1 ELSE 0 END) AS sql_injection_count,
                SUM(CASE WHEN rule_category='cve' OR (cve_id IS NOT NULL AND cve_id <> '') THEN 1 ELSE 0 END) AS cve_count,
                SUM(CASE WHEN attack_type='scanner_probe' THEN 1 ELSE 0 END) AS scanner_count
            FROM request_logs
            WHERE created_at >= ?
            """,
            (since,),
        ).fetchone()

        # 按小时统计流量趋势（24小时）
        hourly_rows = connection.execute(
            """
            SELECT created_at, action, severity
            FROM request_logs
            WHERE created_at >= ?
            ORDER BY created_at ASC
            """,
            (since,),
        ).fetchall()

    hourly_trend = _build_hourly_trend(list(hourly_rows), bucket_count=24)

    return {
        "window_hours": hours,
        "analysis_time": utcnow_iso(),
        "summary": {
            "total_requests": totals["total_requests"] or 0,
            "unique_ips": totals["unique_ips"] or 0,
            "blocked_count": totals["blocked_count"] or 0,
            "high_count": totals["high_count"] or 0,
            "brute_force_count": totals["brute_force_count"] or 0,
            "webshell_count": totals["webshell_count"] or 0,
            "sql_injection_count": totals["sql_injection_count"] or 0,
            "cve_count": totals["cve_count"] or 0,
            "scanner_count": totals["scanner_count"] or 0,
        },
        "frequent_short_ips": [dict(row) for row in frequent_short_ips],
        "top_access_ips": [dict(row) for row in top_access_ips],
        "most_dangerous_ips": [dict(row) for row in most_dangerous_ips],
        "scanner_ips": [dict(row) for row in scanner_ips],
        "blocked_ips": [dict(row) for row in blocked_ip_rows],
        "hourly_trend": hourly_trend,
    }
