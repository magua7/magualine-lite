from __future__ import annotations

import ipaddress
import logging
import threading
import time

import httpx

from .config import get_settings


LOGGER = logging.getLogger(__name__)
_geo_provider_lock = threading.Lock()
_geo_provider_backoff_until = 0.0


def _geo_result(label: str, *, country: str = "", region: str = "", city: str = "", isp: str = "", source: str) -> dict:
    return {
        "label": label,
        "country": country,
        "region": region,
        "city": city,
        "isp": isp,
        "source": source,
    }


def should_cache_geo_result(geo: dict | None) -> bool:
    source = str((geo or {}).get("source") or "").strip().lower()
    if source == "local":
        return True
    if source != "remote":
        return False
    return any(str((geo or {}).get(key) or "").strip() for key in ("country", "region", "city"))


def classify_special_ip(ip: str) -> dict | None:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return _geo_result("无效 IP", source="local")

    if parsed.is_loopback:
        return _geo_result("本机回环地址", country="本机", source="local")

    if parsed.is_private:
        return _geo_result("内网地址", country="内网", source="local")

    if parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified:
        return _geo_result("保留地址", country="保留地址", source="local")

    return None


def _provider_backoff_active() -> bool:
    with _geo_provider_lock:
        return time.monotonic() < _geo_provider_backoff_until


def _activate_provider_backoff(seconds: int) -> None:
    global _geo_provider_backoff_until
    with _geo_provider_lock:
        _geo_provider_backoff_until = time.monotonic() + max(1, seconds)


def _lookup_ip_api(ip: str) -> dict:
    settings = get_settings()
    response = httpx.get(
        f"http://ip-api.com/json/{ip}",
        params={
            "lang": "zh-CN",
            "fields": "status,message,country,regionName,city,isp,query",
        },
        timeout=settings.geo_lookup_timeout,
    )
    response.raise_for_status()
    payload = response.json()

    if payload.get("status") != "success":
        message = str(payload.get("message") or "").strip().lower()
        if message in {"limit reached", "quota exceeded"}:
            _activate_provider_backoff(settings.geo_failure_backoff_seconds)
        return _geo_result("未知位置", source="remote")

    country = str(payload.get("country") or "")
    region = str(payload.get("regionName") or "")
    city = str(payload.get("city") or "")
    isp = str(payload.get("isp") or "")
    label = " / ".join([part for part in (country, region, city) if part]) or "未知位置"
    return _geo_result(label, country=country, region=region, city=city, isp=isp, source="remote")


def lookup_ip_geo(ip: str) -> dict:
    special = classify_special_ip(ip)
    if special is not None:
        return special

    settings = get_settings()
    if not settings.geo_lookup_enabled:
        return _geo_result("未知位置", source="disabled")

    provider = settings.geo_provider
    if provider != "ip-api":
        return _geo_result("未知位置", source="disabled")

    if _provider_backoff_active():
        return _geo_result("位置查询暂不可用", source="backoff")

    try:
        return _lookup_ip_api(ip)
    except Exception as exc:
        _activate_provider_backoff(settings.geo_failure_backoff_seconds)
        LOGGER.warning("Geo lookup failed for %s via %s: %s", ip, provider, exc)
        return _geo_result("定位失败", source="backoff")
