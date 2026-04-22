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


def _coerce_float(value: object, *, minimum: float, maximum: float) -> float | None:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return number if minimum <= number <= maximum else None


def _geo_result(
    label: str,
    *,
    country: str = "",
    country_code: str = "",
    region: str = "",
    region_name: str = "",
    city: str = "",
    isp: str = "",
    lat: float | None = None,
    lon: float | None = None,
    source: str,
    geo_precision: str = "unknown",
) -> dict:
    region_text = region_name or region
    return {
        "label": label,
        "country": country,
        "country_code": country_code,
        "region": region_text,
        "region_name": region_text,
        "region_code": region if region and region != region_text else "",
        "city": city,
        "isp": isp,
        "lat": lat,
        "lon": lon,
        "source": source,
        "geo_precision": geo_precision,
    }


def should_cache_geo_result(geo: dict | None) -> bool:
    source = str((geo or {}).get("source") or "").strip().lower()
    if source == "local":
        return True
    if source != "remote":
        return False
    if (geo or {}).get("lat") is not None and (geo or {}).get("lon") is not None:
        return True
    return any(str((geo or {}).get(key) or "").strip() for key in ("country", "region", "region_name", "city"))


def classify_special_ip(ip: str) -> dict | None:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return _geo_result("无效 IP", source="local", geo_precision="local")

    if parsed.is_loopback:
        return _geo_result("本机回环地址", country="本机", source="local", geo_precision="local")

    if parsed.is_private:
        return _geo_result("内网地址", country="内网", source="local", geo_precision="local")

    if parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified:
        return _geo_result("保留地址", country="保留地址", source="local", geo_precision="local")

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
            "fields": "status,message,country,countryCode,region,regionName,city,lat,lon,isp,query",
        },
        timeout=settings.geo_lookup_timeout,
    )
    response.raise_for_status()
    payload = response.json()

    if payload.get("status") != "success":
        message = str(payload.get("message") or "").strip().lower()
        if message in {"limit reached", "quota exceeded"}:
            _activate_provider_backoff(settings.geo_failure_backoff_seconds)
        return _geo_result("未知位置", source="remote", geo_precision="unknown")

    country = str(payload.get("country") or "")
    country_code = str(payload.get("countryCode") or "")
    region_code = str(payload.get("region") or "")
    region = str(payload.get("regionName") or "")
    city = str(payload.get("city") or "")
    isp = str(payload.get("isp") or "")
    lat = _coerce_float(payload.get("lat"), minimum=-90.0, maximum=90.0)
    lon = _coerce_float(payload.get("lon"), minimum=-180.0, maximum=180.0)
    label = " / ".join([part for part in (country, region, city) if part]) or "未知位置"
    precision = "exact" if lat is not None and lon is not None else ("region" if region or city else "country")
    return _geo_result(
        label,
        country=country,
        country_code=country_code,
        region=region_code,
        region_name=region,
        city=city,
        isp=isp,
        lat=lat,
        lon=lon,
        source="remote",
        geo_precision=precision,
    )


def lookup_ip_geo(ip: str) -> dict:
    special = classify_special_ip(ip)
    if special is not None:
        return special

    settings = get_settings()
    if not settings.geo_lookup_enabled:
        return _geo_result("未知位置", source="disabled", geo_precision="unknown")

    provider = settings.geo_provider
    if provider != "ip-api":
        return _geo_result("未知位置", source="disabled", geo_precision="unknown")

    if _provider_backoff_active():
        return _geo_result("位置查询暂不可用", source="backoff", geo_precision="unknown")

    try:
        return _lookup_ip_api(ip)
    except Exception as exc:
        _activate_provider_backoff(settings.geo_failure_backoff_seconds)
        LOGGER.warning("Geo lookup failed for %s via %s: %s", ip, provider, exc)
        return _geo_result("定位失败", source="backoff", geo_precision="unknown")
