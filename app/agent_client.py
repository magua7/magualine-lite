from __future__ import annotations

import ast
import json
import re

import httpx

from .config import get_settings


class AgentCallError(RuntimeError):
    pass


def _extract_text(data: dict) -> str:
    output = data.get("output")
    if isinstance(output, dict):
        text = output.get("text")
        if isinstance(text, str):
            return text

        content = output.get("content")
        if isinstance(content, str):
            return content

        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, dict):
                    for key in ("text", "content"):
                        value = item.get(key)
                        if isinstance(value, str):
                            parts.append(value)
                elif isinstance(item, str):
                    parts.append(item)
            if parts:
                return "\n".join(parts)

    return ""


def _strip_markdown_json_fence(text: str) -> str:
    fenced = re.match(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        return fenced.group(1).strip()
    return text.strip()


def _try_parse_json(text: str) -> dict | None:
    if not text:
        return None

    cleaned = _strip_markdown_json_fence(text)
    cleaned = cleaned.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'").strip()
    if cleaned.lower().startswith("json"):
        cleaned = cleaned[4:].strip()

    candidates = [cleaned]

    start_idx = cleaned.find('{')
    end_idx = cleaned.rfind('}')
    if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
        candidates.append(cleaned[start_idx:end_idx + 1])

    for candidate in candidates:
        try:
            payload = json.loads(candidate)
            if isinstance(payload, dict):
                return payload
            if isinstance(payload, str) and payload.strip() != candidate.strip():
                nested = _try_parse_json(payload)
                if nested:
                    return nested
        except Exception:
            pass

    normalized = cleaned.replace("None", "null").replace("True", "true").replace("False", "false")
    normalized_candidates = [normalized]
    normalized_start = normalized.find('{')
    normalized_end = normalized.rfind('}')
    if normalized_start != -1 and normalized_end != -1 and normalized_start < normalized_end:
        normalized_candidates.append(normalized[normalized_start:normalized_end + 1])

    for candidate in normalized_candidates:
        try:
            payload = json.loads(candidate)
            if isinstance(payload, dict):
                return payload
            if isinstance(payload, str) and payload.strip() != candidate.strip():
                nested = _try_parse_json(payload)
                if nested:
                    return nested
        except Exception:
            pass

    for candidate in candidates + normalized_candidates:
        try:
            literal = ast.literal_eval(candidate)
            if isinstance(literal, dict):
                return literal
            if isinstance(literal, str) and literal.strip() != candidate.strip():
                nested = _try_parse_json(literal)
                if nested:
                    return nested
        except Exception:
            pass

    return None


def call_agent(prompt: str, session_id: str | None = None, timeout_seconds: float | None = None) -> dict:
    settings = get_settings()
    if not settings.dashscope_api_key:
        raise AgentCallError("未配置 DASHSCOPE_API_KEY")
    if not settings.bailian_app_id:
        raise AgentCallError("未配置 BAILIAN_APP_ID")

    url = f"{settings.bailian_base_url}/api/v1/apps/{settings.bailian_app_id}/completion"
    headers = {
        "Authorization": f"Bearer {settings.dashscope_api_key}",
        "Content-Type": "application/json",
    }
    if settings.bailian_workspace_id:
        headers["X-DashScope-WorkSpace"] = settings.bailian_workspace_id

    payload = {
        "input": {"prompt": prompt},
        "parameters": {},
        "debug": {},
    }
    if session_id:
        payload["input"]["session_id"] = session_id

    request_timeout = float(timeout_seconds or settings.bailian_timeout)
    timeout = httpx.Timeout(
        connect=min(10.0, request_timeout),
        read=request_timeout,
        write=min(30.0, request_timeout),
        pool=min(10.0, request_timeout),
    )

    last_error: Exception | None = None
    response = None
    for attempt in range(2):
        try:
            response = httpx.post(url, headers=headers, json=payload, timeout=timeout)
            break
        except Exception as exc:
            last_error = exc
            if attempt == 0:
                continue

    if response is None:
        error_msg = f"百炼请求失败（已重试2次）: {str(last_error)[:200]}"
        raise AgentCallError(error_msg) from last_error

    if response.status_code >= 400:
        detail = response.text[:500]
        raise AgentCallError(f"百炼返回错误 {response.status_code}: {detail}")

    try:
        data = response.json()
    except Exception as exc:
        raise AgentCallError(f"百炼返回非 JSON: {response.text[:300]}") from exc

    text = _extract_text(data)
    parsed = _try_parse_json(text)
    output = data.get("output") if isinstance(data.get("output"), dict) else {}
    session_value = output.get("session_id") if isinstance(output, dict) else None

    return {
        "request_id": data.get("request_id", ""),
        "session_id": session_value or session_id or "",
        "usage": data.get("usage", {}),
        "raw_text": text,
        "parsed": parsed or {},
    }
