#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
版权盖章脚本:将团队版权 banner 同步写入所有源码文件头。

用法(在项目根目录执行):
    python scripts/stamp_copyright.py          # 写入/更新全部文件头
    python scripts/stamp_copyright.py --check  # 仅检查,不写入(CI 用)

规则:
- banner 基于 app/provenance.py 派生 —— 改署名只需改 provenance.py 再重跑本脚本;
- 已有 banner(由 COPYRIGHT-BEGIN/END 标记识别)会被整块替换,不会重复堆积;
- python/js/css 文件 banner 加在首行之前;html 文件加在 <!DOCTYPE html> 之后;
- 本脚本自身不参与盖章(自引用会破坏标记字符串),以本文件头的声明为版权标记。

本脚本自身也是版权体系的一部分,不得删除或绕过。
版权所有 © 2026 MAGUALINE 初创团队 · 详见 PROPRIETARY-LICENSE.md
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.provenance import (  # noqa: E402
    CONTRIBUTORS,
    COPYRIGHT_HOLDER,
    COPYRIGHT_LINE,
    COPYRIGHT_YEAR_RANGE,
    PROJECT_NAME,
)

BANNER_CORE = f"""{COPYRIGHT_LINE}
   项目:{PROJECT_NAME} · 原始开发贡献者:{'、'.join(CONTRIBUTORS)}
   本软件为专有软件(闭源),© {COPYRIGHT_YEAR_RANGE} {COPYRIGHT_HOLDER} 保留所有权利。
   未经书面许可,不得分发、商用或移除本版权标记。
   许可详见:PROPRIETARY-LICENSE.md · 署名详见:NOTICE.md"""


def build_banner(kind: str) -> str:
    if kind == "py":
        return (
            "# >> COPYRIGHT-BEGIN <<\n"
            "# ─────────────────────────────────────────────────────────────\n"
            + "".join(f"#  {line}\n" for line in BANNER_CORE.splitlines())
            + "# ─────────────────────────────────────────────────────────────\n"
            "# << COPYRIGHT-END >>\n"
        )
    if kind == "jscss":
        return (
            "/*\n"
            " * >> COPYRIGHT-BEGIN <<\n"
            + "".join(f" *  {line}\n" for line in BANNER_CORE.splitlines())
            + " * << COPYRIGHT-END >>\n"
            " */\n"
        )
    if kind == "html":
        return (
            "<!--\n"
            "  >> COPYRIGHT-BEGIN <<\n"
            + "".join(f"   {line}\n" for line in BANNER_CORE.splitlines())
            + "  << COPYRIGHT-END >>\n"
            "-->\n"
        )
    raise ValueError(kind)


# 每种文件类型的既有 banner 识别模式(整块匹配,用于幂等替换)
PATTERNS: dict[str, re.Pattern[str]] = {
    "py": re.compile(r"^# >> COPYRIGHT-BEGIN <<\n.*?^# << COPYRIGHT-END >>\n?", re.M | re.S),
    "jscss": re.compile(r"^/\*\n \* >> COPYRIGHT-BEGIN <<\n.*?^ \* << COPYRIGHT-END >>\n \*/\n?", re.M | re.S),
    "html": re.compile(r"^<!--\n  >> COPYRIGHT-BEGIN <<\n.*?^  << COPYRIGHT-END >>\n-->\n?", re.M | re.S),
}

TARGETS: list[tuple[str, str]] = (
    [(f"app/{p}.py", "py") for p in [
        "__init__", "admin", "agent_client", "config", "detection",
        "gateway", "ip_geo", "provenance", "rule_loader", "storage",
    ]]
    + [(f"app/static/{p}", "jscss") for p in [
        "app.js", "screen.js", "screen-earth.js", "screen.css", "styles.css",
    ]]
    + [(f"app/templates/{p}", "html") for p in [
        "block.html", "dashboard.html", "insights.html", "login.html",
        "log_analysis.html", "logs.html", "screen.html",
    ]]
)


def stamp(rel_path: str, kind: str, check_only: bool) -> str:
    path = ROOT / rel_path
    if not path.exists():
        return f"SKIP(不存在): {rel_path}"
    text = path.read_text(encoding="utf-8").replace("\ufeff", "")  # 清除历史遗留 BOM
    banner = build_banner(kind)

    match = PATTERNS[kind].search(text)
    if match:
        if match.group(0) == banner:
            return f"OK(已是最新): {rel_path}"
        new_text = text[: match.start()] + banner + text[match.end():]
    elif kind == "html":
        marker = "<!DOCTYPE html>"
        if marker not in text:
            return f"SKIP(无 DOCTYPE): {rel_path}"
        new_text = text.replace(marker, marker + "\n" + banner, 1)
    else:
        new_text = banner + text

    if new_text == text:
        return f"OK(已是最新): {rel_path}"
    if not check_only:
        path.write_text(new_text, encoding="utf-8")
        return f"STAMPED: {rel_path}"
    return f"NEEDS-STAMP: {rel_path}"


def main() -> int:
    check_only = "--check" in sys.argv
    results = [stamp(rel, kind, check_only) for rel, kind in TARGETS]
    for line in results:
        print(line)
    pending = [r for r in results if r.startswith("NEEDS-STAMP")]
    print(f"\n共 {len(results)} 个文件,需更新 {len(pending)} 个。")
    return 1 if check_only and pending else 0


if __name__ == "__main__":
    raise SystemExit(main())
