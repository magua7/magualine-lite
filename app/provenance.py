# >> COPYRIGHT-BEGIN <<
# ─────────────────────────────────────────────────────────────
#  © 2026 MAGUALINE 初创团队 · MAGUALINE 威胁流量防护台
#     项目:magualine-lite · 原始开发贡献者:包博文、孙敦龙、孙瑞晰、梁晨、段雅怡、刘羽纯、陈陆洋
#     本软件为专有软件(闭源),© 2026 MAGUALINE 初创团队 保留所有权利。
#     未经书面许可,不得分发、商用或移除本版权标记。
#     许可详见:PROPRIETARY-LICENSE.md · 署名详见:NOTICE.md
# ─────────────────────────────────────────────────────────────
# << COPYRIGHT-END >>
# -*- coding: utf-8 -*-
"""
════════════════════════════════════════════════════════════════════
 版权与出处声明 (Provenance / Copyright Notice)
════════════════════════════════════════════════════════════════════
 本文件是 magualine-lite 项目版权信息的【唯一事实来源】(single source
 of truth)。项目中所有可见/隐性的版权标记——HTTP 响应头、数据库烙印、
 页面页脚、许可文件——均以本文件定义的常量为准。

 任何人不得删除、修改本文件中的版权归属信息。
 依据《PROPRIETARY-LICENSE.md》第 4 条,移除版权标记即构成违约。

 若需更新团队名称或贡献者名单,请仅修改本文件,并在 NOTICE.md 中同步。
════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import hashlib
import datetime as _dt

# ─────────────────────────────────────────────────────────────────
# 1. 版权主体(修改团队名/年份只需改这里)
# ─────────────────────────────────────────────────────────────────
PROJECT_NAME = "magualine-lite"
PROJECT_TITLE = "MAGUALINE 威胁流量防护台"
COPYRIGHT_HOLDER = "MAGUALINE 初创团队"          # ← 团队全称,在此替换
COPYRIGHT_YEAR_START = 2026                       # ← 首次开发年份
_COPYRIGHT_YEAR_NOW = _dt.date.today().year
COPYRIGHT_YEAR_RANGE = (
    str(COPYRIGHT_YEAR_START)
    if _COPYRIGHT_YEAR_NOW <= COPYRIGHT_YEAR_START
    else f"{COPYRIGHT_YEAR_START}-{_COPYRIGHT_YEAR_NOW}"
)

# 开发贡献者(源码级贡献,按姓氏拼音排序;详见 NOTICE.md)
CONTRIBUTORS: tuple[str, ...] = (
    "包博文",
    "孙敦龙",
    "孙瑞晰",
    "梁晨",
    "段雅怡",
    "刘羽纯",
    "陈陆洋",
)

LICENSE_NAME = "Proprietary - All Rights Reserved(专有软件,保留所有权利)"
LICENSE_DOC = "PROPRIETARY-LICENSE.md"
NOTICE_DOC = "NOTICE.md"

# ─────────────────────────────────────────────────────────────────
# 2. 派生文本(勿手改,由上方常量派生)
# ─────────────────────────────────────────────────────────────────
COPYRIGHT_LINE = f"© {COPYRIGHT_YEAR_RANGE} {COPYRIGHT_HOLDER} · {PROJECT_TITLE}"
HEADER_LINE = f"{COPYRIGHT_LINE} | 许可:{LICENSE_NAME} | 详见 {LICENSE_DOC} 与 {NOTICE_DOC}"

# 嵌入页面页脚的单行版权
FOOTER_HTML_LINE = COPYRIGHT_LINE

# HTTP 响应头(HTTP 头仅允许 latin-1,故此处使用 ASCII 署名变体)
X_PROTECTED_BY = "MAGUALINE WAF"
X_COPYRIGHT = (
    f"(C) {COPYRIGHT_YEAR_RANGE} MAGUALINE Startup Team - magualine-lite - "
    "PROPRIETARY, see PROPRIETARY-LICENSE.md"
)

# ─────────────────────────────────────────────────────────────────
# 3. 出处指纹(用于数据库烙印与隐性校验,勿手改)
# ─────────────────────────────────────────────────────────────────
# 指纹 = SHA256(项目名 + 版权主体 + 年份 + 贡献者)
# 任何对署名信息的篡改都会导致指纹变化,可作为"烙印被篡改"的检测依据。
_PROVENANCE_SEED = "|".join(
    [PROJECT_NAME, COPYRIGHT_HOLDER, str(COPYRIGHT_YEAR_START), *CONTRIBUTORS]
)
PROVENANCE_FINGERPRINT = hashlib.sha256(_PROVENANCE_SEED.encode("utf-8")).hexdigest()

# 数据库烙印表(以 _ 开头,SQLite 中仍为普通表,但命名表明其为系统保留表)
PROVENANCE_TABLE = "_provenance"


def provenance_banner(lang: str = "py") -> str:
    """生成源码文件头版权 banner(与 scripts/stamp_copyright.py 保持一致)。"""
    if lang == "html":
        return (
            f"<!--\n  {HEADER_LINE}\n"
            f"  本文件为 {COPYRIGHT_HOLDER} 开发成果,未经书面许可不得分发、商用或移除版权标记。\n-->"
        )
    return (
        f"# ─────────────────────────────────────────────────────────\n"
        f"# {HEADER_LINE}\n"
        f"# 本文件为 {COPYRIGHT_HOLDER} 开发成果,未经书面许可不得分发、商用或移除版权标记。\n"
        f"# ─────────────────────────────────────────────────────────"
    )


def stamp_database(connection) -> None:
    """在数据库中写入版权烙印(_provenance 表)。

    由 app.storage.init_db() 在建库与每次启动时调用:
    - 首次运行:写入项目名、版权主体、年份、贡献者与出处指纹;
    - 后续运行:以 INSERT OR REPLACE 重申真值。若烙印被人手工篡改,
      重启后会被强制改回真值 —— 篡改行为反而留下"值回写"的取证线索。
    """
    from datetime import datetime, timezone

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    fields = {
        "project_name": PROJECT_NAME,
        "copyright_holder": COPYRIGHT_HOLDER,
        "copyright_years": COPYRIGHT_YEAR_RANGE,
        "contributors": "、".join(CONTRIBUTORS),
        "license": LICENSE_NAME,
        "fingerprint": PROVENANCE_FINGERPRINT,
    }
    connection.execute(
        f"""CREATE TABLE IF NOT EXISTS {PROVENANCE_TABLE} (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
    )
    for key, value in fields.items():
        connection.execute(
            f"INSERT OR REPLACE INTO {PROVENANCE_TABLE} (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, now_iso),
        )
