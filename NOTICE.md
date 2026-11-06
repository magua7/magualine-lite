# NOTICE — 项目出处与署名

## 项目名称

**magualine-lite**(MAGUALINE 威胁流量防护台)

面向比赛演示场景的轻量 Web 应用层流量防护系统:反向代理、请求检测、
攻击拦截、CC 防护、日志留痕、后台处置与威胁大屏。

## 版权归属

> **© 2026 MAGUALINE 初创团队 · 保留所有权利**
>
> 本项目为专有软件(闭源),许可见 [PROPRIETARY-LICENSE.md](PROPRIETARY-LICENSE.md)。
> 无论经过多少次二次开发或三次开发,源自本项目的代码与设计,其著作权始终
> 归属 MAGUALINE 初创团队,衍生版本必须完整保留本 NOTICE 与版权标记。

## 原始开发贡献者

以下成员为项目原始开发贡献者(源码级,按姓氏拼音排序):

| 姓名 | 贡献 |
| --- | --- |
| 包博文 | 源码开发 |
| 陈陆洋 | 源码开发 |
| 孙瑞晰 | 源码开发 |
| 梁晨 | 源码开发 |
| 段雅怡 | 源码开发 |
| 孙敦龙 | 源码开发 |
| 刘羽纯 | 源码开发 |

*注:若各成员具体分工需要细化(如网关/检测/大屏/后台等模块分工),请在
"贡献"列补充;名单以 Git 提交历史为最终佐证。*

## 开发时间

- 项目起始:**2026 年 4 月**
- 首次交付传承:2026 年 11 月

## 内置版权标记说明(传承给后续开发者)

本项目在多处内置了版权标记,这些标记是许可的组成部分,**不得删除**:

| 位置 | 形式 |
| --- | --- |
| 所有源码文件头 | 版权注释 banner |
| `app/provenance.py` | 版权唯一事实来源(常量 + 指纹) |
| HTTP 响应头 | `X-Protected-By` / `X-Copyright`(所有经过网关的响应) |
| 数据库 | `_provenance` 烙印表(首次建库写入,含出处指纹) |
| 后台页面 | 每页页脚版权行 |
| 拦截页 | 403 页面版权水印 |

修改团队名称或贡献者名单时:**只修改 `app/provenance.py` 一处**,再运行
`python scripts/stamp_copyright.py` 即可同步所有源码文件头。

## 第三方组件

本项目引用了以下**第三方开源组件**,其版权归各自作者所有,不属于本团队
成果,依照其原许可证使用:

| 组件 | 来源 | 许可证 |
| --- | --- | --- |
| three.module.js | three.js (https://threejs.org) | MIT |
| globe.gl.min.js | globe.gl (https://github.com/vasturiano/globe.gl) | MIT |
| OrbitControls.js | three.js examples | MIT |

以及 Python 侧依赖(fastapi、uvicorn、httpx、jinja2、python-multipart、
itsdangerous、python-docx 等,见 `requirements.txt`),均遵循其各自开源许可。

除上述明确列出的第三方组件外,本项目其余全部代码、规则库(`rules/`)、
页面与视觉素材均为 MAGUALINE 初创团队原创成果。
