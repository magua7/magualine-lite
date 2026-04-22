# magualine-lite

这是一个面向比赛演示场景的轻量 Web 流量防护项目，包含：

- `gateway`：反向代理、基础检测、日志落库
- `admin`：后台管理、大屏、日志查看与处置
- `sqlite`：本地轻量存储

## 快速启动

1. 复制配置文件

```bash
cp .env.example .env
```

2. 按实际业务修改 `.env` 中的上游地址

```env
UPSTREAM_URL=http://host.docker.internal:8090
```

3. 启动服务

```bash
docker compose up -d --build
```

## 访问地址

- 外部流量入口：`http://<server-ip>/`
- 管理后台：`http://<server-ip>:9443/`

## 常用配置

### 代理与真实 IP

```env
TRUSTED_PROXY_IPS=
FORWARD_ORIGINAL_HOST=false
```

- `TRUSTED_PROXY_IPS`：
  只有当请求直连来源命中这些代理 IP 或网段时，才信任 `X-Forwarded-For` / `X-Real-IP`
- `FORWARD_ORIGINAL_HOST`：
  默认关闭。关闭时不会把客户端提供的 `Host` 原样继续转发到上游

### 请求体检测

```env
LOG_BODY_LIMIT=4096
DETECTION_BODY_LIMIT=65536
```

- `LOG_BODY_LIMIT`：日志预览长度
- `DETECTION_BODY_LIMIT`：检测用请求体长度上限

### CC 防护

```env
CC_WINDOW_SECONDS=60
CC_MAX_REQUESTS_PER_IP=120
CC_MAX_REQUESTS_PER_PATH=45
CC_BLOCK_MINUTES=1440
```

- 默认封禁时长为 `1440` 分钟，也就是 `24h`
- 仍可通过环境变量 `CC_BLOCK_MINUTES` 覆盖

### 后台登录防爆破

```env
ADMIN_LOGIN_WINDOW_SECONDS=600
ADMIN_LOGIN_MAX_FAILURES=6
ADMIN_LOGIN_LOCK_SECONDS=300
```

- 同一 IP 在时间窗口内失败次数过多后会被短时锁定
- 不需要 Redis，直接复用项目现有 sqlite

### IP 归属查询

```env
GEO_LOOKUP_ENABLED=false
GEO_PROVIDER=ip-api
GEO_LOOKUP_TIMEOUT=3.0
GEO_FAILURE_BACKOFF_SECONDS=300
```

- 默认关闭远程归属查询
- 大屏和概览优先使用本地缓存
- 远程查询失败后会进入短时退避，避免反复拖慢页面

### AI 研判

```env
DASHSCOPE_API_KEY=
BAILIAN_APP_ID=
BAILIAN_WORKSPACE_ID=
BAILIAN_BASE_URL=https://dashscope.aliyuncs.com
BAILIAN_TIMEOUT=120
```

配置完成后重新执行：

```bash
docker compose up -d --build
```
