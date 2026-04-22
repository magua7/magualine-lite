async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    credentials: "same-origin",
    ...options,
  });

  let payload = null;
  try {
    payload = await response.json();
  } catch (error) {
    payload = null;
  }

  if (!response.ok) {
    throw new Error((payload && (payload.message || payload.detail)) || "请求失败");
  }

  return payload;
}

function createRefreshGuard(task) {
  let inFlight = false;
  return async (...args) => {
    if (inFlight) {
      return;
    }
    inFlight = true;
    try {
      return await task(...args);
    } finally {
      inFlight = false;
    }
  };
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) {
    node.textContent = value;
  }
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatTime(value) {
  if (!value) {
    return "-";
  }
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

function formatCount(value) {
  return Number(value || 0).toLocaleString("zh-CN");
}

function formatBlockDuration(minutesValue) {
  const minutes = Math.max(0, Number(minutesValue || 0));
  if (!Number.isFinite(minutes) || minutes <= 0) {
    return "0 分钟";
  }
  if (minutes >= 60 && Number.isInteger(minutes / 60)) {
    return `${minutes / 60}h`;
  }
  return `${minutes} 分钟`;
}

function setupAutoRefreshWidget() {
  const widget = document.querySelector("[data-auto-refresh-widget]");
  if (
    !widget ||
    document.body.classList.contains("auth-page") ||
    document.body.dataset.page === "log-analysis"
  ) {
    return;
  }

  const timeNode = widget.querySelector(".auto-refresh-widget__time");
  const totalSeconds = Math.max(10, Number(widget.dataset.refreshSeconds || 300));
  let remaining = totalSeconds;

  const render = () => {
    const minutes = String(Math.floor(remaining / 60)).padStart(2, "0");
    const seconds = String(remaining % 60).padStart(2, "0");
    if (timeNode) {
      timeNode.textContent = `${minutes}:${seconds}`;
    }
  };

  render();

  window.setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) {
      if (timeNode) {
        timeNode.textContent = "刷新中";
      }
      window.location.reload();
      return;
    }
    render();
  }, 1000);
}

const ACTION_LABELS = {
  allowed: "放行",
  blocked: "拦截",
  error: "错误",
};

const RULE_LABELS = {
  manual_block: "手动封禁",
  sql_injection: "SQL 注入",
  xss: "跨站脚本",
  path_traversal: "目录穿越",
  command_injection: "命令注入",
  scanner_probe: "扫描探测",
  brute_force: "暴力破解",
  webshell_upload: "WebShell 上传",
  cve_exploit_attempt: "CVE 漏洞利用",
};

const SEVERITY_LABELS = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
};

const ALERT_STATUS_LABELS = {
  real_attack: "真实攻击行为",
  customer_business: "客户业务行为",
  pending_business: "待确认业务行为",
  notified_event: "已通报事件告警",
  whitelist_traffic: "白名单流量",
  pending: "待确认业务行为",
  resolved: "已通报事件告警",
  resolved_event: "已通报事件告警",
  not_applicable: "未分类流量",
};

const ALERT_STATUS_KEYS = [
  "real_attack",
  "customer_business",
  "pending_business",
  "notified_event",
  "whitelist_traffic",
];

const HANDLED_STATUS_LABELS = {
  handled: "已处理",
  unhandled: "未处理",
  not_applicable: "未处理",
};

const LOGS_PAGE_SIZE = 20;
const BLOCKED_IPS_PAGE_SIZE = 20;
const AI_ANALYSIS_CACHE_PREFIX = "magualine:ai-log-analysis:";
const AI_ANALYSIS_CACHE_TTL_MS = 12 * 60 * 60 * 1000;
let currentLogsPage = 1;
let currentManualBlockedPage = 1;
let currentAutoBlockedPage = 1;
let currentAlertView = "all";
let currentHandledView = "all";
let currentLogsScope = "all";
const selectedLogEntries = new Map();

function buildAiAnalysisCacheKey(logId) {
  return `${AI_ANALYSIS_CACHE_PREFIX}${String(logId || "").trim()}`;
}

function readAiAnalysisCache(logId) {
  if (!logId || typeof window === "undefined" || !window.sessionStorage) {
    return "";
  }

  try {
    const raw = window.sessionStorage.getItem(buildAiAnalysisCacheKey(logId));
    if (!raw) {
      return "";
    }

    const payload = JSON.parse(raw);
    const text = String((payload && payload.text) || "").trim();
    const cachedAt = Number((payload && payload.cachedAt) || 0);
    if (!text) {
      window.sessionStorage.removeItem(buildAiAnalysisCacheKey(logId));
      return "";
    }

    if (cachedAt && Date.now() - cachedAt > AI_ANALYSIS_CACHE_TTL_MS) {
      window.sessionStorage.removeItem(buildAiAnalysisCacheKey(logId));
      return "";
    }

    return text;
  } catch (error) {
    return "";
  }
}

function writeAiAnalysisCache(logId, text) {
  if (!logId || !text || typeof window === "undefined" || !window.sessionStorage) {
    return;
  }

  try {
    window.sessionStorage.setItem(
      buildAiAnalysisCacheKey(logId),
      JSON.stringify({
        text: String(text).trim(),
        cachedAt: Date.now(),
      })
    );
  } catch (error) {
    // Ignore cache write errors and keep the current analysis visible.
  }
}

function getCurrentDetailLogId() {
  const drawer = document.getElementById("log-detail-drawer");
  return drawer ? String(drawer.dataset.logId || "") : "";
}

function setCurrentDetailLogId(logId) {
  const drawer = document.getElementById("log-detail-drawer");
  if (drawer) {
    drawer.dataset.logId = String(logId || "");
  }
}

function setDetailAiAnalysis(logId, value) {
  const currentLogId = getCurrentDetailLogId();
  if (currentLogId && String(logId || "") && currentLogId !== String(logId)) {
    return;
  }
  setText("detail-ai-analysis", value);
}

function renderCachedAiAnalysis(logId) {
  const cachedText = readAiAnalysisCache(logId);
  setDetailAiAnalysis(logId, cachedText || "点击日志行中的“智能分析”按钮，生成该流量的智能研判。");
}

function actionLabel(value) {
  return ACTION_LABELS[value] || value || "-";
}

function ruleLabel(value) {
  const extraLabels = {
    sensitive_probe: "敏感路径探测",
    cc_attack: "CC 高频访问",
  };
  return RULE_LABELS[value] || extraLabels[value] || value || "-";
}

function severityLabel(value) {
  return SEVERITY_LABELS[value] || value || "-";
}

function normalizeAlertStatus(value) {
  if (value === "pending") {
    return "pending_business";
  }
  if (value === "resolved" || value === "resolved_event") {
    return "notified_event";
  }
  return value || "not_applicable";
}

function alertStatusLabel(value) {
  const normalized = normalizeAlertStatus(value);
  return ALERT_STATUS_LABELS[normalized] || normalized || "-";
}

function handledStatusLabel(value) {
  return HANDLED_STATUS_LABELS[value] || value || "-";
}

function formatHeaders(headers) {
  if (!headers || typeof headers !== "object" || !Object.keys(headers).length) {
    return "无请求头记录";
  }
  return Object.entries(headers)
    .map(([key, value]) => `${key}: ${value}`)
    .join("\n");
}

function formatAiLogDisplay(display) {
  if (!display || typeof display !== "object") {
    return "AI 未返回结构化结果";
  }

  const sections = [];
  const title = String(display.title || "").trim();
  const summary = String(display.summary || "").trim();
  const dispositionLabel = String(display.disposition_label || alertStatusLabel(display.disposition)).trim();
  const riskLabel = String(display.risk_level_label || severityLabel(display.risk_level)).trim();
  const confidence = String(display.confidence || "").trim();

  if (title) {
    sections.push(title);
  }

  const overviewLine = [];
  if (dispositionLabel && dispositionLabel !== "-") {
    overviewLine.push(`事件分类为${dispositionLabel}`);
  }
  if (riskLabel && riskLabel !== "-") {
    overviewLine.push(`风险等级为${riskLabel}`);
  }
  if (confidence) {
    overviewLine.push(`模型置信度约为${confidence}`);
  }
  if (overviewLine.length) {
    sections.push(overviewLine.join("，") + "。");
  }

  if (summary) {
    sections.push(summary);
  }

  const buildListSection = (titleText, items, leadText) => {
    if (!Array.isArray(items) || !items.length) {
      return;
    }
    const content = items
      .map((item) => String(item || "").trim())
      .filter(Boolean)
      .map((item, index) => `${index + 1}. ${item}`)
      .join("\n");
    if (content) {
      sections.push(`${titleText}\n${leadText ? `${leadText}\n` : ""}${content}`.trim());
    }
  };

  buildListSection("主要依据", display.evidence);
  buildListSection("仍需确认", display.uncertainties);
  buildListSection("建议动作", display.suggested_actions);
  buildListSection("规则与策略建议", display.rule_patch_suggestion);

  return sections.join("\n\n").trim() || "AI 未返回可展示结果";
}

function buildAnalysisNarrative(overview) {
  const total = Number(overview.total_requests || 0);
  const blocked = Number(overview.blocked_requests || 0);
  const uniqueIps = Number(overview.unique_ips || 0);
  const topAttackList = Array.isArray(overview.top_attack_types) ? overview.top_attack_types : [];
  const topAttack = topAttackList[0] && topAttackList[0].name
    ? ruleLabel(topAttackList[0].name)
    : "暂无明显攻击";
  const topAttackCount = Number((topAttackList[0] && topAttackList[0].count) || 0);

  if (blocked > 0) {
    return {
      headline: `近 24 小时累计拦截 ${formatCount(blocked)} 次异常请求`,
      copy: `当前总请求 ${formatCount(total)} 次，独立来源 IP ${formatCount(uniqueIps)} 个。最活跃的攻击类型为 ${topAttack}，共命中 ${formatCount(topAttackCount)} 次。`,
    };
  }

  if (total > 0) {
    return {
      headline: `近 24 小时已处理 ${formatCount(total)} 次访问流量`,
      copy: `当前暂无明确拦截峰值，但已记录 ${formatCount(uniqueIps)} 个来源 IP。建议继续观察登录接口、参数访问和上传入口。`,
    };
  }

  return {
    headline: "当前整体态势稳定",
    copy: "尚未采集到足够流量数据，可以先访问被保护站点或模拟攻击来生成展示样本。",
  };
}

function fillCommonMetrics(overview, options = {}) {
  const prefix = options.prefix || "";
  const blockedIpTotal = Number(overview.blocked_ip_count || 0) + Number(overview.cc_ban_count || 0);
  setText(`${prefix}metric-total`, formatCount(overview.total_requests || 0));
  setText(`${prefix}metric-blocked`, formatCount(overview.blocked_requests || 0));
  setText(`${prefix}metric-ips`, formatCount(overview.unique_ips || 0));
  setText(`${prefix}metric-alert-high`, formatCount(overview.high_risk_alerts || 0));

  if (!prefix) {
    setText("metric-manual-blocks", formatCount(blockedIpTotal));
    setText("metric-alert-total", formatCount(overview.total_alerts || 0));
    setText("metric-alert-unhandled", formatCount(overview.unhandled_alerts || 0));
    setText("metric-alert-handled", formatCount(overview.handled_alerts || 0));
    setText("metric-alert-pending", formatCount(overview.pending_alerts || 0));
    setText("metric-alert-resolved", formatCount(overview.resolved_alerts || 0));
    setText("metric-bruteforce", formatCount(overview.brute_force_events || 0));
    setText("metric-webshell", formatCount(overview.webshell_upload_events || 0));
    setText("metric-cve", formatCount(overview.cve_alert_events || 0));
    setText("metric-cc-events", formatCount(overview.cc_attack_events || 0));
    setText("metric-cc-bans", formatCount(overview.cc_ban_count || 0));
    setText("metric-cc-window", `${Number(overview.cc_protection?.window_seconds || 0)} 秒`);
    setText("metric-cc-ip-limit", `${Number(overview.cc_protection?.max_requests_per_ip || 0)} 次`);
    setText("metric-cc-path-limit", `${Number(overview.cc_protection?.max_requests_per_path || 0)} 次`);
    setText("metric-cc-block-minutes", formatBlockDuration(overview.cc_protection?.block_minutes || 0));
    const ccBoardStatus = document.getElementById("cc-board-status");
    if (ccBoardStatus) {
      ccBoardStatus.textContent = overview.cc_protection?.enabled ? "已启用" : "已停用";
      ccBoardStatus.classList.toggle("is-disabled", !overview.cc_protection?.enabled);
    }
    setText("map-total", formatCount(overview.total_requests || 0));
    setText("map-rate", `${overview.blocked_rate || 0}%`);
  }
}

function renderRankList(containerId, items, emptyText, options = {}) {
  const container = document.getElementById(containerId);
  if (!container) {
    return;
  }

  if (!items.length) {
    container.innerHTML = `<div class="empty-state">${escapeHtml(emptyText)}</div>`;
    return;
  }

  const itemClass = container.classList.contains("screen-rank-list") ? "screen-rank-item" : "rank-item";
  const valueClass = container.classList.contains("screen-rank-list") ? "screen-count-pill" : "count-pill";
  const labelFormatter = options.labelFormatter || ((item) => item.name);
  const valueFormatter = options.valueFormatter || ((item) => item.count);

  container.innerHTML = items
    .map(
      (item, index) => `
        <div class="${itemClass}">
          <div>
            <span class="rank-order">${String(index + 1).padStart(2, "0")}</span>
            <strong>${escapeHtml(labelFormatter(item))}</strong>
          </div>
          <span class="${valueClass}">${escapeHtml(valueFormatter(item))}</span>
        </div>
      `
    )
    .join("");
}

function renderHighRiskAlerts(items) {
  const container = document.getElementById("high-risk-alerts");
  if (!container) {
    return;
  }

  if (!items.length) {
    container.innerHTML = `<div class="empty-state">最近 24 小时没有高危事件</div>`;
    return;
  }

  container.innerHTML = items
    .map(
      (item) => {
        const alertStatus = normalizeAlertStatus(item.alert_status);
        return `
        <div class="alert-item high">
          <div>
            <strong>${escapeHtml(
              item.cve_id ? `${ruleLabel(item.attack_type)} · ${item.cve_id}` : ruleLabel(item.attack_type)
            )}</strong>
            <div class="muted-text">${escapeHtml(item.client_ip)} · ${escapeHtml(item.path)}</div>
            <div class="muted-text">${escapeHtml(formatTime(item.created_at))}</div>
          </div>
          <span class="status-pill alert ${escapeHtml(alertStatus)}">
            ${escapeHtml(alertStatusLabel(alertStatus))}
          </span>
        </div>
      `;
      }
    )
    .join("");
}

function renderBlockedListSection(items, options = {}) {
  const container = document.getElementById(options.containerId || "");
  if (!container) {
    return;
  }

  if (!items.length) {
    container.innerHTML = `<div class="empty-state">${escapeHtml(options.emptyText || "暂无封禁 IP")}</div>`;
    return;
  }

  const isAuto = options.kind === "auto";
  container.innerHTML = items
    .map((item) => {
      const badgeText = isAuto ? "自动封禁" : "手动封禁";
      const badgeClass = isAuto ? "blocked-kind--info" : "blocked-kind--manual";
      const reasonText = isAuto
        ? escapeHtml(item.reason || "CC 高频访问自动封禁")
        : escapeHtml(item.reason || "手动封禁");
      const timeText = isAuto
        ? `到期时间：${escapeHtml(formatTime(item.expires_at))}`
        : escapeHtml(formatTime(item.created_at));

      return `
        <div class="blocked-item blocked-item--${escapeHtml(options.kind || "manual")}">
          <div class="blocked-item__body">
            <div class="blocked-item__top">
              <strong>${escapeHtml(item.ip)}</strong>
              <span class="count-pill blocked-kind ${badgeClass}">${badgeText}</span>
            </div>
            <div class="muted-text">${reasonText}</div>
            <div class="muted-text">${timeText}</div>
          </div>
          ${
            isAuto
              ? `<button class="small-button neutral" type="button" data-auto-unblock="${escapeHtml(item.id)}">提前解除</button>`
              : `<button class="small-button" type="button" data-unblock="${escapeHtml(item.id)}">解除</button>`
          }
        </div>
      `;
    })
    .join("");

  container.querySelectorAll("button[data-unblock]").forEach((button) => {
    button.addEventListener("click", async () => {
      const id = button.getAttribute("data-unblock");
      await fetchJson(`/api/blocked-ips/${id}`, { method: "DELETE" });
      await refreshBlockPage();
    });
  });

  container.querySelectorAll("button[data-auto-unblock]").forEach((button) => {
    button.addEventListener("click", async () => {
      const id = button.getAttribute("data-auto-unblock");
      await fetchJson(`/api/cc-bans/${id}`, { method: "DELETE" });
      await refreshBlockPage();
    });
  });
}

function renderBlockedPaginationSection(payload, options = {}) {
  const summary = document.getElementById(options.summaryId || "");
  const container = document.getElementById(options.containerId || "");
  if (!summary || !container) {
    return;
  }

  const total = Number(payload.total || 0);
  const page = Number(payload.page || 1);
  const pageSize = Number(payload.page_size || BLOCKED_IPS_PAGE_SIZE);
  const totalPages = Number(payload.total_pages || 0);
  const kind = options.kind === "auto" ? "auto" : "manual";

  if (!total) {
    summary.textContent = options.emptySummary || "暂无封禁 IP";
    container.innerHTML = "";
    return;
  }

  const start = (page - 1) * pageSize + 1;
  const end = Math.min(total, page * pageSize);
  summary.textContent = `显示第 ${start}-${end} 条，共 ${total} 条，当前第 ${page}/${Math.max(totalPages, 1)} 页`;

  const buttons = [];
  buttons.push(
    `<button class="pagination-button" type="button" data-block-page="${page - 1}" data-block-kind="${kind}" ${page <= 1 ? "disabled" : ""}>上一页</button>`
  );

  const pageNumbers = [];
  const windowSize = 5;
  const startPage = Math.max(1, page - 2);
  const endPage = Math.min(totalPages, startPage + windowSize - 1);
  const adjustedStart = Math.max(1, endPage - windowSize + 1);
  for (let value = adjustedStart; value <= endPage; value += 1) {
    pageNumbers.push(value);
  }

  pageNumbers.forEach((value) => {
    buttons.push(
      `<button class="pagination-button ${value === page ? "active" : ""}" type="button" data-block-page="${value}" data-block-kind="${kind}">${value}</button>`
    );
  });

  buttons.push(
    `<button class="pagination-button" type="button" data-block-page="${page + 1}" data-block-kind="${kind}" ${page >= totalPages ? "disabled" : ""}>下一页</button>`
  );

  container.innerHTML = buttons.join("");
  container.querySelectorAll("button[data-block-page]").forEach((button) => {
    button.addEventListener("click", async () => {
      const nextPage = Number(button.getAttribute("data-block-page") || "1");
      const nextKind = button.getAttribute("data-block-kind") || "manual";
      if (!nextPage) {
        return;
      }
      if (nextKind === "auto") {
        if (nextPage === currentAutoBlockedPage) {
          return;
        }
        currentAutoBlockedPage = nextPage;
      } else {
        if (nextPage === currentManualBlockedPage) {
          return;
        }
        currentManualBlockedPage = nextPage;
      }
      await refreshBlockPage();
    });
  });
}

function getAlertCategoryDisplay(alertStatus, handledStatus) {
  const normalizedHandledStatus = handledStatus === "handled" ? "handled" : "unhandled";
  const normalizedAlertStatus = normalizeAlertStatus(alertStatus);

  if (normalizedHandledStatus !== "handled") {
    return {
      value: "pending_review",
      label: "待处置",
    };
  }

  if (normalizedAlertStatus && normalizedAlertStatus !== "not_applicable") {
    return {
      value: normalizedAlertStatus,
      label: alertStatusLabel(normalizedAlertStatus),
    };
  }

  return {
    value: "uncategorized",
    label: "未分类",
  };
}

function renderLogDispositionControl(logId, alertStatus, handledStatus) {
  const normalizedHandledStatus = handledStatus === "handled" ? "handled" : "unhandled";
  const normalizedStatus =
    normalizedHandledStatus === "handled" ? normalizeAlertStatus(alertStatus) : "";
  const currentStatus = normalizedStatus && normalizedStatus !== "not_applicable" ? normalizedStatus : "";

  const options = [
    `<option value="" ${currentStatus ? "" : "selected"}>${escapeHtml("请选择处置分类")}</option>`,
    ...ALERT_STATUS_KEYS.map(
      (value) => `
        <option value="${escapeHtml(value)}" ${value === currentStatus ? "selected" : ""}>
          ${escapeHtml(alertStatusLabel(value))}
        </option>
      `
    ),
  ].join("");

  return `
    <label class="status-select-wrap ${escapeHtml(currentStatus || "empty")}">
      <div class="status-select-inline">
        <select class="status-select ${escapeHtml(currentStatus || "empty")}" data-status-select-id="${escapeHtml(logId)}">
          ${options}
        </select>
        <button class="small-button disposition" type="button" data-status-id="${escapeHtml(logId)}" ${currentStatus ? "" : "disabled"}>处置</button>
      </div>
    </label>
  `;
}

function getSelectedDisposition(logId) {
  const select = document.querySelector(`select[data-status-select-id="${logId}"]`);
  return select ? select.value : "";
}

function renderHandledStatusBadge(handledStatus) {
  const normalized = handledStatus === "handled" ? "handled" : "unhandled";
  const badgeClass = normalized === "handled" ? "handled-badge-success" : "handled-badge-pending";
  return `<span class="status-pill handled ${escapeHtml(normalized)} ${badgeClass}">${escapeHtml(handledStatusLabel(normalized))}</span>`;
}

function renderAlertCategoryBadge(alertStatus, handledStatus) {
  const display = getAlertCategoryDisplay(alertStatus, handledStatus);
  return `<span class="status-pill alert ${escapeHtml(display.value)}">${escapeHtml(display.label)}</span>`;
}

function renderLogs(items) {
  const body = document.getElementById("logs-body");
  if (!body) {
    return;
  }

  if (!items.length) {
    body.innerHTML = `<tr><td colspan="14"><div class="empty-state">暂无日志</div></td></tr>`;
    syncLogsSelectionUi([]);
    return;
  }

  body.innerHTML = items
    .map((item) => {
      const reason = item.attack_type
        ? `${ruleLabel(item.attack_type)}${item.cve_id ? ` · ${item.cve_id}` : ""}${item.attack_detail ? ` / ${item.attack_detail}` : ""}`
        : "-";
      const alertStatus = normalizeAlertStatus(item.alert_status);
      const handledStatus = item.handled_status === "handled" ? "handled" : "unhandled";
      const alertCategoryDisplay = getAlertCategoryDisplay(alertStatus, handledStatus);
      const severityClass = String(item.severity || "low").toLowerCase();
      const highRiskSeverity = severityClass === "high" || severityClass === "critical";
      const upstreamStatus = item.upstream_status || item.status_code || "-";
      const destinationIp = item.destination_ip || "-";
      const destinationHost = item.destination_host || "-";

      const buttons = [
        `<button class="small-button detail" type="button" data-detail-id="${escapeHtml(item.id)}">详情</button>`,
        `<button class="small-button neutral" type="button" data-ai-id="${escapeHtml(item.id)}">智能分析</button>`,
        `<button class="small-button" type="button" data-ip="${escapeHtml(item.client_ip)}">封禁</button>`,
      ];

      buttons.push(renderLogDispositionControl(item.id, alertStatus, handledStatus));

      return `
        <tr class="${highRiskSeverity ? "log-row-high" : ""} ${alertCategoryDisplay.value ? `log-row-${alertCategoryDisplay.value}` : ""}">
          <td class="checkbox-column">
            <input
              class="log-select-checkbox"
              type="checkbox"
              data-log-id="${escapeHtml(item.id)}"
              data-ip="${escapeHtml(item.client_ip)}"
              ${selectedLogEntries.has(String(item.id)) ? "checked" : ""}
            />
          </td>
          <td>${escapeHtml(formatTime(item.created_at))}</td>
          <td><code>${escapeHtml(item.client_ip)}</code></td>
          <td><code title="${escapeHtml(destinationHost)}">${escapeHtml(destinationIp)}</code></td>
          <td>${escapeHtml(item.method)}</td>
          <td><code title="${escapeHtml(item.path)}">${escapeHtml(item.path)}</code></td>
          <td><span class="status-pill ${escapeHtml(item.action || "allowed")}">${escapeHtml(actionLabel(item.action))}</span></td>
          <td><span class="status-pill severity ${escapeHtml(severityClass)}">${escapeHtml(severityLabel(item.severity))}</span></td>
          <td>${renderHandledStatusBadge(handledStatus)}</td>
          <td>${renderAlertCategoryBadge(alertStatus, handledStatus)}</td>
          <td><code title="${escapeHtml(reason)}">${escapeHtml(reason)}</code></td>
          <td>${escapeHtml(upstreamStatus)}</td>
          <td>${escapeHtml(item.duration_ms || 0)} ms</td>
          <td><div class="row-actions">${buttons.join("")}</div></td>
        </tr>
      `;
    })
    .join("");

  body.querySelectorAll("button[data-ip]").forEach((button) => {
    button.addEventListener("click", async () => {
      const ip = button.getAttribute("data-ip");
      const reason = window.prompt(`请输入封禁 ${ip} 的原因`, "手动封禁");
      if (reason === null) {
        return;
      }
      await blockIp(ip, reason || "手动封禁");
    });
  });

  body.querySelectorAll("button[data-detail-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      await openLogDetail(button.getAttribute("data-detail-id"));
    });
  });

  body.querySelectorAll("button[data-ai-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      const logId = button.getAttribute("data-ai-id");
      const originalText = button.textContent;
      button.disabled = true;
      button.textContent = "智能分析中";
      try {
        await openLogDetail(logId);
        await analyzeLogWithAi(logId);
      } finally {
        button.disabled = false;
        button.textContent = originalText || "智能分析";
      }
    });
  });

  body.querySelectorAll("select[data-status-select-id]").forEach((select) => {
    const logId = select.getAttribute("data-status-select-id");
    const button = body.querySelector(`button[data-status-id="${logId}"]`);
    const wrap = select.closest(".status-select-wrap");
    const syncState = () => {
      const nextValue = String(select.value || "").trim();
      select.className = `status-select ${nextValue || "empty"}`;
      if (wrap) {
        wrap.className = `status-select-wrap ${nextValue || "empty"}`;
      }
      if (button) {
        button.disabled = !nextValue;
      }
    };
    syncState();
    select.addEventListener("change", syncState);
  });

  body.querySelectorAll("button[data-status-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      const logId = button.getAttribute("data-status-id");
      const alertStatus = getSelectedDisposition(logId);
      if (!alertStatus) {
        return;
      }
      await updateLogStatus(logId, alertStatus);
    });
  });

  body.querySelectorAll(".log-select-checkbox").forEach((checkbox) => {
    checkbox.addEventListener("change", () => {
      const logId = checkbox.getAttribute("data-log-id");
      const ip = checkbox.getAttribute("data-ip") || "";
      if (!logId) {
        return;
      }
      if (checkbox.checked) {
        selectedLogEntries.set(logId, ip);
      } else {
        selectedLogEntries.delete(logId);
      }
      syncLogsSelectionUi(items);
    });
  });

  syncLogsSelectionUi(items);
}

function syncLogsSelectionUi(items) {
  const selectAll = document.getElementById("logs-select-all");
  const summary = document.getElementById("logs-selected-summary");
  const bulkButton = document.getElementById("bulk-block-button");
  const bulkDispositionButton = document.getElementById("bulk-disposition-button");
  if (!selectAll || !summary || !bulkButton || !bulkDispositionButton) {
    return;
  }

  const pageIds = items.map((item) => String(item.id));
  Array.from(selectedLogEntries.keys()).forEach((id) => {
    if (!pageIds.includes(String(id))) {
      selectedLogEntries.delete(id);
    }
  });
  const selectedCount = pageIds.filter((id) => selectedLogEntries.has(id)).length;
  const uniqueIps = new Set(
    pageIds
      .filter((id) => selectedLogEntries.has(id))
      .map((id) => selectedLogEntries.get(id))
      .filter(Boolean)
  );

  selectAll.checked = items.length > 0 && selectedCount === items.length;
  selectAll.indeterminate = selectedCount > 0 && selectedCount < items.length;
  summary.textContent = `已选 ${selectedCount} 条流量，涉及 ${uniqueIps.size} 个 IP`;
  bulkButton.disabled = uniqueIps.size === 0;
  bulkDispositionButton.disabled = selectedCount === 0;
}

function buildLogsPageItems(page, totalPages) {
  if (totalPages <= 7) {
    return Array.from({ length: totalPages }, (_, index) => index + 1);
  }

  const pages = new Set([1, 2, page - 1, page, page + 1, totalPages - 1, totalPages]);
  const normalized = Array.from(pages)
    .filter((value) => value >= 1 && value <= totalPages)
    .sort((left, right) => left - right);

  const items = [];
  normalized.forEach((value, index) => {
    if (index > 0 && value - normalized[index - 1] > 1) {
      items.push("ellipsis");
    }
    items.push(value);
  });
  return items;
}

function renderLogsPagination(payload) {
  const summary = document.getElementById("logs-pagination-summary");
  const container = document.getElementById("logs-pagination");
  const jumpForm = document.getElementById("logs-page-jump");
  const jumpInput = document.getElementById("logs-page-input");
  const currentLabel = document.getElementById("logs-page-current");
  if (!summary || !container) {
    return;
  }

  const total = Number(payload.total || 0);
  const page = Number(payload.page || 1);
  const pageSize = Number(payload.page_size || LOGS_PAGE_SIZE);
  const totalPages = Number(payload.total_pages || 0);

  if (!total) {
    summary.textContent = "暂无流量日志";
    container.innerHTML = "";
    if (currentLabel) {
      currentLabel.textContent = "第 0 / 0 页";
    }
    if (jumpForm) {
      jumpForm.hidden = true;
    }
    return;
  }

  const start = (page - 1) * pageSize + 1;
  const end = Math.min(total, page * pageSize);
  const safeTotalPages = Math.max(totalPages, 1);
  summary.textContent = `显示第 ${start}-${end} 条，共 ${total} 条，当前第 ${page}/${safeTotalPages} 页`;
  if (currentLabel) {
    currentLabel.textContent = `第 ${page} / ${safeTotalPages} 页`;
  }

  const buttons = [];
  buttons.push(`
    <button class="pagination-button" type="button" data-page="1" ${page <= 1 ? "disabled" : ""}>
      首页
    </button>
  `);
  buttons.push(`
    <button class="pagination-button" type="button" data-page="${page - 1}" ${page <= 1 ? "disabled" : ""}>
      上一页
    </button>
  `);

  buildLogsPageItems(page, safeTotalPages).forEach((item) => {
    if (item === "ellipsis") {
      buttons.push(`<span class="pagination-ellipsis">...</span>`);
      return;
    }

    buttons.push(`
      <button class="pagination-button ${item === page ? "active" : ""}" type="button" data-page="${item}">
        ${item}
      </button>
    `);
  });

  buttons.push(`
    <button class="pagination-button" type="button" data-page="${page + 1}" ${page >= safeTotalPages ? "disabled" : ""}>
      下一页
    </button>
  `);
  buttons.push(`
    <button class="pagination-button" type="button" data-page="${safeTotalPages}" ${page >= safeTotalPages ? "disabled" : ""}>
      末页
    </button>
  `);

  container.innerHTML = buttons.join("");

  if (jumpForm && jumpInput) {
    jumpForm.hidden = safeTotalPages <= 1;
    jumpInput.min = "1";
    jumpInput.max = String(safeTotalPages);
    jumpInput.value = "";
    jumpInput.placeholder = `1-${safeTotalPages}`;

    jumpForm.onsubmit = async (event) => {
      event.preventDefault();
      const nextPage = Number(jumpInput.value || "");
      if (!nextPage || nextPage < 1 || nextPage > safeTotalPages || nextPage === currentLogsPage) {
        return;
      }
      selectedLogEntries.clear();
      currentLogsPage = nextPage;
      await refreshLogsPage();
    };
  }

  container.querySelectorAll("button[data-page]").forEach((button) => {
    button.addEventListener("click", async () => {
      const nextPage = Number(button.getAttribute("data-page") || "1");
      if (!nextPage || nextPage < 1 || nextPage > safeTotalPages || nextPage === currentLogsPage) {
        return;
      }
      selectedLogEntries.clear();
      currentLogsPage = nextPage;
      await refreshLogsPage();
    });
  });
}

function renderAlertViewTabs(overview) {
  setText("alert-view-total", formatCount(overview.total_requests || 0));
  setText("alert-view-real-attack", formatCount(overview.real_attack_alerts || 0));
  setText("alert-view-customer-business", formatCount(overview.customer_business_alerts || 0));
  setText("alert-view-pending-business", formatCount(overview.pending_business_alerts || 0));
  setText("alert-view-notified-event", formatCount(overview.notified_event_alerts || overview.resolved_event_alerts || 0));

  document.querySelectorAll(".alert-view-tab").forEach((button) => {
    const view = button.getAttribute("data-alert-view") || "all";
    button.classList.toggle("active", view === currentAlertView);
  });
}

function renderHandledViewTabs(overview) {
  setText("handled-view-total", formatCount(overview.total_requests || 0));
  setText("handled-view-unhandled", formatCount(overview.unhandled_alerts || 0));
  setText("handled-view-handled", formatCount(overview.handled_alerts || 0));

  document.querySelectorAll(".alert-process-tab").forEach((button) => {
    const view = button.getAttribute("data-handled-view") || "all";
    button.classList.toggle("active", view === currentHandledView);
  });
}

function renderLogScopeTabs(overview) {
  setText("log-scope-total", formatCount(overview.total_requests || 0));
  setText("log-scope-alerts", formatCount(overview.total_alerts || 0));

  document.querySelectorAll(".log-scope-tab").forEach((button) => {
    const view = button.getAttribute("data-log-scope") || "all";
    button.classList.toggle("active", view === currentLogsScope);
  });
}

function applyAlertView(view) {
  currentAlertView = view;

  const statusSelect = document.getElementById("log-alert-status");
  if (statusSelect) {
    statusSelect.value = view === "all" ? "" : view;
  }

  const totalNode = document.getElementById("metric-total");
  const realAttackNode = document.getElementById("alert-view-real-attack");
  const customerBusinessNode = document.getElementById("alert-view-customer-business");
  const pendingBusinessNode = document.getElementById("alert-view-pending-business");
  const notifiedEventNode = document.getElementById("alert-view-notified-event");
  renderAlertViewTabs({
    total_requests: (totalNode && totalNode.textContent) || "0",
    real_attack_alerts: (realAttackNode && realAttackNode.textContent) || "0",
    customer_business_alerts: (customerBusinessNode && customerBusinessNode.textContent) || "0",
    pending_business_alerts: (pendingBusinessNode && pendingBusinessNode.textContent) || "0",
    notified_event_alerts: (notifiedEventNode && notifiedEventNode.textContent) || "0",
  });

  const mainToggle = document.getElementById("alert-view-toggle");
  if (mainToggle) {
    mainToggle.classList.toggle("active", view === "all");
  }
}

function applyHandledView(view) {
  currentHandledView = view;

  const totalNode = document.getElementById("metric-total");
  const unhandledNode = document.getElementById("handled-view-unhandled");
  const handledNode = document.getElementById("handled-view-handled");
  renderHandledViewTabs({
    total_requests: (totalNode && totalNode.textContent) || "0",
    unhandled_alerts: (unhandledNode && unhandledNode.textContent) || "0",
    handled_alerts: (handledNode && handledNode.textContent) || "0",
  });
}

function applyLogScope(view) {
  currentLogsScope = view;

  const totalNode = document.getElementById("metric-total");
  const alertNode = document.getElementById("metric-alert-total");
  renderLogScopeTabs({
    total_requests: (totalNode && totalNode.textContent) || "0",
    total_alerts: (alertNode && alertNode.textContent) || "0",
  });
}

async function blockIp(ip, reason) {
  await fetchJson("/api/blocked-ips", {
    method: "POST",
    body: JSON.stringify({ ip, reason }),
  });

  if (document.body.dataset.page === "block") {
    currentManualBlockedPage = 1;
    await refreshBlockPage();
  } else if (document.body.dataset.page === "dashboard") {
    await refreshDashboard();
  } else if (document.body.dataset.page === "logs") {
    await refreshLogsPage();
  }
}

async function bulkBlockSelectedLogs() {
  const selectedIps = Array.from(new Set(Array.from(selectedLogEntries.values()).filter(Boolean)));
  if (!selectedIps.length) {
    return;
  }

  const reason = window.prompt(
    `将批量封禁 ${selectedIps.length} 个 IP，请输入统一封禁原因`,
    "批量处置异常流量来源"
  );
  if (reason === null) {
    return;
  }

  for (const ip of selectedIps) {
    await fetchJson("/api/blocked-ips", {
      method: "POST",
      body: JSON.stringify({ ip, reason: reason || "批量处置异常流量来源" }),
    });
  }

  selectedLogEntries.clear();
  await refreshLogsPage();
}

async function bulkDispositionSelectedLogs() {
  const logIds = Array.from(selectedLogEntries.keys()).map((value) => Number(value)).filter(Boolean);
  const categorySelect = document.getElementById("bulk-disposition-status");
  const alertStatus = categorySelect ? categorySelect.value : "";
  if (!logIds.length || !alertStatus) {
    return;
  }

  await fetchJson("/api/logs/disposition/bulk", {
    method: "POST",
    body: JSON.stringify({
      log_ids: logIds,
      alert_status: alertStatus,
    }),
  });

  selectedLogEntries.clear();
  await refreshLogsPage();
}

async function updateLogStatus(logId, alertStatus) {
  await fetchJson(`/api/logs/${logId}/status`, {
    method: "PATCH",
    body: JSON.stringify({ alert_status: alertStatus }),
  });
  await refreshLogsPage();
}

async function analyzeLogWithAi(logId) {
  const cachedText = readAiAnalysisCache(logId);
  if (cachedText) {
    setDetailAiAnalysis(logId, cachedText);
    return cachedText;
  }

  setDetailAiAnalysis(logId, "AI 正在分析该流量，请稍候...");
  try {
    const result = await fetchJson(`/api/agent/log/${logId}/analyze`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    const renderedText = formatAiLogDisplay(result.display || {});
    writeAiAnalysisCache(logId, renderedText);
    setDetailAiAnalysis(logId, renderedText);
    return renderedText;
  } catch (error) {
    setDetailAiAnalysis(logId, `AI 分析失败：${error.message}`);
    return "";
  }
}

async function openLogDetail(logId) {
  setCurrentDetailLogId(logId);
  const detail = await fetchJson(`/api/logs/${logId}`);

  setText("detail-created-at", formatTime(detail.created_at));
  setText("detail-client-ip", detail.client_ip || "-");
  setText("detail-destination-ip", detail.destination_ip || "-");
  setText("detail-destination-host", detail.destination_host || "-");
  setText("detail-ip-location", (detail.ip_geo && detail.ip_geo.label) || "未知位置");
  setText("detail-ip-isp", (detail.ip_geo && detail.ip_geo.isp) || "-");
  setText("detail-action", actionLabel(detail.action));
  setText("detail-severity", severityLabel(detail.severity));
    setText("detail-handled-status", handledStatusLabel(detail.handled_status));
    setText(
      "detail-alert-status",
      getAlertCategoryDisplay(detail.alert_status, detail.handled_status).label
    );
  setText("detail-cve", detail.cve_id || "-");
  setText(
    "detail-request-line",
    `${detail.method || "-"} ${detail.path || "/"}${detail.query_string ? `?${detail.query_string}` : ""}`
  );
  setText("detail-query", detail.query_string || "无查询参数");
  setText("detail-headers", formatHeaders(detail.request_headers));
  setText("detail-payload", detail.body_preview || "无 payload 预览");
  renderCachedAiAnalysis(logId);
  setText(
    "detail-rule",
    detail.attack_type
      ? `${ruleLabel(detail.attack_type)}${detail.cve_id ? ` / ${detail.cve_id}` : ""}${detail.attack_detail ? `\n${detail.attack_detail}` : ""}`
      : "无命中规则"
  );

  const backdrop = document.getElementById("log-detail-backdrop");
  if (backdrop) {
    backdrop.removeAttribute("hidden");
  }
  const drawer = document.getElementById("log-detail-drawer");
  if (drawer) {
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
  }
}

function closeLogDetail() {
  const backdrop = document.getElementById("log-detail-backdrop");
  if (backdrop) {
    backdrop.setAttribute("hidden", "hidden");
  }
  const drawer = document.getElementById("log-detail-drawer");
  if (drawer) {
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    drawer.dataset.logId = "";
  }
}

function renderDashboardSummary(overview) {
  const narrative = buildAnalysisNarrative(overview);
  setText("analysis-headline", narrative.headline);
  setText("analysis-copy", narrative.copy);
}

function buildLogsUrl() {
  const params = new URLSearchParams();
  const trafficKindNode = document.getElementById("log-traffic-kind");
  const actionNode = document.getElementById("log-action");
  const severityNode = document.getElementById("log-severity");
  const alertStatusNode = document.getElementById("log-alert-status");
  const keywordNode = document.getElementById("log-keyword");
  const trafficKind = (trafficKindNode && trafficKindNode.value) || "";
  const action = (actionNode && actionNode.value) || "";
  const severity = (severityNode && severityNode.value) || "";
  const alertStatus = (alertStatusNode && alertStatusNode.value) || "";
  const keyword = (keywordNode && keywordNode.value.trim()) || "";
  params.set("page", String(currentLogsPage));
  params.set("page_size", String(LOGS_PAGE_SIZE));

  if (trafficKind === "normal" || trafficKind === "abnormal") {
    params.set("traffic_kind", trafficKind);
  }

  if (currentHandledView === "handled" || currentHandledView === "unhandled") {
    params.set("handled_status", currentHandledView);
  }

  if (action) {
    params.set("action", action);
  }
  if (severity) {
    params.set("severity", severity);
  }
  if (ALERT_STATUS_KEYS.includes(currentAlertView)) {
    params.set("alert_status", currentAlertView);
  } else if (alertStatus) {
    params.set("alert_status", normalizeAlertStatus(alertStatus));
  }
  if (keyword) {
    params.set("keyword", keyword);
  }

  return `/api/logs?${params.toString()}`;
}

function buildBlockedIpsUrl() {
  const params = new URLSearchParams();
  params.set("manual_page", String(currentManualBlockedPage));
  params.set("auto_page", String(currentAutoBlockedPage));
  params.set("page_size", String(BLOCKED_IPS_PAGE_SIZE));
  return `/api/blocked-ips?${params.toString()}`;
}

async function refreshDashboard() {
  const [runtime, overview] = await Promise.all([
    fetchJson("/api/runtime"),
    fetchJson("/api/overview"),
  ]);

  setText("runtime-user", runtime.username || "admin");
  fillCommonMetrics(overview);
  renderDashboardSummary(overview);
  renderHighRiskAlerts(overview.latest_high_risk_alerts || []);
  renderRankList("attack-types", overview.top_attack_types || [], "最近 24 小时没有拦截记录", {
    labelFormatter: (item) => ruleLabel(item.name),
    valueFormatter: (item) => formatCount(item.count || 0),
  });
  renderRankList("source-ips", overview.top_source_ips || [], "最近 24 小时没有访问记录", {
    valueFormatter: (item) => formatCount(item.count || 0),
  });
  renderRankList("top-paths", overview.top_paths || [], "最近 24 小时没有路径数据", {
    valueFormatter: (item) => formatCount(item.count || 0),
  });
}

async function refreshBlockPage() {
  const [runtime, overview, blockedIps] = await Promise.all([
    fetchJson("/api/runtime"),
    fetchJson("/api/overview"),
    fetchJson(buildBlockedIpsUrl()),
  ]);

  if (blockedIps.manual && blockedIps.manual.total_pages && currentManualBlockedPage > blockedIps.manual.total_pages) {
    currentManualBlockedPage = blockedIps.manual.total_pages;
    return refreshBlockPage();
  }

  if (blockedIps.auto && blockedIps.auto.total_pages && currentAutoBlockedPage > blockedIps.auto.total_pages) {
    currentAutoBlockedPage = blockedIps.auto.total_pages;
    return refreshBlockPage();
  }

  setText("runtime-user", runtime.username || "admin");
  fillCommonMetrics(overview);
  setText("metric-block-manual", formatCount((blockedIps.counts && blockedIps.counts.manual) || 0));
  setText("metric-block-auto", formatCount((blockedIps.counts && blockedIps.counts.auto) || 0));
  setText("metric-block-total", formatCount((blockedIps.counts && blockedIps.counts.total) || 0));
  setText("manual-block-count", `${formatCount((blockedIps.counts && blockedIps.counts.manual) || 0)} 条`);
  setText("auto-block-count", `${formatCount((blockedIps.counts && blockedIps.counts.auto) || 0)} 条`);
  renderBlockedListSection((blockedIps.manual && blockedIps.manual.items) || [], {
    kind: "manual",
    containerId: "blocked-ips-manual",
    emptyText: "当前没有手动封禁的 IP",
  });
  renderBlockedListSection((blockedIps.auto && blockedIps.auto.items) || [], {
    kind: "auto",
    containerId: "blocked-ips-auto",
    emptyText: "当前没有自动封禁的 IP",
  });
  renderBlockedPaginationSection(blockedIps.manual || {}, {
    kind: "manual",
    summaryId: "blocked-pagination-summary-manual",
    containerId: "blocked-pagination-manual",
    emptySummary: "暂无手动封禁",
  });
  renderBlockedPaginationSection(blockedIps.auto || {}, {
    kind: "auto",
    summaryId: "blocked-pagination-summary-auto",
    containerId: "blocked-pagination-auto",
    emptySummary: "暂无自动封禁",
  });
}

async function refreshLogsPage() {
  const [runtime, overview, logs] = await Promise.all([
    fetchJson("/api/runtime"),
    fetchJson("/api/overview"),
    fetchJson(buildLogsUrl()),
  ]);

  if (logs.total_pages && currentLogsPage > logs.total_pages) {
    currentLogsPage = logs.total_pages;
    return refreshLogsPage();
  }

  setText("runtime-user", runtime.username || "admin");
  fillCommonMetrics(overview);
  renderLogScopeTabs(overview);
  renderHandledViewTabs(overview);
  renderAlertViewTabs(overview);
  renderLogs(logs.items || []);
  renderLogsPagination(logs);
}

function setupLoginForm() {
  const form = document.getElementById("login-form");
  if (!form) {
    return;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const errorNode = document.getElementById("login-error");
    errorNode.hidden = true;

    const formData = new FormData(form);
    try {
      await fetchJson("/api/login", {
        method: "POST",
        body: JSON.stringify({
          username: formData.get("username"),
          password: formData.get("password"),
        }),
      });
      window.location.href = "/dashboard";
    } catch (error) {
      errorNode.textContent = error.message;
      errorNode.hidden = false;
    }
  });
}

function setupAuthenticatedPage() {
  const logoutButton = document.getElementById("logout-button");
  if (logoutButton) {
    logoutButton.addEventListener("click", async () => {
      await fetchJson("/api/logout", { method: "POST" });
      window.location.href = "/login";
    });
  }
}

function setupDashboard() {
  setupAuthenticatedPage();
  const safeRefresh = createRefreshGuard(refreshDashboard);

  safeRefresh().catch((error) => {
    window.alert(`加载仪表盘数据失败：${error.message}`);
  });

  window.setInterval(() => {
    safeRefresh().catch(() => {});
  }, 20000);
}

function setupBlockPage() {
  setupAuthenticatedPage();
  currentManualBlockedPage = 1;
  currentAutoBlockedPage = 1;
  const safeRefresh = createRefreshGuard(refreshBlockPage);

  const blockForm = document.getElementById("block-form");
  if (blockForm) {
    blockForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const ip = document.getElementById("block-ip").value.trim();
      const reason = document.getElementById("block-reason").value.trim();
      if (!ip) {
        return;
      }
      await blockIp(ip, reason || "手动封禁");
      blockForm.reset();
    });
  }

  safeRefresh().catch((error) => {
    window.alert(`加载 IP 封禁数据失败：${error.message}`);
  });

  window.setInterval(() => {
    safeRefresh().catch(() => {});
  }, 20000);
}

function setupLogsPage() {
  setupAuthenticatedPage();
  currentLogsPage = 1;
  currentLogsScope = "all";
  currentAlertView = "all";
  currentHandledView = "all";
  const safeRefresh = createRefreshGuard(refreshLogsPage);

  document.querySelectorAll(".log-scope-tab").forEach((button) => {
    button.addEventListener("click", async () => {
      const view = button.getAttribute("data-log-scope") || "all";
      if (view === currentLogsScope) {
        return;
      }
      selectedLogEntries.clear();
      currentLogsPage = 1;
      applyLogScope(view);
      await safeRefresh();
    });
  });

  const filterForm = document.getElementById("log-filter-form");
  if (filterForm) {
    filterForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      selectedLogEntries.clear();
      currentLogsPage = 1;
      await safeRefresh();
    });
  }

  const alertViewToggle = document.getElementById("alert-view-toggle");
  const alertViewCollapsible = document.getElementById("alert-view-collapsible");
  let isAlertViewExpanded = false;

  if (alertViewToggle && alertViewCollapsible) {
    alertViewToggle.addEventListener("click", () => {
      isAlertViewExpanded = !isAlertViewExpanded;
      alertViewToggle.classList.toggle("expanded", isAlertViewExpanded);
      alertViewCollapsible.classList.toggle("expanded", isAlertViewExpanded);
    });
  }

  document.querySelectorAll(".alert-view-tab").forEach((button) => {
    button.addEventListener("click", async () => {
      const view = button.getAttribute("data-alert-view") || "all";
      if (view === currentAlertView) {
        return;
      }
      selectedLogEntries.clear();
      currentLogsPage = 1;
      applyAlertView(view);
      await safeRefresh();
    });
  });

  document.querySelectorAll(".alert-process-tab").forEach((button) => {
    button.addEventListener("click", async () => {
      const view = button.getAttribute("data-handled-view") || "all";
      if (view === currentHandledView) {
        return;
      }
      selectedLogEntries.clear();
      currentLogsPage = 1;
      applyHandledView(view);
      await safeRefresh();
    });
  });

  const statusSelect = document.getElementById("log-alert-status");
  if (statusSelect) {
    statusSelect.addEventListener("change", async () => {
      const value = normalizeAlertStatus(statusSelect.value || "");
      currentAlertView = ALERT_STATUS_KEYS.includes(value) ? value : "all";
      selectedLogEntries.clear();
      currentLogsPage = 1;
      await safeRefresh();
    });
  }

  const selectAll = document.getElementById("logs-select-all");
  if (selectAll) {
    selectAll.addEventListener("change", () => {
      document.querySelectorAll(".log-select-checkbox").forEach((checkbox) => {
        const logId = checkbox.getAttribute("data-log-id");
        const ip = checkbox.getAttribute("data-ip") || "";
        checkbox.checked = selectAll.checked;
        if (!logId) {
          return;
        }
        if (selectAll.checked) {
          selectedLogEntries.set(logId, ip);
        } else {
          selectedLogEntries.delete(logId);
        }
      });
      const pageItems = Array.from(document.querySelectorAll(".log-select-checkbox")).map((checkbox) => ({
        id: checkbox.getAttribute("data-log-id") || "",
      }));
      syncLogsSelectionUi(pageItems);
    });
  }

  const bulkBlockButton = document.getElementById("bulk-block-button");
  if (bulkBlockButton) {
    bulkBlockButton.addEventListener("click", async () => {
      await bulkBlockSelectedLogs();
    });
  }

  const bulkDispositionButton = document.getElementById("bulk-disposition-button");
  if (bulkDispositionButton) {
    bulkDispositionButton.addEventListener("click", async () => {
      await bulkDispositionSelectedLogs();
    });
  }

  const detailClose = document.getElementById("log-detail-close");
  if (detailClose) {
    detailClose.addEventListener("click", closeLogDetail);
  }
  const detailBackdrop = document.getElementById("log-detail-backdrop");
  if (detailBackdrop) {
    detailBackdrop.addEventListener("click", closeLogDetail);
  }

  const aiAnalysisButton = document.getElementById("ai-analysis-button");
  if (aiAnalysisButton) {
    aiAnalysisButton.addEventListener("click", () => {
      window.location.href = "/log-analysis";
    });
  }

  safeRefresh().catch((error) => {
    window.alert(`加载日志数据失败：${error.message}`);
  });

  window.setInterval(() => {
    safeRefresh().catch(() => {});
  }, 20000);
}

document.addEventListener("DOMContentLoaded", () => {
  setupLoginForm();
  setupAutoRefreshWidget();

  if (document.body.dataset.page === "dashboard") {
    setupDashboard();
  }

  if (document.body.dataset.page === "logs") {
    setupLogsPage();
  }

  if (document.body.dataset.page === "block") {
    setupBlockPage();
  }
});
