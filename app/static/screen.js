import { createThreatGlobe } from "/static/screen-earth.js?v=20260421globe01";

const SCREEN_REFRESH_VISIBLE_MS = 6000;
const SCREEN_REFRESH_HIDDEN_MS = 25000;
const DISPOSITION_KEYS = ["real_attack", "customer_business", "pending_business", "reported_alert", "whitelist_traffic"];

const SEVERITY_META = {
  critical: { label: "严重", color: "#ff5a5f" },
  high: { label: "高危", color: "#ff8a3d" },
  medium: { label: "中危", color: "#f59e0b" },
  low: { label: "低危", color: "#facc15" },
};

const ATTACK_TYPE_LABELS = {
  manual_block: "手动封禁",
  sql_injection: "SQL 注入",
  xss: "跨站脚本",
  ssti: "模板注入",
  ssrf: "服务端请求伪造",
  xxe_injection: "XXE 实体注入",
  nosql_injection: "NoSQL 注入",
  ldap_injection: "LDAP 注入",
  file_inclusion: "文件包含",
  path_traversal: "目录穿越",
  command_injection: "命令注入",
  deserialization_probe: "反序列化探测",
  scanner_probe: "扫描探测",
  sensitive_probe: "敏感路径探测",
  brute_force: "暴力破解",
  webshell_upload: "WebShell 上传",
  cve_exploit_attempt: "CVE 漏洞利用",
  cc_attack: "CC 攻击",
};

const state = {
  destroyed: false,
  serverTimeOffsetMs: 0,
  lastUpdatedAt: "",
  failStreak: 0,
  signatures: Object.create(null),
  clockId: 0,
  recentAlertTickerId: 0,
  recentAlertIndex: 0,
  recentAlertActiveIndex: 0,
  recentAlertItems: [],
  domWriteFrameId: 0,
  pendingTextWrites: new Map(),
  pendingHtmlWrites: new Map(),
  afterDomFlushCallbacks: [],
};

const refs = {
  date: document.getElementById("screen-date"),
  time: document.getElementById("screen-time"),
  runtime: document.querySelector(".threat-screen__runtime"),
  targetName: document.getElementById("screen-target-name"),
  targetLabel: document.getElementById("screen-target-label"),
  targetFocus: document.getElementById("screen-target-focus"),
  totalAlerts: document.getElementById("screen-total-alerts"),
  totalIps: document.getElementById("screen-total-ips"),
  blockedRequests: document.getElementById("screen-blocked-requests"),
  highRisk: document.getElementById("screen-high-risk"),
  blockedIps: document.getElementById("screen-blocked-ips"),
  victimTop5: document.getElementById("screen-victim-top5"),
  severityTotal: document.getElementById("screen-severity-total"),
  severityLegend: document.getElementById("screen-severity-legend"),
  severityDonut: document.getElementById("screen-severity-donut"),
  attackIpTop5: document.getElementById("screen-attack-ip-top5"),
  attackTypeTop5: document.getElementById("screen-type-top5"),
  originTop5: document.getElementById("screen-origin-top5"),
  agentStatus: document.getElementById("threat-agent-status-panel"),
  recentAlerts: document.getElementById("screen-recent-alerts"),
  trendChart: document.getElementById("screen-trend-chart"),
  globeStage: document.getElementById("threat-globe-stage"),
  globeLabels: document.getElementById("threat-globe-labels"),
  logoutButton: document.getElementById("logout-button"),
};

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function formatNumber(value) {
  const number = Number(value || 0);
  return Number.isFinite(number) ? number.toLocaleString("zh-CN") : "0";
}

function formatAttackType(value) {
  const key = String(value || "").trim();
  return ATTACK_TYPE_LABELS[key] || key || "异常流量";
}

function formatTimeOnly(value) {
  if (!value) {
    return "--:--:--";
  }
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "--:--:--";
  }
  return date.toLocaleTimeString("zh-CN", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatDateLabel(value) {
  if (!value) {
    return "--";
  }
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "--";
  }
  return date.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" });
}

function formatDateTimeShort(value) {
  if (!value) {
    return "--";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "--";
  }
  return date.toLocaleString("zh-CN", {
    hour12: false,
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function joinSignature(parts) {
  return safeArray(parts)
    .map((part) => String(part == null ? "" : part))
    .join("\u001f");
}

// Performance-only signatures: compare stable visible fields, not whole payload objects.
function buildRankSignature(items, fields = ["name", "ip", "count", "updated_at", "created_at"], limit = 8) {
  const list = safeArray(items);
  return joinSignature([
    list.length,
    ...list.slice(0, limit).map((item) => joinSignature(fields.map((field) => item?.[field]))),
  ]);
}

function buildSeveritySignature(items) {
  return buildRankSignature(items, ["key", "name", "count"], 8);
}

function buildAlertSignature(items) {
  const list = safeArray(items);
  return joinSignature([
    list.length,
    ...list
      .slice(0, 12)
      .map((item) =>
        joinSignature([
          item?.id,
          item?.created_at,
          item?.handled_status,
          item?.alert_status,
          item?.disposition,
          item?.severity,
          item?.attack_type,
        ])
      ),
  ]);
}

function normalizeSeverityKey(value) {
  const key = String(value || "").trim().toLowerCase();
  return ["critical", "high", "medium", "low"].includes(key) ? key : "medium";
}

function isHighRiskSeverityKey(value) {
  const key = normalizeSeverityKey(value);
  return key === "critical" || key === "high";
}

function buildRecentAlertClasses(item, index) {
  const severityKey = normalizeSeverityKey(item?.severity);
  const alertStatus = String(item?.alert_status || "").trim().toLowerCase();
  const disposition = String(item?.disposition || "").trim().toLowerCase();
  const classes = ["threat-alert-item"];

  if (isHighRiskSeverityKey(severityKey)) {
    classes.push(`threat-alert-item--${severityKey}`, `severity-${severityKey}`);
  } else if (alertStatus === "whitelist_traffic" || disposition === "whitelist_traffic") {
    classes.push("threat-alert-item--whitelist", "whitelist-text");
  } else {
    classes.push(`threat-alert-item--${severityKey}`);
  }

  if (index === 0) {
    classes.push("threat-alert-item--latest", "threat-alert-item--active");
  }
  return classes;
}

function buildTrendSignature(items) {
  const list = safeArray(items);
  return joinSignature([
    list.length,
    ...list.map((item) => joinSignature([item?.label, item?.total, item?.blocked, item?.high])),
  ]);
}

function flowSeverityWeight(flow) {
  switch (String(flow?.severity || "").trim().toLowerCase()) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

function flowSignatureKey(flow) {
  return joinSignature([
    flow?.key || flow?.event_id,
    flow?.source_ip,
    Number(flow?.source_lng || 0).toFixed(3),
    Number(flow?.source_lat || 0).toFixed(3),
    flow?.source_name,
    flow?.source_bucket,
    flow?.source_province,
    flow?.display_country,
    flow?.display_region,
    flow?.display_city,
    flow?.display_label,
    flow?.geo_resolved,
    flow?.geo_source,
    flow?.display_geo_mode,
    flow?.display_coord_source,
    flow?.pseudo_tile,
  ]);
}

function flowSignatureRow(flow) {
  return joinSignature([
    flow?.key || flow?.event_id,
    flow?.source_ip,
    flow?.timestamp,
    flow?.source_name,
    flow?.source_bucket,
    flow?.source_label,
    flow?.source_country,
    flow?.source_region,
    flow?.source_city,
    flow?.source_province,
    flow?.display_country,
    flow?.display_region,
    flow?.display_city,
    flow?.display_label,
    Number(flow?.source_lng || 0).toFixed(3),
    Number(flow?.source_lat || 0).toFixed(3),
    flow?.severity,
    flow?.count,
    flow?.critical_count,
    flow?.high_count,
    flow?.blocked_count,
    flow?.geo_resolved,
    flow?.geo_source,
    flow?.display_geo_mode,
    flow?.display_coord_source,
    flow?.pseudo_tile,
  ]);
}

function buildGlobeSignature(payload) {
  const globe = payload?.globe || {};
  const target = payload?.target || globe.target || {};
  const rawFlows = safeArray(globe.raw_flows || payload?.raw_flows)
    .slice()
    .sort((left, right) => {
      const severityCompare = flowSeverityWeight(right) - flowSeverityWeight(left);
      if (severityCompare !== 0) {
        return severityCompare;
      }
      const timeCompare = String(right?.timestamp || "").localeCompare(String(left?.timestamp || ""));
      if (timeCompare !== 0) {
        return timeCompare;
      }
      return Number(right?.event_id || 0) - Number(left?.event_id || 0);
    })
    .slice(0, 80);
  const usedKeys = new Set(rawFlows.map((flow) => flowSignatureKey(flow)));
  const representativeFlows = safeArray(
    globe.representative_flows || globe.aggregated_flows || payload?.representative_flows || payload?.aggregated_flows
  )
    .slice()
    .sort((left, right) => {
      const severityCompare = flowSeverityWeight(right) - flowSeverityWeight(left);
      if (severityCompare !== 0) {
        return severityCompare;
      }
      const highCompare = Number(right?.high_count || 0) - Number(left?.high_count || 0);
      if (highCompare !== 0) {
        return highCompare;
      }
      return Number(right?.count || 0) - Number(left?.count || 0);
    })
    .filter((flow) => !usedKeys.has(flowSignatureKey(flow)))
    .slice(0, 32);

  return joinSignature([
    Number(target.lng || 0).toFixed(3),
    Number(target.lat || 0).toFixed(3),
    target.name,
    target.label,
    rawFlows.length,
    representativeFlows.length,
    ...rawFlows.map(flowSignatureRow),
    ...representativeFlows.map(flowSignatureRow),
  ]);
}

async function fetchJson(url, signal) {
  const response = await fetch(url, {
    method: "GET",
    headers: { Accept: "application/json" },
    cache: "no-store",
    signal,
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

function setText(element, value) {
  if (!element) {
    return;
  }
  const nextValue = String(value == null ? "--" : value);
  state.pendingTextWrites.set(element, nextValue);
  scheduleDomWriteFlush();
}

// Batch DOM writes from one snapshot into a single animation frame.
function setHtml(element, html, signatureKey, signatureValue) {
  if (!element) {
    return;
  }
  if (state.signatures[signatureKey] === signatureValue) {
    return;
  }
  state.signatures[signatureKey] = signatureValue;
  state.pendingHtmlWrites.set(element, html);
  scheduleDomWriteFlush();
}

function scheduleDomWriteFlush() {
  if (state.domWriteFrameId) {
    return;
  }
  state.domWriteFrameId = window.requestAnimationFrame(flushDomWrites);
}

function afterDomFlush(callback) {
  state.afterDomFlushCallbacks.push(callback);
  scheduleDomWriteFlush();
}

function flushDomWrites() {
  state.domWriteFrameId = 0;
  for (const [element, html] of state.pendingHtmlWrites.entries()) {
    element.innerHTML = html;
  }
  state.pendingHtmlWrites.clear();
  for (const [element, value] of state.pendingTextWrites.entries()) {
    if (element.textContent !== value) {
      element.textContent = value;
    }
  }
  state.pendingTextWrites.clear();

  const callbacks = state.afterDomFlushCallbacks.splice(0);
  for (const callback of callbacks) {
    callback();
  }
}

function isPageVisible() {
  return !document.hidden;
}

function refreshInterval() {
  return isPageVisible() ? SCREEN_REFRESH_VISIBLE_MS : SCREEN_REFRESH_HIDDEN_MS;
}

function normalizeDispositionCounts(input) {
  const dispositionCounts = Object.create(null);
  for (const key of DISPOSITION_KEYS) {
    dispositionCounts[key] = Number(input?.[key] || 0);
  }
  return dispositionCounts;
}

function ensureConsistentDisposition(scope, totalHandled, rawDispositionCounts) {
  const dispositionCounts = normalizeDispositionCounts(rawDispositionCounts);
  const correctedTotal = DISPOSITION_KEYS.reduce((sum, key) => sum + Number(dispositionCounts[key] || 0), 0);
  const declaredTotal = Number(totalHandled || 0);
  if (declaredTotal !== correctedTotal) {
    console.error(`[screen] disposition total mismatch in ${scope}`, {
      declaredTotal,
      correctedTotal,
      dispositionCounts,
    });
  }
  return { dispositionCounts, totalHandled: correctedTotal };
}

function normalizeScreenPayload(payload) {
  const summary = payload?.summary || {};
  const rankings = payload?.rankings || {};
  const alerts = payload?.alerts || {};
  const timeline = payload?.timeline || {};
  const agents = payload?.agents || {};
  const globe = payload?.globe || {};
  const consistency = ensureConsistentDisposition(
    "screen-snapshot",
    summary.total_handled ?? payload?.total_handled,
    summary.disposition_counts ?? payload?.disposition_counts
  );

  return {
    serverTime: String(payload?.server_time || ""),
    updatedAt: String(payload?.updated_at || ""),
    stale: Boolean(payload?.stale),
    summary: {
      ...summary,
      total_handled: consistency.totalHandled,
      total_alerts: consistency.totalHandled,
      disposition_counts: consistency.dispositionCounts,
      inferred_disposition_counts: normalizeDispositionCounts(
        summary.inferred_disposition_counts || payload?.inferred_disposition_counts
      ),
      auto_whitelist_count: Number(summary.auto_whitelist_count || payload?.diagnostics?.auto_whitelist_count || 0),
    },
    hero: payload?.hero || {},
    target: payload?.target || globe.target || {},
    diagnostics: payload?.diagnostics || summary?.diagnostics || {},
    timeline: safeArray(timeline.items || payload?.timeline_24h),
    alerts: safeArray(alerts.items || payload?.recent_alerts),
    severityDistribution: safeArray(rankings.severity_distribution || payload?.severity_distribution),
    victims: safeArray(rankings.victims || payload?.victim_targets_top5),
    attackIps: safeArray(rankings.attack_ips || payload?.attack_ip_top5),
    attackTypes: safeArray(rankings.attack_types || payload?.top_attack_types),
    origins: safeArray(rankings.origins || payload?.attack_source_top5),
    agents: safeArray(agents.items || payload?.agent_status),
    globe: {
      target: payload?.target || globe.target || {},
      raw_flows: safeArray(globe.raw_flows || payload?.raw_flows),
      representative_flows: safeArray(
        globe.representative_flows || globe.aggregated_flows || payload?.representative_flows || payload?.aggregated_flows
      ),
      aggregated_flows: safeArray(globe.aggregated_flows || payload?.aggregated_flows),
      total_raw_flow_count: Number(globe.total_raw_flow_count || payload?.total_raw_flow_count || 0),
      returned_raw_flow_count: Number(globe.returned_raw_flow_count || payload?.returned_raw_flow_count || 0),
      total_aggregated_flow_count: Number(globe.total_aggregated_flow_count || payload?.total_aggregated_flow_count || 0),
      returned_aggregated_flow_count: Number(globe.returned_aggregated_flow_count || payload?.returned_aggregated_flow_count || 0),
    },
  };
}

function buildEmptyState(message) {
  return `<div class="empty-state">${escapeHtml(message)}</div>`;
}

function buildBarWidth(count, maxValue) {
  if (!maxValue) {
    return "0%";
  }
  const width = Math.max(8, Math.min(100, (Number(count || 0) / maxValue) * 100));
  return `${width.toFixed(1)}%`;
}

function renderRankList(element, items, options = {}) {
  const list = safeArray(items);
  const signature = buildRankSignature(list, options.signatureFields);
  if (state.signatures[options.signatureKey] === signature) {
    return;
  }

  if (!list.length) {
    setHtml(element, buildEmptyState(options.emptyMessage || "暂无数据"), options.signatureKey, signature);
    return;
  }

  const maxValue = Math.max(...list.map((item) => Number(item.count || 0)), 1);
  const html = list
    .map((item, index) => {
      const label = escapeHtml(options.labelFormatter ? options.labelFormatter(item) : item.name || item.ip || "--");
      const sub = escapeHtml(options.subFormatter ? options.subFormatter(item) : "");
      return `
        <article class="threat-rank-item">
          <div class="threat-rank-item__top">
            <div>
              <div class="threat-rank-item__label">${index + 1}. ${label}</div>
              <div class="threat-rank-item__sub">${sub || "&nbsp;"}</div>
            </div>
            <strong class="threat-rank-item__count">${formatNumber(item.count || 0)}</strong>
          </div>
          <div class="threat-rank-item__bar"><span style="width:${buildBarWidth(item.count, maxValue)}"></span></div>
        </article>
      `;
    })
    .join("");

  setHtml(element, html, options.signatureKey, signature);
}

function renderSeverity(items) {
  const list = safeArray(items);
  const signature = buildSeveritySignature(list);
  if (state.signatures.severity === signature) {
    return;
  }

  const total = list.reduce((sum, item) => sum + Number(item.count || 0), 0);
  setText(refs.severityTotal, formatNumber(total));

  const legendHtml = list.length
    ? list
        .map((item) => {
          const key = String(item.key || "").trim().toLowerCase();
          const meta = SEVERITY_META[key] || SEVERITY_META.medium;
          return `
            <div class="threat-severity__item">
              <span class="threat-severity__name">
                <i class="threat-severity__swatch threat-severity__swatch--${escapeHtml(key || "medium")}"></i>
                ${escapeHtml(item.name || meta.label)}
              </span>
              <strong>${formatNumber(item.count || 0)}</strong>
            </div>
          `;
        })
        .join("")
    : buildEmptyState("暂无风险分布");

  const donutStops = list
    .reduce(
      (accumulator, item) => {
        const count = Number(item.count || 0);
        if (!total || count <= 0) {
          return accumulator;
        }
        const key = String(item.key || "").trim().toLowerCase();
        const meta = SEVERITY_META[key] || SEVERITY_META.medium;
        const start = accumulator.offset;
        const end = start + (count / total) * 100;
        accumulator.parts.push(`${meta.color} ${start.toFixed(2)}% ${end.toFixed(2)}%`);
        accumulator.offset = end;
        return accumulator;
      },
      { offset: 0, parts: [] }
    )
    .parts.join(", ");

  if (refs.severityDonut) {
    refs.severityDonut.style.background = donutStops
      ? `conic-gradient(${donutStops})`
      : "conic-gradient(rgba(255,138,61,0.14) 0 100%)";
  }
  setHtml(refs.severityLegend, legendHtml, "severity", signature);
}

function renderRecentAlerts(items) {
  const list = safeArray(items);
  const signature = buildAlertSignature(list);
  if (state.signatures.alerts === signature) {
    return;
  }

  if (!list.length) {
    clearInterval(state.recentAlertTickerId);
    state.recentAlertItems = [];
    state.recentAlertIndex = 0;
    state.recentAlertActiveIndex = 0;
    setHtml(refs.recentAlerts, buildEmptyState("暂无告警流"), "alerts", signature);
    return;
  }

  state.recentAlertIndex = 0;
  state.recentAlertActiveIndex = 0;
  const html = list
    .map((item, index) => {
      const handled = String(item.handled_status || "unhandled").toLowerCase() === "handled";
      const itemClasses = buildRecentAlertClasses(item, index).map(escapeHtml).join(" ");
      return `
        <article class="${itemClasses}">
          <div class="threat-alert-item__top">
            <div class="threat-alert-item__time-wrap">
              <span class="threat-alert-item__dot"></span>
              <span class="threat-alert-item__time">${escapeHtml(formatDateTimeShort(item.created_at))}</span>
            </div>
            <div class="threat-alert-item__status-cluster">
              <span class="threat-alert-item__state threat-alert-item__state--${handled ? "handled" : "pending"}">
                ${escapeHtml(handled ? item.handled_text || "已处理" : item.handled_text || "待处理")}
              </span>
            </div>
          </div>
          <div class="threat-alert-item__title-row">
            <div class="threat-alert-item__title">${escapeHtml(item.rule_text || item.attack_label || "异常流量")}</div>
          </div>
          <div class="threat-alert-item__flow">
            <span class="threat-alert-item__ip">${escapeHtml(item.client_ip || "--")}</span>
            <span class="threat-alert-item__separator">→</span>
            <span class="threat-alert-item__location">${escapeHtml(item.location || "未知来源")}</span>
          </div>
          <div class="threat-alert-item__meta">
            <span class="threat-alert-item__tag">${escapeHtml(formatAttackType(item.attack_type || item.attack_label))}</span>
            <span>${escapeHtml(item.alert_status_text || "待研判")}</span>
            <span>${escapeHtml(item.action === "blocked" ? "已拦截" : "已放行")}</span>
          </div>
        </article>
      `;
    })
    .join("");

  setHtml(refs.recentAlerts, html, "alerts", signature);
  afterDomFlush(() => {
    state.recentAlertItems = Array.from(refs.recentAlerts?.querySelectorAll(".threat-alert-item") || []);
    restartAlertTicker();
  });
}

function renderAgentStatus(items) {
  const list = safeArray(items);
  const signature = buildRankSignature(list, ["name", "status", "status_text", "description", "last_seen"], 12);
  if (state.signatures.agents === signature) {
    return;
  }

  const html = list.length
    ? list
        .map((item) => {
          const online = String(item.status || "").trim() === "online";
          return `
            <article class="threat-agent-card threat-agent-card--${online ? "online" : "offline"}">
              <div class="threat-agent-card__header">
                <div class="threat-agent-card__title">${escapeHtml(item.name || "Agent")}</div>
                <div class="threat-agent-card__state">
                  <span class="threat-agent-card__lamp"></span>
                  <span class="threat-agent-card__status-text">${escapeHtml(item.status_text || (online ? "在线" : "离线"))}</span>
                </div>
              </div>
              <div class="threat-agent-card__desc">${escapeHtml(item.description || "日志分析链路")}</div>
              <div class="threat-agent-card__heartbeat">最近心跳：${escapeHtml(formatDateTimeShort(item.last_seen))}</div>
            </article>
          `;
        })
        .join("")
    : buildEmptyState("暂无 Agent 状态");

  setHtml(refs.agentStatus, html, "agents", signature);
}

function createTrendChartManager(svgElement) {
  return {
    render(items) {
      if (!svgElement) {
        return;
      }
      const list = safeArray(items);
      const signature = buildTrendSignature(list);
      if (state.signatures.trend === signature) {
        return;
      }
      if (!list.length) {
        setHtml(svgElement, "", "trend", signature);
        return;
      }

      const width = 960;
      const height = 240;
      const paddingX = 28;
      const paddingTop = 18;
      const paddingBottom = 28;
      const maxValue = Math.max(
        ...list.map((item) => Math.max(Number(item.total || 0), Number(item.blocked || 0), Number(item.high || 0))),
        1
      );
      const xStep = list.length > 1 ? (width - paddingX * 2) / (list.length - 1) : 0;
      const yFor = (value) => height - paddingBottom - (Number(value || 0) / maxValue) * (height - paddingTop - paddingBottom);
      const pointsFor = (field) => list.map((item, index) => `${paddingX + xStep * index},${yFor(item[field])}`).join(" ");
      const totalPoints = pointsFor("total");
      const blockedPoints = pointsFor("blocked");
      const highPoints = pointsFor("high");
      const areaPath = `${totalPoints
        .split(" ")
        .map((point, index) => `${index === 0 ? "M" : "L"} ${point}`)
        .join(" ")} L ${paddingX + xStep * (list.length - 1)} ${height - paddingBottom} L ${paddingX} ${height - paddingBottom} Z`;
      const labels = list
        .map((item, index) => {
          const x = paddingX + xStep * index;
          return `<text x="${x}" y="${height - 6}" text-anchor="middle" fill="rgba(191,219,254,0.55)" font-size="11">${escapeHtml(
            item.label || "--"
          )}</text>`;
        })
        .join("");

      const svgHtml = `
        <defs>
          <linearGradient id="trendAreaFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.22"></stop>
            <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.02"></stop>
          </linearGradient>
        </defs>
        <path d="${areaPath}" fill="url(#trendAreaFill)"></path>
        <polyline points="${totalPoints}" fill="none" stroke="#38bdf8" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"></polyline>
        <polyline points="${blockedPoints}" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></polyline>
        <polyline points="${highPoints}" fill="none" stroke="#ff6b6b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></polyline>
        ${labels}
      `;

      setHtml(svgElement, svgHtml, "trend", signature);
    },
  };
}

function updateClockDisplay() {
  const now = new Date(Date.now() + state.serverTimeOffsetMs);
  setText(refs.date, formatDateLabel(now));
  setText(refs.time, formatTimeOnly(now));
}

function applyServerTime(serverTime) {
  if (!serverTime) {
    return;
  }
  const parsed = new Date(serverTime).getTime();
  if (Number.isNaN(parsed)) {
    return;
  }
  state.serverTimeOffsetMs = parsed - Date.now();
  updateClockDisplay();
}

function runtimeText() {
  if (state.failStreak >= 3) {
    return state.lastUpdatedAt ? `最后更新时间：${formatDateTimeShort(state.lastUpdatedAt)} · 数据降级显示` : "数据连接异常";
  }
  if (state.failStreak > 0) {
    return state.lastUpdatedAt ? `最后更新时间：${formatDateTimeShort(state.lastUpdatedAt)} · 正在重试` : "正在建立数据连接...";
  }
  return state.lastUpdatedAt ? `最后更新时间：${formatDateTimeShort(state.lastUpdatedAt)}` : "正在建立数据连接...";
}

function updateRuntimeText() {
  setText(refs.runtime, runtimeText());
}

function restartAlertTicker() {
  clearInterval(state.recentAlertTickerId);
  const items = state.recentAlertItems;
  if (!items || items.length <= 1 || document.hidden) {
    return;
  }
  state.recentAlertTickerId = window.setInterval(() => {
    const alertItems = state.recentAlertItems;
    if (!alertItems || alertItems.length <= 1 || document.hidden) {
      return;
    }
    const nextIndex = state.recentAlertIndex % alertItems.length;
    if (nextIndex !== state.recentAlertActiveIndex) {
      alertItems[state.recentAlertActiveIndex]?.classList.remove("threat-alert-item--active");
      alertItems[nextIndex]?.classList.add("threat-alert-item--active");
      state.recentAlertActiveIndex = nextIndex;
    }
    state.recentAlertIndex = (state.recentAlertIndex + 1) % alertItems.length;
  }, 2600);
}

function renderSummarySnapshot(payload, trendChart) {
  const { summary, severityDistribution, alerts, timeline } = payload;
  setText(refs.totalAlerts, formatNumber(summary.total_handled || 0));
  setText(refs.totalIps, formatNumber(summary.unique_ips || 0));
  setText(refs.blockedRequests, formatNumber(summary.blocked_requests || 0));
  setText(refs.highRisk, formatNumber(summary.high_risk_alerts || 0));
  setText(refs.blockedIps, formatNumber(summary.blocked_ip_count || 0));
  renderSeverity(severityDistribution);
  renderRecentAlerts(alerts);
  trendChart.render(timeline);
}

function renderDetailSnapshot(payload, globe) {
  const { hero, target, victims, attackIps, attackTypes, origins, agents } = payload;

  setText(refs.targetName, target.name || hero.name || "业务主站");
  setText(refs.targetLabel, target.label || hero.label || "香港 · 业务区");
  const focusText = target.focus_summary || hero.summary || "";
  if (focusText) {
    setText(refs.targetFocus, focusText);
  }

  renderRankList(refs.victimTop5, victims, {
    signatureKey: "victims",
    emptyMessage: "暂无受害入口数据",
    labelFormatter: (item) => item.name || "/",
    subFormatter: (item) => `命中 ${formatNumber(item.count || 0)} 次`,
  });

  renderRankList(refs.attackIpTop5, attackIps, {
    signatureKey: "attackIps",
    emptyMessage: "暂无攻击源数据",
    labelFormatter: (item) => item.ip || "--",
    subFormatter: (item) => item.geo_label || item.label || "未知来源",
  });

  renderRankList(refs.attackTypeTop5, attackTypes, {
    signatureKey: "attackTypes",
    emptyMessage: "暂无攻击类型数据",
    labelFormatter: (item) => formatAttackType(item.name),
    subFormatter: (item) => `命中 ${formatNumber(item.count || 0)} 次`,
  });

  renderRankList(refs.originTop5, origins, {
    signatureKey: "origins",
    emptyMessage: "暂无来源聚合数据",
    labelFormatter: (item) => item.name || "未知来源",
    subFormatter: (item) => `聚合 ${formatNumber(item.count || 0)} 次`,
  });

  renderAgentStatus(agents);

  const globeSignature = buildGlobeSignature(payload);
  if (state.signatures.globe !== globeSignature) {
    globe.setData(payload);
    state.signatures.globe = globeSignature;
  }
}

function createPoller(options) {
  let timerId = 0;
  let controller = null;
  let inFlight = false;

  const clearTimer = () => {
    if (timerId) {
      clearTimeout(timerId);
      timerId = 0;
    }
  };

  const schedule = (delay) => {
    clearTimer();
    if (state.destroyed) {
      return;
    }
    timerId = window.setTimeout(run, Math.max(0, delay));
  };

  const run = async () => {
    if (state.destroyed || inFlight) {
      return;
    }
    inFlight = true;
    controller = new AbortController();
    try {
      const payload = await fetchJson(options.url, controller.signal);
      options.onSuccess(payload);
    } catch (error) {
      if (error?.name !== "AbortError") {
        options.onError(error);
      }
    } finally {
      inFlight = false;
      controller = null;
      schedule(options.interval());
    }
  };

  return {
    start(immediate = true) {
      schedule(immediate ? 0 : options.interval());
    },
    refreshSoon(delay = 0) {
      schedule(delay);
    },
    stop() {
      clearTimer();
      controller?.abort();
      controller = null;
      inFlight = false;
    },
  };
}

function destroyAll(globe, poller) {
  state.destroyed = true;
  poller.stop();
  clearInterval(state.clockId);
  clearInterval(state.recentAlertTickerId);
  if (state.domWriteFrameId) {
    cancelAnimationFrame(state.domWriteFrameId);
    state.domWriteFrameId = 0;
  }
  state.pendingTextWrites.clear();
  state.pendingHtmlWrites.clear();
  state.afterDomFlushCallbacks = [];
  state.recentAlertItems = [];
  globe?.destroy?.();
}

async function setupLogout() {
  if (!refs.logoutButton) {
    return;
  }
  refs.logoutButton.addEventListener("click", async () => {
    try {
      await fetch("/api/logout", { method: "POST", headers: { Accept: "application/json" } });
    } finally {
      window.location.href = "/login";
    }
  });
}

async function bootstrap() {
  const trendChart = createTrendChartManager(refs.trendChart);
  const globe = await createThreatGlobe(refs.globeStage, refs.globeLabels, { performanceMode: "auto" });

  const poller = createPoller({
    url: "/api/screen",
    interval: refreshInterval,
    onSuccess(payload) {
      const data = normalizeScreenPayload(payload);
      applyServerTime(data.serverTime);
      state.lastUpdatedAt = data.updatedAt || state.lastUpdatedAt;
      state.failStreak = data.stale ? 3 : 0;
      renderSummarySnapshot(data, trendChart);
      renderDetailSnapshot(data, globe);
      updateRuntimeText();
    },
    onError(error) {
      state.failStreak += 1;
      console.error("[screen] snapshot refresh failed", error);
      updateRuntimeText();
    },
  });

  state.clockId = window.setInterval(updateClockDisplay, 1000);
  updateClockDisplay();
  updateRuntimeText();
  await setupLogout();

  const handleVisibilityChange = () => {
    globe.setActive(!document.hidden);
    restartAlertTicker();
    poller.refreshSoon(document.hidden ? refreshInterval() : 0);
  };

  document.addEventListener("visibilitychange", handleVisibilityChange);
  window.addEventListener("pagehide", () => destroyAll(globe, poller), { once: true });
  window.addEventListener("beforeunload", () => destroyAll(globe, poller), { once: true });

  poller.start(true);
}

bootstrap().catch((error) => {
  console.error("[screen] bootstrap failed", error);
  setText(refs.runtime, "大屏初始化失败");
});
