const GLOBE_VENDOR_URL = "/static/vendor/globe.gl.min.js?v=2.45.3";
const EARTH_IMAGE_URL = "/static/earth/earth.jpg";
const MAX_VISIBLE_ATTACK_FLOWS = 20;

const DEFAULT_TARGET = {
  name: "业务主站",
  label: "香港 · 业务区",
  lng: 114.1694,
  lat: 22.3193,
};

const PERFORMANCE_PRESETS = {
  easy: {
    maxRawFlows: MAX_VISIBLE_ATTACK_FLOWS,
    maxRepresentativeFlows: MAX_VISIBLE_ATTACK_FLOWS,
    maxFlows: MAX_VISIBLE_ATTACK_FLOWS,
    maxSourceLabels: MAX_VISIBLE_ATTACK_FLOWS,
    maxSourceRings: 8,
    targetAltitude: 2.25,
  },
  normal: {
    maxRawFlows: MAX_VISIBLE_ATTACK_FLOWS,
    maxRepresentativeFlows: MAX_VISIBLE_ATTACK_FLOWS,
    maxFlows: MAX_VISIBLE_ATTACK_FLOWS,
    maxSourceLabels: MAX_VISIBLE_ATTACK_FLOWS,
    maxSourceRings: 12,
    targetAltitude: 2.08,
  },
  high: {
    maxRawFlows: MAX_VISIBLE_ATTACK_FLOWS,
    maxRepresentativeFlows: MAX_VISIBLE_ATTACK_FLOWS,
    maxFlows: MAX_VISIBLE_ATTACK_FLOWS,
    maxSourceLabels: MAX_VISIBLE_ATTACK_FLOWS,
    maxSourceRings: 16,
    targetAltitude: 1.95,
  },
};

const SEVERITY_META = {
  critical: {
    weight: 4,
    label: "严重",
    sourceColor: "rgba(255, 86, 103, 0.96)",
    pointColor: "rgba(255, 86, 103, 0.98)",
    coreColor: "rgba(255, 210, 136, 0.98)",
    glowColor: "rgba(255, 86, 103, 0.36)",
    coreStroke: 0.76,
    glowStroke: 1.7,
  },
  high: {
    weight: 3,
    label: "高危",
    sourceColor: "rgba(255, 138, 61, 0.94)",
    pointColor: "rgba(255, 138, 61, 0.96)",
    coreColor: "rgba(255, 196, 125, 0.96)",
    glowColor: "rgba(255, 138, 61, 0.32)",
    coreStroke: 0.62,
    glowStroke: 1.42,
  },
  medium: {
    weight: 2,
    label: "中危",
    sourceColor: "rgba(246, 197, 106, 0.88)",
    pointColor: "rgba(246, 197, 106, 0.9)",
    coreColor: "rgba(255, 223, 154, 0.9)",
    glowColor: "rgba(246, 197, 106, 0.22)",
    coreStroke: 0.48,
    glowStroke: 1.02,
  },
  low: {
    weight: 1,
    label: "低危",
    sourceColor: "rgba(125, 211, 252, 0.78)",
    pointColor: "rgba(125, 211, 252, 0.82)",
    coreColor: "rgba(186, 230, 253, 0.86)",
    glowColor: "rgba(125, 211, 252, 0.18)",
    coreStroke: 0.4,
    glowStroke: 0.84,
  },
  default: {
    weight: 2,
    label: "中危",
    sourceColor: "rgba(246, 197, 106, 0.88)",
    pointColor: "rgba(246, 197, 106, 0.9)",
    coreColor: "rgba(255, 223, 154, 0.9)",
    glowColor: "rgba(246, 197, 106, 0.22)",
    coreStroke: 0.48,
    glowStroke: 1.02,
  },
};

const COUNTRY_ALIASES = {
  CN: "中国",
  CHN: "中国",
  China: "中国",
  china: "中国",
  中国大陆: "中国",
  中国香港: "中国",
  香港: "中国",
  "Hong Kong": "中国",
  "hong kong": "中国",
  HK: "中国",
  中国澳门: "中国",
  澳门: "中国",
  Macao: "中国",
  Macau: "中国",
  中国台湾: "中国",
  台湾: "中国",
  Taiwan: "中国",
  US: "美国",
  USA: "美国",
  "United States": "美国",
  "United States of America": "美国",
  "united states": "美国",
  GB: "英国",
  UK: "英国",
  "United Kingdom": "英国",
  JP: "日本",
  Japan: "日本",
  DE: "德国",
  Germany: "德国",
  SG: "新加坡",
  Singapore: "新加坡",
  FR: "法国",
  France: "法国",
  CA: "加拿大",
  Canada: "加拿大",
  AU: "澳大利亚",
  Australia: "澳大利亚",
  IN: "印度",
  India: "印度",
  BR: "巴西",
  Brazil: "巴西",
  RU: "俄罗斯",
  Russia: "俄罗斯",
  KR: "韩国",
  Korea: "韩国",
  "South Korea": "韩国",
  NL: "荷兰",
  Netherlands: "荷兰",
};

const CHINA_PROVINCE_ALIASES = {
  Beijing: "北京",
  Tianjin: "天津",
  Hebei: "河北",
  Shanxi: "山西",
  "Inner Mongolia": "内蒙古",
  Liaoning: "辽宁",
  Jilin: "吉林",
  Heilongjiang: "黑龙江",
  Shanghai: "上海",
  Jiangsu: "江苏",
  Zhejiang: "浙江",
  "Zhejiang Province": "浙江",
  Anhui: "安徽",
  Fujian: "福建",
  Jiangxi: "江西",
  Shandong: "山东",
  Henan: "河南",
  Hubei: "湖北",
  Hunan: "湖南",
  Guangdong: "广东",
  "Guangdong Province": "广东",
  Guangxi: "广西",
  Hainan: "海南",
  Chongqing: "重庆",
  Sichuan: "四川",
  Guizhou: "贵州",
  Yunnan: "云南",
  Tibet: "西藏",
  Xizang: "西藏",
  Shaanxi: "陕西",
  Gansu: "甘肃",
  Qinghai: "青海",
  Ningxia: "宁夏",
  Xinjiang: "新疆",
  "Hong Kong": "香港",
  "Hong Kong SAR": "香港",
  HK: "香港",
  Macao: "澳门",
  Macau: "澳门",
  Taiwan: "台湾",
  香港特别行政区: "香港",
  澳门特别行政区: "澳门",
  台湾省: "台湾",
};

const CHINA_PROVINCE_NAMES = new Set([
  "北京",
  "天津",
  "河北",
  "山西",
  "内蒙古",
  "辽宁",
  "吉林",
  "黑龙江",
  "上海",
  "江苏",
  "浙江",
  "安徽",
  "福建",
  "江西",
  "山东",
  "河南",
  "湖北",
  "湖南",
  "广东",
  "广西",
  "海南",
  "重庆",
  "四川",
  "贵州",
  "云南",
  "西藏",
  "陕西",
  "甘肃",
  "青海",
  "宁夏",
  "新疆",
  "香港",
  "澳门",
  "台湾",
]);

let globeVendorPromise = null;

function loadScript(url) {
  return new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[data-threat-globe-vendor="${url}"]`);
    if (existing) {
      existing.addEventListener("load", resolve, { once: true });
      existing.addEventListener("error", reject, { once: true });
      if (window.Globe) {
        resolve();
      }
      return;
    }
    const script = document.createElement("script");
    script.src = url;
    script.async = true;
    script.dataset.threatGlobeVendor = url;
    script.onload = resolve;
    script.onerror = () => reject(new Error(`Failed to load ${url}`));
    document.head.appendChild(script);
  });
}

async function ensureGlobeVendor() {
  if (window.Globe) {
    return window.Globe;
  }
  if (!globeVendorPromise) {
    globeVendorPromise = loadScript(GLOBE_VENDOR_URL).then(() => {
      if (!window.Globe) {
        throw new Error("globe.gl did not expose window.Globe");
      }
      return window.Globe;
    });
  }
  return globeVendorPromise;
}

function choosePerformanceLevel(mode) {
  if (PERFORMANCE_PRESETS[mode]) {
    return mode;
  }
  const cpu = Number(navigator.hardwareConcurrency || 4);
  const memory = Number(navigator.deviceMemory || 4);
  const compactViewport = Math.min(window.innerWidth || 0, window.innerHeight || 0) < 960;
  if (compactViewport || cpu <= 4 || memory <= 4) {
    return "easy";
  }
  if (cpu >= 10 && memory >= 8) {
    return "high";
  }
  return "normal";
}

function joinSignature(parts) {
  return (Array.isArray(parts) ? parts : [])
    .map((part) => String(part == null ? "" : part))
    .join("\u001f");
}

function stableHash(value) {
  let seed = 2166136261;
  for (const char of String(value || "")) {
    seed ^= char.charCodeAt(0);
    seed = Math.imul(seed, 16777619) >>> 0;
  }
  return seed >>> 0;
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeSeverity(value) {
  const key = String(value || "").trim().toLowerCase();
  return SEVERITY_META[key] ? key : "medium";
}

function severityMeta(value) {
  return SEVERITY_META[normalizeSeverity(value)] || SEVERITY_META.default;
}

function toFiniteNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function normalizeGeoName(value) {
  return String(value || "")
    .trim()
    .replaceAll("省", "")
    .replaceAll("市", "")
    .replaceAll("特别行政区", "")
    .replaceAll("自治区", "")
    .replaceAll("壮族", "")
    .replaceAll("回族", "")
    .replaceAll("维吾尔", "");
}

function lookupAlias(aliases, value) {
  const text = String(value || "").trim();
  if (!text) {
    return "";
  }
  if (aliases[text]) {
    return aliases[text];
  }
  const lowered = text.toLowerCase();
  const match = Object.entries(aliases).find(([key]) => key.toLowerCase() === lowered);
  return match ? match[1] : text;
}

function normalizeCountryName(value) {
  return lookupAlias(COUNTRY_ALIASES, value);
}

function normalizeChineseProvince(value) {
  const alias = lookupAlias(CHINA_PROVINCE_ALIASES, value);
  const normalized = normalizeGeoName(alias);
  return lookupAlias(CHINA_PROVINCE_ALIASES, normalized);
}

function containsCjk(value) {
  return /[\u4e00-\u9fff]/.test(String(value || ""));
}

function resolveChineseProvince(flow) {
  const candidates = [
    flow?.source_province,
    flow?.display_region,
    flow?.source_region,
    flow?.source_city,
    flow?.source_country,
    flow?.source_label,
    flow?.source_geo,
  ];
  for (const candidate of candidates) {
    const text = String(candidate || "").trim();
    if (!text) {
      continue;
    }
    const province = normalizeChineseProvince(text);
    if (CHINA_PROVINCE_NAMES.has(province)) {
      return province;
    }
    for (const part of text.split(/[/|·,，\s]+/)) {
      const partProvince = normalizeChineseProvince(part);
      if (CHINA_PROVINCE_NAMES.has(partProvince)) {
        return partProvince;
      }
    }
  }
  return "";
}

function buildSourceDisplayLabel(flow) {
  const backendLabel = String(flow?.display_label || "").trim();
  if (backendLabel && containsCjk(backendLabel) && backendLabel !== "未知位置") {
    return backendLabel;
  }

  const labelParts = String(flow?.source_label || flow?.source_geo || "")
    .split(/[/|·,，]+/)
    .map((part) => part.trim())
    .filter(Boolean);
  const country = normalizeCountryName(flow?.display_country || flow?.source_country || labelParts[0] || "");
  const province = resolveChineseProvince(flow);
  const city = normalizeGeoName(flow?.display_city || flow?.source_city || labelParts[2] || "");

  if (country === "中国" || province) {
    const parts = ["中国"];
    if (province) {
      parts.push(province);
    }
    if (city && city !== province && containsCjk(city)) {
      parts.push(city);
    }
    return parts.join(" · ");
  }

  if (country) {
    const region = normalizeGeoName(flow?.display_region || flow?.source_region || labelParts[1] || "");
    const parts = [country];
    if (region && region !== country) {
      parts.push(region);
    }
    return parts.join(" · ");
  }

  return String(flow?.source_label || flow?.source_geo || flow?.source_name || "未知位置").trim() || "未知位置";
}

function buildSourceBadge(flow) {
  const country = normalizeCountryName(flow?.display_country || flow?.source_country || "");
  if (country === "中国") {
    return "中国";
  }
  if (country) {
    return country.slice(0, 2);
  }
  return severityMeta(flow?.severity).label;
}

function flowIdentity(flow, layer) {
  if (layer === "raw" || layer === "highlight") {
    return joinSignature([
      "raw",
      flow?.source_ip,
      flow?.event_id,
      flow?.timestamp,
      toFiniteNumber(flow?.source_lng).toFixed(3),
      toFiniteNumber(flow?.source_lat).toFixed(3),
      toFiniteNumber(flow?.target_lng).toFixed(3),
      toFiniteNumber(flow?.target_lat).toFixed(3),
    ]);
  }
  return joinSignature([
    "representative",
    flow?.key,
    flow?.source_ip,
    flow?.pseudo_tile,
    toFiniteNumber(flow?.source_lng).toFixed(3),
    toFiniteNumber(flow?.source_lat).toFixed(3),
  ]);
}

function sourceDisplayKey(flow) {
  return joinSignature([
    flow?.source_ip,
    flow?.display_country || flow?.source_country,
    flow?.display_region || flow?.source_region_name || flow?.source_region,
    flow?.display_city || flow?.source_city,
    toFiniteNumber(flow?.source_lng).toFixed(3),
    toFiniteNumber(flow?.source_lat).toFixed(3),
  ]);
}

function sortByImportance(left, right) {
  const severityCompare = severityMeta(right?.severity).weight - severityMeta(left?.severity).weight;
  if (severityCompare !== 0) {
    return severityCompare;
  }
  const highCompare = toFiniteNumber(right?.high_count) - toFiniteNumber(left?.high_count);
  if (highCompare !== 0) {
    return highCompare;
  }
  const countCompare = toFiniteNumber(right?.count || 1) - toFiniteNumber(left?.count || 1);
  if (countCompare !== 0) {
    return countCompare;
  }
  const timeCompare = String(right?.timestamp || "").localeCompare(String(left?.timestamp || ""));
  if (timeCompare !== 0) {
    return timeCompare;
  }
  return toFiniteNumber(right?.event_id) - toFiniteNumber(left?.event_id);
}

function normalizeFlow(flow, target, layer) {
  const sourceLat = toFiniteNumber(flow?.source_lat, NaN);
  const sourceLng = toFiniteNumber(flow?.source_lng, NaN);
  const targetLat = toFiniteNumber(flow?.target_lat, target.lat);
  const targetLng = toFiniteNumber(flow?.target_lng, target.lng);
  if (![sourceLat, sourceLng, targetLat, targetLng].every(Number.isFinite)) {
    return null;
  }
  return {
    ...flow,
    flow_layer: layer,
    source_lat: sourceLat,
    source_lng: sourceLng,
    target_lat: targetLat,
    target_lng: targetLng,
    severity: normalizeSeverity(flow?.severity),
    count: Math.max(1, toFiniteNumber(flow?.count, 1)),
    display_label: buildSourceDisplayLabel(flow),
  };
}

function selectRenderableFlows(rawFlows, representativeFlows, target, profile) {
  const rawCandidates = (Array.isArray(rawFlows) ? rawFlows : [])
    .slice()
    .sort(sortByImportance)
    .slice(0, profile.maxRawFlows)
    .map((flow) => normalizeFlow(flow, target, "raw"))
    .filter(Boolean);

  const selected = [];
  const usedKeys = new Set();
  for (const flow of rawCandidates) {
    if (selected.length >= MAX_VISIBLE_ATTACK_FLOWS) {
      break;
    }
    const key = flowIdentity(flow, "raw");
    if (usedKeys.has(key)) {
      continue;
    }
    usedKeys.add(key);
    selected.push(flow);
  }

  const representativeCandidates = (Array.isArray(representativeFlows) ? representativeFlows : [])
    .slice()
    .sort(sortByImportance)
    .map((flow) => normalizeFlow(flow, target, "representative"))
    .filter(Boolean);

  for (const flow of representativeCandidates) {
    if (selected.length >= MAX_VISIBLE_ATTACK_FLOWS) {
      break;
    }
    const key = flowIdentity(flow, "representative");
    if (usedKeys.has(key)) {
      continue;
    }
    usedKeys.add(key);
    selected.push(flow);
    if (selected.filter((item) => item.flow_layer === "representative").length >= profile.maxRepresentativeFlows) {
      break;
    }
  }

  const distinctRawIps = new Set(
    rawCandidates.map((flow) => String(flow?.source_ip || "").trim()).filter(Boolean)
  );
  if (distinctRawIps.size > 1 && selected.length <= 1) {
    return rawCandidates.slice(0, MAX_VISIBLE_ATTACK_FLOWS);
  }
  return selected.slice(0, MAX_VISIBLE_ATTACK_FLOWS);
}

function arcAltitude(flow) {
  const latDelta = Math.abs(toFiniteNumber(flow.source_lat) - toFiniteNumber(flow.target_lat));
  const lngDelta = Math.abs(toFiniteNumber(flow.source_lng) - toFiniteNumber(flow.target_lng));
  const span = Math.min(180, Math.sqrt(latDelta * latDelta + lngDelta * lngDelta));
  return Math.max(0.18, Math.min(0.54, 0.2 + span / 480));
}

function buildArcLayers(flows) {
  return flows.flatMap((flow, index) => {
    const meta = severityMeta(flow.severity);
    const common = {
      id: flowIdentity(flow, flow.flow_layer),
      flow,
      startLat: flow.source_lat,
      startLng: flow.source_lng,
      endLat: flow.target_lat,
      endLng: flow.target_lng,
      altitude: arcAltitude(flow),
      initialGap: (stableHash(`${flowIdentity(flow, flow.flow_layer)}:${index}`) % 1000) / 1000,
    };
    return [
      {
        ...common,
        layer: "glow",
        color: [meta.glowColor, meta.glowColor],
        stroke: meta.glowStroke,
        dashLength: 0.86,
        dashGap: 0.72,
        animateTime: flow.flow_layer === "representative" ? 5200 : 3600,
      },
      {
        ...common,
        layer: "core",
        color: [meta.sourceColor, meta.coreColor],
        stroke: meta.coreStroke,
        dashLength: 0.42,
        dashGap: 1.08,
        animateTime: flow.flow_layer === "representative" ? 4600 : 2800,
      },
    ];
  });
}

function buildPointLayers(flows, target) {
  const sourcePoints = flows.map((flow, index) => ({
    kind: "source",
    lat: flow.source_lat,
    lng: flow.source_lng,
    severity: flow.severity,
    flow,
    count: flow.count,
    key: `${sourceDisplayKey(flow)}:${index}`,
  }));
  return [
    ...sourcePoints,
    {
      kind: "target",
      lat: target.lat,
      lng: target.lng,
      severity: "critical",
      name: target.name,
      label: target.label,
      count: 1,
    },
  ];
}

function buildRingLayers(flows, target, profile) {
  const highSources = flows
    .filter((flow) => severityMeta(flow.severity).weight >= 3)
    .slice()
    .sort(sortByImportance)
    .slice(0, profile.maxSourceRings)
    .map((flow) => ({
      kind: "source",
      lat: flow.source_lat,
      lng: flow.source_lng,
      severity: flow.severity,
      maxRadius: flow.severity === "critical" ? 1.8 : 1.35,
      repeat: flow.severity === "critical" ? 900 : 1200,
      speed: flow.severity === "critical" ? 1.25 : 0.95,
    }));
  return [
    {
      kind: "target",
      lat: target.lat,
      lng: target.lng,
      severity: "critical",
      maxRadius: 3.1,
      repeat: 850,
      speed: 1.35,
    },
    ...highSources,
  ];
}

function labelOffset(key, index, target = false) {
  if (target) {
    return { x: 26, y: -30 };
  }
  const hash = stableHash(`${key}:${index}`);
  const angle = ((hash % 360) * Math.PI) / 180;
  const radius = 18 + (hash % 4) * 7;
  return {
    x: Math.round(Math.cos(angle) * radius),
    y: Math.round(Math.sin(angle) * radius - 10),
  };
}

function createLabelElement({ label, badge, severity, target = false, offset }) {
  const anchor = document.createElement("div");
  anchor.className = "threat-globe__html-anchor";
  const card = document.createElement("div");
  card.className = [
    "threat-globe__label",
    target ? "threat-globe__label--target" : "threat-globe__label--source",
    `threat-globe__label--${normalizeSeverity(severity)}`,
  ].join(" ");
  card.style.setProperty("--label-x", `${offset.x}px`);
  card.style.setProperty("--label-y", `${offset.y}px`);
  card.innerHTML = `
    <span class="threat-globe__label-head">
      <i class="threat-globe__flag">${escapeHtml(badge)}</i>
      <b>${escapeHtml(label)}</b>
    </span>
  `;
  anchor.appendChild(card);
  return anchor;
}

function pickVisibleLabels(flows, target, profile) {
  const labels = [
    {
      kind: "target",
      lat: target.lat,
      lng: target.lng,
      altitude: 0.09,
      element: createLabelElement({
        target: true,
        label: target.label || target.name || DEFAULT_TARGET.label,
        badge: "TARGET",
        severity: "critical",
        offset: labelOffset("target", 0, true),
      }),
    },
  ];

  const labelFlows = flows.slice(0, Math.min(profile.maxSourceLabels, MAX_VISIBLE_ATTACK_FLOWS));
  for (const [index, flow] of labelFlows.entries()) {
    const key = sourceDisplayKey(flow) || flowIdentity(flow, flow.flow_layer);
    labels.push({
      kind: "source",
      lat: flow.source_lat,
      lng: flow.source_lng,
      altitude: 0.07,
      flow,
      element: createLabelElement({
        label: flow.display_label,
        badge: buildSourceBadge(flow),
        severity: flow.severity,
        offset: labelOffset(key, labels.length),
      }),
    });
  }
  return labels;
}

function buildSignature(target, flows) {
  return joinSignature([
    target.name,
    target.label,
    toFiniteNumber(target.lng).toFixed(3),
    toFiniteNumber(target.lat).toFixed(3),
    flows.length,
    ...flows.map((flow) =>
      joinSignature([
        flowIdentity(flow, flow.flow_layer),
        flow.display_label,
        flow.severity,
        flow.count,
        flow.source_ip,
        flow.source_country_code,
        flow.source_region_name,
        flow.source_lng.toFixed(3),
        flow.source_lat.toFixed(3),
        flow.target_lng.toFixed(3),
        flow.target_lat.toFixed(3),
        flow.geo_precision,
        flow.display_geo_mode,
        flow.display_coord_source,
        flow.pseudo_tile,
      ])
    ),
  ]);
}

function callGlobe(globe, method, ...args) {
  if (globe && typeof globe[method] === "function") {
    globe[method](...args);
  }
  return globe;
}

export class ThreatEarthScreen {
  constructor(stageElement, labelsElement, performanceMode = "auto") {
    this.stageElement = stageElement;
    this.labelsElement = labelsElement;
    this.performanceMode = performanceMode || "auto";
    this.performanceLevel = choosePerformanceLevel(this.performanceMode);
    this.profile = PERFORMANCE_PRESETS[this.performanceLevel];
    this.globe = null;
    this.lastSignature = "";
    this.lastPayload = null;
    this.resizeObserver = null;
    this.resizeFrameId = 0;
    this.active = true;
    this.handleResize = this.handleResize.bind(this);
    this.requestResize = this.requestResize.bind(this);
  }

  async init() {
    const Globe = await ensureGlobeVendor();
    this.stageElement.innerHTML = "";
    if (this.labelsElement) {
      this.labelsElement.innerHTML = "";
    }
    this.globe = Globe({
      waitForGlobeReady: true,
      animateIn: true,
    })(this.stageElement);
    this.configureGlobe();
    if (window.ResizeObserver) {
      this.resizeObserver = new ResizeObserver(() => this.requestResize());
      this.resizeObserver.observe(this.stageElement);
    } else {
      window.addEventListener("resize", this.requestResize);
    }
    this.handleResize();
    this.setData({ globe: { target: DEFAULT_TARGET, raw_flows: [], representative_flows: [] } });
  }

  configureGlobe() {
    const globe = this.globe;
    callGlobe(globe, "backgroundColor", "rgba(0, 0, 0, 0)");
    callGlobe(globe, "globeImageUrl", EARTH_IMAGE_URL);
    callGlobe(globe, "showAtmosphere", true);
    callGlobe(globe, "atmosphereColor", "#47d8ff");
    callGlobe(globe, "atmosphereAltitude", 0.18);
    callGlobe(globe, "pointOfView", { lat: 21, lng: 112, altitude: this.profile.targetAltitude }, 0);

    const material = typeof globe.globeMaterial === "function" ? globe.globeMaterial() : null;
    if (material) {
      material.color?.set?.("#8fd4ff");
      material.emissive?.set?.("#052237");
      material.emissiveIntensity = 0.28;
      material.shininess = 0.8;
    }

    const controls = typeof globe.controls === "function" ? globe.controls() : null;
    if (controls) {
      controls.enablePan = false;
      controls.enableDamping = true;
      controls.dampingFactor = 0.06;
      controls.autoRotate = true;
      controls.autoRotateSpeed = 0.32;
      controls.minDistance = 170;
      controls.maxDistance = 470;
    }

    callGlobe(globe, "arcsTransitionDuration", 650);
    callGlobe(globe, "arcStartLat", (item) => item.startLat);
    callGlobe(globe, "arcStartLng", (item) => item.startLng);
    callGlobe(globe, "arcEndLat", (item) => item.endLat);
    callGlobe(globe, "arcEndLng", (item) => item.endLng);
    callGlobe(globe, "arcAltitude", (item) => item.altitude);
    callGlobe(globe, "arcCurveResolution", 48);
    callGlobe(globe, "arcCircularResolution", 8);
    callGlobe(globe, "arcColor", (item) => item.color);
    callGlobe(globe, "arcStroke", (item) => item.stroke);
    callGlobe(globe, "arcDashLength", (item) => item.dashLength);
    callGlobe(globe, "arcDashGap", (item) => item.dashGap);
    callGlobe(globe, "arcDashInitialGap", (item) => item.initialGap);
    callGlobe(globe, "arcDashAnimateTime", (item) => item.animateTime);

    callGlobe(globe, "pointsTransitionDuration", 450);
    callGlobe(globe, "pointLat", (item) => item.lat);
    callGlobe(globe, "pointLng", (item) => item.lng);
    callGlobe(globe, "pointAltitude", (item) => (item.kind === "target" ? 0.065 : 0.032));
    callGlobe(globe, "pointRadius", (item) => {
      if (item.kind === "target") {
        return 0.48;
      }
      const meta = severityMeta(item.severity);
      return Math.max(0.16, Math.min(0.32, 0.15 + meta.weight * 0.035 + Math.log10(item.count + 1) * 0.04));
    });
    callGlobe(globe, "pointColor", (item) =>
      item.kind === "target" ? "rgba(255, 210, 136, 0.98)" : severityMeta(item.severity).pointColor
    );
    callGlobe(globe, "pointResolution", 18);

    callGlobe(globe, "ringsTransitionDuration", 450);
    callGlobe(globe, "ringLat", (item) => item.lat);
    callGlobe(globe, "ringLng", (item) => item.lng);
    callGlobe(globe, "ringAltitude", (item) => (item.kind === "target" ? 0.072 : 0.04));
    callGlobe(globe, "ringMaxRadius", (item) => item.maxRadius);
    callGlobe(globe, "ringPropagationSpeed", (item) => item.speed);
    callGlobe(globe, "ringRepeatPeriod", (item) => item.repeat);
    callGlobe(globe, "ringColor", (item) => {
      const meta = severityMeta(item.severity);
      return (t) => {
        const opacity = Math.max(0, 0.48 * (1 - t));
        return item.kind === "target"
          ? `rgba(255, 196, 125, ${opacity})`
          : meta.glowColor.replace(/[\d.]+\)$/, `${opacity})`);
      };
    });

    callGlobe(globe, "htmlTransitionDuration", 450);
    callGlobe(globe, "htmlLat", (item) => item.lat);
    callGlobe(globe, "htmlLng", (item) => item.lng);
    callGlobe(globe, "htmlAltitude", (item) => item.altitude);
    callGlobe(globe, "htmlElement", (item) => item.element);
  }

  requestResize() {
    if (this.resizeFrameId) {
      return;
    }
    this.resizeFrameId = requestAnimationFrame(() => {
      this.resizeFrameId = 0;
      this.handleResize();
    });
  }

  handleResize() {
    if (!this.globe) {
      return;
    }
    const width = Math.max(320, this.stageElement.clientWidth || 0);
    const height = Math.max(420, this.stageElement.clientHeight || 0);
    callGlobe(this.globe, "width", width);
    callGlobe(this.globe, "height", height);
  }

  setData(payload) {
    if (!this.globe) {
      this.lastPayload = payload || {};
      return;
    }
    this.lastPayload = payload || {};
    const globePayload = payload?.globe || {};
    const target = {
      ...DEFAULT_TARGET,
      ...(payload?.target || globePayload.target || {}),
    };
    target.lng = toFiniteNumber(target.lng, DEFAULT_TARGET.lng);
    target.lat = toFiniteNumber(target.lat, DEFAULT_TARGET.lat);

    const rawFlows = Array.isArray(globePayload.raw_flows)
      ? globePayload.raw_flows
      : Array.isArray(payload?.raw_flows)
        ? payload.raw_flows
        : [];
    const representativeFlows = Array.isArray(globePayload.representative_flows)
      ? globePayload.representative_flows
      : Array.isArray(globePayload.aggregated_flows)
        ? globePayload.aggregated_flows
        : Array.isArray(payload?.representative_flows)
          ? payload.representative_flows
          : Array.isArray(payload?.aggregated_flows)
            ? payload.aggregated_flows
            : [];

    const flows = selectRenderableFlows(rawFlows, representativeFlows, target, this.profile);
    const signature = buildSignature(target, flows);
    if (signature === this.lastSignature) {
      return;
    }
    this.lastSignature = signature;

    const arcs = buildArcLayers(flows);
    const points = buildPointLayers(flows, target);
    const rings = buildRingLayers(flows, target, this.profile);
    const labels = pickVisibleLabels(flows, target, this.profile);

    callGlobe(this.globe, "arcsData", arcs);
    callGlobe(this.globe, "pointsData", points);
    callGlobe(this.globe, "ringsData", rings);
    callGlobe(this.globe, "htmlElementsData", labels);
  }

  setActive(active) {
    this.active = Boolean(active);
    const controls = this.globe && typeof this.globe.controls === "function" ? this.globe.controls() : null;
    if (controls) {
      controls.autoRotate = this.active;
    }
    if (this.globe) {
      const method = this.active ? "resumeAnimation" : "pauseAnimation";
      callGlobe(this.globe, method);
    }
  }

  destroy() {
    if (this.resizeFrameId) {
      cancelAnimationFrame(this.resizeFrameId);
      this.resizeFrameId = 0;
    }
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
      this.resizeObserver = null;
    } else {
      window.removeEventListener("resize", this.requestResize);
    }
    if (this.globe) {
      callGlobe(this.globe, "arcsData", []);
      callGlobe(this.globe, "pointsData", []);
      callGlobe(this.globe, "ringsData", []);
      callGlobe(this.globe, "htmlElementsData", []);
      if (typeof this.globe._destructor === "function") {
        this.globe._destructor();
      }
      this.globe = null;
    }
    this.stageElement.innerHTML = "";
    if (this.labelsElement) {
      this.labelsElement.innerHTML = "";
    }
  }
}

export async function createThreatGlobe(stageElement, labelsElement, options = {}) {
  const instance = new ThreatEarthScreen(stageElement, labelsElement, options.performanceMode || "auto");
  await instance.init();
  return instance;
}
