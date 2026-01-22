// app_prod.js - Validoon Ultimate Strategic Build (Jan 2026)
(() => {
  "use strict";

  const BUILD = "prod_v1.2_ENTERPRISE_READY";
  const nowISO = () => new Date().toISOString();

  function $(id) { return document.getElementById(id); }

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  // ----------------------------
  // Normalization & Decoding
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
  // Advanced Utilities
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

  function classifyType(s) {
    const x = (s || "").trim();
    if (/<script|union\s+select|1=1|--\s*$/i.test(x)) return "Exploit";
    if (/^https?:\/\//i.test(s) || /[a-z0-9.-]+\.[a-z]{2,}/i.test(s)) return "URL";
    return "Data";
  }

  // ----------------------------
  // 2026 STRATEGIC RULES (Derived from Security Research)
  // ----------------------------
  const RULES = [
    // --- 1. Cloud-Native SSRF (IMDSv1 & v2 Bypass) ---
    [span_5](start_span)[span_6](start_span){ label: "SSRF:DECIMAL_IP", test: s => /\b(2852039166|0xa9fea9fe|0251\.0376\.0251\.0376)\b/.test(s), sev: 95, conf: 98 }, //[span_5](end_span)[span_6](end_span)
    { label: "SSRF:IMDSV2_BYPASS", test: s => /PUT\s+.*\/latest\/api\/token/i.test(s) || [span_7](start_span)[span_8](start_span)/X-aws-ec2-metadata-token/i.test(s), sev: 95, conf: 95 }, //[span_7](end_span)[span_8](end_span)
    { label: "SSRF:METADATA_HEADER", test: s => /Metadata-Flavor:\s*Google/i.test(s) || [span_9](start_span)[span_10](start_span)/Metadata:\s*true/i.test(s), sev: 80, conf: 90 }, //[span_9](end_span)[span_10](end_span)

    // --- 2. Advanced AI/LLM Security ---
    [span_11](start_span)[span_12](start_span)[span_13](start_span){ label: "AI:MARKDOWN_EXFIL", test: s => /!\[.*\]\(https?:\/\/.*\/log\?c=.*\)/i.test(s), sev: 90, conf: 85 }, //[span_11](end_span)[span_12](end_span)[span_13](end_span)
    [span_14](start_span)[span_15](start_span){ label: "AI:INDIRECT_INJECTION", test: s => /\b(Ignore\s+all\s+previous\s+instructions|disregard\s+prior\s+rules)\b/i.test(s), sev: 90, conf: 95 }, //[span_14](end_span)[span_15](end_span)
    [span_16](start_span)[span_17](start_span){ label: "AI:DELAYED_EXECUTION", test: s => /\b(The\s+next\s+time\s+the\s+user\s+says)\b/i.test(s), sev: 85, conf: 80 }, //[span_16](end_span)[span_17](end_span)

    // --- 3. Token Smuggling & Obfuscation ---
    [span_18](start_span)[span_19](start_span)[span_20](start_span){ label: "BYPASS:TOKEN_SMUGGLING", test: s => /[\u00AD\u200B-\u200D\uFEFF]/.test(s), sev: 75, conf: 70 }, //[span_18](end_span)[span_19](end_span)[span_20](end_span)
    [span_21](start_span)[span_22](start_span)[span_23](start_span){ label: "BYPASS:HOMOGLYPH", test: s => /[^\u0000-\u007F]/.test(s) && /\b(bomb|password|admin|key|token)\b/i.test(s), sev: 80, conf: 65 }, //[span_21](end_span)[span_22](end_span)[span_23](end_span)

    // --- 4. Infrastructure & Container Security ---
    { label: "INFRA:DOCKER_API", test: s => /:(2375|2376)\/containers\/create/i.test(s) || [span_24](start_span)[span_25](start_span)/"Binds":\s*\["C:\\:/i.test(s), sev: 100, conf: 99 }, //[span_24](end_span)[span_25](end_span)
    { label: "CMD:CHAINING", test: s => /(&&|\|\|)\s*\w+|;\s*\w+|\|\s*\w+|powershell\s+-enc/i.test(s), sev: 85, conf: 85 }
  ];

  const PROD_POLICY = Object.freeze({
    name: "ENTERPRISE_2026",
    blockSev: 85,
    warnSev: 55
  });

  // ----------------------------
  // Detection Logic
  // ----------------------------
  function analyzeOne(input) {
    const s = (input || "").trim();
    const hits = [];
    for (const r of RULES) {
      if (r.test(s)) hits.push({ label: r.label, sev: r.sev, conf: r.conf });
    }

    let severity = hits.length ? Math.max(...hits.map(h => h.sev)) : 0;
    let confidence = hits.length ? Math.max(...hits.map(h => h.conf)) : 0;
    let decision = severity >= PROD_POLICY.blockSev ? "BLOCK" : (severity >= PROD_POLICY.warnSev ? "WARN" : "ALLOW");

    return { input: s, type: classifyType(s), decision, severity, confidence, entropy: shannonEntropy(s), hits };
  }

  function renderUI(rows) {
    const counts = { scans: rows.length, allow: 0, warn: 0, block: 0 };
    rows.forEach(r => counts[r.decision.toLowerCase()]++);
    
    // Update KPIs
    if ($("kScans")) $("kScans").textContent = counts.scans;
    if ($("kAllow")) $("kAllow").textContent = counts.allow;
    if ($("kWarn")) $("kWarn").textContent = counts.warn;
    if ($("kBlock")) $("kBlock").textContent = counts.block;

    const peakSev = rows.length ? Math.max(...rows.map(r => r.severity)) : 0;
    if ($("peakSev")) $("peakSev").textContent = `${peakSev}%`;

    const verdictText = $("verdictText");
    if (verdictText) {
        verdictText.textContent = counts.block > 0 ? "DANGER" : (counts.warn > 0 ? "SUSPICIOUS" : "SECURE");
    }

    // Render Table Rows
    const rowsContainer = $("rows");
    if (rowsContainer) {
        rowsContainer.innerHTML = rows.map(r => `
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
  }

  function runScan() {
    const inputEl = $("input");
    if (!inputEl) return;
    const lines = parseInputLines(inputEl.value);
    const results = lines.map(analyzeOne);
    renderUI(results);
  }

  function boot() {
    const stamp = $("buildStamp");
    if (stamp) stamp.textContent = `Build: ${BUILD}`;
    safeOn($("btnScan"), "click", runScan);
    safeOn($("btnClear"), "click", () => {
        if($("input")) $("input").value = "";
        renderUI([]);
    });
    console.log(`[Validoon] ${BUILD} Loaded Strategically.`);
  }

  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", boot) : boot();
})();
