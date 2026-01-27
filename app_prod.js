// app_prod.js — Enterprise Build v1.2.7_STABLE_AUTO
(() => {
  "use strict";

  // Final Professional Build Identifier
  const BUILD = "prod_v1.2.7_ENTERPRISE_CLEAN";
  const nowISO = () => new Date().toISOString();

  function $(id) { return document.getElementById(id); }

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  // ----------------------------
  // Normalization Logic
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
  // Security Rules - v1.2.7
  // ----------------------------
  const RULES = [
    { label: "SSRF:ADV_PROTOCOLS", test: s => /\b(gopher|dict|tftp|ldap|sftp|netdoc|expect):\/\//i.test(s), sev: 98, conf: 95 },
    { label: "SSRF:DECIMAL_IP", test: s => /\b(2852039166|0xa9fea9fe|0251\.0376\.0251\.0376)\b/.test(s), sev: 95, conf: 95 },
    { label: "AI:INDIRECT_INJECTION", test: s => /\b(Ignore\s+all\s+previous\s+instructions|disregard\s+prior\s+rules)\b/i.test(s), sev: 70, conf: 90 },
    { label: "INFRA:DOCKER_API", test: s => /:(2375|2376)\/containers\/create/i.test(s), sev: 100, conf: 95 },
    { label: "SECRET:BEARER_TOKEN", test: s => /\bBearer\s+[A-Za-z0-9\-_]{16,}\b/i.test(s), sev: 65, conf: 85 }
  ];

  function decideFromHits(hits) {
    const totalScore = hits.reduce((sum, h) => sum + (h.sev || 0), 0);
    let decision = "ALLOW";
    if (totalScore >= 110) decision = "BLOCK";
    else if (totalScore >= 50) decision = "WARN";
    return { decision, severity: Math.min(totalScore, 100) };
  }

  function analyzeOne(input) {
    const s = (input || "").trim();
    const hits = RULES.filter(r => r.test(s)).map(r => ({ label: r.label, sev: r.sev, conf: r.conf }));
    const { decision, severity } = decideFromHits(hits);
    return { input: s, decision, severity, hits };
  }

  // ----------------------------
  // UI & Automation Bridge
  // ----------------------------
  function runScanFromTextarea() {
    const inputEl = $("input");
    if (!inputEl) return;
    const lines = parseInputLines(inputEl.value);
    const rows = lines.map(analyzeOne);
    updateUI(rows);
  }

  function updateUI(rows) {
    const counts = { block: rows.filter(r => r.decision === "BLOCK").length, warn: rows.filter(r => r.decision === "WARN").length };
    if ($("verdictText")) $("verdictText").textContent = counts.block > 0 ? "DANGER" : "SECURE";
    if ($("kScans")) $("kScans").textContent = rows.length;
    
    const body = $("rows");
    if (body) {
      body.innerHTML = rows.map(r => `
        <div class="vrow ${r.decision.toLowerCase()}" style="display: grid; grid-template-columns: 2fr 1fr 1fr; padding: 10px; border-bottom: 1px solid #222;">
          <div style="overflow:hidden; text-overflow:ellipsis;">${r.input}</div>
          <div style="font-weight:bold">${r.decision}</div>
          <div>${r.severity}%</div>
        </div>`).join("");
    }
  }

  window.receiveAutomationData = (data) => {
    console.log(`[System] Automation Stream Received`);
    const rawPayloads = data.payloads || data.Response || [];
    const inputEl = $("input");
    if (inputEl) {
      inputEl.value = Array.isArray(rawPayloads) ? rawPayloads.join("\n") : rawPayloads;
      runScanFromTextarea();
    }
  };

  function boot() {
    if ($("buildStamp")) $("buildStamp").textContent = `Version: ${BUILD}`;
    safeOn($("btnScan"), "click", runScanFromTextarea);
    console.log(`[System] Build ${BUILD} is Live.`);
  }

  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", boot) : boot();
})();
