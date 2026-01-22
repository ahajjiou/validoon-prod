ط// app_prod.js - Fixed & Enterprise Ready (v1.2.1)
(() => {
  "use strict";

  const BUILD = "prod_v1.2.1_FIXED";
  const $ = (id) => document.getElementById(id);

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  // --- Normalization Logic ---
  function normalizeLine(raw) {
    let s = (raw ?? "").toString();
    s = s.replace(/\r/g, "").trim().replace(/\s+/g, " ");
    try { s = decodeURIComponent(decodeURIComponent(s)); } catch { } 
    return s;
  }

  // --- Entropy Utility ---
  function shannonEntropy(str) {
    if (!str) return 0;
    const freq = new Map();
    for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
    let ent = 0;
    for (const [, c] of freq) {
      const p = c / str.length;
      ent -= p * Math.log2(p);
    }
    return Math.round(ent * 100) / 100;
  }

  // --- 2026 ADVANCED RULES (Based on Research) ---
  const RULES = [
    { label: "SSRF:DECIMAL_IP", test: s => /\b(2852039166|0xa9fea9fe|0251\.0376\.0251\.0376)\b/.test(s), sev: 95, conf: 98 },
    { label: "SSRF:IMDSV2_BYPASS", test: s => /PUT\s+.*\/latest\/api\/token/i.test(s) || /X-aws-ec2-metadata-token/i.test(s), sev: 95, conf: 95 },
    { label: "AI:INDIRECT_INJECTION", test: s => /\b(Ignore\s+all\s+previous\s+instructions|disregard\s+prior\s+rules)\b/i.test(s), sev: 90, conf: 95 },
    { label: "AI:MARKDOWN_EXFIL", test: s => /!\[.*\]\(https?:\/\/.*\/log\?c=.*\)/i.test(s), sev: 90, conf: 85 },
    { label: "BYPASS:TOKEN_SMUGGLING", test: s => /[\u00AD\u200B-\u200D\uFEFF]/.test(s), sev: 75, conf: 70 },
    { label: "INFRA:DOCKER_API", test: s => /:(2375|2376)\/containers\/create/i.test(s) || /"Binds":\s*\["C:\\:/i.test(s), sev: 100, conf: 99 }
  ];

  let lastReport = null;

  function runScan() {
    const inputEl = $("input");
    if (!inputEl) return;
    const lines = inputEl.value.split(/\r?\n/).map(normalizeLine).filter(Boolean);
    
    const rows = lines.map(line => {
      const hits = RULES.filter(r => r.test(line));
      const severity = hits.length ? Math.max(...hits.map(h => h.sev)) : 0;
      const confidence = hits.length ? Math.max(...hits.map(h => h.conf)) : 0;
      const decision = severity >= 85 ? "BLOCK" : (severity >= 55 ? "WARN" : "ALLOW");
      return { input: line, decision, severity, confidence, entropy: shannonEntropy(line), hits };
    });

    lastReport = { generatedAt: new Date().toISOString(), counts: { scans: rows.length, block: rows.filter(r=>r.decision==="BLOCK").length, warn: rows.filter(r=>r.decision==="WARN").length, allow: rows.filter(r=>r.decision==="ALLOW").length }, rows };
    updateUI(lastReport);
  }

  function updateUI(report) {
    if ($("kScans")) $("kScans").textContent = report.counts.scans;
    if ($("kBlock")) $("kBlock").textContent = report.counts.block;
    if ($("kWarn")) $("kWarn").textContent = report.counts.warn;
    if ($("kAllow")) $("kAllow").textContent = report.counts.allow;

    const verdictText = $("verdictText");
    if (verdictText) verdictText.textContent = report.counts.block > 0 ? "DANGER" : (report.counts.warn > 0 ? "SUSPICIOUS" : "SECURE");

    const rowsContainer = $("rows");
    if (rowsContainer) {
      rowsContainer.innerHTML = report.rows.map(r => `
        <div class="vrow ${r.decision.toLowerCase()}">
          <div class="cell">${r.input}</div>
          <div class="cell">Data</div>
          <div class="cell dec">${r.decision}</div>
          <div class="cell">${r.severity}%</div>
          <div class="cell">${r.confidence}%</div>
          <div class="cell">${r.entropy}</div>
        </div>
      `).join("");
    }
  }

  function exportJSON() {
    if (!lastReport) return;
    const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `validoon_report_${Date.now()}.json`;
    a.click();
  }

  function boot() {
    const stamp = $("buildStamp");
    if (stamp) stamp.textContent = `Build: ${BUILD}`;

    safeOn($("btnScan"), "click", runScan);
    safeOn($("btnExport"), "click", exportJSON);
    safeOn($("btnClear"), "click", () => {
      if ($("input")) $("input").value = "";
      updateUI({ counts: { scans: 0, block: 0, warn: 0, allow: 0 }, rows: [] });
    });
    
    // Modal Logic
    safeOn($("btnInfo"), "click", () => $("infoDlg")?.classList.remove("hidden"));
    safeOn($("btnCloseInfo"), "click", () => $("infoDlg")?.classList.add("hidden"));
  }

  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", boot) : boot();
})();
