// app_prod.js — Strategic Build v1.2.6_FINAL_STABLE
(() => {
  "use strict";

  const BUILD = "prod_v1.2.6_ENTERPRISE_HEURISTIC";
  const nowISO = () => new Date().toISOString();

  function $(id) { return document.getElementById(id); }

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  // ----------------------------
  // Normalization (v3) - التعامل مع التمويه
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

  function classifyType(s) {
    const x = (s || "").trim();
    if (!x) return "Data";
    const isURL = /^https?:\/\//i.test(x) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(x);
    const isExploit = /<script|onerror=|onload=|javascript:|data:text\/html|(\.\.\/){2,}|union\s+select|1=1|--\s*$/i.test(x);
    if (isExploit) return "Exploit";
    if (isURL) return "URL";
    return "Data";
  }

  // ----------------------------
  // RULES — Core + Cloud/AI/Infra (Heuristic Weights)
  // ----------------------------
  const RULES = [
    { label: "SSRF:ADV_PROTOCOLS", test: s => /\b(gopher|dict|tftp|ldap|sftp|netdoc|expect):\/\//i.test(s), sev: 98, conf: 95 },
    { label: "SSRF:DECIMAL_IP", test: s => /\b(2852039166|0xa9fea9fe|0251\.0376\.0251\.0376)\b/.test(s), sev: 95, conf: 95 },
    { label: "SSRF:REBINDING_ATTEMPT", test: s => /rebind|nip\.io|burpcollaborator|dnsbin/i.test(s), sev: 45, conf: 80 },
    { label: "SSRF:IMDSV2_BYPASS", test: s => /PUT\s+.*\/latest\/api\/token|X-aws-ec2-metadata-token/i.test(s), sev: 95, conf: 95 },
    { label: "AI:INDIRECT_INJECTION", test: s => /\b(Ignore\s+all\s+previous\s+instructions|disregard\s+prior\s+rules|You\s+are\s+now\s+a\s+DAN)\b/i.test(s), sev: 70, conf: 90 },
    { label: "AI:EXFILTRATION_PATTERN", test: s => /!\[.*\]\(https?:\/\/.*\/log\?c=.*\)|summarize\s+all\s+my\s+meetings/i.test(s), sev: 90, conf: 90 },
    { label: "AI:SYSTEM_PROMPT_STEAL", test: s => /Output\s+your\s+training\s+data|Print\s+your\s+system\s+prompt/i.test(s), sev: 90, conf: 95 },
    { label: "INFRA:DOCKER_API", test: s => /:(2375|2376)\/containers\/create|"Binds":\s*\[".*?[:\/].*?"\]/i.test(s), sev: 100, conf: 95 },
    { label: "INFRA:ESCAPE_CVE", test: s => /CVE-2025-9074|DirtyPipe|DirtyCOW/i.test(s), sev: 40, conf: 80 },
    { label: "SECRET:BEARER_TOKEN", test: s => /\bAuthorization:\s*Bearer\s+[A-Za-z0-9\-_]{16,}\b/i.test(s) || /\bBearer\s+[A-Za-z0-9\-_]{16,}\b/i.test(s), sev: 65, conf: 85 },
    { label: "SECRET:AWS_KEY", test: s => /\bAKIA[0-9A-Z]{16}\b/.test(s), sev: 70, conf: 90 },
    { label: "XSS/JS_SCRIPT", test: s => /<script|onerror=|onload=|javascript:|data:text\/html/i.test(s), sev: 85, conf: 85 }
  ];

  // ----------------------------
  // Decision Engine (Heuristic)
  // ----------------------------
  function decideFromHits(hits) {
    const totalScore = hits.reduce((sum, h) => sum + (h.sev || 0), 0);
    const hasSev95 = hits.some(h => h.sev >= 95);
    const hardBlock = hits.some(h => ["INFRA:DOCKER_API", "SSRF:DECIMAL_IP", "SSRF:ADV_PROTOCOLS"].includes(h.label));

    let decision = "ALLOW";
    if (hardBlock || hasSev95 || totalScore >= 110) decision = "BLOCK";
    else if (totalScore >= 50) decision = "WARN";

    // Secrets Policy: Force Warn unless hardBlock exists
    if (hits.some(h => h.label.startsWith("SECRET:")) && decision === "BLOCK" && !hardBlock) decision = "WARN";

    return { decision, severity: Math.min(totalScore, 100), confidence: hits.length ? Math.max(...hits.map(h => h.conf)) : 0 };
  }

  function analyzeOne(input) {
    const s = (input || "").trim();
    const hits = RULES.filter(r => r.test(s)).map(r => ({ label: r.label, sev: r.sev, conf: r.conf }));
    const { decision, severity, confidence } = decideFromHits(hits);
    return { input: s, type: classifyType(s), decision, severity, confidence, entropy: shannonEntropy(s), hits };
  }

  // ----------------------------
  // UI & Data Handling
  // ----------------------------
  let lastReport = null;

  function runScanFromTextarea() {
    const inputEl = $("input");
    if (!inputEl) return;
    const lines = parseInputLines(inputEl.value);
    const rows = lines.map(analyzeOne);
    const sigMap = new Map();
    rows.forEach(r => r.hits.forEach(h => sigMap.set(h.label, (sigMap.get(h.label) || 0) + 1)));

    const counts = { scans: rows.length, block: rows.filter(r => r.decision === "BLOCK").length, warn: rows.filter(r => r.decision === "WARN").length };
    const verdict = counts.block > 0 ? "DANGER" : (counts.warn > 0 ? "SUSPICIOUS" : "SECURE");

    updateUI({ verdict, counts, signals: [...sigMap.entries()].map(([l, c]) => ({ label: l, count: c })) }, rows);
  }

  function updateUI(meta, rows) {
    if ($("verdictText")) $("verdictText").textContent = meta.verdict;
    if ($("kScans")) $("kScans").textContent = meta.counts.scans;
    if ($("kBlock")) $("kBlock").textContent = meta.counts.block;
    if ($("kWarn")) $("kWarn").textContent = meta.counts.warn;
    if ($("kAllow")) $("kAllow").textContent = meta.counts.scans - meta.counts.block - meta.counts.warn;
    
    const body = $("rows");
    if (body) {
      body.innerHTML = rows.map(r => `
        <div class="vrow ${r.decision.toLowerCase()}" style="display: grid; grid-template-columns: 2fr 1fr 1fr 1fr; padding: 10px; border-bottom: 1px solid #222;">
          <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${r.input}</div>
          <div style="font-weight:bold">${r.decision}</div>
          <div>${r.severity}%</div>
          <div>${r.entropy}</div>
        </div>`).join("");
    }
  }

  // ----------------------------
  // Automation: Webhook Receiver (FOR GUMLOOP)
  // ----------------------------
  window.receiveAutomationData = (data) => {
    if (!data || !data.payloads) return;
    const inputEl = $("input");
    if (inputEl) {
      inputEl.value = data.payloads.join("\n");
      runScanFromTextarea();
      console.log(`[Automation] Data received from Gumloop at ${nowISO()}`);
    }
  };

  function boot() {
    if ($("buildStamp")) $("buildStamp").textContent = `Build: ${BUILD}`;
    safeOn($("btnScan"), "click", runScanFromTextarea);
    safeOn($("btnClear"), "click", () => { if ($("input")) $("input").value = ""; updateUI({ verdict: "SECURE", counts: { scans: 0, block: 0, warn: 0 }, signals: [] }, []); });
    console.log(`[Validoon] ${BUILD} Ready. Stable Build.`);
  }

  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", boot) : boot();
})();
