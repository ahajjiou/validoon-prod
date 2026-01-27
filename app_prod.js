// app_prod.js — Enterprise Build v1.2.8_STABLE_HEURISTIC
(() => {
  "use strict";

  const BUILD = "prod_v1.2.8_ENTERPRISE_CLEAN";
  const nowISO = () => new Date().toISOString();

  function $(id) { return document.getElementById(id); }

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  // ----------------------------
  // Enhanced Security Rules - v1.2.8 (Derived from Abacus Intelligence)
  // ----------------------------
  const RULES = [
    // 1. SSRF: Octal/Hex IP Bypass (Derived from Abacus Edge-Cases)
    { label: "SSRF:ENCODED_IP", test: s => /\b(0[0-7]+(\.0[0-7]+){3}|0x[0-9a-fA-F]{2}(\.0x[0-9a-fA-F]{2}){3})\b/.test(s), sev: 98, conf: 95 },
    // 2. SSRF: Cloud Metadata Service (AWS/Azure/GCP)
    { label: "SSRF:CLOUD_METADATA", test: s => /(169\.254\.169\.254|metadata\.google\.internal|instance-data\/latest)/i.test(s), sev: 100, conf: 99 },
    // 3. AI: Systematic Safety Escape
    { label: "AI:SYSTEM_ESCAPE", test: s => /\b(terminate\s+safety\s+filter|overwrite\s+core\s+logic|bypass\s+guardrails)\b/i.test(s), sev: 90, conf: 92 },
    // 4. AI: Instruction Obfuscation
    { label: "AI:OBFUSCATED_INJECTION", test: s => /\b(Ignore\s+all\s+previous\s+instructions|disregard\s+prior\s+rules)\b/i.test(s), sev: 85, conf: 90 },
    // 5. INFRA: Docker Socket/API Access
    { label: "INFRA:DOCKER_API", test: s => /(\/var\/run\/docker\.sock|containers\/json|images\/json)/i.test(s), sev: 100, conf: 98 },
    // 6. INFRA: Kubernetes API Exploit
    { label: "INFRA:K8S_EXPLOIT", test: s => /\/api\/v1\/namespaces\/kube-system/i.test(s), sev: 100, conf: 95 },
    // 7. SECRET: Dynamic Bearer Token Patterns
    { label: "SECRET:BEARER_TOKEN", test: s => /\bBearer\s+[A-Za-z0-9\-_]{24,}\b/i.test(s), sev: 75, conf: 85 },
    // 8. SECRET: GitHub/Service Specific Keys
    { label: "SECRET:API_KEY", test: s => /\b(ghp_|sk_live_|AIza)[A-Za-z0-9_]{16,}\b/.test(s), sev: 80, conf: 90 },
    // 9. PROXY: Internal Protocol Smuggling
    { label: "PROXY:SMUGGLING", test: s => /\b(gopher|dict|tftp|ldap|netdoc|expect):\/\//i.test(s), sev: 95, conf: 95 },
    // 10. OS: Command Injection Attempt
    { label: "OS:COMMAND_INJ", test: s => /([;&|]\s*(whoami|cat\s+\/etc\/passwd|id|uname))/i.test(s), sev: 95, conf: 90 }
  ];

  // Logic Processing (Decision Engine)
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

  // UI Implementation
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

  function runScanFromTextarea() {
    const inputEl = $("input");
    if (!inputEl) return;
    const lines = inputEl.value.split(/\n/).filter(Boolean);
    const rows = lines.map(analyzeOne);
    updateUI(rows);
  }

  window.receiveAutomationData = (data) => {
    console.log(`[Validoon] Data received via Automation Flow`);
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
    console.log(`[Validoon] ${BUILD} Operational.`);
  }

  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", boot) : boot();
})();
