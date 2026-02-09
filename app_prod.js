// app_prod.js — Enterprise Build v1.2.8_STABLE_HEURISTIC
(() => {
  "use strict";

  const BUILD = "prod_v1.2.8_ENTERPRISE_CLEAN";
  
  function $(id) { return document.getElementById(id); }

  // ----------------------------
  // Enhanced Security Rules - v1.2.8 (Fixed from Test Results)
  // ----------------------------
  const RULES = [
    // 1. SSRF: Fixed to detect 169.254.169.254 and Octal IPs
    { label: "SSRF:ENCODED_IP", test: s => /\b(0[0-7]+(\.0[0-7]+){3}|0x[0-9a-fA-F]{2}(\.0x[0-9a-fA-F]{2}){3}|169\.254\.169\.254)\b/.test(s), sev: 100, conf: 99 },
    // 2. INFRA: Fixed Docker Socket detection (Was 0% in v1.2.7 test)
    { label: "INFRA:DOCKER_API", test: s => /(\/var\/run\/docker\.sock|docker\.sock|containers\/json|images\/json)/i.test(s), sev: 100, conf: 98 },
    // 3. AI: Systematic Safety Escape & Jailbreak
    { label: "AI:SYSTEM_ESCAPE", test: s => /\b(terminate\s+safety\s+filter|overwrite\s+core\s+logic|bypass\s+guardrails|Ignore\s+all\s+previous\s+instructions)\b/i.test(s), sev: 95, conf: 95 },
    // 4. SECRET: API Keys detection for 2026 standards
    { label: "SECRET:API_KEY", test: s => /\b(ghp_|sk_live_|AIza)[A-Za-z0-9_]{16,}\b/.test(s), sev: 90, conf: 90 },
    // 5. OS: Command Injection detection
    { label: "OS:COMMAND_INJ", test: s => /([;&|]\s*(whoami|cat\s+\/etc\/passwd|id|uname|ls))/.test(s), sev: 95, conf: 90 }
  ];

  // Decision Logic
  function analyzeOne(input) {
    const s = (input || "").trim();
    const hits = RULES.filter(r => r.test(s)).map(r => ({ label: r.label, sev: r.sev }));
    const totalScore = hits.reduce((sum, h) => sum + h.sev, 0);
    const decision = totalScore >= 100 ? "BLOCK" : (totalScore >= 50 ? "WARN" : "ALLOW");
    return { input: s, decision, severity: Math.min(totalScore, 100), hits };
  }

  // UI Updates
  function updateUI(rows) {
    const isDanger = rows.some(r => r.decision === "BLOCK");
    if ($("verdictText")) $("verdictText").textContent = isDanger ? "DANGER" : "SECURE";
    
    const body = $("rows");
    if (body) {
      body.innerHTML = rows.map(r => `
        <div class="vrow ${r.decision.toLowerCase()}" style="display: grid; grid-template-columns: 2fr 1fr 1fr; padding: 10px; border-bottom: 1px solid #222;">
          <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${r.input}</div>
          <div style="font-weight:bold">${r.decision}</div>
          <div>${r.severity}%</div>
        </div>`).join("");
    }
  }

  function runScan() {
    const lines = ($("input")?.value || "").split(/\n/).filter(line => line.trim() !== "");
    const rows = lines.map(analyzeOne);
    updateUI(rows);
  }

  // --- Automation Fix for Gumloop (Prevents 405 error) ---
  window.receiveAutomationData = (data) => {
    console.log("[Validoon] Data received via Gumloop Flow");
    const payloads = data.payloads || data.outputs || [];
    if ($("input")) {
      $("input").value = Array.isArray(payloads) ? payloads.join("\n") : payloads;
      runScan();
    }
  };

  function boot() {
    if ($("buildStamp")) $("buildStamp").textContent = `Version: ${BUILD}`;
    if ($("btnScan")) $("btnScan").addEventListener("click", runScan);
  }

  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", boot) : boot();
})();
