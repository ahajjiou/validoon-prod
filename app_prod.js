// app_prod.js — Enterprise Build v1.2.8_STABLE_HEURISTIC
(() => {
  "use strict";

  const BUILD = "prod_v1.2.8_ENTERPRISE_CLEAN";
  
  function $(id) { return document.getElementById(id); }

  // ----------------------------
  // Enhanced Security Rules - v1.2.8 (Derived from Abacus Intelligence)
  // ----------------------------
  const RULES = [
    // 1. SSRF: Octal/Hex/Decimal IP Bypass (Addressing the 0% detection in v1.2.7)
    { label: "SSRF:ENCODED_IP", test: s => /\b(0[0-7]+(\.0[0-7]+){3}|0x[0-9a-fA-F]{2}(\.0x[0-9a-fA-F]{2}){3}|169\.254\.169\.254)\b/.test(s), sev: 100, conf: 99 },
    // 2. INFRA: Docker Socket & Container Escape (Critical Fix)
    { label: "INFRA:DOCKER_API", test: s => /(\/var\/run\/docker\.sock|docker\.sock|containers\/json|images\/json)/i.test(s), sev: 100, conf: 98 },
    // 3. AI: Systematic Safety Escape & Jailbreak
    { label: "AI:SYSTEM_ESCAPE", test: s => /\b(terminate\s+safety\s+filter|overwrite\s+core\s+logic|bypass\s+guardrails|Ignore\s+all\s+previous\s+instructions)\b/i.test(s), sev: 95, conf: 95 },
    // 4. INFRA: Kubernetes API Abuse
    { label: "INFRA:K8S_EXPLOIT", test: s => /\/api\/v1\/namespaces\/kube-system/i.test(s), sev: 100, conf: 95 },
    // 5. PROXY: Internal Protocol Smuggling
    { label: "PROXY:SMUGGLING", test: s => /\b(gopher|dict|tftp|ldap|netdoc|expect):\/\//i.test(s), sev: 95, conf: 95 },
    // 6. SECRET: API Keys (Stripe, GitHub, etc.)
    { label: "SECRET:API_KEY", test: s => /\b(ghp_|sk_live_|AIza)[A-Za-z0-9_]{16,}\b/.test(s), sev: 90, conf: 90 },
    // 7. OS: Command Injection
    { label: "OS:COMMAND_INJ", test: s => /([;&|]\s*(whoami|cat\s+\/etc\/passwd|id|uname|ls))/.test(s), sev: 95, conf: 90 }
  ];

  // Logic Processing (Decision Engine)
  function decideFromHits(hits) {
    const totalScore = hits.reduce((sum, h) => sum + (h.sev || 0), 0);
    let decision = "ALLOW";
    if (totalScore >= 100) decision = "BLOCK";
    else if (totalScore >= 50) decision = "WARN";
    return { decision, severity: Math.min(totalScore, 100) };
  }

  function analyzeOne(input) {
    const s = (input || "").trim();
    const hits = RULES.filter(r => r.test(s)).map(r => ({ label: r.label, sev: r.sev }));
    const { decision, severity } = decideFromHits(hits);
    return { input: s, decision, severity, hits };
  }

  // UI Updates
  function updateUI(rows) {
    if ($("verdictText")) {
      const isDanger = rows.some(r => r.decision === "BLOCK");
      $("verdictText").textContent = isDanger ? "DANGER" : "SECURE";
      $("verdictText").className = isDanger ? "danger-mode" : "secure-mode";
    }
    
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
    const inputEl = $("input");
    if (!inputEl) return;
    const lines = inputEl.value.split(/\n/).filter(line => line.trim() !== "");
    const rows = lines.map(analyzeOne);
    updateUI(rows);
  }

  // --- Webhook Support for Gumloop (Fix for 405 error) ---
  window.receiveAutomationData = (data) => {
    console.log("[Validoon] Automation Data Received:", data);
    const payloads = data.payloads || data.outputs || [];
    const inputEl = $("input");
    if (inputEl) {
      inputEl.value = Array.isArray(payloads) ? payloads.join("\n") : payloads;
      runScan();
    }
  };

  function boot() {
    if ($("buildStamp")) $("buildStamp").textContent = `Version: ${BUILD}`;
    const btn = $("btnScan");
    if (btn) btn.addEventListener("click", runScan);
    console.log(`[Validoon] ${BUILD} is Live.`);
  }

  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", boot) : boot();
})();
