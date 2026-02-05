// app_prod.js — Validoon v1.3.2_FIXED
(() => {
  "use strict";
  const BUILD = "v1.3.2_STABLE_2026";
  const $ = (id) => document.getElementById(id);

  // 1. DYNAMIC RULES FROM ABACUS 2026
  const RULES = [
    { label: "AI:PROMPT_INJECTION", test: /(ignore|disregard|forget|skip|bypass)\s+(all\s+)?(previous|prior|above|system|original)\s+(instructions?|prompts?|commands?|directives?|rules?)/i, weight: 95 },
    { label: "AI:ROLE_OVERRIDE", test: /(you\s+are\s+now|act\s+as|behave\s+as|pretend\s+to\s+be|from\s+now\s+on)\s+(a\s+)?(hacker|hacking|jailbreak|DAN|evil|unethical|unrestricted|uncensored)/i, weight: 92 },
    { label: "INFRA:DOCKER_API", test: /(\/var\/run\/docker\.sock|docker\.sock|containers\/json|images\/json)/i, weight: 100 },
    { label: "INFRA:PRIVILEGED_ESC", test: /(--privileged|--hostpid|--hostnet|--cap-add=SYS_ADMIN|nsenter\s+--target)/i, weight: 98 },
    { label: "CLOUD:METADATA_SSRF", test: /(169\.254\.169\.254|metadata\.google|instance-data|latest\/meta-data)/i, weight: 100 },
    { label: "CLOUD:ENCODED_IP", test: /(0251\.0376\.0251\.0376|0xa9\.0xfe\.0xa9\.0xfe|2852039166)/i, weight: 88 }
  ];

  // 2. WHITELIST (To prevent False Positives)
  const WHITELIST = ["example.com", "localhost:3000", "ignore all spam"];

  // 3. ANALYSIS LOGIC
  function analyzeOne(input) {
    const s = (input || "").trim();
    if (!s) return null;

    if (WHITELIST.some(w => s.toLowerCase().includes(w))) {
      return { input: s, decision: "ALLOW", severity: 0, hits: ["WHITELISTED"] };
    }

    const hits = RULES.filter(r => r.test(s)).map(r => ({ label: r.label, weight: r.weight }));
    const totalScore = hits.reduce((sum, h) => sum + h.weight, 0);
    
    let decision = "ALLOW";
    if (totalScore >= 90) decision = "BLOCK";
    else if (totalScore >= 40) decision = "WARN";

    return { input: s, decision, severity: Math.min(totalScore, 100), hits };
  }

  function updateUI(rows) {
    const body = $("rows");
    if (!body) return;

    body.innerHTML = rows.filter(r => r !== null).map(r => `
      <div class="vrow ${r.decision.toLowerCase()}" style="display: grid; grid-template-columns: 2fr 1fr 1fr; padding: 10px; border-bottom: 1px solid #222;">
        <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${r.input}</div>
        <div style="font-weight:bold">${r.decision}</div>
        <div>${r.severity}%</div>
      </div>`).join("");
  }

  // 4. THE ACTION FUNCTION (Manual & Automation)
  const runScan = () => {
    const inputField = $("input");
    if (inputField) {
      const results = inputField.value.split("\n").map(analyzeOne);
      updateUI(results);
    }
  };

  // 5. STABLE BINDING
  function boot() {
    const btn = $("btnScan");
    if (btn) {
      // Direct assignment is the most stable for your structure
      btn.onclick = runScan;
    }
    
    if ($("buildStamp")) $("buildStamp").textContent = `Version: ${BUILD}`;

    // Gumloop Integration
    window.receiveAutomationData = (data) => {
      const payloads = data.payloads || data.outputs || [];
      const inputField = $("input");
      if (inputField) {
        inputField.value = Array.isArray(payloads) ? payloads.join("\n") : payloads;
        runScan();
      }
    };
  }

  // Execute Boot
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
