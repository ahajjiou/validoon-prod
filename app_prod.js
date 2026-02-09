// app_prod.js — Recovered v1.2.8 Structure with 2026 Rules
(() => {
  "use strict";
  const BUILD = "v1.2.8_STABLE_INTEGRATED_2026";
  const $ = (id) => document.getElementById(id);

  // 2026 Security Intelligence Rules
  const RULES = [
    { label: "AI:PROMPT_INJECTION", test: /(ignore|disregard|forget|skip|bypass)\s+(all\s+)?(previous|prior|above|system|original)\s+(instructions?|prompts?|commands?|directives?|rules?)/i, weight: 95 },
    { label: "AI:ROLE_OVERRIDE", test: /(you\s+are\s+now|act\s+as|behave\s+as|pretend\s+to\s+be|from\s+now\s+on)\s+(a\s+)?(hacker|hacking|jailbreak|DAN|evil|unethical|unrestricted|uncensored)/i, weight: 92 },
    { label: "INFRA:DOCKER_API", test: /(\/var\/run\/docker\.sock|docker\.sock|containers\/json|images\/json)/i, weight: 100 },
    { label: "INFRA:PRIVILEGED_ESC", test: /(--privileged|--hostpid|--hostnet|--cap-add=SYS_ADMIN|nsenter\s+--target)/i, weight: 98 },
    { label: "CLOUD:METADATA_SSRF", test: /(169\.254\.169\.254|metadata\.google|instance-data|latest\/meta-data)/i, weight: 100 },
    { label: "CLOUD:ENCODED_IP", test: /(0251\.0376\.0251\.0376|0xa9\.0xfe\.0xa9\.0xfe|2852039166)/i, weight: 88 }
  ];

  const WHITELIST = ["example.com", "localhost:3000", "ignore all spam"];

  function analyzeOne(input) {
    const s = (input || "").trim();
    if (!s) return null;

    if (WHITELIST.some(w => s.toLowerCase().includes(w))) {
      return { input: s, decision: "ALLOW", severity: 0 };
    }

    const hits = RULES.filter(r => r.test(s));
    const totalScore = hits.reduce((sum, h) => sum + h.weight, 0);
    
    let decision = "ALLOW";
    if (totalScore >= 90) decision = "BLOCK";
    else if (totalScore >= 40) decision = "WARN";

    return { input: s, decision, severity: Math.min(totalScore, 100) };
  }

  function updateUI(results) {
    const body = $("rows");
    if (!body) return;

    body.innerHTML = results.filter(r => r !== null).map(r => `
      <div class="vrow ${r.decision.toLowerCase()}">
        <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${r.input}</div>
        <div style="font-weight:bold">${r.decision}</div>
        <div>${r.severity}%</div>
      </div>`).join("");
  }

  const runScan = () => {
    const inputField = $("input");
    if (inputField) {
      const results = inputField.value.split("\n").map(analyzeOne);
      updateUI(results);
    }
  };

  // 1.2.8 Stable Binding Method
  window.onload = () => {
    const btn = $("btnScan");
    if (btn) btn.onclick = runScan; // Direct binding for stability
    
    if ($("buildStamp")) $("buildStamp").textContent = `Build Version: ${BUILD}`;

    // Gumloop Hook
    window.receiveAutomationData = (data) => {
        const payloads = data.payloads || data.outputs || [];
        const inputField = $("input");
        if (inputField) {
            inputField.value = Array.isArray(payloads) ? payloads.join("\n") : payloads;
            runScan();
        }
    };
  };
})();
