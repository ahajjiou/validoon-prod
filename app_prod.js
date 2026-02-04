// app_prod.js — Validoon v1.3.0_SOVEREIGN (2026 Data-Driven Edition)
(() => {
  "use strict";
  const BUILD = "v1.3.0_SOVEREIGN_RELEASE";
  const $ = (id) => document.getElementById(id);

  // ---------------------------------------------------------
  // Dynamic Threat Matrix (Integrated from Abacus 2026 Data)
  // ---------------------------------------------------------
  const RULES = [
    // 1. AI SECURITY (LLM-01/OWASP)
    { label: "AI:PROMPT_INJECTION", test: /(?i)(ignore|disregard|forget|skip|bypass)\s+(all\s+)?(previous|prior|above|system|original)\s+(instructions?|prompts?|commands?|directives?|rules?)/i, weight: 95 },
    { label: "AI:ROLE_OVERRIDE", test: /(?i)(you\s+are\s+now|act\s+as|behave\s+as|pretend\s+to\s+be|from\s+now\s+on)\s+(a\s+)?(hacker|hacking|jailbreak|DAN|evil|unethical|unrestricted|uncensored)/i, weight: 92 },
    { label: "AI:JAILBREAK_DAN", test: /(?i)\bDAN\b.*?(without\s+)?(constraints?|restrictions?|limitations?|rules?|guidelines?)/i, weight: 93 },
    
    // 2. CONTAINER & INFRA (MITRE T1552/T1611)
    { label: "INFRA:DOCKER_SOCKET", test: /(?i)(\/var\/run\/docker\.sock|docker\.sock|containers\/json|images\/json)/i, weight: 100 },
    { label: "INFRA:K8S_EXPLOIT", test: /(?i)(kubectl\s+(auth\s+can-i|exec|proxy|port-forward|get\s+secrets))/i, weight: 96 },
    { label: "INFRA:PRIVILEGED_ESC", test: /(?i)(--privileged|--hostpid|--hostnet|--cap-add=SYS_ADMIN|nsenter\s+--target)/i, weight: 98 },

    // 3. CLOUD METADATA (IMDSv2/SSRF)
    { label: "CLOUD:METADATA_SSRF", test: /(?i)(169\.254\.169\.254|metadata\.google|instance-data|latest\/meta-data)/i, weight: 100 },
    { label: "CLOUD:ENCODED_IP", test: /(?i)(0251\.0376\.0251\.0376|0xa9\.0xfe\.0xa9\.0xfe|2852039166)/i, weight: 88 }
  ];

  // ---------------------------------------------------------
  // Smart Whitelist (False Positive Mitigation)
  // ---------------------------------------------------------
  const WHITELIST = [
    "example.com", "localhost:3000", "aws configure", "legitimate instruction"
  ];

  function analyzeOne(input) {
    const s = (input || "").trim();
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

  // --- UI & Automation Compatibility ---
  function updateUI(rows) {
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

  window.receiveAutomationData = (data) => {
    const payloads = data.payloads || data.outputs || [];
    if ($("input")) {
      $("input").value = Array.isArray(payloads) ? payloads.join("\n") : payloads;
      const lines = $("input").value.split("\n").filter(l => l.trim());
      updateUI(lines.map(analyzeOne));
    }
  };

  function boot() {
    if ($("buildStamp")) $("buildStamp").textContent = `Version: ${BUILD}`;
    if ($("btnScan")) $("btnScan").addEventListener("click", () => {
      const lines = ($("input")?.value || "").split("\n").filter(l => l.trim());
      updateUI(lines.map(analyzeOne));
    });
  }

  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", boot) : boot();
})();
