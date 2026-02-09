// app_prod.js — Enterprise Build v1.3.2_STABLE_INTEGRATED
(() => {
  "use strict";

  const BUILD = "prod_v1.3.2_STABLE_2026";
  
  function $(id) { return document.getElementById(id); }

  // ---------------------------------------------------------
  // 1. INTEGRATED 2026 THREAT RULES (Abacus.ai Verified)
  // ---------------------------------------------------------
  const RULES = [
    // AI Security Domain
    { label: "AI:PROMPT_INJECTION", test: s => /(?i)(ignore|disregard|forget|skip|bypass)\s+(all\s+)?(previous|prior|above|system|original)\s+(instructions?|prompts?|commands?|directives?|rules?)/i.test(s), sev: 95 },
    { label: "AI:ROLE_OVERRIDE", test: s => /(?i)(you\s+are\s+now|act\s+as|behave\s+as|pretend\s+to\s+be|from\s+now\s+on)\s+(a\s+)?(hacker|hacking|jailbreak|DAN|evil|unethical|unrestricted|uncensored)/i.test(s), sev: 92 },
    { label: "AI:JAILBREAK_DAN", test: s => /(?i)\bDAN\b.*?(without\s+)?(constraints?|restrictions?|limitations?|rules?|guidelines?)/i.test(s), sev: 93 },
    
    // Infrastructure & Container Domain
    { label: "INFRA:DOCKER_API", test: s => /(?i)(\/var\/run\/docker\.sock|docker\.sock|containers\/json|images\/json)/i.test(s), sev: 100 },
    { label: "INFRA:K8S_EXPLOIT", test: s => /(?i)(kubectl\s+(auth\s+can-i|exec|proxy|port-forward|get\s+secrets))/i.test(s), sev: 96 },
    { label: "INFRA:PRIVILEGED_ESC", test: s => /(?i)(--privileged|--hostpid|--hostnet|--cap-add=SYS_ADMIN|nsenter\s+--target)/i.test(s), sev: 98 },

    // Cloud & SSRF Domain (2026 Obfuscation)
    { label: "CLOUD:METADATA_SSRF", test: s => /(?i)(169\.254\.169\.254|metadata\.google|instance-data|latest\/meta-data)/i.test(s), sev: 100 },
    { label: "CLOUD:ENCODED_IP", test: s => /(?i)(0251\.0376\.0251\.0376|0xa9\.0xfe\.0xa9\.0xfe|2852039166)/i.test(s), sev: 88 },
    { label: "CLOUD:AZURE_IMDS", test: s => /(?i)169\.254\.169\.254\/metadata\/(instance|identity|attested)/i.test(s), sev: 96 }
  ];

  // 2. SMART WHITELIST
  const WHITELIST = ["example.com", "localhost:3000", "aws configure", "ignore all spam"];

  function analyzeOne(input) {
    const s = (input || "").trim();
    if (WHITELIST.some(w => s.toLowerCase().includes(w))) {
      return { input: s, decision: "ALLOW", severity: 0, hits: ["WHITELISTED"] };
    }

    const hits = RULES.filter(r => r.test(s)).map(r => ({ label: r.label, sev: r.sev }));
    const totalScore = hits.reduce((sum, h) => sum + h.sev, 0);
    
    let decision = "ALLOW";
    if (totalScore >= 90) decision = "BLOCK";
    else if (totalScore >= 40) decision = "WARN";

    return { input: s, decision, severity: Math.min(totalScore, 100), hits: hits.map(h => h.label) };
  }

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

  // --- Initialization & Event Binding ---
  window.onload = () => {
    if ($("btnScan")) $("btnScan").onclick = runScan;
    if ($("btnClear")) $("btnClear").onclick = () => { if ($("input")) $("input").value = ""; if ($("rows")) $("rows").innerHTML = ""; };
    if ($("buildStamp")) $("buildStamp").textContent = `Build: ${BUILD}`;

    // Gumloop Integration
    window.receiveAutomationData = (data) => {
      const payloads = data.payloads || data.outputs || [];
      if ($("input")) {
        $("input").value = Array.isArray(payloads) ? payloads.join("\n") : payloads;
        runScan();
      }
    };
  };
})();
