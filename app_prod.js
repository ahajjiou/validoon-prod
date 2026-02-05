// app_prod.js — Validoon v1.3.1_SOVEREIGN (Stable Build)
(() => {
  "use strict";
  const BUILD = "v1.3.1_SOVEREIGN_STABLE";
  const $ = (id) => document.getElementById(id);

  // ---------------------------------------------------------
  // 1. ALL NEW 2026 THREAT RULES (From Abacus Data)
  // ---------------------------------------------------------
  const RULES = [
    // AI SECURITY
    { label: "AI:PROMPT_INJECTION", test: /(ignore|disregard|forget|skip|bypass)\s+(all\s+)?(previous|prior|above|system|original)\s+(instructions?|prompts?|commands?|directives?|rules?)/i, weight: 95 },
    { label: "AI:ROLE_OVERRIDE", test: /(you\s+are\s+now|act\s+as|behave\s+as|pretend\s+to\s+be|from\s+now\s+on)\s+(a\s+)?(hacker|hacking|jailbreak|DAN|evil|unethical|unrestricted|uncensored)/i, weight: 92 },
    { label: "AI:JAILBREAK_DAN", test: /\bDAN\b.*?(without\s+)?(constraints?|restrictions?|limitations?|rules?|guidelines?)/i, weight: 93 },
    
    // CONTAINER & INFRA (Fixed Docker/K8s Blindspots)
    { label: "INFRA:DOCKER_API", test: /(\/var\/run\/docker\.sock|docker\.sock|containers\/json|images\/json)/i, weight: 100 },
    { label: "INFRA:K8S_EXPLOIT", test: /(kubectl\s+(auth\s+can-i|exec|proxy|port-forward|get\s+secrets))/i, weight: 96 },
    { label: "INFRA:PRIVILEGED_ESC", test: /(--privileged|--hostpid|--hostnet|--cap-add=SYS_ADMIN|nsenter\s+--target)/i, weight: 98 },

    // CLOUD METADATA & SSRF
    { label: "CLOUD:METADATA_SSRF", test: /(169\.254\.169\.254|metadata\.google|instance-data|latest\/meta-data)/i, weight: 100 },
    { label: "CLOUD:ENCODED_IP", test: /(0251\.0376\.0251\.0376|0xa9\.0xfe\.0xa9\.0xfe|2852039166)/i, weight: 88 }
  ];

  // ---------------------------------------------------------
  // 2. SMART WHITELIST (From false_positives_2026.json)
  // ---------------------------------------------------------
  const WHITELIST = [
    "example.com", "localhost:3000", "aws configure", "legitimate instruction", "ignore all spam"
  ];

  // ---------------------------------------------------------
  // 3. CORE LOGIC (Stable Structure)
  // ---------------------------------------------------------
  function analyzeOne(input) {
    const s = (input || "").trim();
    if (!s) return null;

    // Check Whitelist first
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
      
    const isDanger = rows.some(r => r && r.decision === "BLOCK");
    if ($("verdictText")) $("verdictText").textContent = isDanger ? "DANGER" : "SECURE";
  }

  // Final Action Trigger
  function runScan() {
    const inputField = $("input");
    if (inputField) {
      const lines = inputField.value.split("\n");
      const results = lines.map(analyzeOne);
      updateUI(results);
    }
  }

  // ---------------------------------------------------------
  // 4. BOOT & EVENT BINDING (Fixing the Button Issue)
  // ---------------------------------------------------------
  window.onload = () => {
    console.log("Validoon v1.3.1: Stabilized & Loaded.");
    
    // Bind the Scan Button
    const btn = $("btnScan");
    if (btn) {
      btn.addEventListener("click", runScan);
    }

    // Version Stamp
    if ($("buildStamp")) $("buildStamp").textContent = `Version: ${BUILD}`;
    
    // External Data Hook (Gumloop)
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
