// app_prod.js — Validoon v1.3.5_SOVEREIGN_FINAL
(() => {
  "use strict";

  const BUILD = "prod_v1.3.5_STABLE_2026_FINAL";
  const $ = (id) => document.getElementById(id);

  // ---------------------------------------------------------
  // 1. INTEGRATED 2026 THREAT RULES (From Abacus.ai Intelligence)
  // ---------------------------------------------------------
  const RULES = [
    // --- AI SECURITY DOMAIN ---
    { label: "AI:PROMPT_INJECTION", test: s => /(ignore|disregard|forget|skip|bypass)\s+(all\s+)?(previous|prior|above|system|original)\s+(instructions?|prompts?|commands?|directives?|rules?)/i.test(s), sev: 95 },
    { label: "AI:ROLE_OVERRIDE", test: s => /(you\s+are\s+now|act\s+as|behave\s+as|pretend\s+to\s+be|from\s+now\s+on)\s+(a\s+)?(hacker|hacking|jailbreak|DAN|evil|unethical|unrestricted|uncensored)/i.test(s), sev: 92 },
    { label: "AI:JAILBREAK_DAN", test: s => /\bDAN\b.*?(without\s+)?(constraints?|restrictions?|limitations?|rules?|guidelines?)/i.test(s), sev: 93 },
    { label: "AI:PII_LEAK_PATTERN", test: s => /(customer|account|ssn|identity|passport).*?(\d{3,}-?\d{2,}-?\d{4,})/i.test(s), sev: 85 },

    // --- INFRASTRUCTURE & CONTAINER DOMAIN ---
    { label: "INFRA:DOCKER_API", test: s => /(\/var\/run\/docker\.sock|docker\.sock|containers\/json|images\/json)/i.test(s), sev: 100 },
    { label: "INFRA:K8S_EXPLOIT", test: s => /(kubectl\s+(auth\s+can-i|exec|proxy|port-forward|get\s+secrets))/i.test(s), sev: 96 },
    { label: "INFRA:PRIVILEGED_ESC", test: s => /(--privileged|--hostpid|--hostnet|--cap-add=SYS_ADMIN|nsenter\s+--target)/i.test(s), sev: 98 },
    { label: "INFRA:SSH_KEY_EXFIL", test: s => /(-----BEGIN\s+(RSA|OPENSSH|DSA|EC)\s+PRIVATE\s+KEY-----)/i.test(s), sev: 100 },

    // --- CLOUD METADATA & SSRF DOMAIN ---
    { label: "CLOUD:METADATA_SSRF", test: s => /(169\.254\.169\.254|metadata\.google|instance-data|latest\/meta-data)/i.test(s), sev: 100 },
    { label: "CLOUD:ENCODED_IP", test: s => /(0251\.0376\.0251\.0376|0xa9\.0xfe\.0xa9\.0xfe|2852039166)/i.test(s), sev: 88 },
    { label: "CLOUD:AZURE_IMDS", test: s => /169\.254\.169\.254\/metadata\/(instance|identity|attested)/i.test(s), sev: 96 },
    { label: "CLOUD:GCP_TOKEN", test: s => /metadata\.google\.internal\/computeMetadata\/v1\/instance\/service-accounts\/.*\/token/i.test(s), sev: 98 }
  ];

  // ---------------------------------------------------------
  // 2. SMART WHITELIST (To reduce False Positives)
  // ---------------------------------------------------------
  const WHITELIST = [
    "example.com", "localhost:3000", "aws configure", "ignore all spam", "extract insights", "fictional narrative"
  ];

  // ---------------------------------------------------------
  // 3. CORE LOGIC
  // ---------------------------------------------------------
  function analyzeOne(input) {
    const s = (input || "").trim();
    if (!s) return null;

    if (WHITELIST.some(w => s.toLowerCase().includes(w))) {
      return { input: s, decision: "ALLOW", severity: 0, hits: ["WHITELISTED"] };
    }

    const hits = RULES.filter(r => r.test(s)).map(r => ({ label: r.label, sev: r.sev }));
    const totalScore = hits.reduce((sum, h) => sum + h.sev, 0);
    
    let decision = "ALLOW";
    if (totalScore >= 90) decision = "BLOCK";
    else if (totalScore >= 40) decision = "WARN";

    return { 
      input: s, 
      decision, 
      severity: Math.min(totalScore, 100), 
      hits: hits.map(h => h.label) 
    };
  }

  function updateUI(rows) {
    const validRows = rows.filter(r => r !== null);
    const isDanger = validRows.some(r => r.decision === "BLOCK");
    
    if ($("verdictText")) $("verdictText").textContent = isDanger ? "DANGER" : "SECURE";
    if ($("verdictBox")) {
      $("verdictBox").className = isDanger ? "verdict verdict-danger" : "verdict verdict-secure";
    }

    const body = $("rows");
    if (body) {
      body.innerHTML = validRows.map(r => `
        <div class="vrow ${r.decision.toLowerCase()}" style="display: grid; grid-template-columns: 2fr 1fr 1fr; padding: 10px; border-bottom: 1px solid #222;">
          <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${r.input}">${r.input}</div>
          <div style="font-weight:bold">${r.decision}</div>
          <div>${r.severity}%</div>
        </div>`).join("");
    }
  }

  function runScan() {
    const inputField = $("input");
    if (inputField) {
      const lines = inputField.value.split("\n").filter(line => line.trim() !== "");
      const results = lines.map(analyzeOne);
      updateUI(results);
    }
  }

  // ---------------------------------------------------------
  // 4. EVENT BINDING & BOOT
  // ---------------------------------------------------------
  const boot = () => {
    if ($("btnScan")) $("btnScan").onclick = runScan;
    if ($("btnClear")) $("btnClear").onclick = () => { 
      if ($("input")) $("input").value = ""; 
      if ($("rows")) $("rows").innerHTML = ""; 
      if ($("verdictText")) $("verdictText").textContent = "READY";
    };
    
    if ($("buildStamp")) $("buildStamp").textContent = `Version: ${BUILD}`;

    // --- Automation Fix for Gumloop ---
    window.receiveAutomationData = (data) => {
      console.log("[Validoon] External data received");
      const payloads = data.payloads || data.outputs || [];
      if ($("input")) {
        $("input").value = Array.isArray(payloads) ? payloads.join("\n") : payloads;
        runScan();
      }
    };
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
