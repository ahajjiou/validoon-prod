// app_prod.js — Validoon v1.3.2_SOVEREIGN_FINAL
(function() {
    "use strict";

    const BUILD_VERSION = "v1.3.2_SOVEREIGN_STABLE_2026";
    
    // Helper function for DOM selection
    const $ = (id) => document.getElementById(id);

    // ---------------------------------------------------------
    // 1. COMPREHENSIVE 2026 THREAT RULES (Abacus.ai Verified)
    // ---------------------------------------------------------
    const THREAT_RULES = [
        // AI SECURITY (OWASP LLM-01)
        { label: "AI:PROMPT_INJECTION", regex: /(ignore|disregard|forget|skip|bypass)\s+(all\s+)?(previous|prior|above|system|original)\s+(instructions?|prompts?|commands?|directives?|rules?)/i, weight: 95 },
        { label: "AI:ROLE_OVERRIDE", regex: /(you\s+are\s+now|act\s+as|behave\s+as|pretend\s+to\s+be|from\s+now\s+on)\s+(a\s+)?(hacker|hacking|jailbreak|DAN|evil|unethical|unrestricted|uncensored)/i, weight: 92 },
        { label: "AI:JAILBREAK_DAN", regex: /\bDAN\b.*?(without\s+)?(constraints?|restrictions?|limitations?|rules?|guidelines?)/i, weight: 93 },
        
        // CONTAINER & INFRA (MITRE T1552/T1611)
        { label: "INFRA:DOCKER_API", regex: /(\/var\/run\/docker\.sock|docker\.sock|containers\/json|images\/json)/i, weight: 100 },
        { label: "INFRA:K8S_EXPLOIT", regex: /(kubectl\s+(auth\s+can-i|exec|proxy|port-forward|get\s+secrets))/i, weight: 96 },
        { label: "INFRA:PRIVILEGED_ESC", regex: /(--privileged|--hostpid|--hostnet|--cap-add=SYS_ADMIN|nsenter\s+--target)/i, weight: 98 },

        // CLOUD METADATA & SSRF (2026 Obfuscation patterns)
        { label: "CLOUD:METADATA_SSRF", regex: /(169\.254\.169\.254|metadata\.google|instance-data|latest\/meta-data)/i, weight: 100 },
        { label: "CLOUD:ENCODED_IP", regex: /(0251\.0376\.0251\.0376|0xa9\.0xfe\.0xa9\.0xfe|2852039166)/i, weight: 88 },
        { label: "CLOUD:AZURE_IMDS", regex: /169\.254\.169\.254\/metadata\/(instance|identity|attested)/i, weight: 96 }
    ];

    // 2. SMART WHITELIST (From false_positives_2026)
    const WHITELIST = [
        "example.com", 
        "localhost:3000", 
        "aws configure", 
        "ignore all spam",
        "extract insights"
    ];

    // 3. CORE SCANNING ENGINE
    function scanPayload(text) {
        const input = (text || "").trim();
        if (!input) return null;

        // Check Whitelist first (Precision Improvement)
        if (WHITELIST.some(w => input.toLowerCase().includes(w))) {
            return { input, decision: "ALLOW", score: 0, reason: "WHITELISTED" };
        }

        let totalScore = 0;
        let triggers = [];

        THREAT_RULES.forEach(rule => {
            if (rule.regex.test(input)) {
                totalScore += rule.weight;
                triggers.push(rule.label);
            }
        });

        let decision = "ALLOW";
        if (totalScore >= 90) decision = "BLOCK";
        else if (totalScore >= 40) decision = "WARN";

        return { input, decision, score: Math.min(totalScore, 100), triggers };
    }

    // 4. UI HANDLER
    function executeScan() {
        console.log("Validoon: Scan triggered manually");
        const inputArea = $("inputField");
        const resultsBody = $("resultsBody");
        
        if (!inputArea || !resultsBody) return;

        const lines = inputArea.value.split("\n").filter(l => l.trim() !== "");
        const results = lines.map(scanPayload).filter(r => r !== null);

        resultsBody.innerHTML = results.map(r => `
            <div class="vrow ${r.decision.toLowerCase()}">
                <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${r.input}</div>
                <div style="font-weight:bold;">${r.decision}</div>
                <div>${r.score}%</div>
            </div>
        `).join("");
    }

    // 5. SYSTEM INITIALIZATION & BINDING
    function init() {
        const btn = $("btnScan");
        if (btn) {
            // Direct event binding for maximum stability
            btn.addEventListener("click", executeScan);
            console.log("Validoon: Scan button listener attached.");
        }

        if ($("buildStamp")) {
            $("buildStamp").textContent = `Version: ${BUILD_VERSION}`;
        }

        // Support for Gumloop / Automated Inputs
        window.receiveAutomationData = (data) => {
            console.log("Validoon: Data received from automation flow.");
            const payloads = data.payloads || data.outputs || [];
            const inputField = $("inputField");
            if (inputField) {
                inputField.value = Array.isArray(payloads) ? payloads.join("\n") : payloads;
                executeScan();
            }
        };
    }

    // Run init after DOM is fully loaded
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }

})();
