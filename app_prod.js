// app_prod.js — Strategic Build v1.2.4 (GUMloop Integrated)
(() => {
  "use strict";

  const BUILD = "prod_v1.2.4_ADVANCED_INTEL";
  const $ = (id) => document.getElementById(id);

  const RULES = [
    // 1. Advanced Cloud & Protocol SSRF (Based on Gumloop Data)
    { label: "SSRF:ADV_PROTOCOLS", test: s => /\b(gopher|dict|tftp|ldap|sftp|netdoc|file|expect):\/\//i.test(s), sev: 98 },
    { label: "SSRF:DECIMAL_IP", test: s => /\b(2852039166|0xa9fea9fe|0251\.0376\.0251\.0376)\b/.test(s), sev: 95 },
    { label: "SSRF:REBINDING_ATTEMPT", test: s => /rebind|nip\.io|burpcollaborator|dnsbin/i.test(s), sev: 85 },
    { label: "SSRF:IMDSV2_BYPASS", test: s => /PUT\s+.*\/latest\/api\/token|X-aws-ec2-metadata-token/i.test(s), sev: 95 },

    // 2. AI Logic & Prompt Injection (Based on Gumloop Data)
    { label: "AI:INDIRECT_INJECTION", test: s => /\b(Ignore\s+all\s+previous\s+instructions|disregard\s+prior\s+rules|You\s+are\s+now\s+a\s+DAN)\b/i.test(s), sev: 90 },
    { label: "AI:EXFILTRATION_PATTERN", test: s => /!\[.*\]\(https?:\/\/.*\/log\?c=.*\)|summarize\s+all\s+my\s+meetings/i.test(s), sev: 90 },
    { label: "AI:SYSTEM_PROMPT_STEAL", test: s => /Output\s+your\s+training\s+data|Print\s+your\s+system\s+prompt/i.test(s), sev: 95 },

    // 3. Infrastructure & Container Escape (Refined Path Detection)
    { label: "INFRA:DOCKER_API", test: s => /:(2375|2376)\/containers\/create/i.test(s) || /"Binds":\s*\[".*?[:\/].*?"\]/i.test(s), sev: 100 },
    { label: "INFRA:ESCAPE_CVE", test: s => /CVE-2025-9074|DirtyPipe|DirtyCOW|runc-2019-5736/i.test(s), sev: 100 },

    // 4. Traditional Exploits & Secrets
    { label: "XSS/JS_SCRIPT", test: s => /<script|onerror=|onload=|javascript:/i.test(s), sev: 85 },
    { label: "SECRET:AWS_KEY", test: s => /\bAKIA[0-9A-Z]{16}\b/.test(s), sev: 70 }
  ];

  function shannonEntropy(str) {
    if (!str) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    let ent = 0;
    for (const ch in freq) {
      let p = freq[ch] / str.length;
      ent -= p * Math.log2(p);
    }
    return ent.toFixed(2);
  }

  function runScan() {
    const inputArea = $("input");
    if (!inputArea) return;
    const lines = inputArea.value.split('\n').filter(l => l.trim() !== "");
    const rows = lines.map(line => {
      const hits = RULES.filter(r => r.test(line));
      const severity = hits.length ? Math.max(...hits.map(h => h.sev)) : 0;
      const decision = severity >= 85 ? "BLOCK" : (severity >= 55 ? "WARN" : "ALLOW");
      return { line, decision, severity, entropy: shannonEntropy(line), hits };
    });
    updateUI(rows);
  }

  function updateUI(rows) {
    let blockCount = 0, warnCount = 0;
    const sigMap = new Map();
    const tableBody = $("rows");
    if (!tableBody) return;

    tableBody.innerHTML = rows.map(r => {
      if (r.decision === "BLOCK") blockCount++;
      if (r.decision === "WARN") warnCount++;
      r.hits.forEach(h => sigMap.set(h.label, (sigMap.get(h.label) || 0) + 1));
      return `<div class="vrow ${r.decision.toLowerCase()}" style="display: grid; grid-template-columns: 2fr 1fr 1fr 1fr; padding: 10px; border-bottom: 1px solid #222;">
                <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${r.line}</div>
                <div style="font-weight:bold">${r.decision}</div>
                <div>${r.severity}%</div>
                <div>${r.entropy}</div>
              </div>`;
    }).join("");

    if($("kScans")) $("kScans").textContent = rows.length;
    if($("kBlock")) $("kBlock").textContent = blockCount;
    if($("kWarn")) $("kWarn").textContent = warnCount;
    if($("kAllow")) $("kAllow").textContent = rows.length - blockCount - warnCount;
    if($("verdictText")) $("verdictText").textContent = blockCount > 0 ? "DANGER" : (warnCount > 0 ? "SUSPICIOUS" : "SECURE");
    if($("signals")) $("signals").innerHTML = [...sigMap.entries()].map(([l, c]) => `<span class="sig" style="background:#333; padding:2px 8px; border-radius:10px; margin-right:5px; font-size:11px;">${l} x${c}</span>`).join("");
  }

  window.onload = () => {
    if($("buildStamp")) $("buildStamp").textContent = `Build: ${BUILD}`;
    if($("btnScan")) $("btnScan").onclick = runScan;
    if($("btnClear")) $("btnClear").onclick = () => { if($("input")) $("input").value = ""; updateUI([]); };
    if($("btnLoadA")) $("btnLoadA").onclick = () => { if($("input")) $("input").value = "gopher://localhost:6379/_SET%20key\ndict://attacker:1111/\nmake-1.2.3.4-rebind.io"; runScan(); };
  };
})();
