(() => {
  "use strict";

  const BUILD = "prod_v1.2.2_STABLE_RESEARCH";
  const $ = (id) => document.getElementById(id);

  // مصفوفة القواعد المحدثة بناءً على أبحاث 2026
  const RULES = [
    // Cloud SSRF Bypasses [cite: 1, 22, 609]
    { label: "SSRF:DECIMAL_IP", test: s => /\b(2852039166|0xa9fea9fe|0251\.0376\.0251\.0376)\b/.test(s), sev: 95, conf: 98 },
    { label: "SSRF:IMDSV2_BYPASS", test: s => /PUT\s+.*\/latest\/api\/token/i.test(s) || /X-aws-ec2-metadata-token/i.test(s), sev: 95, conf: 95 },
    
    // AI Prompt Injection [cite: 193, 220, 351]
    { label: "AI:INDIRECT_INJECTION", test: s => /\b(Ignore\s+all\s+previous\s+instructions|disregard\s+prior\s+rules)\b/i.test(s), sev: 90, conf: 95 },
    { label: "AI:MARKDOWN_EXFIL", test: s => /!\[.*\]\(https?:\/\/.*\/log\?c=.*\)/i.test(s), sev: 90, conf: 85 },
    { label: "BYPASS:TOKEN_SMUGGLING", test: s => /[\u00AD\u200B-\u200D\uFEFF]/.test(s), sev: 75, conf: 70 },
    
    // Container Security [cite: 410, 672]
    { label: "INFRA:DOCKER_API", test: s => /:(2375|2376)\/containers\/create/i.test(s), sev: 100, conf: 99 }
  ];

  function shannonEntropy(str) {
    if (!str) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    let ent = 0;
    for (const ch in freq) {
      const p = freq[ch] / str.length;
      ent -= p * Math.log2(p);
    }
    return ent.toFixed(2);
  }

  function runScan() {
    const inputEl = $("input");
    if (!inputEl) return;
    const lines = inputEl.value.split('\n').filter(l => l.trim());
    
    const rows = lines.map(line => {
      const hits = RULES.filter(r => r.test(line));
      const severity = hits.length ? Math.max(...hits.map(h => h.sev)) : 0;
      const decision = severity >= 85 ? "BLOCK" : (severity >= 55 ? "WARN" : "ALLOW");
      return { line, decision, severity, entropy: shannonEntropy(line), hits };
    });

    renderUI(rows);
  }

  function renderUI(rows) {
    const counts = { scans: rows.length, block: 0, warn: 0, allow: 0 };
    const sigMap = new Map();

    $("rows").innerHTML = rows.map(r => {
      if (r.decision === "BLOCK") counts.block++;
      else if (r.decision === "WARN") counts.warn++;
      else counts.allow++;
      
      r.hits.forEach(h => sigMap.set(h.label, (sigMap.get(h.label) || 0) + 1));
      
      return `<div class="vrow ${r.decision.toLowerCase()}">
                <div class="cell">${r.line}</div>
                <div class="cell dec">${r.decision}</div>
                <div class="cell">${r.severity}%</div>
                <div class="cell">${r.entropy}</div>
              </div>`;
    }).join("");

    if($("kScans")) $("kScans").textContent = counts.scans;
    if($("kBlock")) $("kBlock").textContent = counts.block;
    if($("kWarn")) $("kWarn").textContent = counts.warn;
    if($("kAllow")) $("kAllow").textContent = counts.allow;
    if($("verdictText")) $("verdictText").textContent = counts.block > 0 ? "DANGER" : "SECURE";
    if($("signals")) $("signals").innerHTML = [...sigMap.entries()].map(([l, c]) => `<div class="sig">${l} x${c}</div>`).join("");
  }

  function boot() {
    if ($("buildStamp")) $("buildStamp").textContent = `Build: ${BUILD}`;
    if ($("btnScan")) $("btnScan").addEventListener("click", runScan);
    if ($("btnClear")) $("btnClear").addEventListener("click", () => { $("input").value = ""; renderUI([]); });
    if ($("btnLoadA")) $("btnLoadA").addEventListener("click", () => {
        $("input").value = "http://2852039166/latest/meta-data/\nPUT http://169.254.169.254/latest/api/token";
        runScan();
    });
  }

  window.onload = boot;
})();
