(() => {
  "use strict";

  const BUILD = "prod_v1.2.1_FINAL";
  const $ = (id) => document.getElementById(id);

  // --- 2026 Strategic Rules ---
  const RULES = [
    [span_6](start_span)[span_7](start_span){ label: "SSRF:DECIMAL_IP", test: s => /\b(2852039166|0xa9fea9fe|0251\.0376\.0251\.0376)\b/.test(s), sev: 95 },[span_6](end_span)[span_7](end_span)
    { label: "SSRF:IMDSV2_BYPASS", test: s => /PUT\s+.*\/latest\/api\/token/i.test(s) || [span_8](start_span)[span_9](start_span)/X-aws-ec2-metadata-token/i.test(s), sev: 95 },[span_8](end_span)[span_9](end_span)
    [span_10](start_span)[span_11](start_span){ label: "AI:INDIRECT_INJECTION", test: s => /\b(Ignore\s+all\s+previous\s+instructions|disregard\s+prior\s+rules)\b/i.test(s), sev: 90 },[span_10](end_span)[span_11](end_span)
    [span_12](start_span)[span_13](start_span){ label: "AI:MARKDOWN_EXFIL", test: s => /!\[.*\]\(https?:\/\/.*\/log\?c=.*\)/i.test(s), sev: 90 },[span_12](end_span)[span_13](end_span)
    [span_14](start_span)[span_15](start_span){ label: "BYPASS:TOKEN_SMUGGLING", test: s => /[\u00AD\u200B-\u200D\uFEFF]/.test(s), sev: 75 },[span_14](end_span)[span_15](end_span)
    { label: "INFRA:DOCKER_API", test: s => /:(2375|2376)\/containers\/create/i.test(s) || [span_16](start_span)/"Binds":\s*\["C:\\:/i.test(s), sev: 100 }[span_16](end_span)
  ];

  let lastReport = null;

  function shannonEntropy(str) {
    if (!str) return 0;
    const freq = new Map();
    for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
    let ent = 0;
    for (const [, c] of freq) {
      const p = c / str.length;
      ent -= p * Math.log2(p);
    }
    return Math.round(ent * 100) / 100;
  }

  function runScan() {
    const input = $("input").value.split('\n').filter(l => l.trim());
    const rows = input.map(line => {
      const hits = RULES.filter(r => r.test(line));
      const severity = hits.length ? Math.max(...hits.map(h => h.sev)) : 0;
      const decision = severity >= 85 ? "BLOCK" : (severity >= 55 ? "WARN" : "ALLOW");
      return { line, decision, severity, entropy: shannonEntropy(line), hits };
    });

    lastReport = { generatedAt: new Date().toISOString(), rows };
    updateUI(rows);
  }

  function updateUI(rows) {
    const counts = { block: 0, warn: 0, scans: rows.length };
    const sigMap = new Map();

    $("rows").innerHTML = rows.map(r => {
      if (r.decision === "BLOCK") counts.block++;
      if (r.decision === "WARN") counts.warn++;
      r.hits.forEach(h => sigMap.set(h.label, (sigMap.get(h.label) || 0) + 1));
      
      return `
        <div class="vrow ${r.decision.toLowerCase()}">
          <div class="cell">${r.line}</div>
          <div class="cell dec">${r.decision}</div>
          <div class="cell">${r.severity}%</div>
          <div class="cell">${r.entropy}</div>
        </div>
      `;
    }).join("");

    $("kScans").textContent = counts.scans;
    $("kBlock").textContent = counts.block;
    $("kWarn").textContent = counts.warn;
    $("verdictText").textContent = counts.block > 0 ? "DANGER" : (counts.warn > 0 ? "SUSPICIOUS" : "SECURE");
    
    $("signals").innerHTML = [...sigMap.entries()].map(([l, c]) => `<div class="sig">${l} x${c}</div>`).join("");
  }

  function boot() {
    $("buildStamp").textContent = `Build: ${BUILD}`;
    $("btnScan").onclick = runScan;
    $("btnClear").onclick = () => { $("input").value = ""; updateUI([]); };
    $("btnExport").onclick = () => {
      if (!lastReport) return;
      const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "validoon_report.json";
      a.click();
    };
    $("btnInfo").onclick = () => $("infoDlg").classList.remove("hidden");
    $("btnCloseInfo").onclick = () => $("infoDlg").classList.add("hidden");
  }

  window.onload = boot;
})();
