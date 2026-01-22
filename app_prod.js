(() => {
  "use strict";

  const BUILD = "prod_v1.2.1_FINAL_STABLE";
  const $ = (id) => document.getElementById(id);

  // --- 2026 Strategic Rules based on DeepAgent Research ---
  const RULES = [
    [span_5](start_span)[span_6](start_span)[span_7](start_span){ label: "SSRF:DECIMAL_IP", test: s => /\b(2852039166|0xa9fea9fe|0251\.0376\.0251\.0376)\b/.test(s), sev: 95 },[span_5](end_span)[span_6](end_span)[span_7](end_span)
    { label: "SSRF:IMDSV2_BYPASS", test: s => /PUT\s+.*\/latest\/api\/token/i.test(s) || [span_8](start_span)[span_9](start_span)[span_10](start_span)/X-aws-ec2-metadata-token/i.test(s), sev: 95 },[span_8](end_span)[span_9](end_span)[span_10](end_span)
    [span_11](start_span)[span_12](start_span)[span_13](start_span){ label: "AI:INDIRECT_INJECTION", test: s => /\b(Ignore\s+all\s+previous\s+instructions|disregard\s+prior\s+rules)\b/i.test(s), sev: 90 },[span_11](end_span)[span_12](end_span)[span_13](end_span)
    [span_14](start_span)[span_15](start_span)[span_16](start_span){ label: "AI:MARKDOWN_EXFIL", test: s => /!\[.*\]\(https?:\/\/.*\/log\?c=.*\)/i.test(s), sev: 90 },[span_14](end_span)[span_15](end_span)[span_16](end_span)
    [span_17](start_span)[span_18](start_span)[span_19](start_span){ label: "BYPASS:TOKEN_SMUGGLING", test: s => /[\u00AD\u200B-\u200D\uFEFF]/.test(s), sev: 75 },[span_17](end_span)[span_18](end_span)[span_19](end_span)
    { label: "INFRA:DOCKER_API", test: s => /:(2375|2376)\/containers\/create/i.test(s) || [span_20](start_span)[span_21](start_span)[span_22](start_span)/"Binds":\s*\["C:\\:/i.test(s), sev: 100 }[span_20](end_span)[span_21](end_span)[span_22](end_span)
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
    const inputField = $("input");
    if (!inputField) return;
    const lines = inputField.value.split('\n').filter(l => l.trim());
    const rows = lines.map(line => {
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

    const container = $("rows");
    if (!container) return;

    container.innerHTML = rows.map(r => {
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

    if($("kScans")) $("kScans").textContent = counts.scans;
    if($("kBlock")) $("kBlock").textContent = counts.block;
    if($("kWarn")) $("kWarn").textContent = counts.warn;
    if($("verdictText")) $("verdictText").textContent = counts.block > 0 ? "DANGER" : (counts.warn > 0 ? "SUSPICIOUS" : "SECURE");
    if($("signals")) $("signals").innerHTML = [...sigMap.entries()].map(([l, c]) => `<div class="sig">${l} x${c}</div>`).join("");
  }

  function boot() {
    const stamp = $("buildStamp");
    if (stamp) stamp.textContent = `Build: ${BUILD}`;

    const btnScan = $("btnScan");
    if (btnScan) btnScan.addEventListener("click", runScan);

    const btnClear = $("btnClear");
    if (btnClear) btnClear.addEventListener("click", () => {
      if($("input")) $("input").value = "";
      updateUI([]);
    });

    const btnExport = $("btnExport");
    if (btnExport) btnExport.addEventListener("click", () => {
      if (!lastReport) return;
      const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "validoon_report.json";
      a.click();
    });

    const btnInfo = $("btnInfo");
    if (btnInfo) btnInfo.addEventListener("click", () => $("infoDlg")?.classList.remove("hidden"));
    
    const btnCloseInfo = $("btnCloseInfo");
    if (btnCloseInfo) btnCloseInfo.addEventListener("click", () => $("infoDlg")?.classList.add("hidden"));
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
