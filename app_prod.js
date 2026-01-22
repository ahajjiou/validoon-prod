// Validoon Logic Core - Global Definition for Maximum Reliability
window.lastReportData = null;

[span_5](start_span)[span_6](start_span)// 2026 Rules from Research[span_5](end_span)[span_6](end_span)
const VALIDOON_RULES = [
    [span_7](start_span){ label: "SSRF:DECIMAL_IP", test: s => /\b(2852039166|0xa9fea9fe|0251\.0376\.0251\.0376)\b/.test(s), sev: 95 },[span_7](end_span)
    { label: "SSRF:IMDSV2_BYPASS", test: s => /PUT\s+.*\/latest\/api\/token/i.test(s) || [span_8](start_span)/X-aws-ec2-metadata-token/i.test(s), sev: 95 },[span_8](end_span)
    [span_9](start_span){ label: "AI:INDIRECT_INJECTION", test: s => /\b(Ignore\s+all\s+previous\s+instructions|disregard\s+prior\s+rules)\b/i.test(s), sev: 90 },[span_9](end_span)
    [span_10](start_span)[span_11](start_span){ label: "AI:MARKDOWN_EXFIL", test: s => /!\[.*\]\(https?:\/\/.*\/log\?c=.*\)/i.test(s), sev: 90 },[span_10](end_span)[span_11](end_span)
    [span_12](start_span)[span_13](start_span){ label: "BYPASS:TOKEN_SMUGGLING", test: s => /[\u00AD\u200B-\u200D\uFEFF]/.test(s), sev: 75 },[span_12](end_span)[span_13](end_span)
    { label: "INFRA:DOCKER_API", test: s => /:(2375|2376)\/containers\/create/i.test(s) || [span_14](start_span)/"Binds":\s*\["C:\\:/i.test(s), sev: 100 }[span_14](end_span)
];

function calculateEntropy(str) {
    if (!str) return 0;
    const freq = {};
    for (let ch of str) freq[ch] = (freq[ch] || 0) + 1;
    let ent = 0;
    for (let ch in freq) {
        let p = freq[ch] / str.length;
        ent -= p * Math.log2(p);
    }
    return ent.toFixed(2);
}

// Global functions accessible by HTML
window.runValidoonScan = function() {
    const inputArea = document.getElementById("input");
    if (!inputArea) return;
    
    const lines = inputArea.value.split('\n').filter(l => l.trim() !== "");
    const rows = lines.map(line => {
        const hits = VALIDOON_RULES.filter(r => r.test(line));
        const severity = hits.length ? Math.max(...hits.map(h => h.sev)) : 0;
        const decision = severity >= 85 ? "BLOCK" : (severity >= 55 ? "WARN" : "ALLOW");
        return { line, decision, severity, entropy: calculateEntropy(line), hits };
    });

    window.lastReportData = { generatedAt: new Date().toISOString(), rows };
    updateValidoonUI(rows);
};

function updateValidoonUI(rows) {
    const counts = { block: 0, warn: 0, scans: rows.length };
    const sigMap = new Map();

    document.getElementById("rows").innerHTML = rows.map(r => {
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

    document.getElementById("kScans").textContent = counts.scans;
    document.getElementById("kBlock").textContent = counts.block;
    document.getElementById("kWarn").textContent = counts.warn;
    document.getElementById("verdictText").textContent = counts.block > 0 ? "DANGER" : (counts.warn > 0 ? "SUSPICIOUS" : "SECURE");
    document.getElementById("peakSev").textContent = rows.length ? Math.max(...rows.map(r => r.severity)) + "%" : "0%";
    
    document.getElementById("signals").innerHTML = [...sigMap.entries()].map(([l, c]) => `<div class="sig">${l} x${c}</div>`).join("");
}

window.clearValidoonApp = function() {
    document.getElementById("input").value = "";
    updateValidoonUI([]);
};

window.exportValidoonReport = function() {
    if (!window.lastReportData) return alert("Please run a scan first.");
    const blob = new Blob([JSON.stringify(window.lastReportData, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "validoon_intel_report.json";
    a.click();
};

window.toggleInfoModal = function(show) {
    const dlg = document.getElementById("infoDlg");
    if (dlg) show ? dlg.classList.remove("hidden") : dlg.classList.add("hidden");
};
