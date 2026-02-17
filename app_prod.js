/* =========================================================
   VALIDOON v2.1.0 — ENTERPRISE INTELLIGENCE EDITION
   Explainability + Threat Visualization Layer
   Deterministic • Local • Versioned
========================================================= */

(() => {
"use strict";

/* -------------------------
   Threat Classification Map
-------------------------- */

const THREAT_MAP = {
  "CMD-CAT-PASSWD": { type: "Privilege Enumeration", severity: "High" },
  "CMD-CAT-SHADOW": { type: "Credential Access", severity: "Critical" },
  "CMD-WHOAMI": { type: "Execution Probe", severity: "Medium" },
  "CMD-ID": { type: "Execution Probe", severity: "Medium" },
  "CMD-UNAME": { type: "Reconnaissance", severity: "Low" },
  "SSRF-METADATA-IP": { type: "Cloud Metadata Abuse", severity: "High" },
  "SSRF-METADATA-URL": { type: "Cloud Metadata Abuse", severity: "Critical" },
  "INFRA-DOCKER-SOCKET": { type: "Container Escape Vector", severity: "Critical" },
  "SECRET-PRIVATE-KEY": { type: "Sensitive Key Exposure", severity: "Critical" },
  "AI-OVERRIDE": { type: "Prompt Injection / Override", severity: "High" }
};

/* -------------------------
   Severity Weight
-------------------------- */

const SEVERITY_WEIGHT = {
  "Low": 10,
  "Medium": 25,
  "High": 50,
  "Critical": 80
};

/* -------------------------
   Scan Hook
-------------------------- */

document.getElementById("executeScan")?.addEventListener("click", () => {
  setTimeout(() => {
    injectThreatVisualization();
    injectExplainabilityLayer();
  }, 50);
});

/* -------------------------
   Threat Intelligence Layer
-------------------------- */

function injectThreatVisualization() {

  const signals = document.querySelectorAll(".active-signal-badge");
  let score = 0;
  let breakdown = {};

  signals.forEach(badge => {
    const key = badge.innerText.trim();
    const threat = THREAT_MAP[key];
    if (threat) {
      score += SEVERITY_WEIGHT[threat.severity] || 0;
      breakdown[threat.type] = (breakdown[threat.type] || 0) + 1;
    }
  });

  const normalized = Math.min(100, score);

  renderThreatBar(normalized);
  renderThreatBreakdown(breakdown);
}

function renderThreatBar(score) {

  let container = document.getElementById("threatScoreBar");
  if (!container) {
    container = document.createElement("div");
    container.id = "threatScoreBar";
    container.style.marginTop = "12px";
    document.querySelector(".ready-box, .danger-box")?.appendChild(container);
  }

  const level =
    score < 20 ? "LOW" :
    score < 50 ? "MEDIUM" :
    score < 80 ? "HIGH" :
    "CRITICAL";

  container.innerHTML = `
    <div style="font-size:13px;margin-bottom:6px;">
      Threat Intelligence Score: <strong>${score}%</strong> (${level})
    </div>
    <div style="height:8px;background:#1f2937;border-radius:6px;overflow:hidden;">
      <div style="height:100%;width:${score}%;
        background:linear-gradient(90deg,#22c55e,#facc15,#f97316,#ef4444);
        transition:width .3s;"></div>
    </div>
  `;
}

function renderThreatBreakdown(map) {

  let panel = document.getElementById("threatBreakdown");
  if (!panel) {
    panel = document.createElement("div");
    panel.id = "threatBreakdown";
    panel.style.marginTop = "12px";
    document.querySelector(".ready-box, .danger-box")?.appendChild(panel);
  }

  let html = "<div style='font-size:13px;margin-bottom:6px;'>Threat Categories</div>";

  Object.keys(map).forEach(type => {
    html += `
      <div style="font-size:12px;opacity:.85;margin-bottom:4px;">
        • ${type} (${map[type]})
      </div>
    `;
  });

  panel.innerHTML = html;
}

/* -------------------------
   Explainability Layer
-------------------------- */

function injectExplainabilityLayer() {

  const rows = document.querySelectorAll(".result-row");

  rows.forEach(row => {

    const decision = row.querySelector(".decision")?.innerText;
    const ruleBadge = row.querySelector(".rule-badge")?.innerText;

    if (!ruleBadge || !THREAT_MAP[ruleBadge]) return;

    const threat = THREAT_MAP[ruleBadge];

    let explain = row.querySelector(".explain-panel");
    if (!explain) {
      explain = document.createElement("div");
      explain.className = "explain-panel";
      explain.style.fontSize = "12px";
      explain.style.opacity = "0.85";
      explain.style.marginTop = "6px";
      row.appendChild(explain);
    }

    explain.innerHTML = `
      <div>Type: <strong>${threat.type}</strong></div>
      <div>Severity: ${threat.severity}</div>
      <div>Rule Triggered: ${ruleBadge}</div>
      <div>Decision Reason: Matched deterministic security rule.</div>
      <div>Confidence: High (rule-based deterministic match)</div>
    `;
  });
}

})();
