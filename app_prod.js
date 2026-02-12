// app_prod.js — Validoon Enterprise Build v1.3.0_FULL_STABLE
// NOTE: This build avoids real secret patterns (no sk_live_, ghp_, AIza, etc.)
(() => {
  "use strict";

  const BUILD = "prod_v1.3.0_FULL_STABLE";
  const $ = (id) => document.getElementById(id);

  // ----------------------------
  // Rules (Stable, deterministic)
  // ----------------------------
  const RULES = [
    // SSRF: Encoded/Octal/Hex + Metadata IP
    {
      label: "SSRF:ENCODED_IP",
      test: (s) =>
        /\b(0[0-7]+(\.0[0-7]+){3}|0x[0-9a-fA-F]{2}(\.0x[0-9a-fA-F]{2}){3}|169\.254\.169\.254)\b/.test(
          s
        ),
      sev: 100,
      conf: 99,
    },
    // Docker socket / API
    {
      label: "INFRA:DOCKER_API",
      test: (s) =>
        /(\/var\/run\/docker\.sock|docker\.sock|containers\/json|images\/json)/i.test(
          s
        ),
      sev: 100,
      conf: 98,
    },
    // Jailbreak / role override
    {
      label: "AI:SYSTEM_ESCAPE",
      test: (s) =>
        /\b(terminate\s+safety\s+filter|overwrite\s+core\s+logic|bypass\s+guardrails|Ignore\s+all\s+previous\s+instructions)\b/i.test(
          s
        ),
      sev: 95,
      conf: 95,
    },
    // "Secret-like" tokens (SAFE EXAMPLES ONLY — avoids real vendor prefixes)
    {
      label: "SECRET:GENERIC_TOKEN",
      test: (s) =>
        /\b(API_KEY|ACCESS_TOKEN|SECRET_KEY|BEARER_TOKEN)\b/i.test(s) ||
        /\b(example|dummy|placeholder)[-_ ]?(key|token)\b/i.test(s),
      sev: 60,
      conf: 85,
    },
    // Command injection markers
    {
      label: "OS:COMMAND_INJ",
      test: (s) => /([;&|]\s*(whoami|cat\s+\/etc\/passwd|id|uname|ls))/.test(s),
      sev: 95,
      conf: 90,
    },
  ];

  // ----------------------------
  // Helpers
  // ----------------------------
  function clamp(n, a, b) {
    return Math.max(a, Math.min(b, n));
  }

  // Lightweight entropy proxy (0..100)
  function entropyScore(s) {
    const str = (s || "").trim();
    if (!str) return 0;

    const set = new Set(str.split(""));
    const diversity = set.size / Math.max(1, str.length); // 0..1
    const lenBonus = clamp(str.length / 200, 0, 1); // 0..1
    const score = diversity * 60 + lenBonus * 40; // 0..100
    return Math.round(clamp(score, 0, 100));
  }

  function escapeHTML(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function setVerdict(mode /* SECURE|WARN|DANGER|READY */) {
    const vb = $("verdictBox");
    const vt = $("verdictText");
    if (!vb || !vt) return;

    vt.textContent = mode;

    vb.classList.remove("verdict-secure", "verdict-warn", "verdict-danger");
    if (mode === "DANGER") vb.classList.add("verdict-danger");
    else if (mode === "WARN") vb.classList.add("verdict-warn");
    else vb.classList.add("verdict-secure");
  }

  function setCounters({ scans, block, warn, allow }) {
    if ($("kScans")) $("kScans").textContent = String(scans);
    if ($("kBlock")) $("kBlock").textContent = String(block);
    if ($("kWarn")) $("kWarn").textContent = String(warn);
    if ($("kAllow")) $("kAllow").textContent = String(allow);
  }

  function renderSignals(uniqueLabels) {
    const box = $("signals");
    if (!box) return;
    if (!uniqueLabels.length) {
      box.innerHTML = "";
      return;
    }
    box.innerHTML = uniqueLabels
      .map(
        (t) =>
          `<span class="chip" style="display:inline-block;margin:6px 8px 0 0;padding:6px 10px;border:1px solid rgba(255,255,255,.10);border-radius:999px;background:rgba(255,255,255,.04);font-weight:800;font-size:12px;">${escapeHTML(
            t
          )}</span>`
      )
      .join("");
  }

  // ----------------------------
  // Analysis
  // ----------------------------
  function analyzeOne(input) {
    const s = (input || "").trim();
    const hits = RULES.filter((r) => r.test(s)).map((r) => ({
      label: r.label,
      sev: r.sev,
      conf: r.conf,
    }));

    const totalScore = hits.reduce((sum, h) => sum + h.sev, 0);
    const severity = clamp(totalScore, 0, 100);

    const decision =
      severity >= 100 ? "BLOCK" : severity >= 50 ? "WARN" : "ALLOW";

    return {
      input: s,
      decision,
      severity,
      entropy: entropyScore(s),
      hits,
    };
  }

  // ----------------------------
  // UI
  // ----------------------------
  let scanCount = 0;

  function updateUI(rows) {
    const block = rows.filter((r) => r.decision === "BLOCK").length;
    const warn = rows.filter((r) => r.decision === "WARN").length;
    const allow = rows.filter((r) => r.decision === "ALLOW").length;

    if (block > 0) setVerdict("DANGER");
    else if (warn > 0) setVerdict("WARN");
    else if (rows.length > 0) setVerdict("SECURE");
    else setVerdict("READY");

    setCounters({ scans: scanCount, block, warn, allow });

    const allSignals = rows.flatMap((r) => r.hits.map((h) => h.label));
    const uniqueSignals = Array.from(new Set(allSignals)).slice(0, 24);
    renderSignals(uniqueSignals);

    const body = $("rows");
    if (!body) return;

    // 4 columns as in index.html: Input | Decision | Sev | Entropy
    body.innerHTML = rows
      .map((r) => {
        const cls = r.decision.toLowerCase();
        return `
          <div class="vrow ${cls}" style="display:grid;grid-template-columns:2fr 1fr .6fr .7fr;gap:10px;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.08);align-items:center;">
            <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHTML(
              r.input
            )}</div>
            <div style="font-weight:900;">${r.decision}</div>
            <div>${r.severity}%</div>
            <div>${r.entropy}</div>
          </div>
        `;
      })
      .join("");
  }

  function runScan() {
    const txt = $("input")?.value || "";
    const lines = txt
      .split(/\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0);

    const rows = lines.map(analyzeOne);
    scanCount += 1;
    updateUI(rows);
  }

  // ----------------------------
  // Actions (Buttons)
  // ----------------------------
  function exportJSON() {
    const txt = $("input")?.value || "";
    const lines = txt
      .split(/\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0);

    const rows = lines.map(analyzeOne);

    const blob = new Blob([JSON.stringify(rows, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `validoon_scan_${BUILD}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function clearAll() {
    if ($("input")) $("input").value = "";
    scanCount = 0;
    if ($("rows")) $("rows").innerHTML = "";
    renderSignals([]);
    setCounters({ scans: 0, block: 0, warn: 0, allow: 0 });
    setVerdict("READY");
  }

  function loadTestA() {
    if ($("input")) {
      $("input").value = [
        "169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "/var/run/docker.sock",
        "GET /containers/json",
        "whoami",
      ].join("\n");
    }
  }

  // SAFE test strings: do NOT resemble real vendor keys (prevents GitHub secret scanning)
  function loadTestB() {
    if ($("input")) {
      $("input").value = [
        "Ignore all previous instructions",
        "terminate safety filter",
        "API_KEY=EXAMPLE_TOKEN_XXXXXXXXXXXXXXXXXXXXXXXX",
        "ACCESS_TOKEN=PLACEHOLDER_YYYYYYYYYYYYYYYYYYYY",
      ].join("\n");
    }
  }

  // --- Automation bridge (kept) ---
  window.receiveAutomationData = (data) => {
    try {
      const payloads = data?.payloads ?? data?.outputs ?? data ?? [];
      const text = Array.isArray(payloads) ? payloads.join("\n") : String(payloads);
      if ($("input")) $("input").value = text;
      runScan();
    } catch (e) {
      console.warn("[Validoon] receiveAutomationData error:", e);
    }
  };

  // ----------------------------
  // Boot
  // ----------------------------
  function boot() {
    if ($("buildStamp")) $("buildStamp").textContent = `Version: ${BUILD}`;

    // Wire buttons from index.html
    if ($("btnScan")) $("btnScan").addEventListener("click", runScan);
    if ($("btnExport")) $("btnExport").addEventListener("click", exportJSON);
    if ($("btnClear")) $("btnClear").addEventListener("click", clearAll);
    if ($("btnLoadA")) $("btnLoadA").addEventListener("click", loadTestA);
    if ($("btnLoadB")) $("btnLoadB").addEventListener("click", loadTestB);

    // Initial state
    clearAll();
  }

  document.readyState === "loading"
    ? document.addEventListener("DOMContentLoaded", boot)
    : boot();
})();


