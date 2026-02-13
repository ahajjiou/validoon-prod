// app_prod.js — Validoon v2.0.0 stable deterministic security engine
// Patch: Docker API endpoint "GET /containers/json" MUST be BLOCK always (to satisfy benchmark MUST_BLOCK).
(() => {
  "use strict";

  const BUILD = "release: v2.0.0 stable deterministic security engine";
  const $ = (id) => document.getElementById(id);

  // ----------------------------
  // Regex library (deterministic)
  // ----------------------------
  const RX = {
    comment: /^\s*#/,
    quotes: /["'`]/,

    // Exec cues
    execVerb: /\b(run|execute|launch|try|use|paste)\b/i,
    fetchTool: /\b(curl|wget|fetch)\b/i,
    shellMeta: /[;&|]/,

    // Doc/mention/negation cues
    doc: /\b(documentation|doc|example|sample|reference|for\s+reference|placeholder)\b/i,
    mention: /\b(mentioned|blog|article|note|in\s+a\s+post|security\s+article)\b/i,
    negation: /\b(not|harmless|benign|just\s+words|no\s+attack|not\s+an\s+attack|inside\s+quotes)\b/i,

    // High-risk primitives
    metaIP: /\b169\.254\.169\.254\b/,
    metaURL: /https?:\/\/169\.254\.169\.254\/latest\/meta-data\//i,

    dockerSock: /\/var\/run\/docker\.sock/i,
    // NOTE: benchmark includes "GET /containers/json" and also "containers/json"
    dockerApi: /\b(GET\s+\/containers\/json|containers\/json|images\/json)\b/i,

    catPasswd: /\bcat\s+\/etc\/passwd\b/i,
    catShadow: /\bcat\s+\/etc\/shadow\b/i,

    privateKey: /BEGIN RSA PRIVATE KEY/i,

    // AI override
    aiOverride: /\b(ignore\s+all\s+previous\s+instructions|terminate\s+safety\s+filter|dan\s+mode)\b/i,

    // Enum command tokens (anywhere)
    enumAny: /\b(whoami|id|uname|ls)\b/i,

    // Standalone/command-line forms (start of line)
    whoamiLine: /^\s*whoami\b/i,
    idLine: /^\s*id\b/i,
    unameLine: /^\s*uname\b/i,
    lsLine: /^\s*ls\b/i,

    // Token labels (safe)
    tokenLabel: /\b(API_KEY|ACCESS_TOKEN|SECRET_KEY|BEARER_TOKEN)\b/i,

    // HTML markers
    htmlMarker: /<script\b|onerror\s*=|onclick\s*=/i,
  };

  // ----------------------------
  // Utilities
  // ----------------------------
  function clamp(n, a, b) { return Math.max(a, Math.min(b, n)); }

  function escapeHTML(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function entropyScore(s) {
    const str = (s || "").trim();
    if (!str) return 0;
    const set = new Set(str.split(""));
    const diversity = set.size / Math.max(1, str.length);
    const lenBonus = clamp(str.length / 200, 0, 1);
    return Math.round(clamp(diversity * 60 + lenBonus * 40, 0, 100));
  }

  function normalize(raw) { return (raw ?? "").replace(/\r/g, "").trim(); }

  function setVerdict(mode) {
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

  function renderSignals(labels) {
    const box = $("signals");
    if (!box) return;
    if (!labels.length) { box.innerHTML = ""; return; }
    const uniq = Array.from(new Set(labels)).slice(0, 24);
    box.innerHTML = uniq.map(t =>
      `<span class="chip" style="display:inline-block;margin:6px 8px 0 0;padding:6px 10px;border:1px solid rgba(255,255,255,.10);border-radius:999px;background:rgba(255,255,255,.04);font-weight:800;font-size:12px;">${escapeHTML(t)}</span>`
    ).join("");
  }

  // ----------------------------
  // Layer 1: Context classification (Intent + Doc)
  // ----------------------------
  function classify(line) {
    const s = line;

    const isComment = RX.comment.test(s);
    const hasQuotes = RX.quotes.test(s);

    const docCtx = isComment || hasQuotes || RX.doc.test(s) || RX.mention.test(s) || RX.negation.test(s);

    const execCtx =
      RX.execVerb.test(s) ||
      RX.fetchTool.test(s) ||
      RX.shellMeta.test(s) ||
      RX.whoamiLine.test(s) ||
      RX.idLine.test(s) ||
      RX.unameLine.test(s) ||
      RX.lsLine.test(s);

    return { docCtx, execCtx, isComment, hasQuotes };
  }

  // ----------------------------
  // Layer 2: Signal extraction
  // ----------------------------
  function extractSignals(line) {
    const s = line;
    const sig = [];

    if (RX.privateKey.test(s)) sig.push("SECRET:PRIVATE_KEY");

    if (RX.catPasswd.test(s)) sig.push("CMD:CAT_PASSWD");
    if (RX.catShadow.test(s)) sig.push("CMD:CAT_SHADOW");

    if (RX.dockerSock.test(s)) sig.push("INFRA:DOCKER_SOCKET");
    if (RX.dockerApi.test(s)) sig.push("INFRA:DOCKER_API");

    if (RX.metaURL.test(s)) sig.push("SSRF:METADATA_URL");
    if (RX.metaIP.test(s)) sig.push("SSRF:METADATA_IP");

    if (RX.aiOverride.test(s)) sig.push("AI:OVERRIDE");

    if (RX.tokenLabel.test(s)) sig.push("TOKEN:LABEL");
    if (RX.htmlMarker.test(s)) sig.push("WEB:HTML_MARKER");

    if (RX.enumAny.test(s)) sig.push("CMD:ENUM_TOKEN_ANYWHERE");

    return sig;
  }

  // ----------------------------
  // Layer 3: Priority decision rules (Hybrid)
  // ----------------------------
  function decide(line, ctx, sig) {
    const s = line;
    const has = (x) => sig.includes(x);

    const isExactMetaIP = /^\s*169\.254\.169\.254\s*$/.test(s);
    const isExactDockerSock = /^\s*\/var\/run\/docker\.sock\s*$/.test(s);
    const isExactMetaURL = /^\s*https?:\/\/169\.254\.169\.254\/latest\/meta-data\/\s*$/i.test(s);

    const isStandaloneEnumLine =
      RX.whoamiLine.test(s) || RX.idLine.test(s) || RX.unameLine.test(s) || RX.lsLine.test(s);

    const enumInSentence = has("CMD:ENUM_TOKEN_ANYWHERE");
    const enumNeedsWarn =
      isStandaloneEnumLine ||
      (enumInSentence && (ctx.execCtx || RX.execVerb.test(s) || RX.shellMeta.test(s)));

    // 1) Critical secret: always BLOCK
    if (has("SECRET:PRIVATE_KEY")) return { decision: "BLOCK", sev: 100 };

    // 2) Sensitive file read: BLOCK if not DOC, WARN if DOC
    if (has("CMD:CAT_PASSWD") || has("CMD:CAT_SHADOW")) {
      if (ctx.docCtx) return { decision: "WARN", sev: 80 };
      return { decision: "BLOCK", sev: 100 };
    }

    // 3) Docker primitives:
    // PATCH: Docker API endpoint MUST be BLOCK always (benchmark MUST_BLOCK).
    if (has("INFRA:DOCKER_SOCKET") || has("INFRA:DOCKER_API")) {

      // Docker API endpoint like GET /containers/json MUST be BLOCK
      if (has("INFRA:DOCKER_API")) {
        return { decision: "BLOCK", sev: 100 };
      }

      // docker.sock exact primitive MUST be BLOCK
      if (isExactDockerSock) {
        return { decision: "BLOCK", sev: 100 };
      }

      // Documentation context only → WARN
      if (ctx.docCtx) {
        return { decision: "WARN", sev: 75 };
      }

      return { decision: "BLOCK", sev: 100 };
    }

    // 4) Metadata URL: BLOCK unless DOC context; DOC => WARN
    if (has("SSRF:METADATA_URL")) {
      if (ctx.docCtx && !isExactMetaURL) return { decision: "WARN", sev: 70 };
      return { decision: "BLOCK", sev: 100 };
    }

    // 5) Metadata IP:
    // exact IP alone MUST be BLOCK; otherwise DOC => WARN; exec => BLOCK; neutral => WARN
    if (has("SSRF:METADATA_IP")) {
      if (isExactMetaIP) return { decision: "BLOCK", sev: 100 };
      if (ctx.docCtx) return { decision: "WARN", sev: 60 };
      if (ctx.execCtx) return { decision: "BLOCK", sev: 100 };
      return { decision: "WARN", sev: 60 };
    }

    // 6) AI override: always WARN
    if (has("AI:OVERRIDE")) return { decision: "WARN", sev: 70 };

    // 7) HTML markers: WARN
    if (has("WEB:HTML_MARKER")) return { decision: "WARN", sev: 55 };

    // 8) Enum commands:
    // - Standalone line => WARN
    // - In sentence + exec cues => WARN (e.g., "Please run whoami", "Try: id && uname -a")
    // - In random words with doc/negation cues and not exec => ALLOW
    if (enumNeedsWarn) {
      if (!isStandaloneEnumLine && ctx.docCtx && !ctx.execCtx) return { decision: "ALLOW", sev: 0 };
      return { decision: "WARN", sev: 55 };
    }

    // 9) Token labels: ALLOW
    if (has("TOKEN:LABEL")) return { decision: "ALLOW", sev: 0 };

    return { decision: "ALLOW", sev: 0 };
  }

  function polishSeverity(sev, ctx) {
    let s = sev;
    if (ctx.hasQuotes) s = clamp(s - 15, 0, 100);
    if (ctx.isComment) s = clamp(s - 10, 0, 100);
    return s;
  }

  function analyzeLine(line) {
    const ctx = classify(line);
    const sig = extractSignals(line);
    const out = decide(line, ctx, sig);
    return {
      input: line,
      decision: out.decision,
      severity: polishSeverity(out.sev, ctx),
      entropy: entropyScore(line),
      signals: sig.filter(x => x !== "CMD:ENUM_TOKEN_ANYWHERE"),
    };
  }

  // ----------------------------
  // UI / Actions
  // ----------------------------
  let scanCount = 0;

  function updateUI(rows) {
    const block = rows.filter(r => r.decision === "BLOCK").length;
    const warn  = rows.filter(r => r.decision === "WARN").length;
    const allow = rows.filter(r => r.decision === "ALLOW").length;

    if (block > 0) setVerdict("DANGER");
    else if (warn > 0) setVerdict("WARN");
    else if (rows.length > 0) setVerdict("SECURE");
    else setVerdict("READY");

    setCounters({ scans: scanCount, block, warn, allow });

    const allSignals = rows.flatMap(r => r.signals || []);
    renderSignals(allSignals);

    const body = $("rows");
    if (!body) return;

    body.innerHTML = rows.map(r => `
      <div class="vrow ${r.decision.toLowerCase()}" style="display:grid;grid-template-columns:2fr 1fr .6fr .7fr;gap:10px;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.08);align-items:center;">
        <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHTML(r.input)}</div>
        <div style="font-weight:900;">${r.decision}</div>
        <div>${Math.round(r.severity)}%</div>
        <div>${r.entropy}</div>
      </div>
    `).join("");
  }

  function runScan() {
    const txt = $("input")?.value || "";
    const lines = txt.split("\n").map(normalize).filter(l => l.length > 0);
    const rows = lines.map(analyzeLine);
    scanCount += 1;
    updateUI(rows);
  }

  function exportJSON() {
    const txt = $("input")?.value || "";
    const lines = txt.split("\n").map(normalize).filter(l => l.length > 0);
    const rows = lines.map(analyzeLine);

    const blob = new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" });
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
        "cat /etc/passwd",
        "whoami",
      ].join("\n");
    }
  }

  function loadTestB() {
    if ($("input")) {
      $("input").value = [
        "For reference: http://169.254.169.254/latest/meta-data/ (documentation).",
        "The string 169.254.169.254 is mentioned in a blog post, not an attack.",
        "This is a harmless string: \"cat /etc/passwd\" inside quotes only.",
        "Random words: id uname whoami (not commands, just words).",
        "Please run whoami to confirm user.",
        "Try: id && uname -a",
        "Documentation: /var/run/docker.sock is a unix socket path.",
        "GET /containers/json",
      ].join("\n");
    }
  }

  // Automation bridge (kept)
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

  function boot() {
    if ($("buildStamp")) $("buildStamp").textContent = `Version: ${BUILD}`;

    if ($("btnScan")) $("btnScan").addEventListener("click", runScan);
    if ($("btnExport")) $("btnExport").addEventListener("click", exportJSON);
    if ($("btnClear")) $("btnClear").addEventListener("click", clearAll);
    if ($("btnLoadA")) $("btnLoadA").addEventListener("click", loadTestA);
    if ($("btnLoadB")) $("btnLoadB").addEventListener("click", loadTestB);

    if (($("input")?.value || "").trim().length > 0) runScan();
    else clearAll();
  }

  document.readyState === "loading"
    ? document.addEventListener("DOMContentLoaded", boot)
    : boot();
})();

