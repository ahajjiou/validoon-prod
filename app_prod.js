// app_prod.js — Validoon v1.6.0_NEGATION_CONTEXT_ENGINE
(() => {
  "use strict";

  const BUILD = "prod_v1.6.0_NEGATION_CONTEXT_ENGINE";
  const $ = (id) => document.getElementById(id);

  const THRESHOLDS = { BLOCK: 100, WARN: 50 };

  const W = {
    EXEC_INTENT: 35,
    SHELL_META: 25,
    QUOTED: -35,
    COMMENT: -20,

    // Context semantics
    DOC_REF: -35,        // documentation/reference/example
    MENTION_CTX: -30,    // mentioned/blog/article/note
    NEGATION_CTX: -25,   // not/harmless/benign/just words/no attack
    DISCLAIMER_CTX: -20, // for reference/placeholder/sample
    STRONG_EXEC: 20,     // explicit "run/execute/try/curl/fetch"

    // Signals
    CMD_READ_SENSITIVE: 80,
    CMD_ENUM: 45,
    DOCKER_SOCKET: 85,
    DOCKER_API: 70,
    METADATA_IP: 85,
    METADATA_URL: 90,
    PRIVATE_KEY: 100,
    AI_OVERRIDE: 70,
    TOKEN_LABEL: 15,
    HTML_MARKER: 10,
  };

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
    box.innerHTML = labels.slice(0, 24).map(t =>
      `<span class="chip" style="display:inline-block;margin:6px 8px 0 0;padding:6px 10px;border:1px solid rgba(255,255,255,.10);border-radius:999px;background:rgba(255,255,255,.04);font-weight:800;font-size:12px;">${escapeHTML(t)}</span>`
    ).join("");
  }

  function normalize(raw) {
    return (raw ?? "").replace(/\r/g, "").trim();
  }

  // ---- Context semantics (B) ----
  function semanticContext(line) {
    const s = line;

    const isComment = /^\s*#/.test(s);

    // Quotes (downgrade)
    const hasQuotes = /["'`]/.test(s);
    const isMostlyQuoted = /["'`].+["'`]/.test(s);

    // Strong execution cues
    const hasExecVerb = /\b(run|execute|launch|try|use|paste)\b/i.test(s);
    const hasFetchTool = /\b(curl|wget|fetch)\b/i.test(s);
    const hasStrongExec = hasExecVerb || hasFetchTool;

    // Shell operators
    const hasShellMeta = /[;&|]/.test(s);

    // Documentation / reference / mention language (downgrade)
    const isDocRef = /\b(documentation|doc|example|sample|reference|for\s+reference|placeholder)\b/i.test(s);
    const isMention = /\b(mentioned|blog|article|note|in\s+a\s+post|security\s+article)\b/i.test(s);

    // Negation / harmless language (downgrade)
    const hasNegation = /\b(not|harmless|benign|just\s+words|no\s+attack|not\s+an\s+attack|only)\b/i.test(s);

    // Looks like a standalone command (upgrade only if starts with tool/command)
    const startsCommand = /^\s*(cat|whoami|id|uname|ls|curl|wget|docker|kubectl|fetch)\b/i.test(s);

    return {
      isComment,
      hasQuotes,
      isMostlyQuoted,
      hasShellMeta,
      hasStrongExec,
      isDocRef,
      isMention,
      hasNegation,
      startsCommand,
    };
  }

  // ---- Signals ----
  function detectSignals(line) {
    const s = line;
    const sig = [];

    if (/\bcat\s+\/etc\/passwd\b/i.test(s)) sig.push({ label: "CMD:CAT_PASSWD", w: W.CMD_READ_SENSITIVE, kind: "CMD" });
    if (/\bcat\s+\/etc\/shadow\b/i.test(s)) sig.push({ label: "CMD:CAT_SHADOW", w: W.CMD_READ_SENSITIVE, kind: "CMD" });

    // Enumeration: keep strict: match standalone or start-of-line usage
    if (/^\s*whoami\s*$/i.test(s) || /^\s*whoami\b/i.test(s)) sig.push({ label: "CMD:WHOAMI", w: W.CMD_ENUM, kind: "CMD" });
    if (/^\s*id\s*$/i.test(s) || /^\s*id\b/i.test(s)) sig.push({ label: "CMD:ID", w: W.CMD_ENUM, kind: "CMD" });
    if (/^\s*uname(\s+-a)?\s*$/i.test(s) || /^\s*uname\b/i.test(s)) sig.push({ label: "CMD:UNAME", w: W.CMD_ENUM, kind: "CMD" });
    if (/^\s*ls\b/i.test(s)) sig.push({ label: "CMD:LS", w: W.CMD_ENUM, kind: "CMD" });

    if (/\/var\/run\/docker\.sock/i.test(s) || /\bdocker\.sock\b/i.test(s)) sig.push({ label: "INFRA:DOCKER_SOCKET", w: W.DOCKER_SOCKET, kind: "INFRA" });
    if (/\bcontainers\/json\b/i.test(s) || /\bimages\/json\b/i.test(s)) sig.push({ label: "INFRA:DOCKER_API", w: W.DOCKER_API, kind: "INFRA" });

    const hasMetaIP = /\b169\.254\.169\.254\b/.test(s);
    if (hasMetaIP) sig.push({ label: "SSRF:METADATA_IP", w: W.METADATA_IP, kind: "META" });

    const hasMetaURL = /https?:\/\/169\.254\.169\.254\/latest\/meta-data\//i.test(s);
    if (hasMetaURL) sig.push({ label: "SSRF:METADATA_URL", w: W.METADATA_URL, kind: "META" });

    if (/BEGIN RSA PRIVATE KEY/i.test(s)) sig.push({ label: "SECRET:PRIVATE_KEY", w: W.PRIVATE_KEY, kind: "SECRET" });

    if (/\b(ignore\s+all\s+previous\s+instructions|terminate\s+safety\s+filter|dan\s+mode)\b/i.test(s)) {
      sig.push({ label: "AI:OVERRIDE", w: W.AI_OVERRIDE, kind: "AI" });
    }

    if (/\b(API_KEY|ACCESS_TOKEN|SECRET_KEY|BEARER_TOKEN)\b/i.test(s)) {
      sig.push({ label: "TOKEN:LABEL", w: W.TOKEN_LABEL, kind: "TOKEN" });
    }

    if (/<script\b|onerror\s*=|onclick\s*=/i.test(s)) {
      sig.push({ label: "WEB:HTML_MARKER", w: W.HTML_MARKER, kind: "WEB" });
    }

    return sig;
  }

  // ---- Gating Rules (core of option B) ----
  // Convert some would-be BLOCK signals to WARN when they are clearly "reference/mention/negation/quoted"
  function applyGating(line, ctx, sig, baseScore) {
    let score = baseScore;

    const hasMeta = sig.some(x => x.kind === "META");
    const hasCmd  = sig.some(x => x.kind === "CMD");
    const hasInfra= sig.some(x => x.kind === "INFRA");

    // Global downgrades
    if (ctx.isComment) score += W.COMMENT;
    if (ctx.hasQuotes) score += Math.round(W.QUOTED * (ctx.isMostlyQuoted ? 1.0 : 0.6));

    if (ctx.isDocRef) score += W.DOC_REF;
    if (ctx.isMention) score += W.MENTION_CTX;
    if (ctx.hasNegation) score += W.NEGATION_CTX;

    if (ctx.hasShellMeta) score += W.SHELL_META;
    if (ctx.hasStrongExec) score += (W.EXEC_INTENT + W.STRONG_EXEC);
    else if (ctx.startsCommand && !ctx.isDocRef && !ctx.isMention) score += W.EXEC_INTENT;

    // Special: Metadata in doc/mention/negation context should not be BLOCK unless strongly executed.
    if (hasMeta && (ctx.isDocRef || ctx.isMention || ctx.hasNegation || ctx.hasQuotes) && !ctx.hasStrongExec) {
      // Hard cap to WARN range if it would be BLOCK
      score = Math.min(score, THRESHOLDS.BLOCK - 1);
    }

    // Special: Random-word sentence should not become BLOCK just because it contains cmd words.
    // If not startsCommand and hasCmd and (doc/mention/negation) -> cap to WARN.
    if (hasCmd && !ctx.startsCommand && (ctx.isDocRef || ctx.isMention || ctx.hasNegation || ctx.hasQuotes) && !ctx.hasStrongExec) {
      score = Math.min(score, THRESHOLDS.BLOCK - 1);
    }

    // Infra (docker) reference in documentation should not BLOCK unless it starts as actual path/endpoint or has exec intent.
    if (hasInfra && (ctx.isDocRef || ctx.isMention || ctx.hasQuotes) && !ctx.startsCommand && !ctx.hasStrongExec) {
      score = Math.min(score, THRESHOLDS.BLOCK - 1);
    }

    return clamp(score, 0, 100);
  }

  function scoreLine(line) {
    const s = line;
    const ctx = semanticContext(s);
    const sig = detectSignals(s);

    let score = sig.reduce((sum, x) => sum + x.w, 0);
    score = applyGating(s, ctx, sig, score);

    const decision = score >= THRESHOLDS.BLOCK ? "BLOCK" : (score >= THRESHOLDS.WARN ? "WARN" : "ALLOW");

    return {
      input: s,
      decision,
      severity: score,
      entropy: entropyScore(s),
      signals: sig.map(x => x.label),
    };
  }

  // ---- UI ----
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

    const uniq = Array.from(new Set(rows.flatMap(r => r.signals || [])));
    renderSignals(uniq);

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
    const rows = lines.map(scoreLine);
    scanCount += 1;
    updateUI(rows);
  }

  function exportJSON() {
    const txt = $("input")?.value || "";
    const lines = txt.split("\n").map(normalize).filter(l => l.length > 0);
    const rows = lines.map(scoreLine);

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
        "cat /etc/passwd",
        "whoami",
      ].join("\n");
    }
  }

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
