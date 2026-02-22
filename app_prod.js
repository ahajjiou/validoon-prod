// app_prod.js — Validoon v2.0.0.1 (Enterprise Core Refactor)
// Local-only, deterministic. No network calls.
// Keeps existing HTML/CSS IDs. Injects additional controls into existing control row.
// Core separation: ENGINE + RULEPACK + SUITE/Bench + UI Adapter

(() => {
  "use strict";

  // -----------------------------
  // DOM Adapter (existing IDs only)
  // -----------------------------
  const $ = (id) => document.getElementById(id);
  const els = {
    input: $("input"),
    buildStamp: $("buildStamp"),
    policySelect: $("policySelect"),
    policyHint: $("policyHint"),

    btnLoadA: $("btnLoadA"),
    btnLoadB: $("btnLoadB"),
    btnScan: $("btnScan"),
    btnExport: $("btnExport"),
    btnClear: $("btnClear"),

    verdictBox: $("verdictBox"),
    verdictText: $("verdictText"),
    overallConf: $("overallConf"),
    overallMeter: $("overallMeter"),

    kScans: $("kScans"),
    kBlock: $("kBlock"),
    kWarn: $("kWarn"),
    kAllow: $("kAllow"),

    topReason: $("topReason"),
    integrityBadge: $("integrityBadge"),
    engineBadge: $("engineBadge"),

    signals: $("signals"),
    remedList: $("remedList"),
    rows: $("rows"),
  };

  const BUILD = "Validoon v2.0.0.1 • Enterprise Core Refactor (Rules+Decode+AST-lite+Bench)";

  // -----------------------------
  // Utilities
  // -----------------------------
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
  const clamp01 = (n) => clamp(n, 0, 1);

  function escapeHtml(s) {
    return String(s || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function safeJsonParse(txt) {
    try {
      return JSON.parse(txt);
    } catch (_) {
      return null;
    }
  }

  function setVerdictBox(verdict) {
    if (!els.verdictBox) return;
    let cls = "verdict-secure";
    if (verdict === "DANGER") cls = "verdict-danger";
    else if (verdict === "WARN") cls = "verdict-warn";
    els.verdictBox.className = "verdict " + cls;
  }

  function setErrorUI(title, err) {
    const msg = title + (err ? " — " + String(err.message || err) : "");
    try {
      if (els.verdictText) els.verdictText.textContent = "ERROR";
      setVerdictBox("WARN");
      if (els.topReason) els.topReason.textContent = msg;

      if (els.signals) {
        els.signals.innerHTML = "";
        const span = document.createElement("span");
        span.className = "pill warn";
        span.textContent = "UI:ERROR";
        els.signals.appendChild(span);
      }

      if (els.rows) {
        els.rows.innerHTML =
          '<div class="row"><div class="mono">' +
          escapeHtml(msg) +
          '</div><div>WARN</div><div>—</div><div>—</div><div class="mono">Open DevTools Console</div></div>';
      }
    } catch (_) {}
    console.log("[Validoon UI Error]", msg, err);
  }

  function assertDom() {
    const required = [
      ["input", els.input],
      ["btnScan", els.btnScan],
      ["btnExport", els.btnExport],
      ["btnClear", els.btnClear],
      ["verdictText", els.verdictText],
      ["rows", els.rows],
      ["signals", els.signals],
      ["remedList", els.remedList],
      ["policySelect", els.policySelect],
      ["policyHint", els.policyHint],
    ];
    const missing = required.filter(([, el]) => !el).map(([id]) => id);
    if (missing.length) {
      setErrorUI("DOM mismatch: missing element ids: " + missing.join(", "));
      return false;
    }
    return true;
  }

  // -----------------------------
  // Storage (Mode / Calibration / Suite / Rules)
  // -----------------------------
  const STORE = {
    MODE_KEY: "validoon_policy_mode",
    CAL_KEY_PREFIX: "validoon_calibration_",
    SUITE_KEY_PREFIX: "validoon_suite_",
    RULES_KEY_PREFIX: "validoon_rulepack_",

    MODES: ["BALANCED", "STRICT", "DEV"],
    DEFAULT_MODE: "BALANCED",

    getMode() {
      try {
        const saved = (localStorage.getItem(this.MODE_KEY) || "").toUpperCase().trim();
        if (this.MODES.includes(saved)) return saved;
      } catch (_) {}
      return this.DEFAULT_MODE;
    },
    setMode(mode) {
      const m = String(mode || "").toUpperCase().trim();
      if (!this.MODES.includes(m)) return this.getMode();
      try {
        localStorage.setItem(this.MODE_KEY, m);
      } catch (_) {}
      return m;
    },
    describeMode(mode) {
      if (mode === "STRICT") return "STRICT — Highest sensitivity (incident review).";
      if (mode === "DEV") return "DEV — Lower sensitivity (noisy logs).";
      return "BALANCED — Practical default with reduced false positives.";
    },

    loadCalibration(mode) {
      try {
        const raw = localStorage.getItem(this.CAL_KEY_PREFIX + mode);
        if (!raw) return null;
        const obj = JSON.parse(raw);
        return obj && typeof obj === "object" ? obj : null;
      } catch (_) {
        return null;
      }
    },
    saveCalibration(mode, obj) {
      try {
        localStorage.setItem(this.CAL_KEY_PREFIX + mode, JSON.stringify(obj));
      } catch (_) {}
    },
    clearCalibration(mode) {
      try {
        localStorage.removeItem(this.CAL_KEY_PREFIX + mode);
      } catch (_) {}
    },

    loadSuite(mode) {
      try {
        const raw = localStorage.getItem(this.SUITE_KEY_PREFIX + mode);
        if (!raw) return null;
        const obj = JSON.parse(raw);
        if (!obj || typeof obj !== "object") return null;
        if (!Array.isArray(obj.benign) || !Array.isArray(obj.incident)) return null;
        return obj;
      } catch (_) {
        return null;
      }
    },
    saveSuite(mode, suite) {
      try {
        localStorage.setItem(this.SUITE_KEY_PREFIX + mode, JSON.stringify(suite));
      } catch (_) {}
    },
    resetSuite(mode) {
      try {
        localStorage.removeItem(this.SUITE_KEY_PREFIX + mode);
      } catch (_) {}
    },

    loadRulepack(mode) {
      try {
        const raw = localStorage.getItem(this.RULES_KEY_PREFIX + mode);
        if (!raw) return null;
        const obj = JSON.parse(raw);
        return obj && typeof obj === "object" ? obj : null;
      } catch (_) {
        return null;
      }
    },
    saveRulepack(mode, pack) {
      try {
        localStorage.setItem(this.RULES_KEY_PREFIX + mode, JSON.stringify(pack));
      } catch (_) {}
    },
    resetRulepack(mode) {
      try {
        localStorage.removeItem(this.RULES_KEY_PREFIX + mode);
      } catch (_) {}
    },
  };

  let POLICY_MODE = STORE.getMode();

  // -----------------------------
  // Core ENGINE (tech/structural upgrade)
  // -----------------------------
  const ENGINE = (() => {
    // --- Baseline tuning per mode
    function baseTuning(mode) {
      if (mode === "STRICT") {
        return {
          riskMultiplier: 1.15,
          entropyMin: 3.55,
          tokenMinLen: 18,
          warnThreshold: 48,
          dangerThreshold: 115,
          perf: {
            maxLineLen: 7000,
            entropyScanCap: 2000,
            maxLines: 1200,
            maxDecodeLen: 4000,
            decodeDepth: 2,
          },
        };
      }
      if (mode === "DEV") {
        return {
          riskMultiplier: 0.9,
          entropyMin: 3.95,
          tokenMinLen: 22,
          warnThreshold: 60,
          dangerThreshold: 140,
          perf: {
            maxLineLen: 9000,
            entropyScanCap: 1600,
            maxLines: 2000,
            maxDecodeLen: 3500,
            decodeDepth: 2,
          },
        };
      }
      return {
        riskMultiplier: 1.0,
        entropyMin: 3.75,
        tokenMinLen: 20,
        warnThreshold: 55,
        dangerThreshold: 125,
        perf: {
          maxLineLen: 8000,
          entropyScanCap: 1800,
          maxLines: 1500,
          maxDecodeLen: 3800,
          decodeDepth: 2,
        },
      };
    }

    function tuning(mode) {
      const t = baseTuning(mode);
      const cal = STORE.loadCalibration(mode);
      if (!cal) return t;

      const out = { ...t };
      for (const k of ["entropyMin", "tokenMinLen", "warnThreshold", "dangerThreshold", "riskMultiplier"]) {
        if (typeof cal[k] === "number" && Number.isFinite(cal[k])) out[k] = cal[k];
      }
      return out;
    }

    // --- Perf guards
    function safeLine(mode, s) {
      const cap = tuning(mode).perf.maxLineLen;
      const str = String(s || "");
      return str.length <= cap ? str : str.slice(0, cap) + "…(truncated)";
    }

    function normalizeLine(s) {
      return String(s || "").replace(/\u0000/g, "").trimEnd();
    }

    // --- Meaningful lines (fix padding bypass)
    function isMeaningful(line) {
      const s = String(line || "").trim();
      if (!s) return false;
      if (/^(\/\/|#|;|--\s)/.test(s)) return false;
      if (/^\*+/.test(s)) return false;
      return true;
    }

    // --- FP suppressors (taxonomy)
    const FP_CTX = {
      HASH_CONTEXT: /\b(sha256|sha1|md5|checksum|commit|digest)\b/i,
      DOC_PLACEHOLDER: /\b(redacted|placeholder|not\s+real|sample\s+only|example\s+only|dummy|documentation|example|sample)\b/i,
      UUID: /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i,
      TRACEPARENT: /\btraceparent\b/i,
      MINIFIED_JS_HINT: /function\(|=>|\bvar\b|\bconst\b|\blet\b|;\s*\w+\(/i,
      JWT_SHAPE: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/,
    };

    function benignContext(line) {
      const s = String(line || "");
      if (FP_CTX.HASH_CONTEXT.test(s)) return "HASH_CONTEXT";
      if (FP_CTX.DOC_PLACEHOLDER.test(s)) return "DOC_PLACEHOLDER";
      if (FP_CTX.TRACEPARENT.test(s) || FP_CTX.UUID.test(s)) return "UUID_TRACE";
      if (FP_CTX.MINIFIED_JS_HINT.test(s) && s.length > 600) return "MINIFIED_JS";
      return null;
    }

    // --- Decoding Pipeline (multi-layer, capped)
    function tryUrlDecode(s) {
      if (!/%[0-9A-Fa-f]{2}/.test(s)) return null;
      try {
        const out = decodeURIComponent(s);
        return out !== s ? out : null;
      } catch (_) {
        return null;
      }
    }

    function tryHexDecode(s) {
      if (!/(\\x[0-9A-Fa-f]{2}){6,}/.test(s) && !/(?:0x)?[0-9A-Fa-f]{2,}/.test(s)) return null;
      const m = s.match(/(?:\\x[0-9A-Fa-f]{2}){6,}/);
      if (!m) return null;
      const seq = m[0];
      const bytes = seq.match(/\\x[0-9A-Fa-f]{2}/g) || [];
      if (bytes.length < 6) return null;
      let out = "";
      for (const b of bytes.slice(0, 1200)) out += String.fromCharCode(parseInt(b.slice(2), 16));
      return out || null;
    }

    function tryUnicodeEscapes(s) {
      if (!/(\\u[0-9A-Fa-f]{4}){4,}/.test(s)) return null;
      const parts = s.match(/\\u[0-9A-Fa-f]{4}/g);
      if (!parts || parts.length < 4) return null;
      let out = "";
      for (const p of parts.slice(0, 1200)) out += String.fromCharCode(parseInt(p.slice(2), 16));
      return out || null;
    }

    function isBase64Candidate(s) {
      const t = String(s || "").trim();
      if (t.length < 24) return false;
      if (t.length > 4096) return false;
      if (!/^[A-Za-z0-9+/=_-]+$/.test(t)) return false;
      const eq = (t.match(/=/g) || []).length;
      if (eq > 6) return false;
      return true;
    }

    function tryBase64Decode(s) {
      let t = String(s || "").trim().replace(/-/g, "+").replace(/_/g, "/");
      while (t.length % 4 !== 0) t += "=";
      if (!isBase64Candidate(t)) return null;
      try {
        const out = atob(t);
        const printable = out.replace(/[^\x09\x0A\x0D\x20-\x7E]/g, "");
        if (!printable || printable.length < 12) return null;
        return printable;
      } catch (_) {
        return null;
      }
    }

    function decodePipeline(mode, line) {
      const cfg = tuning(mode);
      const cap = cfg.perf.maxDecodeLen;

      let cur = String(line || "");
      if (cur.length > cap) cur = cur.slice(0, cap);

      const decoded = [];
      const seen = new Set([cur]);

      for (let depth = 0; depth < cfg.perf.decodeDepth; depth++) {
        const candidates = [];

        const u = tryUrlDecode(cur);
        if (u && !seen.has(u)) candidates.push({ kind: "URL", text: u });

        const hx = tryHexDecode(cur);
        if (hx && !seen.has(hx)) candidates.push({ kind: "HEX", text: hx });

        const uc = tryUnicodeEscapes(cur);
        if (uc && !seen.has(uc)) candidates.push({ kind: "UNICODE", text: uc });

        const b64 = tryBase64Decode(cur);
        if (b64 && !seen.has(b64)) candidates.push({ kind: "B64", text: b64 });

        if (!candidates.length) break;

        candidates.sort((a, b) => b.text.length - a.text.length);
        for (const c of candidates.slice(0, 3)) {
          const t = c.text.length > cap ? c.text.slice(0, cap) : c.text;
          seen.add(t);
          decoded.push({ kind: c.kind, text: t });
        }

        cur = candidates[0].text;
        if (cur.length > cap) cur = cur.slice(0, cap);
      }

      return decoded;
    }

    // --- AST-lite extraction (assignments / XML tags / JSON keys)
    function astLiteExtract(line) {
      const s = String(line || "");
      const out = [];

      const assign = s.match(/\b([A-Za-z_][A-Za-z0-9_]{2,40})\s*[:=]\s*["']([^"']{6,300})["']/);
      if (assign) out.push({ kind: "ASSIGN_QUOTED", key: assign[1], value: assign[2] });

      const xml = s.match(/<\s*([A-Za-z][A-Za-z0-9:_-]{2,40})\s*>\s*([^<]{6,300})\s*<\s*\/\s*\1\s*>/);
      if (xml) out.push({ kind: "XML_TAG", key: xml[1], value: xml[2] });

      const json = s.match(/["']([A-Za-z_][A-Za-z0-9_]{2,40})["']\s*:\s*["']([^"']{6,300})["']/);
      if (json) out.push({ kind: "JSON_KV", key: json[1], value: json[2] });

      return out;
    }

    // --- Entropy (capped, with JWT non-auth suppression)
    function shannonEntropy(str) {
      const s = String(str || "");
      if (!s) return 0;
      const map = new Map();
      for (const ch of s) map.set(ch, (map.get(ch) || 0) + 1);
      const n = s.length;
      let e = 0;
      for (const c of map.values()) {
        const p = c / n;
        e -= p * Math.log2(p);
      }
      return e;
    }

    function detectEntropy(mode, line) {
      const cfg = tuning(mode);
      const cap = cfg.perf.entropyScanCap;

      const s = String(line || "").slice(0, cap);
      const ctx = benignContext(s);
      if (ctx) return { maxEntropy: 0, hits: [], suppressedBy: ctx };

      const hasJwt = FP_CTX.JWT_SHAPE.test(s);
      const authish = /\b(authorization|bearer|token|secret|api[_-]?key|password|passwd|session)\b/i.test(s);
      if (hasJwt && !authish) return { maxEntropy: 0, hits: [], suppressedBy: "JWT_NON_AUTH_CONTEXT" };

      // IMPORTANT: escape '-' to avoid "Range out of order in character class"
      const tokenRe = /[A-Za-z0-9+/_=.\-]{24,}/g;
      tokenRe.lastIndex = 0;

      const hits = [];
      let m;
      while ((m = tokenRe.exec(s)) !== null) {
        const tok = m[0];
        if (tok.length < cfg.tokenMinLen) continue;
        const ent = shannonEntropy(tok);
        if (ent >= cfg.entropyMin) hits.push({ ent, preview: tok.slice(0, 24) + (tok.length > 24 ? "…" : "") });
        if (hits.length >= 5) break;
      }
      if (!hits.length) return { maxEntropy: 0, hits: [], suppressedBy: null };
      return { maxEntropy: Math.max(...hits.map((x) => x.ent)), hits, suppressedBy: null };
    }

    // --- Default Rule Pack (exportable/importable)
    function defaultRulepack() {
      return {
        version: 1,
        weights: {
          "SECRET:DETERMINISTIC": 130,
          "SSRF:METADATA_IP": 75,
          "SSRF:IAM_CRED_PATH": 90,
          "SSRF:METADATA_PATH": 40,
          "INFRA:DOCKER_SOCK": 90,
          "INFRA:DOCKER_PRIV": 75,
          "INFRA:DOCKER_RUN": 25,
          "SENSITIVE:/etc/shadow": 95,
          "AUTH:HEADER": 20,
          "AUTH:BEARER": 35,
          "AI:ROLE_OVERRIDE": 45,
          "WEB:<script>": 60,
          "WEB:INLINE_EVENT": 40,
          "ENTROPY:AUTH_CONTEXT": 80,
          "ENTROPY:SECRET_LIKE": 35,
          "AST:SECRET_KEY_ASSIGN": 85,
          "AST:PASSWORD_XML": 95,
          "CHAIN:METADATA+DOCKER": 130,
          "CHAIN:METADATA+SHADOW": 125,
          "CHAIN:DETERMINISTIC+AUTH": 110,
          "DECODE:URL_HIT": 20,
          "DECODE:B64_HIT": 25,
          "DECODE:HEX_HIT": 20,
          "DECODE:UNICODE_HIT": 20,
        },
        signals: [
          { id: "SSRF:METADATA_IP", re: "\\b169\\.254\\.169\\.254\\b", flags: "i" },
          { id: "SSRF:IAM_CRED_PATH", re: "\\/latest\\/meta-data\\/iam\\/security-credentials\\b", flags: "i" },
          { id: "SSRF:METADATA_PATH", re: "\\/latest\\/meta-data\\b", flags: "i" },

          { id: "INFRA:DOCKER_SOCK", re: "\\/var\\/run\\/docker\\.sock\\b", flags: "i" },
          { id: "INFRA:DOCKER_PRIV", re: "\\-\\-privileged\\b", flags: "i" },
          { id: "INFRA:DOCKER_RUN", re: "\\bdocker\\s+run\\b", flags: "i" },

          { id: "SENSITIVE:/etc/shadow", re: "\\/etc\\/shadow\\b", flags: "i" },

          { id: "AUTH:HEADER", re: "^\\s*authorization\\s*:", flags: "i" },
          { id: "AUTH:BEARER", re: "\\bBearer\\s+[A-Za-z0-9._\\-+/=]{10,}\\b", flags: "i" },

          { id: "AI:ROLE_OVERRIDE", re: "\\b(ignore\\s+previous|override\\s+system|you\\s+are\\s+now)\\b", flags: "i" },

          { id: "WEB:<script>", re: "<\\s*script\\b", flags: "i" },
          { id: "WEB:INLINE_EVENT", re: "\\bon\\w+\\s*=\\s*[\"']", flags: "i" },
        ],
        // NOTE: these are regex patterns (not secrets). Keep for matching; do NOT embed real tokens.
        deterministic: [
          { type: "AWS_ACCESS_KEY", re: "\\bAKIA[0-9A-Z]{16}\\b", flags: "g" },
          { type: "GITHUB_TOKEN", re: "\\bghp_[A-Za-z0-9]{36,}\\b", flags: "g" },
          { type: "SLACK_TOKEN", re: "\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b", flags: "g" },
          { type: "STRIPE_LIVE", re: "\\bsk_live_[A-Za-z0-9]{16,}\\b", flags: "g" },
          { type: "GOOGLE_API_KEY", re: "\\bAIza[0-9A-Za-z\\-_]{35}\\b", flags: "g" },
        ],
      };
    }

    function loadRulepack(mode) {
      const stored = STORE.loadRulepack(mode);
      return stored && stored.signals && stored.weights ? stored : defaultRulepack();
    }

    function compileRulepack(pack) {
      const compiled = {
        version: pack.version || 1,
        weights: pack.weights || {},
        signals: [],
        deterministic: [],
      };

      for (const s of pack.signals || []) {
        if (!s || !s.id || !s.re) continue;
        try {
          compiled.signals.push({ id: s.id, re: new RegExp(s.re, s.flags || "i") });
        } catch (_) {}
      }
      for (const d of pack.deterministic || []) {
        if (!d || !d.type || !d.re) continue;
        try {
          compiled.deterministic.push({ type: d.type, re: new RegExp(d.re, d.flags || "g") });
        } catch (_) {}
      }
      return compiled;
    }

    function correlate(feats) {
      const chains = [];
      const md = feats.some(
        (f) =>
          f.hits.includes("SSRF:METADATA_IP") ||
          f.hits.includes("SSRF:IAM_CRED_PATH") ||
          f.hits.includes("SSRF:METADATA_PATH")
      );
      const docker = feats.some((f) => f.hits.includes("INFRA:DOCKER_SOCK"));
      const shadow = feats.some((f) => f.hits.includes("SENSITIVE:/etc/shadow"));
      const det = feats.some((f) => f.hits.includes("SECRET:DETERMINISTIC"));
      const auth = feats.some(
        (f) => f.hits.includes("AUTH:HEADER") || f.hits.includes("AUTH:BEARER") || f.hits.includes("ENTROPY:AUTH_CONTEXT")
      );

      // only consider meaningful lines (padding bypass fix)
      const mdM = feats.some(
        (f) =>
          isMeaningful(f.line) &&
          (f.hits.includes("SSRF:METADATA_IP") || f.hits.includes("SSRF:IAM_CRED_PATH") || f.hits.includes("SSRF:METADATA_PATH"))
      );
      const dockerM = feats.some((f) => isMeaningful(f.line) && f.hits.includes("INFRA:DOCKER_SOCK"));
      const shadowM = feats.some((f) => isMeaningful(f.line) && f.hits.includes("SENSITIVE:/etc/shadow"));
      const detM = feats.some((f) => isMeaningful(f.line) && f.hits.includes("SECRET:DETERMINISTIC"));
      const authM = feats.some(
        (f) =>
          isMeaningful(f.line) &&
          (f.hits.includes("AUTH:HEADER") || f.hits.includes("AUTH:BEARER") || f.hits.includes("ENTROPY:AUTH_CONTEXT"))
      );

      if (md && docker && mdM && dockerM) chains.push({ id: "CHAIN:METADATA+DOCKER" });
      if (md && shadow && mdM && shadowM) chains.push({ id: "CHAIN:METADATA+SHADOW" });
      if (det && auth && detM && authM) chains.push({ id: "CHAIN:DETERMINISTIC+AUTH" });

      return chains;
    }

    function reasonForLine(decision, hits, meta) {
      if (hits.has("SECRET:DETERMINISTIC")) return "Deterministic vendor token detected (high certainty).";
      if (hits.has("AST:PASSWORD_XML")) return "Password-like value detected in XML tag context (AST-lite).";
      if (hits.has("AST:SECRET_KEY_ASSIGN")) return "Secret-like value detected in assignment context (AST-lite).";
      if (hits.has("SSRF:IAM_CRED_PATH")) return "Metadata IAM credentials path detected.";
      if (hits.has("SSRF:METADATA_IP")) return "Metadata IP detected (SSRF risk).";
      if (hits.has("INFRA:DOCKER_SOCK")) return "Docker socket access detected.";
      if (hits.has("SENSITIVE:/etc/shadow")) return "Sensitive file access attempt detected.";
      if (hits.has("ENTROPY:AUTH_CONTEXT")) return "High-entropy token in auth context.";
      if (hits.has("ENTROPY:SECRET_LIKE")) return "Secret-like entropy detected.";
      if (meta && meta.entropySuppressedBy) return `Entropy suppressed (benign context: ${meta.entropySuppressedBy}).`;
      if (hits.has("AI:ROLE_OVERRIDE")) return "Prompt override attempt detected.";
      if (hits.has("WEB:<script>")) return "Script tag detected (XSS risk).";
      if (hits.has("WEB:INLINE_EVENT")) return "Inline event handler detected.";
      if (decision === "ALLOW") return "—";
      return "Suspicious signals present; review.";
    }

    function topReason(activeSignals, verdict) {
      const s = new Set(activeSignals || []);
      if (s.has("CHAIN:METADATA+DOCKER")) return "Attack-chain detected: metadata indicators correlated with docker.sock access.";
      if (s.has("CHAIN:METADATA+SHADOW")) return "Attack-chain detected: metadata indicators correlated with /etc/shadow indicators.";
      if (s.has("SECRET:DETERMINISTIC")) return "Deterministic vendor secret detected (high certainty).";
      if (s.has("AST:PASSWORD_XML")) return "Sensitive value detected in XML password-like tag.";
      if (s.has("AST:SECRET_KEY_ASSIGN")) return "Sensitive value detected in key assignment context.";
      if (s.has("ENTROPY:AUTH_CONTEXT")) return "High-entropy credential-like token in auth context.";
      if (s.has("SSRF:METADATA_IP")) return "Cloud metadata endpoint referenced; review for SSRF and credential leakage.";
      if (verdict === "SECURE") return "No high-risk signals detected.";
      if (verdict === "WARN") return "Medium-risk signals detected; manual review recommended.";
      return "High-risk signals detected; treat as potential incident.";
    }

    function extractFeatures(mode, text, compiledPack) {
      const cfg = tuning(mode);
      const lines = String(text || "")
        .split(/\r?\n/)
        .slice(0, cfg.perf.maxLines);

      const feats = [];

      for (let i = 0; i < lines.length; i++) {
        const raw = normalizeLine(lines[i]);
        const line = safeLine(mode, raw);

        const hits = [];

        // signals
        for (const s of compiledPack.signals) {
          try {
            if (s.re.test(line)) hits.push(s.id);
          } catch (_) {}
        }

        // deterministic secrets
        let detFound = false;
        for (const d of compiledPack.deterministic) {
          try {
            d.re.lastIndex = 0;
            const found = line.match(d.re);
            if (found && found.length) detFound = true;
          } catch (_) {}
        }
        if (detFound) hits.push("SECRET:DETERMINISTIC");

        // decode pipeline (apply on line + AST extracted values)
        const decoded = decodePipeline(mode, line);
        for (const d of decoded) {
          if (d.kind === "URL") hits.push("DECODE:URL_HIT");
          if (d.kind === "B64") hits.push("DECODE:B64_HIT");
          if (d.kind === "HEX") hits.push("DECODE:HEX_HIT");
          if (d.kind === "UNICODE") hits.push("DECODE:UNICODE_HIT");

          // run signals on decoded text too (strong FN reducer)
          for (const s of compiledPack.signals) {
            try {
              if (s.re.test(d.text)) hits.push(s.id);
            } catch (_) {}
          }
        }

        // AST-lite extraction and checks
        const ast = astLiteExtract(line);
        for (const node of ast) {
          const key = String(node.key || "").toLowerCase();

          if (node.kind === "ASSIGN_QUOTED" || node.kind === "JSON_KV") {
            if (/(secret|token|apikey|api_key|password|passwd|private|key)/i.test(key)) {
              const ent = detectEntropy(mode, node.value);
              if (!ent.suppressedBy && (ent.hits.length || node.value.length >= 16)) hits.push("AST:SECRET_KEY_ASSIGN");
            }
          }

          if (node.kind === "XML_TAG") {
            if (/(password|passwd|secret|token|apikey|api_key)/i.test(key)) hits.push("AST:PASSWORD_XML");
          }

          const decodedVal = decodePipeline(mode, node.value);
          for (const d of decodedVal) {
            for (const s of compiledPack.signals) {
              try {
                if (s.re.test(d.text)) hits.push(s.id);
              } catch (_) {}
            }
          }
        }

        // entropy
        const ent = detectEntropy(mode, line);
        if (!ent.suppressedBy && ent.hits.length) {
          const authish = /\b(authorization|bearer|token|secret|api[_-]?key|password|passwd|session)\b/i.test(line);
          hits.push(authish ? "ENTROPY:AUTH_CONTEXT" : "ENTROPY:SECRET_LIKE");
        }

        feats.push({
          i,
          line,
          hits: Array.from(new Set(hits)).sort(),
          entropy: Number.isFinite(ent.maxEntropy) ? ent.maxEntropy : 0,
          entropySuppressedBy: ent.suppressedBy,
        });
      }

      return feats;
    }

    function score(mode, feats, compiledPack) {
      const cfg = tuning(mode);
      const weights = compiledPack.weights || {};

      const active = new Set();
      const lineResults = [];

      for (const f of feats) {
        f.hits.forEach((x) => active.add(x));

        let risk = 0;
        for (const h of f.hits) risk += weights[h] || 0;
        risk = Math.round(risk * cfg.riskMultiplier);

        let decision = "ALLOW";
        if (risk >= cfg.dangerThreshold) decision = "BLOCK";
        else if (risk >= cfg.warnThreshold) decision = "WARN";

        const confidence = clamp01(risk / Math.max(1, cfg.dangerThreshold));
        lineResults.push({
          decision,
          confidence: Math.round(confidence * 100),
          risk,
          entropy: Number.isFinite(f.entropy) ? Number(f.entropy.toFixed(1)) : 0,
          reason: reasonForLine(decision, new Set(f.hits), f),
          hits: f.hits,
        });
      }

      const chains = correlate(feats);
      let chainRisk = 0;
      for (const c of chains) {
        active.add(c.id);
        chainRisk += weights[c.id] || 0;
      }

      const totalRisk = lineResults.reduce((a, b) => a + (b.risk || 0), 0) + chainRisk;

      let verdict = "SECURE";
      if (totalRisk >= cfg.dangerThreshold + cfg.warnThreshold) verdict = "DANGER";
      else if (totalRisk >= cfg.warnThreshold) verdict = "WARN";

      const overallConfidence = clamp(Math.round((totalRisk / (cfg.dangerThreshold + cfg.warnThreshold)) * 100), 0, 100);

      return {
        verdict,
        overallConfidence,
        totalRisk,
        activeSignals: Array.from(active).sort(),
        lineResults,
        chains,
        topReason: topReason(Array.from(active), verdict),
      };
    }

    function evaluate(mode, text) {
      const pack = loadRulepack(mode);
      const compiled = compileRulepack(pack);
      const feats = extractFeatures(mode, text, compiled);
      const scored = score(mode, feats, compiled);

      return {
        mode,
        tuning: tuning(mode),
        rulepack: { version: compiled.version, signals: compiled.signals.length, deterministic: compiled.deterministic.length },
        feats,
        scored,
        lines: feats.map((f) => f.line),
      };
    }

    function exportActiveRulepack(mode) {
      const pack = loadRulepack(mode);
      return {
        build: BUILD,
        ts: new Date().toISOString(),
        policyMode: mode,
        rulepack: pack,
      };
    }

    function resetRulepack(mode) {
      STORE.resetRulepack(mode);
    }

    function importRulepack(mode, obj) {
      const pack = obj?.rulepack || obj;
      if (!pack || typeof pack !== "object") return false;
      if (!pack.weights || typeof pack.weights !== "object") return false;
      if (!Array.isArray(pack.signals) || !Array.isArray(pack.deterministic)) return false;
      STORE.saveRulepack(mode, pack);
      return true;
    }

    return {
      evaluate,
      tuning,
      exportActiveRulepack,
      importRulepack,
      resetRulepack,
      defaultRulepack,
    };
  })();

  // -----------------------------
  // Suite + Benchmark + Auto-Calibration
  // -----------------------------
  const SUITE = (() => {
    const EMBEDDED = {
      version: 1,
      benign: [
        { id: "B001", expected: "SECURE", text: "INFO request_id=9b7e1c2a-1f2b-4c3d-9a0b-1234567890ab user=alice action=login ok" },
        { id: "B002", expected: "SECURE", text: "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" },
        { id: "B003", expected: "SECURE", text: "sha256: 7d3b2c1a8b9f0f1e2d3c4b5a6f7e8d9c0b1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d" },
        { id: "B004", expected: "SECURE", text: "documentation sample only: token=PLACEHOLDER_NOT_REAL_1234567890" },
        { id: "B005", expected: "SECURE", text: "GET /healthz 200 12ms host=app-prod" },
      ],
      incident: [
        { id: "I001", expected: "DANGER", text: "GET http://169.254.169.254/latest/meta-data/iam/security-credentials/" },
        { id: "I002", expected: "DANGER", text: "docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock alpine sh" },
        { id: "I003", expected: "DANGER", text: "cat /etc/shadow" },

        // v2.0.0.1: suite hardened to avoid vendor-token formats; still triggers AUTH/ENTROPY/AST signals deterministically
        { id: "I004", expected: "DANGER", text: "authorization: Bearer vld_test_token_4q7X9p2LmN8sQ1rT5yU6iO3aP0sD9fG2hJ7kL1mZ" },
        { id: "I005", expected: "DANGER", text: "config: api_key=\"vld_test_secret_9Kp4Qx7Tn2Rz6Vw8Hs3Jm1Ld0Fg5Bb7Cc9Dd\" // not real" },

        { id: "I006", expected: "WARN", text: "<div onclick=\"doBad()\">x</div>" },
      ],
    };

    function getActive(mode) {
      const custom = STORE.loadSuite(mode);
      if (custom && Array.isArray(custom.benign) && Array.isArray(custom.incident) && custom.benign.length + custom.incident.length >= 10) {
        return { ...custom, source: "CUSTOM" };
      }
      return { ...EMBEDDED, source: "EMBEDDED" };
    }

    function nextId(prefix, list) {
      const n = (list || []).length + 1;
      return prefix + String(n).padStart(3, "0");
    }

    function add(mode, group) {
      const text = (els.input.value || "").trim();
      if (!text) return { ok: false, error: "Input is empty." };

      const suite = STORE.loadSuite(mode) || { version: 1, benign: [], incident: [] };
      const list = suite[group];
      const id = nextId(group === "benign" ? "B" : "I", list);
      const expected = group === "benign" ? "SECURE" : "DANGER";

      list.push({ id, expected, text });

      if (list.length > 200) list.splice(0, list.length - 200);

      STORE.saveSuite(mode, suite);
      return { ok: true };
    }

    function reset(mode) {
      STORE.resetSuite(mode);
    }

    function exportSuite(mode) {
      const suite = STORE.loadSuite(mode) || { version: 1, benign: [], incident: [] };
      return {
        build: BUILD,
        ts: new Date().toISOString(),
        policyMode: mode,
        suite,
      };
    }

    function importSuite(mode, obj) {
      const suite = obj?.suite || obj;
      if (!suite || typeof suite !== "object") return false;
      if (!Array.isArray(suite.benign) || !Array.isArray(suite.incident)) return false;

      const clean = (arr) =>
        arr
          .filter((x) => x && typeof x.text === "string" && x.text.trim())
          .map((x) => ({
            expected: String(x.expected || "SECURE").toUpperCase(),
            text: String(x.text),
          }))
          .slice(0, 400);

      const merged = {
        version: 1,
        benign: clean(suite.benign).map((x, i) => ({ id: "B" + String(i + 1).padStart(3, "0"), expected: "SECURE", text: x.text })),
        incident: clean(suite.incident).map((x, i) => ({
          id: "I" + String(i + 1).padStart(3, "0"),
          expected: x.expected === "WARN" ? "WARN" : "DANGER",
          text: x.text,
        })),
      };

      STORE.saveSuite(mode, merged);
      return true;
    }

    function verdictToAlert(v) {
      return v === "WARN" || v === "DANGER";
    }
    function expectedToAlert(e) {
      return e === "WARN" || e === "DANGER";
    }

    function benchmark(mode, configOverride) {
      const original = STORE.loadCalibration(mode);
      if (configOverride) STORE.saveCalibration(mode, configOverride);

      const suite = getActive(mode);
      const all = [...suite.benign.map((s) => ({ ...s, group: "benign" })), ...suite.incident.map((s) => ({ ...s, group: "incident" }))];

      let TP = 0,
        FP = 0,
        TN = 0,
        FN = 0;
      let strictTP = 0,
        strictFN = 0;
      let benignAlerts = 0,
        incidentMisses = 0;

      const fpCauses = new Map();
      const results = [];

      for (const sample of all) {
        const rep = ENGINE.evaluate(mode, sample.text);
        const pred = rep.scored.verdict;
        const predAlert = verdictToAlert(pred);
        const expAlert = expectedToAlert(sample.expected);

        if (expAlert && predAlert) TP++;
        else if (!expAlert && predAlert) FP++;
        else if (!expAlert && !predAlert) TN++;
        else if (expAlert && !predAlert) FN++;

        if (sample.expected === "DANGER") {
          if (pred === "DANGER") strictTP++;
          else strictFN++;
        }

        if (sample.group === "benign" && predAlert) {
          benignAlerts++;
          const firstAlertLine = rep.scored.lineResults.find((r) => r.decision !== "ALLOW");
          const reason = firstAlertLine?.reason || "UNKNOWN";
          fpCauses.set(reason, (fpCauses.get(reason) || 0) + 1);
        }
        if (sample.group === "incident" && !predAlert) incidentMisses++;

        results.push({
          id: sample.id,
          group: sample.group,
          expected: sample.expected,
          predicted: pred,
          topReason: rep.scored.topReason,
          signals: rep.scored.activeSignals.slice(0, 8),
        });
      }

      const precision = TP + FP === 0 ? 1 : TP / (TP + FP);
      const recall = TP + FN === 0 ? 1 : TP / (TP + FN);

      const benignTotal = suite.benign.length || 1;
      const incidentTotal = suite.incident.length || 1;

      const benignFpRate = benignAlerts / benignTotal;
      const incidentFnRate = incidentMisses / incidentTotal;
      const strictDangerRecall = strictTP + strictFN === 0 ? 1 : strictTP / (strictTP + strictFN);

      const fpTop = Array.from(fpCauses.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([reason, count]) => ({ reason, count }));

      const cfg = ENGINE.tuning(mode);

      const out = {
        ts: new Date().toISOString(),
        suiteSource: suite.source,
        suiteSize: { benign: suite.benign.length, incident: suite.incident.length },
        policyMode: mode,
        config: { ...cfg },
        metrics: {
          TP,
          FP,
          TN,
          FN,
          precision: Number(precision.toFixed(3)),
          recall: Number(recall.toFixed(3)),
          benignFpRate: Number(benignFpRate.toFixed(3)),
          incidentFnRate: Number(incidentFnRate.toFixed(3)),
          strictDangerRecall: Number(strictDangerRecall.toFixed(3)),
        },
        fpTop,
        results,
      };

      if (configOverride) {
        if (original) STORE.saveCalibration(mode, original);
        else STORE.clearCalibration(mode);
      }

      return out;
    }

    function autoCalibrate(mode) {
      const suite = getActive(mode);
      const isCustom = suite.source === "CUSTOM";

      const entropyGrid = mode === "STRICT" ? [3.45, 3.55, 3.65, 3.75] : [3.65, 3.75, 3.85, 3.95, 4.05];
      const lenGrid = mode === "DEV" ? [20, 22, 24] : [18, 20, 22];
      const warnGrid = mode === "STRICT" ? [45, 50, 55] : [50, 55, 60, 65];
      const dangerGrid = mode === "DEV" ? [130, 140, 150] : [115, 125, 135, 145];
      const multGrid = mode === "STRICT" ? [1.1, 1.15, 1.2] : [0.95, 1.0, 1.05];

      const CONSTRAINT_RECALL = isCustom ? 0.92 : 0.9;
      const CONSTRAINT_STRICT_DANGER = isCustom ? 0.8 : 0.75;

      let best = null;

      for (const entropyMin of entropyGrid) {
        for (const tokenMinLen of lenGrid) {
          for (const warnThreshold of warnGrid) {
            for (const dangerThreshold of dangerGrid) {
              if (dangerThreshold <= warnThreshold) continue;
              for (const riskMultiplier of multGrid) {
                const cand = { entropyMin, tokenMinLen, warnThreshold, dangerThreshold, riskMultiplier };
                const b = benchmark(mode, cand);
                const m = b.metrics;

                if (m.recall < CONSTRAINT_RECALL) continue;
                if (m.strictDangerRecall < CONSTRAINT_STRICT_DANGER) continue;

                const score = m.benignFpRate * 0.85 + m.incidentFnRate * 0.15;
                if (!best || score < best.score) best = { score, cand, bench: b };
                else if (best && score === best.score) {
                  if (m.incidentFnRate < best.bench.metrics.incidentFnRate) best = { score, cand, bench: b };
                }
              }
            }
          }
        }
      }
      return best;
    }

    return {
      getActive,
      add,
      reset,
      exportSuite,
      importSuite,
      benchmark,
      autoCalibrate,
    };
  })();

  // -----------------------------
  // UI Rendering
  // -----------------------------
  function renderSignals(activeSignals) {
    els.signals.innerHTML = "";
    const set = new Set(activeSignals || []);
    if (!set.size) {
      const span = document.createElement("span");
      span.className = "pill allow";
      span.textContent = "NO_SIGNALS";
      els.signals.appendChild(span);
      return;
    }

    Array.from(set)
      .sort()
      .forEach((id) => {
        const span = document.createElement("span");
        let cls = "allow";
        if (id.startsWith("SECRET:") || id.startsWith("SSRF:") || id.startsWith("INFRA:") || id.startsWith("SENSITIVE:") || id.startsWith("CHAIN:") || id.startsWith("AST:"))
          cls = "bad";
        else if (id.startsWith("AUTH:") || id.startsWith("ENTROPY:") || id.startsWith("AI:") || id.startsWith("WEB:") || id.startsWith("DECODE:")) cls = "warn";
        span.className = "pill " + cls;
        span.textContent = id;
        els.signals.appendChild(span);
      });
  }

  function renderRemediation(activeSignals) {
    els.remedList.innerHTML = "";
    const sig = new Set(activeSignals || []);
    const items = [];

    if (
      sig.has("SECRET:DETERMINISTIC") ||
      sig.has("ENTROPY:AUTH_CONTEXT") ||
      sig.has("ENTROPY:SECRET_LIKE") ||
      sig.has("AST:SECRET_KEY_ASSIGN") ||
      sig.has("AST:PASSWORD_XML")
    ) {
      items.push({
        tag: "SECRETS",
        name: "Rotate credentials and purge exposure",
        why: "Secrets or secret-like values were detected (deterministic / entropy / AST-lite).",
        actions: [
          "Rotate exposed credentials immediately (vendor console).",
          "Invalidate tokens/sessions where applicable.",
          "Remove secrets from logs/configs and use a secrets manager.",
        ],
      });
    }
    if (sig.has("SSRF:METADATA_IP") || sig.has("SSRF:IAM_CRED_PATH") || sig.has("CHAIN:METADATA+DOCKER") || sig.has("CHAIN:METADATA+SHADOW")) {
      items.push({
        tag: "SSRF",
        name: "Block metadata access and harden egress",
        why: "Cloud metadata indicators were detected (SSRF / credential theft risk).",
        actions: [
          "Block 169.254.169.254 where applicable; prefer IMDSv2 restrictions.",
          "Allowlist outbound URLs and enforce strict validation.",
          "Apply egress policies/timeouts and disable open redirects.",
        ],
      });
    }
    if (sig.has("INFRA:DOCKER_SOCK") || sig.has("CHAIN:METADATA+DOCKER")) {
      items.push({
        tag: "CONTAINERS",
        name: "Prevent docker.sock exposure",
        why: "docker.sock access is a high-impact container escape vector.",
        actions: ["Remove docker.sock mounts from untrusted containers.", "Avoid --privileged; enforce least privilege and seccomp/apparmor.", "Separate build and runtime; isolate CI runners."],
      });
    }
    if (sig.has("WEB:<script>") || sig.has("WEB:INLINE_EVENT")) {
      items.push({
        tag: "WEB",
        name: "Mitigate script injection",
        why: "Script indicators were detected in content.",
        actions: ["Escape/encode untrusted inputs before rendering.", "Adopt CSP and avoid inline handlers.", "Review templating and sanitization routines."],
      });
    }
    if (!items.length) {
      items.push({
        tag: "OK",
        name: "No critical remediation required",
        why: "No actionable high-risk signals were found.",
        actions: ["Keep monitoring and maintain least privilege policies."],
      });
    }

    for (const it of items) {
      const wrap = document.createElement("div");
      wrap.className = "remed-item";
      wrap.innerHTML = `
        <div class="remed-head">
          <div class="remed-tag">${escapeHtml(it.tag)}</div>
          <div class="remed-name">${escapeHtml(it.name)}</div>
        </div>
        <div class="remed-why">${escapeHtml(it.why)}</div>
        <ul class="remed-actions">${it.actions.map((a) => `<li>${escapeHtml(a)}</li>`).join("")}</ul>
      `;
      els.remedList.appendChild(wrap);
    }
  }

  function renderRows(lines, lineResults) {
    els.rows.innerHTML = "";
    for (let i = 0; i < lineResults.length; i++) {
      const r = lineResults[i];
      const row = document.createElement("div");
      row.className = "row";

      const c1 = document.createElement("div");
      c1.className = "mono";
      c1.textContent = String(i + 1);

      const c2 = document.createElement("div");
      c2.className = "decision-" + (r.decision || "ALLOW");
      c2.textContent = r.decision || "ALLOW";

      const c3 = document.createElement("div");
      c3.className = "conf";
      c3.textContent = (r.confidence ?? 0) + "%";

      const c4 = document.createElement("div");
      c4.className = "entropy";
      c4.textContent = String(r.entropy ?? 0);

      const c5 = document.createElement("div");
      c5.className = "mono";
      const preview = lines[i] ?? "";
      const reason = r.reason ? ` — ${r.reason}` : "";
      c5.textContent = String(preview).slice(0, 260) + (String(preview).length > 260 ? "…" : "") + reason;

      row.appendChild(c1);
      row.appendChild(c2);
      row.appendChild(c3);
      row.appendChild(c4);
      row.appendChild(c5);
      els.rows.appendChild(row);
    }
  }

  // -----------------------------
  // Scan state
  // -----------------------------
  let scans = 0;
  let lastScan = null;
  let lastBench = null;

  function renderScan(rep) {
    const scored = rep.scored;

    els.verdictText.textContent = scored.verdict;
    setVerdictBox(scored.verdict);

    els.overallConf.textContent = scored.overallConfidence + "%";
    els.overallMeter.style.width = scored.overallConfidence + "%";

    const counts = { BLOCK: 0, WARN: 0, ALLOW: 0 };
    for (const r of scored.lineResults) counts[r.decision] = (counts[r.decision] || 0) + 1;

    els.kScans.textContent = String(scans);
    els.kBlock.textContent = String(counts.BLOCK || 0);
    els.kWarn.textContent = String(counts.WARN || 0);
    els.kAllow.textContent = String(counts.ALLOW || 0);

    els.topReason.textContent = scored.topReason || "—";
    els.integrityBadge.textContent = "INTEGRITY: LOCAL";
    const cal = STORE.loadCalibration(POLICY_MODE);
    els.engineBadge.textContent =
      `ENGINE: ENTERPRISE_CORE • ${POLICY_MODE}` +
      (cal ? " • CALIBRATED" : " • BASE") +
      ` • rules=${rep.rulepack.signals}/${rep.rulepack.deterministic} • decode+ast+bench`;

    renderSignals(scored.activeSignals);
    renderRemediation(scored.activeSignals);
    renderRows(rep.lines, scored.lineResults);
  }

  function runScan() {
    try {
      const text = els.input.value || "";
      const rep = ENGINE.evaluate(POLICY_MODE, text);
      scans += 1;
      lastScan = rep;
      renderScan(rep);
      console.log("[Validoon Scan v2.0.0.1]", rep);
    } catch (err) {
      setErrorUI("Runtime error in scan", err);
    }
  }

  // -----------------------------
  // Panels: Benchmark + Suite + Rules
  // -----------------------------
  let panel = null;
  let fileSuite = null;
  let fileRules = null;

  function ensurePanel() {
    if (panel && panel.root && panel.root.isConnected) return panel;

    const linePanel = els.rows?.closest(".panel");
    if (!linePanel || !linePanel.parentNode) return null;

    const root = document.createElement("div");
    root.className = "panel";
    root.innerHTML = `
      <div class="panel-head">
        <div>
          <div class="panel-title">Enterprise Benchmark + RulePack</div>
          <div class="panel-sub">Prove FP reduction on your suite + import/export rules (no code changes)</div>
        </div>
      </div>
      <div class="panel-body">
        <div class="reason" id="pSummary">—</div>

        <div style="margin-top:10px" class="badges">
          <div class="badge" id="pSuite">SUITE: —</div>
          <div class="badge" id="pSize">SIZE: —</div>
          <div class="badge" id="pCal">CAL: —</div>
          <div class="badge" id="pRules">RULES: —</div>
        </div>

        <div style="margin-top:12px">
          <div class="mini">
            <div class="mini-k">Benchmark Snapshot</div>
            <div class="mini-v mono" id="pSnap">—</div>
          </div>
        </div>

        <div style="margin-top:12px">
          <div class="mini">
            <div class="mini-k">Top False Positive Causes</div>
            <div class="mini-v mono" id="pFP">—</div>
          </div>
        </div>
      </div>
    `;
    linePanel.parentNode.insertBefore(root, linePanel);

    panel = {
      root,
      summary: root.querySelector("#pSummary"),
      suite: root.querySelector("#pSuite"),
      size: root.querySelector("#pSize"),
      cal: root.querySelector("#pCal"),
      rules: root.querySelector("#pRules"),
      snap: root.querySelector("#pSnap"),
      fp: root.querySelector("#pFP"),
    };

    // hidden file inputs
    fileSuite = document.createElement("input");
    fileSuite.type = "file";
    fileSuite.accept = "application/json";
    fileSuite.style.display = "none";
    document.body.appendChild(fileSuite);

    fileRules = document.createElement("input");
    fileRules.type = "file";
    fileRules.accept = "application/json";
    fileRules.style.display = "none";
    document.body.appendChild(fileRules);

    fileSuite.addEventListener("change", async () => {
      try {
        const f = fileSuite.files && fileSuite.files[0];
        if (!f) return;
        const txt = await f.text();
        const obj = safeJsonParse(txt);
        if (!obj || !SUITE.importSuite(POLICY_MODE, obj)) {
          setErrorUI("Suite import failed: invalid JSON format.");
          return;
        }
        fileSuite.value = "";
        renderPanel();
      } catch (err) {
        setErrorUI("Suite import failed", err);
      }
    });

    fileRules.addEventListener("change", async () => {
      try {
        const f = fileRules.files && fileRules.files[0];
        if (!f) return;
        const txt = await f.text();
        const obj = safeJsonParse(txt);
        if (!obj || !ENGINE.importRulepack(POLICY_MODE, obj)) {
          setErrorUI("RulePack import failed: invalid JSON format.");
          return;
        }
        fileRules.value = "";
        renderPanel();
        if ((els.input.value || "").trim()) runScan();
      } catch (err) {
        setErrorUI("RulePack import failed", err);
      }
    });

    return panel;
  }

  function renderPanel() {
    const p = ensurePanel();
    if (!p) return;

    const suite = SUITE.getActive(POLICY_MODE);
    const cal = STORE.loadCalibration(POLICY_MODE);
    const rp = STORE.loadRulepack(POLICY_MODE) || ENGINE.defaultRulepack();

    p.suite.textContent = "SUITE: " + suite.source;
    p.size.textContent = `SIZE: benign=${suite.benign.length} incident=${suite.incident.length}`;
    p.cal.textContent = cal ? "CAL: ENABLED" : "CAL: BASE";
    p.rules.textContent = `RULES: signals=${(rp.signals || []).length} det=${(rp.deterministic || []).length}`;

    if (!lastBench) {
      p.summary.textContent = "Build a custom suite (Add Benign/Incident) then run Benchmark.";
      p.snap.textContent = "—";
      p.fp.textContent = "—";
      return;
    }

    const m = lastBench.metrics;
    const isCustom = lastBench.suiteSource === "CUSTOM";
    const gateFp = isCustom ? 0.05 : 0.2;
    const gateRecall = isCustom ? 0.92 : 0.9;

    const verdict = m.benignFpRate <= gateFp && m.recall >= gateRecall ? "SELLABLE_CANDIDATE" : "NOT_SELLABLE_YET";

    p.summary.textContent =
      `${verdict} • FP=${m.benignFpRate} • FN=${m.incidentFnRate} • Precision=${m.precision} • Recall=${m.recall} • StrictDangerRecall=${m.strictDangerRecall}`;

    p.snap.textContent =
      `TP=${m.TP} FP=${m.FP} TN=${m.TN} FN=${m.FN} • mode=${lastBench.policyMode} • ent≥${lastBench.config.entropyMin.toFixed(2)} len≥${lastBench.config.tokenMinLen} warn≥${lastBench.config.warnThreshold} danger≥${lastBench.config.dangerThreshold} mult=${lastBench.config.riskMultiplier.toFixed(2)}`;

    p.fp.textContent = lastBench.fpTop.length ? lastBench.fpTop.map((x) => `${x.count}× ${x.reason}`).join(" | ") : "—";
  }

  // -----------------------------
  // Inject controls into existing control row
  // -----------------------------
  function injectButtons() {
    const container = els.btnScan?.parentElement;
    if (!container) return;
    if (container.querySelector("#btnBench")) return;

    const mkBtn = (id, label) => {
      const b = document.createElement("button");
      b.className = "btn";
      b.id = id;
      b.type = "button";
      b.textContent = label;
      return b;
    };

    const btnBench = mkBtn("btnBench", "Benchmark");
    const btnCal = mkBtn("btnAutoCal", "Auto-Calibrate");
    const btnAddBenign = mkBtn("btnAddBenign", "Add Benign");
    const btnAddIncident = mkBtn("btnAddIncident", "Add Incident");
    const btnImportSuite = mkBtn("btnImportSuite", "Import Suite");
    const btnExportSuite = mkBtn("btnExportSuite", "Export Suite");
    const btnResetSuite = mkBtn("btnResetSuite", "Reset Suite");

    const btnImportRules = mkBtn("btnImportRules", "Import Rules");
    const btnExportRules = mkBtn("btnExportRules", "Export Rules");
    const btnResetRules = mkBtn("btnResetRules", "Reset Rules");

    const anchor = els.btnExport && els.btnExport.parentElement === container ? els.btnExport : null;
    const all = [btnBench, btnCal, btnAddBenign, btnAddIncident, btnImportSuite, btnExportSuite, btnResetSuite, btnImportRules, btnExportRules, btnResetRules];

    for (const b of all) {
      if (anchor) container.insertBefore(b, anchor);
      else container.appendChild(b);
    }

    btnBench.addEventListener("click", () => {
      try {
        lastBench = SUITE.benchmark(POLICY_MODE, null);
        renderPanel();
        console.log("[Benchmark v2.0.0.1]", lastBench);
      } catch (err) {
        setErrorUI("Benchmark failed", err);
      }
    });

    btnCal.addEventListener("click", () => {
      try {
        const best = SUITE.autoCalibrate(POLICY_MODE);
        if (!best) {
          setErrorUI("Auto-calibration failed: suite too small or constraints too strict.");
          return;
        }
        STORE.saveCalibration(POLICY_MODE, best.cand);

        lastBench = SUITE.benchmark(POLICY_MODE, null);
        renderPanel();

        if ((els.input.value || "").trim()) runScan();
        console.log("[Auto-Calibrate v2.0.0.1] best", best);
      } catch (err) {
        setErrorUI("Auto-calibration failed", err);
      }
    });

    btnAddBenign.addEventListener("click", () => {
      const r = SUITE.add(POLICY_MODE, "benign");
      if (!r.ok) setErrorUI("Add Benign failed", r.error);
      renderPanel();
    });

    btnAddIncident.addEventListener("click", () => {
      const r = SUITE.add(POLICY_MODE, "incident");
      if (!r.ok) setErrorUI("Add Incident failed", r.error);
      renderPanel();
    });

    btnImportSuite.addEventListener("click", () => {
      ensurePanel();
      fileSuite?.click();
    });

    btnExportSuite.addEventListener("click", () => {
      try {
        const payload = SUITE.exportSuite(POLICY_MODE);
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `validoon_suite_${String(POLICY_MODE).toLowerCase()}_${new Date().toISOString().replaceAll(":", "-")}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 900);
      } catch (err) {
        setErrorUI("Suite export failed", err);
      }
    });

    btnResetSuite.addEventListener("click", () => {
      SUITE.reset(POLICY_MODE);
      renderPanel();
    });

    btnImportRules.addEventListener("click", () => {
      ensurePanel();
      fileRules?.click();
    });

    btnExportRules.addEventListener("click", () => {
      try {
        const payload = ENGINE.exportActiveRulepack(POLICY_MODE);
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `validoon_rules_${String(POLICY_MODE).toLowerCase()}_${new Date().toISOString().replaceAll(":", "-")}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 900);
      } catch (err) {
        setErrorUI("RulePack export failed", err);
      }
    });

    btnResetRules.addEventListener("click", () => {
      ENGINE.resetRulepack(POLICY_MODE);
      renderPanel();
      if ((els.input.value || "").trim()) runScan();
    });
  }

  // -----------------------------
  // Export current report (scan + bench + suite/rules meta)
  // -----------------------------
  function exportCurrent() {
    try {
      const suite = SUITE.getActive(POLICY_MODE);
      const rp = STORE.loadRulepack(POLICY_MODE) || ENGINE.defaultRulepack();
      const payload = {
        build: BUILD,
        ts: new Date().toISOString(),
        policyMode: POLICY_MODE,
        calibration: STORE.loadCalibration(POLICY_MODE),
        suite: { source: suite.source, benign: suite.benign.length, incident: suite.incident.length },
        rules: { signals: (rp.signals || []).length, deterministic: (rp.deterministic || []).length, version: rp.version || 1 },
        scan: lastScan
          ? {
              verdict: lastScan.scored.verdict,
              overallConfidence: lastScan.scored.overallConfidence,
              totalRisk: lastScan.scored.totalRisk,
              activeSignals: lastScan.scored.activeSignals,
              topReason: lastScan.scored.topReason,
              lineResults: lastScan.scored.lineResults,
            }
          : null,
        benchmark: lastBench || null,
      };

      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `validoon_report_${String(POLICY_MODE).toLowerCase()}_${new Date().toISOString().replaceAll(":", "-")}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      setErrorUI("Export failed", err);
    }
  }

  function clearAll() {
    els.input.value = "";
    scans = 0;
    lastScan = null;

    els.verdictText.textContent = "READY";
    els.topReason.textContent = "—";
    setVerdictBox("SECURE");

    els.overallConf.textContent = "0%";
    els.overallMeter.style.width = "0%";
    els.kScans.textContent = "0";
    els.kBlock.textContent = "0";
    els.kWarn.textContent = "0";
    els.kAllow.textContent = "0";

    els.signals.innerHTML = "";
    els.remedList.innerHTML = "";
    els.rows.innerHTML = "";

    renderPanel();
  }

  // -----------------------------
  // Demo payloads (v2.0.0.1 aligned with suite; no vendor-token formats)
  // -----------------------------
  const TEST_A = [
    "GET /?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2F",
    "authorization: Bearer vld_test_token_7nQ3sK8mR2pT9xV5hJ1dF6cZ0aB4uY7wE3qL",
    "<Password>superSecretPass123</Password>",
  ].join("\n");

  const TEST_B = [
    "docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock alpine sh",
    "echo Z2V0IGh0dHA6Ly8xNjkuMjU0LjE2OS4yNTQvbGF0ZXN0L21ldGEtZGF0YS8= | base64 -d",
    "cat /etc/shadow",
  ].join("\n");

  // -----------------------------
  // Boot
  // -----------------------------
  function syncPolicyUI() {
    if (els.buildStamp) els.buildStamp.textContent = BUILD;
    els.policySelect.value = POLICY_MODE;
    els.policyHint.textContent = STORE.describeMode(POLICY_MODE);
  }

  function boot() {
    try {
      if (!assertDom()) return;

      syncPolicyUI();
      injectButtons();
      ensurePanel();

      els.policySelect.addEventListener("change", () => {
        POLICY_MODE = STORE.setMode(els.policySelect.value);
        syncPolicyUI();

        try {
          lastBench = SUITE.benchmark(POLICY_MODE, null);
        } catch (_) {
          lastBench = null;
        }
        renderPanel();

        if ((els.input.value || "").trim()) runScan();
      });

      els.btnScan.addEventListener("click", runScan);
      els.btnExport.addEventListener("click", exportCurrent);
      els.btnClear.addEventListener("click", clearAll);

      if (els.btnLoadA) els.btnLoadA.addEventListener("click", () => { els.input.value = TEST_A; runScan(); });
      if (els.btnLoadB) els.btnLoadB.addEventListener("click", () => { els.input.value = TEST_B; runScan(); });

      lastBench = SUITE.benchmark(POLICY_MODE, null);
      renderPanel();

      clearAll();
    } catch (err) {
      setErrorUI("Boot error", err);
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
