// app_prod.js — Validoon v4.6.2 (patched: remove Stripe-like test secret)
// Fixes 3 Enterprise Red Flags:
// (1) Padding Bypass: decay applies ONLY to meaningful lines (non-empty, non-comment)
// (2) ReDoS / CPU spike: entropy scanning uses safe truncation + strict caps
// (3) Deterministic prefixes + Base64 unpacking (bounded) for high-certainty secret detection
// Local-only. Deterministic. No network calls.

(() => {
  "use strict";

  const BUILD =
    "Validoon v4.6.2 • Correlation + Guard + SafeNorm/Entropy Caps + Deterministic Secrets (patched tests)";
  const $ = (id) => document.getElementById(id);

  // -----------------------------
  // DOM references (must match index.html)
  // -----------------------------
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

  // -----------------------------
  // Policy modes
  // -----------------------------
  const POLICY = {
    MODES: ["BALANCED", "STRICT", "DEV"],
    DEFAULT: "BALANCED",
    STORAGE_KEY: "validoon_policy_mode",
    get() {
      try {
        const saved = (localStorage.getItem(this.STORAGE_KEY) || "")
          .toUpperCase()
          .trim();
        if (this.MODES.includes(saved)) return saved;
      } catch (_) {}
      return this.DEFAULT;
    },
    set(mode) {
      const m = String(mode || "").toUpperCase().trim();
      if (!this.MODES.includes(m)) return this.get();
      try {
        localStorage.setItem(this.STORAGE_KEY, m);
      } catch (_) {}
      return m;
    },
    describe(mode) {
      if (mode === "STRICT")
        return "STRICT — Highest sensitivity. Use for incident review / prod payloads.";
      if (mode === "DEV")
        return "DEV — Lower sensitivity. Use for noisy dev logs / CI.";
      return "BALANCED — Practical default for real logs with reduced false positives.";
    },
  };

  let POLICY_MODE = POLICY.get();

  function tuning() {
    if (POLICY_MODE === "STRICT") {
      return {
        riskMultiplier: 1.25,
        entropyMin: 3.5,
        tokenMinLen: 18,
        corr: { decay: 0.92, floor: 0.05, boostMult: 1.15, chainGate: 0.95 },
        guard: {
          window: 14,
          benignRatio: 0.65,
          chainScale: 0.55,
          forceDangerOnChain: true,
        },
        perf: {
          entropyMaxScanChars: 2200,
          entropyTailChars: 600,
          maxEntropyTokensPerLine: 12,
          maxLineCharsForAnyRegex: 12000,
          maxBase64CandidatesPerLine: 6,
          maxBase64CandidateLen: 1400,
          maxDecodedLen: 2400,
        },
      };
    }
    if (POLICY_MODE === "DEV") {
      return {
        riskMultiplier: 0.75,
        entropyMin: 3.85,
        tokenMinLen: 24,
        corr: { decay: 0.9, floor: 0.02, boostMult: 0.85, chainGate: 1.05 },
        guard: {
          window: 16,
          benignRatio: 0.35,
          chainScale: 0.28,
          forceDangerOnChain: false,
        },
        perf: {
          entropyMaxScanChars: 1800,
          entropyTailChars: 450,
          maxEntropyTokensPerLine: 8,
          maxLineCharsForAnyRegex: 9000,
          maxBase64CandidatesPerLine: 4,
          maxBase64CandidateLen: 1100,
          maxDecodedLen: 1800,
        },
      };
    }
    return {
      riskMultiplier: 1.0,
      entropyMin: 3.6,
      tokenMinLen: 20,
      corr: { decay: 0.92, floor: 0.04, boostMult: 1.0, chainGate: 1.0 },
      guard: {
        window: 14,
        benignRatio: 0.5,
        chainScale: 0.35,
        forceDangerOnChain: true,
      },
      perf: {
        entropyMaxScanChars: 2000,
        entropyTailChars: 500,
        maxEntropyTokensPerLine: 10,
        maxLineCharsForAnyRegex: 10000,
        maxBase64CandidatesPerLine: 5,
        maxBase64CandidateLen: 1300,
        maxDecodedLen: 2200,
      },
    };
  }

  // -----------------------------
  // Helpers
  // -----------------------------
  const clamp = (x, min, max) => Math.max(min, Math.min(max, x));
  const clamp01 = (x) => clamp(x, 0, 1);

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function shannonEntropy(str) {
    const s = String(str || "");
    if (!s.length) return 0;
    const freq = {};
    for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
    let ent = 0;
    const n = s.length;
    for (const ch in freq) {
      const p = freq[ch] / n;
      ent -= p * Math.log2(p);
    }
    return ent;
  }

  function isComment(line) {
    const t = String(line || "").trim();
    if (!t) return true;
    return (
      t.startsWith("#") ||
      t.startsWith("//") ||
      t.startsWith("/*") ||
      t.startsWith("* ")
    );
  }

  function isMeaningfulLine(trimmed, commentFlag) {
    if (commentFlag) return false;
    if (!trimmed) return false;
    return true;
  }

  function looksLikeHashContext(lower) {
    const s = lower || "";
    return (
      s.includes("sha1") ||
      s.includes("sha-1") ||
      s.includes("sha256") ||
      s.includes("sha-256") ||
      s.includes("sha512") ||
      s.includes("sha-512") ||
      s.includes("md5") ||
      s.includes("checksum") ||
      s.includes("digest") ||
      s.includes("commit") ||
      s.includes("revision") ||
      s.includes("image digest") ||
      s.includes("docker image") ||
      s.includes("build id") ||
      s.includes("artifact")
    );
  }

  function isBenignContext(line) {
    const s = String(line || "").toLowerCase();
    return (
      s.includes("example") ||
      s.includes("sample") ||
      s.includes("documentation") ||
      s.includes("docs") ||
      s.includes("not a real secret") ||
      s.includes("dummy") ||
      s.includes("placeholder") ||
      s.includes("for docs") ||
      s.includes("for documentation") ||
      s.includes("test ") ||
      s.includes("staging") ||
      s.includes("sandbox")
    );
  }

  function hasKeywordWindow(lineLower, startIdx, endIdx) {
    const windowSize = 25;
    const a = Math.max(0, startIdx - windowSize);
    const b = Math.min(lineLower.length, endIdx + windowSize);
    const w = lineLower.slice(a, b);
    return (
      w.includes("key") ||
      w.includes("token") ||
      w.includes("secret") ||
      w.includes("password") ||
      w.includes("authorization") ||
      w.includes("auth") ||
      w.includes("api") ||
      w.includes("bearer")
    );
  }

  function safeEntropyScanSlice(trimmed) {
    const p = tuning().perf;
    const s = String(trimmed || "");
    if (s.length <= p.entropyMaxScanChars) return s;
    const head = s.slice(0, p.entropyMaxScanChars);
    const tail = p.entropyTailChars > 0 ? s.slice(-p.entropyTailChars) : "";
    return head + " … " + tail;
  }

  function safeRegexAllowed(trimmed) {
    const p = tuning().perf;
    return String(trimmed || "").length <= p.maxLineCharsForAnyRegex;
  }

  // -----------------------------
  // Deterministic token patterns (enterprise-grade, low FP)
  // -----------------------------
  const DET_PATTERNS = [
    { id: "SECRET:STRIPE", re: /\bsk_(?:live|test)_[0-9a-zA-Z]{18,}\b/g },
    { id: "SECRET:GITHUB", re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g },
    { id: "SECRET:SLACK", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
    { id: "SECRET:AWS_ACCESS_KEY", re: /\bA(?:KIA|SIA)[0-9A-Z]{16}\b/g },
    { id: "SECRET:GCP_API_KEY", re: /\bAIza[0-9A-Za-z\-_]{30,}\b/g },
    { id: "SECRET:TWILIO", re: /\bSK[0-9a-fA-F]{32}\b/g },
    { id: "SECRET:MAILGUN", re: /\bkey-[0-9a-fA-F]{32}\b/g },
  ];

  function findDeterministicSecrets(text) {
    const out = [];
    if (!text) return out;
    for (const p of DET_PATTERNS) {
      let m;
      p.re.lastIndex = 0;
      while ((m = p.re.exec(text)) !== null) {
        out.push({ type: p.id, value: m[0] });
        if (out.length >= 12) return out;
      }
    }
    return out;
  }

  // -----------------------------
  // Base64 unpacking (bounded + safe)
  // -----------------------------
  function isBase64Candidate(tok) {
    if (!tok) return false;
    if (!/^[A-Za-z0-9+/_=-]+$/.test(tok)) return false;
    if (tok.length < 28) return false;
    if (!/[=_-]/.test(tok)) return false;
    return true;
  }

  function safeAtob(b64) {
    try {
      let s = String(b64).replace(/-/g, "+").replace(/_/g, "/");
      while (s.length % 4 !== 0) s += "=";
      return atob(s);
    } catch (_) {
      return null;
    }
  }

  function looksMostlyText(decoded) {
    if (!decoded) return false;
    let bad = 0;
    const n = Math.min(decoded.length, 800);
    for (let i = 0; i < n; i++) {
      const c = decoded.charCodeAt(i);
      if (c === 9 || c === 10 || c === 13) continue;
      if (c < 32 || c === 127) bad++;
    }
    return bad / Math.max(1, n) < 0.06;
  }

  // -----------------------------
  // Feature extraction
  // -----------------------------
  function extractFeatures(lines) {
    const feats = [];
    for (const raw of lines) {
      const trimmed = String(raw || "").replace(/\r/g, "").trim();
      const lower = trimmed.toLowerCase();
      const comment = isComment(trimmed);

      feats.push({
        raw,
        trimmed,
        lower,
        comment,
        meaningful: isMeaningfulLine(trimmed, comment),

        benign: isBenignContext(trimmed),
        hashCtx: looksLikeHashContext(lower),

        hasMetadataIP: /\b169\.254\.169\.254\b/.test(trimmed),
        hasMetadataPath: /\/latest\/meta-?data/i.test(trimmed),

        hasDockerSock: /\/var\/run\/docker\.sock\b/.test(trimmed),
        hasDockerPriv:
          /\b--privileged\b|privileged:\s*true/i.test(trimmed),
        hasEtcShadow: /\/etc\/shadow\b/.test(trimmed),
        hasEtcPasswd: /\/etc\/passwd\b/.test(trimmed),
        hasDockerRun: /\bdocker\s+run\b/i.test(trimmed),

        hasAuthHeader:
          /authorization:\s*bearer/i.test(trimmed) ||
          /\bauthorization:\b/i.test(trimmed),
        hasJwtLike:
          /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/.test(
            trimmed
          ),

        hasPromptOverride:
          /\b(ignore|jailbreak|disregard previous|override instructions|you are now)\b/i.test(
            trimmed
          ),

        hasScriptTag: /<\s*script\b/i.test(trimmed),
        hasInlineEvent: /\bon\w+\s*=\s*["'][^"']*["']/i.test(trimmed),
        hasJsProto: /\bjavascript:\b/i.test(trimmed),

        entropy: 0,
        entropyHit: false,
        entropyIsHashContext: false,
        entropyIsAuthContext: false,
        entropyNearKeyword: false,

        detSecrets: [],
        decodedDetSecrets: [],
        decodedSignals: [],
      });
    }
    return feats;
  }

  function detectDeterministicSecrets(feats) {
    for (const f of feats) {
      if (!f.meaningful) continue;
      if (!safeRegexAllowed(f.trimmed)) continue;
      const found = findDeterministicSecrets(f.trimmed);
      if (found.length) f.detSecrets = found;
    }
  }

  function detectEntropy(feats) {
    const t = tuning();
    const p = t.perf;

    for (const f of feats) {
      if (!f.meaningful) continue;
      if (!safeRegexAllowed(f.trimmed)) continue;

      const scanText = safeEntropyScanSlice(f.trimmed);
      const lowerScan = scanText.toLowerCase();

      const tokens = scanText.match(/[A-Za-z0-9+/_=.-]{24,}/g);
      if (!tokens) continue;

      let checked = 0;
      for (const tok of tokens) {
        if (checked >= p.maxEntropyTokensPerLine) break;
        checked++;

        if (tok.length < t.tokenMinLen) continue;

        const ent = shannonEntropy(tok);
        if (ent < t.entropyMin) continue;

        const idx = lowerScan.indexOf(tok.toLowerCase());
        const nearKw =
          idx >= 0
            ? hasKeywordWindow(lowerScan, idx, idx + tok.length)
            : false;

        const base64Like =
          /^[A-Za-z0-9+/_=.-]+$/.test(tok) && /[=_-]/.test(tok);

        const allowed =
          f.hasAuthHeader || nearKw || (base64Like && POLICY_MODE !== "DEV");
        if (!allowed) continue;

        f.entropy = ent;
        f.entropyHit = true;
        f.entropyIsHashContext = f.hashCtx;
        f.entropyIsAuthContext = f.hasAuthHeader;
        f.entropyNearKeyword = nearKw;
        break;
      }
    }
  }

  function detectBase64Unpack(feats) {
    const p = tuning().perf;

    for (const f of feats) {
      if (!f.meaningful) continue;
      if (!safeRegexAllowed(f.trimmed)) continue;

      const scanText = safeEntropyScanSlice(f.trimmed);
      const candidates = scanText.match(/[A-Za-z0-9+/_=-]{28,}/g);
      if (!candidates) continue;

      let tried = 0;
      for (const tok of candidates) {
        if (tried >= p.maxBase64CandidatesPerLine) break;
        if (!isBase64Candidate(tok)) continue;
        if (tok.length > p.maxBase64CandidateLen) continue;

        tried++;

        const decoded = safeAtob(tok);
        if (!decoded) continue;
        if (decoded.length > p.maxDecodedLen) continue;
        if (!looksMostlyText(decoded)) continue;

        const det = findDeterministicSecrets(decoded);
        if (det.length) {
          f.decodedDetSecrets = det;
          f.decodedSignals.push("DECODED:DETERMINISTIC_SECRET");
          break;
        }

        const dlow = decoded.toLowerCase();
        const hasMeta =
          dlow.includes("169.254.169.254") ||
          dlow.includes("/latest/meta-data");
        const hasSock = dlow.includes("/var/run/docker.sock");
        const hasAuth =
          dlow.includes("authorization:") || dlow.includes("bearer ");
        const hasPrompt =
          /\b(ignore|jailbreak|disregard previous|override instructions|you are now)\b/i.test(
            decoded
          );

        if (hasMeta || hasSock || (hasAuth && !f.benign) || hasPrompt) {
          if (hasMeta) f.decodedSignals.push("DECODED:METADATA");
          if (hasSock) f.decodedSignals.push("DECODED:DOCKER_SOCK");
          if (hasAuth) f.decodedSignals.push("DECODED:AUTH");
          if (hasPrompt) f.decodedSignals.push("DECODED:PROMPT");
          break;
        }
      }
    }
  }

  // -----------------------------
  // FRSM Signal matrix
  // -----------------------------
  const SIGNAL_MATRIX = {
    "SSRF:METADATA": { impact: 5, exploit: 4, exposure: 4 },
    "AUTH:HEADER": { impact: 4, exploit: 4, exposure: 4 },
    "ENTROPY:SECRET": { impact: 4, exploit: 3, exposure: 3 },
    "AUTH:JWT_LIKE": { impact: 3, exploit: 3, exposure: 3 },

    "INFRA:DOCKER_SOCK": { impact: 4, exploit: 4, exposure: 4 },
    "INFRA:DOCKER_PRIV": { impact: 5, exploit: 4, exposure: 3 },
    "INFRA:SHADOW": { impact: 5, exploit: 3, exposure: 3 },
    "INFRA:PASSWD": { impact: 3, exploit: 2, exposure: 3 },
    "INFRA:DOCKER_RUN": { impact: 3, exploit: 3, exposure: 3 },

    "PROMPT:OVERRIDE": { impact: 3, exploit: 4, exposure: 3 },

    "WEB:XSS_SCRIPT": { impact: 3, exploit: 3, exposure: 3 },
    "WEB:INLINE_EVENT": { impact: 2, exploit: 3, exposure: 2 },
    "WEB:JS_PROTOCOL": { impact: 2, exploit: 3, exposure: 2 },

    "ENTROPY:HASH_HINT": { impact: 1, exploit: 1, exposure: 2 },

    "SECRET:DETERMINISTIC": { impact: 5, exploit: 4, exposure: 4 },
    "SECRET:DETERMINISTIC_DECODED": { impact: 5, exploit: 4, exposure: 4 },

    "DECODED:METADATA": { impact: 4, exploit: 4, exposure: 4 },
    "DECODED:DOCKER_SOCK": { impact: 4, exploit: 4, exposure: 4 },
    "DECODED:AUTH": { impact: 4, exploit: 3, exposure: 3 },
    "DECODED:PROMPT": { impact: 3, exploit: 3, exposure: 3 },
  };

  function riskForSignal(id, conf) {
    const m = SIGNAL_MATRIX[id];
    if (!m) return 0;
    const base = m.impact * m.exploit * m.exposure;
    return base * clamp01(conf);
  }

  // -----------------------------
  // Event model (correlation)
  // -----------------------------
  const EV = {
    METADATA: "EV_METADATA",
    AUTH: "EV_AUTH",
    JWT: "EV_JWT",
    SECRET: "EV_SECRET",
    DET_SECRET: "EV_DET_SECRET",
    DOCKER_SOCK: "EV_DOCKER_SOCK",
    DOCKER_PRIV: "EV_DOCKER_PRIV",
    SHADOW: "EV_SHADOW",
    DOCKER_RUN: "EV_DOCKER_RUN",
    PROMPT: "EV_PROMPT",
    XSS: "EV_XSS",
    HASH_CTX: "EV_HASH_CTX",
    DEC_META: "EV_DEC_META",
    DEC_SOCK: "EV_DEC_SOCK",
    DEC_AUTH: "EV_DEC_AUTH",
    DEC_PROMPT: "EV_DEC_PROMPT",
  };

  function eventsForFeature(f) {
    const set = new Set();

    if (f.hasMetadataIP || f.hasMetadataPath) set.add(EV.METADATA);
    if (f.hasAuthHeader) set.add(EV.AUTH);
    if (f.hasJwtLike) set.add(EV.JWT);

    if (f.entropyHit && !f.entropyIsHashContext) set.add(EV.SECRET);

    if (f.detSecrets && f.detSecrets.length) set.add(EV.DET_SECRET);
    if (f.decodedDetSecrets && f.decodedDetSecrets.length) set.add(EV.DET_SECRET);

    if (f.hasDockerSock) set.add(EV.DOCKER_SOCK);
    if (f.hasDockerPriv) set.add(EV.DOCKER_PRIV);
    if (f.hasEtcShadow) set.add(EV.SHADOW);
    if (f.hasDockerRun) set.add(EV.DOCKER_RUN);

    if (f.hasPromptOverride) set.add(EV.PROMPT);

    if (f.hasScriptTag || f.hasInlineEvent || f.hasJsProto) set.add(EV.XSS);

    if (f.hashCtx) set.add(EV.HASH_CTX);

    if (f.decodedSignals && f.decodedSignals.length) {
      if (f.decodedSignals.includes("DECODED:METADATA")) set.add(EV.DEC_META);
      if (f.decodedSignals.includes("DECODED:DOCKER_SOCK")) set.add(EV.DEC_SOCK);
      if (f.decodedSignals.includes("DECODED:AUTH")) set.add(EV.DEC_AUTH);
      if (f.decodedSignals.includes("DECODED:PROMPT")) set.add(EV.DEC_PROMPT);
    }

    return set;
  }

  // -----------------------------
  // Pass 1: line scoring (FRSM)
  // -----------------------------
  function scoreLinesBase(feats) {
    const t = tuning();
    const results = [];
    const activeSignals = [];
    let totalBaseRisk = 0;

    for (const f of feats) {
      if (!f.meaningful) {
        results.push({
          decision: "ALLOW",
          confidence: 0,
          risk: 0,
          entropy: 0,
          reason: "",
          hits: [],
          baseRisk: 0,
          corrBoost: 0,
        });
        continue;
      }

      let lineRisk = 0;
      const hits = [];
      let reason = "";

      const add = (id, conf) => {
        const r = riskForSignal(id, conf);
        if (r > 0) {
          lineRisk += r;
          hits.push(id);
          activeSignals.push(id);
          if (!reason) reason = id;
        }
      };

      if (f.detSecrets && f.detSecrets.length) {
        add("SECRET:DETERMINISTIC", f.benign ? 0.55 : 1.0);
      }
      if (f.decodedDetSecrets && f.decodedDetSecrets.length) {
        add("SECRET:DETERMINISTIC_DECODED", f.benign ? 0.55 : 1.0);
      }

      if (f.decodedSignals && f.decodedSignals.length) {
        if (f.decodedSignals.includes("DECODED:METADATA")) add("DECODED:METADATA", 0.95);
        if (f.decodedSignals.includes("DECODED:DOCKER_SOCK")) add("DECODED:DOCKER_SOCK", 0.95);
        if (f.decodedSignals.includes("DECODED:AUTH")) add("DECODED:AUTH", f.benign ? 0.55 : 0.85);
        if (f.decodedSignals.includes("DECODED:PROMPT")) add("DECODED:PROMPT", f.benign ? 0.55 : 0.8);
      }

      if (f.hasMetadataIP || f.hasMetadataPath) add("SSRF:METADATA", 1.0);

      if (f.hasDockerSock) add("INFRA:DOCKER_SOCK", 1.0);
      if (f.hasDockerPriv) add("INFRA:DOCKER_PRIV", 1.0);
      if (f.hasEtcShadow) add("INFRA:SHADOW", 1.0);
      if (f.hasEtcPasswd) add("INFRA:PASSWD", 0.8);
      if (f.hasDockerRun) add("INFRA:DOCKER_RUN", 0.85);

      if (f.hasAuthHeader) add("AUTH:HEADER", f.benign ? 0.6 : 1.0);
      if (f.hasJwtLike && !f.hasAuthHeader) add("AUTH:JWT_LIKE", f.benign ? 0.55 : 0.8);

      if (f.hasPromptOverride) add("PROMPT:OVERRIDE", f.benign ? 0.6 : 0.9);

      if (f.hasScriptTag) add("WEB:XSS_SCRIPT", 0.8);
      if (f.hasInlineEvent) add("WEB:INLINE_EVENT", 0.75);
      if (f.hasJsProto) add("WEB:JS_PROTOCOL", 0.75);

      if (f.entropyHit && !f.entropyIsHashContext) {
        const conf = f.entropyIsAuthContext && !f.benign ? 1.0 : f.benign ? 0.55 : 0.8;
        add("ENTROPY:SECRET", conf);
      } else if (f.entropyHit && f.entropyIsHashContext) {
        add("ENTROPY:HASH_HINT", POLICY_MODE === "STRICT" ? 0.4 : 0.2);
      }

      lineRisk *= t.riskMultiplier;
      totalBaseRisk += lineRisk;

      let decision = "ALLOW";
      if (lineRisk >= 50) decision = "BLOCK";
      else if (lineRisk >= 20) decision = "WARN";

      const confidence = clamp01(lineRisk / 70);

      results.push({
        decision,
        confidence,
        risk: Math.round(lineRisk),
        entropy: Number(f.entropy.toFixed(1)),
        reason,
        hits: Array.from(new Set(hits)),
        baseRisk: lineRisk,
        corrBoost: 0,
      });
    }

    return {
      results,
      activeSignals: Array.from(new Set(activeSignals)).sort(),
      totalBaseRisk,
    };
  }

  // -----------------------------
  // Context Guard
  // -----------------------------
  function benignWindowRatio(feats, endIndex) {
    const g = tuning().guard;
    const start = Math.max(0, endIndex - g.window);
    let denom = 0;
    let benign = 0;

    for (let i = start; i <= endIndex && i < feats.length; i++) {
      const f = feats[i];
      if (!f || !f.meaningful) continue;
      denom++;
      if (f.benign || f.hashCtx) benign++;
    }

    if (!denom) return { ratio: 0, denom: 0, benign: 0, start, end: endIndex };
    return { ratio: benign / denom, denom, benign, start, end: endIndex };
  }

  function shouldGuardChain(feats, endIndex) {
    const g = tuning().guard;
    const w = benignWindowRatio(feats, endIndex);
    return w.denom >= 3 && w.ratio >= g.benignRatio;
  }

  // -----------------------------
  // Pass 2: correlation accumulator
  // (1) padding bypass fixed: decay ONLY on meaningful lines
  // -----------------------------
  function correlate(feats, base) {
    const t = tuning();
    const c = t.corr;
    const g = t.guard;

    const eventsByLine = feats.map(eventsForFeature);

    const acc = { cloud: 0, infra: 0, ai: 0, secrets: 0, web: 0 };

    const last = {
      metadata: -1,
      auth: -1,
      secret: -1,
      detSecret: -1,
      dockerSock: -1,
      dockerPriv: -1,
      shadow: -1,
      prompt: -1,
    };

    const chain = {
      cloudCreds: false,
      containerTakeover: false,
      aiOps: false,

      cloudCredsGuarded: false,
      containerTakeoverGuarded: false,
      aiOpsGuarded: false,
    };

    let chainRisk = 0;

    const corrBoost = new Array(feats.length).fill(0);
    const corrTags = new Array(feats.length).fill(null).map(() => new Set());

    function decayAccMeaningful() {
      acc.cloud = Math.max(acc.cloud * c.decay, c.floor);
      acc.infra = Math.max(acc.infra * c.decay, c.floor);
      acc.ai = Math.max(acc.ai * c.decay, c.floor);
      acc.secrets = Math.max(acc.secrets * c.decay, c.floor);
      acc.web = Math.max(acc.web * c.decay, c.floor);
    }

    function attributeBoost(idx, amount, tag) {
      if (idx < 0 || idx >= corrBoost.length) return;
      corrBoost[idx] += amount;
      corrTags[idx].add(tag);
    }

    const TH = {
      CLOUD_X: 1.35,
      SECRETS_Y: 1.15,
      INFRA_X: 1.35,
      AI_X: 1.25,
    };

    const W = {
      metadata: 1.0,
      auth: 0.95,
      jwt: 0.55,
      secret: 0.9,
      detSecret: 1.15,
      dockerSock: 0.95,
      dockerPriv: 0.85,
      shadow: 0.8,
      dockerRun: 0.55,
      prompt: 0.8,
      hashCtx: -0.35,
      decodedMeta: 0.95,
      decodedSock: 0.95,
      decodedAuth: 0.75,
      decodedPrompt: 0.7,
    };

    for (let i = 0; i < feats.length; i++) {
      const f = feats[i];
      const ev = eventsByLine[i];

      if (f.meaningful) {
        decayAccMeaningful();
      } else {
        continue;
      }

      if (ev.has(EV.HASH_CTX)) {
        acc.secrets = Math.max(0, acc.secrets + W.hashCtx);
      }

      if (ev.has(EV.METADATA)) {
        acc.cloud += W.metadata;
        last.metadata = i;
      }
      if (ev.has(EV.DEC_META)) {
        acc.cloud += W.decodedMeta;
        last.metadata = i;
      }

      if (ev.has(EV.AUTH)) {
        acc.secrets += W.auth;
        acc.cloud += 0.25;
        last.auth = i;
      }
      if (ev.has(EV.DEC_AUTH)) {
        acc.secrets += W.decodedAuth;
        acc.cloud += 0.2;
        last.auth = i;
      }
      if (ev.has(EV.JWT)) {
        acc.secrets += W.jwt;
      }

      if (ev.has(EV.SECRET)) {
        acc.secrets += f.benign ? W.secret * 0.55 : W.secret;
        last.secret = i;
      }
      if (ev.has(EV.DET_SECRET)) {
        acc.secrets += f.benign ? W.detSecret * 0.55 : W.detSecret;
        last.detSecret = i;
      }

      if (ev.has(EV.DOCKER_SOCK)) {
        acc.infra += W.dockerSock;
        last.dockerSock = i;
      }
      if (ev.has(EV.DEC_SOCK)) {
        acc.infra += W.decodedSock;
        last.dockerSock = i;
      }
      if (ev.has(EV.DOCKER_PRIV)) {
        acc.infra += W.dockerPriv;
        last.dockerPriv = i;
      }
      if (ev.has(EV.SHADOW)) {
        acc.infra += W.shadow;
        last.shadow = i;
      }
      if (ev.has(EV.DOCKER_RUN)) {
        acc.infra += W.dockerRun;
      }

      if (ev.has(EV.PROMPT)) {
        acc.ai += f.benign ? W.prompt * 0.55 : W.prompt;
        last.prompt = i;
      }
      if (ev.has(EV.DEC_PROMPT)) {
        acc.ai += f.benign ? W.decodedPrompt * 0.55 : W.decodedPrompt;
        last.prompt = i;
      }

      // A) Cloud credential chain
      const cloudCredsReady =
        acc.cloud >= TH.CLOUD_X &&
        acc.secrets >= TH.SECRETS_Y &&
        last.metadata >= 0 &&
        (last.auth >= 0 || last.secret >= 0 || last.detSecret >= 0);

      if (cloudCredsReady) {
        chain.cloudCreds = true;

        const guarded = shouldGuardChain(feats, i);
        if (guarded) chain.cloudCredsGuarded = true;

        const baseAdd = 60;
        const scale = guarded ? g.chainScale : 1.0;
        const add = baseAdd * c.boostMult * c.chainGate * scale;
        chainRisk += add;

        const tagPrefix = guarded ? "CHAIN_GUARDED:CLOUD" : "CHAIN:CLOUD";
        const authIdx =
          last.detSecret >= 0
            ? last.detSecret
            : last.auth >= 0
              ? last.auth
              : last.secret;

        attributeBoost(last.metadata, (guarded ? 9 : 19) * c.boostMult, `${tagPrefix}_METADATA`);
        attributeBoost(authIdx, (guarded ? 9 : 19) * c.boostMult, `${tagPrefix}_AUTH`);
        attributeBoost(i, (guarded ? 6 : 12) * c.boostMult, `${tagPrefix}_AGG`);
        if (guarded) attributeBoost(i, 0, "CONTEXT_GUARD:DOC_LIKELY");

        acc.cloud *= guarded ? 0.78 : 0.65;
        acc.secrets *= guarded ? 0.78 : 0.65;
      }

      // B) Container takeover chain
      const containerReady =
        acc.infra >= TH.INFRA_X &&
        last.dockerSock >= 0 &&
        (last.dockerPriv >= 0 || last.shadow >= 0);

      if (containerReady) {
        chain.containerTakeover = true;

        const guarded = shouldGuardChain(feats, i);
        if (guarded) chain.containerTakeoverGuarded = true;

        const baseAdd = 48;
        const scale = guarded ? g.chainScale : 1.0;
        const add = baseAdd * c.boostMult * c.chainGate * scale;
        chainRisk += add;

        const tagPrefix = guarded ? "CHAIN_GUARDED:DOCKER" : "CHAIN:DOCKER";
        attributeBoost(last.dockerSock, (guarded ? 9 : 19) * c.boostMult, `${tagPrefix}_SOCK`);
        attributeBoost(
          last.dockerPriv >= 0 ? last.dockerPriv : last.shadow,
          (guarded ? 8 : 16) * c.boostMult,
          `${tagPrefix}_ESC`
        );
        attributeBoost(i, (guarded ? 6 : 10) * c.boostMult, `${tagPrefix}_AGG`);
        if (guarded) attributeBoost(i, 0, "CONTEXT_GUARD:DOC_LIKELY");

        acc.infra *= guarded ? 0.8 : 0.68;
      }

      // C) AI-to-ops chain
      const aiOpsReady =
        acc.ai >= TH.AI_X &&
        (acc.infra >= 0.9 || acc.cloud >= 0.9) &&
        last.prompt >= 0 &&
        (last.dockerSock >= 0 || last.metadata >= 0);

      if (aiOpsReady) {
        chain.aiOps = true;

        const guarded = shouldGuardChain(feats, i);
        if (guarded) chain.aiOpsGuarded = true;

        const baseAdd = 42;
        const scale = guarded ? g.chainScale : 1.0;
        const add = baseAdd * c.boostMult * c.chainGate * scale;
        chainRisk += add;

        const tagPrefix = guarded ? "CHAIN_GUARDED:AI" : "CHAIN:AI";
        attributeBoost(last.prompt, (guarded ? 8 : 16) * c.boostMult, `${tagPrefix}_PROMPT`);
        attributeBoost(
          last.dockerSock >= 0 ? last.dockerSock : last.metadata,
          (guarded ? 8 : 14) * c.boostMult,
          `${tagPrefix}_INFRA`
        );
        attributeBoost(i, (guarded ? 6 : 10) * c.boostMult, `${tagPrefix}_AGG`);
        if (guarded) attributeBoost(i, 0, "CONTEXT_GUARD:DOC_LIKELY");

        acc.ai *= guarded ? 0.82 : 0.7;
      }
    }

    const merged = base.results.map((r, i) => {
      const boost = corrBoost[i] || 0;
      const newRisk = r.baseRisk + boost;

      let decision = "ALLOW";
      if (newRisk >= 50) decision = "BLOCK";
      else if (newRisk >= 20) decision = "WARN";

      const confidence = clamp01(newRisk / 75);

      let reason = r.reason;
      if (!reason && corrTags[i] && corrTags[i].size) reason = Array.from(corrTags[i])[0];

      const hits = new Set(r.hits || []);
      if (corrTags[i] && corrTags[i].size) {
        for (const tag of corrTags[i]) hits.add(tag);
      }

      return {
        ...r,
        decision,
        confidence,
        risk: Math.round(newRisk),
        reason,
        hits: Array.from(hits),
        corrBoost: boost,
      };
    });

    const corrSignals = [];
    if (chain.cloudCreds)
      corrSignals.push(
        chain.cloudCredsGuarded
          ? "ATTACK_CHAIN:CLOUD_CREDS_GUARDED"
          : "ATTACK_CHAIN:CLOUD_CREDS"
      );
    if (chain.containerTakeover)
      corrSignals.push(
        chain.containerTakeoverGuarded
          ? "ATTACK_CHAIN:CONTAINER_TAKEOVER_GUARDED"
          : "ATTACK_CHAIN:CONTAINER_TAKEOVER"
      );
    if (chain.aiOps)
      corrSignals.push(
        chain.aiOpsGuarded
          ? "ATTACK_CHAIN:AI_TO_OPS_GUARDED"
          : "ATTACK_CHAIN:AI_TO_OPS"
      );

    return { results: merged, chain, chainRisk, corrSignals };
  }

  // -----------------------------
  // Verdict aggregation
  // -----------------------------
  function aggregateVerdict(base, corr) {
    const g = tuning().guard;
    const totalRisk = base.totalBaseRisk + corr.chainRisk;

    let verdict = "SECURE";
    if (totalRisk >= 110) verdict = "DANGER";
    else if (totalRisk >= 45) verdict = "WARN";

    let overallConfidence = clamp(Math.round((totalRisk / 135) * 100), 0, 100);

    const anyChain = corr.chain.cloudCreds || corr.chain.containerTakeover || corr.chain.aiOps;

    const anyUnguardedChain =
      (corr.chain.cloudCreds && !corr.chain.cloudCredsGuarded) ||
      (corr.chain.containerTakeover && !corr.chain.containerTakeoverGuarded) ||
      (corr.chain.aiOps && !corr.chain.aiOpsGuarded);

    const anyGuardedOnly =
      anyChain &&
      !anyUnguardedChain &&
      ((corr.chain.cloudCreds && corr.chain.cloudCredsGuarded) ||
        (corr.chain.containerTakeover && corr.chain.containerTakeoverGuarded) ||
        (corr.chain.aiOps && corr.chain.aiOpsGuarded));

    if (anyChain && anyUnguardedChain && g.forceDangerOnChain) {
      verdict = "DANGER";
      overallConfidence = Math.max(overallConfidence, POLICY_MODE === "DEV" ? 80 : 95);
    }

    if (anyGuardedOnly) {
      overallConfidence = Math.max(overallConfidence, POLICY_MODE === "DEV" ? 55 : 72);
      if (verdict === "SECURE") verdict = "WARN";
    }

    const activeSignals = new Set(base.activeSignals || []);
    for (const s of corr.corrSignals || []) activeSignals.add(s);

    return {
      verdict,
      overallConfidence,
      totalRisk,
      activeSignals: Array.from(activeSignals).sort(),
    };
  }

  // -----------------------------
  // Remediation library
  // -----------------------------
  const REMED = {
    "SECRET:DETERMINISTIC": {
      name: "Rotate deterministic vendor keys immediately",
      why: "High-certainty vendor token pattern detected (enterprise-grade signal).",
      actions: [
        "Rotate/revoke the key/token immediately (treat as incident).",
        "Purge logs/artifacts containing the token; invalidate caches and CI variables.",
        "Add CI secret scanning and runtime log redaction policies.",
      ],
    },
    "SECRET:DETERMINISTIC_DECODED": {
      name: "Rotate keys found via Base64 unpacking",
      why: "A deterministic vendor token was discovered after decoding (common attacker concealment).",
      actions: [
        "Rotate/revoke the key/token immediately.",
        "Identify the encoder source (pipeline/log transform) and stop emitting encoded secrets.",
        "Add policy to block encoded secrets at ingestion.",
      ],
    },
    "ATTACK_CHAIN:CLOUD_CREDS": {
      name: "Stop cloud credential exposure chain",
      why: "Metadata endpoint correlated with auth/secret context indicates potential credential theft.",
      actions: [
        "Block egress to 169.254.169.254 at host/sidecar/firewall level.",
        "Harden IMDS (require session tokens where supported) and disable where not needed.",
        "Disallow server-side fetching of user-controlled URLs unless strict allowlists are enforced.",
      ],
    },
    "ATTACK_CHAIN:CLOUD_CREDS_GUARDED": {
      name: "Cloud chain detected in doc-like context (verify intent)",
      why: "Chain pattern exists but context resembles documentation/examples; guarded to reduce false DANGER.",
      actions: [
        "Confirm whether this is docs/testing content or real production logs.",
        "If production: apply the same mitigations as cloud credential exposure.",
        "If docs: replace with explicit placeholders; avoid realistic Authorization examples.",
      ],
    },
    "ATTACK_CHAIN:CONTAINER_TAKEOVER": {
      name: "Mitigate container-to-host takeover chain",
      why: "Docker socket + escalation signals can enable host compromise.",
      actions: [
        "Remove /var/run/docker.sock mounts from untrusted containers.",
        "Eliminate --privileged; replace with minimal capabilities + seccomp/AppArmor.",
        "Separate build tooling from production runtime; restrict hostPath mounts.",
      ],
    },
    "ATTACK_CHAIN:CONTAINER_TAKEOVER_GUARDED": {
      name: "Container chain detected in doc-like context (verify intent)",
      why: "Chain pattern exists but local context resembles docs/examples.",
      actions: [
        "Confirm whether this is documentation/testing content or real deployment manifests/logs.",
        "If real: remove docker.sock mounts and privileged flags.",
        "If docs: use placeholders and avoid copy-pasteable privileged examples.",
      ],
    },
    "ATTACK_CHAIN:AI_TO_OPS": {
      name: "Prevent AI-to-ops escalation",
      why: "Prompt override correlated with infra/cloud primitives can lead to unsafe automation actions.",
      actions: [
        "Enforce tool allowlists for any agent (HTTP/shell/infra actions).",
        "Treat LLM output as untrusted; apply policy gates before executing actions.",
        "Log and block override patterns when infra primitives are present.",
      ],
    },
    "ATTACK_CHAIN:AI_TO_OPS_GUARDED": {
      name: "AI→Ops chain detected in doc-like context (verify intent)",
      why: "Chain pattern exists but local context resembles docs/examples.",
      actions: [
        "Confirm whether this is a tutorial or production agent trace.",
        "If production: enforce tool gating and allowlists immediately.",
        "If docs: mark override examples clearly and avoid real infra primitives in examples.",
      ],
    },
    "SSRF:METADATA": {
      name: "Block metadata SSRF exposure",
      why: "References to metadata endpoints can leak temporary credentials.",
      actions: [
        "Block egress to metadata IP; validate and sanitize any URL fetching logic.",
        "Use allowlists for outbound requests and disable redirects.",
        "Monitor logs for metadata path access attempts.",
      ],
    },
    "INFRA:DOCKER_SOCK": {
      name: "Harden Docker socket exposure",
      why: "Docker socket access enables container management and potential host-level impact.",
      actions: [
        "Remove docker.sock mounts; use dedicated, locked-down build agents if needed.",
        "Apply least privilege and separate environments.",
        "Audit CI/CD and runtime manifests for docker.sock usage.",
      ],
    },
    "AUTH:HEADER": {
      name: "Redact authorization headers",
      why: "Authorization headers frequently contain live bearer tokens.",
      actions: [
        "Strip or hash Authorization headers before logging.",
        "Rotate leaked tokens; use short-lived scoped tokens.",
        "Avoid embedding tokens in documentation or examples.",
      ],
    },
    "ENTROPY:SECRET": {
      name: "Review high-entropy secret-like strings",
      why: "Random-looking strings near auth/token context may be real secrets.",
      actions: [
        "Confirm if real; if yes rotate immediately and purge logs.",
        "Replace with placeholders in docs.",
        "Add CI secret-scanning for repositories.",
      ],
    },
    "ENTROPY:HASH_HINT": {
      name: "Hash/commit context (low risk)",
      why: "Hashes/commits/checksums are typically benign and should not be hard-blocked.",
      actions: [
        "Keep explicit labels (sha256/commit/checksum) to reduce false positives.",
        "Avoid mixing real secrets into the same line/block as hashes.",
      ],
    },
    "PROMPT:OVERRIDE": {
      name: "Constrain prompt override patterns",
      why: "Override patterns can cause unsafe behavior in AI pipelines.",
      actions: [
        "Use non-overridable system policies and strict tool gating.",
        "Flag and review override attempts, especially when infra signals exist.",
        "Separate user content from control instructions.",
      ],
    },
  };

  function remediationFor(activeSignals) {
    const items = [];
    const s = new Set(activeSignals || []);
    const add = (id) => {
      if (s.has(id) && REMED[id]) items.push({ id, ...REMED[id] });
    };

    add("SECRET:DETERMINISTIC");
    add("SECRET:DETERMINISTIC_DECODED");

    add("ATTACK_CHAIN:CLOUD_CREDS");
    add("ATTACK_CHAIN:CLOUD_CREDS_GUARDED");
    add("ATTACK_CHAIN:CONTAINER_TAKEOVER");
    add("ATTACK_CHAIN:CONTAINER_TAKEOVER_GUARDED");
    add("ATTACK_CHAIN:AI_TO_OPS");
    add("ATTACK_CHAIN:AI_TO_OPS_GUARDED");

    const order = [
      "SSRF:METADATA",
      "INFRA:DOCKER_SOCK",
      "INFRA:DOCKER_PRIV",
      "INFRA:SHADOW",
      "AUTH:HEADER",
      "ENTROPY:SECRET",
      "ENTROPY:HASH_HINT",
      "PROMPT:OVERRIDE",
    ];
    for (const id of order) add(id);

    if (!items.length) {
      items.push({
        id: "HYGIENE:BASELINE",
        name: "Baseline hygiene",
        why: "No high-risk signals detected.",
        actions: [
          "Apply least-privilege to roles/tokens/keys.",
          "Avoid logging secrets; use redaction at ingestion.",
          "Regularly review automation and infra guardrails.",
        ],
      });
    }

    const seen = new Set();
    const out = [];
    for (const it of items) {
      if (seen.has(it.id)) continue;
      seen.add(it.id);
      out.push(it);
    }
    return out.slice(0, 8);
  }

  function topReason(verdict, activeSignals) {
    const s = new Set(activeSignals || []);
    if (s.has("SECRET:DETERMINISTIC") || s.has("SECRET:DETERMINISTIC_DECODED"))
      return "Deterministic vendor secret detected (high certainty).";
    if (s.has("ATTACK_CHAIN:CLOUD_CREDS"))
      return "Attack chain: metadata + auth/secret correlation (cloud credentials risk).";
    if (s.has("ATTACK_CHAIN:CLOUD_CREDS_GUARDED"))
      return "Chain pattern detected but context looks like documentation/examples (guarded).";
    if (s.has("ATTACK_CHAIN:CONTAINER_TAKEOVER"))
      return "Attack chain: docker.sock + escalation signals (container-to-host risk).";
    if (s.has("ATTACK_CHAIN:CONTAINER_TAKEOVER_GUARDED"))
      return "Container chain pattern detected in doc-like context (guarded).";
    if (s.has("ATTACK_CHAIN:AI_TO_OPS"))
      return "Attack chain: prompt override correlated with infra/cloud primitives.";
    if (s.has("ATTACK_CHAIN:AI_TO_OPS_GUARDED"))
      return "AI→Ops chain pattern detected in doc-like context (guarded).";
    if (s.has("SSRF:METADATA"))
      return "Cloud metadata endpoint referenced; review for SSRF and credential leakage.";
    if (s.has("AUTH:HEADER"))
      return "Authorization header detected; potential credential exposure.";
    if (s.has("ENTROPY:SECRET"))
      return "High-entropy secret-like token detected near auth/token context.";
    if (verdict === "SECURE") {
      if (s.has("ENTROPY:HASH_HINT"))
        return "No high-risk signals; only hash/commit-like context detected.";
      return "No high-risk signals detected.";
    }
    if (verdict === "WARN") return "Medium-risk signals detected; manual review recommended.";
    return "High-risk signals detected; treat as potential incident.";
  }

  function buildReport(lines, feats, base, corr, agg) {
    const report = {
      build: BUILD,
      policyMode: POLICY_MODE,
      tuning: tuning(),
      ts: new Date().toISOString(),

      lines: lines.slice(),

      results: corr.results.map((r, i) => {
        const f = feats[i];
        const det =
          f && f.detSecrets && f.detSecrets.length
            ? f.detSecrets.map((x) => x.type)
            : [];
        const detDec =
          f && f.decodedDetSecrets && f.decodedDetSecrets.length
            ? f.decodedDetSecrets.map((x) => x.type)
            : [];
        return {
          decision: r.decision,
          confidence: Math.round(r.confidence * 100),
          risk: r.risk,
          baseRisk: Math.round(r.baseRisk),
          corrBoost: Math.round(r.corrBoost || 0),
          entropy: Number.isFinite(r.entropy) ? Number(r.entropy.toFixed(1)) : 0,
          reason: r.reason || "",
          hits: r.hits || [],
          detSecrets: det,
          decodedDetSecrets: detDec,
        };
      }),

      totalRisk: Math.round(agg.totalRisk),
      baseRiskTotal: Math.round(base.totalBaseRisk),
      chainRisk: Math.round(corr.chainRisk),

      verdict: agg.verdict,
      overallConfidence: agg.overallConfidence,

      chain: corr.chain,
      activeSignals: agg.activeSignals,
    };

    report.topReason = topReason(report.verdict, report.activeSignals);
    report.remediation = remediationFor(report.activeSignals);

    return report;
  }

  // -----------------------------
  // Rendering
  // -----------------------------
  function setVerdictBox(verdict) {
    if (!els.verdictBox) return;
    let cls = "verdict-secure";
    if (verdict === "DANGER") cls = "verdict-danger";
    else if (verdict === "WARN") cls = "verdict-warn";
    els.verdictBox.className = "verdict " + cls;
  }

  function renderSignals(activeSignals) {
    if (!els.signals) return;
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
        if (
          id.startsWith("SECRET:") ||
          id.startsWith("ATTACK_CHAIN:") ||
          id.startsWith("SSRF:") ||
          id.startsWith("INFRA:")
        )
          cls = "bad";
        else if (
          id.startsWith("AUTH:") ||
          id.startsWith("ENTROPY:") ||
          id.startsWith("PROMPT:") ||
          id.startsWith("WEB:")
        )
          cls = "warn";
        span.className = "pill " + cls;
        span.textContent = id;
        els.signals.appendChild(span);
      });
  }

  function renderRemediation(items) {
    if (!els.remedList) return;
    els.remedList.innerHTML = "";
    const arr = items || [];
    for (const it of arr) {
      const card = document.createElement("div");
      card.className = "remed-item";

      const head = document.createElement("div");
      head.className = "remed-head";

      const name = document.createElement("div");
      name.className = "remed-name";
      name.textContent = it.name;

      const tag = document.createElement("div");
      tag.className = "remed-tag";
      tag.textContent = it.id;

      head.appendChild(name);
      head.appendChild(tag);

      const why = document.createElement("div");
      why.className = "remed-why";
      why.textContent = it.why;

      const ul = document.createElement("ul");
      ul.className = "remed-actions";
      for (const a of it.actions) {
        const li = document.createElement("li");
        li.textContent = a;
        ul.appendChild(li);
      }

      card.appendChild(head);
      card.appendChild(why);
      card.appendChild(ul);
      els.remedList.appendChild(card);
    }
  }

  function renderRows(report) {
    if (!els.rows) return;
    els.rows.innerHTML = "";
    const frag = document.createDocumentFragment();

    for (let i = 0; i < report.lines.length; i++) {
      const raw = report.lines[i];
      const r = report.results[i];

      const row = document.createElement("div");
      row.className = "row";

      const c1 = document.createElement("div");
      c1.className = "mono";
      c1.innerHTML = escapeHtml(raw);

      const c2 = document.createElement("div");
      const pill = document.createElement("span");
      pill.className =
        "pill " +
        (r.decision === "BLOCK"
          ? "bad"
          : r.decision === "WARN"
            ? "warn"
            : "allow");
      pill.textContent = r.decision;
      c2.appendChild(pill);

      const c3 = document.createElement("div");
      c3.textContent = r.confidence + "%";

      const c4 = document.createElement("div");
      c4.textContent = String(r.entropy || 0);

      const c5 = document.createElement("div");
      c5.className = "cell-reason";
      const boostNote = r.corrBoost > 0 ? ` • +${r.corrBoost}c` : "";
      const detNote =
        r.detSecrets && r.detSecrets.length
          ? ` • det:${r.detSecrets[0]}`
          : r.decodedDetSecrets && r.decodedDetSecrets.length
            ? ` • b64:${r.decodedDetSecrets[0]}`
            : "";
      c5.textContent = (r.reason || "—") + boostNote + detNote;

      row.appendChild(c1);
      row.appendChild(c2);
      row.appendChild(c3);
      row.appendChild(c4);
      row.appendChild(c5);

      frag.appendChild(row);
    }

    els.rows.appendChild(frag);
  }

  function renderReport(report, scansCount) {
    if (els.verdictText) els.verdictText.textContent = report.verdict;
    setVerdictBox(report.verdict);

    if (els.overallConf) els.overallConf.textContent = report.overallConfidence + "%";
    if (els.overallMeter) els.overallMeter.style.width = report.overallConfidence + "%";

    const counts = { BLOCK: 0, WARN: 0, ALLOW: 0 };
    for (const r of report.results) counts[r.decision] = (counts[r.decision] || 0) + 1;

    if (els.kScans) els.kScans.textContent = String(scansCount);
    if (els.kBlock) els.kBlock.textContent = String(counts.BLOCK || 0);
    if (els.kWarn) els.kWarn.textContent = String(counts.WARN || 0);
    if (els.kAllow) els.kAllow.textContent = String(counts.ALLOW || 0);

    if (els.topReason) els.topReason.textContent = report.topReason || "—";
    if (els.integrityBadge) els.integrityBadge.textContent = "INTEGRITY: LOCAL";
    if (els.engineBadge)
      els.engineBadge.textContent =
        "ENGINE: DETERMINISTIC + CORR + PERF CAPS + DET-SECRETS";

    renderSignals(report.activeSignals);
    renderRemediation(report.remediation || []);
    renderRows(report);
  }

  // -----------------------------
  // Export JSON
  // -----------------------------
  function exportJson(report) {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const ts = report.ts.replace(/[:.]/g, "-");
    a.download = `validoon_report_${POLICY_MODE.toLowerCase()}_${ts}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // -----------------------------
  // Scan orchestration
  // -----------------------------
  let scans = 0;
  let lastReport = null;

  function runScan() {
    const text = els.input ? els.input.value || "" : "";
    const lines = String(text).split(/\r?\n/);

    const feats = extractFeatures(lines);

    detectDeterministicSecrets(feats);
    detectEntropy(feats);
    detectBase64Unpack(feats);

    const base = scoreLinesBase(feats);
    const corr = correlate(feats, base);
    const agg = aggregateVerdict(base, corr);

    const report = buildReport(lines, feats, base, corr, agg);

    scans += 1;
    lastReport = report;
    renderReport(report, scans);

    console.log("[Validoon v4.6.2]", report);
  }

  function clearAll() {
    if (els.input) els.input.value = "";

    scans = 0;
    lastReport = null;

    if (els.rows) els.rows.innerHTML = "";
    if (els.signals) els.signals.innerHTML = "";
    if (els.remedList) els.remedList.innerHTML = "";

    if (els.verdictText) els.verdictText.textContent = "READY";
    setVerdictBox("SECURE");

    if (els.overallConf) els.overallConf.textContent = "0%";
    if (els.overallMeter) els.overallMeter.style.width = "0%";

    if (els.kScans) els.kScans.textContent = "0";
    if (els.kBlock) els.kBlock.textContent = "0";
    if (els.kWarn) els.kWarn.textContent = "0";
    if (els.kAllow) els.kAllow.textContent = "0";

    if (els.topReason) els.topReason.textContent = "—";
    if (els.integrityBadge) els.integrityBadge.textContent = "INTEGRITY: LOCAL";
    if (els.engineBadge) els.engineBadge.textContent = "ENGINE: DETERMINISTIC";
  }

  function exportCurrent() {
    if (!lastReport) runScan();
    exportJson(lastReport);
  }

  // -----------------------------
  // Built-in tests (A/B)
  // NOTE: Patched TEST_B to avoid any Stripe-like token strings that trigger repo secret scanning.
  // -----------------------------
  const TEST_A = [
    "# Test A — padding bypass attempt (100 comment lines) should NOT kill accumulator now",
    "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/dev-role",
    ...Array.from({ length: 100 }, (_, i) => `# padding line ${i + 1}`),
    'docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine:latest sh -lc "id"',
    "privileged: true",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRldlRva2VuIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  ].join("\n");

  // Patched: does NOT contain "sk_live_" or "sk_test_" patterns.
  const TEST_B = [
    "# Test B — base64 concealed string (safe placeholder, not a vendor token)",
    "Here is a benign line.",
    "Encoded blob (base64): " + btoa("STRIPE_KEY_REDACTED_FOR_TESTS"),
    "sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "note: docs example only",
  ].join("\n");

  // -----------------------------
  // Boot
  // -----------------------------
  function syncPolicyUI() {
    if (els.policySelect) els.policySelect.value = POLICY_MODE;
    if (els.policyHint)
      els.policyHint.textContent =
        "Mode: " + POLICY_MODE + " — " + POLICY.describe(POLICY_MODE);
  }

  function boot() {
    if (els.buildStamp) els.buildStamp.textContent = BUILD;
    syncPolicyUI();

    if (els.policySelect) {
      els.policySelect.addEventListener("change", () => {
        POLICY_MODE = POLICY.set(els.policySelect.value);
        syncPolicyUI();
        if (els.input && (els.input.value || "").trim()) runScan();
      });
    }

    if (els.btnScan) els.btnScan.addEventListener("click", runScan);
    if (els.btnExport) els.btnExport.addEventListener("click", exportCurrent);
    if (els.btnClear) els.btnClear.addEventListener("click", clearAll);

    if (els.btnLoadA) {
      els.btnLoadA.addEventListener("click", () => {
        if (els.input) els.input.value = TEST_A;
        runScan();
      });
    }

    if (els.btnLoadB) {
      els.btnLoadB.addEventListener("click", () => {
        if (els.input) els.input.value = TEST_B;
        runScan();
      });
    }

    clearAll();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
