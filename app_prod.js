// app_prod.js — Validoon v1.4.0_STRICT_ENGINE
(() => {
"use strict";

const BUILD = "prod_v1.4.0_STRICT_ENGINE";
const $ = id => document.getElementById(id);

const RULES = [

  // --- System Commands (STRICT) ---
  { label:"CMD:CAT_PASSWD", test:s=>/\bcat\s+\/etc\/passwd\b/i.test(s), sev:100 },
  { label:"CMD:CAT_SHADOW", test:s=>/\bcat\s+\/etc\/shadow\b/i.test(s), sev:100 },
  { label:"CMD:WHOAMI", test:s=>/\bwhoami\b/i.test(s), sev:95 },
  { label:"CMD:ID", test:s=>/\bid\b/i.test(s), sev:90 },
  { label:"CMD:UNAME", test:s=>/\buname\b/i.test(s), sev:90 },

  // --- Metadata SSRF ---
  { label:"SSRF:METADATA", test:s=>/169\.254\.169\.254/.test(s), sev:100 },

  // --- Docker ---
  { label:"INFRA:DOCKER", test:s=>/docker\.sock|containers\/json/i.test(s), sev:100 },

  // --- Private Key ---
  { label:"SECRET:PRIVATE_KEY", test:s=>/BEGIN RSA PRIVATE KEY/i.test(s), sev:100 },

  // --- AI Override ---
  { label:"AI:JAILBREAK", test:s=>/ignore all previous instructions|terminate safety filter|dan mode/i.test(s), sev:95 }

];

function analyzeOne(input){
  const s = input.trim();
  const hits = RULES.filter(r=>r.test(s));
  const score = hits.reduce((a,b)=>a+b.sev,0);
  const sev = Math.min(score,100);
  const decision = sev>=100?"BLOCK":sev>=50?"WARN":"ALLOW";
  return {input:s, decision, sev};
}

let scanCount=0;

function runScan(){
  const lines = ($("input").value||"")
    .split("\n")
    .map(l=>l.trim())
    .filter(l=>l);

  const rows = lines.map(analyzeOne);
  scanCount++;
  updateUI(rows);
}

function updateUI(rows){
  const block = rows.filter(r=>r.decision==="BLOCK").length;
  const warn  = rows.filter(r=>r.decision==="WARN").length;
  const allow = rows.filter(r=>r.decision==="ALLOW").length;

  $("kScans").textContent=scanCount;
  $("kBlock").textContent=block;
  $("kWarn").textContent=warn;
  $("kAllow").textContent=allow;

  const verdict =
    block>0?"DANGER":
    warn>0?"WARN":
    rows.length>0?"SECURE":"READY";

  $("verdictText").textContent=verdict;

  const box=$("verdictBox");
  box.classList.remove("verdict-secure","verdict-warn","verdict-danger");
  if(verdict==="DANGER") box.classList.add("verdict-danger");
  else if(verdict==="WARN") box.classList.add("verdict-warn");
  else box.classList.add("verdict-secure");

  $("rows").innerHTML = rows.map(r=>`
    <div style="display:grid;grid-template-columns:2fr 1fr 1fr;gap:10px;padding:10px;border-bottom:1px solid #222;">
      <div>${r.input}</div>
      <div><b>${r.decision}</b></div>
      <div>${r.sev}%</div>
    </div>
  `).join("");
}

function clearAll(){
  $("input").value="";
  scanCount=0;
  $("rows").innerHTML="";
  $("kScans").textContent=0;
  $("kBlock").textContent=0;
  $("kWarn").textContent=0;
  $("kAllow").textContent=0;
  $("verdictText").textContent="READY";
}

function boot(){
  $("buildStamp").textContent="Version: "+BUILD;
  $("btnScan").addEventListener("click",runScan);
  $("btnClear").addEventListener("click",clearAll);

  if($("input").value.trim().length>0){
    runScan();
  }
}

document.readyState==="loading"
?document.addEventListener("DOMContentLoaded",boot)
:boot();

})();
