import test from "node:test";
import assert from "node:assert/strict";
import { buildFriendlyReport, renderFriendlyHtml } from "../cloudflare/friendly.mjs";

const url="https://artisys.dev/";
function fixture(extra={}) {
  return {id:"a".repeat(32),url,status:"completed",mode:"passive",started:1794161387,ended:1794161640,findings:[],
    modules:[
      {tool:"zap",status:"ok",excerpt:[
        "WARN-NEW: Strict-Transport-Security Header Not Set [10035] x 5",
        "\thttps://artisys.dev/ (200 OK)",
        "\thttps://artisys.dev/academy (200 OK)",
        "WARN-NEW: Content Security Policy (CSP) Header Not Set [10038] x 5",
        "\thttps://artisys.dev/ (200 OK)",
        "WARN-NEW: Permissions Policy Header Not Set [10063] x 5",
        "WARN-NEW: Modern Web Application [10109] x 4",
        "FAIL-NEW: 0\tWARN-NEW: 14\tPASS: 54",
        "Automation plan failures: NoSuchFileException /zap/wrk/zap/wrk/zap.html"
      ].join("\n")},
      {tool:"subfinder",status:"ok",excerpt:"pdv.artisys.dev\nwww.artisys.dev"},
      {tool:"httpx",status:"ok",excerpt:"status_code: 200"},
      {tool:"katana",status:"ok",excerpt:""},
      {tool:"testssl",status:"ok",excerpt:'Dados de testssl.json:\\n{"scanResult":[{"protocols":[{"id":"SSLv2","severity":"OK","finding":"not offered"},{"id":"TLS1","severity":"LOW","finding":"offered (deprecated)"},{"id":"TLS1_1","severity":"LOW","finding":"offered (deprecated)"},{"id":"TLS1_2","severity":"OK","finding":"offered"},{"id":"TLS1_3","severity":"OK","finding":"offered"}]}]}'}
    ],...extra};
}
test("relatório antigo com zero findings ganha explicações em português sem inventar vulnerabilidade crítica",()=>{
  const data=buildFriendlyReport(fixture());
  assert.equal(data.warningsZap,14);
  assert.equal(data.executedTools,5);
  assert.equal(data.criticalConfirmed,0);
  assert.match(data.headline,/melhoria|revis/i);
  assert.deepEqual(data.items.filter(i=>i.priority==="alta").map(i=>i.id).sort(),
    ["tls_legacy","zap_10035","zap_10038"]);
  assert.equal(data.items.find(i=>i.id==="tls_legacy").evidence.length,2);
  assert.ok(data.items.find(i=>i.id==="zap_10038").recommendation.includes("CSP"));
  assert.ok(data.caveats.some(x=>/relatório estruturado do ZAP|parciais/i.test(x)));
  assert.ok(data.items.find(i=>i.id==="zap_10109").priority!=="alta");
  assert.ok(!data.items.some(x=>/SSLv2/.test(x.title)));
});
test("não confunde avisos ZAP com falhas críticas confirmadas",()=>{
  const data=buildFriendlyReport(fixture());
  assert.equal(data.warningsZap,14);
  assert.equal(data.criticalConfirmed,0);
  assert.ok(data.items.length>=4);
  assert.ok(data.priorityCount===3);
});
test("combina achados estruturados e logs sem multiplicar ocorrências",()=>{
  const old=fixture({findings:[
    {tool:"zap",rule_id:"10035",title:"Strict-Transport-Security Header Not Set",
     url:"https://artisys.dev/",severity:"medium",occurrences:5},
    {tool:"testssl",rule_id:"TLS1",title:"TLS1",description:"offered (deprecated)",severity:"low",url}
  ]});
  const x=buildFriendlyReport(old);
  assert.equal(x.items.filter(i=>i.id==="zap_10035").length,1);
  assert.equal(x.items.filter(i=>i.id==="tls_legacy").length,1);
  assert.equal(x.items.find(i=>i.id==="zap_10035").occurrences,5);
});
test("subdomínios descobertos não viram sites auditados",()=>{
  const a=buildFriendlyReport(fixture());
  assert.deepEqual(a.discoveredSubdomains.sort(),["pdv.artisys.dev","www.artisys.dev"]);
  assert.ok(a.caveats.some(x=>/subdomínios|escopo/i.test(x)));
});
test("nunca afirma site seguro quando o scanner falha ou não retorna achados",()=>{
  const empty=buildFriendlyReport({id:"f".repeat(32),url,status:"failed",
    findings:[],modules:[{tool:"zap",status:"error",excerpt:""}]});
  assert.equal(empty.items.length,0);
  assert.match(empty.headline,/inconclusiv|incomplet/i);
  assert.ok(empty.caveats.length>0);
});
test("HTML exportado escapa payloads maliciosos nos dados",()=>{
  const report=fixture({findings:[{tool:"nuclei",severity:"medium",title:'<img src=x onerror=alert(1)>',description:"Descrição",url}]});
  const html=renderFriendlyHtml(report);
  assert.match(html,/&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(html,/<img src=x/);
  assert.match(html,/Plano de ação/i);
  assert.match(html,/Detalhes técnicos/i);
});
test("resultados desconhecidos permanecem revisão técnica, sem texto imaginado",()=>{
  const report=fixture({modules:[],findings:[{tool:"nuclei",severity:"medium",title:"CVE test",url}]});
  const x=buildFriendlyReport(report);
  assert.equal(x.items.length,1);
  assert.equal(x.items[0].priority,"revisar");
  assert.match(x.items[0].description,/scanner|valida/i);
});
