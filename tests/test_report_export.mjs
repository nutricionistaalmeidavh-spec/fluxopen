import test from "node:test";
import assert from "node:assert/strict";
import {renderFriendlyHtml, friendlyReportFilename} from "../cloudflare/friendly.mjs";

const report={
  id:"6cba6977f1afecfefea30df3e844424b",
  url:"https://artisys.dev/",
  started:1794163810,ended:1794165557,status:"completed_with_errors",
  modules:[{tool:"zap",status:"ok",excerpt:"Verificações concluídas."},
    {tool:"httpx",status:"ok",excerpt:"HTTP 200"},
    {tool:"nuclei",status:"error",excerpt:"Tempo limite atingido."},
    {tool:"sqlmap",status:"skipped",excerpt:"Sem parâmetros para testar."}],
  findings:[
    {tool:"zap",rule_id:"10038",title:"Content Security Policy Header Not Set",
      severity:"medium",occurrences:5,url:"https://artisys.dev/links/diagnostico/?email=teste%40example.com&secret=private",
      urls:["https://artisys.dev/links/diagnostico/?email=teste%40example.com&secret=private"],
      description:"CSP não configurado"},
    {tool:"zap",rule_id:"10035",title:"Strict-Transport-Security Header Not Set",severity:"medium",url:"https://artisys.dev/"},
    {tool:"nuclei",rule_id:"example-unknown",title:"<img src=x onerror=alert(1)>",severity:"medium",url:"https://artisys.dev/"}
  ]
};
test("nome HTML é legível, inclui domínio e data/hora, sem ID opaco",()=>{
  const name=friendlyReportFilename(report,"html");
  assert.match(name,/^FluxOpen_Relatorio_Seguranca_artisys\.dev_08-11-2026_[0-9]{2}-[0-9]{2}\.html$/);
  assert.doesNotMatch(name,/6cba6977|[<>/\\?*":|]/);
  assert.match(friendlyReportFilename(report,"json"),/^FluxOpen_Dados_Tecnicos_artisys\.dev_08-11-2026_/);
});
test("exportação tem capa, visão geral, prioridades, plano, evidências e impressão",()=>{
  const html=renderFriendlyHtml(report);
  for(const label of ["Visão geral","Prioridades","Plano de ação","Detalhes técnicos","artisys.dev","Relatório de Segurança"])assert.ok(html.includes(label),label);
  assert.match(html,/<meta name="viewport"/);
  assert.match(html,/@media\s*\(max-width:\s*680px\)/);
  assert.match(html,/@media print/);
  assert.match(html,/status-banner/);
  assert.match(html,/2 concluídas/);
  assert.match(html,/1 ignorada/);
  assert.match(html,/1 com erro/);
  assert.match(html,/<details[^>]+class="evidence"/);
  assert.match(html,/<details[^>]+class="tech-report"/);
});
test("não expõe consultas com possíveis dados pessoais no resumo nem injeta HTML",()=>{
  const html=renderFriendlyHtml(report);
  const visible=html.split('id="technical"')[0];
  assert.doesNotMatch(visible,/teste%40example|secret=private/);
  assert.match(visible,/parâmetros ocultos/);
  assert.match(html,/&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(html,/<img src=x onerror/);
});
test("arquivo é independente, sem JS, fontes externas ou CDN",()=>{
  const html=renderFriendlyHtml(report);
  assert.doesNotMatch(html,/<script|<link/i);
  assert.match(html,/<style>/);
  assert.match(html,/<html lang="pt-BR">/);
});
test("domínio inválido não cria caminho ou nome perigoso",()=>{
  const data={...report,url:"https://exemplo.tld:8443/x",ended:null};
  assert.match(friendlyReportFilename(data,"html"),/^FluxOpen_Relatorio_Seguranca_exemplo\.tld_08-11-2026_/);
});

test("HTML oculta credenciais em evidencias e logs, mantendo alerta tecnico",()=>{
  const leak={...report,modules:[{tool:"zap",status:"warning",
    excerpt:"GET https://artisys.dev/admin?token=ABCD123&email=pessoa%40example.com\nAuthorization: Bearer xyz789\nCookie: session=private111\nerror 403"}],
    findings:[{tool:"zap",rule_id:"10038",title:"Missing CSP",severity:"medium",
      url:"https://artisys.dev/page?api_key=valuable123",description:"token=private222",
      urls:["https://artisys.dev/page?code=secret123"]}]};
  const html=renderFriendlyHtml(leak);
  for(const secret of ["ABCD123","pessoa%40example.com","xyz789","private111","private222","valuable123","secret123"])assert.ok(!html.includes(secret),secret);
  assert.match(html,/OCULTO|ocultos/i);
  assert.match(html,/error 403/);
});
