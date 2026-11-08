/**
 * FluxOpen standalone security report layout.
 * No browser scripts, remote fonts, external stylesheets or paid dependencies.
 * The original signed report is not modified. Technical evidence stays collapsed.
 */
const htmlEscape=value=>String(value??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const safeInt=value=>Number.isFinite(Number(value))?Math.max(0,Math.floor(Number(value))):0;
function hostFor(report){
  try{return new URL(report.url).hostname.toLowerCase()}catch{return "alvo-desconhecido"}
}
function timeParts(report) {
  const ts=Number(report.ended||report.started);
  const date=ts>0&&Number.isFinite(ts)?new Date(ts*1000):new Date(0);
  const parts=new Intl.DateTimeFormat("pt-BR",{timeZone:"America/Sao_Paulo",day:"2-digit",month:"2-digit",year:"numeric",hour:"2-digit",minute:"2-digit",hour12:false}).formatToParts(date);
  return Object.fromEntries(parts.map(p=>[p.type,p.value]));
}
export function friendlyReportFilename(report,format="html") {
  if(!["html","json"].includes(format))throw new Error("Formato inválido");
  const host=hostFor(report).replace(/[^a-z0-9.-]/g,"").slice(0,75).replace(/^\.+|\.+$/g,"")||"alvo";
  const p=timeParts(report);
  const prefix=format==="html"?"FluxOpen_Relatorio_Seguranca":"FluxOpen_Dados_Tecnicos";
  return prefix+"_"+host+"_"+p.day+"-"+p.month+"-"+p.year+"_"+p.hour+"-"+p.minute+"."+format;
}
function displayURL(raw){
  try {
    const u=new URL(String(raw));
    if(!["https:","http:"].includes(u.protocol))return htmlEscape(String(raw).slice(0,120));
    const path=u.origin+u.pathname;
    const shown=path.length>115?path.slice(0,112)+"…":path;
    return htmlEscape(shown)+(u.search?" <span class=\"redacted\">(parâmetros ocultos)</span>":"");
  }catch{return htmlEscape(String(raw).slice(0,100))}
}
function labels(key){
  return ({alta:"Alta prioridade",media:"Média prioridade",baixa:"Baixa prioridade",revisar:"Revisar",informativo:"Informativo"})[key]||"Revisar";
}
const GROUPS=[
  {priority:"alta",title:"Ações prioritárias",note:"Itens que merecem atenção primeiro, sujeitos a confirmação técnica."},
  {priority:"media",title:"Melhorias recomendadas",note:"Medidas úteis para aumentar a proteção do site."},
  {priority:"revisar",title:"Pontos que exigem confirmação",note:"Alertas automáticos ainda não demonstram uma falha explorável."},
  {priority:"baixa",title:"Ajustes complementares",note:"Configurações opcionais ou de menor prioridade."},
  {priority:"informativo",title:"Informações da análise",note:"Registros que não representam, isoladamente, vulnerabilidades."}
];
function renderedCard(item,i,compact=false){
  const urls=(item.urls||[]).slice(0,8);
  const urlContent=urls.length?'<div class="scope"><strong>Onde foi observado</strong><ul>'+urls.map(u=>'<li>'+displayURL(u)+'</li>').join("")+'</ul></div>':"";
  const evidence=(item.evidence||[]).map(htmlEscape).join("\n");
  const detail='<details class="evidence"><summary>Ver evidências do scanner</summary><div class="evidence-body"><div><b>Origem:</b> '+htmlEscape(item.tool)+' · '+htmlEscape(item.source||"scanner")+' · '+safeInt(item.occurrences)+' ocorrência(s) relatada(s)</div>'+urlContent+'<pre>'+evidence+'</pre></div></details>';
  const content='<p><b>O que foi identificado?</b> '+htmlEscape(item.description)+'</p>'+
    '<p><b>Por que isso importa?</b> '+htmlEscape(item.impact)+'</p>'+
    '<div class="fix"><span>COMO CORRIGIR</span><p>'+htmlEscape(item.recommendation)+'</p></div>'+detail;
  if(compact)return '<details class="issue issue-compact priority-'+htmlEscape(item.priority)+'"><summary><span class="issue-index">'+String(i+1).padStart(2,"0")+'</span><span class="issue-title">'+htmlEscape(item.title)+'</span><span class="tag">'+labels(item.priority)+'</span></summary><div class="issue-inner">'+content+'</div></details>';
  return '<article class="issue priority-'+htmlEscape(item.priority)+'"><header class="issue-head"><span class="issue-index">'+String(i+1).padStart(2,"0")+'</span><h3>'+htmlEscape(item.title)+'</h3><span class="tag">'+labels(item.priority)+'</span></header><div class="issue-inner">'+content+'</div></article>';
}
function renderFindings(groups,friendly) {
  let index=0;
  return groups.map(g=>{
    const matches=(friendly.items||[]).filter(x=>x.priority===g.priority);
    if(!matches.length)return "";
    const compact=["revisar","informativo","baixa"].includes(g.priority);
    const cards=matches.map(x=>renderedCard(x,index++,compact)).join("");
    return '<section class="finding-group" id="findings-'+g.priority+'"><div class="section-heading"><div><div class="section-kicker">ACHADOS · '+matches.length+' REGISTRO(S)</div><h3>'+g.title+'</h3><p>'+g.note+'</p></div><span class="group-count">'+matches.length+'</span></div>'+cards+'</section>';
  }).join("");
}
function printStyles(){
  return [
    "*,*::before,*::after{box-sizing:border-box}",
    ":root{color-scheme:light;--ink:#142336;--muted:#64758b;--blue:#137f82;--navy:#0c1828;--line:#e1e8ef;--bg:#f4f7fb;--card:#fff;--amber:#a86e1b}",
    "html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.58 -apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif}",
    ".document{width:min(1040px,100%);margin:0 auto;background:#fff;min-height:100vh;box-shadow:0 18px 70px #18314a12}",
    ".hero{background:linear-gradient(132deg,#091625 0%,#15364b 78%,#1b726d 150%);color:#fff;padding:35px 52px 40px}",
    ".brand{display:flex;justify-content:space-between;align-items:center;gap:16px;border-bottom:1px solid #ffffff25;padding-bottom:23px}",
    ".brand-left{display:flex;align-items:center;gap:12px;font-size:20px;font-weight:750;letter-spacing:-.04em}.mark{display:inline-grid;place-items:center;width:38px;height:38px;border-radius:11px;background:#20645f;border:1px solid #5fb6a8;color:#d7fff6;font-size:22px}",
    ".brand-right{font-size:11px;letter-spacing:.12em;color:#a7becb;text-align:right;font-weight:750}",
    ".hero-inner{padding-top:40px}.eyebrow{color:#70dcc8;letter-spacing:.18em;font-size:11px;font-weight:800}.hero h1{font-size:clamp(32px,4vw,48px);line-height:1.12;letter-spacing:-.04em;margin:11px 0 10px}.domain{font-size:clamp(18px,3vw,24px);color:#b9e9e4;font-weight:620;overflow-wrap:anywhere}",
    ".hero-meta{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:28px}.hero-meta span{border:1px solid #ffffff38;background:#ffffff12;border-radius:99px;padding:7px 12px;color:#edf7f8;font-size:12px}",
    ".hero-summary{max-width:720px;color:#c8d9e1;margin:22px 0 0;font-size:14px}",
    ".content{padding:34px 52px 50px}a{color:#0f777b;text-underline-offset:3px}",
    ".toc{display:flex;gap:10px;flex-wrap:wrap;padding-bottom:30px;border-bottom:1px solid var(--line)}.toc a{font-size:12px;text-decoration:none;border:1px solid var(--line);border-radius:99px;padding:8px 13px;color:#465b70;background:#f9fbfd;font-weight:650}",
    ".block{padding-top:33px}.kicker{color:#28867d;font-size:11px;font-weight:850;letter-spacing:.17em;text-transform:uppercase}.block h2{font-size:clamp(24px,3.3vw,31px);letter-spacing:-.035em;line-height:1.2;margin:8px 0 14px}",
    ".callout{padding:20px 22px;border-radius:14px;background:#eff8f6;border:1px solid #c6e8e0}.callout.incomplete{background:#fff8eb;border-color:#f3dfbb}.callout h3{font-size:18px;margin:0 0 6px}.callout p{margin:0;color:#44566b}",
    ".metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:20px}",
    ".metric{border:1px solid var(--line);border-radius:13px;padding:16px;background:#fff}.metric strong{display:block;font-size:27px;line-height:1.2;letter-spacing:-.04em}.metric small{display:block;color:var(--muted);font-size:12px;margin-top:6px}.metric .tiny{font-size:10px;color:#8592a5}",
    ".run-summary{display:flex;gap:8px;flex-wrap:wrap;margin-top:15px}.run-summary span{border-radius:99px;background:#eef4f7;color:#3f566d;padding:6px 11px;font-size:12px;font-weight:650}",
    ".section-heading{display:flex;align-items:start;justify-content:space-between;gap:14px;margin:30px 0 14px}.section-heading h3{margin:4px 0 2px;font-size:22px;letter-spacing:-.025em}.section-heading p{color:var(--muted);font-size:13px;margin:0}",
    ".section-kicker{color:#57837f;font-size:10px;letter-spacing:.16em;font-weight:800}.group-count{background:#edf3f6;border-radius:9px;min-width:33px;text-align:center;padding:6px;color:#42647c;font-weight:800}",
    ".issue{border:1px solid var(--line);border-radius:13px;background:var(--card);margin:12px 0;box-shadow:0 5px 18px #19253606;overflow:hidden}",
    ".issue-head{display:flex;gap:13px;align-items:center;padding:18px 20px 4px}.issue-head h3{font-size:16px;line-height:1.4;flex:1;margin:0;letter-spacing:-.01em}.issue-index{font-size:11px;color:#8192a4;font-weight:800;white-space:nowrap}.tag{font-size:11px;font-weight:750;border-radius:99px;padding:5px 10px;background:#fff0de;color:#955a11;white-space:nowrap}",
    ".priority-media .tag{background:#e8f3ff;color:#236596}.priority-baixa .tag,.priority-informativo .tag{background:#ecf6f4;color:#307e73}.priority-revisar .tag{background:#f0f2f7;color:#536275}",
    ".issue-inner{padding:8px 20px 18px}.issue-inner p{font-size:13px;color:#47576b;margin:11px 0}.issue-inner b{color:#1d3448}",
    ".fix{border-left:3px solid #29a396;background:#f1f8f7;border-radius:0 9px 9px 0;padding:10px 14px;margin:14px 0}.fix span{font-size:10px;letter-spacing:.12em;font-weight:850;color:#267d74}.fix p{margin:4px 0;color:#233d42}",
    ".evidence{border-top:1px solid var(--line);margin-top:16px;padding-top:12px}.evidence summary{font-size:12px;color:#51657d;cursor:pointer;font-weight:650}.evidence-body{padding:12px 0;color:#586d81;font-size:12px}.scope ul{padding-left:17px;margin:5px 0}.scope li{margin:4px 0;overflow-wrap:anywhere}.redacted{color:#8a6475;font-size:11px}",
    ".issue-compact>summary{display:flex;align-items:center;gap:12px;cursor:pointer;list-style:none;padding:14px 16px}.issue-compact>summary::-webkit-details-marker{display:none}.issue-title{font-size:13px;font-weight:690;flex:1;min-width:0}.issue-compact>summary:after{content:'+';font-size:20px;color:#8193a7}.issue-compact[open]>summary:after{content:'−'}",
    ".action-plan{counter-reset:task;list-style:none;padding:0;margin:17px 0}.action-plan li{counter-increment:task;display:grid;grid-template-columns:32px minmax(0,1fr);gap:13px;padding:15px 0;border-bottom:1px solid var(--line)}.action-plan li:before{content:counter(task,decimal-leading-zero);font-size:13px;color:#138a83;font-weight:850}.action-plan strong{font-size:14px}.action-plan p{font-size:12px;color:var(--muted);margin:5px 0}",
    ".disclaimer{border:1px solid #e8dfca;border-radius:12px;background:#fffaf0;padding:14px 20px}.disclaimer ul{margin:0;padding-left:17px}.disclaimer li{font-size:13px;margin:7px 0;color:#5a6371}",
    ".tech-report{border:1px solid var(--line);border-radius:10px;margin:9px 0;overflow:hidden}.tech-report>summary{display:flex;align-items:center;gap:10px;cursor:pointer;padding:13px 16px;background:#f7f9fb;font-size:13px;font-weight:750}.tech-report>summary span{margin-left:auto;color:#6b7f93;font-size:12px}.tech-report pre,.evidence pre{font:11px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;max-height:400px;overflow:auto;padding:12px;border-radius:8px;background:#eff3f7;color:#38516b}",
    ".tech-note{font-size:12px;color:#77899b}.footer{border-top:1px solid var(--line);margin-top:40px;padding-top:17px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:#8594a4;font-size:11px}",
    "@media (max-width: 680px){.hero{padding:21px 21px 28px}.brand-right{font-size:9px}.hero-inner{padding-top:29px}.content{padding:19px 17px 30px}.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.metric{padding:13px}.metric strong{font-size:24px}.toc{gap:7px}.toc a{font-size:11px;padding:7px 10px}.issue-head{flex-wrap:wrap;align-items:start;padding:16px 15px 4px}.issue-head h3{flex:1 1 calc(100% - 50px)}.issue-head .tag{margin-left:23px}.issue-inner{padding:7px 15px 16px}.issue-compact>summary{flex-wrap:wrap}.issue-title{flex:1 1 calc(100% - 50px)}.issue-compact .tag{margin-left:23px}.section-heading h3{font-size:19px}.footer{display:block}}",
    "@page{size:A4;margin:13mm 12mm}",
    "@media print{html{scroll-behavior:auto}body{background:white;color:#111;font-size:11px}.document{width:100%;box-shadow:none}.hero{background:#152b3c!important;color:white!important;print-color-adjust:exact;-webkit-print-color-adjust:exact;padding:18px 22px 24px}.hero-inner{padding-top:15px}.hero h1{font-size:28px}.hero-meta{margin-top:15px}.content{padding:15px 5px}.toc,.evidence,.technical,.tech-note{display:none!important}.block{padding-top:17px}.block h2{font-size:20px}.metric-grid{grid-template-columns:repeat(4,minmax(0,1fr));gap:7px}.metric{padding:9px}.metric strong{font-size:20px}.issue,.finding-group,.action-plan li{break-inside:avoid;page-break-inside:avoid}.issue{margin:7px 0}.issue-head{padding:9px 12px 0}.issue-inner{padding:4px 12px 9px}.issue-inner p{margin:4px 0}.fix{margin:7px 0;padding:6px 8px}.issue-compact{display:none}.section-heading{margin:18px 0 9px}.section-heading h3{font-size:16px}.footer{margin-top:17px}}"
  ].join("\n");
}
export function renderProfessionalReport(report,friendly){
  const when=timeParts(report);
  const dateLabel=when.day+"/"+when.month+"/"+when.year+" às "+when.hour+":"+when.minute;
  const host=hostFor(report);
  const modules=Array.isArray(report.modules)?report.modules:[];
  const completed=modules.filter(m=>m.status==="ok"||m.status==="warning").length;
  const skipped=modules.filter(m=>m.status==="skipped").length;
  const error=modules.filter(m=>m.status==="error").length;
  const considered=modules.length;
  const incomplete=error>0||friendly.incomplete;
  const counts={alta:0,media:0,baixa:0,revisar:0,informativo:0};
  (friendly.items||[]).forEach(x=>{if(Object.hasOwn(counts,x.priority))counts[x.priority]++});
  const actions=(friendly.items||[]).filter(x=>["alta","media"].includes(x.priority)).slice(0,7);
  const nav='<nav class="toc" aria-label="Navegação do relatório"><a href="#overview">Visão geral</a><a href="#priorities">Prioridades</a><a href="#findings">Achados</a><a href="#action-plan">Plano de ação</a><a href="#technical">Detalhes técnicos</a></nav>';
  const metrics=[
    {n:counts.alta,label:"Pontos prioritários"},
    {n:(friendly.items||[]).length,label:"Pontos identificados"},
    {n:completed+"/"+considered,label:"Ferramentas concluídas"},
    {n:error,label:"Ferramentas com erro"}
  ].map(x=>'<div class="metric"><strong>'+x.n+'</strong><small>'+x.label+'</small></div>').join("");
  const flags='<div class="run-summary"><span aria-label="'+completed+' concluídas">'+completed+' concluídas</span><span aria-label="'+skipped+' ignorada(s)">'+skipped+' ignorada(s)</span><span aria-label="'+error+' com erro">'+error+' com erro</span></div>';
  const actionsHtml=actions.map(x=>'<li><div><strong>'+htmlEscape(x.title)+'</strong><p>'+htmlEscape(x.recommendation)+'</p></div></li>').join("");
  const tech=modules.map(m=>'<details class="tech-report"><summary>'+htmlEscape(m.tool)+'<span>'+htmlEscape(m.status||"não informado")+'</span></summary><pre>'+htmlEscape(m.excerpt||"Sem saída textual disponível.")+'</pre></details>').join("");
  const disclaimer=(friendly.caveats||[]).map(x=>'<li>'+htmlEscape(x)+'</li>').join("");
  const groups=renderFindings(GROUPS,friendly);
  const statusTitle=error?"Análise parcialmente concluída":incomplete?"Análise com ressalvas":"Análise concluída";
  const banner=error?"Uma ou mais ferramentas não terminaram. Os achados das ferramentas concluídas continuam disponíveis; o resultado não substitui avaliação manual.":friendly.assessment;
  return '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>Relatório de Segurança | '+htmlEscape(host)+' | FluxOpen</title><style>'+printStyles()+'</style></head><body><div class="document">'+
    '<header class="hero"><div class="brand"><div class="brand-left"><span class="mark" aria-hidden="true">F</span>FluxOpen</div><div class="brand-right">AUDITORIA DE SEGURANÇA<br>RELATÓRIO EXECUTIVO</div></div>'+
    '<div class="hero-inner"><div class="eyebrow">RELATÓRIO DE SEGURANÇA</div><h1>Relatório de Segurança</h1><div class="domain">'+htmlEscape(host)+'</div><div class="hero-meta"><span>'+dateLabel+'</span><span>'+(report.mode==="active"?"Modo ativo":"Modo conservador")+'</span><span>'+statusTitle+'</span></div><p class="hero-summary">Análise automatizada com resultados explicados em português e evidências técnicas disponíveis para consulta.</p></div></header>'+
    '<main class="content">'+nav+
    '<section class="block" id="overview"><div class="kicker">01 / PANORAMA</div><h2>Visão geral</h2><div class="callout '+(incomplete?"incomplete":"")+'"><h3>'+statusTitle+'</h3><p>'+htmlEscape(banner)+'</p></div><div class="metric-grid">'+metrics+'</div>'+flags+'</section>'+
    '<section class="block" id="priorities"><div class="kicker">02 / ATENÇÃO PRIMEIRO</div><h2>Prioridades</h2><p class="tech-note">A classificação indica ordem sugerida de revisão, não comprova exploração ou comprometimento.</p><div class="metric-grid"><div class="metric"><strong>'+counts.alta+'</strong><small>Alta prioridade</small></div><div class="metric"><strong>'+counts.media+'</strong><small>Média prioridade</small></div><div class="metric"><strong>'+counts.revisar+'</strong><small>A confirmar</small></div><div class="metric"><strong>'+counts.baixa+'</strong><small>Baixa prioridade</small></div></div></section>'+
    '<section class="block" id="findings"><div class="kicker">03 / EXPLICAÇÕES</div><h2>Achados explicados</h2><p class="tech-note">Cada item explica o significado, o possível impacto e uma ação recomendada. Pontos não confirmados aparecem recolhidos.</p>'+ (groups||'<p>Nenhum achado interpretável foi identificado nos dados disponíveis. Isso não comprova ausência de falhas.</p>')+'</section>'+
    '<section class="block" id="action-plan"><div class="kicker">04 / PRÓXIMAS AÇÕES</div><h2>Plano de ação</h2>'+ (actionsHtml?'<ol class="action-plan">'+actionsHtml+'</ol>':'<p>Sem correções automáticas recomendadas. Revise as evidências antes de tomar decisões.</p>')+
    '<div class="disclaimer"><strong>Sobre este resultado</strong><ul>'+disclaimer+'</ul></div></section>'+
    '<section class="block technical" id="technical"><div class="kicker">05 / REGISTROS ORIGINAIS</div><h2>Detalhes técnicos</h2><p class="tech-note">Os registros completos ficam ocultos por padrão. Eles podem incluir parâmetros de URL e dados de teste; compartilhe o arquivo apenas com pessoas autorizadas.</p>'+tech+'</section>'+
    '<footer class="footer"><span>FluxOpen · Relatório gerado automaticamente, sem serviços pagos</span><span>Alvo: '+htmlEscape(host)+' · '+dateLabel+'</span></footer>'+
    '</main></div></body></html>';
}
