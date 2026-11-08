import {renderProfessionalReport, friendlyReportFilename} from "./report-layout.mjs";
export {friendlyReportFilename};
/**
 * FluxOpen report interpreter — no LLM, network, paid service or personal data.
 * Pure deterministic mapping of scanner evidence to Portuguese explanations.
 * Old D1 reports are interpreted at READ time, without modifying their signed originals.
 * Do not equate passive scanner warnings with confirmed exploitable vulnerabilities.
 */
const KNOWLEDGE={
  zap_10035:{title:"Proteção HTTPS pode ser reforçada (HSTS)",priority:"alta",
    description:"O navegador não recebe uma instrução para continuar utilizando conexões HTTPS nas próximas visitas.",
    impact:"Sem essa proteção adicional, uma tentativa de acesso por HTTP pode ficar menos protegida em algumas situações.",
    recommendation:"Configurar o cabeçalho Strict-Transport-Security (HSTS) gradualmente, confirmando HTTPS nos subdomínios antes de habilitar includeSubDomains."},
  zap_10038:{title:"Política de proteção contra scripts não configurada (CSP)",priority:"alta",
    description:"O site não envia regras explícitas que limitam as origens dos scripts e de outros conteúdos carregados pelo navegador.",
    impact:"Uma CSP adequada ajuda a reduzir o impacto de algumas falhas de injeção de conteúdo, mas não substitui a correção da causa.",
    recommendation:"Definir uma Content-Security-Policy (CSP), começar em modo Report-Only, testar recursos legítimos e então aplicar a política com bloqueio."},
  tls_legacy:{title:"Versões antigas de criptografia TLS oferecidas",priority:"alta",
    description:"A ferramenta observou que a conexão aceita pelo menos uma versão antiga de TLS (1.0 ou 1.1).",
    impact:"Conexões negociadas com versões antigas têm proteção inferior à recomendada atualmente.",
    recommendation:"Confirmar o resultado com outra ferramenta e configurar o TLS mínimo como 1.2 no provedor responsável pelo HTTPS, sem prejudicar clientes compatíveis."},
  zap_10063:{title:"Permissões do navegador sem restrição explícita",priority:"media",
    description:"O site não declara quais recursos do navegador podem ser utilizados, como câmera e localização.",
    impact:"Definir permissões restritas ajuda a reduzir a superfície de abuso em componentes incorporados.",
    recommendation:"Adicionar Permissions-Policy apenas com os recursos necessários e verificar possíveis integrações."},
  zap_90003:{title:"Integridade de alguns recursos externos não declarada",priority:"media",
    description:"O scanner encontrou referências a arquivos externos sem um atributo de integridade verificável.",
    impact:"Quando um arquivo externo é alterado, a ausência de verificação de integridade pode ampliar o impacto. Nem todos os recursos permitem SRI.",
    recommendation:"Examinar scripts e estilos externos; usar Subresource Integrity (SRI) quando aplicável ou hospedar recursos sob controle próprio."},
  zap_10202:{title:"Possível ausência de proteção contra solicitações indevidas (CSRF)",priority:"revisar",
    description:"O scanner não identificou uma proteção anti-CSRF na página sinalizada.",
    impact:"Só representa um problema se houver uma ação autenticada que modifica dados e não possua proteção equivalente.",
    recommendation:"Verificar se essa página contém formulários ou ações autenticadas que alteram dados; caso existam, validar proteção CSRF adequada."},
  zap_90004:{title:"Política de isolamento de recursos não definida",priority:"baixa",
    description:"O navegador não recebeu uma política Cross-Origin-Embedder-Policy (COEP).",
    impact:"A ausência da política pode ser aceitável; ela não é obrigatória para todos os sites.",
    recommendation:"Avaliar se o aplicativo precisa de isolamento de origem e testar integrações antes de habilitar COEP."},
  zap_10049:{title:"Comportamento de cache requer verificação",priority:"revisar",
    description:"O scanner observou páginas ou respostas não armazenáveis em cache.",
    impact:"O comportamento pode ser intencional, principalmente em respostas dinâmicas ou sensíveis.",
    recommendation:"Conferir as regras de cache; não é necessário alterar respostas que devem permanecer privadas ou sem cache."},
  zap_10109:{title:"Aplicação web moderna identificada",priority:"informativo",
    description:"O scanner reconheceu características de uma aplicação web moderna.",
    impact:"Trata-se de uma informação técnica, não de uma vulnerabilidade.",
    recommendation:"Nenhuma correção exigida por essa observação isolada."}
};
const ORDER={alta:0,media:1,baixa:2,revisar:3,informativo:4};
const canonicalSeverity=s=>String(s||"").toLowerCase();
const escapeHTML=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const truncate=(v,n)=>String(v??"").slice(0,n);
function allowedURL(value,originHost){
  try{const u=new URL(value);return (u.protocol==="https:"||u.protocol==="http:")&&u.hostname===originHost?u.href:null;}catch{return null}
}
function kbFor(id,raw){
  const known=KNOWLEDGE[id];
  return known||{
    title:"Alerta técnico para validação ("+truncate(raw?.title||id,85)+")",
    priority:"revisar",
    description:"Uma ferramenta sinalizou um resultado que exige validação técnica. Não foi possível verificar automaticamente seu impacto.",
    impact:"A existência do alerta não comprova que a vulnerabilidade seja explorável.",
    recommendation:"Verificar o resultado original e confirmar manualmente antes de atribuir uma prioridade de risco."
  };
}
export function buildFriendlyReport(report){
  const modules=Array.isArray(report?.modules)?report.modules:[];
  const findings=Array.isArray(report?.findings)?report.findings:[];
  let host="";
  try{host=new URL(report.url).hostname}catch{host="";} 
  const items=new Map();
  const register=(id,tool,raw={},options={})=>{
    const info=kbFor(id,raw);
    let item=items.get(id);
    if(!item){
      item={id,tool,title:info.title,priority:info.priority,description:info.description,
        impact:info.impact,recommendation:info.recommendation,occurrences:0,
        urls:[],evidence:[],source:"log",scannerTitle:truncate(raw.title||"",140)};
      items.set(id,item);
    }
    const count=Number.isFinite(Number(options.count))?Math.max(1,Math.min(999,Number(options.count))):1;
    item.occurrences=Math.max(item.occurrences,count);
    if(options.source==="estruturado")item.source="estruturado";
    const pages=options.urls||[];
    for(const value of pages){
      const valid=allowedURL(value,host);
      if(valid&&!item.urls.includes(valid)&&item.urls.length<12)item.urls.push(valid);
    }
    const note=truncate(options.evidence||"",220).trim();
    if(note&&!item.evidence.includes(note)&&item.evidence.length<8)item.evidence.push(note);
    return item;
  };
  // Structured records from future scanner revisions take precedence over textual logs.
  for(const f of findings.slice(0,200)){
    if(!f||typeof f!=="object")continue;
    const tool=String(f.tool||"").toLowerCase();
    const rawId=String(f.rule_id||f.pluginid||"");
    const title=String(f.title||"");
    const desc=String(f.description||"");
    if(tool==="zap"){
      const match=rawId.match(/\d{5}/)||title.match(/\[(\d{5})\]/);
      const key=match?"zap_"+(match[1]||match[0]):"zap_unknown_"+title.slice(0,80);
      register(key,tool,f,{source:"estruturado",count:f.occurrences||1,urls:[f.url,...(Array.isArray(f.urls)?f.urls:[])],evidence:title});
    }else if(tool==="testssl"){
      const norm=rawId.toUpperCase().replace(/[^A-Z0-9_]/g,"");
      if(["TLS1","TLS1_1"].includes(norm)){
        if(/not offered|disabled|not supported/i.test(desc))continue;
        if(!/offered|supported|enabled/i.test(desc))continue;
        register("tls_legacy",tool,f,{source:"estruturado",urls:[f.url],evidence:norm.replace("TLS1_1","TLS 1.1").replace("TLS1","TLS 1.0")+": "+desc});
      }else if(["high","critical","medium"].includes(canonicalSeverity(f.severity))&&desc){
        register("testssl_"+(norm||title.slice(0,50)),tool,f,{source:"estruturado",urls:[f.url],evidence:title+": "+desc});
      }
    }else if(tool){
      register(tool+"_"+(rawId||title).slice(0,100),tool,f,{source:"estruturado",count:f.occurrences||1,urls:[f.url],evidence:title});
    }
  }
  let warningsZap=null,hasZapPartial=false;
  const knownSubdomains=new Set();
  const auditedHost=host||"";
  for(const m of modules){
    const tool=String(m.tool||"");
    const excerpt=String(m.excerpt||"").replace(/\\n/g,"\n");
    if(tool==="zap"){
      const matches=[...excerpt.matchAll(/^\s*WARN-NEW:\s*(.+?)\s+\[(\d{5})\]\s+x\s+(\d+)\s*$/gm)];
      const total=excerpt.match(/(?:^|\s)WARN-NEW:\s*(\d+)(?=\s|$)/m);
      if(total)warningsZap=Number(total[1]);
      if(Number.isInteger(m.zap_warnings))warningsZap=m.zap_warnings;
      if(/Automation plan failures|NoSuchFileException|failed to generate report/i.test(excerpt))hasZapPartial=true;
      for(let n=0;n<matches.length;n++){
        const one=matches[n],following=excerpt.slice(one.index+one[0].length,
          n+1<matches.length?matches[n+1].index:excerpt.length);
        const pages=[...following.matchAll(/https?:\/\/[^\s()<>]+/g)].slice(0,12).map(x=>x[0]);
        register("zap_"+one[2],"zap",{title:one[1]},{count:Number(one[3]),urls:pages,evidence:"ZAP: "+one[1]});
      }
      if(warningsZap===null&&matches.length)warningsZap=matches.length;
    }
    if(tool==="testssl"){
      const regex=/"id"\s*:\s*"(TLS1(?:_1)?)"\s*,\s*"severity"\s*:\s*"([^"]+)"\s*,\s*"finding"\s*:\s*"([^"]+)"/gi;
      for(const x of excerpt.matchAll(regex)){
        if(/not offered|disabled|not supported/i.test(x[3])||!/offered|supported|enabled/i.test(x[3]))continue;
        const version=x[1].toUpperCase()==="TLS1_1"?"TLS 1.1":"TLS 1.0";
        register("tls_legacy","testssl",{title:"TLS antigo"},{urls:[report.url],evidence:version+": "+x[3]});
      }
    }
    if(tool==="subfinder"){
      for(const line of excerpt.split(/\r?\n/)){
        const candidate=line.trim().toLowerCase();
        if(candidate!==auditedHost&&candidate.endsWith("."+auditedHost)&&/^[a-z0-9.-]{1,253}$/.test(candidate)&&knownSubdomains.size<20)knownSubdomains.add(candidate);
      }
    }
  }
  const list=[...items.values()].sort((a,b)=>(ORDER[a.priority]??9)-(ORDER[b.priority]??9)||a.title.localeCompare(b.title,"pt-BR")).slice(0,100);
  const failed=report.status==="failed"||modules.some(m=>m.status==="error");
  const incomplete=hasZapPartial||failed||modules.length===0;
  const caveats=[
    "Auditoria automatizada conservadora: não testa integralmente autenticação, permissões internas, pagamentos ou invasões reais.",
    "Alertas de scanners são indícios que precisam ser confirmados; não equivalem a falhas exploráveis comprovadas."
  ];
  if(hasZapPartial)caveats.push("As evidências do ZAP são parciais: houve erro na geração do relatório estruturado. Os avisos em texto foram recuperados.");
  if(knownSubdomains.size)caveats.push("Subdomínios identificados por reconhecimento não foram automaticamente incluídos no escopo da auditoria.");
  if(failed)caveats.push("Uma ou mais ferramentas não concluíram normalmente; o resultado é inconclusivo para essas verificações.");
  const priorityCount=list.filter(x=>x.priority==="alta").length;
  return{
    version:1,
    headline:failed?"Auditoria incompleta: resultados inconclusivos":list.some(x=>x.priority==="alta"||x.priority==="media")?"Melhorias de segurança recomendadas":list.length?"Pontos para revisão técnica":"Nenhum alerta interpretável nesta análise",
    assessment:failed?
      "Não é possível emitir uma avaliação geral: uma etapa falhou.":
      list.length?
      "Foram encontradas configurações a revisar. Nenhum achado listado aqui, isoladamente, comprova invasão, vazamento ou uma vulnerabilidade explorada.":
      "Os scanners não geraram achados interpretáveis no relatório disponível. Isso não garante que o site esteja seguro.",
    executedTools:modules.filter(x=>["ok","warning","skipped"].includes(x.status)).length,
    totalTools:modules.length,
    warningsZap,
    priorityCount,
    criticalConfirmed:0,
    items:list,
    discoveredSubdomains:[...knownSubdomains].sort(),
    caveats,
    incomplete,
    scopeHost:host,
    sourceFindings:findings.length,
    evidenceMode:hasZapPartial?"parcial":"estruturado-ou-log"
  };
}
export function renderFriendlyHtml(report){
  return renderProfessionalReport(report,buildFriendlyReport(report));
}
