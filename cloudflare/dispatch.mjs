/**
 * Recover scans that have an approved D1 record but never reached GitHub Actions.
 * Called by a Cloudflare Cron Trigger; no public dispatch/retry endpoint.
 * One-time claims prevent concurrent cron executions and duplicate scans.
 */
const TOOLS=new Set(["zap","nuclei","subfinder","httpx","katana","ffuf","feroxbuster","sqlmap","testssl","nikto"]);
const CONSERVATIVE=new Set(["zap","subfinder","httpx","katana","testssl"]);
const epoch=()=>Math.floor(Date.now()/1000);

function authorize(row,now) {
  const iso=new Date(now*1000).toISOString().slice(0,10);
  if(row.valid_until<=iso)throw Error("Autorização do alvo expirada");
  if(row.url!==row.target_url)throw Error("Endereço da auditoria diverge do alvo autorizado");
  if(!/^[a-f0-9]{32}$/.test(row.id)||row.status!=="queued")throw Error("Registro inválido");
  let tools;
  try{tools=JSON.parse(row.tools)}catch{throw Error("Ferramentas inválidas")}
  if(!Array.isArray(tools)||tools.length===0||tools.length>10||new Set(tools).size!==tools.length||tools.some(x=>!TOOLS.has(x)))throw Error("Ferramentas inválidas");
  if(row.mode!=="active"&&row.mode!=="passive")throw Error("Perfil inválido");
  if(row.mode==="passive"&&tools.some(x=>!CONSERVATIVE.has(x)))throw Error("Testes ativos não foram autorizados");
  if(!/^https?:\/\/[^/?#]+/.test(row.url))throw Error("URL inválida");
  if(now-row.started>172800)throw Error("Solicitação antiga demais; crie uma nova auditoria");
  return tools;
}
export async function reconcilePending(env,{now=epoch(),github,signManifest}={}) {
  if(typeof github!=="function"||typeof signManifest!=="function")throw Error("Dependências de envio ausentes");
  const summary={dispatched:0,found:0,failed:0,skipped:0};
  const entries=(await env.DB.prepare(
    "SELECT s.id,s.url,s.tools,s.mode,s.status,s.started,t.url AS target_url,t.valid_until "+
    "FROM scans s JOIN targets t ON t.id=s.target_id "+
    "WHERE s.status='queued' AND s.report IS NULL AND s.started<=? "+
    "ORDER BY s.started ASC LIMIT 3"
  ).bind(now-90).all()).results||[];
  for(const row of entries){
    const claim=await env.DB.prepare(
      "INSERT OR IGNORE INTO scan_dispatch(scan_id,claimed_at) VALUES (?,?)"
    ).bind(row.id,now).run();
    if(claim.meta?.changes!==1){summary.skipped++;continue}
    try{
      const tools=authorize(row,now);
      if(!env.GH_TOKEN||!env.SCAN_SIGNING_SECRET||env.SCAN_SIGNING_SECRET.length<32)
        throw Error("Secrets do GitHub não configurados no Worker");
      // A scan may already have been started by a preceding Actions push.
      const list=await github(env,"/actions/workflows/scan.yml/runs?event=workflow_dispatch&per_page=100");
      const previous=(list?.workflow_runs||[]).find(x=>(x.display_title||"").includes(row.id));
      if(previous){
        await env.DB.prepare(
          "UPDATE scans SET status='running',run_id=?,updated=?,last_synced=? WHERE id=? AND status='queued'"
        ).bind(previous.id,now,now,row.id).run();
        summary.found++;continue;
      }
      const {packed,signature}=await signManifest(
        {id:row.id,url:row.url,tools,mode:row.mode,issued:now,expires:now+3600},
        env.SCAN_SIGNING_SECRET
      );
      await github(env,"/actions/workflows/scan.yml/dispatches",{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({ref:"main",inputs:{
          payload:packed,signature,scan_id:row.id,verification_only:false
        }})
      });
      await env.DB.prepare(
        "UPDATE scans SET status='running',updated=?,error=NULL,last_synced=? WHERE id=? AND status='queued'"
      ).bind(now,now,row.id).run();
      summary.dispatched++;
    }catch(e){
      const message=String(e?.message||e).slice(0,220);
      await env.DB.prepare(
        "UPDATE scans SET status='failed',updated=?,error=? WHERE id=? AND status='queued'"
      ).bind(now,"Não foi possível disparar a auditoria: "+message,row.id).run();
      summary.failed++;
    }
  }
  return summary;
}
