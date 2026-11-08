import { PANEL_HTML } from "./panel.mjs";
import { buildFriendlyReport, renderFriendlyHtml, friendlyReportFilename } from "./friendly.mjs";
import { reconcilePending } from "./dispatch.mjs";
import { registrationOptions, registrationFinish, authenticationOptions, authenticationFinish, identity, setIdentity, checkIdentity } from "./webauthn.mjs";
/**
 * FluxOpen Cloudflare Worker.
 * Workers Free + D1 Free; scanner containers remain in GitHub Actions.
 * API compatible with app/static/index.html. No third-party JS dependencies.
 */
const TOOL_ORDER = ["zap","nuclei","subfinder","httpx","katana","ffuf","feroxbuster","sqlmap","testssl","nikto"];
const CONSERVATIVE = new Set(["zap","subfinder","httpx","katana","testssl"]);
const GH_REPO = "nutricionistaalmeidavh-spec/fluxopen";
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const BASE_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
};
class WebError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const epoch = () => Math.floor(Date.now() / 1000);
const hex = bytes => [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,"0")).join("");
const rand = n => { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; };
const b64url = arr => btoa(String.fromCharCode(...arr)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
async function digest(s) { return hex(await crypto.subtle.digest("SHA-256", encoder.encode(s))); }
async function mac(secret, payload) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), {name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return hex(await crypto.subtle.sign("HMAC",key,typeof payload==="string"?encoder.encode(payload):payload));
}
function same(a,b) {
  if (typeof a!=="string" || typeof b!=="string" || a.length!==b.length) return false;
  let diff=0;for(let i=0;i<a.length;i++) diff |= a.charCodeAt(i)^b.charCodeAt(i);return diff===0;
}
function json(value, status=200, headers={}) {
  return new Response(JSON.stringify(value), {status,headers:{"Content-Type":"application/json; charset=utf-8",...BASE_HEADERS,...headers}});
}
function fail(status, reason) { throw new WebError(status,reason); }
function content(html, status=200, headers={}) {
  return new Response(html,{status,headers:{"Content-Type":"text/html; charset=utf-8",...BASE_HEADERS,...headers}});
}
async function readJSON(req, max=15000) {
  if (Number(req.headers.get("content-length")||0)>max) fail(413,"Corpo muito grande");
  const str=await req.text();
  if (str.length>max) fail(413,"Corpo muito grande");
  try{return JSON.parse(str);}catch{fail(400,"JSON inválido");}
}
function today() {return new Date().toISOString().slice(0,10);}

export function normalizeTarget(raw) {
  if(typeof raw!=="string" || raw.length>2048 || raw.length<10 || raw.trim()!==raw || /[\u0000-\u0020\u007f]/.test(raw))fail(422,"URL inválida");
  let u;try{u=new URL(raw);}catch{fail(422,"URL inválida")}
  if(!["http:","https:"].includes(u.protocol)||u.username||u.password||u.hash)fail(422,"Somente HTTP(S), sem credenciais ou fragmentos");
  const host=u.hostname.toLowerCase().replace(/^\[|\]$/g,"");
  if(!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(host)||host.length>253||!host.includes(".")||host.includes("..")||host.endsWith("."))fail(422,"Domínio público inválido");
  if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)||host.includes(":")||/^\d+$/.test(host.split(".").at(-1)))fail(422,"IPs e nomes numéricos são bloqueados");
  if(["localhost","local","internal","test","invalid","example"].some(x=>host===x||host.endsWith("."+x)))fail(422,"Domínio reservado ou interno");
  if(u.port&&!["80","443","8080","8443"].includes(u.port))fail(422,"Porta fora do conjunto permitido");
  // Host resolution and final public-IP validation happen again in the signed runner.
  return u.toString();
}
export function validateTools(tools,mode) {
  if(!Array.isArray(tools)||!tools.length||tools.length>TOOL_ORDER.length||new Set(tools).size!==tools.length)fail(422,"Seleção de ferramentas inválida");
  if(mode!=="passive"&&mode!=="active")fail(422,"Modo inválido");
  if(tools.some(t=>!TOOL_ORDER.includes(t)))fail(422,"Ferramenta desconhecida");
  if(mode==="passive"&&tools.some(t=>!CONSERVATIVE.has(t)))fail(422,"Teste ativo exige confirmação");
  return tools;
}
function cookie(req) {
  const str=req.headers.get("cookie")||"";
  const item=str.split(";").map(x=>x.trim()).find(x=>x.startsWith("fluxopen_session="));
  return item?item.slice("fluxopen_session=".length):"";
}
async function auth(req,env,mutating=false) {
  const token=cookie(req);
  if(!token||token.length>200)fail(401,"Faça login no painel");
  const record=await env.DB.prepare("SELECT csrf,expires FROM sessions WHERE token_hash=?").bind(await digest(token)).first();
  if(!record||record.expires<epoch())fail(401,"Sessão expirada");
  if(mutating) {
    const origin=req.headers.get("origin");
    if(origin && origin!==new URL(req.url).origin)fail(403,"Origem inválida");
    if(!same(req.headers.get("x-csrf-token")||"",record.csrf))fail(403,"Proteção CSRF");
  }
  return record;
}
async function newSession(env) {
  const token=b64url(rand(48)), csrf=b64url(rand(32)), now=epoch();
  await env.DB.prepare("INSERT INTO sessions(token_hash,csrf,expires) VALUES (?,?,?)").bind(await digest(token),csrf,now+43200).run();
  return {csrf, sessionCookie:"fluxopen_session="+token+"; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200"};
}
async function login(req,env) {
  if(!env.ADMIN_PASSWORD||env.ADMIN_PASSWORD.length<12)fail(503,"Painel ainda não configurado: ADMIN_PASSWORD ausente");
  const ip=await digest(req.headers.get("cf-connecting-ip")||"unknown");
  const now=epoch();
  const state=await env.DB.prepare("SELECT attempts,first_attempt FROM login_failures WHERE ip_hash=?").bind(ip).first();
  if(state&&state.attempts>=6&&now-state.first_attempt<900)fail(429,"Muitas tentativas. Aguarde 15 minutos");
  const data=await readJSON(req);
  const input=typeof data.password==="string"?data.password:"";
  const valid=(typeof data.email==="string"&&data.email.trim().length>0)
    ? await checkIdentity(env,data.email,input)
    : same(await digest(input),await digest(env.ADMIN_PASSWORD));
  if(!valid) {
    const attempts=state&&now-state.first_attempt<900?state.attempts+1:1;
    const first=state&&now-state.first_attempt<900?state.first_attempt:now;
    await env.DB.prepare("INSERT INTO login_failures(ip_hash,attempts,first_attempt) VALUES (?,?,?) ON CONFLICT(ip_hash) DO UPDATE SET attempts=excluded.attempts,first_attempt=excluded.first_attempt").bind(ip,attempts,first).run();
    fail(401,"Senha incorreta");
  }
  await env.DB.prepare("DELETE FROM login_failures WHERE ip_hash=?").bind(ip).run();
  const fresh=await newSession(env);
  return json({authenticated:true,csrf:fresh.csrf},200,{"Set-Cookie":fresh.sessionCookie});
}
async function gh(env,endpoint,opts={}) {
  if(!env.GH_TOKEN)fail(503,"Configure GH_TOKEN como secret no Cloudflare para disparar workflows");
  const r=await fetch("https://api.github.com/repos/"+GH_REPO+endpoint,{
    ...opts,headers:{"Authorization":"Bearer "+env.GH_TOKEN,"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"FluxOpen",...(opts.headers||{})}
  });
  if(!r.ok)fail(502,"GitHub Actions retornou HTTP "+r.status);
  if(r.status===204)return null;
  return await r.json();
}
export async function encodeManifest(manifest,secret) {
  if(typeof secret!=="string"||secret.length<32)fail(503,"SCAN_SIGNING_SECRET não configurado");
  // Python verify_manifest() uses json.dumps(sort_keys=True, separators=(',',':')).
  const ordered={expires:manifest.expires,id:manifest.id,issued:manifest.issued,mode:manifest.mode,tools:manifest.tools,url:manifest.url};
  const packed=b64url(encoder.encode(JSON.stringify(ordered)));
  return {packed,signature:await mac(secret,packed)};
}
async function createTarget(req,env) {
  const data=await readJSON(req);
  if(!data||data.confirmed!==true)fail(422,"Confirme a autorização explícita do proprietário");
  if(typeof data.name!=="string"||data.name.trim().length<2||data.name.length>80)fail(422,"Nome inválido");
  if(typeof data.permission!=="string"||data.permission.trim().length<15||data.permission.length>500)fail(422,"Informe a referência da autorização");
  if(typeof data.valid_until!=="string"||! /^\d{4}-\d{2}-\d{2}$/.test(data.valid_until)||!Number.isFinite(Date.parse(data.valid_until))||data.valid_until<=today())fail(422,"Autorização precisa estar vigente");
  const url=normalizeTarget(data.url);
  let result;
  try{result=await env.DB.prepare("INSERT INTO targets(name,url,permission,valid_until,created) VALUES (?,?,?,?,?)").bind(data.name.trim(),url,data.permission.trim(),data.valid_until,epoch()).run();}
  catch(e){if(String(e).includes("UNIQUE"))fail(409,"URL já cadastrada");throw e;}
  return json({id:result.meta.last_row_id,url});
}
async function createScan(req,env) {
  const data=await readJSON(req);
  validateTools(data.tools,data.mode);
  if(data.mode==="active"&&data.confirmed_active!==true)fail(422,"Confirme a autorização específica para os testes ativos");
  if(!Number.isSafeInteger(data.target_id)||data.target_id<1)fail(422,"Alvo inválido");
  const target=await env.DB.prepare("SELECT id,url,valid_until FROM targets WHERE id=?").bind(data.target_id).first();
  if(!target)fail(404,"Alvo não encontrado");
  if(target.valid_until<=today())fail(422,"Autorização do alvo expirada");
  const url=normalizeTarget(target.url);
  if(!env.GH_TOKEN)fail(503,"Configure o secret GH_TOKEN no Worker");
  if(!env.SCAN_SIGNING_SECRET||env.SCAN_SIGNING_SECRET.length<32)fail(503,"Configure o secret SCAN_SIGNING_SECRET no Worker");
  const bytes=rand(16),id=hex(bytes);
  const now=epoch();
  const {packed,signature}=await encodeManifest({id,url,tools:data.tools,mode:data.mode,issued:now,expires:now+7200},env.SCAN_SIGNING_SECRET);
  await env.DB.prepare("INSERT INTO scans(id,target_id,url,tools,mode,status,started,updated,last_synced) VALUES (?,?,?,?,?,?,?,?,0)").bind(id,data.target_id,url,JSON.stringify(data.tools),data.mode,"queued",now,now).run();
  try {
    await gh(env,"/actions/workflows/scan.yml/dispatches",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ref:"main",inputs:{payload:packed,signature,scan_id:id,verification_only:data.verification_only===true?"true":"false"}})});
  } catch(error) {
    await env.DB.prepare("UPDATE scans SET status='failed',error=?,updated=? WHERE id=?").bind("Falha no disparo: "+String(error.message).slice(0,180),epoch(),id).run();
    throw error;
  }
  return json({id,status:"queued",backend:"github"});
}
async function refreshRun(env,row) {
  // The "Sincronizar" button also repairs old D1-only queued entries immediately.
  // scan_dispatch claims make this safe even if a Cron Trigger runs concurrently.
  if(row.status==="queued" && !row.run_id && epoch()-row.started>90){
    await reconcilePending(env,{github:gh,signManifest:encodeManifest});
    return;
  }
  if(!env.GH_TOKEN||!["queued","running"].includes(row.status)||epoch()-row.last_synced<35)return;
  const n=epoch();
  await env.DB.prepare("UPDATE scans SET last_synced=? WHERE id=?").bind(n,row.id).run();
  try{
    let run;
    if(row.run_id)run=await gh(env,"/actions/runs/"+row.run_id);
    else{
      const all=await gh(env,"/actions/workflows/scan.yml/runs?event=workflow_dispatch&per_page=50");
      run=(all.workflow_runs||[]).find(x=>String(x.display_title||"").includes(row.id));
    }
    if(!run)return;
    const running=run.status!=="completed";
    await env.DB.prepare("UPDATE scans SET run_id=?,status=?,updated=? WHERE id=? AND report IS NULL").bind(run.id,running?"running":(epoch()-row.started>180?"failed":"running"),n,row.id).run();
  }catch{ /* Keep last state. The callback will still finalize the scan. */ }
}
function parseReport(row) {if(!row.report)return null;const report=JSON.parse(row.report);report.friendly=buildFriendlyReport(report);return report;}
async function detail(req,env,id) {
  if(!/^[a-f0-9]{32}$/.test(id))fail(404,"Auditoria não encontrada");
  let row=await env.DB.prepare("SELECT * FROM scans WHERE id=?").bind(id).first();
  if(!row)fail(404,"Auditoria não encontrada");
  await refreshRun(env,row);
  row=await env.DB.prepare("SELECT * FROM scans WHERE id=?").bind(id).first();
  const report=parseReport(row);
  return {...row,tools:JSON.parse(row.tools),report,friendly:report?.friendly||null};
}
function escapeHTML(x) {
  return String(x??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
async function downloadReport(env,id,format) {
  if(!/^[a-f0-9]{32}$/.test(id))fail(404,"Relatório não encontrado");
  const row=await env.DB.prepare("SELECT report FROM scans WHERE id=?").bind(id).first();
  if(!row||!row.report)fail(404,"Relatório ainda indisponível");
  const report=JSON.parse(row.report);
  report.friendly=buildFriendlyReport(report);
  if(!["html","json"].includes(format))fail(422,"Formato inválido");
  const headers={"Content-Disposition":'attachment; filename="'+friendlyReportFilename(report,format)+'"'};
  if(format==="json")return json(report,200,headers);
  if(format!=="html")fail(422,"Formato inválido");
  return content(renderFriendlyHtml(report),200,headers);
}
async function callback(req,env) {
  if(!env.SCAN_SIGNING_SECRET||env.SCAN_SIGNING_SECRET.length<32)fail(503,"Assinatura de retorno não configurada");
  if(Number(req.headers.get("content-length")||0)>180000)fail(413,"Relatório muito grande");
  const buffer=await req.arrayBuffer();
  if(buffer.byteLength>180000)fail(413,"Relatório muito grande");
  const supplied=req.headers.get("x-fluxopen-signature")||"";
  if(!same(supplied,await mac(env.SCAN_SIGNING_SECRET,buffer)))fail(403,"Assinatura inválida");
  let report;try{report=JSON.parse(decoder.decode(buffer));}catch{fail(400,"Relatório inválido");}
  if(!report||! /^[a-f0-9]{32}$/.test(report.id||""))fail(422,"Identificador inválido");
  const row=await env.DB.prepare("SELECT url,tools,mode,status FROM scans WHERE id=?").bind(report.id).first();
  if(!row)fail(404,"Auditoria não localizada");
  if(report.url!==row.url||report.mode!==row.mode||!Array.isArray(report.modules)||report.modules.length>10||!Array.isArray(report.findings)||report.findings.length>200)fail(422,"Relatório fora do escopo");
  const allowed=JSON.parse(row.tools);
  if(report.modules.some(m=>!allowed.includes(m.tool)))fail(422,"Ferramentas inconsistentes");
  if(!["completed","completed_with_errors","failed"].includes(report.status))fail(422,"Status de relatório inválido");
  await env.DB.prepare("UPDATE scans SET report=?,status=?,updated=?,error=NULL WHERE id=?").bind(JSON.stringify(report),report.status,epoch(),report.id).run();
  return json({ok:true});
}
export default {
  async scheduled(event,env,ctx){
    ctx.waitUntil(reconcilePending(env,{github:gh,signManifest:encodeManifest}));
  },
  async fetch(req,env) {
    const url=new URL(req.url),path=url.pathname,method=req.method;
    try {
      if(path==="/"&&method==="GET")return content(PANEL_HTML||"<h1>FluxOpen</h1><p>O painel precisa ser publicado.</p>");
      if(path==="/health"&&method==="GET")return json({ok:true,platform:"cloudflare-workers",database:!!env.DB,login_configured:!!env.ADMIN_PASSWORD,github_configured:!!env.GH_TOKEN,signing_configured:!!env.SCAN_SIGNING_SECRET,queue_recovery:"cron"});
      if(!path.startsWith("/api/"))fail(404,"Rota não encontrada");
      if(path==="/api/callback"&&method==="POST")return await callback(req,env);
      if(path==="/api/session"&&method==="GET"){
        try{const record=await auth(req,env);return json({authenticated:true,csrf:record.csrf,backend:"github",tools:TOOL_ORDER,passive:[...CONSERVATIVE]});}
        catch(e){if(e.status===401)return json({authenticated:false});throw e;}
      }
      if(path==="/api/login"&&method==="POST")return await login(req,env);
      if(path==="/api/security"&&method==="GET"){
        await auth(req,env);
        return json(await identity(env));
      }
      if(path==="/api/security/password"&&method==="POST"){
        await auth(req,env,true);
        const {email,password}=await readJSON(req);
        try{return json(await setIdentity(env,email,password))}
        catch(e){fail(422,e.message||"Não foi possível configurar a senha");}
      }
      if(path==="/api/passkeys/registration/options"&&method==="POST"){
        await auth(req,env,true);
        const result=await registrationOptions(req,env,await digest(cookie(req)));
        return json(result.body,200,{"Set-Cookie":result.cookie});
      }
      if(path==="/api/passkeys/registration/verify"&&method==="POST"){
        await auth(req,env,true);
        const body=await readJSON(req,60000);
        try{
          const result=await registrationFinish(req,env,await digest(cookie(req)),body);
          return json({ok:true,id:result.id},200,{"Set-Cookie":result.clearCookie});
        }catch(e){fail(422,"Não foi possível registrar a chave-senha: "+String(e.message).slice(0,180));}
      }
      if(path==="/api/passkeys/authentication/options"&&method==="POST"){
        try{
          const result=await authenticationOptions(req,env);
          return json(result.body,200,{"Set-Cookie":result.cookie});
        }catch(e){fail(422,String(e.message).slice(0,180));}
      }
      if(path==="/api/passkeys/authentication/verify"&&method==="POST"){
        const body=await readJSON(req,60000);
        try{
          const result=await authenticationFinish(req,env,body);
          const fresh=await newSession(env);
          const response=json({authenticated:true,csrf:fresh.csrf});
          response.headers.append("Set-Cookie",fresh.sessionCookie);
          response.headers.append("Set-Cookie",result.clearCookie);
          return response;
        }catch(e){fail(401,"Chave-senha recusada: "+String(e.message).slice(0,180));}
      }
      if(path==="/api/logout"&&method==="POST"){
        await auth(req,env,true);
        await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(cookie(req))).run();
        return json({ok:true},200,{"Set-Cookie":"fluxopen_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"});
      }
      if(path==="/api/targets"&&method==="GET"){
        await auth(req,env);
        const r=await env.DB.prepare("SELECT id,name,url,valid_until,created FROM targets ORDER BY id DESC LIMIT 500").all();
        return json(r.results);
      }
      if(path==="/api/targets"&&method==="POST"){await auth(req,env,true);return await createTarget(req,env);}
      if(path==="/api/scans"&&method==="GET"){
        await auth(req,env);
        const r=await env.DB.prepare("SELECT s.id,s.url,s.tools,s.mode,s.status,s.started,s.updated,s.run_id,s.error,t.name AS target_name FROM scans s JOIN targets t ON t.id=s.target_id ORDER BY s.started DESC LIMIT 100").all();
        return json(r.results.map(row=>({...row,tools:JSON.parse(row.tools)})));
      }
      if(path==="/api/scans"&&method==="POST"){await auth(req,env,true);return await createScan(req,env);}
      const match=path.match(/^\/api\/scans\/([a-f0-9]{32})(?:\/(download))?$/);
      if(match&&method==="GET"){
        await auth(req,env);
        if(match[2])return await downloadReport(env,match[1],url.searchParams.get("format")||"json");
        return json(await detail(req,env,match[1]));
      }
      fail(404,"Rota não encontrada");
    }catch(e) {
      if(e instanceof WebError)return json({detail:e.message},e.status);
      console.error("FluxOpen Worker failure",e && e.stack?String(e.stack).slice(0,600):String(e).slice(0,200));
      return json({detail:"Erro interno do painel"},500);
    }
  }
};
