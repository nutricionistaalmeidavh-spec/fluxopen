import test from "node:test";
import assert from "node:assert/strict";
import { reconcilePending } from "../cloudflare/dispatch.mjs";

const scan={
  id:"25d3aad623c8b467bf5c329b614ca01f",
  url:"https://artisys.dev/",
  tools:'["zap","subfinder","httpx","katana","testssl"]',
  mode:"passive", status:"queued",started:1794155013,
  target_url:"https://artisys.dev/",valid_until:"2026-11-10"
};
function harness({row=scan,claim=1,token="github-safe",secret="x".repeat(45),runs=[],throwGithub=false}={}){
  const sql=[],calls=[];
  const database={
    prepare(query){
      return {
        bind(...values){
          return {
            async all(){sql.push({query,values});return{results:row?[row]:[]}},
            async run(){sql.push({query,values});return{meta:{changes:query.includes("INSERT OR IGNORE")?claim:1}}}
          };
        }
      };
    }
  };
  const env={DB:database,GH_TOKEN:token,SCAN_SIGNING_SECRET:secret};
  const github=async (_env,route,options)=>{
    calls.push({route,options});
    if(throwGithub)throw Error("GitHub API indisponível");
    if(route.includes("/runs?"))return{workflow_runs:runs};
    return null;
  };
  const signManifest=async (payload,securityKey)=>{
    assert.equal(securityKey,secret);
    return{packed:JSON.stringify(payload),signature:"signed"};
  };
  return{env,sql,calls,github,signManifest};
}
test("Recupera pedido enfileirado com um único dispatch assinado e escopo limitado",async()=>{
  const h=harness();
  const result=await reconcilePending(h.env,{now:1794159000,github:h.github,signManifest:h.signManifest});
  assert.equal(result.dispatched,1);
  assert.equal(h.calls.length,2);
  assert.match(h.calls[1].route,/scan.yml\/dispatches$/);
  const input=JSON.parse(h.calls[1].options.body).inputs;
  const payload=JSON.parse(input.payload);
  assert.equal(input.scan_id,scan.id);
  assert.equal(input.signature,"signed");
  assert.equal(input.verification_only,"false");
  assert.equal(payload.url,scan.url);
  assert.equal(payload.mode,"passive");
  assert.deepEqual(payload.tools,JSON.parse(scan.tools));
  assert.ok(h.sql.some(s=>s.query.includes("UPDATE scans SET status='running'")));
});
test("Não duplica se outra execução já reivindicou o pedido",async()=>{
  const h=harness({claim:0});
  const result=await reconcilePending(h.env,{now:1794159000,github:h.github,signManifest:h.signManifest});
  assert.equal(result.dispatched,0);
  assert.equal(h.calls.length,0);
});
test("Acha execução já existente e não cria novo workflow",async()=>{
  const h=harness({runs:[{id:1234,display_title:"FluxOpen "+scan.id,status:"in_progress"}]});
  const result=await reconcilePending(h.env,{now:1794159000,github:h.github,signManifest:h.signManifest});
  assert.equal(result.dispatched,0);
  assert.equal(result.found,1);
  assert.equal(h.calls.length,1);
  assert.ok(h.sql.some(s=>s.query.includes("UPDATE scans SET status='running'")&&s.values.includes(1234)));
});
test("Não executa quando autorização expirou ou domínio divergiu",async()=>{
  for(const replacement of [{valid_until:"2026-11-08"},{target_url:"https://other.example.org/"}]){
    const h=harness({row:{...scan,...replacement}});
    const result=await reconcilePending(h.env,{now:1794159000,github:h.github,signManifest:h.signManifest});
    assert.equal(result.dispatched,0);
    assert.equal(h.calls.length,0);
    assert.ok(h.sql.some(s=>s.query.includes("status='failed'")));
  }
});
test("Falha fica explícita no painel em vez de na fila para sempre",async()=>{
  const h=harness({throwGithub:true});
  const result=await reconcilePending(h.env,{now:1794159000,github:h.github,signManifest:h.signManifest});
  assert.equal(result.failed,1);
  assert.ok(h.sql.some(s=>s.query.includes("status='failed'")&&s.values.some(v=>String(v).includes("GitHub API indisponível"))));
});
test("Não despacha se os segredos não estão disponíveis",async()=>{
  const h=harness({token:""});
  const result=await reconcilePending(h.env,{now:1794159000,github:h.github,signManifest:h.signManifest});
  assert.equal(result.failed,1);
  assert.equal(h.calls.length,0);
});
