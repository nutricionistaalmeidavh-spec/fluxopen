import test from "node:test";
import assert from "node:assert/strict";
import worker from "../cloudflare/worker.mjs";

const ID="a".repeat(32);
const SECRET="test-callback-hmac-key-".repeat(3);
const BASE={id:ID,url:"https://example.org/",mode:"passive",status:"completed",started:1794161387,ended:1794161640,modules:[{tool:"zap",status:"ok",excerpt:"WARN-NEW: 0"}],findings:[]};
function database(){
  const row={url:BASE.url,mode:BASE.mode,tools:JSON.stringify(["zap"]),status:"running",report:null};
  let writes=0;
  const env={SCAN_SIGNING_SECRET:SECRET,DB:{
    prepare(sql){
      return {bind(...params){
        return {
          async first(){if(sql.startsWith("SELECT url,tools,mode,status FROM scans"))return {...row};throw Error("SQL inesperado: "+sql)},
          async run(){
            if(!sql.includes("AND report IS NULL"))throw Error("Atualizacao nao atomica");
            if(!["running","queued"].includes(row.status)||row.report!==null)return {meta:{changes:0}};
            row.report=params[0];row.status=params[1];writes++;return {meta:{changes:1}};
          }
        }
      }}
    }
  }};
  return {env,row,getWrites:()=>writes};
}
async function request(payload,secret=SECRET){
  const body=JSON.stringify(payload);
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const bytes=await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(body));
  const signature=[...new Uint8Array(bytes)].map(v=>v.toString(16).padStart(2,"0")).join("");
  return new Request("https://fluxopen.example.org/api/callback",{method:"POST",headers:{"Content-Type":"application/json","X-FluxOpen-Signature":signature},body});
}
test("callback autentica HMAC e finaliza uma unica vez",async()=>{
  const db=database();
  const response=await worker.fetch(await request(BASE),db.env);
  assert.equal(response.status,200);
  assert.equal(db.getWrites(),1);
  assert.deepEqual(JSON.parse(db.row.report),BASE);
  const again=await worker.fetch(await request(BASE),db.env);
  assert.equal(again.status,409);
  assert.equal(db.getWrites(),1);
});
test("HMAC invalido nao escreve no banco",async()=>{
  const db=database();
  const response=await worker.fetch(await request(BASE,"wrong-signature-key-".repeat(3)),db.env);
  assert.equal(response.status,403);
  assert.equal(db.getWrites(),0);
});
test("callback rejeita achados desconhecidos e ferramentas inconsistentes",async()=>{
  const db=database();
  const badModule={...BASE,modules:[{tool:"sqlmap",status:"ok",excerpt:"x"}]};
  assert.equal((await worker.fetch(await request(badModule),db.env)).status,422);
  const badFinding={...BASE,findings:[{tool:"zap",severity:"high",title:"x",url:"https://example.org/",urls:["x".repeat(2049)]}]};
  assert.equal((await worker.fetch(await request(badFinding),db.env)).status,422);
  assert.equal(db.getWrites(),0);
});
test("callbacks simultaneos nao substituem relatorio final",async()=>{
  const db=database();
  const [a,b]=await Promise.all([worker.fetch(await request(BASE),db.env),worker.fetch(await request(BASE),db.env)]);
  assert.deepEqual([a.status,b.status].sort(),[200,409]);
  assert.equal(db.getWrites(),1);
});
