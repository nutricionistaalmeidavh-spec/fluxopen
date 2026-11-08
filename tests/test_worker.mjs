import test from "node:test";
import assert from "node:assert/strict";
import { normalizeTarget,validateTools,encodeManifest } from "../cloudflare/worker.mjs";
import { execFileSync } from "node:child_process";

test("target URL normalization and rejection", () => {
  assert.equal(normalizeTarget("https://App.Example.ORG/a?b=1"),"https://app.example.org/a?b=1");
  for(const uri of ["http://localhost/","http://127.0.0.1/","https://192.168.1.1/",
    "https://foo.local/","https://foo.internal/","file:///etc/passwd",
    "https://user:pass@example.org/","https://example.org:22/",
    "https://example.org/#hash","https://bad.example.com:9999/"]) {
    assert.throws(()=>normalizeTarget(uri),{status:422},uri);
  }
});
test("passive scan refuses active tools", () => {
  assert.deepEqual(validateTools(["zap","subfinder"],"passive"),["zap","subfinder"]);
  assert.throws(()=>validateTools(["sqlmap"],"passive"),{status:422});
  assert.throws(()=>validateTools(["zap","zap"],"active"),{status:422});
  assert.deepEqual(validateTools(["sqlmap","nuclei"],"active"),["sqlmap","nuclei"]);
});
test("manifest interoperates with signed Python runner",async()=>{
  const now=Math.floor(Date.now()/1000);
  const manifest={id:"a".repeat(32),url:"https://example.org/",tools:["zap","subfinder"],
    mode:"passive",issued:now,expires:now+3600};
  const signed=await encodeManifest(manifest,"x".repeat(40));
  const code="import json,sys; from security import verify_manifest; item=verify_manifest(sys.argv[1],sys.argv[2],'x'*40,resolve=False); print(json.dumps(item))";
  const payload=execFileSync("python3",["-c",code,signed.packed,signed.signature],{encoding:"utf8"});
  assert.deepEqual(JSON.parse(payload),manifest);
});
test("Worker serves existing dashboard at root", async()=>{
  const {default:worker}=await import("../cloudflare/worker.mjs");
  const response=await worker.fetch(new Request("https://fluxopen-security.example.org/"),{});
  assert.equal(response.status,200);
  assert.match(await response.text(),/FluxOpen/);
  assert.equal(response.headers.get("x-frame-options"),"DENY");
});


test("callback rejects replay and validates scanner result fields",async()=>{
  const {readFileSync}=await import("node:fs");
  const source=readFileSync(new URL("../cloudflare/worker.mjs",import.meta.url),"utf8");
  assert.match(source,/status IN \\('queued','running'\\) AND report IS NULL/);
  assert.match(source,/saved\\.meta\\?\\.changes!==1/);
  assert.match(source,/Achados inválidos/);
  assert.match(source,/Módulos inválidos/);
  assert.match(source,/\\\"warning\\\"/);
});
