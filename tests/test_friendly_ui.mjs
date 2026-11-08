import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import {PANEL_HTML} from "../cloudflare/panel.mjs";
import {buildFriendlyReport} from "../cloudflare/friendly.mjs";

test("Cloudflare panel embedded JS parses after friendly report update",()=>{
  const script=PANEL_HTML.split("<script>",2)[1]?.split("</script>",1)[0];
  assert.ok(script);
  assert.doesNotThrow(()=>new vm.Script(script));
  assert.match(script,/data\.friendly/);
  assert.match(script,/friendlyCard/);
  assert.match(script,/Plano de correção recomendado/);
});
test("native HTML export contains Portuguese summary and technical evidence",()=>{
  const sample={url:"https://example.org/",status:"completed",modules:[{tool:"zap",status:"ok",excerpt:"WARN-NEW: Strict-Transport-Security Header Not Set [10035] x 2\nhttps://example.org/ (200 OK)"}],findings:[]};
  const result=buildFriendlyReport(sample);
  assert.equal(result.items.length,1);
  assert.match(result.items[0].title,/HTTPS/);
  assert.match(PANEL_HTML,/Pentest Diagnoses/);
  assert.match(PANEL_HTML,/Ver evidências e detalhes técnicos/);
});
