import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { PANEL_HTML } from "../cloudflare/panel.mjs";

test("production Cloudflare panel compiles and renders friendly summary labels",()=>{
  const script=PANEL_HTML.split("<script>",2)[1]?.split("</script>",1)[0];
  assert.ok(script,"missing client script");
  assert.doesNotThrow(()=>new vm.Script(script));
  assert.match(PANEL_HTML,/Relatório de segurança/);
  assert.match(PANEL_HTML,/Baixar relatório amigável/);
  assert.match(PANEL_HTML,/Evidências técnicas originais/);
  assert.match(PANEL_HTML,/id="passkeyLogin"/,"Face ID login preserved");
  assert.match(PANEL_HTML,/id="passkeyRegister"/,"Face ID registration preserved");
});
