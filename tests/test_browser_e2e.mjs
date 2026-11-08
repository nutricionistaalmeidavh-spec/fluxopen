import test from "node:test";
import assert from "node:assert/strict";
import {chromium} from "playwright";
import {PANEL_HTML} from "../cloudflare/panel.mjs";
import {renderFriendlyHtml} from "../cloudflare/friendly.mjs";

const audit={
  id:"a".repeat(32),url:"https://example.org/?token=do-not-show",mode:"passive",
  started:1794161387,ended:1794161640,status:"completed_with_errors",
  modules:[{tool:"zap",status:"ok",excerpt:"WARN-NEW: Content Security Policy Header Not Set [10038] x 1"},
           {tool:"nuclei",status:"error",excerpt:"Tempo limite."}],
  findings:[{tool:"zap",rule_id:"10038",title:"CSP Header Not Set",severity:"medium",url:"https://example.org/?key=private"}]
};
test("FluxOpen: painel mobile exibe login e passkey sem overflow",async()=>{
  const browser=await chromium.launch({headless:true});
  try{
    const page=await browser.newPage({viewport:{width:375,height:812},deviceScaleFactor:1});
    await page.route("https://fluxopen.test/**",async route=>{
      const path=new URL(route.request().url()).pathname;
      if(path==="/")return route.fulfill({status:200,contentType:"text/html",body:PANEL_HTML});
      if(path==="/api/session")return route.fulfill({status:200,contentType:"application/json",body:'{"authenticated":false}'});
      return route.fulfill({status:404,contentType:"application/json",body:'{"error":"Not found"}'});
    });
    await page.goto("https://fluxopen.test/");
    await page.locator("#loginform").waitFor({state:"visible"});
    assert.equal(await page.locator("#passkeyLogin").isVisible(),true);
    assert.equal(await page.locator("#loginEmail").isVisible(),true);
    assert.equal(await page.locator("#loginPassword").isVisible(),true);
    const size=await page.evaluate(()=>({scroll:document.documentElement.scrollWidth,viewport:innerWidth}));
    assert.ok(size.scroll<=size.viewport+2,JSON.stringify(size));
  }finally{await browser.close()}
});
test("FluxOpen: HTML de relatorio mobile, navegacao e evidencias sem credenciais",async()=>{
  const browser=await chromium.launch({headless:true});
  try{
    const page=await browser.newPage({viewport:{width:375,height:812},deviceScaleFactor:1});
    await page.setContent(renderFriendlyHtml(audit));
    assert.equal(await page.locator("h1").first().innerText(),"Relatório de Segurança");
    assert.equal(await page.locator(".status-banner").isVisible(),true);
    const size=await page.evaluate(()=>({scroll:document.documentElement.scrollWidth,viewport:innerWidth}));
    assert.ok(size.scroll<=size.viewport+2,JSON.stringify(size));
    await page.locator('a[href="#technical"]').click();
    assert.equal(await page.evaluate(()=>location.hash),"#technical");
    await page.locator("details.tech-report summary").first().click();
    assert.equal(await page.locator("details.tech-report pre").first().isVisible(),true);
    const markup=await page.content();
    assert.ok(!markup.includes("do-not-show"));
    assert.ok(!markup.includes("key=private"));
    await page.emulateMedia({media:"print"});
    assert.equal(await page.locator(".technical").evaluate(el=>getComputedStyle(el).display),"none");
  }finally{await browser.close()}
});
