import vm from "node:vm";
import { PANEL_HTML } from "../cloudflare/panel.mjs";
import test from "node:test";
import assert from "node:assert/strict";
import {
  b64u,un64,hash,verifyRegistration,verifyAssertion,derSignatureToRaw
} from "../cloudflare/webauthn.mjs";

const enc=new TextEncoder();
const origin="https://fluxopen-security.nutricionistaalmeidavh.workers.dev";
const host=new URL(origin).hostname;
const cat=(...parts)=>Uint8Array.from(parts.flatMap(p=>[...p]));
const header=(major,n)=>{
  if(n<24)return Uint8Array.of((major<<5)|n);
  if(n<256)return Uint8Array.of((major<<5)|24,n);
  return Uint8Array.of((major<<5)|25,(n>>8)&255,n&255);
};
function cbor(v){
  if(v instanceof Uint8Array)return cat(header(2,v.length),v);
  if(typeof v==="string"){const b=enc.encode(v);return cat(header(3,b.length),b)}
  if(typeof v==="number"){return header(v>=0?0:1,v>=0?v:-1-v)}
  if(v instanceof Map){const parts=[header(5,v.size)];for(const [k,x]of v){parts.push(cbor(k),cbor(x))}return cat(...parts)}
  throw Error("test-only CBOR type");
}
const client=(type,challenge,baseOrigin=origin)=>b64u(enc.encode(JSON.stringify({type,challenge,origin:baseOrigin,crossOrigin:false})));
function derInteger(raw){let i=0;while(i<31&&raw[i]===0)i++;let value=raw.slice(i);if(value[0]&128)value=cat([0],value);return cat([2,value.length],value)}
function toDER(raw){const a=derInteger(raw.slice(0,32)),b=derInteger(raw.slice(32));return cat([0x30,a.length+b.length],a,b)}

test("passkey Base64URL is reversible",()=>{
  const v=crypto.getRandomValues(new Uint8Array(32));
  assert.deepEqual(un64(b64u(v)),v);
  assert.throws(()=>un64("???"));
});
test("verify WebAuthn registration and signed login end-to-end",async()=>{
  const key=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const jwk=await crypto.subtle.exportKey("jwk",key.publicKey);
  const credentialId=crypto.getRandomValues(new Uint8Array(32));
  const rpHash=new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(host)));
  const cose=new Map([[1,2],[3,-7],[-1,1],[-2,un64(jwk.x)],[-3,un64(jwk.y)]]);
  const attested=cat(rpHash,[0x45,0,0,0,0],new Uint8Array(16),[0,32],credentialId,cbor(cose));
  const attObj=cbor(new Map([["fmt","none"],["attStmt",new Map()],["authData",attested]]));
  const challenge=b64u(crypto.getRandomValues(new Uint8Array(32)));
  const registered={
    id:b64u(credentialId),rawId:b64u(credentialId),type:"public-key",
    response:{clientDataJSON:client("webauthn.create",challenge),attestationObject:b64u(attObj)}
  };
  const saved=await verifyRegistration(registered,challenge,origin);
  assert.equal(saved.id,registered.id);
  assert.equal(JSON.parse(saved.jwk).crv,"P-256");
  assert.equal(saved.counter,0);
  await assert.rejects(()=>verifyRegistration(registered,challenge+"x",origin),/Challenge/);
  await assert.rejects(()=>verifyRegistration(registered,challenge,"https://attacker.example.com"),/Challenge|origem/);
  const bad={...registered,response:{...registered.response,attestationObject:b64u(cbor(new Map([["fmt","none"],["attStmt",new Map()],["authData",cat(rpHash,[0x41,0,0,0,0],new Uint8Array(16),[0,32],credentialId,cbor(cose))]])))}};
  await assert.rejects(()=>verifyRegistration(bad,challenge,origin),/verificação/);

  const assertionData=cat(rpHash,[5,0,0,0,1]);
  const challenge2=b64u(crypto.getRandomValues(new Uint8Array(32)));
  const clientBytes=un64(client("webauthn.get",challenge2));
  const clientHash=new Uint8Array(await crypto.subtle.digest("SHA-256",clientBytes));
  const rawSig=new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key.privateKey,cat(assertionData,clientHash)));
  const signature=b64u(toDER(rawSig));
  assert.deepEqual(derSignatureToRaw(un64(signature)),rawSig);
  const assertion={
    id:saved.id,rawId:saved.id,type:"public-key",
    response:{clientDataJSON:b64u(clientBytes),authenticatorData:b64u(assertionData),signature,userHandle:"Zmx1eG9wZW4tYWRtaW4"}
  };
  const verified=await verifyAssertion(assertion,challenge2,origin,{...saved,counter:0});
  assert.equal(verified.counter,1);
  await assert.rejects(()=>verifyAssertion(assertion,challenge2,origin,{...saved,counter:1}),/Contador/);
  const tampered={...assertion,response:{...assertion.response,signature:b64u(toDER(new Uint8Array(64).fill(1)))}};
  await assert.rejects(()=>verifyAssertion(tampered,challenge2,origin,saved),/Assinatura/);
});

test("published Cloudflare dashboard JavaScript parses and includes passkey controls",()=>{
  const script=PANEL_HTML.split("<script>",2)[1]?.split("</script>",1)[0];
  assert.ok(script,"missing panel script");
  assert.doesNotThrow(()=>new vm.Script(script));
  assert.match(PANEL_HTML,/id="passkeyLogin"/);
  assert.match(PANEL_HTML,/id="passkeyRegister"/);
});
