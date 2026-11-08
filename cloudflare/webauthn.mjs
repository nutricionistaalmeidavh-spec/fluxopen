/**
 * Zero-dependency WebAuthn passkeys (ES256, user verification required).
 * Passkeys are scoped to this exact workers.dev hostname.
 * Registration is ONLY possible from an authenticated administrator session.
 */
const enc=new TextEncoder(),dec=new TextDecoder("utf-8",{fatal:true});
export const b64u=(input)=>btoa(String.fromCharCode(...new Uint8Array(input))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
export function un64(s){
  if(typeof s!=="string"||s.length>50000||! /^[A-Za-z0-9_-]+$/.test(s))throw new Error("Base64URL inválido");
  const binary=atob(s.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(s.length/4)*4,"="));
  return Uint8Array.from(binary,c=>c.charCodeAt(0));
}
export const random=(size=32)=>crypto.getRandomValues(new Uint8Array(size));
export const randomString=(size=32)=>b64u(random(size));
export async function hash(value){return b64u(await crypto.subtle.digest("SHA-256",typeof value==="string"?enc.encode(value):value));}
const equal=(a,b)=>{if(a.length!==b.length)return false;let n=0;for(let i=0;i<a.length;i++)n|=a[i]^b[i];return n===0};
const err=(message)=>{throw new Error(message)};
function cbor(bytes,pos=0,depth=0){
  if(depth>12||pos>=bytes.length)err("CBOR inválido");
  const start=bytes[pos++],major=start>>5,aux=start&31;
  let len;
  if(aux<24)len=aux;
  else if(aux===24)len=bytes[pos++];
  else if(aux===25){if(pos+2>bytes.length)err("CBOR truncado");len=bytes[pos]*256+bytes[pos+1];pos+=2;}
  else if(aux===26){if(pos+4>bytes.length)err("CBOR truncado");len=new DataView(bytes.buffer,bytes.byteOffset+pos,4).getUint32(0);pos+=4;}
  else err("Tipo CBOR não suportado");
  if(!Number.isSafeInteger(len)||len<0||len>65536)err("Tamanho CBOR inválido");
  if(major===0||major===1)return{value:major===0?len:-1-len,pos};
  if(major===2||major===3){
    if(pos+len>bytes.length)err("CBOR truncado");
    const section=bytes.slice(pos,pos+len);return{value:major===2?section:dec.decode(section),pos:pos+len};
  }
  if(major===4){
    const a=[];for(let i=0;i<len;i++){const v=cbor(bytes,pos,depth+1);a.push(v.value);pos=v.pos}
    return{value:a,pos};
  }
  if(major===5){
    const map=new Map();
    for(let i=0;i<len;i++){
      const k=cbor(bytes,pos,depth+1);const v=cbor(bytes,k.pos,depth+1);
      if(map.has(k.value))err("CBOR com chave duplicada");
      map.set(k.value,v.value);pos=v.pos;
    }return{value:map,pos};
  }
  if(major===7&&aux===20)return{value:false,pos};
  if(major===7&&aux===21)return{value:true,pos};
  if(major===7&&aux===22)return{value:null,pos};
  err("CBOR não suportado");
}
export function parseAuthenticatorData(raw,rpId,registration=false) {
  const bytes=raw instanceof Uint8Array?raw:new Uint8Array(raw);
  if(bytes.byteLength<37||bytes.byteLength>16384)err("authenticatorData inválido");
  const head=bytes.slice(0,32),flags=bytes[32],counter=new DataView(bytes.buffer,bytes.byteOffset+33,4).getUint32(0);
  if(!(flags&0x01)||!(flags&0x04))err("Presença e verificação do usuário são obrigatórias");
  const result={rpHash:head,flags,counter};
  if(registration){
    if(!(flags&0x40)||bytes.byteLength<55)err("Credencial não fornecida");
    const len=bytes[53]*256+bytes[54];
    if(len<16||len>1024||55+len>=bytes.byteLength)err("ID da credencial inválido");
    result.credentialId=bytes.slice(55,55+len);
    const parsed=cbor(bytes,55+len);
    if(!(parsed.value instanceof Map))err("Chave COSE inválida");
    const cose=parsed.value;
    const x=cose.get(-2),y=cose.get(-3);
    if(cose.get(1)!==2||cose.get(3)!==-7||cose.get(-1)!==1||!(x instanceof Uint8Array)||!(y instanceof Uint8Array)||x.length!==32||y.length!==32)err("Somente passkeys ES256 P-256 são suportadas");
    result.publicKey={kty:"EC",crv:"P-256",x:b64u(x),y:b64u(y),ext:true,key_ops:["verify"]};
  }
  return result;
}
async function validateAuthData(raw,rpId,registration){
  const out=parseAuthenticatorData(raw,rpId,registration);
  const expected=await crypto.subtle.digest("SHA-256",enc.encode(rpId));
  if(!equal(out.rpHash,new Uint8Array(expected)))err("RP ID não corresponde ao domínio");
  return out;
}
function validateClient(raw,expectedType,challenge,origin){
  if(!origin.startsWith("https://"))err("HTTPS obrigatório");
  let client;
  try{client=JSON.parse(dec.decode(un64(raw)))}catch{err("clientDataJSON inválido")}
  if(client.type!==expectedType||client.challenge!==challenge||client.origin!==origin||client.crossOrigin===true||client.topOrigin)err("Challenge ou origem inválida");
  return un64(raw);
}
export async function verifyRegistration(credential,challenge,origin){
  if(!credential||credential.type!=="public-key"||!credential.response)err("Resposta WebAuthn inválida");
  const rpId=new URL(origin).hostname;
  const rawId=un64(credential.rawId||credential.id);
  validateClient(credential.response.clientDataJSON,"webauthn.create",challenge,origin);
  const obj=cbor(un64(credential.response.attestationObject)).value;
  if(!(obj instanceof Map)||obj.get("fmt")!=="none"||!(obj.get("authData") instanceof Uint8Array))err("Atestação não suportada");
  const stmt=obj.get("attStmt");
  if(!(stmt instanceof Map)||stmt.size!==0)err("Atestação inválida");
  const data=await validateAuthData(obj.get("authData"),rpId,true);
  if(!equal(rawId,data.credentialId))err("ID da credencial divergente");
  return{id:b64u(rawId),jwk:JSON.stringify(data.publicKey),counter:data.counter};
}
export function derSignatureToRaw(bytes){
  if(!(bytes instanceof Uint8Array))bytes=new Uint8Array(bytes);
  if(bytes.length<8||bytes.length>80||bytes[0]!==0x30||bytes[1]!==bytes.length-2)err("Assinatura DER inválida");
  let idx=2;
  const read=()=>{
    if(bytes[idx++]!==0x02)err("Assinatura DER inválida");
    const n=bytes[idx++];
    if(n<1||n>33||idx+n>bytes.length)err("Assinatura DER inválida");
    let v=bytes.slice(idx,idx+n);idx+=n;
    if(v.length===33){if(v[0]!==0)err("Assinatura DER inválida");v=v.slice(1);}
    if(v.length>32)err("Assinatura DER inválida");
    const r=new Uint8Array(32);r.set(v,32-v.length);return r;
  };
  const r=read(),s=read();
  if(idx!==bytes.length)err("Assinatura DER inválida");
  return Uint8Array.from([...r,...s]);
}
export async function verifyAssertion(credential,challenge,origin,stored){
  if(!credential||credential.type!=="public-key"||!credential.response||!stored||typeof stored.jwk!=="string")err("Credencial desconhecida");
  const id=b64u(un64(credential.rawId||credential.id));
  if(id!==stored.id)err("Credencial divergente");
  const clientBytes=validateClient(credential.response.clientDataJSON,"webauthn.get",challenge,origin);
  const rawData=un64(credential.response.authenticatorData);
  const data=await validateAuthData(rawData,new URL(origin).hostname,false);
  if(credential.response.userHandle){
    // The user handle is a fixed single-account random byte identifier, not an email address.
    if(b64u(un64(credential.response.userHandle))!=="Zmx1eG9wZW4tYWRtaW4")err("Usuário não corresponde");
  }
  const hashClient=new Uint8Array(await crypto.subtle.digest("SHA-256",clientBytes));
  const bytes=new Uint8Array(rawData.length+hashClient.length);bytes.set(rawData);bytes.set(hashClient,rawData.length);
  let jwk;try{jwk=JSON.parse(stored.jwk)}catch{err("Chave pública inválida")}
  const key=await crypto.subtle.importKey("jwk",jwk,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
  const sig=derSignatureToRaw(un64(credential.response.signature));
  if(!await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,sig,bytes))err("Assinatura inválida");
  const old=Number(stored.counter)||0;
  if(old!==0&&data.counter!==0&&data.counter<=old)err("Contador de autenticação inválido");
  return{counter:data.counter};
}
const ttl=300;
const nonceCookie=n=>"fluxopen_webauthn="+n+"; Path=/api/passkeys; Max-Age=300; Secure; HttpOnly; SameSite=Strict";
const clearNonce="fluxopen_webauthn=; Path=/api/passkeys; Max-Age=0; Secure; HttpOnly; SameSite=Strict";
function getNonce(req) {
  const match=(req.headers.get("Cookie")||"").split(";").map(s=>s.trim()).find(s=>s.startsWith("fluxopen_webauthn="));
  return match?match.slice("fluxopen_webauthn=".length):"";
}
async function begin(req,env,purpose,sessionHash=null){
  if(!env.DB)err("Banco D1 indisponível");
  const now=Math.floor(Date.now()/1000);
  await env.DB.prepare("DELETE FROM webauthn_challenges WHERE expires<?").bind(now).run();
  const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM webauthn_challenges").first();
  if(count.n>250)err("Muitas tentativas; tente novamente");
  const nonce=randomString(32),challenge=randomString(32);
  await env.DB.prepare("INSERT INTO webauthn_challenges(token_hash,challenge,purpose,session_hash,expires) VALUES (?,?,?,?,?)").bind(await hash(nonce),challenge,purpose,sessionHash,now+ttl).run();
  return{challenge,nonceCookie:nonceCookie(nonce)};
}
async function consume(req,env,purpose,sessionHash=null){
  const nonce=getNonce(req);
  if(!nonce||nonce.length>100)err("Desafio expirado: tente novamente");
  const key=await hash(nonce);
  const item=await env.DB.prepare("SELECT challenge,purpose,session_hash,expires FROM webauthn_challenges WHERE token_hash=?").bind(key).first();
  await env.DB.prepare("DELETE FROM webauthn_challenges WHERE token_hash=?").bind(key).run();
  if(!item||item.purpose!==purpose||item.session_hash!==sessionHash||item.expires<Math.floor(Date.now()/1000))err("Desafio inválido ou expirado");
  return{challenge:item.challenge,clearCookie:clearNonce};
}
export async function registrationOptions(req,env,sessionHash){
  const {challenge,nonceCookie:cookie}=await begin(req,env,"registration",sessionHash);
  const rpId=new URL(req.url).hostname;
  const keys=(await env.DB.prepare("SELECT id FROM passkeys LIMIT 20").all()).results||[];
  const info=await env.DB.prepare("SELECT email FROM admin_identity WHERE id=1").first();
  return{cookie,body:{
    challenge,rp:{id:rpId,name:"FluxOpen"},user:{id:"Zmx1eG9wZW4tYWRtaW4",name:info?.email||"FluxOpen Admin",displayName:"Administrador FluxOpen"},
    pubKeyCredParams:[{type:"public-key",alg:-7}],timeout:60000,attestation:"none",
    authenticatorSelection:{residentKey:"required",requireResidentKey:true,userVerification:"required"},
    excludeCredentials:keys.map(x=>({type:"public-key",id:x.id}))
  }};
}
export async function registrationFinish(req,env,sessionHash,payload){
  const consumed=await consume(req,env,"registration",sessionHash);
  const item=await verifyRegistration(payload,consumed.challenge,new URL(req.url).origin);
  await env.DB.prepare("INSERT INTO passkeys(id,jwk,counter,created,last_used) VALUES (?,?,?,?,?)").bind(item.id,item.jwk,item.counter,Math.floor(Date.now()/1000),null).run();
  return{ok:true,id:item.id,clearCookie:consumed.clearCookie};
}
export async function authenticationOptions(req,env){
  const registered=await env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys").first();
  if(!registered?.n)err("Nenhuma chave-senha cadastrada. Entre com a senha administrativa primeiro.");
  const {challenge,nonceCookie:cookie}=await begin(req,env,"authentication");
  return{cookie,body:{challenge,rpId:new URL(req.url).hostname,userVerification:"required",timeout:60000,allowCredentials:[]}};
}
export async function authenticationFinish(req,env,payload){
  const consumed=await consume(req,env,"authentication");
  const id=payload&&typeof payload.id==="string"?payload.id:"";
  if(!id||id.length>2048)err("Chave-senha inválida");
  const saved=await env.DB.prepare("SELECT id,jwk,counter FROM passkeys WHERE id=?").bind(id).first();
  if(!saved)err("Chave-senha não cadastrada");
  const result=await verifyAssertion(payload,consumed.challenge,new URL(req.url).origin,saved);
  await env.DB.prepare("UPDATE passkeys SET counter=?,last_used=? WHERE id=?").bind(result.counter,Math.floor(Date.now()/1000),saved.id).run();
  return{ok:true,clearCookie:consumed.clearCookie};
}
export async function identity(env){
  const [row,count]=await Promise.all([env.DB.prepare("SELECT email,updated FROM admin_identity WHERE id=1").first(),env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys").first()]);
  return{email:row?.email||null,passkeys:count?.n||0};
}
async function pbkdf2(password,salt,iterations=310000){
  const key=await crypto.subtle.importKey("raw",enc.encode(password),{name:"PBKDF2"},false,["deriveBits"]);
  return b64u(await crypto.subtle.deriveBits({name:"PBKDF2",salt:un64(salt),iterations,hash:"SHA-256"},key,256));
}
export async function setIdentity(env,email,password){
  if(typeof email!=="string"||email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.trim()!==email)err("Informe um e-mail válido");
  if(typeof password!=="string"||password.length<12||password.length>128)err("Senha precisa conter 12 a 128 caracteres");
  const salt=randomString(24),iterations=310000;
  const digest=await pbkdf2(password,salt,iterations);
  await env.DB.prepare("INSERT INTO admin_identity(id,email,salt,password_hash,iterations,updated) VALUES (1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET email=excluded.email,salt=excluded.salt,password_hash=excluded.password_hash,iterations=excluded.iterations,updated=excluded.updated").bind(email.toLowerCase(),salt,digest,iterations,Math.floor(Date.now()/1000)).run();
  return{ok:true,email:email.toLowerCase()};
}
export async function checkIdentity(env,email,password){
  if(typeof email!=="string"||typeof password!=="string"||password.length>256)return false;
  const row=await env.DB.prepare("SELECT email,salt,password_hash,iterations FROM admin_identity WHERE id=1").first();
  if(!row||email.trim().toLowerCase()!==row.email)return false;
  const val=await pbkdf2(password,row.salt,row.iterations);
  const a=un64(val),b=un64(row.password_hash);return equal(a,b);
}
