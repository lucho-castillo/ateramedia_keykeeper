'use strict';
// E2E real del flujo push/pull NUEVO contra el backend (server.js).
// Usa CryptoJS del vendor (el del navegador) para cifrar/descifrar.
const http = require('http');
const fs = require('fs');
const vm = require('vm');
const cryptoMod = require('crypto');

const cryptoJsSrc = fs.readFileSync('public/vendor/crypto-js.min.js', 'utf8');
const sandbox = { window: {}, self: {}, console, setTimeout, clearTimeout, Buffer, crypto: cryptoMod, module: undefined, exports: undefined };
sandbox.self = sandbox.window;
vm.createContext(sandbox);
vm.runInContext(cryptoJsSrc, sandbox);
const CryptoJS = sandbox.window.CryptoJS || sandbox.CryptoJS || sandbox.window.crypto;

function deriveKey(pw, salt){ return CryptoJS.PBKDF2(pw, salt, { keySize: 256/32, iterations: 120000 }); }
function encryptVault(obj, key){ const t = JSON.stringify(obj); return CryptoJS.AES.encrypt(t, key).toString(); }
function decryptVault(ct, key){ try { const b = CryptoJS.AES.decrypt(ct, key); return JSON.parse(b.toString(CryptoJS.enc.Utf8)); } catch(e){ throw e; } }
function apiJSON(method, path, body, cookie){
  return new Promise((res) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host:'127.0.0.1', port: PORT, path, method,
      headers: Object.assign({ 'Content-Type':'application/json' }, cookie?{Cookie:cookie}:{}, data?{'Content-Length':Buffer.byteLength(data)}:{}) },
      (resp) => { let out=''; resp.on('data',c=>out+=c); resp.on('end',()=>{
        let parsed=null; try{ parsed = out?JSON.parse(out):null; }catch(_){}
        res({ status: resp.statusCode, setCookie: resp.headers['set-cookie'], body: parsed }); }); });
    if(data) r.write(data); r.end();
  });
}

const PORT = 3483;
const assert = (name, cond) => { console.log((cond?'OK  ':'FAIL')+' '+name); if(!cond) process.exitCode = 1; };

(async () => {
  const pw = 'Password123';
  const salt = 'deadbeefsalt1234';
  const verifier = 'abc123verifier';
  const vaultEnc = 'iv:ciphertext_simulado_base64==';

  // register (body nuevo del frontend)
  const reg = await apiJSON('POST','/api/register',{ email:'pushpull@test.com', password:pw, salt, verifier, vault: vaultEnc });
  assert('register 200', reg.status===200 && reg.ok!==false);
  const cookie = reg.setCookie && reg.setCookie[0].split(';')[0];

  // push meta + data
  const rMeta = await apiJSON('PUT','/api/vault/meta',{ value: JSON.stringify({salt, verifier}) }, cookie);
  assert('PUT /api/vault/meta 200', rMeta.status===200 && rMeta.body.ok===true);
  const rData = await apiJSON('PUT','/api/vault/data',{ value: vaultEnc }, cookie);
  assert('PUT /api/vault/data 200', rData.status===200 && rData.body.ok===true);

  // pull meta + data
  const gMeta = await apiJSON('GET','/api/vault/meta',null,cookie);
  const gData = await apiJSON('GET','/api/vault/data',null,cookie);
  assert('GET /api/vault/meta 200', gMeta.status===200);
  assert('GET /api/vault/data 200', gData.status===200);
  const m = JSON.parse(gMeta.body.value);
  assert('meta trae salt', m.salt===salt);
  const remote = gData.body.value;
  assert('vault bajado == subido (integro)', remote===vaultEnc);

  console.log(process.exitCode ? 'VERIFICACION: FAIL' : 'VERIFICACION: PASS');
})();
