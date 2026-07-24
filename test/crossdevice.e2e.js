'use strict';
// E2E CRUZADO (Fase 1): dos "dispositivos" independientes que inician sesion
// con el MISMO correo + password de cuenta y deben descifrar el MISMO vault
// subido a la nube. Valida que la clave del vault en nube sea REPRODUCIBLE
// entre dispositivos (vault_salt estable del server), no aleatoria por login.
const http = require('http');
const fs = require('fs');
const vm = require('vm');
const cryptoMod = require('crypto');

const cryptoJsSrc = fs.readFileSync('public/vendor/crypto-js.min.js', 'utf8');
const sb = { window:{}, self:{}, crypto: cryptoMod, globalThis:{}, console };
sb.globalThis = sb;
vm.createContext(sb);
vm.runInContext(cryptoJsSrc, sb);
const CryptoJS = sb.window.CryptoJS || sb.CryptoJS || sb.window;
function deriveKey(pw, saltHex){ return CryptoJS.PBKDF2(pw, CryptoJS.enc.Hex.parse(saltHex), { keySize: 256/32, iterations: 120000 }); }
function verifierOf(k){ return CryptoJS.SHA256(k.toString()).toString(); }
function encryptVault(obj, k){ const iv = CryptoJS.lib.WordArray.random(16); return iv.toString() + ':' + CryptoJS.AES.encrypt(JSON.stringify(obj), k, { iv }).toString(); }
function decryptVault(p, k){ const [iv, ct] = p.split(':'); return JSON.parse(CryptoJS.AES.decrypt(ct, k, { iv: CryptoJS.enc.Hex.parse(iv) }).toString(CryptoJS.enc.Utf8)); }
function apiJSON(method, path, body, cookie){
  return new Promise((res) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host:'127.0.0.1', port: PORT, path, method,
      headers: Object.assign({ 'Content-Type':'application/json' }, cookie?{Cookie:cookie}:{}, data?{'Content-Length':Buffer.byteLength(data)}:{}) },
      (resp) => { let out=''; resp.on('data',c=>out+=c); resp.on('end',()=>{ let p=null; try{p=out?JSON.parse(out):null;}catch(_){} res({ status:resp.statusCode, setCookie:resp.headers['set-cookie'], body:p }); }); });
    if(data) r.write(data); r.end();
  });
}
const PORT = 3482;
const assert = (n, c) => { console.log((c?'OK  ':'FAIL')+' '+n); if(!c) process.exitCode = 1; };

(async () => {
  // Dispositivo A: crea cuenta, sube vault cifrado con la clave derivada de vault_salt
  const EMAIL = 'xdev' + Date.now() + '@ej.com';
  const ACC_PW = 'Password123';                 // password de CUENTA (misma en A y B)
  const reg = await apiJSON('POST','/api/register',{ email:EMAIL, password:ACC_PW });
  assert('register 200', reg.status===200 && reg.body.ok);
  const vaultSaltA = reg.body.vaultSalt;
  assert('server devuelve vault_salt estable', !!vaultSaltA);
  const keyA = deriveKey(ACC_PW, vaultSaltA);  // clave del vault en nube (A)
  assert('verifier A coincide con lo que envia el frontend', verifierOf(keyA) === verifierOf(keyA));
  const vault = { credentials:[{ id:'c1', site:'ClienteX', user:'u', password:'s3cr3t', updatedAt: Date.now() }], groups:[{id:'g1',name:'General'}] };
  const vaultEnc = encryptVault(vault, keyA);
  const cookieA = reg.setCookie && reg.setCookie[0].split(';')[0];
  const pm = await apiJSON('PUT','/api/vault/meta',{ value: JSON.stringify({ salt:vaultSaltA, verifier:verifierOf(keyA) }) }, cookieA);
  const pd = await apiJSON('PUT','/api/vault/data',{ value: vaultEnc }, cookieA);
  assert('PUT meta 200', pm.status===200 && pm.body.ok);
  assert('PUT data 200', pd.status===200 && pd.body.ok);

  // Dispositivo B: OTRO login independiente (misma cuenta) -> debe recibir el MISMO vault_salt
  const login = await apiJSON('POST','/api/login',{ email:EMAIL, password:ACC_PW, salt:'abcdef0123456789', verifier:'x' });
  assert('login B 200', login.status===200 && login.body.ok);
  assert('login B devuelve MISMO vault_salt que A', login.body.vaultSalt === vaultSaltA);
  const keyB = deriveKey(ACC_PW, login.body.vaultSalt);  // clave del vault en nube (B)
  assert('clave de vault reproducible entre dispositivos', keyB.toString() === keyA.toString());
  const cookieB = login.setCookie && login.setCookie[0].split(';')[0];
  const gData = await apiJSON('GET','/api/vault/data',null,cookieB);
  assert('GET data B 200', gData.status===200 && gData.body && gData.body.value);
  let dec;
  try { dec = decryptVault(gData.body.value, keyB); } catch(e){ dec = null; }
  assert('B descifra el MISMO vault que subio A', dec && dec.credentials && dec.credentials[0].site === 'ClienteX' && dec.credentials[0].password === 's3cr3t');

  console.log(process.exitCode ? 'VERIFICACION: FAIL' : 'VERIFICACION: PASS');
})();
