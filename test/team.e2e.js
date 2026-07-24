'use strict';
// E2E Fase2: equipo + roles + vault compartido zero-knowledge.
// 1) El PRIMER registro se vuelve admin.
// 2) Admin crea un miembro 'editor' con su propia contrasena.
// 3) Admin sube org vault cifrado con clave derivada de fraseDeEquipo+orgSalt.
// 4) El miembro (editor) baja el org vault y lo descifra (server no vio la frase).
// 5) Un 'viewer' NO puede escribir (403) pero sí leer.
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
function encryptVault(obj, k){ const iv = CryptoJS.lib.WordArray.random(16); return iv.toString() + ':' + CryptoJS.AES.encrypt(JSON.stringify(obj), k, { iv }).toString(); }
function decryptVault(p, k){ const [iv, ct] = p.split(':'); return JSON.parse(CryptoJS.AES.decrypt(ct, k, { iv: CryptoJS.enc.Hex.parse(iv) }).toString(CryptoJS.enc.Utf8)); }
function api(method, path, body, cookie){
  return new Promise((res) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host:'127.0.0.1', port: PORT, path, method,
      headers: Object.assign({ 'Content-Type':'application/json' }, cookie?{Cookie:cookie}:{}, data?{'Content-Length':Buffer.byteLength(data)}:{}) },
      (resp) => { let out=''; resp.on('data',c=>out+=c); resp.on('end',()=>{ let p=null; try{p=out?JSON.parse(out):null;}catch(_){} res({ status:resp.statusCode, setCookie:resp.headers['set-cookie'], body:p }); }); });
    if(data) r.write(data); r.end();
  });
}
const PORT = 3481;
const assert = (n, c) => { console.log((c?'OK  ':'FAIL')+' '+n); if(!c) process.exitCode = 1; };

(async () => {
  const ADMIN_PW = 'AdminFuerte123!';
  const EMAIL_ADMIN = 'admin' + Date.now() + '@equ.com';
  // 1) primer registro => admin
  const regA = await api('POST','/api/register',{ email:EMAIL_ADMIN, password:ADMIN_PW });
  assert('registro admin 200', regA.status===200 && regA.body.ok);
  assert('PRIMER usuario es admin', regA.body.role === 'admin');
  const cookieA = regA.setCookie && regA.setCookie[0].split(';')[0];

  // 2) admin crea miembro editor
  const EMAIL_ED = 'editor' + Date.now() + '@equ.com';
  const ED_PW = 'EditorFuerte123!';
  const mk = await api('POST','/api/team',{ email:EMAIL_ED, password:ED_PW, role:'editor' }, cookieA);
  assert('admin crea editor 200', mk.status===200 && mk.body.ok && mk.body.role==='editor');

  // 3) admin sube org vault cifrado (frase de equipo + orgSalt del server)
  const orgMeta = await api('GET','/api/org/vault/meta',null,cookieA);
  assert('GET org meta 200', orgMeta.status===200 && orgMeta.body.orgSalt);
  const orgSalt = orgMeta.body.orgSalt;
  const fraseEquipo = 'FraseSecretaDelEquipo987!';   // compartida por canal aparte
  const orgKey = deriveKey(fraseEquipo, orgSalt);
  const orgVault = { credentials:[{ id:'s1', site:'ClienteA', user:'a', password:'claveA', updatedAt:Date.now() }] };
  const orgEnc = encryptVault(orgVault, orgKey);
  const putD = await api('PUT','/api/org/vault/data',{ value: orgEnc }, cookieA);
  assert('admin sube org vault 200', putD.status===200 && putD.body.ok);

  // 4) editor (mismo equipo, conoce frase) baja y descifra
  const loginED = await api('POST','/api/login',{ email:EMAIL_ED, password:ED_PW, salt:'00', verifier:'x' });
  assert('editor login 200', loginED.status===200 && loginED.body.role==='editor');
  const cookieED = loginED.setCookie && loginED.setCookie[0].split(';')[0];
  const gMetaED = await api('GET','/api/org/vault/meta',null,cookieED);
  const gDataED = await api('GET','/api/org/vault/data',null,cookieED);
  assert('editor lee org meta 200', gMetaED.status===200 && gMetaED.body.orgSalt===orgSalt);
  assert('editor lee org data 200', gDataED.status===200 && gDataED.body.value===orgEnc);
  let decED; try { decED = decryptVault(gDataED.body.value, deriveKey(fraseEquipo, gMetaED.body.orgSalt)); } catch(e){ decED=null; }
  assert('editor descifra org vault (server no vio frase)', decED && decED.credentials[0].site==='ClienteA' && decED.credentials[0].password==='claveA');

  // 5) viewer: se crea y NO puede escribir (403) pero sí leer
  const EMAIL_VW = 'viewer' + Date.now() + '@equ.com';
  const VW_PW = 'ViewerFuerte123!';
  await api('POST','/api/team',{ email:EMAIL_VW, password:VW_PW, role:'viewer' }, cookieA);
  const loginVW = await api('POST','/api/login',{ email:EMAIL_VW, password:VW_PW, salt:'00', verifier:'x' });
  const cookieVW = loginVW.setCookie && loginVW.setCookie[0].split(';')[0];
  const wVW = await api('PUT','/api/org/vault/data',{ value:'x' }, cookieVW);
  assert('viewer NO puede escribir (403)', wVW.status===403);
  const rVW = await api('GET','/api/org/vault/data',null,cookieVW);
  assert('viewer SÍ puede leer (200)', rVW.status===200 && rVW.body.value===orgEnc);

  // 6) member no-admin NO puede listar equipo (403)
  const listTeam = await api('GET','/api/team',null,cookieED);
  assert('editor NO lista equipo (403)', listTeam.status===403);
  const listTeamA = await api('GET','/api/team',null,cookieA);
  assert('admin SÍ lista equipo (200)', listTeamA.status===200 && Array.isArray(listTeamA.body.members) && listTeamA.body.members.length>=3);

  console.log(process.exitCode ? 'VERIFICACION: FAIL' : 'VERIFICACION: PASS');
})();
