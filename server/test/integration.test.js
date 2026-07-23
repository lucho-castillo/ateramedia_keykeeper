'use strict';
// Test de INTEGRACIÓN REAL contra el backend existente (server.js clonado),
// usando CryptoJS del vendor (el del navegador) y el protocolo /api/vault/meta|data.
const http = require('http');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PORT = process.env.PORT || 3125;
process.env.PORT = String(PORT);
process.env.DB_PATH = path.join(__dirname, '..', 'it-test.db');
require('../server');

// CryptoJS en sandbox con crypto nativo.
const cryptoMod = require('crypto');
const sandbox = { window: {}, self: {}, crypto: cryptoMod, globalThis: {}, console };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'public', 'vendor', 'crypto-js.min.js'), 'utf8'), sandbox);
const CryptoJS = sandbox.window.CryptoJS || sandbox.CryptoJS || sandbox.window;

function deriveKey(password, saltHex) { return CryptoJS.PBKDF2(password, CryptoJS.enc.Hex.parse(saltHex), { keySize: 256 / 32, iterations: 120000 }); }
function verifierOf(k) { return CryptoJS.SHA256(k.toString()).toString(); }
function encryptVault(obj, k) { const iv = CryptoJS.lib.WordArray.random(16); return iv.toString() + ':' + CryptoJS.AES.encrypt(JSON.stringify(obj), k, { iv }).toString(); }
function decryptVault(p, k) { const [iv, ct] = p.split(':'); return JSON.parse(CryptoJS.AES.decrypt(ct, k, { iv: CryptoJS.enc.Hex.parse(iv) }).toString(CryptoJS.enc.Utf8)); }

function req(method, p, body, cookie) {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method, headers: {
      'Content-Type': 'application/json', ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}), ...(cookie ? { Cookie: cookie } : {}),
    } }, (res) => { let o = ''; res.on('data', (c) => o += c); res.on('end', () => { let d = null; try { d = JSON.parse(o); } catch (_) {} resolve({ ok: res.statusCode < 400, status: res.statusCode, body: d, cookie: res.headers['set-cookie'] ? res.headers['set-cookie'][0].split(';')[0] : null }); }); });
    r.on('error', (e) => resolve({ ok: false, error: e.message }));
    if (data) r.write(data); r.end();
  });
}

let fail = 0; const assert = (n, c) => { console.log((c ? 'OK  ' : 'FAIL') + ' ' + n); if (!c) fail++; };

(async () => {
  const EMAIL = 'it' + Date.now() + '@ej.com';
  const ACC_PW = 'CuentaFuerte123!';           // password de CUENTA (distinto de la clave maestra del vault)
  const MASTER = 'ClaveMaestraVault999!';       // clave maestra del vault
  const vSalt = CryptoJS.lib.WordArray.random(16).toString();
  const vKey = deriveKey(MASTER, vSalt);
  const vVerifier = verifierOf(vKey);
  const vault = { credentials: [{ id: 'a', site: 'GitHub', password: 'x', updatedAt: 100 }], groups: [{ id: 'g_general', name: 'General' }] };
  const dataBlob = encryptVault(vault, vKey);
  const meta = JSON.stringify({ salt: vSalt, verifier: vVerifier, updatedAt: Date.now() });

  // 1) registro de cuenta
  const reg = await req('POST', '/api/register', { email: EMAIL, password: ACC_PW });
  assert('registro de cuenta 200', reg.ok && reg.cookie);
  const cookie = reg.cookie;

  // 2) push meta + data
  const pm = await req('PUT', '/api/vault/meta', { value: meta }, cookie);
  const pd = await req('PUT', '/api/vault/data', { value: dataBlob }, cookie);
  assert('PUT meta 200', pm.ok);
  assert('PUT data 200', pd.ok);

  // 3) pull meta + data y descifrar con la clave maestra
  const gm = await req('GET', '/api/vault/meta', null, cookie);
  const gd = await req('GET', '/api/vault/data', null, cookie);
  assert('GET meta 200', gm.ok && gm.body.value === meta);
  assert('GET data 200', gd.ok && gd.body.value === dataBlob);
  const dec = decryptVault(gd.body.value, vKey);
  assert('vault descifrado con clave maestra == original', JSON.stringify(dec) === JSON.stringify(vault));

  // 4) login con otra sesión y pull
  const reg2 = await req('POST', '/api/login', { email: EMAIL, password: ACC_PW });
  assert('login cuenta 200', reg2.ok && reg2.cookie);
  const cookie2 = reg2.cookie;
  const gd2 = await req('GET', '/api/vault/data', null, cookie2);
  assert('segunda sesión ve el mismo vault cifrado', gd2.body.value === dataBlob);

  // 5) password de cuenta incorrecto denegado
  const bad = await req('POST', '/api/login', { email: EMAIL, password: 'mala' });
  assert('login cuenta incorrecta denegado 401', bad.status === 401);

  // 6) sin cookie denegado
  const noAuth = await req('GET', '/api/vault/data', null, null);
  assert('vault sin sesión denegado 401', noAuth.status === 401);

  console.log('\n' + (fail === 0 ? 'INTEGRACIÓN CON BACKEND REAL: TODOS OK' : fail + ' FALLOS'));
  process.exit(fail === 0 ? 0 : 1);
})();
