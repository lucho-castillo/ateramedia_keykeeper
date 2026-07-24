/*
 * Supreme Key — Servidor Nivel 1 (blob sync + zero-knowledge)
 * -----------------------------------------------------------
 * - Auth de CUENTA (email + password) con scrypt (node:crypto).
 * - El vault se guarda como texto cifrado opaco: el servidor NUNCA ve
 *   las credenciales en claro. Solo almacena ciphertext + meta (salt, verifier).
 * - Sirve tambien el frontend (index.html, vendor/, icons/) para evitar CORS
 *   y mantener cookies httpOnly same-origin.
 *
 * Requiere Node >= 22 (usa node:sqlite nativo).
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const ROOT = path.join(__dirname, 'public');             // frontend servido al public/
// En local la DB vive en la carpeta del server; en hostings (Railway/Render)
// se monta un disco persistente y se pasa su ruta en DB_PATH.
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'supreme_key.db');
const SESSION_TTL = 30 * 24 * 3600;                    // 30 dias

// Asegura que el directorio de la DB exista (los Volumes pueden no crearlo).
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

// ---------- Base de datos ----------
// ---------- Base de datos ----------
// Fase 2: roles de equipo (admin/editor/viewer/member) + vault compartido
// zero-knowledge (org_vault). El server solo guarda ciphertext + salt.
const ROLES = ['admin', 'editor', 'viewer', 'member'];
const db = new DatabaseSync(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT UNIQUE NOT NULL,
    pw_hash    TEXT NOT NULL,
    pw_salt    TEXT NOT NULL,
    vault_salt TEXT NOT NULL,   -- salt ESTABLE del vault en nube (reproducible entre dispositivos)
    role       TEXT NOT NULL DEFAULT 'member',  -- admin | editor | viewer | member
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS vault (
    user_id    INTEGER PRIMARY KEY,
    meta       TEXT,
    data       TEXT,
    version    INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS org_vault (
    id         INTEGER PRIMARY KEY CHECK (id = 1),  -- unico vault compartido del equipo
    org_salt   TEXT NOT NULL,   -- salt estable del vault compartido (reproducible por frase de equipo)
    meta       TEXT,
    data       TEXT,
    version    INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
  );
`);
// Asegura que exista la fila de org_vault (lazily, con un salt estable).
(function ensureOrgVault(){
  const row = db.prepare('SELECT id FROM org_vault WHERE id = 1').get();
  if (!row) db.prepare('INSERT INTO org_vault (id, org_salt, version, updated_at) VALUES (1, ?, 0, ?)').run(newSalt(), Date.now());
})();

// ---------- Helpers cripto ----------
function hashPassword(password, saltHex) {
  // scrypt: coste elevado, resistente a hardware
  return crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), 64).toString('hex');
}
function newSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function newToken() {
  return crypto.randomBytes(32).toString('hex');
}
function timingSafeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// ---------- Rate limiting (fuerza bruta en login/registro) ----------
// 10 intentos por IP cada 15 min en /api/login; 5 registros por IP/hora.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos. Espera 15 minutos e intentalo de nuevo.' }
});
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Has creado demasiadas cuentas. Intenta mas tarde.' }
});

// ---------- App ----------
const app = express();
app.set('trust proxy', 1);   // detras de proxy inverso (Railway/Render/Caddy)
app.use(express.json({ limit: '5mb' }));

// CORS permisivo para /api (permite probar el frontend desde otro origen si hiciera falta)
app.use('/api', (req, res, next) => {
  const origin = req.headers.origin;
  if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---------- Sesion (cookie httpOnly) ----------
function getSessionToken(req) {
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/sk_session=([a-f0-9]{64})/);
  return m ? m[1] : null;
}
function setSessionCookie(res, token) {
  const attrs = [
    `sk_session=${token}`,
    'HttpOnly',
    'Path=/',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${SESSION_TTL}`
  ];
  res.setHeader('Set-Cookie', attrs.join('; '));
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'sk_session=; HttpOnly; Path=/; Secure; SameSite=Lax; Max-Age=0');
}
function currentUser(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  const row = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }
  const user = db.prepare('SELECT id, email, role FROM users WHERE id = ?').get(row.user_id);
  return user || null;
}
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'No autenticado' });
  req.user = user;
  next();
}

// ---------- Auth endpoints ----------
app.post('/api/register', registerLimiter, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({ error: 'Correo no valido' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'La contrasena de cuenta debe tener al menos 8 caracteres' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    return res.status(409).json({ error: 'Ese correo ya esta registrado' });
  }
  // El PRIMER usuario registrado se vuelve admin del equipo (define estructura/roles).
  const isFirst = db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 0;
  const role = isFirst ? 'admin' : 'member';
  const salt = newSalt();
  const hash = hashPassword(password, salt);
  const vaultSalt = newSalt();   // estable: define la clave del vault en la nube
  const info = db.prepare('INSERT INTO users (email, pw_hash, pw_salt, vault_salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(email, hash, salt, vaultSalt, role, Date.now());
  const userId = info.lastInsertRowid;
  // crea fila de vault vacia
  db.prepare('INSERT OR IGNORE INTO vault (user_id, meta, data, version, updated_at) VALUES (?, NULL, NULL, 0, ?)')
    .run(userId, Date.now());
  const token = newToken();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .run(token, userId, Date.now() + SESSION_TTL * 1000);
  setSessionCookie(res, token);
  res.json({ ok: true, email, vaultSalt, role });
});

app.post('/api/login', loginLimiter, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) {
    return res.status(401).json({ error: 'Correo o contrasena incorrectos' });
  }
  const hash = hashPassword(password, user.pw_salt);
  if (!timingSafeEqual(hash, user.pw_hash)) {
    return res.status(401).json({ error: 'Correo o contrasena incorrectos' });
  }
  // vault_salt estable: si la cuenta es vieja (sin columna), lo generamos una
  // vez y lo guardamos; así la clave del vault en nube es reproducible.
  let vaultSalt = user.vault_salt;
  if (!vaultSalt) {
    vaultSalt = newSalt();
    db.prepare('UPDATE users SET vault_salt = ? WHERE id = ?').run(vaultSalt, user.id);
  }
  // Lazy-promote: si la BD no tiene NINGUN admin (p.ej. cuenta creada antes de
  // Fase2), el primer usuario que inicia sesion se vuelve admin del equipo.
  let role = user.role;
  if (role !== 'admin') {
    const anyAdmin = db.prepare("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").get();
    if (!anyAdmin) {
      role = 'admin';
      db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, user.id);
    }
  }
  const token = newToken();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .run(token, user.id, Date.now() + SESSION_TTL * 1000);
  setSessionCookie(res, token);
  res.json({ ok: true, email: user.email, vaultSalt, role });
});

app.post('/api/logout', requireAuth, (req, res) => {
  const token = getSessionToken(req);
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'No autenticado' });
  // Lazy-promote: si no hay admin en la BD, este usuario lo es.
  let role = user.role;
  if (role !== 'admin') {
    const anyAdmin = db.prepare("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").get();
    if (!anyAdmin) {
      role = 'admin';
      db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, user.id);
    }
  }
  res.json({ email: user.email, role });
});

// ---------- Vault endpoints (zero-knowledge: solo ciphertext) ----------
// meta: {salt, verifier, createdAt, updatedAt}  (string JSON del cliente)
// data: blob cifrado del vault (string "iv:ct")
app.get('/api/vault/meta', requireAuth, (req, res) => {
  const row = db.prepare('SELECT meta, version FROM vault WHERE user_id = ?').get(req.user.id);
  res.json({ value: row && row.meta ? row.meta : null, version: row ? row.version : 0 });
});
app.get('/api/vault/data', requireAuth, (req, res) => {
  const row = db.prepare('SELECT data, version FROM vault WHERE user_id = ?').get(req.user.id);
  res.json({ value: row && row.data ? row.data : null, version: row ? row.version : 0 });
});
app.put('/api/vault/meta', requireAuth, (req, res) => {
  const value = req.body && typeof req.body.value === 'string' ? req.body.value : null;
  db.prepare('INSERT INTO vault (user_id, meta, version, updated_at) VALUES (?, ?, 1, ?) ' +
    'ON CONFLICT(user_id) DO UPDATE SET meta = excluded.meta, version = version + 1, updated_at = excluded.updated_at')
    .run(req.user.id, value, Date.now());
  const row = db.prepare('SELECT version FROM vault WHERE user_id = ?').get(req.user.id);
  res.json({ ok: true, version: row.version });
});
app.put('/api/vault/data', requireAuth, (req, res) => {
  const value = req.body && typeof req.body.value === 'string' ? req.body.value : null;
  db.prepare('INSERT INTO vault (user_id, data, version, updated_at) VALUES (?, ?, 1, ?) ' +
    'ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, version = version + 1, updated_at = excluded.updated_at')
    .run(req.user.id, value, Date.now());
  const row = db.prepare('SELECT version FROM vault WHERE user_id = ?').get(req.user.id);
  res.json({ ok: true, version: row.version });
});

// ---------- Equipo / roles (Fase 2) ----------
// Solo el admin gestiona usuarios. Roles: admin | editor | viewer | member.
function requireRole(...roles) {
  return (req, res, next) => {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ error: 'No autenticado' });
    if (!roles.includes(user.role)) return res.status(403).json({ error: 'No tienes permiso para esto' });
    req.user = user;
    next();
  };
}

// Lista de miembros (solo admin) — NUNCA expone hashes ni vaults.
app.get('/api/team', requireRole('admin'), (req, res) => {
  const rows = db.prepare('SELECT id, email, role, created_at FROM users ORDER BY created_at').all();
  res.json({ members: rows });
});

// Admin crea un miembro con rol (el miembro luego inicia sesion con su propia contrasena).
app.post('/api/team', requireRole('admin'), (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const role = String(req.body.role || 'member');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Correo no valido' });
  if (password.length < 8) return res.status(400).json({ error: 'La contrasena debe tener al menos 8 caracteres' });
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Rol no valido' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return res.status(409).json({ error: 'Ese correo ya esta registrado' });
  const salt = newSalt();
  const hash = hashPassword(password, salt);
  const vaultSalt = newSalt();
  db.prepare('INSERT INTO users (email, pw_hash, pw_salt, vault_salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(email, hash, salt, vaultSalt, role, Date.now());
  res.json({ ok: true, email, role });
});

// Admin cambia el rol de un miembro.
app.put('/api/team/:id/role', requireRole('admin'), (req, res) => {
  const id = Number(req.params.id);
  const role = String(req.body.role || '');
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Rol no valido' });
  if (req.user.id === id) return res.status(400).json({ error: 'No puedes cambiar tu propio rol' });
  const info = db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
  if (info.changes === 0) return res.status(404).json({ error: 'Miembro no encontrado' });
  res.json({ ok: true, role });
});

// ---------- Vault compartido del equipo (zero-knowledge) ----------
// El blob se cifra en el CLIENTE con una clave derivada de una "frase de equipo"
// + org_salt (estable, publico). El server SOLO guarda ciphertext + meta.
// Permisos: editor/admin escriben; viewer/member/editor/admin leen.
app.get('/api/org/vault/meta', requireAuth, (req, res) => {
  const row = db.prepare('SELECT org_salt, meta, version FROM org_vault WHERE id = 1').get();
  res.json({ orgSalt: row.org_salt, value: row.meta, version: row.version });
});
app.get('/api/org/vault/data', requireAuth, (req, res) => {
  const row = db.prepare('SELECT data, version FROM org_vault WHERE id = 1').get();
  res.json({ value: row.data, version: row.version });
});
app.put('/api/org/vault/meta', requireRole('admin', 'editor'), (req, res) => {
  const value = req.body && typeof req.body.value === 'string' ? req.body.value : null;
  db.prepare('UPDATE org_vault SET meta = ?, version = version + 1, updated_at = ? WHERE id = 1').run(value, Date.now());
  const row = db.prepare('SELECT version FROM org_vault WHERE id = 1').get();
  res.json({ ok: true, version: row.version });
});
app.put('/api/org/vault/data', requireRole('admin', 'editor'), (req, res) => {
  const value = req.body && typeof req.body.value === 'string' ? req.body.value : null;
  db.prepare('UPDATE org_vault SET data = ?, version = version + 1, updated_at = ? WHERE id = 1').run(value, Date.now());
  const row = db.prepare('SELECT version FROM org_vault WHERE id = 1').get();
  res.json({ ok: true, version: row.version });
});

// ---------- Sirve el frontend (mismo origen => cookies httpOnly sin CORS) ----------
app.use(express.static(ROOT, {
  setHeaders: (res, filePath) => {
    // no cachear el html para siempre (así ves cambios al recargar)
    if (filePath.endsWith('index.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));

app.listen(PORT, () => {
  const base = process.env.RAILWAY_PUBLIC_DOMAIN
    ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
    : `http://localhost:${PORT}`;
  console.log(`Supreme Key server en ${base}`);
  console.log(`BD: ${DB_PATH}`);
});
