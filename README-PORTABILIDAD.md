# Portabilidad: trabajar desde otro equipo

Este repo es el backend **Supreme Key** (Node + Express + node:sqlite) que sirve
el frontend PWA **ATERA KEYMAKER**. Todo vive en la **RAÍZ** del repo (no hay
subcarpeta `server/` que valga — la que ves es basura de una estructura vieja
e ignorada por `.gitignore`).

## Requisitos (cualquier equipo)
- **Node >= 22** (usa `node:sqlite` nativo; no requiere compilación de binarios).
  Verifica con `node -v`.
- Git.

## Clonar y arrancar en local
```bash
git clone https://github.com/lucho-castillo/ateramedia_keykeeper.git
cd ateramedia_keykeeper
npm install
npm start
# abre http://localhost:3000
```
La base de datos local se crea sola en `./supreme_key.db` (ignorada por git).
Para usar un volumen/disco persistente en hosting, define `DB_PATH`.

## Variables de entorno
| Variable | Por defecto | Uso |
|----------|-------------|-----|
| `PORT` | `3000` | Puerto del servidor |
| `DB_PATH` | `./supreme_key.db` | Ruta de la base SQLite (en Railway: `/data/supreme_key.db`) |

En Railway ya están configuradas vía `railway.json` (builder nixpacks, sin
rootDir) + el Volume `/data`. Solo conecta el repo y despliega.

## Multi-dispositivo (sincronización entre equipos/celulares)
El frontend llama a `/api/...` con **rutas relativas y mismo origen** (sin
host hardcodeado), así que funciona igual en `localhost:3000`, en el dominio de
Railway o en cualquier otro equipo que apunte al mismo backend. Para sincronizar
entre dispositivos: crea la cuenta en la nube desde un equipo y usa el mismo
correo + contraseña de cuenta en los demás. El vault viaja **cifrado**; la clave
maestra nunca sale del dispositivo.

## Notas de deploy
- No Uses `rootDir=server`: Nixpacks no copiaba el `package-lock.json` y el
  build fallaba (`npm ci` sin lockfile). Por eso el código está en la raíz.
- El service worker (`public/service-worker.js`) cachea el app shell. Al cambiar
  el `CACHE_NAME` (p.ej. `v8`→`v9`) se fuerza el refresh del `index.html` en
  clientes ya instalados (importante en iOS/PWA).
- Dominio bueno de producción: `ateramediakeykeeper-production-v1.up.railway.app`
  (el `...-production.up.railway.app` sin `-v1` está muerto).
