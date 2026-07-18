# Supreme Key — Servidor (Nivel 1)

Backend mínimo para sincronizar el vault de Supreme Key entre equipos.
El servidor **nunca ve las contraseñas en claro**: solo guarda el vault
cifrado (zero-knowledge). La criptografía sigue ocurriendo en el navegador.

## Arranque

```bash
cd D:\supreme_key\server
npm install        # solo la primera vez (instala express)
npm start          # o: node server.js
```

Abre en el navegador: **http://localhost:3000**

Para usar otro puerto: `PORT=8080 npm start`

## Cómo funciona

1. **Cuenta** (`/api/register`, `/api/login`): identifica al usuario en el
   servidor. La contraseña de cuenta se hashea con **scrypt** (nunca en claro).
   El servidor devuelve una cookie de sesión `httpOnly` + `SameSite=Strict`.
2. **Vault** (`/api/vault/meta`, `/api/vault/data`): el frontend sube el vault
   ya cifrado con AES-256 + PBKDF2 (clave maestra = solo local). El servidor
   guarda el texto cifrado opaco en SQLite. No puede leerlo.
3. Al abrir desde otro equipo: login con la misma cuenta → se descarga el
   blob cifrado → se descifra con tu clave maestra. **Ya no hace falta
   exportar el archivo .vault.**

## Base de datos

SQLite nativo de Node (`node:sqlite`, requiere Node >= 22).
Un solo archivo: `server/supreme_key.db`.

Para respaldar: copia ese archivo. Para borrar todo: elimínalo (se recrea
vacío al volver a registrar).

## Seguridad — lee esto antes de exponerlo

- **Solo para red local / pruebas.** En `localhost` va por HTTP; la contraseña
  de cuenta viaja en claro. Para acceso por internet, ponlo detrás de
  **Caddy o nginx con TLS** (Let's Encrypt, gratis). Obligatorio.
- El servidor no tiene límite de intentos de login (rate limiting) todavía.
- `vault-meta` guarda el `verifier` (SHA-256 de la clave derivada) en claro.
  Con acceso a la BD, alguien podría atacar la clave maestra por fuerza bruta.
  Por eso el LEEME recomienda subir PBKDF2 a 600k iteraciones.
- Concurrencia: el vault es un blob único (last-write-wins). Si editas en dos
  equipos a la vez, gana el último guardado.

## Despliegue en Railway (Opción 1 — recomendada)

Railway corre Node + SQLite y te da **HTTPS automático**. El repo ya trae
`railway.json` y el server respeta `PORT` y `DB_PATH`.

1. Entra a https://railway.app y crea una cuenta (puedes usar GitHub).
2. "New Project" → "Deploy from GitHub repo" → elige
   **lucho-castillo/ateramedia_keykeeper**.
3. Railway detecta `package.json` y usa `npm start` (definido en railway.json).
4. En la pestaña del servicio → **Variables**, agrega:
     - `PORT` = 3000  (Railway lo sobreescribe con el suyo, pero definirlo evita sorpresas)
     - `DB_PATH` = /data/supreme_key.db  (ruta DENTRO del Volume persistente)
       IMPORTANTE: primero crea un **Volume** en "Settings → Volumes" montado
       en `/data`, si no la DB se borra en cada reinicio.
5. En "Settings → Domains" Railway te da una URL https
   (ej. https://ateramedia-keykeeper.up.railway.app). ¡Listo, ya es website!
6. Abre la URL, crea tu cuenta y tu clave maestra.

Notas:
- El servidor ya usa `app.set('trust proxy', 1)` para funcionar detrás del
  proxy de Railway.
- La primera vez crea la BD en `DB_PATH`. Si no usas Volume, los datos no
  persisten entre reinicios del deploy.
- Para producción: usa PBKDF2 a 600.000 iteraciones (ya configurado en el
  frontend) y el rate limiting en `/api/login` ya está activo (máx 10
  intentos / IP / 15 min; 5 registros / IP / hora). Sube esos límites si
  tu equipo es grande.

## Despliegue local (pruebas)

```bash
cd D:\supreme_key\server
npm install
npm start
```
Abre http://localhost:3000

## Seguridad — lee esto antes de exponerlo

Cifrado por campo + usuarios + compartir grupos entre personas distintas +
edición concurrente por registro + HTTPS.

## Endpoints

| Método | Ruta                | Auth | Descripción                    |
|--------|---------------------|------|--------------------------------|
| POST   | /api/register       | no   | Crea cuenta                    |
| POST   | /api/login          | no   | Inicia sesión (cookie)         |
| POST   | /api/logout         | sí   | Cierra sesión                  |
| GET    | /api/me             | sí   | Devuelve el email de la cuenta |
| GET    | /api/vault/meta     | sí   | Lee meta del vault (cifrado)   |
| PUT    | /api/vault/meta     | sí   | Guarda meta del vault          |
| GET    | /api/vault/data     | sí   | Lee vault (cifrado)            |
| PUT    | /api/vault/data     | sí   | Guarda vault (cifrado)         |
| GET    | /index.html, /vendor, /icons, /manifest.json | no | Sirve el frontend (mismo origen) |
