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

## Siguiente fase (Nivel 2, no implementado)

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
