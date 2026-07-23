# Sincronización en la nube — AteraMedia Passwords Manager

Este documento explica paso a paso cómo usar la **sincronización en la nube** del
gestor de contraseñas AteraMedia para tener tus credenciales disponibles en
varios dispositivos (PC, celular, tablet) sin enviar jamás tu clave maestra al servidor.

---

## 1. Concepto clave (zero-knowledge)

El servidor **nunca ve tus contraseñas ni tu clave maestra**. Funciona así:

- En tu dispositivo derivas una **clave del vault** a partir de tu clave maestra
  (PBKDF2, 120.000 iteraciones) y cifras todo el vault con AES-256.
- El servidor solo guarda ese vault **ya cifrado** (un bloque opaco `iv:ciphertext`)
  más un pequeño `meta` con el `salt` y un `verifier`. No puede leerlo.
- Tu **clave maestra nunca sale del dispositivo**. Si la olvidas, ni el servidor
  puede recuperar tus datos.

Por eso hay **dos contraseñas distintas**:

| Contraseña | Para qué sirve | ¿Viaja al servidor? |
|---|---|---|
| **Clave maestra del vault** | Cifra/descifra tus credenciales en el dispositivo. | NO (solo se usa localmente) |
| **Contraseña de cuenta (nube)** | Te identifica en el servidor para subir/bajar tu vault cifrado. | SÍ (hasheada con scrypt en el servidor) |

> Tip: pueden ser iguales si quieres, pero lo recomendable es que sean distintas.
> La contraseña de cuenta NO descifra nada; solo te da acceso a tu copia cifrada.

---

## 2. Primer uso en un dispositivo

1. Abre la app (URL de Railway o `index.html` local) y crea tu **clave maestra del vault**
   en la pantalla inicial. Esta es la que cifra tus credenciales.
2. Crea una o varias credenciales (botón **+ Nueva credencial**).
3. Ve a **Ajustes → Sincronizar entre dispositivos (nube)**.
4. En el bloque "Cuenta", escribe:
   - **Correo**: tu email.
   - **Contraseña de cuenta (nube)**: una contraseña para tu cuenta en el servidor
     (mínimo 8 caracteres).
5. Pulsa **Crear cuenta**.
   - Se registra la cuenta en el servidor y, de inmediato, se **sube tu vault cifrado**.
   - Verás el mensaje "Cuenta creada en la nube" y "Vault subido a la nube ✓".

¡Listo! Tu vault ya está respaldado y cifrado en el servidor.

---

## 3. Usarlo en un segundo dispositivo

1. Abre la app en el otro dispositivo y crea tu **clave maestra del vault**
   (debe ser **la misma** que usaste en el primer dispositivo, si quieres recuperar
   las credenciales existentes).
2. Ve a **Ajustes → Sincronizar entre dispositivos (nube)**.
3. Escribe el mismo **correo** y tu **contraseña de cuenta**, pulsa **Iniciar sesión**.
4. Al entrar, la app **baja automáticamente** el vault de la nube y lo fusiona con
   lo que haya localmente (conservando lo más reciente por credencial).
5. Verás "Nube bajada ✓ (N nuevas, M actualizadas)".

A partir de ahí, ambos dispositivos comparten el mismo vault cifrado.

---

## 4. Subir y bajar manualmente

En la sección de nube (una vez con sesión iniciada) hay dos botones:

- **Subir vault a la nube ↑**: sobrescribe la copia del servidor con el vault actual
  de este dispositivo. Úsalo cuando hayas añadido/editado credenciales aquí y quieras
  propagarlos.
- **Bajar vault de la nube ↓**: trae la copia del servidor y la **fusiona** con la
  local (last-write-wins por credencial: si la misma credencial cambió en ambos lados,
  se queda con la versión más reciente).

Recomendación de flujo:
- Antes de trabajar en un dispositivo: pulsa **Bajar** para traer los últimos cambios.
- Después de trabajar: pulsa **Subir** para guardarlos.

---

## 5. Cerrar sesión

Pulsa **Cerrar sesión** en la sección de nube. Esto borra la cookie de sesión en el
servidor (no borra tus credenciales locales ni la copia cifrada en la nube). Para
volver a sincronizar, solo inicias sesión de nuevo.

---

## 6. Respaldo manual (método alternativo, sin servidor)

Si no quieres usar la nube, en la misma pantalla de Ajustes está la sección
**Respaldo manual (archivo .skvault)**:

- **Exportar backup (.skvault)**: descarga un archivo cifrado.
- **Importar y fusionar**: lee un `.skvault` (por archivo o pegando el contenido manualmente,
  útil en iPhone) y lo fusiona.

Esto es útil para pasar el vault entre dispositivos por correo, cable o AirDrop sin
necesidad del servidor.

---

## 7. Seguridad

- **Cifrado**: AES-256, clave derivada con PBKDF2 (120.000 iteraciones) desde tu clave maestra.
- **Transporte**: la app se sirve por HTTPS; la cookie de sesión es `HttpOnly`,
  `Secure` y `SameSite=Lax`.
- **En el servidor solo hay ciphertext**: si alguien accede a la base de datos, solo
  ve basura cifrada. Sin tu clave maestra, es ilegible.
- **Rate limiting**: el login está limitado a 10 intentos por IP cada 15 min y el
  registro a 5 cuentas por IP por hora, para frenar ataques de fuerza bruta.
- **Olvido de clave maestra**: no hay recuperación. Quien olvida la clave maestra del
  vault no puede descifrar ni siquiera con la contraseña de cuenta. Guárdala en un
  lugar seguro.

---

## 8. Preguntas frecuentes

**¿Puedo usar la misma cuenta en 5 dispositivos?**
Sí. Inicia sesión con el mismo correo + contraseña de cuenta en cada uno y pulsa
"Bajar" para sincronizar.

**¿Qué pasa si edito en el celular y luego en la PC sin sincronizar?**
Al hacer "Bajar" en uno y "Subir" en el otro, el merge conserva la versión más reciente
de cada credencial (por `updatedAt`). Si editaste la *misma* credencial en ambos, gana
la más reciente; las demás se suman.

**¿La contraseña de cuenta descifra mis contraseñas?**
No. Solo te autentica contra el servidor. El descifrado lo hace tu clave maestra del
vault, localmente.

**¿Dónde vive el vault en el servidor?**
En una base SQLite (Railway: `/data/supreme_key.db`, en un volumen persistente). Solo
contiene el vault cifrado y el `meta` (salt + verifier), nunca en texto plano.

**¿Y si borro la app del celular?**
Tus credenciales siguen en el servidor (cifradas). Reinstala, inicia sesión y pulsa
"Bajar". Lo que había en el dispositivo se pierde, no lo de la nube.
