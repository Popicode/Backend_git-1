# Proposal: Enrolamiento MFA desde el primer login

## Why

El alta entregaba el secreto MFA al administrador y las cuentas sin secreto no podían
iniciar sesión. Además, la ruta genérica de JWT permitía eludir el segundo factor.
La persona debe configurar y confirmar su autenticador después de validar su contraseña.

## What Changes

- Login distingue enrolamiento y verificación mediante un desafío temporal, sin JWT.
- Setup entrega el secreto pendiente, URI y SVG local; confirm activa MFA y emite JWT.
- Verify solo admite cuentas confirmadas y desafíos de verificación.
- Desafíos con caducidad, nonce, límite de intentos y vínculo a contraseña/vigencia.
- Códigos estrictos, throttle y eliminación de la ruta JWT de contraseña sola.
- CRUD de usuarios sin secretos; estado de confirmación de solo lectura.
- Migración conserva usuarios heredados confirmados y helper compatible.
- Pruebas y documentación en español; frontend pendiente.

## Capabilities Affected

- `auth`: enrolamiento, verificación, emisión de JWT y administración del estado MFA.

## Impact

- Migración de base de datos: sí, estado y material pendiente de MFA.
- Cambios incompatibles de API: sí, alta sin secretos y eliminación de token por contraseña.
- Seguridad: JWT condicionado a TOTP; QR generado sin servicio externo.
- Estado: implementación integrada y revisada estáticamente, sin verificación ejecutable.
- Bloqueo: Python 3.12 inaccesible (Acceso denegado), ningún otro intérprete ejecutable y uv falló por red OS10013;
  qrcode==8.2 declarado pero no instalado. Instalación, checks, pruebas y migraciones pendientes.
