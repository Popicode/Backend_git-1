# Enrolamiento MFA del personal

El primer acceso de una cuenta nueva requiere contraseña y configuración de una
aplicación autenticadora TOTP. Crear una cuenta no entrega un secreto al administrador
ni crea una sesión. `mfa_confirmed` comienza en `false` y es de solo lectura en la API.

## Recorrido de la persona

1. El administrador crea la cuenta y comunica sus credenciales por el canal acordado.
2. La persona inicia sesión con usuario y contraseña. El servidor devuelve un desafío
   temporal y `mfa_setup_required: true`, sin tokens JWT.
3. Con ese desafío solicita la configuración. Escanea el SVG en su autenticador o
   introduce manualmente el secreto. El backend genera el QR con `qrcode.svg`;
   no envía el secreto a una API externa de imágenes.
4. Introduce el código de seis dígitos del autenticador como texto, conservando ceros
   iniciales. La confirmación correcta activa MFA y entrega `access`, `refresh` y `user`.
5. En accesos posteriores, el login devuelve `mfa_setup_required: false` y se utiliza
   `/api/auth/mfa/verify/`. No se muestra nuevamente la configuración del autenticador.

La integración de estas pantallas y transiciones en el frontend está pendiente.
El frontend deberá borrar el desafío y la configuración al terminar o abandonar el
flujo, gestionar los errores y solicitar nuevamente la contraseña si caduca el desafío.

## Contrato HTTP y ejemplos

Los valores entre `<...>` son marcadores ficticios: reemplazarlos localmente.
Los ejemplos usan sintaxis de shell compatible con curl; en PowerShell puede usarse
`curl.exe` adaptando las comillas. No guardar credenciales, desafíos, códigos ni tokens
reales en documentación, registros o capturas. Usar HTTPS fuera del desarrollo local.

```sh
curl -X POST https://backend.example/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"<USUARIO>","password":"<CONTRASEÑA>"}'
```

Respuesta de enrolamiento (HTTP 200):

```json
{"mfa_setup_required":true,"mfa_challenge":"<DESAFÍO_TEMPORAL>"}
```

Para una cuenta confirmada, el mismo formato contiene `mfa_setup_required: false`.
Ninguna de estas respuestas contiene `access` ni `refresh`.

```sh
curl -X POST https://backend.example/api/auth/mfa/setup/ \
  -H 'Content-Type: application/json' \
  -d '{"mfa_challenge":"<DESAFÍO_DE_ENROLAMIENTO>"}'
```

Respuesta HTTP 200 con `Cache-Control: no-store`:

```json
{
  "mfa_secret":"<SECRETO_TOTP>",
  "mfa_provisioning_uri":"<URI_OTPAUTH>",
  "qr_code_svg":"<SVG_GENERADO_POR_EL_BACKEND>"
}
```

```sh
curl -X POST https://backend.example/api/auth/mfa/confirm/ \
  -H 'Content-Type: application/json' \
  -d '{"mfa_challenge":"<DESAFÍO_DE_ENROLAMIENTO>","code":"<SEIS_DÍGITOS_ASCII>"}'

curl -X POST https://backend.example/api/auth/mfa/verify/ \
  -H 'Content-Type: application/json' \
  -d '{"mfa_challenge":"<DESAFÍO_DE_VERIFICACIÓN>","code":"<SEIS_DÍGITOS_ASCII>"}'
```

`code` debe ser una cadena de exactamente seis caracteres entre `0` y `9`, sin
espacios ni saltos de línea; no se admiten números JSON ni dígitos Unicode.
Ambos pasos finales devuelven HTTP 200 con esta forma (el usuario incluye otros
campos públicos, omitidos aquí):

```json
{"access":"<JWT_ACCESS>","refresh":"<JWT_REFRESH>","user":{"id":1,"username":"<USUARIO>","mfa_confirmed":true}}
```

La renovación conserva `POST /api/api/token/refresh/` con
`{"refresh":"<JWT_REFRESH>"}`. Se elimina `POST /api/api/token/`, que permitía obtener
JWT usando solamente contraseña.

## Límites y protección del secreto

Los desafíos duran 300 segundos desde su emisión. Se vinculan al usuario, a su
contraseña, a un nonce y al propósito de enrolamiento o verificación. Un nuevo login
invalida el desafío anterior. El éxito consume el nonce; repetir la solicitud no
emite otra sesión. Cinco códigos incorrectos agotan el desafío y exigen otro login.
Los endpoints de autenticación comparten el límite `auth` de 30 solicitudes por minuto
por cliente/IP; al excederlo devuelven HTTP 429 y `Retry-After`.

`DRF_NUM_PROXIES` tiene valor predeterminado `0`: acceso directo que utiliza la dirección
de conexión e ignora `X-Forwarded-For` para el throttle. Detrás de proxies inversos,
configurar el número real de proxies confiables, impedir el acceso directo al backend
y asegurar que el proxy controle la cabecera; no confiar en valores enviados por clientes.
Con varios workers o instancias se necesita una caché compartida para que el contador
de solicitudes sea común. Una caché local por proceso no proporciona ese límite global.

Login, setup, confirm y verify ignoran un Bearer inválido o caducado que el cliente
conserve: validan las credenciales propias del flujo. Las actualizaciones de usuarios,
del administrador y de su formulario de contraseña preservan el estado MFA concurrente;
un formulario abierto antes de la confirmación no debe restaurar el nonce consumido.
La protección concurrente mediante `select_for_update` necesita una base transaccional
con bloqueo de filas, como PostgreSQL, en producción. SQLite no implementa esos bloqueos;
las pruebas secuenciales locales no demuestran seguridad ante peticiones simultáneas.

No se puede verificar una sesión con un desafío de enrolamiento ni enrolar usando
uno de verificación. Los cambios de contraseña, la desactivación de la cuenta o
la pérdida de vigencia de una cuenta temporal invalidan el flujo pendiente.

El QR **contiene un secreto reutilizable**, no es un QR verdaderamente de un solo uso.
Quien conserve una copia puede generar códigos futuros. Lo que caduca y se consume
es el desafío que autoriza acceder a la configuración y completar este flujo.
Mientras ese desafío siga vigente, repetir setup devuelve el mismo secreto pendiente.
Ni el QR ni la URI ni el secreto deben almacenarse en caché o exponerse en el CRUD
de usuarios. `POST /api/users/` devuelve `mfa_confirmed: false` sin material MFA.

## Usuarios anteriores y administrador inicial

La migración `0002_user_mfa_enrollment` marca como confirmadas las cuentas que ya
tenían un secreto TOTP no vacío. Conservan su autenticador y pasan a verificación;
no se les exige escanear un nuevo QR. Las cuentas sin secreto quedan pendientes.
Si una cuenta ya tenía secreto pero su titular nunca recibió el QR, seguirá confirmada:
el secreto no se sobrescribe automáticamente. Necesita un procedimiento de recuperación
separado, todavía no implementado. Este cambio tampoco implementa envío automático de
correo, contraseñas temporales con cambio obligatorio ni endpoints de recuperación/reset MFA.
El helper `generate_mfa_secret` se conserva para compatibilidad con pruebas y
aprovisionamiento heredado, y marca la cuenta como confirmada; no forma parte del
alta normal de usuarios.

Después de instalar dependencias y aplicar migraciones, crear el primer administrador:

```powershell
.\venv\Scripts\python.exe manage.py createsuperuser
```

El permiso administrativo de la API requiere `role='ADMIN'` o `is_superuser=True`.
`createsuperuser` establece `is_superuser=True`; una cuenta creada por otros medios
necesita uno de esos permisos. El administrador nuevo también debe enrolar MFA en
su primer login por contraseña a la API. Ser superusuario no evita ese paso.
El administrador Django usa `UserAdmin`, permite gestionar rol y vigencia, muestra
`mfa_confirmed` solo como lectura y no expone ni permite editar secretos MFA.
Este flujo MFA corresponde a la API; no implica que el login de `/admin/` tenga TOTP.

## Verificación pendiente

Se añadieron pruebas de integración para el contrato, ocultación de secretos,
propósitos, replay, caducidad, códigos malformados, intentos, throttle, invalidez de
cuentas, administración y migración. Implementación integrada y revisada estáticamente;
ejecución, instalación y aplicación de migraciones pendientes. El venv antiguo apunta
a Python 3.12 cuya ruta devuelve «Acceso denegado» desde esta sesión. No se puede
confirmar que esté desinstalado; no se encontró otro intérprete accesible.
La instalación de Python 3.13 mediante uv falló por restricción de red OS10013.
Se intentaron la instalación con pip y `manage.py test`, pero ambos fallaron antes de
ejecutarse porque el intérprete no es accesible. `qrcode==8.2` figura en requirements.txt pero
no está instalado. No se ejecutaron pruebas, checks ni migraciones.

Restaurar Python y recrear un entorno funcional, o proporcionar su ruta para usarlo.
Después, ejecutar estos comandos con ese intérprete (se supone un venv reparado):

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe manage.py check
.\venv\Scripts\python.exe manage.py makemigrations --check --dry-run
.\venv\Scripts\python.exe manage.py test apiGit
.\venv\Scripts\python.exe manage.py migrate
```

No se considera validada la implementación hasta registrar los resultados reales.
