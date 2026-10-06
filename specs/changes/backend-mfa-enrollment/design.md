# Design: Enrolamiento MFA del backend

## Technical Decisions

### 1. Data Model & Migrations

Agregar `mfa_confirmed` con valor inicial falso, `mfa_pending_secret`, nonce y contador
de fallos. La migración confirma únicamente usuarios con secreto previo no vacío.
Separar secreto pendiente y activo evita confirmar la cuenta por el mero acceso al QR.

### 2. Serializers & Validation

`mfa_confirmed` es de solo lectura. Los serializers públicos excluyen secretos, nonce
y URI. `code` exige un string de seis dígitos ASCII exactos, sin conversión de tipos ni
recorte de espacios. Login devuelve únicamente indicador de setup y desafío.

### 3. Services & Business Logic

El desafío firmado incluye usuario, propósito, nonce y vínculo derivado de contraseña;
no incorpora secretos MFA ni el hash de contraseña almacenado. Caduca en 300 segundos.
Las transacciones bloquean la fila, comprueban estado/vigencia, registran fallos y
consumen el nonce al completar. El quinto error invalida el desafío. Un nuevo login
invalida el anterior y elimina la configuración pendiente. Repetir setup con el mismo
desafío vigente conserva el secreto pendiente. El helper heredado confirma el secreto.
El bloqueo de filas de `select_for_update` solo existe en motores compatibles:
SQLite no lo implementa. Producción requiere una base transaccional compatible, como
PostgreSQL; las pruebas secuenciales no validan carreras entre solicitudes simultáneas.

### 4. Views & Routing

POST login → setup → confirm para usuarios pendientes; login → verify para confirmados.
Setup produce SVG mediante `qrcode.svg` y responde con `Cache-Control: no-store`.
Confirm/verify emiten JWT solo después del éxito del servicio. El scope `auth` limita
a 30 solicitudes/minuto por cliente/IP. Eliminar `/api/api/token/` y conservar
`/api/api/token/refresh/`. `UserAdmin` no expone secretos; rol/vigencia son editables y
confirmación es de solo lectura. El frontend aún debe implementar los pasos del flujo.
Los endpoints del flujo ignoran Bearer inválidos. Las escrituras del serializer y del
admin, incluido el formulario de contraseña, no sobrescriben campos MFA concurrentes.
DRF_NUM_PROXIES=0 usa la IP de conexión; configurar el número real de proxies confiables
y bloquear acceso directo si se despliega detrás de ellos. Varios workers requieren
caché compartida para el throttle; la caché local no agrega solicitudes entre procesos.

### 5. Testing Strategy

APITestCase verifica el flujo completo con TOTP real y JWT usable, ocultación de secretos,
propósitos incompatibles, códigos malformados, replay, nuevo login, caducidad, cinco
errores, contraseña/estado/vigencia y throttle. Limpiar caché entre pruebas evita
interferencia del límite por IP. Probar la migración con modelos históricos y restaurar
el esquema final. No ejecutar cambios sobre la base de datos real en estas pruebas.

Implementación integrada y revisada estáticamente; ejecución y migraciones pendientes.
El venv referencia Python 3.12 inaccesible (Acceso denegado) y no hay otro intérprete ejecutable. uv falló por red
OS10013. Los intentos de pip install y manage.py test fallaron antes de ejecutarse.
qrcode==8.2 está declarado pero no instalado. Restaurar Python o aportar su ruta,
instalar requirements.txt y ejecutar check, makemigrations --check --dry-run, test y migrate.
No hay recuperación/reset, correo automático ni cambio obligatorio de contraseña temporal;
un secreto heredado nunca recibido necesita recuperación separada y no se sobrescribe.
