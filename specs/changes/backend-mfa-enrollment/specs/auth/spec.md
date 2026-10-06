# Delta: auth

## ADDED Requirements

### Requirement: Enrolamiento validado por contraseña y TOTP

El sistema SHALL permitir configurar MFA después de validar la contraseña y SHALL NOT
emitir JWT hasta confirmar un código TOTP válido.

#### Scenario: Primera sesión

- GIVEN una cuenta activa sin MFA confirmado y dentro de su vigencia
- WHEN envía username y password correctos a POST /api/auth/login/
- THEN recibe mfa_setup_required=true y mfa_challenge, sin access ni refresh
- AND setup con ese desafío devuelve mfa_secret, mfa_provisioning_uri y qr_code_svg
- AND el SVG se genera en backend con qrcode.svg, sin API externa, y usa no-store
- AND confirm con el desafío y TOTP correcto devuelve access, refresh y user confirmado

### Requirement: Separación de propósitos

El sistema SHALL separar desafíos de setup y verify.

#### Scenario: Cuenta confirmada

- GIVEN una cuenta con MFA confirmado
- WHEN valida su contraseña
- THEN recibe mfa_setup_required=false y un desafío para verify
- AND ese desafío no permite setup ni confirm

#### Scenario: Cuenta pendiente intenta verificar

- GIVEN un desafío de enrolamiento válido
- WHEN se presenta a verify incluso con TOTP correcto
- THEN se rechaza sin emitir JWT ni confirmar la cuenta

### Requirement: Desafíos limitados y consumibles

El sistema SHALL limitar desafíos a 300 segundos y cinco códigos incorrectos, consumir
su nonce al completar y vincularlos a contraseña, cuenta y propósito.

#### Scenario: Replay o nuevo login

- GIVEN un desafío consumido o sustituido por un nuevo login
- WHEN se reutiliza en un endpoint MFA
- THEN se rechaza sin emitir tokens ni material de enrolamiento

#### Scenario: Caducidad o agotamiento

- GIVEN un desafío con más de 300 segundos o cinco códigos incorrectos
- WHEN se presenta incluso con un código correcto
- THEN se rechaza y se requiere otro login

#### Scenario: Cuenta modificada

- GIVEN un desafío emitido antes de un cambio de contraseña, desactivación o pérdida de vigencia
- WHEN se intenta continuar el flujo
- THEN se rechaza sin tokens ni secretos

### Requirement: Validación estricta y throttle

El sistema SHALL admitir solamente strings de seis dígitos ASCII y SHALL limitar las
solicitudes de autenticación al scope auth de 30/minuto por cliente/IP.

#### Scenario: Código malformado

- GIVEN un código numérico JSON, Unicode, con espacios o longitud incorrecta
- WHEN se presenta a confirm o verify
- THEN recibe un error de validación sin tokens

#### Scenario: Exceso de solicitudes

- GIVEN 30 solicitudes de autenticación en un minuto desde el mismo cliente/IP
- WHEN se envía otra solicitud
- THEN recibe HTTP 429 y Retry-After

### Requirement: Creación y administración sin secretos

El sistema SHALL crear usuarios con mfa_confirmed=false y SHALL NOT exponer secretos,
URI ni QR en el CRUD. La confirmación SHALL ser de solo lectura para clientes y admin.

#### Scenario: Administrador crea una cuenta

- GIVEN un administrador autorizado por role ADMIN o is_superuser
- WHEN crea una cuenta mediante POST /api/users/ incluso enviando mfa_confirmed=true
- THEN la cuenta queda pendiente y la respuesta no contiene material MFA

#### Scenario: Administrador inicial

- GIVEN un superusuario recién creado por createsuperuser sin secreto MFA
- WHEN inicia sesión por contraseña en la API
- THEN debe completar el mismo enrolamiento antes de recibir JWT

### Requirement: Compatibilidad de usuarios existentes

El sistema SHALL conservar como confirmados los usuarios con secreto previo no vacío.

#### Scenario: Migración

- GIVEN cuentas anteriores con secreto y sin secreto
- WHEN se aplica la migración de enrolamiento
- THEN solo las cuentas con secreto quedan confirmadas y conservan su secreto
- AND generate_mfa_secret continúa disponible y marca MFA como confirmado

## REMOVED Requirements

### Requirement: Emisión JWT mediante contraseña sola

Se elimina POST /api/api/token/. Se conserva POST /api/api/token/refresh/ para tokens
de renovación existentes. La integración del frontend queda pendiente.
