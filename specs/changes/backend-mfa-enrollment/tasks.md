# Tasks: Enrolamiento MFA del backend

- [x] **Task 1 (Test First)**: Redactar pruebas API de enrolamiento y casos de seguridad;
  actualizar expectativas heredadas y aislar caché entre pruebas. Incluir migración,
  admin sin secretos, actualizaciones antiguas de serializer/admin/contraseña, Bearer
  inválido y X-Forwarded-For falsificado. Ejecución pendiente.
- [ ] **Task 2 (Data Layer)**: Integrar modelo y migración, conservar secretos heredados;
  verificar migración con base de pruebas.
- [ ] **Task 3 (Validation Layer)**: Integrar serializers de desafíos y códigos estrictos,
  confirmación de solo lectura y exclusión de secretos.
- [ ] **Task 4 (Business Layer)**: Integrar propósitos, nonce, caducidad, intentos y
  validaciones de cuenta; comprobar atomicidad y compatibilidad del helper.
- [ ] **Task 5 (API & Routing)**: Integrar setup/confirm/verify, QR local, no-store,
  throttle, eliminación del bypass y administración sin secretos.
- [x] **Task 6 (Documentation)**: Documentar contrato, recorrido humano, administrador
  inicial, compatibilidad y naturaleza reutilizable del secreto QR en español.
- [ ] **Task 7 (Verification)**: Reparar entorno e instalar dependencias; ejecutar check,
  makemigrations --check --dry-run y manage.py test apiGit; registrar resultados reales.
- [ ] **Task 8 (Integration Review)**: Confirmar la integración del agente principal y
  actualizar el estado del cambio después de verificarlo. No hacer commits.

Las casillas pendientes incluyen revisión y ejecución, aunque otro agente ya haya
integrado la implementación y completado la revisión estática. Bloqueo actual: venv con
Python 3.12 inaccesible (Acceso denegado), sin otro intérprete ejecutable; uv falló por red OS10013.
pip install y manage.py test no pudieron ejecutarse. qrcode==8.2 no instalado.
Restaurar Python o aportar su ruta; instalación, ejecución y migraciones pendientes.
Frontend, correo automático, cambio obligatorio de contraseña temporal y recuperación/reset
MFA fuera de este cambio. No se sobrescriben secretos heredados sin acceso al QR.
