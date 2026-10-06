## Proyecto Entorno Virtual Django

Repositorio con entorno virtual listo para ejecutar Django (Python) para clases de INACAP.

El flujo de vinculación del autenticador, los endpoints y los pasos de verificación
están documentados en [Enrolamiento MFA](docs/mfa-enrollment.md).
La bitácora de esta implementación está en [CAMBIOS.txt](CAMBIOS.txt).

---

## Tabla de Contenidos
- [Proyecto Entorno Virtual Django](#proyecto-entorno-virtual-django)
- [Tabla de Contenidos](#tabla-de-contenidos)
- [🎓 Guía para Estudiantes e IA](#-guía-para-estudiantes-e-ia)
- [Prerrequisitos](#prerrequisitos)
- [Entorno Virtual](#entorno-virtual)
- [Instalación y Configuración](#instalación-y-configuración)
- [Uso](#uso)
- [Tecnologías Utilizadas](#tecnologías-utilizadas)

---

## 🎓 Guía para Estudiantes e IA

Este repositorio cuenta con un sistema de agentes y habilidades de IA diseñado para el aprendizaje activo:
* 📖 [**`GUIA_ESTUDIANTES.md`**](GUIA_ESTUDIANTES.md): Manual paso a paso para aprender usando los agentes y habilidades.
* 💡 [**`exemplars.md`**](exemplars.md): Código de referencia modelo (Cheat Sheet) de modelos, serializers, vistas y servicios.
* 🤖 [**`AGENTS.md`**](AGENTS.md): Reglas de arquitectura y configuración de asistentes inteligentes.
* 📐 [**`docs/analisis-preliminar.md`**](docs/analisis-preliminar.md): Análisis preliminar del Sistema de Gestión de Biblioteca (problema, actores, entidades, modelo de datos, endpoints y consultas ORM).
* 🧩 [**`docs/resumen-implementacion.md`**](docs/resumen-implementacion.md): Resumen explicativo del código ya implementado (modelos, serializadores, vistas, rutas) con glosario de términos de Django/DRF de mayor complejidad.

---

## Prerrequisitos
- Disponer de un IDE (por ejemplo, VS Code o PyCharm).
- Python 3.x instalado.
- Entorno virtual activado.

---

## Entorno Virtual

El entorno virtual (`vgit/`) **no viene incluido en el repositorio** (está excluido vía
`.gitignore`), por lo que cada persona debe crearlo localmente antes de trabajar.

```powershell
# 0. Verificar la versión de Python instalada (se requiere 3.12+, idealmente 3.13+)
python --version

# 1. Crear el entorno virtual (se genera la carpeta vgit/)
python -m venv vgit

# 2. Activar el entorno virtual (PowerShell en Windows)
.\vgit\Scripts\Activate.ps1

# En caso de bloqueo por política de ejecución de scripts, ejecutar una sola vez:
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

# 3. Instalar las dependencias del proyecto
pip install -r requirements.txt
```

> En Windows también se puede activar con `.\vgit\Scripts\activate.bat` desde `cmd.exe`, o con
> `source vgit/Scripts/activate` desde Git Bash.

> ⚠️ **Si `python --version` muestra una versión inferior a 3.12**, actualiza Python antes de
> continuar (descarga la última versión desde [python.org/downloads](https://www.python.org/downloads/)
> marcando la opción "Add python.exe to PATH" durante la instalación). Si tienes varias versiones
> instaladas en Windows, puedes usar el *Python Launcher* para elegir una específica sin cambiar
> el comando anterior, por ejemplo:
> ```powershell
> py -3.13 -m venv vgit
> ```

Una vez activado, el prompt mostrará el prefijo `(vgit)`. A partir de ahí, todos los comandos de
`manage.py` deben ejecutarse con el intérprete del entorno virtual, por ejemplo:

```bash
.\vgit\Scripts\python.exe manage.py runserver
```

### Instalación manual de dependencias (alternativa a `requirements.txt`)

Si prefieres instalar los paquetes uno por uno (por ejemplo, para fijar versiones puntuales o sin
activar el entorno primero), puedes invocar `pip` directamente a través del intérprete de `vgit`:

```powershell
.\vgit\Scripts\python.exe -m pip install "Django==5.2.17" djangorestframework==3.18.1 python-decouple==3.8
```

> ⚠️ `requirements.txt` es la fuente de verdad del proyecto y actualmente fija `Django==6.1.1`. El
> comando anterior instala una versión distinta (`5.2.17`); úsalo solo si necesitas replicar ese
> entorno puntual, y luego ejecuta `pip install -r requirements.txt` para volver a las versiones
> oficiales del repositorio.

---

## Instalación y Configuración

Comandos para inicializar y configurar el proyecto (con el entorno virtual ya activado):

```bash
# Generar scripts de migración basados en los modelos definidos
python manage.py makemigrations

# Aplicar las migraciones a la base de datos
python manage.py migrate

# Crear superusuario para acceder al panel de administración de Django
python manage.py createsuperuser

# Ejecutar el servidor de desarrollo local
python manage.py runserver
```

---

## Uso
Utilizar como repositorio base para el desarrollo de APIs REST y creación de nuevos modelos durante las clases.

---

## Tecnologías Utilizadas
- **Lenguaje de Programación:** Python
- **Framework Web:** Django
- **API Toolkit:** Django REST Framework
