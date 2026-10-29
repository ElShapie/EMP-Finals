# Identity Access Lab MVP

Laboratorio autocontenido para aprender el flujo de identidad digital: inicio de sesión OIDC, permisos por rol, altas y bajas por SCIM y registro de auditoría. El modo incluido usa Keycloak local en Docker para que el ejercicio pueda levantarse sin un tenant externo.

> **Solo para demostración local.** Compose publica los servicios en `127.0.0.1`. No expongas estos contenedores a Internet ni uses nombres, credenciales, tarjetas o datos reales. La configuración de desarrollo no es un despliegue de producción.

## Inicio rápido

```bash
git clone https://github.com/ElShapie/identity-access-lab-mvp.git
cd identity-access-lab-mvp
```

Requisitos: Docker Desktop o Docker Engine con el complemento `docker compose`, 4 GB de RAM disponibles y puertos locales `8000` y `8081` libres.

1. Copia `.env.example` como `.env`.
2. Ejecuta `docker compose up --build -d`.
3. Espera a que Keycloak y la aplicación estén saludables:

   ```bash
   docker compose ps
   ```

4. Abre <http://localhost:8000> y pulsa **Iniciar sesión**.
5. Usa `ingeniero@example.test` y la contraseña de demostración indicada en `.env.example`.

El inicio de Keycloak puede tardar un minuto la primera vez. La guía completa, incluyendo comprobaciones y solución de problemas, está en [`docs/GUIA_INSTALACION.md`](docs/GUIA_INSTALACION.md).

## Recorrido del MVP

1. Inicia sesión como ingeniero y prueba consulta y mantenimiento.
2. Intenta administrar; la app debe devolver `403`.
3. Inicia sesión como auditor y consulta los eventos; mantenimiento debe quedar denegado.
4. Envía una actualización SCIM para desactivar al ingeniero; la sesión abierta debe perder acceso a las acciones protegidas.
5. Reactiva la cuenta para continuar probando.

Los comandos reproducibles están en la guía de instalación. El rol y el estado que autorizan acciones viven en la base local de la aplicación; SCIM es la vía documentada para sincronizar esos cambios.

### Encargados de área de demostración

El realm local incluye cuentas ficticias para **RRHH**, **TI**, **IAM**, **SOC / Auditoría** y **Seguridad Física**. Sus correos y contraseñas se encuentran en `.env.example`; los roles existentes se aplican a toda la aplicación y todavía no tienen alcance por área.

| Área | Correo | Rol | Permisos adicionales |
|---|---|---|---|
| RRHH | `rrhh@example.test` | `consulta` | `usuarios`, `nfc` |
| TI | `ti@example.test` | `mantenimiento` | — |
| IAM | `iam@example.test` | `admin` | — (el rol ya incluye la gestión completa) |
| SOC / Auditoría | `soc-auditoria@example.test` | `auditor` | `roles` |
| Seguridad Física | `seguridad-fisica@example.test` | `consulta` | — |

La pantalla **Usuarios** permite crear cuentas con contraseña inicial, vincular una tarjeta NFC en el mismo alta y ajustar rol y permisos extra según el perfil que administra. RRHH puede crear identidades, vincular tarjetas y dar altas o bajas, pero no asignar permisos; SOC / Auditoría es quien cambia roles y permisos. Keycloak importa el realm al crear su volumen por primera vez; un volumen ya inicializado no recibe usuarios nuevos automáticamente. Para reiniciar el laboratorio desde cero y volver a importar las cuentas, `docker compose down -v` elimina las bases locales y las sesiones guardadas.

## Componentes

- **Keycloak 26.7.3:** proveedor OIDC local; importa un realm de demostración al iniciar por primera vez.
- **Flask + Gunicorn:** login OIDC, permisos por rol, CSRF, sesión, subconjunto SCIM 2.0 y portal de Cambio de Turno (`/turno`).
- **NVR Frigate:** monitoreo centralizado de video, compatible con cámaras Android, cámara en vivo de prueba (Zócalo CDMX) y retransmisión RTSP/WebRTC para aplicaciones móviles.
- **Módulo Móvil Flutter:** app para monitoreo de cámaras NVR en tiempo real y registro de relevos de guardia desde smartphones.
- **SQLite:** persistencia local de usuarios, credenciales cifradas, tarjetas y últimos 500 eventos.
- **Docker Compose:** red interna unificada, volúmenes persistentes, healthchecks y servicios centralizados (`keycloak`, `app`, `frigate`).
- **Módulos opcionales:** ejemplos de RFID, badge NFC USB para inicio de sesión físico y ejercicios de Microsoft 365. Ver [`docs/GUIA_NVR_FRIGATE.md`](docs/GUIA_NVR_FRIGATE.md) y [`docs/MODULOS_OPCIONALES.md`](docs/MODULOS_OPCIONALES.md).

La app ofrece una matriz editable por rol: `superadmin`, `admin`, `mantenimiento`, `auditor`, `consulta` y `sin_acceso`, con los permisos `consulta`, `mantenimiento`, `admin`, `registros`, `usuarios`, `roles`, `nfc` y `respaldo`. Consulta el detalle en [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md).

Para las extensiones consulta [`docs/MODULOS_OPCIONALES.md`](docs/MODULOS_OPCIONALES.md). No son necesarias para iniciar el MVP.


### Directorio de empleados y gestión de roles

El padrón de empleados se carga desde un CSV privado y contiene 31 identidades activas; las cuentas con mayor privilegio reciben el rol `superadmin`. El rol `superadmin` sigue reservado a esas tres identidades. La administración diaria se controla con los permisos `usuarios` (crear cuentas, credenciales y altas/bajas), `roles` (asignar rol y permisos extra), `nfc` (vincular tarjetas) y `respaldo` (exportar/importar). El rol `admin` recibe la gestión completa; RRHH y SOC reciben permisos extra acotados. Las contraseñas iniciales se generan al azar o las define quien crea la cuenta, y se guardan cifradas en SQLite para el acceso por badge.

El directorio y sus contraseñas están en `.directory/accounts.json`, carpeta local ignorada por Git y montada como solo lectura en la app. La imagen aprovisiona esas cuentas en SQLite y Keycloak al arrancar. La cuenta administrativa de demostración se conserva con permisos de auditoría; el acceso de máximo privilegio se asigna a las cuentas autorizadas en el padrón privado. Los UID NFC no vienen en el Excel: registra cada UID físico en **Badge NFC** después de iniciar el puente lector; no se inventan UID.


### Importar directorio privado

El código no incluye nombres, correos ni contraseñas personales. Para cargar el padrón local, entrega el CSV privado al equipo de confianza y ejecútalo en la carpeta del proyecto:

```bash
python tools/import_directory_credentials.py RUTA_AL_CSV_PRIVADO.csv
```

El comando crea `.directory/accounts.json` (ignorado por Git y montado como solo lectura). Después, `docker compose up --build -d` sincroniza las identidades con SQLite y Keycloak. El CSV y `accounts.json` contienen contraseñas; no los publiques.

### NVR Frigate, Cámaras Android & App Móvil Flutter

El laboratorio incluye el servicio de video **Frigate NVR** centralizado en `compose.yaml`:
- **Portal de Cambio de Turno:** accede a <http://localhost:8000/turno> para registrar relevos y verificar el flujo de cámaras.
- **Panel Frigate NVR:** accede a <http://localhost:8971> para supervisar las grabaciones y streams.
- **Cámara en vivo (Zócalo CDMX):** habilitada por defecto como señal de prueba mediante go2rtc y HLS.
- **Cámaras Android (Entrada e Interior):** configuradas y listas para vincular teléfonos mediante aplicaciones RTSP como *IP Webcam*.
- **Aplicación Móvil en Flutter:** ubicada en [`modules/mobile_flutter/`](modules/mobile_flutter/), permite visualizar las cámaras por RTSP/MJPEG y asentar turnos desde el teléfono. Consulta la guía completa en [`docs/GUIA_NVR_FRIGATE.md`](docs/GUIA_NVR_FRIGATE.md).

### Inicio de sesión con badge NFC (opcional)

Con `NFC_ENABLED=true` y el puente [`tools/nfc-bridge.ps1`](tools/nfc-bridge.ps1) corriendo en el host del lector USB, acercar una tarjeta NFC registrada abre sesión en la app sin escribir la contraseña. La app contrasta el UID con su lista blanca y usa la credencial cifrada guardada para el usuario (o las credenciales de respaldo del `.env` para las cuentas demo). La guía está en [`docs/NFC_LOGIN.md`](docs/NFC_LOGIN.md).

### Respaldo de la base local

La pantalla **Respaldo** (permiso `respaldo`) descarga un JSON con usuarios, matriz de permisos, tarjetas NFC y credenciales. El archivo permite restaurar el laboratorio en otro equipo y debe tratarse como material secreto. Al importar, la app valida el archivo, sincroniza primero las identidades con Keycloak y ofrece dos modos: **combinar** (actualiza o crea sin borrar lo existente) o **reemplazar** (sustituye tarjetas y credenciales y da de baja a los usuarios que no estén en el archivo).

## Comandos útiles

```bash
docker compose logs -f app keycloak
docker compose restart app
docker compose down
```

`docker compose down` conserva datos. Para borrar el laboratorio y su base de datos local de Keycloak, usa `docker compose down -v`; esta acción elimina los datos guardados.

## Integración con OneLogin

El código usa descubrimiento OIDC configurable. La guía [`docs/ONelogin.md`](docs/ONelogin.md) describe cómo cambiar del proveedor local a un tenant autorizado, habilitar HTTPS y mapear la cuenta local. SCIM implementa únicamente las operaciones documentadas en el perfil de este MVP; no debe declararse compatibilidad SCIM completa.

## Validación

Las pruebas locales se ejecutan con `python -m unittest discover -s tests -v`. Para comprobar contenedores y realm, sigue la guía de instalación. Las pruebas automatizadas no sustituyen una validación con un tenant, equipo o proveedor real.

## Licencia

MIT; ver [`LICENSE`](LICENSE).


