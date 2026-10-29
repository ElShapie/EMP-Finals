# App móvil Flutter: Frigate NVR & Control Operativo

Aplicación Flutter del **Identity Access Lab** para:

1. Monitorear en tiempo real las cámaras de Frigate NVR (`cam_entrada`, `cam_interior` y la cámara demo).
2. Registrar cambios de turno y eventos de acceso del SOC desde el teléfono.
3. Consultar el dashboard Flask/IAM del laboratorio.

Esta app reemplaza al módulo mínimo anterior y es la versión integrada al proyecto.

---

## 1. Arquitectura

```text
Celular / navegador
  │
  ├── http://IP_PC:9000          App Flutter Web (build/web)
  │        └── /api/*  ────────►  proxy local ──► http://127.0.0.1:5000 (Frigate)
  │
  ├── http://IP_PC:8000          Dashboard Flask / IAM
  └── rtsp://IP_PC:8554/<cam>    go2rtc (RTSP de Frigate)
```

El proxy `tools/serve_web.py` es necesario porque Frigate responde
`401 Missing CSRF header` a peticiones cruzadas desde el navegador. El proxy
elimina la cabecera `Origin` y agrega CORS.

| Protocolo | Puerto | Endpoint | Uso |
| :--- | :--- | :--- | :--- |
| HTTP snapshots | `5000` | `/api/<cam>/latest.jpg?h=480` | Refresco periódico, máxima compatibilidad |
| API REST | `5000` | `/api/config`, `/api/stats` | Estado de cámaras y NVR |
| RTSP go2rtc | `8554` | `rtsp://<IP_PC>:8554/<cam>` | Video H.264 de baja latencia |
| Dashboard Flask | `8000` | `/`, `/turno`, `/registros` | Identidad, turnos y auditoría |

---

## 2. Ejecutar en el PC (Flutter Web + proxy)

Desde la raíz del repositorio:

```powershell
.\iniciar-movil.ps1
```

Ese script compila `build/web`, levanta el proxy en el puerto `9000` y muestra
las URLs. Luego abre:

- En el PC: <http://localhost:9000>
- En el celular (misma Wi-Fi): `http://IP_DEL_PC:9000`

Si ya compilaste y solo quieres servir:

```powershell
.\iniciar-movil.ps1 -SkipBuild
```

### Manual

```powershell
Set-Location modules\mobile_flutter
flutter pub get
flutter build web --release
python tools\serve_web.py
```

Variables opcionales del proxy:

```powershell
$env:PORT="9000"
$env:FRIGATE_URL="http://127.0.0.1:5000"
python tools\serve_web.py
```

---

## 3. Ejecutar como app nativa (Android/iOS)

```powershell
Set-Location modules\mobile_flutter
flutter pub get
flutter run
```

Por defecto la app usa el host de la URL cuando corre en web. En un dispositivo
nativo usa `192.168.100.8`; cámbialo desde el botón de **Configuración de
Servidor** dentro de la app o edita `_defaultHost` en `lib/main.dart`.

Para HTTP en claro en Android, el `AndroidManifest.xml` ya debe incluir
`android:usesCleartextTraffic="true"` y el permiso `INTERNET`.

---

## 4. Estructura

- `lib/main.dart`: dashboard completo (cámaras, accesos RFID, turnos, evidencias).
- `tools/serve_web.py`: servidor estático + proxy `/api` hacia Frigate.
- `web/`: plantilla de Flutter Web.
- `android/`, `ios/`, `windows/`, `linux/`, `macos/`: plataformas Flutter.

---

## 5. Solución de problemas

- **La app abre pero no hay cámara:** confirma que DroidCam esté activo y que
  `FRIGATE_CAM_ENTRADA_IP`/`FRIGATE_CAM_PORT` en `.env` apunten al celular.
- **`/api/...` devuelve 502:** el proxy no alcanza Frigate; revisa
  `docker compose ps` y que el puerto `5000` esté arriba.
- **No carga desde el celular:** permite `python.exe` y el puerto `9000` en el
  Firewall de Windows para redes privadas.
- **Login OIDC redirige a una IP vieja:** actualiza `KC_HOSTNAME` en `.env` y
  recrea Keycloak con `docker compose up -d`.
