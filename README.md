# 🔍 Watchdog de Red — Monitor de Privacidad

Panel de vigilancia de red en tiempo real para Windows. Permite ver **qué procesos están conectados a internet, con quién hablan, desde qué IPs, en qué países y organizaciones**, y actuar directamente: matar procesos, bloquear IPs en el firewall, o capturar los paquetes para ver exactamente qué datos se envían y reciben.

> **Uso personal.** Diseñado para tener control total sobre la actividad de red de tu propio equipo.

---

## 📸 Funcionalidades

| Módulo | Descripción |
|--------|-------------|
| **📡 En Vivo** | Conexiones TCP/UDP activas en tiempo real: proceso, PID, IP remota, hostname, país, ISP/Org, estado |
| **📜 Historial** | Log persistente en SQLite de todas las conexiones externas registradas |
| **🚫 Bloqueados** | Lista de IPs y procesos bloqueados. Bloqueo/desbloqueo manual |
| **📦 Captura** | Inspección de paquetes por IP: DNS queries, HTTP requests, TCP flags, payload texto plano |
| **🌍 Top Destinos** | Ranking histórico de IPs/hosts más contactados por tus aplicaciones |
| **⚡ Eventos** | Bitácora de todas las acciones realizadas (bloqueos, kills, capturas) |

### Acciones por conexión
- **✕ Matar proceso** — finaliza el proceso del sistema operativo
- **🚫 Bloquear IP** — añade regla en Windows Firewall (entrada, salida, o ambas)
- **🔒 Bloquear proceso** — el ejecutable completo queda sin acceso a internet
- **🔍 Inspeccionar** — captura en vivo los paquetes de esa IP (requiere Npcap)

---

## 📋 Requisitos

- **Windows 10 / 11**
- **Python 3.10+** → [python.org](https://www.python.org/downloads/)
- **Npcap** *(solo para captura de paquetes)* → [npcap.com](https://npcap.com/) — instalar con la opción *"WinPcap API-compatible Mode"* activada

---

## ⚡ Instalación rápida

```bash
# 1. Clonar el repositorio
git clone https://github.com/TU_USUARIO/watchdog-red.git
cd watchdog-red

# 2. Crear entorno virtual
python -m venv .venv

# 3. Activar el entorno
.venv\Scripts\activate

# 4. Instalar dependencias
pip install -r requirements.txt

# 5. (Opcional) Instalar scapy para captura de paquetes
pip install scapy
```

---

## 🚀 Uso

### Opción A — Lanzador automático (recomendado)

Doble clic en **`iniciar_admin.vbs`** → pide elevación de UAC → abre el navegador automáticamente.

> Ejecutar como Administrador es necesario para:
> - Crear/eliminar reglas en el Firewall de Windows
> - Capturar paquetes con Npcap/Scapy

### Opción B — Terminal

```bash
# Sin admin (solo monitoreo, sin firewall ni captura)
python run.py

# Con admin (funcionalidad completa)
# Clic derecho en cmd/PowerShell → "Ejecutar como administrador"
python run.py
```

El panel queda disponible en **http://127.0.0.1:5757** y el navegador se abre solo.

---

## 🗂️ Estructura del proyecto

```
watchdog-red/
│
├── run.py                  # Punto de entrada del servidor
├── iniciar.bat             # Lanzador sin privilegios
├── iniciar_admin.vbs       # Lanzador con elevación UAC (recomendado)
├── requirements.txt        # Dependencias Python
│
├── app/
│   ├── __init__.py         # Factory de Flask + SocketIO
│   ├── routes.py           # Rutas HTTP y eventos WebSocket
│   ├── monitor.py          # Escaneo de conexiones activas (psutil)
│   ├── firewall.py         # Gestión del Firewall (netsh)
│   ├── capture.py          # Captura de paquetes (scapy)
│   └── database.py         # Historial persistente (SQLite)
│
├── templates/
│   └── index.html          # Dashboard (dark theme)
│
└── static/
    ├── css/style.css        # Estilos dark theme
    └── js/app.js            # Lógica frontend + SocketIO
```

**Archivo generado automáticamente (no incluir en git):**
- `watchdog_history.db` — base de datos SQLite con todo el historial

---

## 🛠️ Stack tecnológico

| Capa | Tecnología |
|------|------------|
| Backend | Python 3 + Flask 3 + Flask-SocketIO |
| Tiempo real | WebSocket (threading mode) |
| Monitoreo | `psutil` — conexiones, procesos, stats de red |
| Firewall | `netsh advfirewall` — Windows Firewall nativo |
| Captura | `scapy` + Npcap — inspección profunda de paquetes |
| Geolocalización | [ip-api.com](http://ip-api.com) — gratuito, sin API key |
| Historial | SQLite — sin dependencias externas |
| Frontend | HTML5 + CSS3 (dark theme) + Vanilla JS + Socket.IO CDN |

---

## 🔒 Privacidad y seguridad

- El servidor escucha **solo en `127.0.0.1`** (localhost). No es accesible desde la red.
- No se envía ningún dato a servidores externos, excepto las consultas de geolocalización a `ip-api.com` (solo la IP remota de cada conexión detectada).
- Todo el historial se guarda localmente en `watchdog_history.db`.
- Para usar `ip-api.com` offline o privado, se puede adaptar `monitor.py` para usar una base de datos GeoIP local (ej. MaxMind GeoLite2).

---

## 📦 Dependencias (`requirements.txt`)

```
flask==3.0.3
flask-socketio==5.3.6
psutil==6.0.0
scapy==2.5.0          # Opcional, para captura de paquetes
requests==2.32.3
python-dotenv==1.0.1
```

---

## 🗺️ Roadmap / Futuras mejoras

- [ ] **Notificaciones nativas** — alerta en Windows cuando un proceso nuevo se conecta a internet por primera vez
- [ ] **Modo offline de geolocalización** — integrar MaxMind GeoLite2 para no depender de ip-api.com
- [ ] **Exportar historial** — CSV / JSON con un clic desde el panel
- [ ] **Reglas automáticas** — lista blanca/negra configurable (auto-bloquear procesos desconocidos)
- [ ] **Mapa de conexiones** — visualización geográfica de las conexiones activas
- [ ] **Alertas por umbral** — disparar aviso si un proceso supera X MB enviados
- [ ] **Vista de árbol de procesos** — agrupar conexiones por proceso padre
- [ ] **Soporte HTTPS local** — certificado autofirmado para el panel
- [ ] **Tray icon** — minimizar a la bandeja del sistema con indicador de actividad
- [ ] **Soporte multi-interfaz** — seleccionar la interfaz de red a monitorear para captura

---

## 🐛 Problemas conocidos

| Problema | Causa | Solución |
|----------|-------|----------|
| "Acceso denegado" al bloquear IP | No se ejecuta como Administrador | Usar `iniciar_admin.vbs` |
| Captura no funciona | Npcap no instalado | Instalar desde [npcap.com](https://npcap.com) con WinPcap API mode |
| Sin datos de geolocalización | Sin internet o ip-api.com bloqueado | Esperar o implementar GeoLite2 local |
| IPs locales sin país | Correcto — son conexiones de red local | Son `192.168.x.x`, `10.x.x.x`, etc. |
| `WARNING: Wireshark is installed, but cannot read manuf!` | Scapy busca archivos de Wireshark | Ignorar — no afecta el funcionamiento |

---

## 📄 Licencia

MIT — libre para uso personal y modificación.

---

> Desarrollado para uso personal en Windows. Úsalo de forma responsable y **solo en tu propio equipo**.
