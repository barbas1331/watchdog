"""
monitor.py — Servicio de monitoreo de conexiones de red en tiempo real.
Usa psutil para obtener conexiones activas, procesos y estadísticas de red.
"""

import psutil
import socket
import time
import threading
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Cache de resolución de hostnames para no saturar DNS
_hostname_cache: dict[str, str] = {}
_geo_cache: dict[str, dict] = {}
# IPs que ya tienen lookup en progreso (evita lanzar el mismo lookup dos veces)
_lookup_in_progress: set[str] = set()
_lookup_lock = threading.Lock()
# Pool para lookups en background (sin bloquear el monitor)
_geo_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="geo_lookup")
# Historial de bytes por conexión para calcular velocidad
_prev_bytes: dict[str, tuple] = {}

PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
    ("169.254.0.0", "169.254.255.255"),
    ("::1", "::1"),
]

def _ip_to_int(ip: str) -> int:
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return sum(int(p) << (24 - 8 * i) for i, p in enumerate(parts))
    except Exception:
        pass
    return 0

def is_private_ip(ip: str) -> bool:
    if not ip or ip in ("0.0.0.0", "::", "::1", "127.0.0.1"):
        return True
    val = _ip_to_int(ip)
    for start, end in PRIVATE_RANGES:
        if _ip_to_int(start) <= val <= _ip_to_int(end):
            return True
    return False

def resolve_hostname(ip: str) -> str:
    """Retorna hostname cacheado o ip. El lookup real lo hace _fetch_geo_bg."""
    return _hostname_cache.get(ip, ip)

def get_geo_info(ip: str) -> dict:
    """Retorna geo cacheado inmediatamente. Lanza lookup en background si no existe."""
    if ip in _geo_cache:
        return _geo_cache[ip]
    if is_private_ip(ip):
        info = {"country": "Local", "city": "", "org": "", "flag": "🏠"}
        _geo_cache[ip] = info
        return info
    # Lanzar lookup en background sin bloquear
    _schedule_geo_lookup(ip)
    return {"country": "...", "city": "", "org": "", "flag": "🌐"}

def _schedule_geo_lookup(ip: str):
    """Encola el lookup de geo+hostname solo si no está ya en progreso."""
    with _lookup_lock:
        if ip in _lookup_in_progress or ip in _geo_cache:
            return
        _lookup_in_progress.add(ip)
    _geo_executor.submit(_fetch_geo_bg, ip)

def _fetch_geo_bg(ip: str):
    """Realiza el lookup DNS y geo fuera del hilo principal (no bloquea el monitor)."""
    # Hostname via DNS
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        host = ip
    _hostname_cache[ip] = host

    # Geo via ip-api.com
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org,isp,lat,lon",
            timeout=4
        )
        data = r.json()
        if data.get("status") == "success":
            info = {
                "country": data.get("country", "?"),
                "city": data.get("city", ""),
                "org": data.get("org", data.get("isp", "")),
                "flag": _country_flag(data.get("countryCode", "")),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
            }
        else:
            info = {"country": "?", "city": "", "org": "", "flag": "🌐"}
    except Exception:
        info = {"country": "?", "city": "", "org": "", "flag": "🌐"}

    _geo_cache[ip] = info
    with _lookup_lock:
        _lookup_in_progress.discard(ip)

def _country_flag(code: str) -> str:
    """Convierte código de país a emoji de bandera."""
    if not code or len(code) != 2:
        return "🌐"
    try:
        return chr(ord(code[0].upper()) + 0x1F1A5) + chr(ord(code[1].upper()) + 0x1F1A5)
    except Exception:
        return "🌐"

def get_process_details(pid: int) -> dict:
    """Obtiene detalles del proceso dado su PID (sin bloquear)."""
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            return {
                "pid": pid,
                "name": p.name(),
                "exe": p.exe(),
                "status": p.status(),
                "username": p.username(),
                "cpu": round(p.cpu_percent(interval=None), 2),  # No bloqueante
                "mem_mb": round(p.memory_info().rss / 1024 / 1024, 2),
                "cmdline": " ".join(p.cmdline())[:300],
                "created": datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
        return {"pid": pid, "name": "N/A", "exe": "", "status": "gone",
                "username": "", "cpu": 0, "mem_mb": 0, "cmdline": "", "created": ""}

def get_active_connections() -> list[dict]:
    """
    Retorna lista de todas las conexiones TCP/UDP activas con info enriquecida.
    """
    conns = []
    try:
        raw = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return []

    seen_keys = set()

    for c in raw:
        try:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr_ip = c.raddr.ip if c.raddr else ""
            raddr_port = c.raddr.port if c.raddr else 0
            raddr = f"{raddr_ip}:{raddr_port}" if raddr_ip else ""

            key = f"{laddr}-{raddr}-{c.pid}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            pid = c.pid or 0
            proc = get_process_details(pid) if pid else {
                "pid": 0, "name": "Sistema", "exe": "", "status": c.status,
                "username": "SYSTEM", "cpu": 0, "mem_mb": 0, "cmdline": "", "created": ""
            }

            geo = {}
            hostname = raddr_ip
            if raddr_ip and not is_private_ip(raddr_ip):
                hostname = resolve_hostname(raddr_ip)
                geo = get_geo_info(raddr_ip)
            elif raddr_ip:
                geo = {"country": "Red local", "city": "", "org": "", "flag": "🏠"}

            conn = {
                "key": key,
                "pid": pid,
                "process": proc["name"],
                "exe": proc["exe"],
                "username": proc["username"],
                "local": laddr,
                "remote_ip": raddr_ip,
                "remote_port": raddr_port,
                "remote": raddr,
                "hostname": hostname,
                "status": c.status or "UDP",
                "family": "IPv6" if ":" in (raddr_ip or "") else "IPv4",
                "is_external": not is_private_ip(raddr_ip) if raddr_ip else False,
                "geo": geo,
                "proc_detail": proc,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }
            conns.append(conn)
        except Exception:
            continue

    # Ordenar: externas primero, luego por proceso
    conns.sort(key=lambda x: (not x["is_external"], x["process"].lower()))
    return conns

def get_network_stats() -> dict:
    """Estadísticas globales de red."""
    try:
        io = psutil.net_io_counters()
        return {
            "bytes_sent": io.bytes_sent,
            "bytes_recv": io.bytes_recv,
            "pkts_sent": io.packets_sent,
            "pkts_recv": io.packets_recv,
        }
    except Exception:
        return {}

def kill_process(pid: int) -> dict:
    """Termina el proceso con el PID dado."""
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        time.sleep(0.5)
        if p.is_running():
            p.kill()
        return {"ok": True, "msg": f"Proceso '{name}' (PID {pid}) terminado."}
    except psutil.NoSuchProcess:
        return {"ok": False, "msg": f"Proceso {pid} ya no existe."}
    except psutil.AccessDenied:
        return {"ok": False, "msg": f"Acceso denegado para terminar PID {pid}. Ejecuta como Administrador."}
    except Exception as e:
        return {"ok": False, "msg": str(e)}
