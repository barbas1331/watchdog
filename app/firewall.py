"""
firewall.py — Gestión del Firewall de Windows via netsh.
Requiere ejecución como Administrador para agregar/quitar reglas.
"""

import subprocess
import re
from datetime import datetime

RULE_PREFIX = "WatchdogBlock_"

def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        ok = result.returncode == 0
        out = (result.stdout + result.stderr).strip()
        return ok, out
    except Exception as e:
        return False, str(e)

def block_ip(ip: str, direction: str = "both") -> dict:
    """
    Bloquea una IP en el Firewall de Windows.
    direction: 'in', 'out', 'both'
    """
    results = []
    dirs = []
    if direction in ("in", "both"):
        dirs.append(("in", "entrada"))
    if direction in ("out", "both"):
        dirs.append(("out", "salida"))

    for d, label in dirs:
        rule_name = f"{RULE_PREFIX}{ip}_{d}"
        ok, out = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={d}",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
            "profile=any",
        ])
        results.append({"dir": label, "ok": ok, "msg": out if not ok else f"Bloqueado {label}"})

    all_ok = all(r["ok"] for r in results)
    return {
        "ok": all_ok,
        "ip": ip,
        "details": results,
        "msg": f"IP {ip} bloqueada ({direction})" if all_ok else "Error parcial al bloquear",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }

def unblock_ip(ip: str) -> dict:
    """Elimina todas las reglas de bloqueo para una IP."""
    results = []
    for d in ("in", "out"):
        rule_name = f"{RULE_PREFIX}{ip}_{d}"
        ok, out = _run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        ])
        results.append({"dir": d, "ok": ok, "msg": out})
    all_ok = any(r["ok"] for r in results)
    return {
        "ok": all_ok,
        "ip": ip,
        "msg": f"IP {ip} desbloqueada" if all_ok else f"No se encontró regla para {ip}",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }

def block_process_by_path(exe_path: str, process_name: str) -> dict:
    """Bloquea un proceso por su ruta ejecutable en el firewall."""
    safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", process_name)
    rule_name_out = f"{RULE_PREFIX}PROC_{safe_name}_out"
    rule_name_in = f"{RULE_PREFIX}PROC_{safe_name}_in"
    results = []
    for rname, d in [(rule_name_out, "out"), (rule_name_in, "in")]:
        ok, out = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rname}",
            f"dir={d}",
            "action=block",
            f"program={exe_path}",
            "enable=yes",
            "profile=any",
        ])
        results.append({"dir": d, "ok": ok, "msg": out if not ok else f"OK"})
    all_ok = all(r["ok"] for r in results)
    return {
        "ok": all_ok,
        "process": process_name,
        "exe": exe_path,
        "msg": f"Proceso '{process_name}' bloqueado en firewall" if all_ok else "Error al bloquear proceso",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }

def get_blocked_list() -> list[dict]:
    """Lista todas las reglas de bloqueo creadas por Watchdog."""
    ok, out = _run([
        "netsh", "advfirewall", "firewall", "show", "rule",
        f"name=all",
    ])
    blocked = []
    if not ok:
        return blocked

    # Parsear salida de netsh
    current_rule = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Nombre de regla:") or line.startswith("Rule Name:"):
            if current_rule and RULE_PREFIX in current_rule.get("name", ""):
                blocked.append(current_rule)
            name = line.split(":", 1)[1].strip()
            current_rule = {"name": name}
        elif ("Dirección:" in line or "Direction:" in line) and current_rule:
            current_rule["direction"] = line.split(":", 1)[1].strip()
        elif ("IP remotas:" in line or "RemoteIP:" in line) and current_rule:
            current_rule["remote_ip"] = line.split(":", 1)[1].strip()
        elif ("Programa:" in line or "Program:" in line) and current_rule:
            current_rule["program"] = line.split(":", 1)[1].strip()
        elif ("Habilitado:" in line or "Enabled:" in line) and current_rule:
            current_rule["enabled"] = line.split(":", 1)[1].strip()

    if current_rule and RULE_PREFIX in current_rule.get("name", ""):
        blocked.append(current_rule)

    return blocked

def check_admin() -> bool:
    """Verifica si el proceso corre con privilegios de administrador."""
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False
