"""
routes.py — Rutas HTTP y eventos SocketIO del servidor Watchdog.
"""

import socket
import threading
import time
from flask import Blueprint, render_template, jsonify, request
from flask_socketio import emit

from . import socketio
from .monitor import get_active_connections, get_network_stats, kill_process, get_process_details
from .firewall import block_ip, unblock_ip, block_process_by_path, get_blocked_list, check_admin
from .capture import (start_capture, stop_capture, get_capture_packets,
                      get_capture_stats, list_sessions, is_scapy_available)
from .database import (init_db, log_connection, log_event, log_blocked,
                       log_packet, get_history_connections, get_history_events,
                       get_blocked_ips, mark_unblocked, get_top_destinations,
                       get_stats_summary, get_packets_for_session)

bp = Blueprint("main", __name__)

# ── Init DB al importar ──────────────────────────────────────────────────────
init_db()

# ── Estado global del monitor ────────────────────────────────────────────────
_monitor_running = False
_monitor_thread: threading.Thread | None = None
_last_conn_keys: set = set()

def _get_my_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def _monitor_loop():
    global _monitor_running, _last_conn_keys
    my_ip = _get_my_ip()
    is_admin_val  = check_admin()
    is_scapy_val  = is_scapy_available()
    tick = 0
    while _monitor_running:
        try:
            conns = get_active_connections()
            stats = get_network_stats()

            # Detectar nuevas conexiones externas → loguear
            current_keys = set(c["key"] for c in conns)
            new_keys = current_keys - _last_conn_keys
            for c in conns:
                if c["key"] in new_keys and c.get("is_external"):
                    log_connection(c)
            _last_conn_keys = current_keys

            # Emitir siempre (el frontend hace el diff)
            socketio.emit("connections_update", {
                "connections": conns,
                "stats": stats,
                "my_ip": my_ip,
                "admin": is_admin_val,
                "scapy": is_scapy_val,
            })
            tick += 1
        except Exception as e:
            print(f"[Monitor Error] {e}")
        time.sleep(3)  # 3s — suficiente para UI fluida sin saturar

# ── Rutas HTTP ────────────────────────────────────────────────────────────────

@bp.route("/")
def index():
    return render_template("index.html",
                           admin=check_admin(),
                           scapy=is_scapy_available())

@bp.route("/api/connections")
def api_connections():
    return jsonify(get_active_connections())

@bp.route("/api/history")
def api_history():
    ip = request.args.get("ip")
    limit = int(request.args.get("limit", 200))
    return jsonify(get_history_connections(limit=limit, remote_ip=ip))

@bp.route("/api/events")
def api_events():
    return jsonify(get_history_events())

@bp.route("/api/top")
def api_top():
    return jsonify(get_top_destinations())

@bp.route("/api/stats")
def api_stats():
    return jsonify(get_stats_summary())

@bp.route("/api/blocked")
def api_blocked():
    return jsonify(get_blocked_list())

@bp.route("/api/packets/<session_id>")
def api_packets(session_id):
    return jsonify(get_packets_for_session(session_id))

@bp.route("/api/process/<int:pid>")
def api_process(pid):
    return jsonify(get_process_details(pid))

# ── SocketIO eventos ──────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    global _monitor_running, _monitor_thread
    if not _monitor_running:
        _monitor_running = True
        _monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
        _monitor_thread.start()
    emit("server_info", {
        "admin": check_admin(),
        "scapy": is_scapy_available(),
        "my_ip": _get_my_ip(),
    })

@socketio.on("disconnect")
def on_disconnect():
    pass  # No parar el monitor al desconectar un cliente

@socketio.on("kill_process")
def on_kill_process(data):
    pid = data.get("pid")
    process = data.get("process", str(pid))
    result = kill_process(pid)
    log_event("KILL", f"{process} (PID {pid})", result["msg"], result["ok"])
    emit("action_result", {"action": "kill", **result})

@socketio.on("block_ip")
def on_block_ip(data):
    ip = data.get("ip")
    direction = data.get("direction", "both")
    result = block_ip(ip, direction)
    log_event("BLOCK_IP", ip, result["msg"], result["ok"])
    if result["ok"]:
        log_blocked(ip=ip, direction=direction)
    emit("action_result", {"action": "block_ip", **result})

@socketio.on("unblock_ip")
def on_unblock_ip(data):
    ip = data.get("ip")
    result = unblock_ip(ip)
    log_event("UNBLOCK_IP", ip, result["msg"], result["ok"])
    if result["ok"]:
        mark_unblocked(ip)
    emit("action_result", {"action": "unblock_ip", **result})

@socketio.on("block_process")
def on_block_process(data):
    exe = data.get("exe", "")
    process = data.get("process", "")
    if not exe:
        emit("action_result", {"action": "block_process", "ok": False,
                               "msg": "No se encontró ruta del ejecutable"})
        return
    result = block_process_by_path(exe, process)
    log_event("BLOCK_PROC", process, result["msg"], result["ok"])
    if result["ok"]:
        log_blocked(process=process, exe=exe, direction="both")
    emit("action_result", {"action": "block_process", **result})

@socketio.on("start_capture")
def on_start_capture(data):
    target_ip = data.get("ip")
    my_ip = _get_my_ip()

    def pkt_callback(session_id, pkt_info):
        log_packet(session_id, target_ip, pkt_info)
        socketio.emit("packet", {"session_id": session_id, "packet": pkt_info})

    result = start_capture(target_ip, my_ip=my_ip, callback=pkt_callback)
    log_event("CAPTURE_START", target_ip, result.get("msg", ""), result["ok"])
    emit("action_result", {"action": "start_capture", **result})

@socketio.on("stop_capture")
def on_stop_capture(data):
    session_id = data.get("session_id")
    result = stop_capture(session_id)
    log_event("CAPTURE_STOP", session_id, result["msg"], result["ok"])
    emit("action_result", {"action": "stop_capture", **result})

@socketio.on("get_capture_sessions")
def on_get_sessions(data):
    emit("capture_sessions", {"sessions": list_sessions()})

@socketio.on("request_geo")
def on_request_geo(data):
    from .monitor import get_geo_info, resolve_hostname
    ip = data.get("ip")
    geo = get_geo_info(ip)
    hostname = resolve_hostname(ip)
    emit("geo_result", {"ip": ip, "geo": geo, "hostname": hostname})
