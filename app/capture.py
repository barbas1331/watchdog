"""
capture.py — Captura de paquetes por IP o proceso usando scapy.
Requiere Npcap instalado: https://npcap.com/
"""

import threading
import time
from datetime import datetime
from collections import deque

# Intentar importar scapy (opcional)
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, conf
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
    conf.verb = 0  # silenciar salida de scapy
except ImportError:
    SCAPY_AVAILABLE = False

MAX_PACKETS = 500  # máximo de paquetes en memoria por sesión

class CaptureSession:
    """Sesión de captura para una IP específica."""

    def __init__(self, target_ip: str, session_id: str):
        self.target_ip = target_ip
        self.session_id = session_id
        self.packets: deque = deque(maxlen=MAX_PACKETS)
        self.active = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.stats = {
            "total": 0,
            "sent": 0,
            "recv": 0,
            "bytes_sent": 0,
            "bytes_recv": 0,
            "started": datetime.now().strftime("%H:%M:%S"),
        }

    def start(self, my_ip: str = None, callback=None):
        if not SCAPY_AVAILABLE:
            return False
        self.active = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(my_ip, callback),
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self):
        self.active = False
        self._stop_event.set()

    def _capture_loop(self, my_ip: str, callback):
        bpf_filter = f"host {self.target_ip}"
        def process_packet(pkt):
            if self._stop_event.is_set():
                return
            info = self._parse_packet(pkt, my_ip)
            if info:
                self.packets.append(info)
                self.stats["total"] += 1
                if info["direction"] == "OUT":
                    self.stats["sent"] += 1
                    self.stats["bytes_sent"] += info["size"]
                else:
                    self.stats["recv"] += 1
                    self.stats["bytes_recv"] += info["size"]
                if callback:
                    callback(self.session_id, info)

        try:
            sniff(
                filter=bpf_filter,
                prn=process_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
                timeout=None,
            )
        except Exception as e:
            pass
        self.active = False

    # Contador de ID único por sesión
    _pkt_counter = 0

    def _parse_packet(self, pkt, my_ip: str) -> dict | None:
        if not pkt.haslayer(IP):
            return None
        try:
            CaptureSession._pkt_counter += 1
            pkt_id = CaptureSession._pkt_counter

            ip_layer = pkt[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            ttl = ip_layer.ttl
            size = len(pkt)
            direction = "OUT" if src == my_ip else "IN"

            proto = "OTHER"
            sport = dport = 0
            tcp_flags_raw = ""
            tcp_flags_human = ""
            layers = [f"IP ({src} → {dst}, TTL={ttl})"]

            # ── TCP / UDP ────────────────────────────────────────────
            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                tcp_flags_raw = str(pkt[TCP].flags)
                tcp_flags_human = _explain_tcp_flags(pkt[TCP].flags)
                layers.append(f"TCP (:{sport} → :{dport}, flags={tcp_flags_raw})")
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                layers.append(f"UDP (:{sport} → :{dport})")

            payload_summary = ""
            human = ""
            details = {}

            # ── DNS ──────────────────────────────────────────────────
            if pkt.haslayer(DNS):
                proto = "DNS"
                layers.append("DNS")
                dns = pkt[DNS]
                queries = []
                answers = []
                try:
                    qd = dns.qd
                    while qd:
                        name = qd.qname.decode("utf-8", errors="replace").rstrip(".") if qd.qname else ""
                        queries.append(name)
                        qd = qd.payload if hasattr(qd, "payload") else None
                except Exception:
                    pass
                try:
                    an = dns.an
                    while an:
                        rdata = str(an.rdata)
                        answers.append(rdata)
                        an = an.payload if hasattr(an, "payload") else None
                except Exception:
                    pass
                if queries:
                    payload_summary = f"DNS Query → {', '.join(queries)}"
                    human = f"{'Tu PC' if direction == 'OUT' else 'El servidor'} está preguntando al servidor DNS: ¿cuál es la IP de \"{', '.join(queries)}\"?"
                elif answers:
                    payload_summary = f"DNS Respuesta ← {', '.join(answers[:3])}"
                    human = f"El servidor DNS responde: la IP es {', '.join(answers[:3])}"
                details = {"dns_queries": queries, "dns_answers": answers}

            # ── HTTP ─────────────────────────────────────────────────
            elif pkt.haslayer(HTTPRequest):
                proto = "HTTP"
                req = pkt[HTTPRequest]
                method  = _dec(req.Method)
                host    = _dec(req.Host)
                path    = _dec(req.Path)
                version = _dec(req.Http_Version)
                headers = _extract_http_headers(req)
                body_preview = ""
                if pkt.haslayer(Raw):
                    full = pkt[Raw].load.decode("utf-8", errors="replace")
                    # Separar headers de body
                    parts = full.split("\r\n\r\n", 1)
                    if len(parts) > 1:
                        body_preview = parts[1][:500]
                layers.append(f"HTTP Request")
                payload_summary = f"HTTP {method} {host}{path}"
                human = (f"{'Tu PC' if direction=='OUT' else 'El servidor remoto'} envía una solicitud "
                         f"HTTP {method} al servidor «{host}» pidiendo el recurso: {path}")
                details = {
                    "http_method": method, "http_host": host, "http_path": path,
                    "http_version": version, "http_headers": headers, "http_body": body_preview,
                }

            elif pkt.haslayer(HTTPResponse):
                proto = "HTTP"
                resp = pkt[HTTPResponse]
                code   = _dec(resp.Status_Code)
                reason = _dec(resp.Reason_Phrase) if hasattr(resp, "Reason_Phrase") else ""
                version = _dec(resp.Http_Version)
                headers = _extract_http_headers(resp)
                body_preview = ""
                if pkt.haslayer(Raw):
                    full = pkt[Raw].load.decode("utf-8", errors="replace")
                    parts = full.split("\r\n\r\n", 1)
                    if len(parts) > 1:
                        body_preview = parts[1][:500]
                layers.append("HTTP Response")
                payload_summary = f"HTTP {code} {reason}"
                human = (f"El servidor responde con código {code} {reason}. "
                         + (f"Contenido: {headers.get('Content-Type','')}" if headers.get("Content-Type") else ""))
                details = {
                    "http_status": code, "http_reason": reason,
                    "http_version": version, "http_headers": headers, "http_body": body_preview,
                }

            # ── TLS / HTTPS ──────────────────────────────────────────
            elif dport == 443 or sport == 443 or dport == 8443 or sport == 8443:
                sni = _extract_tls_sni(pkt)
                if sni:
                    proto = "TLS"
                    layers.append(f"TLS (SNI: {sni})")
                    payload_summary = f"TLS → {sni}"
                    human = (f"{'Tu PC' if direction=='OUT' else 'El servidor'} inicia una conexión "
                             f"HTTPS cifrada con «{sni}». No se puede leer el contenido (cifrado).")
                    details = {"tls_sni": sni}
                else:
                    proto = "TLS"
                    layers.append("TLS (cifrado)")
                    payload_summary = f"Datos TLS cifrados (puerto {dport if direction=='OUT' else sport})"
                    human = ("Tráfico HTTPS cifrado. El contenido no es legible sin la clave privada. "
                             f"{'Enviando' if direction=='OUT' else 'Recibiendo'} {size} bytes.")
                    details = {}

            # ── TCP puro (sin payload conocido) ──────────────────────
            elif proto == "TCP" and not payload_summary:
                payload_summary = f"TCP {tcp_flags_raw} (:{sport}→:{dport})"
                human = _tcp_human(direction, sport, dport, tcp_flags_human, size)
                details = {"tcp_flags": tcp_flags_raw, "tcp_flags_human": tcp_flags_human}

            # ── UDP puro ─────────────────────────────────────────────
            elif proto == "UDP" and not payload_summary:
                payload_summary = f"UDP :{sport} → :{dport}"
                human = f"Paquete UDP de {size} bytes. {'Enviado a' if direction=='OUT' else 'Recibido de'} :{dport}."
                details = {}

            # ── Raw payload (texto o hex) ─────────────────────────────
            raw_bytes = b""
            raw_text  = ""
            raw_hex   = ""
            hex_dump  = ""
            if pkt.haslayer(Raw):
                raw_bytes = pkt[Raw].load
                raw_text  = raw_bytes.decode("utf-8", errors="replace")
                raw_hex   = raw_bytes.hex()
                hex_dump  = _format_hex_dump(raw_bytes[:512])
            elif not pkt.haslayer(Raw) and proto not in ("DNS", "HTTP"):
                # Capturar todo el payload del paquete
                raw_bytes = bytes(pkt)[20:]  # skip IP header
                raw_hex   = raw_bytes[:256].hex()
                hex_dump  = _format_hex_dump(raw_bytes[:256])

            return {
                "id":        pkt_id,
                "ts":        datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "direction": direction,
                "proto":     proto,
                "src":       f"{src}:{sport}",
                "dst":       f"{dst}:{dport}",
                "size":      size,
                "ttl":       ttl,
                "summary":   payload_summary or f"{proto} {src}→{dst}",
                "human":     human or payload_summary,
                "layers":    layers,
                "details":   details,
                "raw":       raw_text[:80] if raw_text else "",
                "raw_full":  raw_text[:2000] if raw_text else "",
                "hex":       raw_hex[:128] if raw_hex else "",
                "hex_dump":  hex_dump,
            }
        except Exception:
            return None


# ── Helpers de análisis ───────────────────────────────────────────────────────

def _dec(val) -> str:
    """Decodifica bytes a string."""
    if val is None:
        return ""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)

def _explain_tcp_flags(flags) -> str:
    explanations = []
    flag_val = int(flags)
    if flag_val & 0x01: explanations.append("FIN (cerrar conexión)")
    if flag_val & 0x02: explanations.append("SYN (iniciar conexión)")
    if flag_val & 0x04: explanations.append("RST (reset/forzar cierre)")
    if flag_val & 0x08: explanations.append("PSH (enviar datos ahora)")
    if flag_val & 0x10: explanations.append("ACK (confirmación recibida)")
    if flag_val & 0x20: explanations.append("URG (datos urgentes)")
    return ", ".join(explanations) if explanations else "sin flags especiales"

def _tcp_human(direction: str, sport: int, dport: int, flags_human: str, size: int) -> str:
    port = dport if direction == "OUT" else sport
    service = _known_port(port)
    who = "Tu PC" if direction == "OUT" else "El servidor"
    verb = "envía" if direction == "OUT" else "recibe"
    svc_str = f" (servicio {service})" if service else ""
    return f"{who} {verb} un paquete TCP de {size} bytes al puerto {port}{svc_str}. Flags: {flags_human}."

def _known_port(port: int) -> str:
    ports = {
        80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP",
        25: "SMTP", 587: "SMTP", 993: "IMAP", 995: "POP3",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        8080: "HTTP-alt", 8443: "HTTPS-alt", 3389: "RDP", 1194: "OpenVPN",
        5222: "XMPP/Chat", 1935: "RTMP/Streaming", 4433: "QUIC",
    }
    return ports.get(port, "")

def _extract_http_headers(layer) -> dict:
    headers = {}
    skip = {"Method", "Path", "Http_Version", "Host", "Status_Code",
            "Reason_Phrase", "name", "underlayer", "payload", "fieldtype"}
    for field in layer.fields:
        if field in skip:
            continue
        val = getattr(layer, field, None)
        if val is not None and val != b"":
            headers[field.replace("_", "-")] = _dec(val)
    return headers

def _extract_tls_sni(pkt) -> str:
    """Intenta extraer el SNI del ClientHello TLS."""
    try:
        raw = None
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
        elif pkt.haslayer(TCP):
            raw = bytes(pkt[TCP].payload)
        if not raw or len(raw) < 5:
            return ""
        # TLS record: tipo=0x16 (handshake), versión, longitud
        if raw[0] != 0x16:
            return ""
        # Handshake type = 0x01 (ClientHello)
        offset = 5
        if offset >= len(raw) or raw[offset] != 0x01:
            return ""
        offset += 4  # handshake header
        offset += 2  # version
        offset += 32  # random
        if offset >= len(raw):
            return ""
        sess_len = raw[offset]
        offset += 1 + sess_len
        if offset + 2 > len(raw):
            return ""
        cipher_len = int.from_bytes(raw[offset:offset+2], "big")
        offset += 2 + cipher_len
        if offset >= len(raw):
            return ""
        comp_len = raw[offset]
        offset += 1 + comp_len
        if offset + 2 > len(raw):
            return ""
        ext_total = int.from_bytes(raw[offset:offset+2], "big")
        offset += 2
        end = offset + ext_total
        while offset + 4 <= end and offset + 4 <= len(raw):
            ext_type = int.from_bytes(raw[offset:offset+2], "big")
            ext_len  = int.from_bytes(raw[offset+2:offset+4], "big")
            offset += 4
            if ext_type == 0x0000:  # SNI
                # server_name_list_length (2) + type (1) + name_length (2) + name
                name_start = offset + 5
                name_len   = int.from_bytes(raw[offset+3:offset+5], "big")
                sni = raw[name_start:name_start+name_len].decode("utf-8", errors="replace")
                return sni
            offset += ext_len
    except Exception:
        pass
    return ""

def _format_hex_dump(data: bytes) -> str:
    """Genera un dump hex+ASCII legible, 16 bytes por línea."""
    if not data:
        return ""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)

# ── Gestor global de sesiones de captura ────────────────────────────────────

_sessions: dict[str, CaptureSession] = {}

def start_capture(target_ip: str, my_ip: str = None, callback=None) -> dict:
    if not SCAPY_AVAILABLE:
        return {
            "ok": False,
            "msg": "Scapy no está instalado o Npcap no está presente. "
                   "Instala Npcap desde https://npcap.com y ejecuta: pip install scapy",
        }
    session_id = f"cap_{target_ip}_{int(time.time())}"
    session = CaptureSession(target_ip, session_id)
    ok = session.start(my_ip=my_ip, callback=callback)
    if ok:
        _sessions[session_id] = session
        return {"ok": True, "session_id": session_id, "target_ip": target_ip}
    return {"ok": False, "msg": "No se pudo iniciar la captura"}

def stop_capture(session_id: str) -> dict:
    if session_id in _sessions:
        _sessions[session_id].stop()
        return {"ok": True, "msg": f"Captura {session_id} detenida"}
    return {"ok": False, "msg": "Sesión no encontrada"}

def get_capture_packets(session_id: str) -> list:
    if session_id in _sessions:
        return list(_sessions[session_id].packets)
    return []

def get_capture_stats(session_id: str) -> dict:
    if session_id in _sessions:
        return _sessions[session_id].stats
    return {}

def list_sessions() -> list:
    return [
        {
            "session_id": sid,
            "target_ip": s.target_ip,
            "active": s.active,
            "total": s.stats["total"],
            "started": s.stats["started"],
        }
        for sid, s in _sessions.items()
    ]

def is_scapy_available() -> bool:
    return SCAPY_AVAILABLE
