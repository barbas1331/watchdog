"""
run.py — Punto de entrada del Watchdog de Red.
Ejecutar como Administrador para acceso completo (firewall + captura de paquetes).
"""

import os
import sys
import ctypes
import webbrowser
import threading

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def elevate():
    """Reinicia el proceso como Administrador si no lo es ya."""
    script = os.path.abspath(__file__)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}"', None, 1
    )
    sys.exit()

if __name__ == "__main__":
    from app import create_app, socketio

    if not is_admin():
        print("=" * 60)
        print("  ⚠  ADVERTENCIA: No estás ejecutando como Administrador.")
        print("     La captura de paquetes y el bloqueo en firewall")
        print("     pueden no funcionar correctamente.")
        print("     Reinicia con: clic derecho → Ejecutar como admin")
        print("=" * 60)

    app = create_app()

    HOST = "127.0.0.1"
    PORT = 5757

    print(f"""
╔══════════════════════════════════════════════════════╗
║           🔍  WATCHDOG DE RED  —  Privacidad         ║
╠══════════════════════════════════════════════════════╣
║  Admin: {'✅ SÍ' if is_admin() else '❌ NO (algunas funciones limitadas)'}
║  Panel: http://{HOST}:{PORT}
╚══════════════════════════════════════════════════════╝
    """)

    # Abrir el navegador automáticamente tras un pequeño delay
    def open_browser():
        import time
        time.sleep(1.5)
        webbrowser.open(f"http://{HOST}:{PORT}")

    threading.Thread(target=open_browser, daemon=True).start()

    socketio.run(app, host=HOST, port=PORT, debug=False,
                 use_reloader=False, allow_unsafe_werkzeug=True)
