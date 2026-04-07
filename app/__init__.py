import os
import secrets
from flask import Flask
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")

def create_app():
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    # Usa SECRET_KEY del entorno si existe, o genera una aleatoria por sesión
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

    socketio.init_app(app)

    from .routes import bp
    app.register_blueprint(bp)

    return app
