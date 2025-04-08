from flask import Flask
from flask_wtf.csrf import CSRFProtect
from config import Config
from .extensions import db, migrate


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    csrf = CSRFProtect(app)

    db.init_app(app)
    migrate.init_app(app, db)

    from . import routes
    app.register_blueprint(routes.main_bp)

    return app