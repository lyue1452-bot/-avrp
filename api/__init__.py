"""API Blueprint 聚合入口。"""
from flask import Blueprint

api_bp = Blueprint("api", __name__, url_prefix="/api")

from api.auth import auth_bp
from api.dashboard import dashboard_bp
from api.vulns import vulns_bp
from api.tasks import tasks_bp
from api.reports import reports_bp
from api.settings import settings_bp
from api.users import users_bp
from api.pipeline import pipeline_bp

api_bp.register_blueprint(auth_bp)
api_bp.register_blueprint(dashboard_bp)
api_bp.register_blueprint(vulns_bp)
api_bp.register_blueprint(tasks_bp)
api_bp.register_blueprint(reports_bp)
api_bp.register_blueprint(settings_bp)
api_bp.register_blueprint(users_bp)
api_bp.register_blueprint(pipeline_bp)
