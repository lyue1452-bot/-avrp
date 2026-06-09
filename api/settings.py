"""系统设置接口。"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required

from models import get_all_settings, set_setting

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("", methods=["GET"])
@jwt_required()
def get_settings():
    settings = get_all_settings()
    return jsonify({"ok": True, "data": settings})


@settings_bp.route("", methods=["PUT"])
@jwt_required()
def update_settings():
    data = request.get_json() or {}
    for key, value in data.items():
        set_setting(key, str(value))
    return jsonify({"ok": True, "msg": "设置已保存"})
