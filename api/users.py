"""用户管理接口（admin only）。"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt

from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity

from models import (
    list_users, get_user_by_id, create_user, update_user, delete_user,
)
from api.auth import _hash_password

users_bp = Blueprint("users", __name__, url_prefix="/users")


def _require_admin():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return False
    return True


@users_bp.route("")
@jwt_required()
def user_list():
    if not _require_admin():
        return jsonify({"ok": False, "msg": "需要管理员权限"}), 403
    users = list_users()
    return jsonify({"ok": True, "data": users})


@users_bp.route("", methods=["POST"])
@jwt_required()
def user_create():
    if not _require_admin():
        return jsonify({"ok": False, "msg": "需要管理员权限"}), 403

    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"ok": False, "msg": "用户名和密码不能为空"}), 400

    from models import get_user_by_username
    if get_user_by_username(username):
        return jsonify({"ok": False, "msg": "用户名已存在"}), 400

    hashed = _hash_password(password)
    role = data.get("role", "user")
    display_name = data.get("display_name", "")
    uid = create_user(username, hashed, display_name=display_name, role=role)
    return jsonify({"ok": True, "msg": "用户已创建", "id": uid})


@users_bp.route("/<int:uid>", methods=["PUT"])
@jwt_required()
def user_update(uid):
    if not _require_admin():
        return jsonify({"ok": False, "msg": "需要管理员权限"}), 403

    data = request.get_json() or {}
    ok = update_user(uid, **data)
    if not ok:
        return jsonify({"ok": False, "msg": "用户不存在或无字段更新"}), 404
    return jsonify({"ok": True, "msg": "已更新"})


@users_bp.route("/<int:uid>", methods=["DELETE"])
@jwt_required()
def user_delete(uid):
    if not _require_admin():
        return jsonify({"ok": False, "msg": "需要管理员权限"}), 403

    # 禁止删除自己
    current_uid = int(get_jwt_identity())
    if uid == current_uid:
        return jsonify({"ok": False, "msg": "不能删除自己"}), 400

    ok = delete_user(uid)
    if not ok:
        return jsonify({"ok": False, "msg": "用户不存在"}), 404
    return jsonify({"ok": True, "msg": "已删除"})


@users_bp.route("/<int:uid>/password", methods=["PUT"])
@jwt_required()
def user_password(uid):
    if not _require_admin():
        return jsonify({"ok": False, "msg": "需要管理员权限"}), 403

    data = request.get_json() or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"ok": False, "msg": "密码不能为空"}), 400

    hashed = _hash_password(password)
    ok = update_user(uid, password_hash=hashed)
    if not ok:
        return jsonify({"ok": False, "msg": "用户不存在"}), 404
    return jsonify({"ok": True, "msg": "密码已重置"})
