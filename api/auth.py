"""JWT 认证接口。"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required,
    get_jwt_identity,
)
import bcrypt

from models import create_user, get_user_by_username, get_user_by_id, count_users

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


@auth_bp.route("/init", methods=["POST"])
def init_admin():
    """首次初始化管理员账号（只在无用户时可用）"""
    if count_users() > 0:
        return jsonify({"ok": False, "msg": "系统已初始化"}), 400

    data = request.get_json() or {}
    username = data.get("username", "admin")
    password = data.get("password", "admin123")
    hashed = _hash_password(password)
    create_user(username, hashed, display_name="管理员", role="admin")
    return jsonify({"ok": True, "msg": f"管理员账号已创建: {username}"})


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = get_user_by_username(username)
    if not user or not _check_password(password, user["password_hash"]):
        return jsonify({"ok": False, "msg": "用户名或密码错误"}), 401

    if not user["is_active"]:
        return jsonify({"ok": False, "msg": "账号已禁用"}), 403

    from config import JWT_EXPIRY_HOURS
    from datetime import timedelta

    access_token = create_access_token(
        identity=str(user["id"]),
        additional_claims={"role": user["role"], "username": user["username"]},
        expires_delta=timedelta(hours=JWT_EXPIRY_HOURS),
    )
    refresh_token = create_refresh_token(identity=str(user["id"]))

    return jsonify({
        "ok": True,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
    })


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    uid = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user:
        return jsonify({"ok": False, "msg": "用户不存在"}), 404

    from config import JWT_EXPIRY_HOURS
    from datetime import timedelta

    access_token = create_access_token(
        identity=str(uid),
        additional_claims={"role": user["role"], "username": user["username"]},
        expires_delta=timedelta(hours=JWT_EXPIRY_HOURS),
    )
    return jsonify({"ok": True, "access_token": access_token})


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    uid = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user:
        return jsonify({"ok": False, "msg": "用户不存在"}), 404
    return jsonify({"ok": True, "user": dict(user)})
