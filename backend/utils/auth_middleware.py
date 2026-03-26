from flask import request, jsonify
from functools import wraps
from utils.jwt_utils import decode_token


def jwt_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Allow OPTIONS requests to pass through (CORS preflight)
            if request.method == "OPTIONS":
                return "", 200

            auth_header = request.headers.get("Authorization")

            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({
                    "success": False,
                    "message": "Authorization token missing"
                }), 401

            token = auth_header.split(" ")[1]
            decoded = decode_token(token)

            if not decoded:
                return jsonify({
                    "success": False,
                    "message": "Invalid or expired token"
                }), 401

            if role and decoded.get("role") != role:
                return jsonify({
                    "success": False,
                    "message": "Access denied"
                }), 403

            # Attach user info to request (optional but useful)
            request.user = decoded

            return fn(*args, **kwargs)

        return wrapper
    return decorator
