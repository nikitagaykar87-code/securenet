import jwt
from datetime import datetime, timedelta
from config import JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRE_HOURS


def generate_token(user_id, email, role):
    payload = {
        "user_id": user_id,
        "email": email,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token):
    try:
        decoded = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        return decoded

    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# Decorator for protected routes
def token_required(f):
    from functools import wraps
    from flask import request, jsonify
    
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'success': False, 'message': 'Token is missing'}), 401
        
        # Decode token
        current_user = decode_token(token)
        
        if not current_user:
            return jsonify({'success': False, 'message': 'Token is invalid or expired'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated
