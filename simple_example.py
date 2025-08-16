"""
Flask RBAC装饰器使用示例 - 简化版本
演示基本的权限控制装饰器用法
"""

from flask import Flask, request, jsonify, g
from functools import wraps
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# 模拟数据
USERS = {
    'admin': {'id': 1, 'password': 'admin123', 'roles': ['admin']},
    'user': {'id': 2, 'password': 'user123', 'roles': ['user']}
}

PERMISSIONS = {
    'admin': ['read', 'write', 'delete'],
    'user': ['read']
}


def get_user_permissions(roles):
    """获取用户权限"""
    perms = set()
    for role in roles:
        perms.update(PERMISSIONS.get(role, []))
    return list(perms)


def token_required(f):
    """JWT认证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        
        try:
            token = token.split(' ')[1]  # 移除 'Bearer ' 前缀
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user = data
        except:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated


def require_permission(permission):
    """权限验证装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            user_perms = get_user_permissions(g.current_user['roles'])
            if permission not in user_perms:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required': permission,
                    'user_permissions': user_perms
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_role(role):
    """角色验证装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            if role not in g.current_user['roles']:
                return jsonify({
                    'error': 'Insufficient role',
                    'required': role,
                    'user_roles': g.current_user['roles']
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


# API 路由
@app.route('/login', methods=['POST'])
def login():
    """用户登录"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = USERS.get(username)
    if user and user['password'] == password:
        token = jwt.encode({
            'id': user['id'],
            'username': username,
            'roles': user['roles'],
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'])
        
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/profile')
@token_required
def profile():
    """用户资料 - 需要登录"""
    return jsonify({
        'user': g.current_user['username'],
        'roles': g.current_user['roles'],
        'permissions': get_user_permissions(g.current_user['roles'])
    })


@app.route('/data')
@token_required
@require_permission('read')
def get_data():
    """获取数据 - 需要read权限"""
    return jsonify({'data': 'This is some data'})


@app.route('/data', methods=['POST'])
@token_required
@require_permission('write')
def create_data():
    """创建数据 - 需要write权限"""
    return jsonify({'message': 'Data created'})


@app.route('/admin')
@token_required
@require_role('admin')
def admin_only():
    """管理员专用 - 需要admin角色"""
    return jsonify({'message': 'Admin area'})


if __name__ == '__main__':
    print("Simple Flask RBAC Example")
    print("Users: admin/admin123 (admin), user/user123 (user)")
    print("\nTesting:")
    print("1. POST /login with credentials")
    print("2. Use returned token in Authorization: Bearer <token>")
    print("3. Access /profile, /data, /admin with different users")
    app.run(debug=True, port=5002)
