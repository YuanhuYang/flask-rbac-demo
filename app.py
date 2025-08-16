from flask import Flask, request, jsonify, g
from functools import wraps
import jwt
from datetime import datetime, timedelta
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# 模拟用户数据库
USERS = {
    'admin': {
        'id': 1,
        'username': 'admin',
        'password': hashlib.sha256('admin123'.encode()).hexdigest(),
        'roles': ['admin']
    },
    'user1': {
        'id': 2,
        'username': 'user1',
        'password': hashlib.sha256('user123'.encode()).hexdigest(),
        'roles': ['user']
    },
    'manager': {
        'id': 3,
        'username': 'manager',
        'password': hashlib.sha256('manager123'.encode()).hexdigest(),
        'roles': ['manager', 'user']
    }
}

# 角色权限映射
ROLE_PERMISSIONS = {
    'admin': ['read', 'write', 'delete', 'manage_users'],
    'manager': ['read', 'write', 'manage_team'],
    'user': ['read']
}

# 资源权限映射
RESOURCE_PERMISSIONS = {
    '/api/users': {
        'GET': ['read'],
        'POST': ['write', 'manage_users'],
        'PUT': ['write', 'manage_users'],
        'DELETE': ['delete', 'manage_users']
    },
    '/api/data': {
        'GET': ['read'],
        'POST': ['write'],
        'PUT': ['write'],
        'DELETE': ['delete']
    },
    '/api/team': {
        'GET': ['read'],
        'POST': ['manage_team'],
        'PUT': ['manage_team'],
        'DELETE': ['manage_team']
    }
}


def get_user_permissions(user_roles):
    """获取用户的所有权限"""
    permissions = set()
    for role in user_roles:
        if role in ROLE_PERMISSIONS:
            permissions.update(ROLE_PERMISSIONS[role])
    return list(permissions)


def token_required(f):
    """JWT token验证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'message': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = None
            for user_data in USERS.values():
                if user_data['id'] == data['user_id']:
                    current_user = user_data
                    break
            
            if not current_user:
                return jsonify({'message': 'Invalid token'}), 401
                
            g.current_user = current_user
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated


def require_permission(required_permissions):
    """权限验证装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'message': 'Authentication required'}), 401
            
            user_permissions = get_user_permissions(g.current_user['roles'])
            
            # 检查用户是否拥有所需的任何一个权限
            if isinstance(required_permissions, str):
                required_perms = [required_permissions]
            else:
                required_perms = required_permissions
            
            has_permission = any(perm in user_permissions for perm in required_perms)
            
            if not has_permission:
                return jsonify({
                    'message': 'Insufficient permissions',
                    'required': required_perms,
                    'user_permissions': user_permissions
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_role(required_roles):
    """角色验证装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'message': 'Authentication required'}), 401
            
            user_roles = g.current_user['roles']
            
            # 检查用户是否拥有所需的任何一个角色
            if isinstance(required_roles, str):
                required_role_list = [required_roles]
            else:
                required_role_list = required_roles
            
            has_role = any(role in user_roles for role in required_role_list)
            
            if not has_role:
                return jsonify({
                    'message': 'Insufficient role',
                    'required_roles': required_role_list,
                    'user_roles': user_roles
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


def rbac_check(resource_path=None):
    """基于资源的RBAC检查装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'message': 'Authentication required'}), 401
            
            # 确定资源路径
            path = resource_path or request.path
            method = request.method
            
            # 获取资源所需的权限
            if path in RESOURCE_PERMISSIONS and method in RESOURCE_PERMISSIONS[path]:
                required_permissions = RESOURCE_PERMISSIONS[path][method]
                user_permissions = get_user_permissions(g.current_user['roles'])
                
                # 检查权限
                has_permission = any(perm in user_permissions for perm in required_permissions)
                
                if not has_permission:
                    return jsonify({
                        'message': 'Access denied',
                        'resource': path,
                        'method': method,
                        'required_permissions': required_permissions,
                        'user_permissions': user_permissions
                    }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


# 认证相关路由
@app.route('/api/login', methods=['POST'])
def login():
    """用户登录"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    
    # 验证用户
    user = USERS.get(username)
    if user and user['password'] == hashlib.sha256(password.encode()).hexdigest():
        # 生成JWT token
        token = jwt.encode({
            'user_id': user['id'],
            'username': user['username'],
            'roles': user['roles'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'roles': user['roles']
            }
        })
    
    return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile():
    """获取用户资料"""
    return jsonify({
        'user': {
            'id': g.current_user['id'],
            'username': g.current_user['username'],
            'roles': g.current_user['roles'],
            'permissions': get_user_permissions(g.current_user['roles'])
        }
    })


# 受保护的API路由示例
@app.route('/api/users', methods=['GET'])
@token_required
@require_permission('read')
def get_users():
    """获取用户列表 - 需要read权限"""
    users = []
    for user in USERS.values():
        users.append({
            'id': user['id'],
            'username': user['username'],
            'roles': user['roles']
        })
    return jsonify({'users': users})


@app.route('/api/users', methods=['POST'])
@token_required
@require_permission('manage_users')
def create_user():
    """创建用户 - 需要manage_users权限"""
    data = request.get_json()
    return jsonify({
        'message': 'User created successfully',
        'data': data
    })


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required
@require_role('admin')
def delete_user(user_id):
    """删除用户 - 需要admin角色"""
    return jsonify({
        'message': f'User {user_id} deleted successfully'
    })


@app.route('/api/data', methods=['GET'])
@token_required
@rbac_check()
def get_data():
    """获取数据 - 使用基于资源的RBAC检查"""
    return jsonify({
        'data': 'This is some protected data',
        'access_time': datetime.now().isoformat()
    })


@app.route('/api/data', methods=['POST'])
@token_required
@rbac_check()
def create_data():
    """创建数据 - 使用基于资源的RBAC检查"""
    data = request.get_json()
    return jsonify({
        'message': 'Data created successfully',
        'data': data
    })


@app.route('/api/team', methods=['GET'])
@token_required
@require_permission(['read', 'manage_team'])
def get_team():
    """获取团队信息 - 需要read或manage_team权限"""
    return jsonify({
        'team': 'Development Team',
        'members': ['user1', 'manager']
    })


@app.route('/api/team', methods=['POST'])
@token_required
@require_permission('manage_team')
def manage_team():
    """管理团队 - 需要manage_team权限"""
    data = request.get_json()
    return jsonify({
        'message': 'Team updated successfully',
        'data': data
    })


@app.route('/api/admin/stats', methods=['GET'])
@token_required
@require_role('admin')
def admin_stats():
    """管理员统计 - 需要admin角色"""
    return jsonify({
        'total_users': len(USERS),
        'total_roles': len(ROLE_PERMISSIONS),
        'system_status': 'running'
    })


# 错误处理
@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'message': 'Internal server error'}), 500


if __name__ == '__main__':
    print("Flask RBAC Demo Server")
    print("Available users:")
    for username, user in USERS.items():
        print(f"  {username}: roles={user['roles']}, password={username}123")
    print("\nStarting server on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
