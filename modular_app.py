"""
使用独立RBAC装饰器模块的示例应用
演示如何将RBAC功能模块化
"""
from flask import Flask, request, jsonify, g
from rbac_decorators import RBACManager
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# 创建RBAC管理器
rbac = RBACManager(app)

# 配置用户数据
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

# 配置角色权限
ROLE_PERMISSIONS = {
    'admin': ['read', 'write', 'delete', 'manage_users'],
    'manager': ['read', 'write', 'manage_team'],
    'user': ['read']
}

# 配置资源权限
RESOURCE_PERMISSIONS = {
    '/api/data': {
        'GET': ['read'],
        'POST': ['write'],
        'PUT': ['write'],
        'DELETE': ['delete']
    }
}

# 设置RBAC配置
rbac.set_users(USERS)
rbac.set_role_permissions(ROLE_PERMISSIONS)
rbac.set_resource_permissions(RESOURCE_PERMISSIONS)


@app.route('/api/login', methods=['POST'])
def login():
    """用户登录"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    
    result = rbac.authenticate_user(username, password)
    
    if result['success']:
        return jsonify({
            'message': 'Login successful',
            'token': result['token'],
            'user': result['user']
        })
    else:
        return jsonify({'message': result['message']}), 401


@app.route('/api/profile', methods=['GET'])
@rbac.token_required
def get_profile():
    """获取用户资料"""
    return jsonify({
        'user': {
            'id': g.current_user['id'],
            'username': g.current_user['username'],
            'roles': g.current_user['roles'],
            'permissions': rbac.get_user_permissions(g.current_user['roles'])
        }
    })


@app.route('/api/users', methods=['GET'])
@rbac.token_required
@rbac.require_permission('read')
def get_users():
    """获取用户列表"""
    users = []
    for user in USERS.values():
        users.append({
            'id': user['id'],
            'username': user['username'],
            'roles': user['roles']
        })
    return jsonify({'users': users})


@app.route('/api/users', methods=['POST'])
@rbac.token_required
@rbac.require_permission('manage_users')
def create_user():
    """创建用户"""
    data = request.get_json()
    return jsonify({
        'message': 'User created successfully',
        'data': data
    })


@app.route('/api/admin/stats', methods=['GET'])
@rbac.token_required
@rbac.require_role('admin')
def admin_stats():
    """管理员统计"""
    return jsonify({
        'total_users': len(USERS),
        'total_roles': len(ROLE_PERMISSIONS),
        'system_status': 'running'
    })


@app.route('/api/data', methods=['GET', 'POST'])
@rbac.token_required
@rbac.rbac_check()
def handle_data():
    """处理数据请求 - 使用基于资源的RBAC"""
    if request.method == 'GET':
        return jsonify({
            'data': 'This is some protected data',
            'method': 'GET'
        })
    elif request.method == 'POST':
        data = request.get_json()
        return jsonify({
            'message': 'Data created successfully',
            'data': data,
            'method': 'POST'
        })


if __name__ == '__main__':
    print("Flask RBAC Modular Demo")
    print("Available users:")
    for username, user in USERS.items():
        print(f"  {username}: roles={user['roles']}, password={username}123")
    print("\nStarting server on http://localhost:5001")
    app.run(debug=True, host='0.0.0.0', port=5001)
