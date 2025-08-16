"""
RBAC权限装饰器模块
可以单独导入使用的权限控制装饰器
"""
from flask import request, jsonify, g
from functools import wraps
import jwt
from datetime import datetime, timedelta


class RBACManager:
    """RBAC权限管理器"""
    
    def __init__(self, app=None, secret_key=None):
        self.app = app
        self.secret_key = secret_key
        self.users = {}
        self.role_permissions = {}
        self.resource_permissions = {}
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """初始化Flask应用"""
        self.app = app
        if not self.secret_key:
            self.secret_key = app.config.get('SECRET_KEY', 'default-secret-key')
    
    def set_users(self, users):
        """设置用户数据"""
        self.users = users
    
    def set_role_permissions(self, role_permissions):
        """设置角色权限映射"""
        self.role_permissions = role_permissions
    
    def set_resource_permissions(self, resource_permissions):
        """设置资源权限映射"""
        self.resource_permissions = resource_permissions
    
    def get_user_permissions(self, user_roles):
        """获取用户的所有权限"""
        permissions = set()
        for role in user_roles:
            if role in self.role_permissions:
                permissions.update(self.role_permissions[role])
        return list(permissions)
    
    def token_required(self, f):
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
                data = jwt.decode(token, self.secret_key, algorithms=['HS256'])
                current_user = None
                for user_data in self.users.values():
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
    
    def require_permission(self, required_permissions):
        """权限验证装饰器"""
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                if not hasattr(g, 'current_user'):
                    return jsonify({'message': 'Authentication required'}), 401
                
                user_permissions = self.get_user_permissions(g.current_user['roles'])
                
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
    
    def require_role(self, required_roles):
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
    
    def rbac_check(self, resource_path=None):
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
                if path in self.resource_permissions and method in self.resource_permissions[path]:
                    required_permissions = self.resource_permissions[path][method]
                    user_permissions = self.get_user_permissions(g.current_user['roles'])
                    
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
    
    def generate_token(self, user_data, expires_in_hours=24):
        """生成JWT token"""
        token = jwt.encode({
            'user_id': user_data['id'],
            'username': user_data['username'],
            'roles': user_data['roles'],
            'exp': datetime.utcnow() + timedelta(hours=expires_in_hours)
        }, self.secret_key, algorithm='HS256')
        return token
    
    def verify_password(self, username, password):
        """验证用户密码"""
        user = self.users.get(username)
        if user:
            import hashlib
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            return user['password'] == hashed_password
        return False
    
    def authenticate_user(self, username, password):
        """认证用户并返回token"""
        if self.verify_password(username, password):
            user = self.users[username]
            token = self.generate_token(user)
            return {
                'success': True,
                'token': token,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'roles': user['roles']
                }
            }
        return {'success': False, 'message': 'Invalid credentials'}


# 创建全局RBAC管理器实例
rbac = RBACManager()

# 便捷函数
def token_required(f):
    """便捷的token验证装饰器"""
    return rbac.token_required(f)

def require_permission(permissions):
    """便捷的权限验证装饰器"""
    return rbac.require_permission(permissions)

def require_role(roles):
    """便捷的角色验证装饰器"""
    return rbac.require_role(roles)

def rbac_check(resource_path=None):
    """便捷的资源RBAC检查装饰器"""
    return rbac.rbac_check(resource_path)
