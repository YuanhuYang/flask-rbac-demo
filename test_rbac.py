"""
Flask RBAC 装饰器单元测试
"""
import unittest
import json
from app import app, USERS, ROLE_PERMISSIONS

class FlaskRBACTestCase(unittest.TestCase):
    def setUp(self):
        """测试前设置"""
        self.app = app.test_client()
        self.app.testing = True
    
    def login_user(self, username, password):
        """辅助方法：用户登录获取token"""
        response = self.app.post('/api/login',
                                data=json.dumps({
                                    'username': username,
                                    'password': password
                                }),
                                content_type='application/json')
        if response.status_code == 200:
            data = json.loads(response.data)
            return data['token']
        return None
    
    def test_login_success(self):
        """测试成功登录"""
        response = self.app.post('/api/login',
                                data=json.dumps({
                                    'username': 'admin',
                                    'password': 'admin123'
                                }),
                                content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)
        self.assertEqual(data['user']['username'], 'admin')
    
    def test_login_failure(self):
        """测试登录失败"""
        response = self.app.post('/api/login',
                                data=json.dumps({
                                    'username': 'admin',
                                    'password': 'wrongpassword'
                                }),
                                content_type='application/json')
        
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Invalid credentials')
    
    def test_access_without_token(self):
        """测试无token访问受保护资源"""
        response = self.app.get('/api/profile')
        self.assertEqual(response.status_code, 401)
        
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Token is missing')
    
    def test_profile_access_with_token(self):
        """测试有效token访问用户资料"""
        token = self.login_user('admin', 'admin123')
        self.assertIsNotNone(token)
        
        response = self.app.get('/api/profile',
                               headers={'Authorization': f'Bearer {token}'})
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['user']['username'], 'admin')
    
    def test_permission_based_access(self):
        """测试基于权限的访问控制"""
        # 管理员应该能够创建用户（有manage_users权限）
        admin_token = self.login_user('admin', 'admin123')
        response = self.app.post('/api/users',
                                headers={'Authorization': f'Bearer {admin_token}'},
                                data=json.dumps({'username': 'newuser'}),
                                content_type='application/json')
        self.assertEqual(response.status_code, 200)
        
        # 普通用户不应该能够创建用户（没有manage_users权限）
        user_token = self.login_user('user1', 'user123')
        response = self.app.post('/api/users',
                                headers={'Authorization': f'Bearer {user_token}'},
                                data=json.dumps({'username': 'newuser'}),
                                content_type='application/json')
        self.assertEqual(response.status_code, 403)
    
    def test_role_based_access(self):
        """测试基于角色的访问控制"""
        # 管理员应该能够删除用户（admin角色）
        admin_token = self.login_user('admin', 'admin123')
        response = self.app.delete('/api/users/1',
                                  headers={'Authorization': f'Bearer {admin_token}'})
        self.assertEqual(response.status_code, 200)
        
        # 普通用户不应该能够删除用户（不是admin角色）
        user_token = self.login_user('user1', 'user123')
        response = self.app.delete('/api/users/1',
                                  headers={'Authorization': f'Bearer {user_token}'})
        self.assertEqual(response.status_code, 403)
    
    def test_rbac_resource_based_access(self):
        """测试基于资源的RBAC访问控制"""
        # 用户应该能够读取数据（有read权限）
        user_token = self.login_user('user1', 'user123')
        response = self.app.get('/api/data',
                               headers={'Authorization': f'Bearer {user_token}'})
        self.assertEqual(response.status_code, 200)
        
        # 用户不应该能够创建数据（没有write权限）
        response = self.app.post('/api/data',
                                headers={'Authorization': f'Bearer {user_token}'},
                                data=json.dumps({'data': 'test'}),
                                content_type='application/json')
        self.assertEqual(response.status_code, 403)
        
        # 经理应该能够创建数据（有write权限）
        manager_token = self.login_user('manager', 'manager123')
        response = self.app.post('/api/data',
                                headers={'Authorization': f'Bearer {manager_token}'},
                                data=json.dumps({'data': 'test'}),
                                content_type='application/json')
        self.assertEqual(response.status_code, 200)
    
    def test_multiple_permissions(self):
        """测试多权限要求"""
        # 测试team API，需要read或manage_team权限
        user_token = self.login_user('user1', 'user123')  # 有read权限
        response = self.app.get('/api/team',
                               headers={'Authorization': f'Bearer {user_token}'})
        self.assertEqual(response.status_code, 200)
        
        manager_token = self.login_user('manager', 'manager123')  # 有manage_team权限
        response = self.app.get('/api/team',
                               headers={'Authorization': f'Bearer {manager_token}'})
        self.assertEqual(response.status_code, 200)
    
    def test_admin_only_access(self):
        """测试仅管理员访问"""
        # 管理员应该能够访问统计信息
        admin_token = self.login_user('admin', 'admin123')
        response = self.app.get('/api/admin/stats',
                               headers={'Authorization': f'Bearer {admin_token}'})
        self.assertEqual(response.status_code, 200)
        
        # 经理不应该能够访问管理员统计（不是admin角色）
        manager_token = self.login_user('manager', 'manager123')
        response = self.app.get('/api/admin/stats',
                               headers={'Authorization': f'Bearer {manager_token}'})
        self.assertEqual(response.status_code, 403)
    
    def test_invalid_token(self):
        """测试无效token"""
        response = self.app.get('/api/profile',
                               headers={'Authorization': 'Bearer invalid_token'})
        self.assertEqual(response.status_code, 401)
    
    def test_malformed_authorization_header(self):
        """测试格式错误的Authorization头"""
        response = self.app.get('/api/profile',
                               headers={'Authorization': 'InvalidFormat'})
        self.assertEqual(response.status_code, 401)
        
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Invalid token format')


if __name__ == '__main__':
    # 运行测试
    unittest.main(verbosity=2)
