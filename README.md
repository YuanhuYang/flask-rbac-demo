# Flask RBAC 权限控制装饰器演示

这个项目演示了如何使用 Flask 实现基于角色的访问控制 (RBAC) 系统，包含多个权限控制装饰器。

## 功能特点

### 1. 装饰器类型
- **`@token_required`**: JWT token验证装饰器
- **`@require_permission`**: 基于权限的访问控制
- **`@require_role`**: 基于角色的访问控制  
- **`@rbac_check`**: 基于资源路径的自动权限检查

### 2. 权限系统设计
- **用户 (Users)**: 拥有用户名、密码和角色
- **角色 (Roles)**: admin, manager, user
- **权限 (Permissions)**: read, write, delete, manage_users, manage_team
- **资源 (Resources)**: API端点和HTTP方法的组合

### 3. 预设用户
- **admin**: 密码 `admin123`, 角色 `['admin']`
- **manager**: 密码 `manager123`, 角色 `['manager', 'user']`
- **user1**: 密码 `user123`, 角色 `['user']`

### 4. 权限映射
```
admin: ['read', 'write', 'delete', 'manage_users']
manager: ['read', 'write', 'manage_team']
user: ['read']
```

## 安装和运行

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 启动服务器
```bash
python app.py
```

服务器将在 `http://localhost:5000` 启动

### 3. 运行测试
```bash
chmod +x test_api.sh
./test_api.sh
```

## API 端点说明

### 认证相关
- `POST /api/login` - 用户登录，获取JWT token

### 用户信息
- `GET /api/profile` - 获取当前用户资料

### 用户管理 (需要相应权限)
- `GET /api/users` - 获取用户列表 (需要 read 权限)
- `POST /api/users` - 创建用户 (需要 manage_users 权限)
- `DELETE /api/users/<id>` - 删除用户 (需要 admin 角色)

### 数据管理 (基于资源的RBAC)
- `GET /api/data` - 获取数据 (需要 read 权限)
- `POST /api/data` - 创建数据 (需要 write 权限)

### 团队管理
- `GET /api/team` - 获取团队信息 (需要 read 或 manage_team 权限)
- `POST /api/team` - 管理团队 (需要 manage_team 权限)

### 管理员功能
- `GET /api/admin/stats` - 获取系统统计 (需要 admin 角色)

## 装饰器使用示例

### 1. Token验证
```python
@app.route('/api/profile')
@token_required
def get_profile():
    return jsonify({'user': g.current_user})
```

### 2. 权限验证
```python
@app.route('/api/users', methods=['POST'])
@token_required
@require_permission('manage_users')
def create_user():
    # 只有拥有manage_users权限的用户才能访问
    pass
```

### 3. 角色验证
```python
@app.route('/api/admin/stats')
@token_required
@require_role('admin')
def admin_stats():
    # 只有admin角色才能访问
    pass
```

### 4. 基于资源的RBAC
```python
@app.route('/api/data', methods=['GET'])
@token_required
@rbac_check()
def get_data():
    # 自动根据资源路径和HTTP方法检查权限
    pass
```

## 测试用例

使用提供的测试脚本可以验证以下场景：

1. **认证测试**: 不同用户的登录
2. **权限测试**: 用户访问需要特定权限的API
3. **角色测试**: 用户访问需要特定角色的API
4. **资源RBAC测试**: 基于资源路径的自动权限检查
5. **错误处理**: 无权限访问时的错误响应

## 扩展建议

1. **数据库集成**: 将用户、角色、权限存储到数据库
2. **动态权限**: 支持运行时动态修改权限配置
3. **细粒度控制**: 支持对象级别的权限控制
4. **审计日志**: 记录所有权限检查和访问日志
5. **权限继承**: 支持角色层次和权限继承

## 安全注意事项

1. 使用强密码和安全的JWT密钥
2. 定期轮换JWT密钥
3. 实现token刷新机制
4. 添加请求频率限制
5. 使用HTTPS进行传输加密
