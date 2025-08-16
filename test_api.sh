#!/bin/bash

# Flask RBAC API 测试脚本

BASE_URL="http://localhost:5000"

echo "=== Flask RBAC API 测试 ==="
echo

# 1. 登录获取token
echo "1. 测试用户登录..."
echo "--- 管理员登录 ---"
ADMIN_TOKEN=$(curl -s -X POST ${BASE_URL}/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' | \
    python3 -c "import sys, json; print(json.load(sys.stdin)['token'])" 2>/dev/null)

echo "Admin Token: ${ADMIN_TOKEN:0:50}..."

echo "--- 普通用户登录 ---"
USER_TOKEN=$(curl -s -X POST ${BASE_URL}/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"user1","password":"user123"}' | \
    python3 -c "import sys, json; print(json.load(sys.stdin)['token'])" 2>/dev/null)

echo "User Token: ${USER_TOKEN:0:50}..."

echo "--- 经理登录 ---"
MANAGER_TOKEN=$(curl -s -X POST ${BASE_URL}/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"manager","password":"manager123"}' | \
    python3 -c "import sys, json; print(json.load(sys.stdin)['token'])" 2>/dev/null)

echo "Manager Token: ${MANAGER_TOKEN:0:50}..."
echo

# 2. 测试用户资料
echo "2. 测试获取用户资料..."
echo "--- 管理员资料 ---"
curl -s -X GET ${BASE_URL}/api/profile \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | python3 -m json.tool
echo

echo "--- 普通用户资料 ---"
curl -s -X GET ${BASE_URL}/api/profile \
    -H "Authorization: Bearer ${USER_TOKEN}" | python3 -m json.tool
echo

# 3. 测试权限控制
echo "3. 测试权限控制..."
echo "--- 管理员获取用户列表 (应该成功) ---"
curl -s -X GET ${BASE_URL}/api/users \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | python3 -m json.tool
echo

echo "--- 普通用户获取用户列表 (应该成功，因为有read权限) ---"
curl -s -X GET ${BASE_URL}/api/users \
    -H "Authorization: Bearer ${USER_TOKEN}" | python3 -m json.tool
echo

echo "--- 普通用户创建用户 (应该失败，没有manage_users权限) ---"
curl -s -X POST ${BASE_URL}/api/users \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"username":"newuser","roles":["user"]}' | python3 -m json.tool
echo

echo "--- 管理员创建用户 (应该成功) ---"
curl -s -X POST ${BASE_URL}/api/users \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"username":"newuser","roles":["user"]}' | python3 -m json.tool
echo

# 4. 测试角色控制
echo "4. 测试角色控制..."
echo "--- 普通用户删除用户 (应该失败，不是admin角色) ---"
curl -s -X DELETE ${BASE_URL}/api/users/1 \
    -H "Authorization: Bearer ${USER_TOKEN}" | python3 -m json.tool
echo

echo "--- 管理员删除用户 (应该成功) ---"
curl -s -X DELETE ${BASE_URL}/api/users/1 \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | python3 -m json.tool
echo

# 5. 测试基于资源的RBAC
echo "5. 测试基于资源的RBAC..."
echo "--- 普通用户获取数据 (应该成功，有read权限) ---"
curl -s -X GET ${BASE_URL}/api/data \
    -H "Authorization: Bearer ${USER_TOKEN}" | python3 -m json.tool
echo

echo "--- 普通用户创建数据 (应该失败，没有write权限) ---"
curl -s -X POST ${BASE_URL}/api/data \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"data":"test"}' | python3 -m json.tool
echo

echo "--- 经理创建数据 (应该成功，有write权限) ---"
curl -s -X POST ${BASE_URL}/api/data \
    -H "Authorization: Bearer ${MANAGER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"data":"test"}' | python3 -m json.tool
echo

# 6. 测试团队管理
echo "6. 测试团队管理..."
echo "--- 普通用户获取团队信息 (应该成功，有read权限) ---"
curl -s -X GET ${BASE_URL}/api/team \
    -H "Authorization: Bearer ${USER_TOKEN}" | python3 -m json.tool
echo

echo "--- 普通用户管理团队 (应该失败，没有manage_team权限) ---"
curl -s -X POST ${BASE_URL}/api/team \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"action":"add_member","member":"newuser"}' | python3 -m json.tool
echo

echo "--- 经理管理团队 (应该成功，有manage_team权限) ---"
curl -s -X POST ${BASE_URL}/api/team \
    -H "Authorization: Bearer ${MANAGER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"action":"add_member","member":"newuser"}' | python3 -m json.tool
echo

# 7. 测试管理员功能
echo "7. 测试管理员功能..."
echo "--- 普通用户获取管理员统计 (应该失败，不是admin角色) ---"
curl -s -X GET ${BASE_URL}/api/admin/stats \
    -H "Authorization: Bearer ${USER_TOKEN}" | python3 -m json.tool
echo

echo "--- 管理员获取管理员统计 (应该成功) ---"
curl -s -X GET ${BASE_URL}/api/admin/stats \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | python3 -m json.tool
echo

# 8. 测试无token访问
echo "8. 测试无认证访问..."
echo "--- 无token访问受保护资源 (应该失败) ---"
curl -s -X GET ${BASE_URL}/api/users | python3 -m json.tool
echo

echo "=== 测试完成 ==="
