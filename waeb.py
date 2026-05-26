#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
4类漏报场景综合测试网站
用于测试敏感文件扫描器在复杂混淆场景下的表现

启动方式：
    python waeb.py

然后访问 http://127.0.0.1:5000
"""

from flask import Flask, render_template_string, abort, redirect, request, jsonify
import time
import random
import re

app = Flask(__name__)

# --------------------------
# 正常业务页面（基础混淆）
# --------------------------
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>XX电商平台官网</title></head>
    <body>
        <h1>欢迎来到XX电商平台</h1>
        <p>正品保障，极速发货</p>
        <a href="/about">关于我们</a> | <a href="/products">商品列表</a> | <a href="/contact">联系我们</a>
    </body>
    </html>
    '''

@app.route('/about')
def about():
    return '<h1>关于我们</h1><p>成立于2018年，专注于电商服务</p>'

@app.route('/products')
def products():
    return '<h1>商品列表</h1><ul><li>手机</li><li>电脑</li><li>家电</li></ul>'

@app.route('/contact')
def contact():
    return '<h1>联系我们</h1><p>客服电话：400-123-4567</p>'

# --------------------------
# 场景1：302重定向到敏感页面（中高危）
# --------------------------
# 测试用例1：最常见的后台根路径重定向
@app.route('/admin')
def admin_redirect():
    return redirect('/admin/login.html')

@app.route('/admin/login.html')
def real_admin_login():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>电商后台管理系统</title></head>
    <body>
        <h1>后台管理登录</h1>
        <form method="post">
            用户名：<input type="text" name="username"><br>
            密码：<input type="password" name="password"><br>
            <input type="submit" value="登录">
        </form>
    </body>
    </html>
    '''

# 测试用例2：API根路径重定向到认证接口
@app.route('/api')
def api_root_redirect():
    return redirect('/api/v1/auth/login')

@app.route('/api/v1/auth/login')
def api_login():
    return jsonify({"code": 401, "message": "请先登录"})

# 测试用例3：管理路径重定向到系统登录页
@app.route('/manage')
def manage_redirect():
    return redirect('/system/login.php')

@app.route('/system/login.php')
def system_login():
    return '<h1>系统管理平台</h1><p>请输入管理员账号密码</p>'

# 测试用例4：诱饵重定向（重定向到首页，无价值）
@app.route('/fake-admin')
def fake_redirect():
    return redirect('/')

# --------------------------
# 场景2：空内容但有价值的API接口（中危）
# --------------------------
# 测试用例1：GET空，POST返回用户列表
@app.route('/api/v1/users', methods=['GET', 'POST'])
def api_users():
    if request.method == 'GET':
        return '', 200  # GET请求返回空内容
    elif request.method == 'POST':
        return jsonify({
            "code": 200,
            "data": [
                {"id": 1, "username": "admin", "email": "admin@example.com"},
                {"id": 2, "username": "user1", "email": "user1@example.com"}
            ]
        })

# 测试用例2：GET空，PUT可修改订单
@app.route('/api/v1/orders/<int:order_id>', methods=['GET', 'PUT'])
def api_orders(order_id):
    if request.method == 'GET':
        return '', 200
    elif request.method == 'PUT':
        return jsonify({"code": 200, "message": f"订单{order_id}修改成功"})

# 测试用例3：GET空，POST可上传文件
@app.route('/api/v1/upload', methods=['GET', 'POST'])
def api_upload():
    if request.method == 'GET':
        return '', 200
    elif request.method == 'POST':
        return jsonify({"code": 200, "message": "文件上传成功", "url": "/uploads/test.jpg"})

# --------------------------
# 场景3：403页面内容泄露（中低危）
# --------------------------
# 测试用例1：Apache服务器403页面（泄露版本）
@app.route('/apache-secret')
def apache_403():
    return '''
    <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    <html><head>
    <title>403 Forbidden</title>
    </head><body>
    <h1>Forbidden</h1>
    <p>You don't have permission to access /apache-secret on this server.</p>
    <hr>
    <address>Apache/2.4.41 (Ubuntu) Server at 127.0.0.1 Port 5000</address>
    </body></html>
    ''', 403

# 测试用例2：Nginx服务器403页面（泄露版本）
@app.route('/nginx-secret')
def nginx_403():
    return '''
    <html>
    <head><title>403 Forbidden</title></head>
    <body>
    <center><h1>403 Forbidden</h1></center>
    <hr><center>nginx/1.18.0 (Ubuntu)</center>
    </body>
    </html>
    ''', 403

# 测试用例3：ThinkPHP框架403页面（泄露版本）
@app.route('/thinkphp-secret')
def thinkphp_403():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>403 Forbidden</title>
    </head>
    <body>
        <h1>403 Forbidden</h1>
        <p>抱歉，您没有权限访问此页面</p>
        <p>Powered by ThinkPHP 5.0.24</p>
    </body>
    </html>
    ''', 403

# --------------------------
# 场景4：目录遍历漏洞的中间路径（高危）
# --------------------------
# 原始路径返回403
@app.route('/static/../etc/passwd')
def traversal_original():
    abort(403)

# 测试用例1：./绕过
@app.route('/static/./../etc/passwd')
def traversal_dot_slash():
    return '''
    root:x:0:0:root:/root:/bin/bash
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    mysql:x:100:101:MySQL Server:/var/lib/mysql:/bin/false
    '''

# 测试用例2：URL编码绕过
@app.route('/static/%2e%2e/etc/passwd')
def traversal_url_encode():
    return '''
    root:x:0:0:root:/root:/bin/bash
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    mysql:x:100:101:MySQL Server:/var/lib/mysql:/bin/false
    '''

# 测试用例3：双写编码绕过
@app.route('/static/%252e%252e/etc/passwd')
def traversal_double_encode():
    return '''
    root:x:0:0:root:/root:/bin/bash
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    mysql:x:100:101:MySQL Server:/var/lib/mysql:/bin/false
    '''

# --------------------------
# 原有反扫描混淆机制
# --------------------------
@app.errorhandler(404)
def page_not_found(e):
    time.sleep(random.uniform(0, 2))
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>404 Not Found</title></head>
    <body>
        <h1>404 Not Found</h1>
        <p>The requested URL was not found on this server.</p>
        <hr>
        <address>Apache/2.4.41 (Ubuntu) Server</address>
    </body>
    </html>
    ''', 200

@app.route('/wp-admin')
@app.route('/administrator')
def fake_admin_403():
    time.sleep(random.uniform(0.5, 1.5))
    abort(403)

@app.route('/phpinfo.php')
@app.route('/test.php')
def empty_200():
    time.sleep(random.uniform(0, 1))
    return '', 200

@app.route('/backup.sql')
@app.route('/db.bak')
def redirect_to_home():
    time.sleep(random.uniform(0.3, 1))
    return redirect('/')

@app.route('/.idea/<path:filename>')
def idea_files(filename):
    time.sleep(random.uniform(0.2, 0.8))
    abort(403)

if __name__ == '__main__':
    print("="*70)
    print("4类漏报场景综合测试网站已启动")
    print("访问地址：http://127.0.0.1:5000")
    print("\n=== 场景1：302重定向到敏感页面 ===")
    print("1. /admin → 302 → /admin/login.html（真实后台）")
    print("2. /api → 302 → /api/v1/auth/login（API认证）")
    print("3. /manage → 302 → /system/login.php（系统后台）")
    print("4. /fake-admin → 302 → /（诱饵重定向）")
    print("\n=== 场景2：空内容但有价值的API接口 ===")
    print("1. /api/v1/users：GET空，POST返回用户列表")
    print("2. /api/v1/orders/1：GET空，PUT可修改订单")
    print("3. /api/v1/upload：GET空，POST可上传文件")
    print("\n=== 场景3：403页面内容泄露 ===")
    print("1. /apache-secret：泄露Apache 2.4.41版本")
    print("2. /nginx-secret：泄露Nginx 1.18.0版本")
    print("3. /thinkphp-secret：泄露ThinkPHP 5.0.24版本")
    print("\n=== 场景4：目录遍历漏洞的中间路径 ===")
    print("1. /static/../etc/passwd：原始路径返回403")
    print("2. /static/./../etc/passwd：./绕过成功")
    print("3. /static/%2e%2e/etc/passwd：URL编码绕过成功")
    print("4. /static/%252e%252e/etc/passwd：双写编码绕过成功")
    print("="*70)
    app.run(debug=False, host='127.0.0.1')
