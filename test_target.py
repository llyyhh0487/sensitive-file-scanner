#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本地测试目标服务器
用于测试敏感文件扫描器的各项功能

启动方式：
    python test_target.py

然后访问 http://127.0.0.1:5000
"""

from flask import Flask, render_template_string, abort, redirect, request, jsonify, make_response
import random
import hashlib

app = Flask(__name__)

# ============================================================
# 模拟的敏感文件内容（用于产生真实漏洞）
# ============================================================

# 模拟 .env 文件
FAKE_ENV_CONTENT = """# Application Configuration
APP_NAME=MyWebApp
APP_ENV=production
APP_DEBUG=false
APP_URL=https://example.com

# Database Configuration
DB_CONNECTION=mysql
DB_HOST=192.168.1.100
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=admin
DB_PASSWORD=MyS3cur3P@ssw0rd!

# Redis Configuration
REDIS_HOST=192.168.1.101
REDIS_PASSWORD=RedisP@ss123
REDIS_PORT=6379

# JWT Secret
JWT_SECRET=super-secret-jwt-key-change-me

# AWS Credentials
AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
AWS_SECRET_ACCESS_KEY=abcdef1234567890abcdef1234567890abcdef12
AWS_REGION=us-east-1

# Email Configuration
MAIL_MAILER=smtp
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=admin@example.com
MAIL_PASSWORD=EmailP@ss789

# API Keys
STRIPE_KEY=sk_live_1234567890abcdef
STRIPE_SECRET=whsec_0987654321fedcba
GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234
"""

# 模拟 .git/config 内容
FAKE_GIT_CONFIG = """[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	ignorecase = true
	precomposeunicode = true
[remote "origin"]
	url = https://github.com/company/secret-project.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[branch "develop"]
	remote = origin
	merge = refs/heads/develop
[user]
	name = admin
	email = admin@company.com
"""

# 模拟备份 SQL 文件
FAKE_SQL_BACKUP = """-- MySQL dump 10.13  Distrib 8.0.33, for Linux (x86_64)
--
-- Host: localhost    Database: production_db
-- ------------------------------------------------------
-- Server version	8.0.33-0ubuntu0.22.04.2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `role` varchar(20) DEFAULT 'user',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `users`
--

INSERT INTO `users` VALUES (1,'admin','$2b$10$SomeHashedPasswordValueHere1234567890','admin@company.com','superadmin','2024-01-01 00:00:00');
INSERT INTO `users` VALUES (2,'john_doe','$2b$10$AnotherHashedPasswordValueHere0987654321','john@company.com','user','2024-01-15 10:30:00');
INSERT INTO `users` VALUES (3,'jane_smith','$2b$10$ThirdHashedPasswordValueHereabcdefghijklm','jane@company.com','moderator','2024-02-01 14:20:00');
"""

# 模拟 robots.txt（带隐藏路径）
FAKE_ROBOTS_TXT = """User-agent: *
Disallow: /admin/
Disallow: /api/
Disallow: /backup/
Disallow: /config/
Disallow: /debug/
Disallow: /internal/
Disallow: /logs/
Disallow: /private/
Disallow: /secret/
Disallow: /staff/
Disallow: /test/
Allow: /public/
"""

# ============================================================
# 正常业务页面
# ============================================================

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="utf-8">
        <title>XX电商平台 - 首页</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            h1 { color: #e4393c; }
            .nav { margin: 20px 0; }
            .nav a { margin-right: 15px; color: #333; text-decoration: none; }
            .nav a:hover { color: #e4393c; }
        </style>
    </head>
    <body>
        <h1>🛒 XX电商平台</h1>
        <p>正品保障，极速发货，7天无理由退换</p>
        <div class="nav">
            <a href="/">首页</a>
            <a href="/about">关于我们</a>
            <a href="/products">商品列表</a>
            <a href="/contact">联系我们</a>
            <a href="/login">登录</a>
        </div>
        <hr>
        <p>欢迎访问XX电商平台！</p>
        <p>这是一个用于安全测试的模拟网站。</p>
    </body>
    </html>
    '''

@app.route('/about')
def about():
    return '<h1>关于我们</h1><p>成立于2018年，专注于电商服务。</p>'

@app.route('/products')
def products():
    return '''
    <h1>商品列表</h1>
    <ul>
        <li>📱 iPhone 15 Pro - ¥8999</li>
        <li>💻 MacBook Air - ¥7999</li>
        <li>⌚ Apple Watch - ¥2999</li>
        <li>🎧 AirPods Pro - ¥1899</li>
    </ul>
    '''

@app.route('/contact')
def contact():
    return '<h1>联系我们</h1><p>客服电话：400-123-4567</p><p>邮箱：support@example.com</p>'

@app.route('/login')
def login():
    return '''
    <h1>用户登录</h1>
    <form method="post">
        <p>用户名：<input type="text" name="username"></p>
        <p>密码：<input type="password" name="password"></p>
        <p><input type="submit" value="登录"></p>
    </form>
    '''

# ============================================================
# 场景1：真实的敏感文件泄露（漏洞）
# ============================================================

@app.route('/.env')
def leak_env():
    """真实 .env 文件泄露 - 应被 AI 判定为高危漏洞"""
    resp = make_response(FAKE_ENV_CONTENT, 200)
    resp.headers['Content-Type'] = 'text/plain'
    return resp

@app.route('/.env.backup')
def leak_env_backup():
    """真实 .env.backup 文件泄露"""
    resp = make_response(FAKE_ENV_CONTENT, 200)
    resp.headers['Content-Type'] = 'text/plain'
    return resp

@app.route('/.env.production')
def leak_env_production():
    """真实 .env.production 文件泄露"""
    resp = make_response(FAKE_ENV_CONTENT, 200)
    resp.headers['Content-Type'] = 'text/plain'
    return resp

@app.route('/.git/config')
def leak_git_config():
    """真实 .git/config 泄露 - 应被 AI 判定为中危漏洞"""
    resp = make_response(FAKE_GIT_CONFIG, 200)
    resp.headers['Content-Type'] = 'text/plain'
    return resp

@app.route('/backup/db.sql')
@app.route('/backup.sql')
@app.route('/db_backup.sql')
def leak_sql_backup():
    """真实 SQL 备份文件泄露 - 应被 AI 判定为高危漏洞"""
    resp = make_response(FAKE_SQL_BACKUP, 200)
    resp.headers['Content-Type'] = 'text/plain'
    return resp

@app.route('/robots.txt')
def leak_robots():
    """真实 robots.txt 泄露（含隐藏路径）- 中低危信息泄露"""
    resp = make_response(FAKE_ROBOTS_TXT, 200)
    resp.headers['Content-Type'] = 'text/plain'
    return resp

@app.route('/phpinfo.php')
def leak_phpinfo():
    """真实 phpinfo 泄露 - 应被 AI 判定为中危"""
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>phpinfo()</title></head>
    <body>
    <h1>PHP Version 7.4.33</h1>
    <table>
    <tr><td>System</td><td>Linux server01 5.15.0-91-generic #101-Ubuntu</td></tr>
    <tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
    <tr><td>PHP Version</td><td>7.4.33</td></tr>
    <tr><td>Loaded Configuration File</td><td>/etc/php/7.4/apache2/php.ini</td></tr>
    <tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr>
    <tr><td>SERVER_ADMIN</td><td>webmaster@example.com</td></tr>
    <tr><td>SERVER_SOFTWARE</td><td>Apache/2.4.41 (Ubuntu)</td></tr>
    </table>
    </body>
    </html>
    '''

# ============================================================
# 场景2：假 200 页面（返回 200 但实际是 404 内容）- 误报
# ============================================================

@app.errorhandler(404)
def page_not_found(e):
    """自定义 404 页面 - 返回 200 状态码来干扰扫描器"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>404 - Page Not Found</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            h1 { font-size: 72px; color: #ccc; margin: 0; }
            p { font-size: 18px; color: #666; }
        </style>
    </head>
    <body>
        <h1>404</h1>
        <p>Oops! The page you are looking for does not exist.</p>
        <p>The requested URL was not found on this server.</p>
        <p><a href="/">Return to Homepage</a></p>
    </body>
    </html>
    ''', 200

# ============================================================
# 场景3：正常的 403/301/302 响应
# ============================================================

@app.route('/admin')
def admin_redirect():
    """后台管理 - 重定向到登录页"""
    return redirect('/admin/login')

@app.route('/admin/login')
def admin_login():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>后台管理 - 登录</title></head>
    <body>
        <h1>🔒 后台管理系统</h1>
        <form method="post">
            <p>用户名：<input type="text" name="username"></p>
            <p>密码：<input type="password" name="password"></p>
            <p><input type="submit" value="登录"></p>
        </form>
        <p style="color:#999;font-size:12px;">Powered by Django 3.2.5</p>
    </body>
    </html>
    '''

@app.route('/wp-admin')
@app.route('/administrator')
def forbidden_pages():
    """WordPress 和 Joomla 后台 - 返回 403"""
    abort(403)

@app.route('/api/v1/users')
def api_users():
    """API 接口 - JSON 格式敏感数据"""
    return jsonify({
        "code": 200,
        "data": [
            {"id": 1, "username": "admin", "email": "admin@company.com", "role": "superadmin", "last_login": "2024-03-15 10:30:00"},
            {"id": 2, "username": "john", "email": "john@company.com", "role": "user", "last_login": "2024-03-14 15:20:00"},
            {"id": 3, "username": "jane", "email": "jane@company.com", "role": "moderator", "last_login": "2024-03-15 09:00:00"}
        ],
        "total": 3,
        "page": 1
    })

@app.route('/api/config')
def api_config():
    """API 配置接口 - JSON 格式敏感数据"""
    return jsonify({
        "debug": True,
        "database": {
            "host": "db.internal.example.com",
            "port": 5432,
            "name": "app_production",
            "user": "app_user",
            "pool_size": 20
        },
        "redis": {
            "host": "redis.internal.example.com",
            "port": 6379,
            "db": 0
        },
        "smtp": {
            "host": "smtp.example.com",
            "port": 587,
            "user": "noreply@example.com"
        }
    })

# ============================================================
# 场景4：空内容 200 响应
# ============================================================

@app.route('/api/health')
@app.route('/ping')
def empty_200():
    """健康检查接口 - 空内容 200"""
    return '', 200

@app.route('/api/status')
def status_200():
    """状态接口 - 简单 JSON"""
    return jsonify({"status": "ok"}), 200

# ============================================================
# 启动
# ============================================================

if __name__ == '__main__':
    print("=" * 60)
    print("🧪 敏感文件扫描器 - 测试目标服务器")
    print("=" * 60)
    print()
    print("📋 模拟场景说明：")
    print()
    print("⚠️  真实漏洞（应被检出）：")
    print("   GET /.env              → 200 (含数据库密码、AWS密钥)")
    print("   GET /.env.backup       → 200 (同上)")
    print("   GET /.env.production   → 200 (同上)")
    print("   GET /.git/config       → 200 (含仓库地址)")
    print("   GET /backup.sql        → 200 (数据库备份)")
    print("   GET /backup/db.sql     → 200 (同上)")
    print("   GET /db_backup.sql     → 200 (同上)")
    print("   GET /robots.txt        → 200 (含隐藏路径)")
    print("   GET /phpinfo.php       → 200 (PHP配置信息)")
    print("   GET /api/v1/users      → 200 (JSON用户列表)")
    print("   GET /api/config        → 200 (JSON配置信息)")
    print()
    print("🚫 误报（应被过滤）：")
    print("   GET /任意不存在的路径  → 200 (返回404页面内容)")
    print()
    print("🔒 其他响应：")
    print("   GET /admin             → 302 → /admin/login")
    print("   GET /wp-admin          → 403")
    print("   GET /api/health        → 200 (空内容)")
    print()
    print("=" * 60)
    print("🚀 服务启动在: http://127.0.0.1:5000")
    print("=" * 60)
    
    app.run(debug=False, host='127.0.0.1', port=5000)
