#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepSeek AI 模块测试脚本
用于验证 DeepSeek API 的连通性和语义分析能力
"""

import json
import sys
from openai import OpenAI

# ============================================================
# 配置
# ============================================================
API_KEY = "sk-005aaa21a38c4d8a9013b6482d682639"
API_BASE = "https://api.deepseek.com"
MODEL = "deepseek-chat"

# ============================================================
# 测试用例：模拟不同场景的页面内容
# ============================================================
TEST_CASES = [
    {
        "name": "场景1：真实 .env 文件泄露",
        "url": "https://target.com/.env",
        "content": """
DB_HOST=mysql.internal.example.com
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=admin
DB_PASSWORD=SuperSecret123!
REDIS_URL=redis://:auth_token@redis.internal:6379/0
JWT_SECRET=eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4i
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
    },
    {
        "name": "场景2：假 404 页面（返回200但页面不存在）",
        "url": "https://target.com/.env",
        "content": """
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
"""
    },
    {
        "name": "场景3：真实 .git/config 泄露",
        "url": "https://target.com/.git/config",
        "content": """
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/company/secret-project.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
"""
    },
    {
        "name": "场景4：空内容 200 响应",
        "url": "https://target.com/api/health",
        "content": ""
    },
    {
        "name": "场景5：JSON API 响应（含敏感数据）",
        "url": "https://target.com/api/users",
        "content": json.dumps({
            "code": 200,
            "data": [
                {"id": 1, "username": "admin", "email": "admin@company.com", "role": "superadmin"},
                {"id": 2, "username": "zhangsan", "email": "zhangsan@company.com", "role": "user"}
            ],
            "total": 2
        })
    }
]


def test_ai_analysis(client, test_case):
    """测试 AI 对单个场景的分析"""
    url = test_case["url"]
    content = test_case["content"]
    
    # 截取前 2000 字符
    content_preview = content[:2000] if content else "（空内容）"
    
    prompt = f"""你是一个信息安全专家。请分析以下 URL 的 HTTP 响应内容，判断它是否代表一个真实的安全漏洞（敏感文件/信息泄露）。

URL: {url}
响应内容:
```
{content_preview}
```

请回答：
1. 这是真实敏感信息泄露吗？(YES/NO)
2. 风险等级：critical/high/medium/low/info
3. 分类：config_leak / source_code_leak / credential_leak / backup_file / api_endpoint / listing / info_disclosure / false_positive
4. 简要分析理由
5. 如果泄露了密钥/密码，列出泄露的具体字段名（不列出值）

请以 JSON 格式回复：
{{"is_vulnerable": true/false, "risk_level": "...", "category": "...", "reason": "...", "leaked_fields": [...]}}"""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "你是一个专业的信息安全专家，擅长识别敏感信息泄露和Web安全漏洞。请始终以JSON格式回复。"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=500
        )
        
        result_text = response.choices[0].message.content
        print(f"\n{'='*60}")
        print(f"测试: {test_case['name']}")
        print(f"URL: {url}")
        print(f"内容长度: {len(content)} 字符")
        print(f"AI 回复:\n{result_text}")
        
        # 尝试解析 JSON
        try:
            result_json = json.loads(result_text)
            print(f"\n解析结果:")
            print(f"  是否漏洞: {'⚠️ 是' if result_json.get('is_vulnerable') else '✅ 否（误报）'}")
            print(f"  风险等级: {result_json.get('risk_level', 'N/A')}")
            print(f"  分类: {result_json.get('category', 'N/A')}")
            print(f"  理由: {result_json.get('reason', 'N/A')}")
            if result_json.get('leaked_fields'):
                print(f"  泄露字段: {', '.join(result_json['leaked_fields'])}")
        except json.JSONDecodeError:
            print("  (AI 返回的不是有效 JSON，可能需要调整 prompt)")
            
        return True
        
    except Exception as e:
        print(f"\n❌ AI 分析失败: {e}")
        return False


def main():
    """主测试函数"""
    print("="*60)
    print("DeepSeek AI 敏感文件分析 - 功能测试")
    print("="*60)
    
    # 初始化客户端
    try:
        client = OpenAI(
            api_key=API_KEY,
            base_url=API_BASE
        )
        print(f"✅ API 客户端初始化成功")
        print(f"   Base URL: {API_BASE}")
        print(f"   Model: {MODEL}")
    except Exception as e:
        print(f"❌ API 客户端初始化失败: {e}")
        sys.exit(1)
    
    # 运行所有测试用例
    success_count = 0
    for test_case in TEST_CASES:
        if test_ai_analysis(client, test_case):
            success_count += 1
    
    # 汇总
    print(f"\n{'='*60}")
    print(f"测试完成: {success_count}/{len(TEST_CASES)} 个用例成功")
    print(f"{'='*60}")
    
    # 额外功能测试：模拟扫描报告摘要
    print("\n📊 模拟扫描报告摘要:")
    print("-" * 40)
    summary_prompt = """以下是某次扫描的结果摘要，请用中文给出安全建议：

扫描目标: https://example.com
扫描路径数: 356
返回200: 45
AI确认真实漏洞: 3

漏洞详情:
1. /.env - 发现数据库密码和AWS密钥 (critical)
2. /.git/config - 发现内部Git仓库地址 (medium)
3. /backup/db.sql - 发现数据库备份文件 (high)

请给出修复建议。"""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "你是一个安全顾问，请用中文给出专业的安全建议。"},
                {"role": "user", "content": summary_prompt}
            ],
            temperature=0.3,
            max_tokens=500
        )
        print(response.choices[0].message.content)
    except Exception as e:
        print(f"❌ 摘要生成失败: {e}")


if __name__ == "__main__":
    main()
