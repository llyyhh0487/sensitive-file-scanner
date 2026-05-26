#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
敏感文件扫描工具 - 命令行+GUI版本
基于 Python + requests + DeepSeek AI 的自动化敏感文件扫描工具

功能：
1. 批量扫描敏感路径字典
2. 多层误报过滤（状态码、关键词、404指纹）
3. DeepSeek AI 语义校验
4. 重定向跟踪
5. 目录穿越探测
6. 扫描报告生成
7. PyQt5 图形化界面

用法：
    python sensitive_scanner.py --url https://target.com
    python sensitive_scanner.py --gui
"""

import os
import sys
import time
import json
import hashlib
import argparse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

API_KEY = "sk-005aaa21a38c4d8a9013b6482d682639"
API_BASE = "https://api.deepseek.com"
MODEL = "deepseek-chat"
DEFAULT_TIMEOUT = 8
DEFAULT_CONCURRENCY = 30
MAX_REDIRECT_HOPS = 3
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

NOT_FOUND_KEYWORDS = [
    "404 not found", "404 page not found", "page not found",
    "the requested url was not found", "requested url was not found",
    "file not found", "not found on this server",
    "no results found", "nothing found", "no posts",
    "does not exist", "cannot be found", "could not be found",
    "the page you are looking for", "sorry, page not found",
    "oops! that page can't be found", "404 error",
    "error 404", "http 404", "status 404",
    "the requested resource", "is not available",
    "page not available", "content not found",
    "we couldn't find", "page doesn't exist"
]

SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "api_key", "apikey",
    "access_key", "secret_key", "private_key", "token",
    "database", "db_host", "db_user", "db_password",
    "jwt_secret", "encryption_key", "auth_token",
    "mysql", "postgresql", "redis", "mongodb",
    "connection string", "connectionstring",
    "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
    "-----BEGIN", "ssh-rsa",
    "AKIA", "sk-", "ghp_", "github_pat_",
    "smtp", "mail_password", "mail_host",
    "APP_KEY=", "APP_SECRET=",
]


def load_paths(dict_file):
    paths = []
    if not os.path.exists(dict_file):
        print(f"[!] 字典文件不存在: {dict_file}")
        return paths
    with open(dict_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if not line.startswith("/"):
                    line = "/" + line
                paths.append(line)
    return paths


def get_404_fingerprint(url, session):
    fake_path = url.rstrip("/") + "/this_page_does_not_exist_" + str(int(time.time()))
    try:
        resp = session.get(fake_path, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        content = resp.text[:3000] if resp.text else ""
        return hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
    except Exception:
        return None


class SensitiveScanner:
    def __init__(self, url, dict_file, concurrency=DEFAULT_CONCURRENCY,
                 timeout=DEFAULT_TIMEOUT, use_ai=True, scan_root=True,
                 scan_traversal=True):
        self.url = url.rstrip("/")
        self.dict_file = dict_file
        self.concurrency = concurrency
        self.timeout = timeout
        self.use_ai = use_ai and HAS_OPENAI
        self.scan_root = scan_root
        self.scan_traversal = scan_traversal
        self.paths = load_paths(dict_file)
        self.results = {
            "vulnerabilities": [],
            "false_positives": [],
            "redirects": [],
            "forbidden": [],
            "errors": [],
            "other": []
        }
        self.lock = threading.Lock()
        self._seen_urls = set()
        self._ai_client = None
        self.session = self._create_session()
        self.fingerprint_404 = None
        if self.use_ai:
            try:
                self._ai_client = OpenAI(api_key=API_KEY, base_url=API_BASE)
                print(f"[+] DeepSeek AI 已启用")
            except Exception as e:
                print(f"[!] AI 初始化失败: {e}")
                self.use_ai = False

    def _create_session(self):
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        })
        session.verify = True
        return session

    def _follow_redirect(self, path, response, hops=0):
        if hops >= MAX_REDIRECT_HOPS:
            return None, hops
        location = response.headers.get("Location", "")
        if not location:
            return None, hops
        next_url = urljoin(self.url + path, location)
        if next_url in self._seen_urls:
            return None, hops
        if urlparse(next_url).netloc != urlparse(self.url).netloc:
            return None, hops
        self._seen_urls.add(next_url)
        try:
            resp = self.session.get(next_url, timeout=self.timeout, allow_redirects=False, stream=True)
            status = resp.status_code
            content = resp.text[:5000] if resp.text else ""
            resp.close()
            if status == 200:
                return {"url": next_url, "status": status, "content": content, "hops": hops + 1}, hops + 1
            elif status in (301, 302, 307, 308):
                return self._follow_redirect(path, resp, hops + 1)
            elif status in (401, 403):
                return {"url": next_url, "status": status, "content": content, "hops": hops + 1, "auth_required": True}, hops + 1
            else:
                return {"url": next_url, "status": status, "content": content, "hops": hops + 1}, hops + 1
        except Exception:
            return None, hops

    def _check_not_found_local(self, content):
        if not content or len(content.strip()) < 10:
            return False
        content_lower = content.lower()
        hits = sum(1 for kw in NOT_FOUND_KEYWORDS if kw in content_lower)
        return hits >= 2

    def _check_sensitive_local(self, content):
        if not content:
            return False
        content_lower = content.lower()
        return any(kw.lower() in content_lower for kw in SENSITIVE_KEYWORDS)

    def _ai_analyze(self, path, content, redirect_info=None):
        if not self.use_ai or not self._ai_client:
            return None
        preview = content[:2000] if content else "（空内容）"
        redirect_note = ""
        if redirect_info:
            redirect_note = f"\n注意：此URL经过了 {redirect_info.get('hops', 0)} 次重定向，最终到达: {redirect_info.get('url', 'N/A')}"
        prompt = f"""你是一个信息安全专家。请分析以下 URL 的 HTTP 响应内容，判断它是否代表一个真实的安全漏洞（敏感文件/信息泄露）。

目标URL: {self.url}{path}{redirect_note}
响应内容:
```
{preview}
```

请判断：
1. 这是真实敏感信息泄露吗？(注意区分：返回200但内容是404提示、或空页面、或通用错误页面的情况属于误报)
2. 风险等级：critical/high/medium/low/info
3. 分类：config_leak / source_code_leak / credential_leak / backup_file / api_endpoint / listing / info_disclosure / false_positive
4. 简要分析理由（中文）
5. 如果泄露了密钥/密码等敏感字段，列出泄露的具体字段名（不列出值）

请以 JSON 格式回复：
{{"is_vulnerable": true/false, "risk_level": "...", "category": "...", "reason": "...", "leaked_fields": [...]}}"""
        try:
            response = self._ai_client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": "你是一个专业的信息安全专家，擅长识别敏感信息泄露和Web安全漏洞。请始终以JSON格式回复。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=600
            )
            result_text = response.choices[0].message.content
            try:
                if "```json" in result_text:
                    result_text = result_text.split("```json")[1].split("```")[0].strip()
                elif "```" in result_text:
                    result_text = result_text.split("```")[1].split("```")[0].strip()
                return json.loads(result_text)
            except json.JSONDecodeError:
                is_vuln = "true" in result_text.lower() and "is_vulnerable" in result_text.lower()
                return {
                    "is_vulnerable": is_vuln,
                    "risk_level": "medium" if is_vuln else "info",
                    "category": "unknown",
                    "reason": result_text[:200],
                    "leaked_fields": []
                }
        except Exception as e:
            print(f"  [!] AI 分析异常: {e}")
            return None

    def _scan_single_path(self, path):
        full_url = self.url + path
        if full_url in self._seen_urls:
            return None
        self._seen_urls.add(full_url)
        try:
            resp = self.session.get(full_url, timeout=self.timeout, allow_redirects=False, stream=True)
            status = resp.status_code
            content = resp.text[:10000] if resp.text else ""
            resp.close()
            result = {
                "path": path, "url": full_url, "status": status,
                "content_length": len(content), "content_preview": content[:500],
                "timestamp": datetime.now().isoformat()
            }
            if status == 200:
                if not content or len(content.strip()) < 10:
                    result["verdict"] = "skipped"
                    result["reason"] = "空内容响应"
                    return result
                if self.fingerprint_404:
                    content_hash = hashlib.md5((content[:3000] if content else "").encode("utf-8", errors="ignore")).hexdigest()
                    if content_hash == self.fingerprint_404:
                        with self.lock:
                            self.results["false_positives"].append({
                                **result, "verdict": "false_positive",
                                "reason": "内容与站点404页面一致", "ai_analysis": None
                            })
                        return result
                if self._check_not_found_local(content):
                    with self.lock:
                        self.results["false_positives"].append({
                            **result, "verdict": "false_positive",
                            "reason": "命中404特征关键词(≥2个)", "ai_analysis": None
                        })
                    return result
                ai_result = self._ai_analyze(path, content)
                if ai_result:
                    if ai_result.get("is_vulnerable"):
                        risk = ai_result.get("risk_level", "medium")
                        risk_display = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}.get(risk, risk)
                        with self.lock:
                            self.results["vulnerabilities"].append({
                                **result, "verdict": "vulnerable", "risk_level": risk,
                                "risk_display": risk_display,
                                "category": ai_result.get("category", "unknown"),
                                "reason": ai_result.get("reason", ""),
                                "leaked_fields": ai_result.get("leaked_fields", []),
                                "ai_analysis": ai_result
                            })
                        print(f"  [⚠ {risk_display}] {path} - {ai_result.get('reason', '')[:80]}")
                    else:
                        with self.lock:
                            self.results["false_positives"].append({
                                **result, "verdict": "false_positive",
                                "reason": f"AI判定: {ai_result.get('reason', '非敏感内容')[:100]}",
                                "ai_analysis": ai_result
                            })
                else:
                    if self._check_sensitive_local(content):
                        with self.lock:
                            self.results["vulnerabilities"].append({
                                **result, "verdict": "vulnerable", "risk_level": "medium",
                                "risk_display": "中危", "category": "sensitive_content",
                                "reason": "本地规则命中敏感关键词(AI不可用)",
                                "leaked_fields": [], "ai_analysis": None
                            })
                        print(f"  [⚠ 中危(本地)] {path}")
                    else:
                        with self.lock:
                            self.results["other"].append({
                                **result, "verdict": "unclear",
                                "reason": "无法确定(AI不可用且未命中本地规则)"
                            })
            elif status in (301, 302, 307, 308):
                redirect_result, hops = self._follow_redirect(path, resp)
                if redirect_result:
                    redirect_content = redirect_result.get("content", "")
                    redirect_url = redirect_result.get("url", "")
                    final_status = redirect_result.get("status", 0)
                    if final_status == 200 and redirect_content and len(redirect_content.strip()) >= 10:
                        ai_result = self._ai_analyze(path, redirect_content, redirect_info=redirect_result)
                        if ai_result and ai_result.get("is_vulnerable"):
                            risk = ai_result.get("risk_level", "medium")
                            risk_display = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}.get(risk, risk)
                            if risk in ("low", "info"):
                                risk = "medium"
                                risk_display = "中危"
                            with self.lock:
                                self.results["vulnerabilities"].append({
                                    **result, "verdict": "vulnerable", "risk_level": risk,
                                    "risk_display": risk_display,
                                    "category": ai_result.get("category", "unknown"),
                                    "reason": f"[经过{hops}次重定向] {ai_result.get('reason', '')}",
                                    "leaked_fields": ai_result.get("leaked_fields", []),
                                    "redirect_chain": f"{path} → {redirect_url}",
                                    "ai_analysis": ai_result
                                })
                            print(f"  [⚠ {risk_display}] {path} → {redirect_url} - {ai_result.get('reason', '')[:60]}")
                        else:
                            with self.lock:
                                self.results["redirects"].append({
                                    **result, "verdict": "redirect",
                                    "final_url": redirect_url, "final_status": final_status,
                                    "hops": hops, "reason": "重定向后AI判定非敏感"
                                })
                    else:
                        with self.lock:
                            self.results["redirects"].append({
                                **result, "verdict": "redirect",
                                "final_url": redirect_url, "final_status": final_status, "hops": hops
                            })
                else:
                    with self.lock:
                        self.results["redirects"].append({
                            **result, "verdict": "redirect_loop", "reason": "重定向链无法跟踪或循环"
                        })
            elif status in (401, 403):
                with self.lock:
                    self.results["forbidden"].append({**result, "verdict": "forbidden"})
                print(f"  [🔒 {status}] {path}")
            else:
                with self.lock:
                    self.results["other"].append({**result, "verdict": f"status_{status}"})
            return result
        except requests.exceptions.Timeout:
            with self.lock:
                self.results["errors"].append({"path": path, "url": full_url, "verdict": "timeout", "reason": "请求超时"})
        except requests.exceptions.ConnectionError:
            with self.lock:
                self.results["errors"].append({"path": path, "url": full_url, "verdict": "connection_error", "reason": "连接失败"})
        except Exception as e:
            with self.lock:
                self.results["errors"].append({"path": path, "url": full_url, "verdict": "error", "reason": str(e)[:200]})
        return None

    def _build_traversal_paths(self):
        triggers = ["/static/", "/uploads/", "/upload/", "/files/", "/file/",
                     "/images/", "/img/", "/assets/", "/css/", "/js/",
                     "/download/", "/downloads/", "/media/", "/data/",
                     "/tmp/", "/temp/", "/logs/", "/log/", "/backup/",
                     "/backups/", "/cache/", "/includes/", "/include/",
                     "/lib/", "/libs/", "/modules/", "/templates/",
                     "/views/", "/public/", "/private/", "/docs/",
                     "/content/", "/user/", "/users/", "/admin/",
                     "/config/", "/conf/", "/attachment/", "/attachments/",
                     "/storage/"]
        payloads = ["../../../../../../../../etc/passwd",
                     "../../../../../../../../etc/shadow",
                     "../../../../../../../../etc/hosts",
                     "../../../../../../../../etc/group",
                     "../../../../../../../../etc/crontab",
                     "../../../../../../../../etc/ssh/sshd_config",
                     "../../../../../../../../etc/nginx/nginx.conf",
                     "../../../../../../../../etc/apache2/apache2.conf",
                     "../../../../../../../../etc/mysql/my.cnf",
                     "../../../../../../../../etc/redis/redis.conf",
                     "../../../../../../../../proc/self/environ",
                     "../../../../../../../../proc/self/cmdline",
                     "../../../../../../../../var/log/auth.log",
                     "../../../../../../../../Windows/win.ini",
                     "../../../../../../../../Windows/System32/drivers/etc/hosts",
                     "../../../../../../../../.env",
                     "../../../../../../../../.git/config",
                     "../../../../../../../../.htaccess",
                     "../../../../../../../../config.php",
                     "../../../../../../../../wp-config.php",
                     "../../../../../../../../settings.py",
                     "../../../../../../../../database.yml",
                     "../../../../../../../../id_rsa",
                     "../../../../../../../../.ssh/id_rsa",
                     "../../../../../../../../Dockerfile",
                     "../../../../../../../../docker-compose.yml",
                     "../../../../../../../../backup.sql",
                     "../../../../../../../../WEB-INF/web.xml"]
        traversal_paths = []
        for trigger in triggers[:10]:
            for payload in payloads[:15]:
                traversal_paths.append(trigger.rstrip("/") + "/" + payload)
        return traversal_paths

    def run(self):
        print(f"\n{'='*60}")
        print(f"🔍 敏感文件扫描器 v1.0")
        print(f"{'='*60}")
        print(f"目标URL: {self.url}")
        print(f"字典文件: {self.dict_file}")
        print(f"敏感路径数: {len(self.paths)}")
        print(f"并发数: {self.concurrency}")
        print(f"超时: {self.timeout}s")
        print(f"AI校验: {'启用' if self.use_ai else '禁用'}")
        print(f"根目录扫描: {'启用' if self.scan_root else '禁用'}")
        print(f"目录穿越探测: {'启用' if self.scan_traversal else '禁用'}")
        print(f"{'='*60}\n")
        print("[*] 正在获取站点 404 页面指纹...")
        self.fingerprint_404 = get_404_fingerprint(self.url, self.session)
        if self.fingerprint_404:
            print(f"[+] 404 指纹: {self.fingerprint_404[:16]}...")
        else:
            print("[!] 无法获取 404 指纹，跳过指纹对比")
        all_paths = list(self.paths)
        if self.scan_root:
            root_paths = []
            for p in self.paths:
                parts = p.strip("/").split("/")
                if parts:
                    root_path = "/" + parts[-1]
                    if root_path not in all_paths and root_path not in root_paths:
                        root_paths.append(root_path)
            all_paths.extend(root_paths)
            print(f"[+] 添加根目录扫描路径: {len(root_paths)} 条")
        if self.scan_traversal:
            traversal_paths = self._build_traversal_paths()
            all_paths.extend(traversal_paths)
            print(f"[+] 添加目录穿越路径: {len(traversal_paths)} 条")
        all_paths = list(set(all_paths))
        print(f"[+] 总扫描路径: {len(all_paths)}")
        print()
        print("[*] 开始扫描...")
        start_time = time.time()
        completed = 0
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {executor.submit(self._scan_single_path, p): p for p in all_paths}
            for future in as_completed(futures):
                path = futures[future]
                completed += 1
                if completed % 50 == 0 or completed == 1:
                    elapsed = time.time() - start_time
                    vuln_count = len(self.results["vulnerabilities"])
                    print(f"\r  进度: {completed}/{len(all_paths)} ({completed*100//len(all_paths)}%) | "
                          f"耗时: {elapsed:.0f}s | 发现漏洞: {vuln_count}", end="")
                try:
                    future.result(timeout=5)
                except Exception:
                    pass
        elapsed = time.time() - start_time
        print(f"\n\n[+] 扫描完成! 耗时: {elapsed:.1f}s")
        self._print_results()
        report_path = self._generate_report(elapsed)
        print(f"\n[+] 报告已生成: {report_path}")
        return self.results

    def _print_results(self):
        print(f"\n{'='*60}")
        print(f"📊 扫描结果汇总")
        print(f"{'='*60}")
        print(f"  真实漏洞: {len(self.results['vulnerabilities'])}")
        print(f"  误报(假200): {len(self.results['false_positives'])}")
        print(f"  重定向: {len(self.results['redirects'])}")
        print(f"  禁止访问(403/401): {len(self.results['forbidden'])}")
        print(f"  错误: {len(self.results['errors'])}")
        print(f"  其他: {len(self.results['other'])}")
        if self.results["vulnerabilities"]:
            print(f"\n{'='*60}")
            print(f"⚠️  真实漏洞详情 ({len(self.results['vulnerabilities'])} 个)")
            print(f"{'='*60}")
            risk_order = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "信息": 4}
            sorted_vulns = sorted(self.results["vulnerabilities"], key=lambda x: risk_order.get(x.get("risk_display", "信息"), 5))
            for i, vuln in enumerate(sorted_vulns, 1):
                risk_icon = {"严重": "🔴", "高危": "🟠", "中危": "🟡", "低危": "🟢", "信息": "🔵"}
                icon = risk_icon.get(vuln.get("risk_display", "信息"), "⚪")
                print(f"\n  [{i}] {icon} {vuln.get('risk_display', 'N/A')} - {vuln['path']}")
                print(f"      URL: {vuln['url']}")
                if vuln.get('redirect_chain'):
                    print(f"      重定向链: {vuln['redirect_chain']}")
                print(f"      分类: {vuln.get('category', 'N/A')}")
                print(f"      原因: {vuln.get('reason', 'N/A')}")
                if vuln.get('leaked_fields'):
                    print(f"      泄露字段: {', '.join(vuln['leaked_fields'])}")

    def _generate_report(self, elapsed):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"scan_report_{timestamp}.md"
        target_domain = urlparse(self.url).netloc
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"# 🔍 敏感文件扫描报告\n\n")
            f.write(f"**生成时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"---\n\n## 📋 扫描概况\n\n")
            f.write(f"| 项目 | 详情 |\n|------|------|\n")
            f.write(f"| 目标URL | {self.url} |\n")
            f.write(f"| 目标域名 | {target_domain} |\n")
            f.write(f"| 扫描路径数 | {len(self.paths)} |\n")
            f.write(f"| 扫描耗时 | {elapsed:.1f}s |\n")
            f.write(f"| AI 校验 | {'启用' if self.use_ai else '禁用'} |\n\n")
            f.write(f"## 📊 结果统计\n\n")
            f.write(f"| 类型 | 数量 |\n|------|------|\n")
            f.write(f"| ⚠️ 真实漏洞 | {len(self.results['vulnerabilities'])} |\n")
            f.write(f"| 🚫 误报(假200) | {len(self.results['false_positives'])} |\n")
            f.write(f"| 🔄 重定向 | {len(self.results['redirects'])} |\n")
            f.write(f"| 🔒 禁止访问 | {len(self.results['forbidden'])} |\n")
            f.write(f"| ❌ 错误 | {len(self.results['errors'])} |\n\n")
            if self.results["vulnerabilities"]:
                risk_order = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "信息": 4}
                sorted_vulns = sorted(self.results["vulnerabilities"], key=lambda x: risk_order.get(x.get("risk_display", "信息"), 5))
                f.write(f"## ⚠️ 真实漏洞详情\n\n")
                for i, vuln in enumerate(sorted_vulns, 1):
                    f.write(f"### {i}. {vuln.get('risk_display', 'N/A')} - `{vuln['path']}`\n\n")
                    f.write(f"- **URL:** {vuln['url']}\n")
                    f.write(f"- **HTTP状态码:** {vuln['status']}\n")
                    f.write(f"- **风险等级:** {vuln.get('risk_display', 'N/A')}\n")
                    f.write(f"- **分类:** {vuln.get('category', 'N/A')}\n")
                    if vuln.get('redirect_chain'):
                        f.write(f"- **重定向链:** {vuln['redirect_chain']}\n")
                    f.write(f"- **判定原因:** {vuln.get('reason', 'N/A')}\n")
                    if vuln.get('leaked_fields'):
                        f.write(f"- **泄露字段:** {', '.join(vuln['leaked_fields'])}\n")
                    f.write(f"\n")
            if self.results["false_positives"]:
                f.write(f"## 🚫 误报详情 (假200页面)\n\n")
                f.write(f"以下路径返回 200 状态码，但经分析判定为非敏感页面：\n\n")
                f.write(f"| 路径 | 原因 |\n|------|------|\n")
                for fp in self.results["false_positives"][:30]:
                    f.write(f"| `{fp['path']}` | {fp.get('reason', 'N/A')[:100]} |\n")
                if len(self.results["false_positives"]) > 30:
                    f.write(f"| ... | 还有 {len(self.results['false_positives']) - 30} 条 |\n")
                f.write(f"\n")
            f.write(f"## 🛡️ 安全建议\n\n")
            if self.results["vulnerabilities"]:
                f.write(f"1. **立即修复**：删除或限制对敏感文件的访问权限\n")
                f.write(f"2. **配置 Web 服务器**：禁止访问隐藏文件（如 `.env`、`.git`）\n")
                f.write(f"3. **使用 `.gitignore`**：确保敏感配置不会被提交到版本控制系统\n")
                f.write(f"4. **定期扫描**：建议将此工具纳入 CI/CD 流程\n")
            else:
                f.write(f"未发现明显的敏感文件泄露，但仍建议定期进行安全扫描。\n")
            f.write(f"\n---\n*本报告由敏感文件扫描工具自动生成*\n")
        return report_path


def launch_gui():
    try:
        from PyQt5.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout,
            QHBoxLayout, QLabel, QLineEdit, QPushButton,
            QTextEdit, QFileDialog, QCheckBox, QSpinBox,
            QProgressBar, QGroupBox, QMessageBox, QTabWidget,
            QTreeWidget, QTreeWidgetItem, QHeaderView
        )
        from PyQt5.QtCore import Qt, QThread, pyqtSignal
        from PyQt5.QtGui import QFont, QColor, QTextCursor
    except ImportError:
        print("[!] PyQt5 未安装，无法启动 GUI")
        print("    安装: pip install PyQt5")
        sys.exit(1)

    class ScanWorker(QThread):
        update_signal = pyqtSignal(str)
        finished_signal = pyqtSignal(dict)

        def __init__(self, url, dict_file, concurrency, timeout, use_ai, scan_root, scan_traversal):
            super().__init__()
            self.url = url
            self.dict_file = dict_file
            self.concurrency = concurrency
            self.timeout = timeout
            self.use_ai = use_ai
            self.scan_root = scan_root
            self.scan_traversal = scan_traversal

        def run(self):
            scanner = SensitiveScanner(
                url=self.url, dict_file=self.dict_file,
                concurrency=self.concurrency, timeout=self.timeout,
                use_ai=self.use_ai, scan_root=self.scan_root,
                scan_traversal=self.scan_traversal
            )
            import io
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                results = scanner.run()
                self.finished_signal.emit(results)
            except Exception as e:
                self.update_signal.emit(f"\n[!] 扫描异常: {str(e)}")
            finally:
                sys.stdout = old_stdout

    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.worker = None
            self.results = None
            self.init_ui()

        def init_ui(self):
            self.setWindowTitle("🔍 敏感文件扫描工具 - AI 智能版")
            self.setGeometry(100, 100, 1200, 800)
            self.setMinimumSize(900, 600)
            central = QWidget()
            self.setCentralWidget(central)
            main_layout = QVBoxLayout(central)
            main_layout.setSpacing(8)

            input_group = QGroupBox("📋 扫描配置")
            input_layout = QVBoxLayout(input_group)

            url_layout = QHBoxLayout()
            url_layout.addWidget(QLabel("目标 URL:"))
            self.url_input = QLineEdit()
            self.url_input.setPlaceholderText("https://example.com")
            url_layout.addWidget(self.url_input)
            input_layout.addLayout(url_layout)

            dict_layout = QHBoxLayout()
            dict_layout.addWidget(QLabel("字典文件:"))
            self.dict_input = QLineEdit()
            self.dict_input.setPlaceholderText("dicts/sensitive_paths.txt")
            self.dict_input.setText("dicts/sensitive_paths.txt")
            dict_layout.addWidget(self.dict_input)
            self.dict_btn = QPushButton("浏览...")
            self.dict_btn.clicked.connect(self.browse_dict)
            dict_layout.addWidget(self.dict_btn)
            input_layout.addLayout(dict_layout)

            options_layout = QHBoxLayout()
            options_layout.addWidget(QLabel("并发数:"))
            self.concurrency_spin = QSpinBox()
            self.concurrency_spin.setRange(1, 100)
            self.concurrency_spin.setValue(30)
            options_layout.addWidget(self.concurrency_spin)
            options_layout.addWidget(QLabel("超时(s):"))
            self.timeout_spin = QSpinBox()
            self.timeout_spin.setRange(1, 60)
            self.timeout_spin.setValue(8)
            options_layout.addWidget(self.timeout_spin)
            options_layout.addStretch()
            self.ai_check = QCheckBox("AI 语义校验")
            self.ai_check.setChecked(True)
            self.ai_check.setToolTip("使用 DeepSeek AI 对返回200的页面进行语义分析")
            options_layout.addWidget(self.ai_check)
            self.root_check = QCheckBox("根目录扫描")
            self.root_check.setChecked(True)
            options_layout.addWidget(self.root_check)
            self.traversal_check = QCheckBox("目录穿越探测")
            self.traversal_check.setChecked(True)
            options_layout.addWidget(self.traversal_check)
            input_layout.addLayout(options_layout)

            btn_layout = QHBoxLayout()
            self.start_btn = QPushButton("🚀 开始扫描")
            self.start_btn.setStyleSheet(
                "QPushButton { background-color: #0078D4; color: white; padding: 8px 20px; font-size: 14px; border-radius: 4px; }"
                "QPushButton:hover { background-color: #106EBE; }"
                "QPushButton:disabled { background-color: #ccc; }"
            )
            self.start_btn.clicked.connect(self.start_scan)
            btn_layout.addWidget(self.start_btn)
            self.stop_btn = QPushButton("⏹ 停止")
            self.stop_btn.setEnabled(False)
            btn_layout.addWidget(self.stop_btn)
            btn_layout.addStretch()
            self.save_btn = QPushButton("💾 导出报告")
            self.save_btn.clicked.connect(self.save_report)
            self.save_btn.setEnabled(False)
            btn_layout.addWidget(self.save_btn)
            input_layout.addLayout(btn_layout)
            main_layout.addWidget(input_group)

            self.progress_bar = QProgressBar()
            self.progress_bar.setVisible(False)
            main_layout.addWidget(self.progress_bar)

            result_group = QGroupBox("📊 扫描结果")
            result_layout = QVBoxLayout(result_group)
            self.stats_label = QLabel("就绪 - 请输入目标 URL 和字典文件，然后点击「开始扫描」")
            self.stats_label.setStyleSheet("color: #666; padding: 5px;")
            result_layout.addWidget(self.stats_label)

            self.tabs = QTabWidget()
            self.log_text = QTextEdit()
            self.log_text.setReadOnly(True)
            self.log_text.setFont(QFont("Consolas", 10))
            self.tabs.addTab(self.log_text, "📝 扫描日志")

            self.vuln_tree = QTreeWidget()
            self.vuln_tree.setHeaderLabels(["风险等级", "路径", "分类", "原因"])
            self.vuln_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            self.vuln_tree.header().setSectionResizeMode(1, QHeaderView.Stretch)
            self.vuln_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
            self.vuln_tree.header().setSectionResizeMode(3, QHeaderView.Stretch)
            self.tabs.addTab(self.vuln_tree, "⚠️ 漏洞详情")

            self.summary_text = QTextEdit()
            self.summary_text.setReadOnly(True)
            self.summary_text.setFont(QFont("Microsoft YaHei", 10))
            self.tabs.addTab(self.summary_text, "📄 结果摘要")

            result_layout.addWidget(self.tabs)
            main_layout.addWidget(result_group)

            self.log("🔍 敏感文件扫描工具 v1.0 已启动")
            self.log(f"AI 引擎: DeepSeek ({MODEL})")
            self.log("")

        def log(self, msg):
            self.log_text.append(msg)
            self.log_text.moveCursor(QTextCursor.End)
            QApplication.processEvents()

        def browse_dict(self):
            file_path, _ = QFileDialog.getOpenFileName(self, "选择字典文件", "", "文本文件 (*.txt);;所有文件 (*)")
            if file_path:
                self.dict_input.setText(file_path)

        def start_scan(self):
            url = self.url_input.text().strip()
            dict_file = self.dict_input.text().strip()
            if not url:
                QMessageBox.warning(self, "错误", "请输入目标 URL")
                return
            if not dict_file:
                QMessageBox.warning(self, "错误", "请选择字典文件")
                return
            if not url.startswith("http"):
                url = "https://" + url
                self.url_input.setText(url)
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.save_btn.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            self.vuln_tree.clear()
            self.summary_text.clear()
            self.log(f"\n{'='*60}")
            self.log(f"开始扫描: {url}")
            self.log(f"字典文件: {dict_file}")
            self.log(f"{'='*60}\n")
            self.worker = ScanWorker(
                url=url, dict_file=dict_file,
                concurrency=self.concurrency_spin.value(),
                timeout=self.timeout_spin.value(),
                use_ai=self.ai_check.isChecked(),
                scan_root=self.root_check.isChecked(),
                scan_traversal=self.traversal_check.isChecked()
            )
            self.worker.update_signal.connect(self.log)
            self.worker.finished_signal.connect(self.on_scan_finished)
            self.worker.start()

        def on_scan_finished(self, results):
            self.results = results
            self.progress_bar.setVisible(False)
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.save_btn.setEnabled(True)
            vulns = results.get("vulnerabilities", [])
            fps = results.get("false_positives", [])
            redirects = results.get("redirects", [])
            forbiddens = results.get("forbidden", [])
            errors = results.get("errors", [])
            stats = (f"扫描完成 | ⚠️ 真实漏洞: {len(vulns)} | 🚫 误报: {len(fps)} | "
                     f"🔄 重定向: {len(redirects)} | 🔒 禁止访问: {len(forbiddens)} | ❌ 错误: {len(errors)}")
            self.stats_label.setText(stats)
            self.stats_label.setStyleSheet("color: red; font-weight: bold; padding: 5px;" if vulns else "color: green; padding: 5px;")
            self.log(f"\n扫描完成! 真实漏洞: {len(vulns)}, 误报: {len(fps)}")
            risk_order = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "信息": 4}
            sorted_vulns = sorted(vulns, key=lambda x: risk_order.get(x.get("risk_display", "信息"), 5))
            for vuln in sorted_vulns:
                item = QTreeWidgetItem([
                    vuln.get("risk_display", "N/A"),
                    vuln.get("path", ""),
                    vuln.get("category", "N/A"),
                    vuln.get("reason", "")[:150]
                ])
                colors = {"严重": QColor(255, 0, 0), "高危": QColor(255, 128, 0),
                          "中危": QColor(255, 200, 0), "低危": QColor(0, 128, 0),
                          "信息": QColor(0, 0, 255)}
                color = colors.get(vuln.get("risk_display", "信息"), QColor(0, 0, 0))
                for i in range(4):
                    item.setForeground(i, color)
                self.vuln_tree.addTopLevelItem(item)
            summary = f"# 📊 扫描结果摘要\n\n"
            summary += f"- 真实漏洞: **{len(vulns)}** 个\n"
            summary += f"- 误报(假200): **{len(fps)}** 个\n"
            summary += f"- 重定向: **{len(redirects)}** 个\n"
            summary += f"- 禁止访问: **{len(forbiddens)}** 个\n"
            summary += f"- 错误: **{len(errors)}** 个\n\n"
            if vulns:
                summary += "## ⚠️ 漏洞详情\n\n"
                for i, vuln in enumerate(sorted_vulns, 1):
                    summary += f"### {i}. [{vuln.get('risk_display', 'N/A')}] {vuln.get('path')}\n\n"
                    summary += f"- **URL:** {vuln.get('url')}\n"
                    summary += f"- **分类:** {vuln.get('category', 'N/A')}\n"
                    if vuln.get('redirect_chain'):
                        summary += f"- **重定向链:** {vuln.get('redirect_chain')}\n"
                    summary += f"- **原因:** {vuln.get('reason', 'N/A')}\n"
                    if vuln.get('leaked_fields'):
                        summary += f"- **泄露字段:** {', '.join(vuln.get('leaked_fields'))}\n"
                    summary += "\n"
            self.summary_text.setMarkdown(summary)
            if vulns:
                self.tabs.setCurrentIndex(1)
            self.log("\n✅ 扫描完成！可在「漏洞详情」和「结果摘要」标签页查看结果")

        def save_report(self):
            file_path, _ = QFileDialog.getSaveFileName(self, "保存报告", "scan_report.md", "Markdown 文件 (*.md);;所有文件 (*)")
            if file_path:
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(self.summary_text.toPlainText())
                    QMessageBox.information(self, "成功", f"报告已保存到:\n{file_path}")
                except Exception as e:
                    QMessageBox.warning(self, "错误", f"保存失败: {str(e)}")

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


def main():
    parser = argparse.ArgumentParser(description="🔍 敏感文件扫描工具 - 基于 DeepSeek AI 的自动化扫描")
    parser.add_argument("--url", type=str, help="目标 URL")
    parser.add_argument("--dict", type=str, default="dicts/sensitive_paths.txt", help="敏感路径字典文件")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help=f"并发线程数 (默认: {DEFAULT_CONCURRENCY})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"请求超时秒数 (默认: {DEFAULT_TIMEOUT})")
    parser.add_argument("--no-ai", action="store_true", help="禁用 AI 语义校验")
    parser.add_argument("--no-root", action="store_true", help="禁用根目录扫描")
    parser.add_argument("--no-traversal", action="store_true", help="禁用目录穿越探测")
    parser.add_argument("--gui", action="store_true", help="启动图形界面")
    args = parser.parse_args()
    if args.gui:
        launch_gui()
        return
    if not args.url:
        parser.print_help()
        print("\n[!] 请指定 --url 参数，或使用 --gui 启动图形界面")
        sys.exit(1)
    scanner = SensitiveScanner(
        url=args.url, dict_file=args.dict,
        concurrency=args.concurrency, timeout=args.timeout,
        use_ai=not args.no_ai, scan_root=not args.no_root,
        scan_traversal=not args.no_traversal
    )
    scanner.run()


if __name__ == "__main__":
    main()
