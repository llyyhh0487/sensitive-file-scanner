#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
敏感文件扫描工具 - Sensitive File Scanner
==========================================
功能：
  1. 输入一个 URL 和敏感路径字典
  2. 批量扫描所有路径
  3. 对返回 200 的路径，调用 DeepSeek API 做 AI 语义校验
  4. 输出最终的真实漏洞结果（中文）
  5. 图形化界面

依赖：pip install requests aiohttp
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import sys
import time
import threading
import queue
import hashlib
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

# ============================================================
# 常量配置
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_DICT = PROJECT_ROOT / "dicts" / "sensitive_paths.txt"
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
VERSION = "2.0.0"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

# 常见的 404 页面特征关键词
FALSE_POSITIVE_INDICATORS = [
    "404 not found", "page not found", "页面不存在", "找不到页面",
    "找不到", "无法找到", "error 404", "not found",
    "does not exist", "doesn't exist", "sorry, the page",
    "没有找到", "您访问的页面不存在", "页面未找到",
    "请求的页面不存在", "所请求的页面不存在", "can't be found",
    "cannot be found", "url not found", "file not found",
    "oops", "nothing here", "no such file",
]


# ============================================================
# 工具函数
# ============================================================

def normalize_url(url: str) -> str:
    """规范化 URL，确保有 http(s):// 前缀且不以 / 结尾。"""
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def extract_title(html: str) -> str:
    """提取 HTML 页面标题。"""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()
    return "(无标题)"


def check_local_false_positive(content: str) -> Tuple[bool, str]:
    """本地规则快速判断是否为误报（返回 200 但实际是 404）。"""
    content_lower = content.lower()
    hit_count = 0
    hit_keywords: List[str] = []
    for kw in FALSE_POSITIVE_INDICATORS:
        if kw in content_lower:
            hit_count += 1
            hit_keywords.append(kw)
    if hit_count >= 2:
        return True, f"本地规则命中 {hit_count} 个 404 特征词: {', '.join(hit_keywords[:3])}"
    if len(content.strip()) < 30:
        return True, f"响应内容过短 ({len(content.strip())} 字符)"
    return False, ""


# ============================================================
# LRU 缓存
# ============================================================

class LRUCache(OrderedDict):
    """基于 OrderedDict 的 LRU 缓存。"""
    def __init__(self, maxsize: int = 500):
        super().__init__()
        self.maxsize = maxsize

    def get(self, key: str, default: Any = None) -> Any:
        if key in self:
            self.move_to_end(key)
            return self[key]
        return default

    def set(self, key: str, value: Any) -> None:
        if key in self:
            self.move_to_end(key)
        self[key] = value
        if len(self) > self.maxsize:
            self.popitem(last=False)


# ============================================================
# DeepSeek AI 接口
# ============================================================

class DeepSeekAI:
    """DeepSeek API 封装，用于语义判断是否为真正的敏感文件。"""

    AI_PROMPT = """你是一名资深网络安全专家。请分析以下 HTTP 响应，判断该 URL 是否是：
1. **真实敏感文件**（确实暴露了敏感信息，如配置文件、数据库、密钥、源码等）
2. **误报**（虽然返回 200 状态码，但内容是自定义 404 页面、首页重定向、空页面或无关内容）

目标 URL：{url}
HTTP 状态码：{status}
内容类型：{content_type}
页面标题：{title}
响应内容前 1500 字符：
```
{content}
```

请严格按以下 JSON 格式输出，不要添加任何其他内容：
{{
  "is_vulnerable": true或false,
  "confidence": "high/medium/low",
  "risk_level": "high/medium/low/info",
  "summary": "一句话中文描述这个发现（如果 is_vulnerable 为 true），或说明为什么是误报（如果 is_vulnerable 为 false）",
  "file_category": "敏感文件分类，如：配置文件/数据库文件/密钥文件/备份文件/日志文件/管理后台/API接口/源码泄露/其他",
  "suggestion": "如果 is_vulnerable 为 true，用中文给出简略的修复建议（2-3句话，说明应该怎么做）。如果 is_vulnerable 为 false，此字段为空字符串"
}}

判断标准：
- 如果内容是自定义 404 页面、首页、登录页重定向到首页，则 is_vulnerable=false
- 如果内容确实暴露了敏感信息（数据库密码、API密钥、服务器配置、源码等），则 is_vulnerable=true
- 注意很多网站对所有不存在的路径都返回 200，但内容是自定义错误页"""
    
    def __init__(self, api_key: str = DEEPSEEK_API_KEY):
        self.api_key = api_key
        self.cache = LRUCache(maxsize=500)
    
    def _cache_key(self, url: str, content: str) -> str:
        raw = f"{url}|{hashlib.md5(content[:500].encode()).hexdigest()}"
        return hashlib.md5(raw.encode()).hexdigest()
    
    def analyze(self, url: str, status: int, content_type: str,
                content: str) -> Dict[str, Any]:
        """调用 DeepSeek API 进行语义分析。
        
        Returns:
            {
                "is_vulnerable": bool,
                "confidence": str,
                "risk_level": str,
                "summary": str,
                "file_category": str
            }
        """
        ck = self._cache_key(url, content)
        cached = self.cache.get(ck)
        if cached is not None:
            return cached
        
        title = extract_title(content)
        prompt = self.AI_PROMPT.format(
            url=url,
            status=status,
            content_type=content_type,
            title=title,
            content=content[:1500]
        )
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        
        payload = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": "你是一位资深网络安全专家，请严格按 JSON 格式输出分析结果。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 1024,
        }
        
        try:
            resp = requests.post(
                DEEPSEEK_API_URL,
                headers=headers,
                json=payload,
                timeout=25,
            )
            if resp.status_code == 200:
                data = resp.json()
                text = data["choices"][0]["message"]["content"].strip()
                result = self._parse_json(text)
                self.cache.set(ck, result)
                return result
            else:
                return self._fallback_analysis(url, content)
        except Exception:
            return self._fallback_analysis(url, content)
    
    def _parse_json(self, text: str) -> Dict[str, Any]:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        if "```json" in text:
            s = text.find("```json") + 7
            e = text.find("```", s)
            if e > s:
                try:
                    return json.loads(text[s:e].strip())
                except json.JSONDecodeError:
                    pass
        s = text.find("{")
        e = text.rfind("}")
        if s >= 0 and e > s:
            try:
                return json.loads(text[s:e+1])
            except json.JSONDecodeError:
                pass
        return {
            "is_vulnerable": False,
            "confidence": "low",
            "risk_level": "info",
            "summary": "AI 响应解析失败",
            "file_category": "未知",
            "suggestion": ""
        }
    
    def _fallback_analysis(self, url: str, content: str) -> Dict[str, Any]:
        is_fp, reason = check_local_false_positive(content)
        if is_fp:
            return {
                "is_vulnerable": False,
                "confidence": "low",
                "risk_level": "info",
                "summary": reason,
                "file_category": "误报",
                "suggestion": ""
            }
        content_lower = content.lower()
        sensitive_keywords = [
            "password", "secret", "api_key", "apikey", "access_key",
            "private_key", "token", "credential", "mysql", "postgresql",
            "mongodb", "redis", "jdbc", "connectionstring",
            "ssh-rsa", "-----begin rsa", "-----begin private",
            "-----begin openssh", "administrator", "root:",
            "数据库", "密码", "密钥", "配置",
        ]
        hit = [kw for kw in sensitive_keywords if kw in content_lower]
        if hit:
            return {
                "is_vulnerable": True,
                "confidence": "medium",
                "risk_level": "high",
                "summary": f"本地规则检测到敏感关键词: {', '.join(hit[:5])}",
                "file_category": "敏感文件",
                "suggestion": "建议立即检查该文件是否暴露了敏感信息，如有密码/密钥应立即更换，并通过 .htaccess 或 Nginx 规则禁止直接访问。"
            }
        return {
            "is_vulnerable": True,
            "confidence": "low",
            "risk_level": "info",
            "summary": "返回 200，未检测到明显 404 特征，需人工确认",
            "file_category": "待确认",
            "suggestion": "建议人工访问该 URL 确认是否为敏感文件，必要时在 robots.txt 中声明禁止爬取并在服务器端配置访问控制。"
        }


# ============================================================
# 核心扫描引擎
# ============================================================

class SensitiveScanner:
    """敏感文件扫描引擎。"""
    
    def __init__(self, url: str, dict_path: str, concurrency: int = 5,
                 timeout: int = 8, use_ai: bool = True,
                 scan_root: bool = True,
                 use_traversal: bool = True,
                 traversal_triggers_file: str = None,
                 traversal_payloads_file: str = None,
                 log_callback=None, progress_callback=None):
        self.url = normalize_url(url)
        self.dict_path = dict_path
        self.concurrency = concurrency
        self.timeout = timeout
        self.use_ai = use_ai
        self.scan_root = scan_root
        self.use_traversal = use_traversal
        self.traversal_triggers_file = traversal_triggers_file
        self.traversal_payloads_file = traversal_payloads_file
        self.log = log_callback or (lambda msg, tag=None: None)
        self.progress = progress_callback or (lambda val, total: None)
        self._completed = 0
        
        self.ai = DeepSeekAI() if use_ai else None
        self._session_local = threading.local()
        self._session_headers = {"User-Agent": USER_AGENT}
        self.semaphore = asyncio.Semaphore(concurrency)
        self._executor = ThreadPoolExecutor(max_workers=concurrency)
        self.results: List[Dict[str, Any]] = []
        self.stats = {"total": 0, "200_count": 0, "vuln_count": 0, "fp_count": 0}
        self._lock = asyncio.Lock()
        self._seen_urls: Set[str] = set()
        self._404_fingerprints: Dict[int, str] = {}
        self._root_url: Optional[str] = None
    
    def _get_session(self) -> requests.Session:
        if not hasattr(self._session_local, "session"):
            s = requests.Session()
            s.headers.update(self._session_headers)
            s.max_redirects = 3
            self._session_local.session = s
        return self._session_local.session
    
    def _close_all_sessions(self):
        if hasattr(self._session_local, "session"):
            try:
                self._session_local.session.close()
            except Exception:
                pass
    
    def load_paths(self) -> List[str]:
        if not os.path.isfile(self.dict_path):
            raise FileNotFoundError(f"字典文件不存在: {self.dict_path}")
        paths = []
        with open(self.dict_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    paths.append(line)
        return paths
    
    def _load_traversal_paths(self) -> List[str]:
        triggers_file = self.traversal_triggers_file or str(PROJECT_ROOT / "dicts" / "traversal_triggers.txt")
        payloads_file = self.traversal_payloads_file or str(PROJECT_ROOT / "dicts" / "traversal_payloads.txt")
        triggers: List[str] = []
        payloads: List[str] = []
        for filepath, target_list, label in [
            (triggers_file, triggers, "触发路径"),
            (payloads_file, payloads, "穿越载荷"),
        ]:
            if not os.path.isfile(filepath):
                self.log(f"[系统] 目录穿越字典不存在 ({label}): {filepath}", "warning")
                continue
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        target_list.append(line)
        if not triggers or not payloads:
            self.log("[系统] 目录穿越字典为空，跳过穿越扫描", "info")
            return []
        combined: List[str] = []
        for trigger in triggers:
            trigger = trigger.rstrip("/") + "/"
            for payload in payloads:
                combined.append(f"{trigger}{payload}")
        self.log(f"[系统] 已加载目录穿越字典: {len(triggers)} × {len(payloads)} = {len(combined)} 条组合", "info")
        return combined
    
    async def scan(self) -> List[Dict[str, Any]]:
        paths = self.load_paths()
        total = len(paths)
        self.stats["total"] = total
        self.log(f"[系统] 目标 URL: {self.url}")
        self.log(f"[系统] 已加载 {total} 条敏感路径")
        parsed = urlparse(self.url)
        self._root_url = f"{parsed.scheme}://{parsed.netloc}"
        base_path = parsed.path.rstrip("/") if parsed.path else ""
        
        if self.scan_root and base_path and len(base_path) > 1:
            self.log(f"[系统] 根扫描模式：同时扫描根目录 {self._root_url} + 子目录 {self.url}")
        elif self.scan_root:
            self.log(f"[系统] 目标已是根目录，无需额外根扫描")
        self.log(f"[系统] 并发数: {self.concurrency} | AI 校验: {'开启' if self.use_ai else '关闭'}")
        self.log("-" * 60)
        
        self._session_local = threading.local()
        self._session_headers = {"User-Agent": USER_AGENT}
        
        self.log("[系统] 正在获取 404 基准页面用于指纹比对...")
        await self._get_404_baseline()
        
        tasks = [self._check_path(p) for p in paths]
        
        if self.scan_root and base_path and len(base_path) > 1:
            self.log(f"[系统] 追加根目录扫描任务 (+{len(paths)} 条)...")
            for p in paths:
                root_url = urljoin(self._root_url, p.lstrip("/"))
                if root_url not in self._seen_urls:
                    tasks.append(self._check_path_with_base(p, self._root_url))
        
        if self.use_traversal:
            traversal_paths = self._load_traversal_paths()
            if traversal_paths:
                self.log(f"[系统] 追加目录穿越扫描任务 (+{len(traversal_paths)} 条)...")
                for tp in traversal_paths:
                    traversal_url = self._root_url.rstrip("/") + "/" + tp.lstrip("/")
                    if traversal_url not in self._seen_urls:
                        tasks.append(self._check_path_with_base(tp, self._root_url))
        
        task_total = len(tasks)
        completed = 0
        
        for coro in asyncio.as_completed(tasks):
            await coro
            completed += 1
            self.progress(completed, task_total)
        
        self._close_all_sessions()
        
        self.log("=" * 60)
        self.log(f"[系统] 扫描完成")
        self.log(f"   总路径数: {self.stats['total']}")
        self.log(f"   实际请求: {task_total}")
        self.log(f"   返回 200: {self.stats['200_count']}")
        self.log(f"   真实漏洞: {self.stats['vuln_count']}")
        self.log(f"   已过滤误报: {self.stats['fp_count']}")
        self.log("=" * 60)
        
        return self.results
    
    async def _check_path_with_base(self, path: str, base_url: str):
        async with self.semaphore:
            if ".." in path:
                url = base_url.rstrip("/") + "/" + path.lstrip("/")
            else:
                url = urljoin(base_url, path.lstrip("/"))

            if url in self._seen_urls:
                return
            self._seen_urls.add(url)
            
            try:
                loop = asyncio.get_event_loop()
                resp = await loop.run_in_executor(
                    None,
                    lambda: self._get_session().get(
                        url,
                        timeout=self.timeout,
                        allow_redirects=False,
                        stream=True
                    )
                )
                content = ""
                try:
                    raw = resp.content
                    charset = "utf-8"
                    ct = resp.headers.get("Content-Type", "")
                    if "charset=" in ct:
                        charset = ct.split("charset=")[-1].split(";")[0].strip()
                    content = raw.decode(charset, errors="replace")
                except Exception:
                    content = resp.text if hasattr(resp, 'text') else ""
                
                status = resp.status_code
                content_type = resp.headers.get("Content-Type", "")
                
                if status == 200:
                    self.stats["200_count"] += 1
                    await self._analyze_200_response(url, status, content_type, content)
                elif status in (301, 302, 307, 308):
                    loc = resp.headers.get("Location", "")
                    self.log(f"[重定向-根] {url} -> {loc}，自动跟踪...", "info")
                    if loc:
                        redirect_result = await self._follow_redirect(url, status, loc)
                        if redirect_result:
                            if redirect_result.get("ai_result"):
                                ai = redirect_result["ai_result"]
                                risk = ai.get("risk_level", "high")
                                summary = ai.get("summary", "")
                                category = ai.get("category", "敏感文件")
                                suggestion = ai.get("suggestion", "")
                                if risk == "low":
                                    risk = "medium"
                                elif risk == "info":
                                    risk = "medium"
                                self.results.append({
                                    "url": redirect_result["chain"][-1],
                                    "redirect_from": url,
                                    "redirect_chain": redirect_result["chain"],
                                    "status": 200,
                                    "risk_level": risk,
                                    "confidence": ai.get("confidence", "medium"),
                                    "summary": f"根目录重定向跟踪 -> {summary}",
                                    "category": category,
                                    "suggestion": suggestion,
                                    "content_snippet": ai.get("content_snippet", redirect_result.get("content", "")),
                                    "ai_verified": True,
                                    "ai_reason": ai.get("reason", ""),
                                })
                            else:
                                if redirect_result.get("is_fp") and not redirect_result.get("fp_reason"):
                                    self.log(f"[重定向-根] 目标为通用不存在页面 (误报)", "info")
                                else:
                                    self.results.append({
                                        "url": redirect_result["chain"][-1],
                                        "redirect_from": url,
                                        "redirect_chain": redirect_result["chain"],
                                        "status": 200,
                                        "risk_level": "medium",
                                        "summary": f"根目录重定向跟踪 -> 被重定向到页面",
                                        "category": "重定向跟踪",
                                        "suggestion": "",
                                        "content_snippet": redirect_result.get("content", ""),
                                        "ai_verified": False,
                                    })
                        else:
                            self.log(f"[重定向-根] 自动跟踪失败，保存原始记录", "info")
                            self.results.append({
                                "url": url,
                                "status": status,
                                "risk_level": "info",
                                "confidence": "low",
                                "summary": f"根目录 - 重定向 -> {loc}" if loc else f"根目录 - 重定向 ({status})",
                                "category": "重定向",
                                "suggestion": "建议检查重定向目标是否指向敏感路径或登录页面",
                                "content_snippet": f"Location: {loc}" if loc else "",
                                "ai_verified": False,
                            })
                    else:
                        self.results.append({
                            "url": url,
                            "status": status,
                            "risk_level": "info",
                            "confidence": "low",
                            "summary": f"根目录 - 重定向 ({status})，无 Location 头",
                            "category": "重定向",
                            "suggestion": "",
                            "content_snippet": "",
                            "ai_verified": False,
                        })
                elif status == 403:
                    sensitive_headers = {}
                    for h in ("Server", "X-Powered-By", "X-AspNet-Version",
                              "X-AspNetMvc-Version", "X-Runtime", "X-Version",
                              "X-Generator", "X-Drupal-Cache", "X-Drupal-Dynamic-Cache"):
                        v = resp.headers.get(h)
                        if v:
                            sensitive_headers[h] = v
                    header_info = ", ".join(f"{k}: {v}" for k, v in sensitive_headers.items()) if sensitive_headers else ""
                    content_info = (content[:300] if content and len(content) > 10 else "") or ""
                    snippet = (header_info + "\n" + content_info).strip()

                    self.log(f"[发现-403-根] {url} (禁止访问，但路径存在)" +
                             (f" 头部: {header_info}" if header_info else ""), "warning")
                    self.results.append({
                        "url": url,
                        "status": 403,
                        "risk_level": "medium" if sensitive_headers else "low",
                        "summary": (
                            "根目录 - 路径存在但禁止访问 (403 Forbidden)"
                            + (f"，暴露服务器信息: {', '.join(sensitive_headers.values())}" if sensitive_headers else "")
                        ),
                        "category": "路径存在" if not sensitive_headers else "信息泄露",
                        "suggestion": (
                            "建议在服务器配置中隐藏版本信息，如设置 'ServerTokens Prod' (Apache) 或 'server_tokens off;' (Nginx)，"
                            "移除 X-Powered-By 等响应头"
                        ) if sensitive_headers else "",
                        "content_snippet": snippet,
                        "ai_verified": False,
                    })
                elif status == 401:
                    self.log(f"[发现-401-根] {url} (需要认证)", "warning")
                    self.results.append({
                        "url": url,
                        "status": 401,
                        "risk_level": "info",
                        "summary": "根目录 - 需要认证 (401 Unauthorized)",
                        "category": "认证页面",
                        "ai_verified": False,
                    })
                    
            except requests.Timeout:
                pass
            except requests.ConnectionError:
                pass
            except Exception:
                pass
    
    async def _follow_redirect(self, original_url: str, original_status: int,
                                location: str, max_hops: int = 3) -> Dict[str, Any]:
        current_url = original_url
        current_loc = location
        hops = 0
        redirect_chain = [original_url]

        while hops < max_hops and current_loc:
            next_url = urljoin(current_url, current_loc)
            if next_url in self._seen_urls:
                break
            self._seen_urls.add(next_url)

            if urlparse(next_url).netloc != urlparse(self.url).netloc:
                self.log(f"[重定向跟踪] 跨域中止: {next_url}", "info")
                break

            redirect_chain.append(next_url)
            hops += 1

            try:
                loop = asyncio.get_event_loop()
                resp = await loop.run_in_executor(
                    None,
                    lambda: self._get_session().get(
                        next_url,
                        timeout=self.timeout,
                        allow_redirects=False,
                        stream=True,
                    )
                )
                status = resp.status_code
                content = ""
                try:
                    raw = resp.content
                    charset = "utf-8"
                    ct = resp.headers.get("Content-Type", "")
                    if "charset=" in ct:
                        charset = ct.split("charset=")[-1].split(";")[0].strip()
                    content = raw.decode(charset, errors="replace")
                except Exception:
                    content = resp.text if hasattr(resp, 'text') else ""

                content_type = resp.headers.get("Content-Type", "")

                if status == 200:
                    self.log(f"[重定向跟踪] {original_url} -> ... -> {next_url} (200)，正在 AI 分析...", "info")
                    if self.use_ai and self.ai:
                        ai_result = self.ai.analyze(next_url, status, content_type, content)
                        return {
                            "original_url": original_url,
                            "final_url": next_url,
                            "chain": redirect_chain,
                            "status": 200,
                            "ai_result": ai_result,
                            "content": content[:300],
                        }
                    else:
                        is_fp, reason = check_local_false_positive(content)
                        return {
                            "original_url": original_url,
                            "final_url": next_url,
                            "chain": redirect_chain,
                            "status": 200,
                            "is_fp": is_fp,
                            "fp_reason": reason,
                            "content": content[:300],
                        }
                elif status in (301, 302, 307, 308):
                    current_url = next_url
                    current_loc = resp.headers.get("Location", "")
                    if not current_loc:
                        break
                elif status in (401, 403):
                    return {
                        "original_url": original_url,
                        "final_url": next_url,
                        "chain": redirect_chain,
                        "status": status,
                        "content": content[:300],
                    }
                else:
                    break
            except Exception:
                break

        return None

    async def _get_404_baseline(self):
        test_paths = [
            "/this_page_definitely_not_exists_404_test_" + str(int(time.time())),
            "/nonexistent_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
        ]
        for tp in test_paths:
            try:
                url = urljoin(self.url, tp)
                resp = self._get_session().get(url, timeout=self.timeout, allow_redirects=True)
                content = resp.text[:500]
                self._404_fingerprints[hash(content)] = content
                break
            except Exception:
                continue

    async def _check_path(self, path: str):
        async with self.semaphore:
            url = urljoin(self.url, path.lstrip("/"))

            if url in self._seen_urls:
                return
            self._seen_urls.add(url)

            try:
                loop = asyncio.get_event_loop()
                resp = await loop.run_in_executor(
                    None,
                    lambda: self._get_session().get(
                        url,
                        timeout=self.timeout,
                        allow_redirects=False,
                        stream=True
                    )
                )
                content = ""
                try:
                    raw = resp.content
                    charset = "utf-8"
                    ct = resp.headers.get("Content-Type", "")
                    if "charset=" in ct:
                        charset = ct.split("charset=")[-1].split(";")[0].strip()
                    content = raw.decode(charset, errors="replace")
                except Exception:
                    content = resp.text if hasattr(resp, 'text') else ""
                
                status = resp.status_code
                content_type = resp.headers.get("Content-Type", "")
                
                if status == 200:
                    self.stats["200_count"] += 1
                    await self._analyze_200_response(url, status, content_type, content)
                elif status in (301, 302, 307, 308):
                    loc = resp.headers.get("Location", "")
                    self.log(f"[重定向] {url} -> {loc}，自动跟踪...", "info")
                    if loc:
                        redirect_result = await self._follow_redirect(url, status, loc)
                        if redirect_result:
                            if redirect_result.get("ai_result"):
                                ai = redirect_result["ai_result"]
                                risk = ai.get("risk_level", "high")
                                summary = ai.get("summary", "")
                                category = ai.get("category", "敏感文件")
                                suggestion = ai.get("suggestion", "")
                                if risk == "low":
                                    risk = "medium"
                                elif risk == "info":
                                    risk = "medium"
                                self.results.append({
                                    "url": redirect_result["chain"][-1],
                                    "redirect_from": url,
                                    "redirect_chain": redirect_result["chain"],
                                    "status": 200,
                                    "risk_level": risk,
                                    "confidence": ai.get("confidence", "medium"),
                                    "summary": f"重定向跟踪 -> {summary}",
                                    "category": category,
                                    "suggestion": suggestion,
                                    "content_snippet": ai.get("content_snippet", redirect_result.get("content", "")),
                                    "ai_verified": True,
                                    "ai_reason": ai.get("reason", ""),
                                })
                            else:
                                if redirect_result.get("is_fp") and not redirect_result.get("fp_reason"):
                                    self.log(f"[重定向] 目标为通用不存在页面 (误报)", "info")
                                else:
                                    self.results.append({
                                        "url": redirect_result["chain"][-1],
                                        "redirect_from": url,
                                        "redirect_chain": redirect_result["chain"],
                                        "status": 200,
                                        "risk_level": "medium",
                                        "summary": f"重定向跟踪 -> 被重定向到页面",
                                        "category": "重定向跟踪",
                                        "suggestion": "",
                                        "content_snippet": redirect_result.get("content", ""),
                                        "ai_verified": False,
                                    })
                        else:
                            self.log(f"[重定向] 自动跟踪失败，保存原始记录", "info")
                            self.results.append({
                                "url": url,
                                "status": status,
                                "risk_level": "info",
                                "confidence": "low",
                                "summary": f"重定向 -> {loc}" if loc else f"重定向 ({status})",
                                "category": "重定向",
                                "suggestion": "建议检查重定向目标是否指向敏感路径或登录页面",
                                "content_snippet": f"Location: {loc}" if loc else "",
                                "ai_verified": False,
                            })
                    else:
                        self.results.append({
                            "url": url,
                            "status": status,
                            "risk_level": "info",
                            "confidence": "low",
                            "summary": f"重定向 ({status})，无 Location 头",
                            "category": "重定向",
                            "suggestion": "",
                            "content_snippet": "",
                            "ai_verified": False,
                        })
                elif status == 403:
                    sensitive_headers = {}
                    for h in ("Server", "X-Powered-By", "X-AspNet-Version",
                              "X-AspNetMvc-Version", "X-Runtime", "X-Version",
                              "X-Generator", "X-Drupal-Cache", "X-Drupal-Dynamic-Cache"):
                        v = resp.headers.get(h)
                        if v:
                            sensitive_headers[h] = v
                    header_info = ", ".join(f"{k}: {v}" for k, v in sensitive_headers.items()) if sensitive_headers else ""
                    content_info = (content[:300] if content and len(content) > 10 else "") or ""
                    snippet = (header_info + "\n" + content_info).strip()

                    self.log(f"[发现-403] {url} (禁止访问，但路径存在)" +
                             (f" 头部: {header_info}" if header_info else ""), "warning")
                    self.results.append({
                        "url": url,
                        "status": 403,
                        "risk_level": "medium" if sensitive_headers else "low",
                        "summary": (
                            "路径存在但禁止访问 (403 Forbidden)"
                            + (f"，暴露服务器信息: {', '.join(sensitive_headers.values())}" if sensitive_headers else "")
                        ),
                        "category": "路径存在" if not sensitive_headers else "信息泄露",
                        "suggestion": (
                            "建议在服务器配置中隐藏版本信息，如设置 'ServerTokens Prod' (Apache) 或 'server_tokens off;' (Nginx)，"
                            "移除 X-Powered-By 等响应头"
                        ) if sensitive_headers else "",
                        "content_snippet": snippet,
                        "ai_verified": False,
                    })
                elif status == 401:
                    self.log(f"[发现-401] {url} (需要认证)", "warning")
                    self.results.append({
                        "url": url,
                        "status": 401,
                        "risk_level": "info",
                        "summary": "需要认证 (401 Unauthorized)",
                        "category": "认证页面",
                        "ai_verified": False,
                    })
                    
            except requests.Timeout:
                self.log(f"[超时] {url} 请求超时", "dim")
            except requests.ConnectionError:
                self.log(f"[连接失败] {url} 无法连接", "dim")
            except Exception as e:
                self.log(f"[错误] {url} - {type(e).__name__}: {e}", "error")
    
    async def _analyze_200_response(self, url: str, status: int,
                                     content_type: str, content: str):
        content_hash = hash(content[:500])
        if content_hash in self._404_fingerprints:
            self.stats["fp_count"] += 1
            self.log(f"[过滤] {url} (与 404 基准页面指纹匹配)", "dim")
            return
        
        is_fp_local, reason_local = check_local_false_positive(content)
        if is_fp_local:
            self.stats["fp_count"] += 1
            self.log(f"[过滤] {url} - {reason_local}", "dim")
            return
        
        if self.use_ai and self.ai:
            self.log(f"[AI分析] {url} ...", "info")
            loop = asyncio.get_event_loop()
            ai_result = await loop.run_in_executor(
                self._executor,
                lambda: self.ai.analyze(url, status, content_type, content)
            )
            
            if not ai_result.get("is_vulnerable", False):
                self.stats["fp_count"] += 1
                self.log(
                    f"[AI过滤] {url} - {ai_result.get('summary', 'AI 判定为误报')}",
                    "dim"
                )
                return
            
            self.stats["vuln_count"] += 1
            risk = ai_result.get("risk_level", "medium")
            self.log(
                f"[✓ 漏洞] {url} | 风险:{risk} | {ai_result.get('summary', '')}",
                "success"
            )
            self.results.append({
                "url": url,
                "status": status,
                "risk_level": risk,
                "confidence": ai_result.get("confidence", "medium"),
                "summary": ai_result.get("summary", ""),
                "category": ai_result.get("file_category", "敏感文件"),
                "suggestion": ai_result.get("suggestion", ""),
                "content_snippet": content[:300],
                "ai_verified": True,
            })
        else:
            self.stats["vuln_count"] += 1
            self.log(f"[发现] {url} (状态码: 200)", "success")
            self.results.append({
                "url": url,
                "status": status,
                "risk_level": "info",
                "confidence": "low",
                "summary": "返回 200，未启用 AI 校验",
                "category": "待确认",
                "suggestion": "建议人工访问该 URL 确认是否为敏感文件，必要时在服务器端配置访问控制。",
                "content_snippet": content[:300],
                "ai_verified": False,
            })


# ============================================================
# 图形化界面 (Tkinter)
# ============================================================

class ScannerGUI:
    """敏感文件扫描工具 - 图形化界面。"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"敏感文件扫描工具 v{VERSION}")
        self.root.geometry("1050x800")
        self.root.minsize(900, 650)
        
        self.style = ttk.Style()
        available_themes = self.style.theme_names()
        if "clam" in available_themes:
            self.style.theme_use("clam")
        
        self.scanning = False
        self.scanner_thread: Optional[threading.Thread] = None
        self.log_queue = queue.Queue()
        self.results: List[Dict] = []
        
        self._build_menu()
        self._build_config_panel()
        self._build_button_bar()
        self._build_result_area()
        self._build_log_area()
        self._build_status_bar()
        
        self._start_log_poller()
        
        self.root.update_idletasks()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _build_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="选择字典文件...", command=self._select_dict)
        file_menu.add_command(label="导出结果 (JSON)...", command=self._export_json)
        file_menu.add_command(label="导出结果 (CSV)...", command=self._export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self._on_close)
        menubar.add_cascade(label="文件", menu=file_menu)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="使用帮助", command=self._show_help)
        help_menu.add_command(label="关于", command=self._show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)
    
    def _build_config_panel(self):
        frame = ttk.LabelFrame(self.root, text="扫描配置", padding=10)
        frame.pack(fill=tk.X, padx=12, pady=(10, 5))
        
        r1 = ttk.Frame(frame)
        r1.pack(fill=tk.X, pady=2)
        ttk.Label(r1, text="目标 URL:", width=12).pack(side=tk.LEFT)
        self.url_var = tk.StringVar(value="")
        ttk.Entry(r1, textvariable=self.url_var, width=55).pack(side=tk.LEFT, padx=5)
        ttk.Label(r1, text="例: https://example.com", foreground="gray").pack(side=tk.LEFT, padx=5)
        
        r2 = ttk.Frame(frame)
        r2.pack(fill=tk.X, pady=2)
        ttk.Label(r2, text="路径字典:", width=12).pack(side=tk.LEFT)
        self.dict_var = tk.StringVar(value=str(DEFAULT_DICT))
        ttk.Entry(r2, textvariable=self.dict_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(r2, text="浏览...", command=self._select_dict, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(r2, text="打开目录", command=self._open_dict_dir, width=8).pack(side=tk.LEFT, padx=2)
        
        r3 = ttk.Frame(frame)
        r3.pack(fill=tk.X, pady=2)
        ttk.Label(r3, text="并发数:", width=12).pack(side=tk.LEFT)
        self.concurrency_var = tk.IntVar(value=5)
        ttk.Spinbox(r3, from_=1, to=200, textvariable=self.concurrency_var, width=6).pack(side=tk.LEFT)
        
        ttk.Label(r3, text="超时(秒):", width=8).pack(side=tk.LEFT, padx=(15, 0))
        self.timeout_var = tk.IntVar(value=8)
        ttk.Spinbox(r3, from_=1, to=60, textvariable=self.timeout_var, width=6).pack(side=tk.LEFT)
        
        ttk.Label(r3, text="AI 语义校验:", width=10).pack(side=tk.LEFT, padx=(15, 0))
        self.ai_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(r3, variable=self.ai_var, text="启用 DeepSeek AI").pack(side=tk.LEFT)
        
        ttk.Label(r3, text="API Key:", width=7).pack(side=tk.LEFT, padx=(15, 0))
        self.apikey_var = tk.StringVar(value=DEEPSEEK_API_KEY if DEEPSEEK_API_KEY else "")
        ttk.Entry(r3, textvariable=self.apikey_var, width=30).pack(side=tk.LEFT, padx=3)
        
        ttk.Label(r3, text="扫描根目录:", width=10).pack(side=tk.LEFT, padx=(15, 0))
        self.scan_root_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(r3, variable=self.scan_root_var, text="同时扫描根目录").pack(side=tk.LEFT)

        r4 = ttk.Frame(frame)
        r4.pack(fill=tk.X, pady=2)
        ttk.Label(r4, text="目录穿越:", width=12).pack(side=tk.LEFT)
        self.traversal_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(r4, variable=self.traversal_var, text="启用目录穿越 (trigger × payload)").pack(side=tk.LEFT)

        ttk.Label(r4, text="触发路径:", width=8).pack(side=tk.LEFT, padx=(15, 0))
        self.traversal_triggers_var = tk.StringVar(value=str(PROJECT_ROOT / "dicts" / "traversal_triggers.txt"))
        ttk.Entry(r4, textvariable=self.traversal_triggers_var, width=28).pack(side=tk.LEFT, padx=3)
        ttk.Button(r4, text="浏览...", command=self._select_traversal_triggers, width=7).pack(side=tk.LEFT, padx=1)

        ttk.Label(r4, text="载荷:", width=5).pack(side=tk.LEFT, padx=(10, 0))
        self.traversal_payloads_var = tk.StringVar(value=str(PROJECT_ROOT / "dicts" / "traversal_payloads.txt"))
        ttk.Entry(r4, textvariable=self.traversal_payloads_var, width=28).pack(side=tk.LEFT, padx=3)
        ttk.Button(r4, text="浏览...", command=self._select_traversal_payloads, width=7).pack(side=tk.LEFT, padx=1)

    
    def _build_button_bar(self):
        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.X, padx=12, pady=(5, 5))
        
        self.start_btn = ttk.Button(
            frame, text="▶ 开始扫描", command=self._start_scan, width=14
        )
        self.start_btn.pack(side=tk.LEFT, padx=3)
        
        self.stop_btn = ttk.Button(
            frame, text="■ 停止扫描", command=self._stop_scan,
            state=tk.DISABLED, width=14
        )
        self.stop_btn.pack(side=tk.LEFT, padx=3)
        
        ttk.Button(
            frame, text="📋 复制结果", command=self._copy_results, width=14
        ).pack(side=tk.LEFT, padx=3)
        
        ttk.Button(
            frame, text="🗑 清空结果", command=self._clear_results, width=14
        ).pack(side=tk.LEFT, padx=3)
        
        ttk.Button(
            frame, text="💾 导出 JSON", command=self._export_json, width=14
        ).pack(side=tk.LEFT, padx=3)
        
        ttk.Button(
            frame, text="📊 导出 CSV", command=self._export_csv, width=14
        ).pack(side=tk.LEFT, padx=3)
    
    def _build_result_area(self):
        frame = ttk.LabelFrame(self.root, text="漏洞结果", padding=5)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(3, 3))
        
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, pady=2)
        
        ttk.Label(toolbar, text="风险筛选:").pack(side=tk.LEFT, padx=3)
        self.filter_var = tk.StringVar(value="全部")
        filter_combo = ttk.Combobox(
            toolbar, textvariable=self.filter_var, state="readonly",
            values=["全部", "高危", "中危", "低危", "信息"],
            width=8
        )
        filter_combo.pack(side=tk.LEFT, padx=3)
        filter_combo.bind("<<ComboboxSelected>>", lambda e: self._refresh_results())
        
        self.result_count_var = tk.StringVar(value="发现 0 个漏洞")
        ttk.Label(toolbar, textvariable=self.result_count_var, foreground="gray").pack(
            side=tk.RIGHT, padx=10
        )
        
        columns = ("risk", "url", "category", "summary")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", height=12)
        
        self.tree.heading("risk", text="风险")
        self.tree.heading("url", text="URL")
        self.tree.heading("category", text="分类")
        self.tree.heading("summary", text="摘要")
        
        self.tree.column("risk", width=70, anchor="center")
        self.tree.column("url", width=380)
        self.tree.column("category", width=120)
        self.tree.column("summary", width=350)
        
        vbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree.bind("<Double-1>", self._show_detail)
        
        self.tree.tag_configure("high", foreground="#cc0000", font=("微软雅黑", 9, "bold"))
        self.tree.tag_configure("medium", foreground="#e68a00")
        self.tree.tag_configure("low", foreground="#3366cc")
        self.tree.tag_configure("info", foreground="#666666")
    
    def _build_log_area(self):
        frame = ttk.LabelFrame(self.root, text="扫描日志", padding=5)
        frame.pack(fill=tk.BOTH, padx=12, pady=(3, 3))
        
        self.log_text = scrolledtext.ScrolledText(
            frame, wrap=tk.WORD, font=("Consolas", 9),
            bg="#1a1a2e", fg="#00cc66", insertbackground="white",
            height=8,
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        self.log_text.tag_configure("success", foreground="#00ff88")
        self.log_text.tag_configure("error", foreground="#ff4444")
        self.log_text.tag_configure("warning", foreground="#ffaa00")
        self.log_text.tag_configure("info", foreground="#44aaff")
        self.log_text.tag_configure("dim", foreground="#666688")
    
    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="就绪 - 请输入目标 URL 并点击「开始扫描」")
        bar = ttk.Label(
            self.root, textvariable=self.status_var,
            relief=tk.SUNKEN, anchor=tk.W, padding=(10, 2),
        )
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.progress_var = tk.IntVar(value=0)
        self.progress_bar = ttk.Progressbar(
            self.root, variable=self.progress_var, maximum=100, mode="determinate"
        )
        self.progress_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=12, pady=(0, 2))
    
    def _log(self, msg: str, tag: str = "info"):
        self.log_queue.put((msg, tag))
    
    def _start_log_poller(self):
        def poll():
            while True:
                try:
                    msg, tag = self.log_queue.get_nowait()
                    ts = datetime.now().strftime("%H:%M:%S")
                    self.log_text.insert(tk.END, f"[{ts}] {msg}\n", tag)
                    self.log_text.see(tk.END)
                except queue.Empty:
                    break
            self.root.after(80, poll)
        self.root.after(80, poll)
    
    def _start_scan(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("参数错误", "请输入目标 URL！")
            return
        
        dict_path = self.dict_var.get().strip()
        if not os.path.isfile(dict_path):
            messagebox.showwarning("参数错误", f"字典文件不存在:\n{dict_path}")
            return
        
        self._clear_results()
        self.log_text.delete(1.0, tk.END)
        self._log("=" * 50, "info")
        self._log(f"敏感文件扫描工具 v{VERSION}", "info")
        self._log(f"目标: {url}", "info")
        self._log(f"字典: {dict_path}", "info")
        self._log("=" * 50, "info")
        
        self.scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("扫描中...")
        self.progress_var.set(0)
        
        self.scanner_thread = threading.Thread(
            target=self._run_scan, args=(url, dict_path), daemon=True
        )
        self.scanner_thread.start()
    
    def _run_scan(self, url: str, dict_path: str):
        async def _do():
            scanner = SensitiveScanner(
                url=url,
                dict_path=dict_path,
                concurrency=self.concurrency_var.get(),
                timeout=self.timeout_var.get(),
                use_ai=self.ai_var.get(),
                scan_root=self.scan_root_var.get(),
                use_traversal=self.traversal_var.get(),
                traversal_triggers_file=self.traversal_triggers_var.get() or None,
                traversal_payloads_file=self.traversal_payloads_var.get() or None,
                log_callback=self._log,
                progress_callback=lambda v, t: self.root.after(
                    0, lambda: self.progress_var.set(int(v / t * 100))
                ),
            )
            return await scanner.scan()
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            results = loop.run_until_complete(_do())
            loop.close()
            
            self.results = results
            self.root.after(0, self._on_scan_finished)
        except Exception as e:
            self._log(f"[错误] 扫描异常: {e}", "error")
            self.root.after(0, self._on_scan_finished)
    
    def _on_scan_finished(self):
        self.scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set(
            f"扫描完成 - 共发现 {len(self.results)} 个漏洞"
        )
        self._refresh_results()
    
    def _stop_scan(self):
        self._log("⚠ 用户手动停止扫描", "warning")
        self.status_var.set("已停止")
        self._on_scan_finished()
    
    def _refresh_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        filter_val = self.filter_var.get()
        risk_map = {"高危": "high", "中危": "medium", "低危": "low", "信息": "info"}
        
        risk_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        sorted_results = sorted(
            self.results,
            key=lambda r: risk_order.get(r.get("risk_level", "info"), 99)
        )
        
        count = 0
        for r in sorted_results:
            level = r.get("risk_level", "info")
            if filter_val != "全部" and risk_map.get(filter_val) != level:
                continue
            
            label_map = {"high": "🔴 高危", "medium": "🟠 中危", "low": "🟡 低危", "info": "🔵 信息"}
            tag_map = {"high": "high", "medium": "medium", "low": "low", "info": "info"}
            
            self.tree.insert(
                "", tk.END,
                values=(
                    label_map.get(level, level),
                    r.get("url", ""),
                    r.get("category", ""),
                    r.get("summary", ""),
                ),
                tags=(tag_map.get(level, "info"),),
            )
            count += 1
        
        self.result_count_var.set(f"发现 {count} 个漏洞 (共 {len(self.results)} 个)")
    
    def _show_detail(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        url = item["values"][1]
        
        detail = None
        for r in self.results:
            if r.get("url") == url:
                detail = r
                break
        
        if not detail:
            return
        
        win = tk.Toplevel(self.root)
        win.title("漏洞详情")
        win.geometry("700x500")
        
        text = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("微软雅黑", 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        lines = [
            f"URL: {detail.get('url', '')}",
            f"状态码: {detail.get('status', '')}",
            f"风险等级: {detail.get('risk_level', '')}",
            f"AI 验证: {'是' if detail.get('ai_verified') else '否'}",
            f"置信度: {detail.get('confidence', '')}",
            f"分类: {detail.get('category', '')}",
            f"摘要: {detail.get('summary', '')}",
        ]
        
        suggestion = detail.get("suggestion", "")
        if suggestion:
            lines.append("")
            lines.append("━━━ 💡 修复建议 ━━━")
            lines.append(suggestion)
        
        lines.append("")
        lines.append("━━━ 响应内容片段 ━━━")
        lines.append(detail.get("content_snippet", "(无)"))
        
        text.insert(1.0, "\n".join(lines))
        text.config(state=tk.DISABLED)
    
    def _clear_results(self):
        self.results = []
        self._refresh_results()
        self.result_count_var.set("发现 0 个漏洞")
        self.progress_var.set(0)
    
    def _copy_results(self):
        lines = []
        for r in self.results:
            lines.append(f"{r.get('url')} | {r.get('risk_level')} | {r.get('category')} | {r.get('summary')}")
        if lines:
            text = "\n".join(lines)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("已复制", f"已复制 {len(lines)} 条结果到剪贴板")
        else:
            messagebox.showinfo("无结果", "没有可复制的结果")
    
    def _export_json(self):
        if not self.results:
            messagebox.showinfo("无结果", "没有可导出的结果")
            return
        fp = filedialog.asksaveasfilename(
            title="导出 JSON",
            defaultextension=".json",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")],
            initialfile=f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if fp:
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(self.results, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("导出成功", f"已导出到:\n{fp}")
    
    def _export_csv(self):
        if not self.results:
            messagebox.showinfo("无结果", "没有可导出的结果")
            return
        import csv
        fp = filedialog.asksaveasfilename(
            title="导出 CSV",
            defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")],
            initialfile=f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if fp:
            with open(fp, "w", encoding="utf-8-sig", newline="") as f:
                if self.results:
                    writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                    writer.writeheader()
                    writer.writerows(self.results)
            messagebox.showinfo("导出成功", f"已导出到:\n{fp}")
    
    def _select_dict(self):
        fp = filedialog.askopenfilename(
            title="选择敏感路径字典",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialdir=str(PROJECT_ROOT / "dicts"),
        )
        if fp:
            self.dict_var.set(fp)
    
    def _select_traversal_triggers(self):
        fp = filedialog.askopenfilename(
            title="选择目录穿越触发路径字典",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialdir=str(PROJECT_ROOT / "dicts"),
        )
        if fp:
            self.traversal_triggers_var.set(fp)

    def _select_traversal_payloads(self):
        fp = filedialog.askopenfilename(
            title="选择目录穿越载荷字典",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialdir=str(PROJECT_ROOT / "dicts"),
        )
        if fp:
            self.traversal_payloads_var.set(fp)

    def _open_dict_dir(self):
        d = str(PROJECT_ROOT / "dicts")
        os.makedirs(d, exist_ok=True)
        os.startfile(d)
    
    def _show_help(self):
        text = (
            "敏感文件扫描工具 - 使用帮助\n"
            "=" * 50 + "\n\n"
            "1️⃣ 输入目标 URL\n"
            "   - 支持 http:// 和 https://\n"
            "   - 如果未指定协议，默认使用 http://\n\n"
            "2️⃣ 选择路径字典\n"
            "   - 默认内置 500+ 敏感路径\n"
            "   - 可自定义字典文件（每行一个路径，支持 # 注释）\n\n"
            "3️⃣ 配置参数\n"
            "   - 并发数：同时扫描的请求数 (默认 5)\n"
            "   - 超时：每个请求的超时时间 (默认 8 秒)\n"
            "   - AI 语义校验：开启后对返回 200 的路径调用 DeepSeek AI 判断\n\n"
            "4️⃣ 开始扫描\n"
            "   - 点击「开始扫描」执行\n"
            "   - 实时显示日志和进度\n"
            "   - 结果在漏洞结果区域展示\n\n"
            "5️⃣ 结果处理\n"
            "   - 双击结果行查看详情\n"
            "   - 可按风险等级筛选\n"
            "   - 支持导出 JSON / CSV\n\n"
            "API Key 设置：\n"
            "请通过环境变量 DEEPSEEK_API_KEY 设置您的 API Key，\n"
            "或在 GUI 界面中直接填入。\n"
            "\nAI 校验原理：\n"
            "扫描工具先通过本地规则（404 关键词、指纹比对）快速过滤，\n"
            "再调用 DeepSeek API 对返回 200 的页面做语义分析，\n"
            "判断是真实敏感文件还是「软 404」（返回 200 但内容不对）。\n\n"
            "⚠️ 法律声明：\n"
            "本工具仅用于授权的安全评估，未经授权扫描他人系统可能违法。\n"
            "使用者需自行承担所有法律责任。"
        )
        win = tk.Toplevel(self.root)
        win.title("使用帮助")
        win.geometry("650x550")
        t = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("微软雅黑", 10))
        t.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        t.insert(1.0, text)
        t.config(state=tk.DISABLED)
    
    def _show_about(self):
        messagebox.showinfo(
            "关于",
            f"敏感文件扫描工具 v{VERSION}\n\n"
            "功能：\n"
            "  • 批量扫描目标 URL 的敏感路径\n"
            "  • 内置 500+ 敏感路径字典\n"
            "  • DeepSeek AI 语义校验去误报\n"
            "  • 中文图形化界面\n"
            "  • 支持导出的 JSON / CSV\n\n"
            "API Key 请通过环境变量 DEEPSEEK_API_KEY 设置\n"
            "或粘贴到 GUI 的 API Key 输入框中。\n\n"
            "API: DeepSeek Chat\n"
            "⚠️ 仅用于授权的安全评估"
        )
    
    def _on_close(self):
        if self.scanning:
            if not messagebox.askyesno("确认退出", "扫描正在进行中，确定退出吗？"):
                return
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()


# ============================================================
# 命令行入口
# ============================================================

def main_cli():
    import argparse
    parser = argparse.ArgumentParser(
        description=f"敏感文件扫描工具 v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python sensitive_scanner.py --url https://example.com
  python sensitive_scanner.py --url https://example.com --dict my_paths.txt --no-ai
  python sensitive_scanner.py --gui
        """
    )
    parser.add_argument("--url", "-u", help="目标 URL")
    parser.add_argument("--dict", "-d", default=str(DEFAULT_DICT), help="敏感路径字典文件")
    parser.add_argument("--concurrency", "-c", type=int, default=5, help="并发数 (默认 5)")
    parser.add_argument("--timeout", "-t", type=int, default=8, help="超时秒数 (默认 8)")
    parser.add_argument("--no-ai", action="store_true", help="禁用 AI 语义校验")
    parser.add_argument("--gui", "-g", action="store_true", help="启动图形化界面")
    parser.add_argument("--output", "-o", help="输出 JSON 结果文件")
    parser.add_argument("--no-root-scan", action="store_true", help="不扫描根目录")
    parser.add_argument("--no-traversal", action="store_true", help="禁用目录穿越扫描")
    
    args = parser.parse_args()
    
    if args.gui:
        ScannerGUI().run()
        return
    
    if not args.url:
        print("请指定目标 URL (--url) 或使用 --gui 启动图形界面")
        print("使用 --help 查看更多帮助")
        return
    
    async def run():
        scanner = SensitiveScanner(
            url=args.url,
            dict_path=args.dict,
            concurrency=args.concurrency,
            timeout=args.timeout,
            use_ai=not args.no_ai,
            scan_root=not args.no_root_scan,
            use_traversal=not args.no_traversal,
        )
        results = await scanner.scan()
        
        print("\n" + "=" * 60)
        print("【漏洞结果汇总】")
        print("=" * 60)
        for i, r in enumerate(results, 1):
            level_label = {"high": "🔴高危", "medium": "🟠中危", "low": "🟡低危", "info": "🔵信息"}
            level = level_label.get(r.get("risk_level", "info"), r.get("risk_level"))
            print(f"\n{i}. {level} | {r.get('category', '')}")
            print(f"   URL: {r.get('url', '')}")
            print(f"   摘要: {r.get('summary', '')}")
        
        if args.output and results:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"结果已导出到: {args.output}")
    
    asyncio.run(run())


if __name__ == "__main__":
    if len(sys.argv) == 1:
        ScannerGUI().run()
    else:
        main_cli()