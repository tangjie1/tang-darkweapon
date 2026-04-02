"""
Fofa 爬虫核心模块
唐门-暗之器 - 网络安全工具集
"""
import time
import random
import logging
from typing import List, Dict, Optional, Callable
from urllib.parse import quote
import requests
from lxml import etree

logger = logging.getLogger(__name__)


class FofaSpider:
    """Fofa 搜索引擎爬虫"""
    
    BASE_URL = "https://fofa.info"
    SEARCH_URL = f"{BASE_URL}/result"
    
    def __init__(self, cookie: str, authorization: str = "", timeout: int = 30, delay: tuple = (3, 6)):
        self.cookie = cookie
        self.authorization = authorization
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self._setup_headers()
        self._stop_flag = False
        self._pause_flag = False
        
    def _setup_headers(self) -> None:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Cookie": self.cookie,
            "Connection": "keep-alive",
        }
        if self.authorization:
            headers["Authorization"] = self.authorization
        self.session.headers.update(headers)
        
    def _make_request(self, url: str, params=None):
        try:
            response = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True)
            response.raise_for_status()
            return response.text
        except requests.exceptions.Timeout:
            logger.error(f"请求超时: {url}")
        except requests.exceptions.ConnectionError:
            logger.error(f"连接错误: {url}")
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP 错误 {e.response.status_code}: {url}")
        except requests.exceptions.RequestException as e:
            logger.error(f"请求异常: {e}")
        return None
        
    def _parse_results(self, html: str):
        """
        解析搜索结果页面 (适配 2026 年新版 FOFA HTML 结构)

        新版结构：
          - Host: //span[@class="hsxa-host"]/a[1]/@href
          - Port: //a[@class="hsxa-port"]/text()
          - Title: //p[contains(@class,"hsxa-one-line")]/text()
        """
        import re as _re
        results = []
        try:
            tree = etree.HTML(html)
            hosts = tree.xpath('//span[@class="hsxa-host"]/a[1]/@href')
            ports = tree.xpath('//a[@class="hsxa-port"]/text()')
            titles = tree.xpath('//p[contains(@class,"hsxa-one-line")]/text()')
            _ip_pattern = _re.compile(r'^https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            for i, host in enumerate(hosts):
                try:
                    host = host.strip() if host else ""
                    if not host:
                        continue
                    ip_match = _ip_pattern.match(host)
                    ip = ip_match.group(1) if ip_match else ""
                    result = {
                        "host": host,
                        "ip": ip,
                        "port": ports[i].strip() if i < len(ports) else "",
                        "title": titles[i].strip() if i < len(titles) else "",
                        "protocol": "https" if host.startswith("https") else "http",
                    }
                    results.append(result)
                except Exception as e:
                    logger.warning("解析单项结果时出错: %s", e)
                    continue
        except Exception as e:
            logger.error("解析页面失败: %s", e)
        return results

    def search(self, keyword, start_page=1, end_page=1, progress_callback=None, result_callback=None):
        all_results = []
        total_pages = end_page - start_page + 1
        for page in range(start_page, end_page + 1):
            if self._stop_flag:
                break
            while self._pause_flag and not self._stop_flag:
                time.sleep(0.5)
                if progress_callback:
                    progress_callback(page, total_pages, "已暂停")
            params = {"qbase64": self._encode_keyword(keyword), "page": page}
            if progress_callback:
                progress_callback(page, total_pages, f"正在请求第 {page} 页...")
            html = self._make_request(self.SEARCH_URL, params)
            if html is None:
                if progress_callback:
                    progress_callback(page, total_pages, f"第 {page} 页请求失败")
                continue
            results = self._parse_results(html)
            all_results.extend(results)
            if progress_callback:
                progress_callback(page, total_pages, f"第 {page} 页完成，获取 {len(results)} 条")
            if result_callback:
                result_callback(results)
            if page < end_page:
                time.sleep(random.uniform(*self.delay))
        return all_results
        
    def _encode_keyword(self, keyword: str) -> str:
        import base64
        return base64.b64encode(keyword.encode()).decode()
        
    def stop(self): self._stop_flag = True; self._pause_flag = False
    def pause(self): self._pause_flag = True
    def resume(self): self._pause_flag = False
    def reset(self): self._stop_flag = False; self._pause_flag = False


def save_results_to_file(results, filepath, format_type="txt"):
    try:
        if format_type.lower() == "csv":
            return _save_csv(results, filepath)
        else:
            return _save_txt(results, filepath)
    except Exception as e:
        logger.error(f"保存文件失败: {e}")
        return False


def _save_txt(results, filepath):
    with open(filepath, 'w', encoding='utf-8') as f:
        for item in results:
            line = f"{item.get('host', '')} | {item.get('ip', '')}:{item.get('port', '')} | {item.get('title', '')}\n"
            f.write(line)
    return True


def _save_csv(results, filepath):
    import csv
    if not results:
        return True
    fieldnames = ['host', 'ip', 'port', 'title', 'protocol']
    with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    return True
