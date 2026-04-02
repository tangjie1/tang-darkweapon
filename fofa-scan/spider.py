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
        """
        初始化爬虫
        
        Args:
            cookie: Fofa 登录 Cookie
            authorization: Fofa Authorization（可选，某些账号需要）
            timeout: 请求超时时间（秒）
            delay: 请求间隔随机范围 (最小, 最大)
        """
        self.cookie = cookie
        self.authorization = authorization
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self._setup_headers()
        self._stop_flag = False
        self._pause_flag = False
        
    def _setup_headers(self) -> None:
        """配置请求头"""
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
        
        # 添加 Authorization（如果提供）
        if self.authorization:
            headers["Authorization"] = self.authorization
            
        self.session.headers.update(headers)
        
    def _make_request(self, url: str, params: Optional[Dict] = None) -> Optional[str]:
        """
        发送 HTTP 请求
        
        Returns:
            响应内容或 None（如果失败）
        """
        try:
            response = self.session.get(
                url, 
                params=params, 
                timeout=self.timeout,
                allow_redirects=True
            )
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
        
    def _parse_results(self, html: str) -> List[Dict[str, str]]:
        """
        解析搜索结果页面 (适配 2026 年新版 FOFA HTML 结构)

        新版结构：
          - Host: //span[@class="hsxa-host"]/a[1]/@href  (每个span有2个a，取第一个)
          - Port: //a[@class="hsxa-port"]/text()         (独立的 <a> 标签)
          - Title: //p[contains(@class,"hsxa-one-line")]/text()
          
        Args:
            html: 页面 HTML 内容
            
        Returns:
            结果列表，每项包含 host, ip, port, title 等字段
        """
        import re as _re
        results = []
        
        try:
            tree = etree.HTML(html)
            
            # Host URL: 每个 hsxa-host span 包含两个 <a>，取第一个 href
            hosts = tree.xpath('//span[@class="hsxa-host"]/a[1]/@href')
            
            # Port: 新版使用 <a class="hsxa-port"> 标签
            ports = tree.xpath('//a[@class="hsxa-port"]/text()')
            
            # Title: <p class="hsxa-one-line ..."> 标签
            titles = tree.xpath('//p[contains(@class,"hsxa-one-line")]/text()')
            
            # IP 从 host URL 中提取
            _ip_pattern = _re.compile(r'^https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            
            for i, host in enumerate(hosts):
                try:
                    host = host.strip() if host else ""
                    if not host:
                        continue
                    
                    # 从 URL 中提取 IP（仅对纯 IP 地址有效，域名留空）
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
        
    def _extract_text(self, element, xpath: str) -> str:
        """安全提取文本"""
        try:
            texts = element.xpath(xpath)
            return "".join(t.strip() for t in texts if t.strip())
        except:
            return ""
            
    def search(
        self,
        keyword: str,
        start_page: int = 1,
        end_page: int = 1,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        result_callback: Optional[Callable[[List[Dict]], None]] = None
    ) -> List[Dict[str, str]]:
        """
        执行搜索
        
        Args:
            keyword: 搜索关键词
            start_page: 起始页码
            end_page: 结束页码
            progress_callback: 进度回调函数 (当前页, 总页数, 状态信息)
            result_callback: 每页结果回调函数
            
        Returns:
            所有结果列表
        """
        all_results = []
        total_pages = end_page - start_page + 1
        
        logger.info(f"开始搜索: '{keyword}', 页码范围: {start_page}-{end_page}")
        
        for page in range(start_page, end_page + 1):
            # 检查停止标志
            if self._stop_flag:
                logger.info("搜索已停止")
                break
                
            # 处理暂停
            while self._pause_flag and not self._stop_flag:
                time.sleep(0.5)
                if progress_callback:
                    progress_callback(page, total_pages, "已暂停")
                    
            # 发送请求
            params = {
                "qbase64": self._encode_keyword(keyword),
                "page": page
            }
            
            if progress_callback:
                progress_callback(page, total_pages, f"正在请求第 {page} 页...")
                
            html = self._make_request(self.SEARCH_URL, params)
            
            if html is None:
                logger.error(f"第 {page} 页请求失败")
                if progress_callback:
                    progress_callback(page, total_pages, f"第 {page} 页请求失败")
                continue
                
            # 解析结果
            results = self._parse_results(html)
            all_results.extend(results)
            
            logger.info(f"第 {page} 页获取到 {len(results)} 条结果")
            
            if progress_callback:
                progress_callback(page, total_pages, f"第 {page} 页完成，获取 {len(results)} 条")
                
            if result_callback:
                result_callback(results)
                
            # 延迟，避免请求过快
            if page < end_page:
                delay = random.uniform(*self.delay)
                time.sleep(delay)
                
        logger.info(f"搜索完成，共获取 {len(all_results)} 条结果")
        return all_results
        
    def _encode_keyword(self, keyword: str) -> str:
        """Base64 编码搜索关键词"""
        import base64
        return base64.b64encode(keyword.encode()).decode()
        
    def stop(self) -> None:
        """停止搜索"""
        self._stop_flag = True
        self._pause_flag = False
        logger.info("收到停止信号")
        
    def pause(self) -> None:
        """暂停搜索"""
        self._pause_flag = True
        logger.info("收到暂停信号")
        
    def resume(self) -> None:
        """继续搜索"""
        self._pause_flag = False
        logger.info("收到继续信号")
        
    def reset(self) -> None:
        """重置状态"""
        self._stop_flag = False
        self._pause_flag = False
        logger.info("状态已重置")


def save_results_to_file(
    results: List[Dict[str, str]], 
    filepath: str,
    format_type: str = "txt"
) -> bool:
    """
    保存结果到文件
    
    Args:
        results: 结果列表
        filepath: 文件路径
        format_type: 格式类型 (txt/csv)
        
    Returns:
        是否成功
    """
    try:
        if format_type.lower() == "csv":
            return _save_csv(results, filepath)
        else:
            return _save_txt(results, filepath)
    except Exception as e:
        logger.error(f"保存文件失败: {e}")
        return False


def _save_txt(results: List[Dict[str, str]], filepath: str) -> bool:
    """保存为 TXT 格式"""
    with open(filepath, 'w', encoding='utf-8') as f:
        for item in results:
            line = f"{item.get('host', '')} | {item.get('ip', '')}:{item.get('port', '')} | {item.get('title', '')}\n"
            f.write(line)
    return True


def _save_csv(results: List[Dict[str, str]], filepath: str) -> bool:
    """保存为 CSV 格式"""
    import csv
    
    if not results:
        return True
        
    fieldnames = ['host', 'ip', 'port', 'title', 'protocol']
    
    with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    return True
