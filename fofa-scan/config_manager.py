"""
配置管理模块
"""
import json
import os
from pathlib import Path


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self.config_file = self.config_dir / "settings.json"
        self._config = self._load()
        
    def _load(self) -> dict:
        """加载配置"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
        
    def save(self) -> bool:
        """保存配置"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"保存配置失败: {e}")
            return False
            
    def get(self, key: str, default=None):
        """获取配置项"""
        return self._config.get(key, default)
        
    def set(self, key: str, value) -> None:
        """设置配置项"""
        self._config[key] = value
        
    def get_cookie(self) -> str:
        """获取 Cookie"""
        return self.get('fofa_cookie', '')
        
    def set_cookie(self, cookie: str) -> None:
        """设置 Cookie"""
        self.set('fofa_cookie', cookie)
        self.save()
