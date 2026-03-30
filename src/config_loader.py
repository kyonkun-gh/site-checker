"""
設定檔載入模組

讀取並驗證 YAML 設定檔，提供應用程式所需的配置。
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ConfigLoader:
    """載入和驗證設定檔"""
    
    def __init__(self, config_path: str = "config/sites.yaml"):
        """
        初始化設定載入器
        
        參數：
            config_path: 設定檔路徑（相對於工作目錄）
        """
        self.config_path = Path(config_path)
        self.config = None
        
    def load(self) -> Dict[str, Any]:
        """
        載入 YAML 設定檔
        
        返回：
            設定檔內容（字典）
            
        拋出：
            FileNotFoundError: 設定檔不存在
            yaml.YAMLError: YAML 語法錯誤
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"設定檔不存在: {self.config_path}")
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
            logger.info(f"成功載入設定檔: {self.config_path}")
            return self.config
        except yaml.YAMLError as e:
            logger.error(f"YAML 語法錯誤: {e}")
            raise
        except Exception as e:
            logger.error(f"載入設定檔失敗: {e}")
            raise
    
    def get_email_config(self) -> Dict[str, Any]:
        """取得電子郵件設定"""
        if not self.config:
            self.load()
        return self.config.get("email", {})
    
    def get_sites(self) -> List[Dict[str, Any]]:
        """取得監控網站列表"""
        if not self.config:
            self.load()
        return self.config.get("sites", [])
    
    def get_check_interval(self) -> int:
        """取得檢查間隔（小時）"""
        if not self.config:
            self.load()
        return self.config.get("check_interval_hours", 1)
    
    def validate(self) -> bool:
        """
        驗證設定檔完整性
        
        返回：
            True 如果驗證通過，否則拋出例外
        """
        if not self.config:
            self.load()
        
        # 驗證必要欄位
        required_keys = ["email", "sites"]
        for key in required_keys:
            if key not in self.config:
                raise ValueError(f"設定檔缺少必要欄位: {key}")
        
        # 驗證電子郵件設定
        email_required = ["smtp_server", "smtp_port", "sender_email", "sender_name", "recipients"]
        email_config = self.config.get("email", {})
        for key in email_required:
            if key not in email_config:
                raise ValueError(f"電子郵件設定缺少必要欄位: {key}")
        
        # 驗證監控網站
        sites = self.config.get("sites", [])
        if not sites:
            raise ValueError("至少需要配置一個監控網站")
        
        for idx, site in enumerate(sites):
            if "url" not in site:
                raise ValueError(f"監控網站 #{idx+1} 缺少 'url' 欄位")
            if "expected_status" not in site:
                raise ValueError(f"監控網站 #{idx+1} 缺少 'expected_status' 欄位")
            if site["expected_status"] not in ["good", "expired", "revoked"]:
                raise ValueError(
                    f"監控網站 #{idx+1} 的 expected_status 值無效: {site['expected_status']}"
                )
        
        logger.info("設定檔驗證通過")
        return True
