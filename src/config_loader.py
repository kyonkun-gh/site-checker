"""
設定檔載入模組

讀取並驗證 YAML 設定檔，提供應用程式所需的配置。
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List

from password_manager import PasswordNormalizer, KeyManager

logger = logging.getLogger(__name__)


class ConfigLoader:
    """載入和驗證設定檔"""
    
    def __init__(self, config_path: str = "config/sites.yaml"):
        """
        初始化設定載入器
        
        參數：
            config_path: sites 設定檔路徑（相對於工作目錄）
        """
        self.config_path = Path(config_path)
        self.email_config_path = self.config_path.parent / "email.yaml"
        self.config = None
        self.email_config: Dict[str, Any] = {}
        
    def load(self) -> Dict[str, Any]:
        """
        載入 YAML 設定檔
        
        返回：
            sites 設定內容（字典）
            
        拋出：
            FileNotFoundError: 設定檔不存在
            yaml.YAMLError: YAML 語法錯誤
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"設定檔不存在: {self.config_path}")
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                loaded = yaml.safe_load(f) or {}

            if not isinstance(loaded, dict):
                raise ValueError(f"sites 設定檔格式錯誤，必須是字典: {self.config_path}")

            self.config = loaded
            logger.info(f"成功載入 sites 設定檔: {self.config_path}")

            self.email_config = self._load_email_config()
            return self.config
        except yaml.YAMLError as e:
            logger.error(f"YAML 語法錯誤: {e}")
            raise
        except Exception as e:
            logger.error(f"載入設定檔失敗: {e}")
            raise

    def _load_email_config(self) -> Dict[str, Any]:
        """載入 email.yaml，並自動正規化 smtp_password。
        
        - 明碼：自動加密並回寫到 email.yaml
        - 密文（{AES}...）：解密供執行期使用
        - 未設定（null/空）：保持原樣
        """
        if not self.email_config_path.exists():
            logger.warning(f"找不到 email 設定檔，將停用通知: {self.email_config_path}")
            return {}

        with open(self.email_config_path, 'r', encoding='utf-8') as f:
            loaded = yaml.safe_load(f) or {}

        if not isinstance(loaded, dict):
            raise ValueError(f"email 設定檔格式錯誤，必須是字典: {self.email_config_path}")

        logger.info(f"成功載入 email 設定檔: {self.email_config_path}")
        
        # 密碼正規化與加密
        try:
            key_manager = KeyManager()
            normalizer = PasswordNormalizer(key_manager)
            
            raw_password = loaded.get('smtp_password')
            plaintext_password = normalizer.normalize_and_get_plaintext(
                raw_password,
                self.email_config_path
            )
            
            # 將明文密碼放回執行期設定（notifier 會用到）
            if plaintext_password is not None:
                loaded['smtp_password'] = plaintext_password
            
            logger.info("SMTP 密碼正規化完成")
        
        except (ValueError, IOError, FileNotFoundError) as e:
            error_msg = (
                f"【致命錯誤】SMTP 密碼處理失敗\n"
                f"詳細訊息：{e}\n"
                f"\n程式無法繼續。請參照上方解決方案，修正問題後重新啟動。"
            )
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        
        return loaded
    
    def get_email_config(self) -> Dict[str, Any]:
        """取得電子郵件設定"""
        if self.config is None:
            self.load()
        return self.email_config
    
    def get_sites(self) -> List[Dict[str, Any]]:
        """取得監控網站列表"""
        if self.config is None:
            self.load()
        return self.config.get("sites", [])
    
    def get_check_interval(self) -> int:
        """取得檢查間隔（小時）"""
        if self.config is None:
            self.load()
        return self.config.get("check_interval_hours", 1)
    
    def validate(self) -> bool:
        """
        驗證設定檔完整性
        
        返回：
            True 如果驗證通過，否則拋出例外
        """
        if self.config is None:
            self.load()
        
        # 驗證 sites 設定必要欄位
        required_keys = ["sites"]
        for key in required_keys:
            if key not in self.config:
                raise ValueError(f"設定檔缺少必要欄位: {key}")

        # 驗證電子郵件設定（僅在啟用通知時）
        email_config = self.get_email_config()
        if email_config and email_config.get("enabled", True):
            email_required = [
                "smtp_server",
                "smtp_port",
                "smtp_username",
                "sender_email",
                "sender_name",
                "recipients"
            ]
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
            if "ocsp_url" not in site:
                raise ValueError(f"監控網站 #{idx+1} 缺少 'ocsp_url' 欄位")
            if site["expected_status"] not in ["good", "expired", "revoked"]:
                raise ValueError(
                    f"監控網站 #{idx+1} 的 expected_status 值無效: {site['expected_status']}"
                )
            if not isinstance(site["ocsp_url"], str) or not site["ocsp_url"].strip():
                raise ValueError(f"監控網站 #{idx+1} 的 ocsp_url 必須是非空字串")
            if "issuer_url" in site and site["issuer_url"] is not None and not isinstance(site["issuer_url"], str):
                raise ValueError(f"監控網站 #{idx+1} 的 issuer_url 必須是字串或空值")
        
        logger.info("設定檔驗證通過")
        return True
