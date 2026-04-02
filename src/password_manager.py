"""
SMTP 密碼加密管理模組

負責密碼的加密、解密、金鑰管理和 YAML 回寫。
- 支援 AES-256-GCM 加密
- 格式：{AES} + base64(version + nonce + ciphertext_with_tag)
- 金鑰存儲：~/.site-checker/secret.key
"""

import os
import base64
import logging
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# 密文格式前綴
CIPHERTEXT_PREFIX = "{AES}"
# 密文版本：當前支援 v1 (0x01)
CIPHER_VERSION_V1 = 0x01
# AES nonce 大小（GCM 標準 96 bits）
NONCE_SIZE = 12
# AES key 大小（256 bits）
KEY_SIZE = 32


class KeyManager:
    """管理加密金鑰的生命週期"""
    
    def __init__(self, key_path: Optional[str] = None):
        """
        初始化金鑰管理器
        
        參數：
            key_path: 金鑰檔路徑，預設為 ~/.site-checker/secret.key
        """
        if key_path:
            self.key_path = Path(key_path)
        else:
            # 預設路徑：使用者 home 目錄下的 .site-checker/secret.key
            self.key_path = Path.home() / ".site-checker" / "secret.key"
    
    def get_or_create_key(self) -> bytes:
        """
        取得或建立金鑰
        
        首次呼叫時若金鑰不存在會自動建立（隨機 32 bytes）。
        後續呼叫回傳內容不變。
        
        返回：
            32-byte 金鑰
            
        拋出：
            ValueError: 金鑰檔格式或大小不符
            IOError: 檔案讀寫異常
        """
        if self.key_path.exists():
            return self._read_key()
        else:
            return self._create_key()
    
    def _read_key(self) -> bytes:
        """讀取既有金鑰檔"""
        try:
            with open(self.key_path, 'r', encoding='utf-8') as f:
                key_b64 = f.read().strip()
            
            if not key_b64:
                raise ValueError("金鑰檔內容為空")
            
            try:
                key_bytes = base64.b64decode(key_b64)
            except Exception as e:
                raise ValueError(f"金鑰檔 Base64 解碼失敗: {e}")
            
            if len(key_bytes) != KEY_SIZE:
                raise ValueError(
                    f"金鑰大小 {len(key_bytes)} 不符，必須為 {KEY_SIZE} bytes"
                )
            
            logger.info(f"成功載入金鑰: {self.key_path}")
            return key_bytes
        
        except FileNotFoundError:
            error_msg = (
                f"\n\n"
                f"【金鑰遺失】\n"
                f"SMTP 密碼已加密，但無法找到解密金鑰。\n\n"
                f"金鑰位置：{self.key_path}\n\n"
                f"解決方案：\n"
                f"  1. 尋找並恢復舊的 secret.key 檔案到 {self.key_path}\n"
                f"  2. 或將 config/email.yaml 中 smtp_password 改回明碼，重新啟動程式以重新加密\n\n"
            )
            raise FileNotFoundError(error_msg)
        
        except (IOError, OSError) as e:
            error_msg = (
                f"\n\n"
                f"【無法讀取金鑰】\n"
                f"金鑰檔位置：{self.key_path}\n"
                f"錯誤詳情：{e}\n\n"
                f"解決方案：\n"
                f"  1. 檢查檔案是否存在且可讀\n"
                f"  2. 或備份並刪除 {self.key_path}，重新啟動程式以建立新金鑰\n"
                f"     （適用於明碼密碼；密文密碼會無法解密）\n\n"
            )
            raise IOError(error_msg)
        
        except ValueError as e:
            error_msg = (
                f"\n\n"
                f"【金鑰檔損毀】\n"
                f"金鑰檔位置：{self.key_path}\n"
                f"錯誤詳情：{e}\n\n"
                f"解決方案：\n"
                f"  1. 尋找併備份舊的 secret.key 檔案\n"
                f"  2. 或將 config/email.yaml 中 smtp_password 改回明碼，重新啟動程式\n\n"
            )
            raise ValueError(error_msg)
    
    def _create_key(self) -> bytes:
        """產生新金鑰並儲存"""
        try:
            # 產生 32-byte 隨機金鑰
            key_bytes = os.urandom(KEY_SIZE)
            key_b64 = base64.b64encode(key_bytes).decode('ascii')
            
            # 建立目錄
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Windows: 寫入時直接依賴 ACL；Unix: 設定 0o600 權限
            with open(self.key_path, 'w', encoding='utf-8') as f:
                f.write(key_b64)
            
            # Unix/Linux 平台額外限制權限
            if hasattr(os, 'chmod'):
                os.chmod(self.key_path, 0o600)
            
            logger.info(f"新金鑰已建立: {self.key_path}")
            return key_bytes
        
        except (IOError, OSError) as e:
            raise IOError(f"無法建立金鑰檔 {self.key_path}: {e}")


class PasswordEncryptor:
    """使用 AES-256-GCM 加密與解密密碼"""
    
    def __init__(self, key: bytes):
        """
        初始化加密器
        
        參數：
            key: 32-byte AES-256 金鑰
        """
        if len(key) != KEY_SIZE:
            raise ValueError(f"金鑰大小必須為 {KEY_SIZE} bytes")
        self.key = key
    
    def encrypt(self, plaintext: str) -> str:
        """
        加密明文密碼
        
        參數：
            plaintext: 明文密碼
            
        返回：
            {AES} 前綴的密文字串
        """
        plaintext_bytes = plaintext.encode('utf-8')
        
        # 產生隨機 nonce（GCM 標準 96 bits）
        nonce = os.urandom(NONCE_SIZE)
        
        # 初始化 cipher
        cipher = AESGCM(self.key)
        
        # 加密與產生 tag
        ciphertext_with_tag = cipher.encrypt(nonce, plaintext_bytes, None)
        
        # 組成 payload: version(1) + nonce(12) + ciphertext_with_tag
        payload = bytes([CIPHER_VERSION_V1]) + nonce + ciphertext_with_tag
        
        # Base64 編碼
        payload_b64 = base64.b64encode(payload).decode('ascii')
        
        # 加上前綴
        return f"{CIPHERTEXT_PREFIX}{payload_b64}"
    
    def decrypt(self, ciphertext: str) -> str:
        """
        解密密文密碼
        
        參數：
            ciphertext: {AES} 前綴的密文字串
            
        返回：
            明文密碼
            
        拋出：
            ValueError: 密文格式不符、版本不支援、解密失敗
        """
        # 驗證前綴
        if not ciphertext.startswith(CIPHERTEXT_PREFIX):
            raise ValueError(f"無效的密文前綴，應以 {CIPHERTEXT_PREFIX} 開頭")
        
        # 移除前綴並 Base64 解碼
        payload_b64 = ciphertext[len(CIPHERTEXT_PREFIX):]
        try:
            payload = base64.b64decode(payload_b64)
        except Exception as e:
            raise ValueError(f"密文 Base64 解碼失敗: {e}")
        
        # 檢查最小長度：version(1) + nonce(12) + ciphertext_with_tag(至少 16 bytes tag)
        if len(payload) < 1 + NONCE_SIZE + 16:
            raise ValueError(f"密文資料不完整，長度 {len(payload)}")
        
        # 讀取版本
        version = payload[0]
        if version != CIPHER_VERSION_V1:
            raise ValueError(f"不支援的密文版本：{version}，目前支援 {CIPHER_VERSION_V1}")
        
        # 解析 nonce 與 ciphertext_with_tag
        nonce = payload[1:1+NONCE_SIZE]
        ciphertext_with_tag = payload[1+NONCE_SIZE:]
        
        # 初始化 cipher 並解密
        cipher = AESGCM(self.key)
        try:
            plaintext_bytes = cipher.decrypt(nonce, ciphertext_with_tag, None)
        except Exception as e:
            raise ValueError(f"解密失敗 - 金鑰可能不正確或密文已損毀: {e}")
        
        return plaintext_bytes.decode('utf-8')


class PasswordNormalizer:
    """
    標準化 SMTP 密碼：判斷是否為明碼或密文，並執行加密 + 回寫
    """
    
    def __init__(self, key_manager: KeyManager):
        """
        初始化正規化器
        
        參數：
            key_manager: KeyManager 實例
        """
        self.key_manager = key_manager
    
    def normalize_and_get_plaintext(self, 
                                      password_value: any,
                                      yaml_path: Path) -> Optional[str]:
        """
        正規化密碼：判斷明碼/密文並進行相應處理
        
        參數：
            password_value: YAML 中讀取的原始值（可能為 None、str 等）
            yaml_path: email.yaml 檔案路徑（用於回寫）
            
        返回：
            - None: 密碼未設定（null 或空字串）
            - str: 明文密碼（若原為明碼或解密後的結果）
            
        拋出：
            - ValueError: 密文格式錯誤或解密失敗
            - IOError: YAML 回寫失敗或金鑰遺失
        """
        # 情況 1: 未設定密碼（None 或空字串）
        if password_value is None or password_value == "":
            return None
        
        # 轉為字串（以防非 str 型別）
        password_str = str(password_value).strip()
        if not password_str:
            return None
        
        # 情況 2: 已是密文
        if password_str.startswith(CIPHERTEXT_PREFIX):
            try:
                encryptor = self._get_encryptor()
                plaintext = encryptor.decrypt(password_str)
                logger.info("密碼已加密，成功解密")
                return plaintext
            except (FileNotFoundError, IOError) as e:
                # 金鑰遺失或無法讀取
                logger.error(f"金鑰問題：{e}")
                raise
            except ValueError as e:
                # 解密失敗（金鑰錯誤或密文損毀）
                error_msg = (
                    f"\n\n"
                    f"【無法解密 SMTP 密碼】\n"
                    f"配置檔：{yaml_path}\n"
                    f"解密錯誤：{str(e)}\n\n"
                    f"可能原因：\n"
                    f"  1. secret.key 已變更或遺失\n"
                    f"  2. config/email.yaml 中的密文已損毀\n\n"
                    f"解決方案：\n"
                    f"  1. 若有舊的 secret.key：\n"
                    f"     將其複製至 {Path.home() / '.site-checker' / 'secret.key'}\n"
                    f"     然後重新啟動程式\n\n"
                    f"  2. 若無法恢復舊金鑰：\n"
                    f"     編輯 config/email.yaml，將 smtp_password 改為明碼\n"
                    f"     將 smtp_password 設為非空字串（不含 {CIPHERTEXT_PREFIX} 前綴）\n"
                    f"     保存並重新啟動程式，程式會自動重新加密密碼\n\n"
                    f"  3. 若要重新開始（清除所有加密）：\n"
                    f"     刪除 {Path.home() / '.site-checker' / 'secret.key'}\n"
                    f"     將 config/email.yaml 中 smtp_password 改為明碼\n"
                    f"     重新啟動程式\n\n"
                )
                logger.error(error_msg)
                raise ValueError(error_msg)
        
        # 情況 3: 明碼，需要加密與回寫
        try:
            encryptor = self._get_encryptor()
            ciphertext = encryptor.encrypt(password_str)
            
            # 回寫 YAML
            self._rewrite_yaml(yaml_path, ciphertext)
            logger.info(f"明碼密碼已加密並回寫到 {yaml_path}")
            
            # 返回明文供執行期使用
            return password_str
        except (FileNotFoundError, IOError, ValueError) as e:
            logger.error(f"密碼加密失敗：{e}")
            raise
    
    def _get_encryptor(self) -> PasswordEncryptor:
        """取得或建立 encryptor 實例"""
        key = self.key_manager.get_or_create_key()
        return PasswordEncryptor(key)
    
    def _rewrite_yaml(self, yaml_path: Path, ciphertext: str) -> None:
        """
        回寫 YAML 檔案，將 smtp_password 更新為密文
        
        使用 PyYAML，接受格式可能重排。
        """
        import yaml
        
        try:
            # 讀取現有設定
            with open(yaml_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
            
            # 更新密碼
            config['smtp_password'] = ciphertext
            
            # 寫回檔案
            with open(yaml_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            
            logger.info(f"YAML 回寫成功: {yaml_path}")
        
        except (IOError, OSError) as e:
            raise IOError(f"無法回寫 YAML 檔案 {yaml_path}: {e}")
        except yaml.YAMLError as e:
            raise IOError(f"YAML 處理失敗: {e}")
